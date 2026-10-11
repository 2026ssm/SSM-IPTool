import { join } from 'path';
import { app } from 'electron';
import type { DeviceCategory, DiscoveredDevice, ModifyNetworkRequest, ModifyNetworkResult, PortSettings } from '../../shared/types';
import { normalizeMac } from './arpLookup';
import { vendorFromMac } from './macVendors';
import { isOnLocalSubnet, localIPv4Interfaces } from './networkInterfaces';
import { changeOnvifPorts, hasOnvifService } from './onvifNetwork';
import { pickEditedDevice } from './scanResults';

interface NativeDiscoveredDevice {
  host: string;
  port: number;
  httpPort: number;
  mac: string;
  subnetMask: string;
  gateway: string;
  model: string;
  vendor: string;
  name: string;
  manuFactory: number;
  // DEVICE_NET_INFO_EX.szDeviceType — confirmed live (via the
  // [dahua-devicetype-diag] log in addon.cc) to carry short PRODUCT-LINE
  // codes, not the generic words "IPC"/"DVR"/"NVR" first assumed: a real
  // SD6C230S-HN speed-dome PTZ camera reported "SD" (Speed Dome), not
  // "IPC" — the original "IPC"/"DVR"/"NVR" substring check was too narrow
  // and silently left every camera uncategorized. DVR/NVR units DID
  // report something containing "NVR"/"DVR" literally (confirmed working
  // live), so only the camera side needed expanding. More camera-type
  // codes (box/bullet/fisheye/etc.) likely exist and aren't covered yet —
  // add them here as they're actually observed, not guessed ahead of time.
  deviceType: string;
  // DEVICE_NET_INFO_EX.bDhcpEn — the device gets its address by DHCP.
  dhcp: boolean;
}

const CONFIRMED_IPC_DEVICE_TYPE_CODES = ['IPC', 'SD'];

function categoryFromDeviceType(deviceType: string): DeviceCategory | undefined {
  const upper = deviceType.trim().toUpperCase();
  if (!upper) return undefined;
  if (CONFIRMED_IPC_DEVICE_TYPE_CODES.some((code) => upper.includes(code))) return 'ipc';
  if (upper.includes('NVR') || upper.includes('DVR')) return 'dvr_nvr';
  return undefined;
}

interface NativeModifyResult {
  ok: boolean;
  notFound?: boolean;
  errorCode?: number;
}

interface NativeAddon {
  startDiscovery(onDevice: (device: NativeDiscoveredDevice) => void): void;
  stopDiscovery(): void;
  searchByIps(ips: string[], localIp: string, waitMs: number): Promise<NativeDiscoveredDevice[]>;
  modifyDevice(params: {
    mac: string;
    ip: string;
    subnetMask: string;
    gateway: string;
    port?: number;
    httpPort?: number;
    setStatic: boolean;
    setDhcp: boolean;
    username: string;
    password: string;
    localIp: string;
  }): Promise<NativeModifyResult>;
}

// Every raw record from the most recent scan, in arrival order — several
// devices can share an IP, so the one being edited is picked by MAC (see
// pickEditedDevice). The addon keys its own cached DEVICE_NET_INFO_EX by
// the raw szMac, so the modify call needs that exact string back, not the
// normalized one shown in the UI.
let lastSeen: NativeDiscoveredDevice[] = [];

let cachedNative: NativeAddon | null = null;

function resolveAddonPath(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'native/dahua/build/Release/dahua_native.node');
  }
  return join(__dirname, '../../native/dahua/build/Release/dahua_native.node');
}

function loadNative(): NativeAddon {
  if (!cachedNative) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cachedNative = require(resolveAddonPath()) as NativeAddon;
  }
  return cachedNative;
}

const DISCOVERY_DURATION_MS = 3000;

// Sunell cameras (MACs starting 00:1C:27, Sunell Electronics' registered
// prefix — see macVendors.ts) answer Dahua's search as native Dahua
// devices: port 37777, vendor "Private", byManuFactory 0 — found on an
// ECL-IP2TN sold under a distributor's brand. They're labelled Sunell, and
// their HTTP/HTTPS/RTSP ports go over ONVIF, which confirms a change by
// reading it back: whether Sunell applies the HTTP port in Dahua's command
// is untested, and the genuine Dahua PTZ on the test network ignored it
// while reporting success. So the HTTP port in their reply isn't relied on
// either (see modifyDahuaDevice and ipc/discovery.ts).
function isSunellMac(mac: string | undefined): boolean {
  return vendorFromMac(mac) === 'sunell';
}

// Same trust model as TVT above — CLIENT_StartSearchDevices is genuinely
// vendor-proprietary, so a response is trusted as confirmed Dahua on its
// own. Deliberately NOT gated on szVendor/byManuFactory — both were tried
// as a confirmation field in SSM-VMS and both turned out to be generic
// SDK-fallback values even for a real, confirmed-genuine Dahua device
// (szVendor="General", byManuFactory=48/"OTHER") — see that project's
// memory for the full live-tested story before reusing either field here.
// The one exception is the MAC's maker: Sunell cameras answer this search
// too (see isSunellMac).
function toDiscoveredDevice(device: NativeDiscoveredDevice): DiscoveredDevice {
  const sunell = isSunellMac(device.mac);
  return {
    host: device.host,
    port: device.port,
    httpPort: device.httpPort,
    model: device.model,
    manufacturer: sunell ? 'Sunell' : 'Dahua',
    guessedVendor: sunell ? 'sunell' : 'dahua',
    mac: device.mac,
    subnetMask: device.subnetMask || undefined,
    gateway: device.gateway || undefined,
    deviceCategory: categoryFromDeviceType(device.deviceType),
    discoveryMethod: 'Dahua',
    networkEdit: { ports: sunell ? ['device'] : ['http', 'device'], dns: false, username: true, dhcp: true },
    currentPorts: { http: sunell ? undefined : device.httpPort || undefined, device: device.port || undefined },
    dhcp: device.dhcp,
  };
}

export async function discoverDahuaDevices(): Promise<DiscoveredDevice[]> {
  const seen: NativeDiscoveredDevice[] = [];
  loadNative().startDiscovery((device) => seen.push(device));
  await new Promise((resolve) => setTimeout(resolve, DISCOVERY_DURATION_MS));
  loadNative().stopDiscovery();
  lastSeen = seen;
  return seen.map(toDiscoveredDevice);
}

// Dahua's own search-by-IP (CLIENT_SearchDevicesByIPs): each address is
// asked directly instead of by broadcast. The test network's Dahua PTZ
// stopped getting its reply to the broadcast search through to this PC
// (so it could only be reached over ONVIF, whose login it refuses) but
// answers this at once. Answers join lastSeen, so the modify command finds
// them.
const IP_SEARCH_WAIT_MS = 3000;

export async function searchDahuaByIps(hosts: string[]): Promise<DiscoveredDevice[]> {
  if (hosts.length === 0) return [];
  const found = await loadNative().searchByIps(hosts, '', IP_SEARCH_WAIT_MS);
  lastSeen = [...lastSeen.filter((d) => !found.some((f) => f.mac === d.mac)), ...found];
  return found.map(toDiscoveredDevice);
}

// CLIENT_GetLastError codes (0x80000000 flag masked off) from dhnetsdk.h.
const DAHUA_ERRORS: Record<number, string> = {
  2: 'No response from the device (network error or timeout).',
  7: 'The device rejected one of the settings as invalid.',
  23: "This device doesn't support changing its IP from a search.",
  100: 'Wrong password.',
  101: "That username doesn't exist on the device.",
  104: 'The account is locked — too many failed attempts. Wait and try again later.',
};

// The local interface to send the modify command out of: the one sharing
// the device's current subnet. For a device outside every local subnet the
// NIC that heard it is unknown (the search ran on all of them), so it's left
// empty for the SDK to choose — as the SDK's own DevInit demo does for such
// records — rather than pinned to whichever adapter happens to be listed
// first (a Wi-Fi/VPN/virtual adapter would send it nowhere near the camera).
function localIpFor(host: string): string {
  return localIPv4Interfaces().find((iface) => isOnLocalSubnet(host, [iface]))?.address ?? '';
}

// The SDK's "success" doesn't show what a device applied — the genuine
// Dahua PTZ on the test network reported success for an HTTP port change
// and kept its old port — so what the search reply shows is confirmed from
// it: the ports, and a switch to DHCP (which also gives the address the
// DHCP server handed out). A DHCP reply from the old address only counts
// after DHCP_SETTLE_MS: the server may hand the same address back, but
// right after the switch the device can still be answering from its old one.
const PORTS_VERIFY_TIMEOUT_MS = 20000;
const DHCP_VERIFY_TIMEOUT_MS = 45000;
const DHCP_SETTLE_MS = 10000;

// Re-runs the search until the device (found by MAC) answers with what
// `matches` wants, or the timeout runs out — asking `ips` directly too when
// the broadcast search doesn't hear it. Returns that reply, and the last one
// seen for the MAC.
async function searchDahuaUntil(
  mac: string,
  matches: (device: DiscoveredDevice, elapsedMs: number) => boolean,
  timeoutMs: number,
  ips: string[],
): Promise<{ matched?: DiscoveredDevice; last?: DiscoveredDevice }> {
  const wanted = normalizeMac(mac);
  const started = Date.now();
  let last: DiscoveredDevice | undefined;
  while (Date.now() - started < timeoutMs) {
    const found =
      (await discoverDahuaDevices()).find((d) => normalizeMac(d.mac) === wanted) ??
      (await searchDahuaByIps(ips)).find((d) => normalizeMac(d.mac) === wanted);
    if (!found) continue;
    last = found;
    if (matches(found, Date.now() - started)) return { matched: found, last };
  }
  return { last };
}

async function confirmDahuaPorts(mac: string, ports: PortSettings, ipChanged: boolean, ip: string): Promise<ModifyNetworkResult> {
  const { matched, last } = await searchDahuaUntil(
    mac,
    (d) => (ports.http === undefined || d.httpPort === ports.http) && (ports.device === undefined || d.port === ports.device),
    PORTS_VERIFY_TIMEOUT_MS,
    [ip],
  );
  if (matched) return { ok: true };
  if (!last) {
    return { ok: true, warning: "The change was sent, but the device hasn't answered a search since, so the new ports couldn't be confirmed. Rescan in a minute to check." };
  }
  const kept = [
    ports.http !== undefined && last.httpPort !== ports.http ? `HTTP port at ${last.httpPort}` : undefined,
    ports.device !== undefined && last.port !== ports.device ? `device port at ${last.port}` : undefined,
  ].filter(Boolean);
  const requested = [ports.http, ports.device].filter((p) => p !== undefined).length;
  const keptText = `it kept its ${kept.join(' and ')} — change ${kept.length > 1 ? 'those' : 'that'} from its web page`;
  return ipChanged || kept.length < requested
    ? { ok: true, warning: `The device applied the rest of the change, but ${keptText}.` }
    : { ok: false, error: `The device reported success, but ${keptText}.` };
}

async function confirmDahuaDhcp(mac: string, oldIp: string): Promise<ModifyNetworkResult> {
  const { matched, last } = await searchDahuaUntil(
    mac,
    (d, elapsedMs) => d.dhcp === true && (d.host !== oldIp || elapsedMs >= DHCP_SETTLE_MS),
    DHCP_VERIFY_TIMEOUT_MS,
    [oldIp],
  );
  if (matched) {
    return { ok: true, message: `It switched to DHCP and got the address ${matched.host}${isOnLocalSubnet(matched.host) ? '' : ", which is outside this PC's subnet"}.` };
  }
  if (!last) return { ok: true, warning: `The change was sent, but the device hasn't answered a search within ${DHCP_VERIFY_TIMEOUT_MS / 1000} seconds. Rescan in a minute to check.` };
  return last.dhcp
    ? { ok: true, warning: 'The device switched to DHCP. Rescan in a minute to see the address it gets.' }
    : { ok: false, error: "The device reported success but is still answering with a static address — it didn't switch to DHCP." };
}

export async function modifyDahuaDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  const device = pickEditedDevice(lastSeen, request.host, request.mac);
  if (!device) return { ok: false, error: 'This device is no longer in the Dahua search results. Scan again and retry.' };

  // Sunell: HTTP/HTTPS/RTSP ports over ONVIF first, at the camera's current
  // address; IP settings and the device port through the search command.
  let ports = request.ports;
  let webPortsChanged = false;
  let webPortsWarning: string | undefined;
  if (isSunellMac(device.mac) && ports) {
    const { device: devicePort, ...webPorts } = ports;
    if (Object.keys(webPorts).length > 0) {
      const onvif = hasOnvifService(request.host)
        ? await changeOnvifPorts(request, webPorts)
        : { ok: false as const, error: "This camera's HTTP, HTTPS and RTSP ports can only be changed over ONVIF, and it didn't answer ONVIF discovery." };
      if (!onvif.ok || (!request.network && devicePort === undefined)) return onvif;
      webPortsChanged = true;
      webPortsWarning = onvif.warning;
    }
    ports = devicePort !== undefined ? { device: devicePort } : undefined;
  }

  // One command carries both IP settings and ports: a ports-only edit — or
  // a switch to DHCP, where the DHCP server picks the address — re-sends
  // the device's current IP settings as its search reported them, and a
  // blank gateway keeps the current one.
  const dhcp = request.network?.dhcp === true;
  const net = request.network && !dhcp ? request.network : { ip: device.host, subnetMask: device.subnetMask, gateway: device.gateway };
  const result = await loadNative().modifyDevice({
    mac: device.mac,
    ip: net.ip,
    subnetMask: net.subnetMask,
    gateway: net.gateway || device.gateway,
    port: ports?.device,
    httpPort: ports?.http,
    // Setting an address means a static one: a device in DHCP mode would
    // otherwise keep DHCP and ignore the new IP.
    setStatic: request.network !== undefined && !dhcp,
    setDhcp: dhcp,
    username: request.username,
    password: request.password,
    localIp: localIpFor(request.host),
  });
  let outcome: ModifyNetworkResult;
  if (result.notFound) outcome = { ok: false, error: 'This device is no longer in the Dahua search results. Scan again and retry.' };
  else if (!result.ok) outcome = { ok: false, error: DAHUA_ERRORS[result.errorCode ?? 0] ?? `The device refused the change (Dahua error ${result.errorCode ?? 0}).` };
  else if (dhcp) outcome = await confirmDahuaDhcp(device.mac, request.host);
  else if (ports?.http !== undefined || ports?.device !== undefined) outcome = await confirmDahuaPorts(device.mac, ports, request.network !== undefined, net.ip);
  else outcome = { ok: true };

  if (!webPortsChanged) return outcome;
  if (!outcome.ok) return { ok: false, error: `The ports were already changed, but then: ${outcome.error}` };
  const warning = [webPortsWarning, outcome.warning].filter(Boolean).join(' ');
  return warning ? { ...outcome, warning } : outcome;
}
