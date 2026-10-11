import { ipcMain, shell } from 'electron';
import { existsSync } from 'fs';
import { join } from 'path';
import { openDeviceBrowser } from '../deviceBrowser';
import { modifyDahuaDevice, factoryResetDahuaDevice } from '../services/dahuaDiscovery';
import { modifyTvtDevice, rebootTvtDevice } from '../services/tvtDiscovery';
import { modifyUniviewDevice } from '../services/univiewDiscovery';
import { readUniviewNetworkViaLapi, factoryResetUniviewViaLapi } from '../services/univiewLapi';
import { modifyOnvifDevice, readOnvifHttpPort, readOnvifNetwork, rebootOnvifDevice, factoryResetOnvifDevice, hasOnvifService } from '../services/onvifNetwork';
import { modifyHikvisionDevice, rebootHikvisionDevice, factoryResetHikvisionDevice } from '../services/hikvisionIsapi';
import { modifyAxisDevice, readAxisNetworkForPrefill, rebootAxisDevice } from '../services/axisVapix';
import { hasGateway, localIPv4Interfaces } from '../services/networkInterfaces';
import { lastScanHosts, lastScanRowsFor } from '../services/scanResults';
import type { FactoryResetRequest, ModifyNetworkRequest, ModifyNetworkResult, PortKind, PortSettings, RebootRequest } from '../../shared/types';

// Changing a device's network settings is a write against live hardware —
// a bad IP/mask/gateway can leave a device unreachable until someone
// factory-resets it on site — so everything is validated here in main
// before any SDK call, not just in the dialog.
//
// Octets with leading zeros are refused rather than read as decimal: the
// strings go to vendor SDKs and firmware whose inet_addr-style parsers
// read "064" as octal (52), which would move a device to an address that
// was never validated.
function parseIPv4(value: string): number | undefined {
  const parts = value.trim().split('.');
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    n = n * 256 + octet;
  }
  return n;
}

const IPV4_HINT = 'without leading zeros, e.g. 192.168.1.64';

function validate(request: ModifyNetworkRequest): string | undefined {
  const ports = Object.entries(request.ports ?? {}) as [PortKind, number][];
  if (!request.network && ports.length === 0) return 'Nothing was changed.';

  const net = request.network;
  // With DHCP the device's address comes from the DHCP server, so only the
  // DNS servers (where the route sets them) are checked.
  if (net && !net.dhcp) {
    if (!net.subnetMask.trim()) return "Enter the subnet mask — this device didn't report its current one.";
    const ip = parseIPv4(net.ip);
    const mask = parseIPv4(net.subnetMask);
    if (ip === undefined) return `IP address must be a valid IPv4 address (${IPV4_HINT}).`;
    if (mask === undefined) return 'Subnet mask must be a valid IPv4 mask (e.g. 255.255.255.0).';
    // A valid mask is a contiguous run of 1 bits followed by 0s.
    const inverted = ~mask >>> 0;
    if (mask === 0 || (inverted & (inverted + 1)) !== 0) return 'Subnet mask is not a valid mask (e.g. 255.255.255.0).';
    const network = (ip & mask) >>> 0;
    const broadcast = (network | inverted) >>> 0;
    if (ip === network || ip === broadcast) return "IP address can't be the subnet's network or broadcast address.";
    if (hasGateway(net.gateway)) {
      const gateway = parseIPv4(net.gateway);
      if (gateway === undefined) return `Gateway must be a valid IPv4 address (${IPV4_HINT}), or 0.0.0.0 for none.`;
      if (((gateway & mask) >>> 0) !== network) return 'Gateway must be in the same subnet as the IP address.';
      if (gateway === ip) return "The IP address can't be the same as the gateway's.";
    }
    // Moving a device onto an address something else already answers on
    // causes an ARP conflict that can take the PC or the LAN's gateway
    // offline — so refuse addresses main already knows are taken.
    const newIp = net.ip.trim();
    if (newIp !== request.host) {
      if (localIPv4Interfaces().some((iface) => iface.address === newIp)) return `${newIp} is this PC's own address.`;
      if (lastScanHosts().has(newIp)) return `${newIp} is already used by another device found in the last scan.`;
    }
  }
  for (const [label, dns] of [['Preferred DNS', net?.dns1], ['Alternate DNS', net?.dns2]] as const) {
    if (dns?.trim() && parseIPv4(dns) === undefined) return `${label} must be a valid IPv4 address (${IPV4_HINT}).`;
  }

  // Range and "no two the same" among the ports being changed here; each
  // service also checks them against the device's unchanged ports once it
  // has read them (and TVT against its own reserved-port list).
  for (const [kind, port] of ports) {
    if (!(Number.isInteger(port) && port >= 1 && port <= 65535)) return `${PORT_LABELS[kind]} port must be between 1 and 65535.`;
    if ((kind === 'http' || kind === 'https') && BROWSER_BLOCKED_PORTS.has(port)) {
      return `Browsers refuse to open web pages on port ${port} (it's on the web's restricted-port list), so the device's web page wouldn't load there. Pick a different ${PORT_LABELS[kind]} port.`;
    }
  }
  for (let i = 0; i < ports.length; i++) {
    for (let j = i + 1; j < ports.length; j++) {
      if (ports[i][1] === ports[j][1]) return `${PORT_LABELS[ports[i][0]]} and ${PORT_LABELS[ports[j][0]]} ports can't both be ${ports[i][1]}.`;
    }
  }
  if (!request.password) return "The device's password is required.";
  return undefined;
}

// The request the services get: every address trimmed (and, with leading
// zeros refused above, canonical), so what's validated is exactly what's
// sent to the device and compared against afterwards.
function normalizeRequest(request: ModifyNetworkRequest): ModifyNetworkRequest {
  const net = request.network;
  return {
    ...request,
    username: request.username.trim(),
    network: net && {
      dhcp: net.dhcp === true || undefined,
      ip: net.ip.trim(),
      subnetMask: net.subnetMask.trim(),
      gateway: net.gateway.trim(),
      dns1: net.dns1?.trim(),
      dns2: net.dns2?.trim(),
    },
  };
}

const PORT_LABELS: Record<PortKind, string> = { http: 'HTTP', https: 'HTTPS', rtsp: 'RTSP', device: 'Device' };

// The WHATWG Fetch standard's "bad ports": every modern browser refuses to
// load a page on these (Chrome/Edge show ERR_UNSAFE_PORT, Electron a blank
// window). Found live: a TVT NVR moved to HTTP port 87 exactly as asked,
// but its web page never opened. Only checked for HTTP/HTTPS — RTSP and
// the device port aren't opened by a browser (RTSP's standard 554 is on
// this list itself).
const BROWSER_BLOCKED_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111,
  113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548,
  554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566,
  6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

// The device's web page URL, with its real HTTP port: a vendor search's own
// HTTP port first (TVT/Dahua/Uniview report it; Uniview's lives in `port`,
// which the renderer's old link missed), then any other non-ONVIF row's
// HTTP port (Hikvision SADP; not Sunell's reply to Dahua's search, which
// isn't trusted for it), then what the camera itself reports over
// ONVIF, and the ONVIF XAddr port only as a last resort — that one is the
// ONVIF service's port, not always the web port (8080 vs 8081 on one test
// camera).
async function webPageUrl(host: string): Promise<string | undefined> {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return undefined;
  const rows = lastScanRowsFor(host);
  const trusted = rows.filter((r) => !(r.discoveryMethod === 'Dahua' && r.guessedVendor === 'sunell'));
  let port =
    trusted.find((r) => r.currentPorts?.http)?.currentPorts?.http ??
    trusted.find((r) => r.discoveryMethod !== 'ONVIF' && r.httpPort)?.httpPort;
  if (port === undefined && rows.some((r) => r.discoveryMethod === 'ONVIF')) port = await readOnvifHttpPort(host);
  port ??= trusted.find((r) => r.httpPort)?.httpPort ?? rows.find((r) => r.httpPort)?.httpPort ?? 80;
  return `http://${host}${port === 80 ? '' : `:${port}`}/`;
}

export function registerDeviceIpcHandlers(): void {
  // Best-effort pre-fill for the Edit dialog; only ONVIF can read a
  // device's current mask/gateway/ports/DHCP mode without a login here (the
  // vendor searches already report what they can — see DiscoveredDevice).
  // Uniview's search reports none of those, and Sunell's reply to Dahua's
  // search isn't trusted for its web port, so those rows are read over ONVIF
  // too when the camera answers it.
  // Authenticated pre-fill: Uniview reveals its mask/gateway only to a
  // logged-in request, so the Edit dialog can ask for them once the user
  // has entered the password (device:readNetwork above is the no-login one).
  ipcMain.handle(
    'device:readNetworkAuth',
    async (
      _event,
      host: string,
      discoveryMethod: string,
      username: string,
      password: string,
    ): Promise<{ subnetMask?: string; gateway?: string; dhcp?: boolean; error?: string }> => {
      if (!password) return { error: 'Enter the password first.' };
      if (discoveryMethod === 'Axis') {
        const row = lastScanRowsFor(host).find((r) => r.discoveryMethod === 'Axis');
        const port = row?.currentPorts?.http ?? row?.httpPort ?? 80;
        try {
          return await readAxisNetworkForPrefill(host, port, { username: username.trim(), password });
        } catch (e) {
          return { error: e instanceof Error ? e.message : String(e) };
        }
      }
      if (discoveryMethod !== 'Uniview') return {};
      const row = lastScanRowsFor(host).find((r) => r.discoveryMethod === 'Uniview');
      const port = row?.currentPorts?.http ?? row?.port ?? 80;
      try {
        return await readUniviewNetworkViaLapi(host, port, { username: username.trim(), password });
      } catch (e) {
        return { error: e instanceof Error ? e.message : String(e) };
      }
    },
  );

  ipcMain.handle(
    'device:readNetwork',
    async (_event, host: string, discoveryMethod: string): Promise<{ subnetMask?: string; gateway?: string; ports?: PortSettings; dhcp?: boolean }> =>
      discoveryMethod === 'ONVIF' || discoveryMethod === 'Uniview' || lastScanRowsFor(host).some((r) => r.guessedVendor === 'sunell')
        ? readOnvifNetwork(host)
        : {},
  );

  // Opens the device's web UI in an in-app browser window — isolated, with
  // no app bridge and no Node (see deviceBrowser.ts), so the camera's page
  // can't reach the app's device-control functions.
  ipcMain.handle('device:openWebPage', async (_event, host: string): Promise<void> => {
    const url = await webPageUrl(host);
    if (url) openDeviceBrowser(url, host);
  });

  // Opens Hikvision's own SADP tool so the tech can reset a forgotten admin
  // password there (export the request file, send it to Hikvision, import
  // the signed file). The app only launches the vendor tool — it never
  // handles the reset protocol or the password itself. SADP scans on its
  // own, so no device argument is passed; the dialog tells the tech which
  // device to pick.
  ipcMain.handle('device:openSadpTool', async (): Promise<ModifyNetworkResult> => {
    const programFiles = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, 'C:\\Program Files (x86)', 'C:\\Program Files'].filter(
      (dir): dir is string => Boolean(dir),
    );
    const candidates = programFiles.flatMap((dir) => [join(dir, 'SADP', 'SADP', 'SADPTool.exe'), join(dir, 'SADP', 'SADPTool.exe')]);
    const exe = candidates.find((path) => existsSync(path));
    if (!exe) {
      return { ok: false, error: "Couldn't find Hikvision's SADP tool on this PC. Install it from Hikvision (HiTools), then try again." };
    }
    const problem = await shell.openPath(exe);
    return problem ? { ok: false, error: `Couldn't open the SADP tool: ${problem}` } : { ok: true };
  });

  // Reboot from the Actions column: Hikvision over ISAPI, a TVT NVR/DVR over
  // its SDK login (the SDK's reboot isn't for IPCs), everything else over
  // ONVIF. Each route checks the login and the device's MAC first.
  ipcMain.handle('device:reboot', async (_event, request: RebootRequest): Promise<ModifyNetworkResult> => {
    if (!request.password) return { ok: false, error: "The device's password is required." };
    request = { ...request, username: request.username.trim() };
    try {
      if (request.discoveryMethod === 'Hikvision SADP') return await rebootHikvisionDevice(request);
      if (request.discoveryMethod === 'Axis') return await rebootAxisDevice(request);
      const tvt = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'TVT');
      if (request.discoveryMethod === 'TVT' && tvt?.deviceCategory !== 'ipc') return await rebootTvtDevice(request);
      return await rebootOnvifDevice(request);
    } catch (e) {
      // Never log the request itself — it carries the device password.
      console.error(`[device] ${request.discoveryMethod} reboot failed:`, e);
      return { ok: false, error: `The reboot couldn't be sent (${e instanceof Error ? e.message : String(e)}).` };
    }
  });

  // Factory reset from the Actions column: the same row-targeting rules as
  // a reboot or an edit (host + MAC from the last scan). Each brand rides
  // its own route — Dahua's SDK via its login, Uniview's LAPI, Hikvision's
  // ISAPI, and a TVT camera via ONVIF (its SDK's reset is NVR-only) —
  // checked to be present before anything is sent.
  ipcMain.handle('device:factoryReset', async (_event, request: FactoryResetRequest): Promise<ModifyNetworkResult> => {
    if (!request.password) return { ok: false, error: "The device's password is required." };
    if (request.mode !== 'keep_network' && request.mode !== 'full') return { ok: false, error: 'Choose a reset mode first.' };
    request = { ...request, username: request.username.trim() };
    try {
      switch (request.discoveryMethod) {
        case 'Dahua':
          return await factoryResetDahuaDevice(request);
        case 'Uniview': {
          const row = lastScanRowsFor(request.host).find((r) => r.discoveryMethod === 'Uniview');
          return await factoryResetUniviewViaLapi(request.host, row?.currentPorts?.http ?? row?.port ?? 80, { username: request.username, password: request.password }, request.mode);
        }
        case 'TVT':
          if (!hasOnvifService(request.host)) {
            return { ok: false, error: "This TVT device doesn't answer ONVIF, and its own SDK doesn't offer a camera reset — reset it from its web page instead." };
          }
          return await factoryResetOnvifDevice(request);
        case 'Hikvision SADP':
          return await factoryResetHikvisionDevice(request);
        default:
          return { ok: false, error: `Factory reset isn't supported for ${request.discoveryMethod} yet.` };
      }
    } catch (e) {
      // Never log the request itself — it carries the device password.
      console.error(`[device] ${request.discoveryMethod} factory reset failed:`, e);
      return { ok: false, error: `The reset couldn't be sent (${e instanceof Error ? e.message : String(e)}).` };
    }
  });

  ipcMain.handle('device:modifyNetwork', async (_event, request: ModifyNetworkRequest): Promise<ModifyNetworkResult> => {
    const error = validate(request);
    if (error) return { ok: false, error };
    request = normalizeRequest(request);
    try {
      switch (request.discoveryMethod) {
        case 'Dahua':
          return await modifyDahuaDevice(request);
        case 'TVT':
          return await modifyTvtDevice(request);
        case 'Uniview':
          return await modifyUniviewDevice(request);
        case 'Hikvision SADP':
          return await modifyHikvisionDevice(request);
        case 'Axis':
          return await modifyAxisDevice(request);
        case 'ONVIF':
          return await modifyOnvifDevice(request);
        default:
          return { ok: false, error: `Changing network settings isn't supported for ${request.discoveryMethod} yet.` };
      }
    } catch (e) {
      // Never log the request itself — it carries the device password.
      console.error(`[device] ${request.discoveryMethod} modify failed:`, e);
      return { ok: false, error: `The ${request.discoveryMethod} SDK couldn't send the change (${e instanceof Error ? e.message : String(e)}).` };
    }
  });
}
