import { join } from 'path';
import { app } from 'electron';
import type {
  DeviceCategory,
  DiscoveredDevice,
  ModifyNetworkRequest,
  ModifyNetworkResult,
  NetworkSettings,
  PortSettings,
  RebootRequest,
} from '../../shared/types';
import { hasGateway, isOnLocalSubnet } from './networkInterfaces';
import { pickEditedDevice } from './scanResults';

interface NativeDiscoveredDevice {
  host: string;
  port: number;
  httpPort: number;
  mac: string;
  subnetMask: string;
  gateway: string;
  model: string;
  name: string;
  // NET_SDK_DEVICE_TYPE, straight from DVR_NET_SDK.h's own enum.
  deviceType: number;
  // NET_SDK_DEVICE_DISCOVERY_INFO.ucIPMode — the device gets its address by
  // DHCP.
  dhcp: boolean;
}

// NET_SDK_DEVICE_TYPE: DVR=0, DVS=1, IPCAMERA=2, NVR=3, SUPERDVR=4,
// DECODER=5, N_DVR=6. DVS (video server/encoder) and DECODER don't fit
// either bucket cleanly, left uncategorized rather than forced into the
// wrong one.
function categoryFromDeviceType(deviceType: number): DeviceCategory | undefined {
  if (deviceType === 2) return 'ipc';
  if (deviceType === 0 || deviceType === 3 || deviceType === 4 || deviceType === 6) return 'dvr_nvr';
  return undefined;
}

interface NativeAddon {
  discoverDevices(): Promise<NativeDiscoveredDevice[]>;
  setDeviceIp(params: {
    mac: string;
    password: string;
    ip: string;
    subnetMask: string;
    gateway: string;
    dns1: string;
    dns2: string;
    // Absent: NET_SDK_SetDeviceIP; 0/1: NET_SDK_ModifyDeviceNetInfo with that
    // IP mode (static/DHCP).
    ipMode?: 0 | 1;
  }): Promise<{ ok: boolean; errorCode?: number }>;
  login(params: { host: string; port: number; username: string; password: string }): Promise<{ ok: boolean; sessionId?: number; errorCode?: number }>;
  transparent(sessionId: number, url: string, xml: string): Promise<{ ok: boolean; xml?: string; errorCode?: number }>;
  logout(sessionId: number): Promise<void>;
  reboot(sessionId: number): Promise<{ ok: boolean; errorCode?: number }>;
}

// Every record from the most recent search — several devices can share an
// IP, so the one being edited is picked by MAC (see pickEditedDevice).
let lastSeen: NativeDiscoveredDevice[] = [];

let cachedNative: NativeAddon | null = null;

function resolveAddonPath(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'native/tvt/build/Release/tvt_native.node');
  }
  return join(__dirname, '../../native/tvt/build/Release/tvt_native.node');
}

function loadNative(): NativeAddon {
  if (!cachedNative) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cachedNative = require(resolveAddonPath()) as NativeAddon;
  }
  return cachedNative;
}

// TVT's own discovery call is genuinely vendor-proprietary (unlike
// Uniview's NETDEV_Discovery, not a shared broadcast format other
// vendors' firmware also answers) — a response through it is trusted as
// confirmed TVT on its own, same trust model SSM-VMS settled on for this
// exact call. No manual timing needed — the native call blocks internally
// for its own fixed wait window.
export async function discoverTvtDevices(): Promise<DiscoveredDevice[]> {
  const devices = await loadNative().discoverDevices();
  lastSeen = devices;
  return devices.map((d) => ({
    host: d.host,
    port: d.port,
    httpPort: d.httpPort,
    model: d.model,
    manufacturer: 'TVT',
    guessedVendor: 'tvt',
    mac: d.mac,
    subnetMask: d.subnetMask || undefined,
    gateway: d.gateway || undefined,
    deviceCategory: categoryFromDeviceType(d.deviceType),
    discoveryMethod: 'TVT',
    networkEdit: { ports: ['http', 'https', 'device', 'rtsp'], dns: true, username: true, dhcp: true },
    currentPorts: { http: d.httpPort || undefined, device: d.port || undefined },
    dhcp: d.dhcp,
  }));
}

// NET_SDK_GetLastError values — DVR_NET_SDK.h's error enum, which counts
// up from NET_SDK_SUCCESS = 0 with no explicit values.
const TVT_ERRORS: Record<number, string> = {
  1: 'Wrong password.',
  2: "The account doesn't have permission to change network settings.",
  8: 'No response from the device.',
};

// How long to keep re-searching for the device after a change. Each
// NET_SDK_DiscoverDevice call blocks for its own ~3s window.
const VERIFY_TIMEOUT_MS = 20000;
// A switch to DHCP gets longer (the device has to get a lease), and a reply
// from its old address only counts after DHCP_SETTLE_MS — the DHCP server
// may hand the same address back, but right after the switch the device can
// still be answering from its old one.
const DHCP_VERIFY_TIMEOUT_MS = 45000;
const DHCP_SETTLE_MS = 10000;

// Re-searches until `matches` accepts the device's reply (found by MAC), or
// the timeout runs out. Returns the last reply seen for that MAC, if any.
async function searchUntil(
  mac: string,
  matches: (device: NativeDiscoveredDevice) => boolean,
  timeoutMs = VERIFY_TIMEOUT_MS,
): Promise<{ matched: boolean; last?: NativeDiscoveredDevice }> {
  const deadline = Date.now() + timeoutMs;
  let last: NativeDiscoveredDevice | undefined;
  while (Date.now() < deadline) {
    const devices = await loadNative().discoverDevices();
    const match = devices.find((d) => d.mac === mac);
    if (match) {
      last = match;
      if (matches(match)) {
        lastSeen = devices;
        return { matched: true, last };
      }
    }
  }
  return { matched: false, last };
}

// ---- Ports: login + the device's own NVMS-9000 API ------------------------
//
// NET_SDK_GetDVRConfig/SetDVRConfig (DD_NETWORK_ADVANCE_CONFIG) are
// documented "3.0 DVR only", so ports go through NET_SDK_TransparentConfig
// instead, using the exact requests the device's own web UI sends — read
// from the test NVR's js/app/NetCfg/port.js: queryNetPortCfg returns
// httpPort/httpsPort/netPort/rtspPort/posPort (+ anonymousAccess,
// virtualHostEnabled, reservedPort), and editNetPortCfg takes them all back.
const TVT_REQUEST_OPEN = '<?xml version="1.0" encoding="utf-8" ?><request version="1.0"  systemType="NVMS-9000" clientType="WEB">';
const TVT_EMPTY_REQUEST = '<?xml version="1.0" encoding="utf-8" ?><request version="1.0"  systemType="NVMS-9000" clientType="WEB"/>';

// NET_SDK_GetLastError values after a failed NET_SDK_Login.
const TVT_LOGIN_ERRORS: Record<number, string> = {
  1: 'Wrong username or password.',
  2: "That account doesn't have permission to change network settings.",
  5: 'Too many clients are connected to the device right now. Try again later.',
  8: "Couldn't connect to the device on its device port.",
};

function xmlText(xml: string, tag: string): string | undefined {
  return xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]*)</${tag}>`))?.[1]?.trim();
}

// The same checks the device's own web UI applies before saving: every
// port 10-65535, no two the same, none on the device's reserved list.
function tvtPortProblem(ports: Record<string, number>, reserved: string): string | undefined {
  const labels: Record<string, string> = { httpPort: 'HTTP', httpsPort: 'HTTPS', netPort: 'Device', rtspPort: 'RTSP', posPort: 'POS' };
  const entries = Object.entries(ports).filter(([, v]) => v > 0);
  for (const [key, value] of entries) {
    if (value < 10 || value > 65535) return `${labels[key]} port must be between 10 and 65535 on this device.`;
  }
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      if (entries[i][1] === entries[j][1]) return `${labels[entries[i][0]]} and ${labels[entries[j][0]]} ports can't both be ${entries[i][1]}.`;
    }
  }
  for (const item of reserved.split(',').map((r) => r.trim()).filter(Boolean)) {
    const [low, high] = item.split('-').map(Number);
    for (const [key, value] of entries) {
      if (value >= low && value <= (high ?? low)) return `${value} is reserved on this device and can't be used for the ${labels[key]} port.`;
    }
  }
  return undefined;
}

async function changeTvtPorts(device: NativeDiscoveredDevice, request: ModifyNetworkRequest, wanted: PortSettings): Promise<ModifyNetworkResult> {
  const native = loadNative();
  const login = await native.login({ host: device.host, port: device.port, username: request.username, password: request.password });
  if (!login.ok || login.sessionId === undefined) {
    const code = login.errorCode ?? 0;
    return { ok: false, error: TVT_LOGIN_ERRORS[code] ?? `Couldn't log in to the device (TVT error ${code}).` };
  }
  const sessionId = login.sessionId;
  let changed: Record<string, number>;
  try {
    const query = await native.transparent(sessionId, 'queryNetPortCfg', TVT_EMPTY_REQUEST);
    if (!query.ok || !query.xml || xmlText(query.xml, 'status') !== 'success') {
      return { ok: false, error: `This TVT device didn't return its port settings (queryNetPortCfg${query.errorCode ? `, error ${query.errorCode}` : ''}), so ports can't be changed from here.` };
    }
    const current = (tag: string): number => Number(xmlText(query.xml as string, tag) ?? 0);
    changed = {
      httpPort: wanted.http ?? current('httpPort'),
      httpsPort: wanted.https ?? current('httpsPort'),
      netPort: wanted.device ?? current('netPort'),
      rtspPort: wanted.rtsp ?? current('rtspPort'),
      posPort: current('posPort'),
    };
    const problem = tvtPortProblem(changed, xmlText(query.xml, 'reservedPort') ?? '');
    if (problem) return { ok: false, error: problem };

    // Send back everything the device reported, with only the requested
    // ports replaced — optional fields only if the device has them.
    const optional = ['posPort', 'anonymousAccess', 'virtualHostEnabled']
      .map((tag) => [tag, tag === 'posPort' ? String(changed.posPort) : xmlText(query.xml as string, tag)] as const)
      .filter(([tag, value]) => value !== undefined && xmlText(query.xml as string, tag) !== undefined)
      .map(([tag, value]) => `<${tag}>${value}</${tag}>`)
      .join('');
    const edit = await native.transparent(
      sessionId,
      'editNetPortCfg',
      `${TVT_REQUEST_OPEN}<content><httpPort>${changed.httpPort}</httpPort><httpsPort>${changed.httpsPort}</httpsPort>` +
        `<netPort>${changed.netPort}</netPort><rtspPort>${changed.rtspPort}</rtspPort>${optional}</content></request>`,
    );
    if (!edit.ok || !edit.xml || xmlText(edit.xml, 'status') !== 'success') {
      const code = (edit.xml && xmlText(edit.xml, 'errorCode')) ?? edit.errorCode;
      return { ok: false, error: `The device refused the port change${code ? ` (TVT error ${code})` : ''}.` };
    }
  } finally {
    // The session may already be gone if the device port just changed.
    await native.logout(sessionId).catch(() => undefined);
  }

  // HTTP and device ports show up in TVT's own search reply, so those can
  // be confirmed; HTTPS/RTSP rest on the device's "success".
  if (wanted.http === undefined && wanted.device === undefined) return { ok: true };
  const { matched } = await searchUntil(device.mac, (d) => d.httpPort === changed.httpPort && d.port === changed.netPort);
  if (matched) return { ok: true };
  return {
    ok: true,
    warning: `The device accepted the port change, but its search reply hasn't shown the new ports yet (HTTP ${changed.httpPort}, device ${changed.netPort}). Rescan in a minute to check.`,
  };
}

// The Actions column's Reboot for a TVT NVR/DVR: login + NET_SDK_RebootDVR
// (DVR_NET_SDK.h: not for IPCs, which go over ONVIF — see ipc/device.ts).
// Like NET_SDK_SetDeviceIP, a FALSE with error 0 doesn't say much, so it's
// reported as unconfirmed rather than failed.
export async function rebootTvtDevice(request: RebootRequest): Promise<ModifyNetworkResult> {
  const device = pickEditedDevice(lastSeen, request.host, request.mac);
  if (!device) return { ok: false, error: 'This device is no longer in the TVT search results. Scan again and retry.' };
  const native = loadNative();
  const login = await native.login({ host: device.host, port: device.port, username: request.username, password: request.password });
  if (!login.ok || login.sessionId === undefined) {
    const code = login.errorCode ?? 0;
    return { ok: false, error: TVT_LOGIN_ERRORS[code] ?? `Couldn't log in to the device (TVT error ${code}).` };
  }
  try {
    const result = await native.reboot(login.sessionId);
    if (result.ok) return { ok: true };
    const code = result.errorCode ?? 0;
    if (code === 0) {
      return { ok: true, warning: "The reboot was sent, but the device didn't confirm it. If it doesn't go offline in a moment, reboot it from its web page." };
    }
    return { ok: false, error: TVT_ERRORS[code] ?? `The device refused the reboot (TVT error ${code}).` };
  } finally {
    // The session may already be gone with the device.
    await native.logout(login.sessionId).catch(() => undefined);
  }
}

// Blank and 0.0.0.0 both mean "no gateway" (TVT reports 0.0.0.0).
function sameGateway(a: string, b: string): boolean {
  return (hasGateway(a) ? a.trim() : '') === (hasGateway(b) ? b.trim() : '');
}

// ---- IP settings: NET_SDK_SetDeviceIP (search-level, no login) -------------
//
// NET_SDK_SetDeviceIP's return value can't be trusted: confirmed live, it
// returned FALSE with NET_SDK_GetLastError() = 0 (NET_SDK_SUCCESS) on every
// attempt, even though the device really did move to the new IP each time.
// So a FALSE result is checked against what the device actually does:
// re-search for it by MAC until it answers with the requested IP, mask and
// gateway, or the timeout runs out.
// A switch to DHCP is confirmed the same way — the device's search reply
// reporting DHCP — which also says where the DHCP server put it.
async function confirmTvtDhcp(device: NativeDiscoveredDevice, errorCode: number | undefined): Promise<ModifyNetworkResult> {
  const started = Date.now();
  const { matched, last } = await searchUntil(
    device.mac,
    (d) => d.dhcp && (d.host !== device.host || Date.now() - started >= DHCP_SETTLE_MS),
    DHCP_VERIFY_TIMEOUT_MS,
  );
  if (matched && last) {
    return { ok: true, message: `It switched to DHCP and got the address ${last.host}${isOnLocalSubnet(last.host) ? '' : ", which is outside this PC's subnet"}.` };
  }
  if (!last) {
    return { ok: true, warning: `The change was sent, but the device hasn't answered a search within ${DHCP_VERIFY_TIMEOUT_MS / 1000} seconds. Rescan in a minute to check.` };
  }
  return { ok: false, error: TVT_ERRORS[errorCode ?? 0] ?? "The device didn't switch to DHCP — it's still answering with a static address. Check the password and try again." };
}

async function changeTvtNetwork(device: NativeDiscoveredDevice, request: ModifyNetworkRequest, net: NetworkSettings): Promise<ModifyNetworkResult> {
  // DHCP, and a move from DHCP back to a static address, need the IP mode
  // (NET_SDK_ModifyDeviceNetInfo); plain address changes stay on
  // NET_SDK_SetDeviceIP, confirmed live. With DHCP the address fields go
  // as the device's search reported them.
  const ipMode = net.dhcp ? 1 : device.dhcp ? 0 : undefined;
  const address = net.dhcp ? { ip: device.host, subnetMask: device.subnetMask, gateway: device.gateway } : net;
  const result = await loadNative().setDeviceIp({
    // The addon reports "58-5B-69-..."; the SDK's own demo passes the
    // colon-separated form to NET_SDK_SetDeviceIP.
    mac: device.mac.replace(/-/g, ':'),
    password: request.password,
    ip: address.ip,
    subnetMask: address.subnetMask,
    // "No gateway" goes as an empty string, as the SDK's own demo passes it.
    gateway: hasGateway(address.gateway) ? address.gateway : '',
    dns1: net.dns1 ?? '',
    dns2: net.dns2 ?? '',
    ipMode,
  });
  if (net.dhcp) return confirmTvtDhcp(device, result.errorCode);
  if (result.ok) return { ok: true };

  // If IP, mask and gateway were already the requested values (only DNS
  // changed, which TVT's search doesn't report), there's nothing
  // observable to verify against.
  const nothingObservable =
    !device.dhcp &&
    device.host === net.ip.trim() &&
    device.subnetMask.trim() === net.subnetMask.trim() &&
    sameGateway(device.gateway, net.gateway);
  if (nothingObservable) {
    return {
      ok: true,
      warning:
        "The device didn't confirm the change, and its IP, mask and gateway were already these values, so the app can't tell whether it applied (TVT's search doesn't report DNS).",
    };
  }

  const { matched, last } = await searchUntil(
    device.mac,
    (d) => !d.dhcp && d.host === net.ip && d.subnetMask.trim() === net.subnetMask && sameGateway(d.gateway, net.gateway),
  );
  if (matched) return { ok: true };
  if (!last) {
    return {
      ok: true,
      warning: `The change was sent, but the device hasn't answered a search at either address within ${VERIFY_TIMEOUT_MS / 1000} seconds. Rescan in a minute to check.`,
    };
  }
  const code = result.errorCode ?? 0;
  return {
    ok: false,
    error: TVT_ERRORS[code] ?? `The device didn't apply the change — it's still answering with its old settings. Check the password and try again.`,
  };
}

// Ports first (they need a login at the device's current address), then IP
// settings — each only if it was actually changed.
export async function modifyTvtDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  const device = pickEditedDevice(lastSeen, request.host, request.mac);
  if (!device) return { ok: false, error: 'This device is no longer in the TVT search results. Scan again and retry.' };

  // Ports need a login at the device's current address, which can't reach
  // a device outside the PC's subnet — and failing there first would also
  // block the IP change that does work across subnets.
  const wantsPorts = request.ports !== undefined && Object.keys(request.ports).length > 0;
  if (wantsPorts && !isOnLocalSubnet(device.host)) {
    return { ok: false, error: "Ports can only be changed while the device is in this PC's subnet — change its IP first, rescan, then change the ports." };
  }

  let portsChanged = false;
  let portsWarning: string | undefined;
  if (wantsPorts && request.ports) {
    const portsResult = await changeTvtPorts(device, request, request.ports);
    if (!portsResult.ok || !request.network) return portsResult;
    portsChanged = true;
    portsWarning = portsResult.warning;
  }
  if (!request.network) return { ok: true };

  const networkResult = await changeTvtNetwork(device, request, request.network);
  if (!networkResult.ok) {
    return portsChanged ? { ok: false, error: `The ports were changed, but the IP change failed: ${networkResult.error}` } : networkResult;
  }
  const warnings = [portsWarning, networkResult.warning].filter(Boolean).join(' ');
  return warnings ? { ok: true, warning: warnings } : { ok: true };
}
