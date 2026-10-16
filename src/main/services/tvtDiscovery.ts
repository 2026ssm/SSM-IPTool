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

// ---- Ports: login + the device's own config API ---------------------------
//
// NET_SDK_GetDVRConfig/SetDVRConfig (DD_NETWORK_ADVANCE_CONFIG) are documented
// "3.0 DVR only", so ports go through NET_SDK_TransparentConfig using the exact
// requests the device's own web UI sends. TVT devices speak one of two config
// APIs, and which one depends on the device class:
//   - NVR/DVR (NVMS-9000): queryNetPortCfg / editNetPortCfg, with an XML
//     <request systemType="NVMS-9000">…<content>…</content></request> envelope.
//     Ports: httpPort/httpsPort/netPort/rtspPort/posPort (+ anonymousAccess,
//     virtualHostEnabled, reservedPort). Read from the test NVR's web UI
//     (js/app/NetCfg/port.js). Reply status is an element <status>success</…>.
//   - IPC (www.ipc.com): GetPortConfig / SetPortConfig, with an XML
//     <config xmlns="http://www.ipc.com/ver10"><port>…</port></config> envelope
//     (read-modify-write — GetPortConfig returns the block, SetPortConfig takes
//     it back). Ports: httpPort/httpsPort/netPort/rtspPort/longPollingPort, each
//     with a type="uint16" attribute. Read from the IPC's web UI
//     (Scripts/ConfigMgr/Net/netAdvance.htm.js). Reply status is an ATTRIBUTE,
//     status="success" on <config>.
// Both name the device port <netPort>; only the command and envelope differ.
// Sending the NVR commands to an IPC returns a www.ipc.com reply with
// status="failed" errorCode="499" (unknown command) — which is why port changes
// used to fail on TVT IPCs (confirmed live on an IPCT 4W-4MP at device port
// 9008; the NVR path is confirmed on an ED8004H5).
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

type TvtPortApi = 'nvr' | 'ipc';
interface TvtPortState {
  api: TvtPortApi;
  // The device's own reply, kept whole for the IPC read-modify-write.
  xml: string;
  current: { http: number; https: number; net: number; rtsp: number };
  // The NVR's reserved-port ranges; empty for the IPC (it reports none).
  reserved: string;
}

function tvtPortsFrom(xml: string): TvtPortState['current'] {
  const n = (tag: string): number => Number(xmlText(xml, tag) ?? 0);
  return { http: n('httpPort'), https: n('httpsPort'), net: n('netPort'), rtsp: n('rtspPort') };
}

// Reads the device's current ports, trying the API its class suggests first
// (IPCAMERA → www.ipc.com, else NVMS-9000) and falling back to the other, so an
// OEM that reports an unexpected device type still works. Undefined when
// neither API answers with a usable port list.
async function readTvtPorts(native: NativeAddon, sessionId: number, deviceType: number): Promise<TvtPortState | undefined> {
  const readNvr = async (): Promise<TvtPortState | undefined> => {
    const q = await native.transparent(sessionId, 'queryNetPortCfg', TVT_EMPTY_REQUEST);
    if (q.ok && q.xml && xmlText(q.xml, 'status') === 'success') {
      return { api: 'nvr', xml: q.xml, current: tvtPortsFrom(q.xml), reserved: xmlText(q.xml, 'reservedPort') ?? '' };
    }
    return undefined;
  };
  const readIpc = async (): Promise<TvtPortState | undefined> => {
    const g = await native.transparent(sessionId, 'GetPortConfig', '');
    // The www.ipc.com reply has no <status> element — a failure is an attribute
    // (status="failed"); a good reply carries the <port> block with <netPort>.
    if (g.ok && g.xml && /<netPort[\s>]/i.test(g.xml) && !/\bstatus="failed"/i.test(g.xml)) {
      return { api: 'ipc', xml: g.xml, current: tvtPortsFrom(g.xml), reserved: '' };
    }
    return undefined;
  };
  const order = deviceType === 2 ? [readIpc, readNvr] : [readNvr, readIpc];
  for (const read of order) {
    const state = await read();
    if (state) return state;
  }
  return undefined;
}

// Replaces a leaf tag's text in place, keeping any attributes (the www.ipc.com
// tags carry type="uint16"), for the IPC read-modify-write.
function setXmlTag(xml: string, tag: string, value: number): string {
  return xml.replace(new RegExp(`(<${tag}(?:\\s[^>]*)?>)[^<]*(</${tag}>)`), `$1${value}$2`);
}

// The request that writes the changed ports back, in the device's own schema.
function buildTvtPortEdit(state: TvtPortState, changed: TvtPortState['current']): { command: string; body: string } {
  if (state.api === 'ipc') {
    let body = setXmlTag(state.xml, 'httpPort', changed.http);
    body = setXmlTag(body, 'httpsPort', changed.https);
    body = setXmlTag(body, 'netPort', changed.net);
    body = setXmlTag(body, 'rtspPort', changed.rtsp);
    return { command: 'SetPortConfig', body };
  }
  // NVR: send back everything the device reported, with only the requested
  // ports replaced — optional fields only if the device has them.
  const optional = ['posPort', 'anonymousAccess', 'virtualHostEnabled']
    .map((tag) => [tag, xmlText(state.xml, tag)] as const)
    .filter(([, value]) => value !== undefined)
    .map(([tag, value]) => `<${tag}>${value}</${tag}>`)
    .join('');
  const body =
    `${TVT_REQUEST_OPEN}<content><httpPort>${changed.http}</httpPort><httpsPort>${changed.https}</httpsPort>` +
    `<netPort>${changed.net}</netPort><rtspPort>${changed.rtsp}</rtspPort>${optional}</content></request>`;
  return { command: 'editNetPortCfg', body };
}

// The edit reply's status: an element <status>success</status> on the NVR, an
// attribute status="success" on <config> for the IPC.
function tvtEditStatus(api: TvtPortApi, xml: string | undefined): string | undefined {
  if (!xml) return undefined;
  return api === 'ipc' ? xml.match(/<config[^>]*\bstatus="([^"]*)"/i)?.[1] : xmlText(xml, 'status');
}

function tvtEditErrorCode(api: TvtPortApi, xml: string | undefined): string | undefined {
  if (!xml) return undefined;
  return api === 'ipc' ? xml.match(/\berrorCode="([^"]*)"/i)?.[1] : xmlText(xml, 'errorCode');
}

async function changeTvtPorts(device: NativeDiscoveredDevice, request: ModifyNetworkRequest, wanted: PortSettings): Promise<ModifyNetworkResult> {
  const native = loadNative();
  const login = await native.login({ host: device.host, port: device.port, username: request.username, password: request.password });
  if (!login.ok || login.sessionId === undefined) {
    const code = login.errorCode ?? 0;
    return { ok: false, error: TVT_LOGIN_ERRORS[code] ?? `Couldn't log in to the device (TVT error ${code}).` };
  }
  const sessionId = login.sessionId;
  const changed = { http: 0, https: 0, net: 0, rtsp: 0 };
  try {
    const state = await readTvtPorts(native, sessionId, device.deviceType);
    if (!state) {
      return { ok: false, error: "This TVT device didn't return its port settings, so its ports can't be changed from here." };
    }
    changed.http = wanted.http ?? state.current.http;
    changed.https = wanted.https ?? state.current.https;
    changed.net = wanted.device ?? state.current.net;
    changed.rtsp = wanted.rtsp ?? state.current.rtsp;
    const netPortChanged = changed.net !== state.current.net;

    // The device's own web-UI checks: range, no two the same, none reserved.
    const portsForCheck: Record<string, number> = { httpPort: changed.http, httpsPort: changed.https, netPort: changed.net, rtspPort: changed.rtsp };
    if (state.api === 'nvr') {
      const pos = Number(xmlText(state.xml, 'posPort') ?? 0);
      if (pos > 0) portsForCheck.posPort = pos;
    }
    const problem = tvtPortProblem(portsForCheck, state.reserved);
    if (problem) return { ok: false, error: problem };

    const { command, body } = buildTvtPortEdit(state, changed);
    const edit = await native.transparent(sessionId, command, body);
    const editStatus = tvtEditStatus(state.api, edit.xml);
    if (editStatus !== 'success') {
      // Changing the device port (netPort) restarts the service this very login
      // session runs over, so the device often drops the connection before its
      // reply reaches us — a lost reply, not a refusal. (Confirmed by the
      // symptom: HTTP-only changes, which don't restart that service, always
      // reply cleanly; the device port, 9008 on IPCs, is where the session
      // lives.) A lost reply falls through to the re-search below, which
      // confirms the change from the device's own discovery reply. Only a reply
      // that actually came back with a non-success status, or a failure on a
      // change that isn't the device port, is a real refusal.
      const deviceAnswered = editStatus !== undefined;
      if (deviceAnswered || !netPortChanged) {
        const code = tvtEditErrorCode(state.api, edit.xml) ?? edit.errorCode;
        return { ok: false, error: `The device refused the port change${code ? ` (TVT error ${code})` : ''}.` };
      }
    }
  } finally {
    // The session may already be gone if the device port just changed.
    await native.logout(sessionId).catch(() => undefined);
  }

  // HTTP and device ports show up in TVT's own search reply, so those can
  // be confirmed; HTTPS/RTSP rest on the device's "success".
  if (wanted.http === undefined && wanted.device === undefined) return { ok: true };
  const { matched } = await searchUntil(device.mac, (d) => d.httpPort === changed.http && d.port === changed.net);
  if (matched) return { ok: true };
  return {
    ok: true,
    warning: `The port change was sent, but the device's search reply hasn't shown the new ports yet (HTTP ${changed.http}, device ${changed.net}). Rescan in a minute to check.`,
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
