import type { ModifyNetworkRequest, ModifyNetworkResult, NetworkSettings, PortKind, PortSettings, RebootRequest } from '../../shared/types';
import { normalizeMac, waitForMacAt } from './arpLookup';
import { deviceHttpRequest } from './deviceHttp';
import { digestAuthorization, pickDigestChallenge } from './httpDigest';
import { hasGateway, isOnLocalSubnet } from './networkInterfaces';
import { lastScanMacFor, lastScanRowsFor } from './scanResults';

// Axis network settings through VAPIX, the HTTP API the camera's own web
// page uses (HTTP Digest, the same transport as Hikvision's ISAPI). Axis
// ships with ONVIF control disabled by default (newer firmware), so the
// generic ONVIF route can't be relied on for an out-of-the-box Axis camera —
// but VAPIX answers on the ordinary admin login whether or not ONVIF is on.
// Like ISAPI, it's plain HTTP to the device's current address, so it only
// reaches devices inside the PC's own subnet (an Axis row also keeps its
// ONVIF sibling, so the Edit dialog can still offer the ONVIF retry).
//
// Everything goes through /axis-cgi/param.cgi, the parameter CGI:
//   - read:   action=list&group=Network  → "Network.<name>=<value>" lines;
//   - write:  action=update&Network.<name>=<value>&…
// The exact port parameter names vary by AXIS OS version, so the ones to
// write are taken from what the read reports (Network.HTTP.Port /
// Network.HTTPS.Port / Network.RTSP.Port), never hard-coded — the same
// read-then-edit approach as the Hikvision/Uniview routes. Addressing uses
// the long-standing Network.BootProto / IPAddress / SubnetMask /
// DefaultRouter parameters. A reboot (restart.cgi) is only for the Reboot
// action; Axis applies network and port changes without one.

const PARAM_PATH = '/axis-cgi/param.cgi';
// restart.cgi is the classic path; newer firmware moved it under /admin.
const RESTART_PATHS = ['/axis-cgi/restart.cgi', '/axis-cgi/admin/restart.cgi'];

const REQUEST_TIMEOUT_MS = 6000;
const VERIFY_TIMEOUT_MS = 30000;

const PORT_PARAMS: Record<PortKind, RegExp | undefined> = {
  http: /(?:^|\.)Network\.HTTP\.Port$/i,
  https: /(?:^|\.)Network\.HTTPS\.Port$/i,
  rtsp: /(?:^|\.)Network\.RTSP\.Port$/i,
  // Axis has no single "device/SDK port" the way Dahua/TVT do.
  device: undefined,
};
const PORT_LABELS: Record<PortKind, string> = { http: 'HTTP', https: 'HTTPS', rtsp: 'RTSP', device: 'Device' };

interface Target {
  host: string;
  port: number;
}

interface Credentials {
  username: string;
  password: string;
}

class VapixError extends Error {
  constructor(
    message: string,
    readonly kind: 'auth' | 'network' | 'refused' | 'missing',
  ) {
    super(message);
  }
}

// ---- param.cgi ----

// Query string shared by the request URL and the Digest `uri` (they must be
// byte-identical). Parameter names (Network.IPAddress, …) are safe
// unencoded; only the values are escaped.
function buildQuery(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join('&');
}

// One param.cgi call (always GET): unauthenticated first, then once with
// HTTP Digest when the camera answers 401 with a challenge — never retried
// with the same credentials after a refusal. Returns the reply body.
async function paramCgi(at: Target, params: Record<string, string>, creds: Credentials): Promise<string> {
  const pathWithQuery = `${PARAM_PATH}?${buildQuery(params)}`;
  const send = async (authorization?: string): Promise<{ status: number; body: string; challenges: string[] }> => {
    try {
      return await deviceHttpRequest(`http://${at.host}:${at.port}${pathWithQuery}`, {
        method: 'GET',
        headers: authorization ? { Authorization: authorization } : {},
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch (e) {
      throw new VapixError(`No response from the camera (${e instanceof Error ? e.message : String(e)}).`, 'network');
    }
  };

  let res = await send();
  if (res.status === 401) {
    const challenge = pickDigestChallenge(res.challenges);
    // Basic auth would send the password in the clear over plain HTTP.
    if (!challenge) {
      throw new VapixError("The camera didn't offer Digest login (its web authentication may be set to Basic only), so the password wasn't sent.", 'auth');
    }
    res = await send(digestAuthorization(challenge, 'GET', pathWithQuery, creds.username, creds.password));
  }
  if (res.status === 401) throw new VapixError('Wrong username or password.', 'auth');
  if (res.status === 404) throw new VapixError("The camera doesn't provide the VAPIX parameter API (param.cgi).", 'missing');
  if (res.status < 200 || res.status >= 300) throw new VapixError(`The camera refused the request (HTTP ${res.status}).`, 'refused');
  // param.cgi answers 200 even for some errors, with a "# Error: …" body.
  const error = res.body.match(/(?:^|\n)\s*(?:#\s*)?(?:Error|Request failed)\s*:?\s*(.+)/i);
  if (error) throw new VapixError(`The camera reported: ${error[1].trim()}`, 'refused');
  return res.body;
}

// "Network.<name>=<value>" lines (the leading "root." some firmware adds is
// kept — matchers ignore it) into a map.
function parseParams(body: string): Map<string, string> {
  const params = new Map<string, string>();
  for (const line of body.split(/\r?\n/)) {
    const eq = line.indexOf('=');
    if (eq > 0) params.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
  }
  return params;
}

function findParam(params: Map<string, string>, re: RegExp): { key: string; value: string } | undefined {
  for (const [key, value] of params) if (re.test(key)) return { key, value };
  return undefined;
}

// param.cgi accepts the parameter name with or without the "root." prefix on
// a write; use the bare form.
function writeKey(key: string): string {
  return key.replace(/^root\./i, '');
}

interface AxisNetwork {
  params: Map<string, string>;
  dhcp: boolean;
  ip?: string;
  subnetMask?: string;
  gateway?: string;
  mac?: string;
}

async function readNetwork(at: Target, creds: Credentials): Promise<AxisNetwork> {
  const params = parseParams(await paramCgi(at, { action: 'list', group: 'Network' }, creds));
  return {
    params,
    dhcp: findParam(params, /(?:^|\.)Network\.BootProto$/i)?.value.toLowerCase() === 'dhcp',
    ip: findParam(params, /(?:^|\.)Network\.IPAddress$/i)?.value,
    subnetMask: findParam(params, /(?:^|\.)Network\.SubnetMask$/i)?.value,
    gateway: findParam(params, /(?:^|\.)Network\.DefaultRouter$/i)?.value,
    mac: normalizeMac(findParam(params, /(?:^|\.)Network\.(?:eth0\.)?MACAddress$/i)?.value),
  };
}

// ---- Ports ----

// The port parameters to write and the values a read-back should then show —
// undefined when the camera already has them. Throws when it doesn't expose
// a parameter for a port the user is changing (so the dialog can offer the
// ONVIF retry for the web ports).
function editedPorts(net: AxisNetwork, wanted: PortSettings): { params: Record<string, string>; expected: [string, number][] } | undefined {
  const kinds = (Object.keys(wanted) as PortKind[]).filter((k) => wanted[k] !== undefined);
  const update: Record<string, string> = {};
  const expected: [string, number][] = [];
  // The camera's current web/RTSP ports, so a changed one isn't put on top
  // of another service's port.
  const current = new Map<PortKind, number>();
  for (const kind of ['http', 'https', 'rtsp'] as PortKind[]) {
    const re = PORT_PARAMS[kind];
    const found = re && findParam(net.params, re);
    if (found && Number.isInteger(Number(found.value))) current.set(kind, Number(found.value));
  }

  for (const kind of kinds) {
    const re = PORT_PARAMS[kind];
    const found = re && findParam(net.params, re);
    if (!found) throw new VapixError(`The camera doesn't expose a ${PORT_LABELS[kind]} port parameter over VAPIX, so it can't be changed from here.`, 'refused');
    const value = wanted[kind] as number;
    if (current.get(kind) === value) continue;
    update[writeKey(found.key)] = String(value);
    expected.push([found.key, value]);
    current.set(kind, value);
  }
  if (expected.length === 0) return undefined;

  const seen = new Map<number, PortKind>();
  for (const [kind, value] of current) {
    const clash = seen.get(value);
    if (clash) throw new VapixError(`${PORT_LABELS[clash]} and ${PORT_LABELS[kind]} ports can't both be ${value}.`, 'refused');
    seen.set(value, kind);
  }
  return { params: update, expected };
}

async function waitForPorts(at: Target, creds: Credentials, expected: [string, number][], timeoutMs: number): Promise<'match' | 'mismatch' | 'unreachable'> {
  const deadline = Date.now() + timeoutMs;
  let answered = false;
  while (Date.now() < deadline) {
    try {
      const params = (await readNetwork(at, creds)).params;
      answered = true;
      if (expected.every(([key, port]) => Number(params.get(key) ?? params.get(writeKey(key))) === port)) return 'match';
    } catch (e) {
      // A refused login stops the polling; anything else is the camera
      // restarting its web server — keep polling.
      if (e instanceof VapixError && e.kind === 'auth') {
        throw new VapixError("The camera refused the login while the change was being checked, so it couldn't be confirmed — check it from its web page.", 'auth');
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return answered ? 'mismatch' : 'unreachable';
}

// ---- Addressing ----

// The address parameters to write, or undefined when the camera already has
// them. A blank or 0.0.0.0 gateway keeps the camera's current one, as on the
// other routes.
function editedAddress(net: AxisNetwork, settings: NetworkSettings): Record<string, string> | undefined {
  if (settings.dhcp) return net.dhcp ? undefined : { 'Network.BootProto': 'dhcp' };
  const gateway = hasGateway(settings.gateway) ? settings.gateway : undefined;
  const sameAddress = !net.dhcp && net.ip === settings.ip && net.subnetMask === settings.subnetMask;
  if (sameAddress && (!gateway || net.gateway === gateway)) return undefined;
  const update: Record<string, string> = {
    'Network.BootProto': 'none',
    'Network.IPAddress': settings.ip,
    'Network.SubnetMask': settings.subnetMask,
  };
  if (gateway) update['Network.DefaultRouter'] = gateway;
  return update;
}

// A param.cgi write. The camera may drop the connection before replying when
// a change moves its web server or its address, so no reply is 'unanswered'
// rather than a failure — the checks afterwards decide.
async function sendUpdate(at: Target, params: Record<string, string>, creds: Credentials): Promise<'ok' | 'unanswered'> {
  try {
    await paramCgi(at, { action: 'update', ...params }, creds);
    return 'ok';
  } catch (e) {
    if (e instanceof VapixError && e.kind === 'network') return 'unanswered';
    throw e;
  }
}

// ---- Reboot ----

async function restart(at: Target, creds: Credentials): Promise<void> {
  let lastMissing: VapixError | undefined;
  for (const path of RESTART_PATHS) {
    try {
      await deviceHttpRequestWithDigest(at, path, creds);
      return;
    } catch (e) {
      if (e instanceof VapixError && e.kind === 'network') return; // went down mid-reply — that's the reboot
      if (e instanceof VapixError && e.kind === 'missing') {
        lastMissing = e;
        continue; // try the other restart path
      }
      throw e;
    }
  }
  throw lastMissing ?? new VapixError("The camera doesn't provide a restart endpoint over VAPIX — reboot it from its web page.", 'missing');
}

// A plain Digest GET to a non-param.cgi CGI (restart.cgi).
async function deviceHttpRequestWithDigest(at: Target, path: string, creds: Credentials): Promise<void> {
  const send = async (authorization?: string): ReturnType<typeof deviceHttpRequest> =>
    deviceHttpRequest(`http://${at.host}:${at.port}${path}`, {
      method: 'GET',
      headers: authorization ? { Authorization: authorization } : {},
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  let res;
  try {
    res = await send();
    if (res.status === 401) {
      const challenge = pickDigestChallenge(res.challenges);
      if (!challenge) throw new VapixError("The camera didn't offer Digest login, so the password wasn't sent.", 'auth');
      res = await send(digestAuthorization(challenge, 'GET', path, creds.username, creds.password));
    }
  } catch (e) {
    if (e instanceof VapixError) throw e;
    throw new VapixError(`No response from the camera (${e instanceof Error ? e.message : String(e)}).`, 'network');
  }
  if (res.status === 401) throw new VapixError('Wrong username or password.', 'auth');
  if (res.status === 404) throw new VapixError(`The camera doesn't provide ${path}.`, 'missing');
  if (res.status < 200 || res.status >= 300) throw new VapixError(`The camera refused the reboot (HTTP ${res.status}).`, 'refused');
}

// The Actions column's Reboot: the Network group is read first, which proves
// the login and checks it's the scanned device before anything is rebooted.
export async function rebootAxisDevice(request: RebootRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Axis');
  if (!row) return { ok: false, error: 'This device is no longer in the Axis results. Scan again and retry.' };
  const at: Target = { host: request.host, port: row.currentPorts?.http ?? row.httpPort ?? 80 };
  const creds: Credentials = { username: request.username, password: request.password };
  try {
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const net = await readNetwork(at, creds);
    if (scannedMac && net.mac && net.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${net.mac}) isn't the one the scan found (${scannedMac}). Nothing was rebooted — rescan and try again.` };
    }
    await restart(at, creds);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---- Modify ----

export async function modifyAxisDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Axis');
  if (!row) return { ok: false, error: 'This device is no longer in the Axis results. Scan again and retry.' };
  const creds: Credentials = { username: request.username, password: request.password };
  const settings = request.network;
  const wanted = request.ports && Object.keys(request.ports).length > 0 ? request.ports : undefined;
  let at: Target = { host: request.host, port: row.currentPorts?.http ?? row.httpPort ?? 80 };

  // What's already been applied, so a later failure never reads as "nothing
  // happened".
  const applied: string[] = [];
  const withApplied = (result: ModifyNetworkResult): ModifyNetworkResult => {
    if (applied.length === 0) return result;
    const what = `The ${applied.join(' and ')} ${applied.length > 1 || applied[0].endsWith('s') ? 'were' : 'was'}`;
    if (!result.ok) return { ok: false, error: `${what} already changed, but then: ${result.error}` };
    return result.warning ? { ok: true, warning: `${what} changed. ${result.warning}` } : result;
  };

  try {
    // Read first: proves the login, confirms it's the scanned device, and
    // gives the current values and the exact port parameter names.
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const net = await readNetwork(at, creds);
    if (scannedMac && net.mac && net.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${net.mac}) isn't the one the scan found (${scannedMac}). Nothing was changed — rescan and try again.` };
    }
    const mac = net.mac ?? scannedMac;
    const ports = wanted ? editedPorts(net, wanted) : undefined;
    const address = settings ? editedAddress(net, settings) : undefined;
    const httpExpected = ports?.expected.find(([key]) => PORT_PARAMS.http?.test(key));
    const newHttp = httpExpected?.[1] ?? at.port;

    // ---- Ports first (while the camera is still at its current address) ----
    if (ports) {
      await sendUpdate(at, ports.params, creds);
      // The web server may move to the new HTTP port; check there, then fall
      // back to the old port in case it applied without moving.
      let check = await waitForPorts({ ...at, port: newHttp }, creds, ports.expected, VERIFY_TIMEOUT_MS);
      if (check === 'match') at = { ...at, port: newHttp };
      else if (check === 'unreachable' && newHttp !== at.port) check = await waitForPorts(at, creds, ports.expected, 4000);
      const skipped = address ? ` The ${settings?.dhcp ? 'DHCP' : 'IP'} change wasn't sent.` : '';
      if (check === 'mismatch') return { ok: false, error: `The camera answered but kept its old ports — the change didn't take.${skipped}` };
      if (check === 'unreachable') {
        return {
          ok: true,
          warning: `The port change was sent, but the camera hasn't answered since${newHttp !== at.port ? ` (checked HTTP port ${newHttp} and the old one)` : ''}.${skipped} Rescan in a minute to check.`,
        };
      }
      applied.push('ports');
    }

    if (!address) return { ok: true };

    // ---- Addressing ----
    await sendUpdate(at, address, creds);

    if (settings?.dhcp) {
      applied.push('DHCP setting');
      // The DHCP server picks the address; it can't be confirmed from here
      // without rediscovering the camera, so the tech rescans.
      return {
        ok: true,
        message: "It was switched to DHCP. Its address now comes from the network's DHCP server — make sure this network has one, and rescan in a minute to find it.",
      };
    }

    applied.push('IP settings');
    const newIp = settings!.ip;
    if (!mac || !isOnLocalSubnet(newIp)) {
      return withApplied({
        ok: true,
        warning: `The camera accepted the change, but it can't be confirmed from this PC${isOnLocalSubnet(newIp) ? '' : " (the new IP is outside this PC's subnet)"}. Its web page should be at ${newIp}.`,
      });
    }
    if (!(await waitForMacAt(newIp, newHttp, mac, VERIFY_TIMEOUT_MS))) {
      return withApplied({ ok: true, warning: `The camera accepted the change, but hasn't shown up at ${newIp} yet. Rescan in a minute to check.` });
    }
    return { ok: true };
  } catch (e) {
    return withApplied({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
}

// The camera's current mask/gateway/DHCP for pre-filling the Edit dialog —
// read over VAPIX with the login the user entered (Axis reveals none of this
// without one, and ONVIF is often off). The "Load current settings" button.
export async function readAxisNetworkForPrefill(
  host: string,
  httpPort: number,
  creds: Credentials,
): Promise<{ subnetMask?: string; gateway?: string; dhcp?: boolean; error?: string }> {
  try {
    const net = await readNetwork({ host, port: httpPort }, creds);
    return { subnetMask: net.subnetMask, gateway: net.gateway, dhcp: net.dhcp };
  } catch (e) {
    if (e instanceof VapixError) {
      if (e.kind === 'auth') return { error: 'Wrong username or password.' };
      if (e.kind === 'missing') return {};
      return { error: e.message };
    }
    return { error: e instanceof Error ? e.message : String(e) };
  }
}
