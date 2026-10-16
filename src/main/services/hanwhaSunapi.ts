import type { ModifyNetworkRequest, ModifyNetworkResult, NetworkSettings, PortKind, RebootRequest } from '../../shared/types';
import { normalizeMac, waitForMacAt } from './arpLookup';
import { deviceHttpRequest } from './deviceHttp';
import { digestAuthorization, pickDigestChallenge } from './httpDigest';
import { hasGateway, isOnLocalSubnet } from './networkInterfaces';
import { lastScanMacFor, lastScanRowsFor } from './scanResults';

// Hanwha (Wisenet) network settings through SUNAPI, the HTTP API the camera's
// own web UI and Hanwha's Device Manager use (HTTP Digest, realm "iPolis_…").
// Confirmed live on an XNV-6011 (CGIVersion 2.5.6): the admin login answers
// SUNAPI whether or not an ONVIF user exists, so it's preferred over ONVIF for
// edits — same model as the Axis/VAPIX and Hikvision/ISAPI routes. Plain HTTP
// to the camera's current address, so same-subnet only (a Hanwha row keeps its
// ONVIF sibling, so the Edit dialog can still offer the ONVIF retry).
//
// Everything is a GET on /stw-cgi/<cgi>.cgi?msubmenu=<x>&action=<view|set>:
//   - IP/mask/gateway/DHCP: network.cgi?msubmenu=interface — IPv4Type
//     (Manual|DHCP), IPv4Address, IPv4SubnetMask, IPv4Gateway (keyed to
//     InterfaceName, e.g. NetworkInterface1).
//   - ports: network.cgi?msubmenu=http | https | rtsp, each a single Port=
//     field. Hanwha has no separate vendor "device" port.
// A set replies with an empty 200 on success, or a body starting with "NG"
// and an "Error Code:" line on failure.

const NETWORK_CGI = '/stw-cgi/network.cgi';
const SYSTEM_CGI = '/stw-cgi/system.cgi';

const REQUEST_TIMEOUT_MS = 6000;
const VERIFY_TIMEOUT_MS = 30000;

// Which SUNAPI network submenu holds each port. No "device" port on Hanwha.
const PORT_SUBMENU: Record<PortKind, string | undefined> = { http: 'http', https: 'https', rtsp: 'rtsp', device: undefined };
const PORT_LABELS: Record<PortKind, string> = { http: 'HTTP', https: 'HTTPS', rtsp: 'RTSP', device: 'Device' };

interface Target {
  host: string;
  port: number;
}
interface Credentials {
  username: string;
  password: string;
}

class SunapiError extends Error {
  constructor(
    message: string,
    readonly kind: 'auth' | 'network' | 'refused',
  ) {
    super(message);
  }
}

// Query string shared by the request URL and the Digest `uri` (they must be
// byte-identical). Parameter names are safe unencoded; only values are escaped.
function buildQuery(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join('&');
}

// One SUNAPI call (always GET): unauthenticated first, then once with HTTP
// Digest when the camera answers 401 — never retried after a refusal. Returns
// the reply body.
async function sunapi(at: Target, cgi: string, params: Record<string, string>, creds: Credentials): Promise<string> {
  const pathWithQuery = `${cgi}?${buildQuery(params)}`;
  const send = async (authorization?: string): Promise<{ status: number; body: string; challenges: string[] }> => {
    try {
      return await deviceHttpRequest(`http://${at.host}:${at.port}${pathWithQuery}`, {
        method: 'GET',
        headers: authorization ? { Authorization: authorization } : {},
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch (e) {
      throw new SunapiError(`No response from the camera (${e instanceof Error ? e.message : String(e)}).`, 'network');
    }
  };

  let res = await send();
  if (res.status === 401) {
    const challenge = pickDigestChallenge(res.challenges);
    if (!challenge) throw new SunapiError("The camera didn't offer Digest login, so the password wasn't sent.", 'auth');
    res = await send(digestAuthorization(challenge, 'GET', pathWithQuery, creds.username, creds.password));
  }
  if (res.status === 401) throw new SunapiError('Wrong username or password.', 'auth');
  if (res.status === 404) throw new SunapiError("The camera doesn't provide this SUNAPI command.", 'refused');
  if (res.status < 200 || res.status >= 300) throw new SunapiError(`The camera refused the request (HTTP ${res.status}).`, 'refused');
  // SUNAPI answers 200 even for some errors, with a "NG … Error Code: N" body.
  const body = res.body ?? '';
  if (/^\s*NG\b/.test(body)) {
    const code = body.match(/Error Code:\s*(\d+)/i)?.[1];
    throw new SunapiError(`The camera rejected the command${code ? ` (error ${code})` : ''}.`, 'refused');
  }
  return body;
}

// "Key=Value" lines into a map.
function parseKv(body: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of body.split(/\r?\n/)) {
    const eq = line.indexOf('=');
    if (eq > 0) map.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
  }
  return map;
}

interface HanwhaInterface {
  interfaceName: string;
  dhcp: boolean;
  ip?: string;
  subnetMask?: string;
  gateway?: string;
  mac?: string;
}

async function readInterface(at: Target, creds: Credentials): Promise<HanwhaInterface> {
  const kv = parseKv(await sunapi(at, NETWORK_CGI, { msubmenu: 'interface', action: 'view' }, creds));
  return {
    interfaceName: kv.get('InterfaceName') ?? 'NetworkInterface1',
    dhcp: (kv.get('IPv4Type') ?? '').toLowerCase() === 'dhcp',
    ip: kv.get('IPv4Address'),
    subnetMask: kv.get('IPv4SubnetMask'),
    gateway: kv.get('IPv4Gateway'),
    mac: normalizeMac(kv.get('MACAddress')),
  };
}

async function readPort(at: Target, submenu: string, creds: Credentials): Promise<number | undefined> {
  const port = Number(parseKv(await sunapi(at, NETWORK_CGI, { msubmenu: submenu, action: 'view' }, creds)).get('Port'));
  return Number.isInteger(port) ? port : undefined;
}

async function waitForPort(at: Target, submenu: string, expected: number, timeoutMs: number, creds: Credentials): Promise<'match' | 'mismatch' | 'unreachable'> {
  const deadline = Date.now() + timeoutMs;
  let answered = false;
  while (Date.now() < deadline) {
    try {
      const port = await readPort(at, submenu, creds);
      answered = true;
      if (port === expected) return 'match';
    } catch (e) {
      if (e instanceof SunapiError && e.kind === 'auth') {
        throw new SunapiError("The camera refused the login while the change was being checked — check it from its web page.", 'auth');
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return answered ? 'mismatch' : 'unreachable';
}

// The interface params to write, or undefined when the camera already has them.
// A blank or 0.0.0.0 gateway keeps the camera's current one.
function editedAddress(iface: HanwhaInterface, net: NetworkSettings): Record<string, string> | undefined {
  if (net.dhcp) return iface.dhcp ? undefined : { msubmenu: 'interface', action: 'set', InterfaceName: iface.interfaceName, IPv4Type: 'DHCP' };
  const gateway = hasGateway(net.gateway) ? net.gateway : undefined;
  const sameAddress = !iface.dhcp && iface.ip === net.ip && iface.subnetMask === net.subnetMask;
  if (sameAddress && (!gateway || iface.gateway === gateway)) return undefined;
  const params: Record<string, string> = {
    msubmenu: 'interface',
    action: 'set',
    InterfaceName: iface.interfaceName,
    IPv4Type: 'Manual',
    IPv4Address: net.ip,
    IPv4SubnetMask: net.subnetMask,
  };
  if (gateway) params.IPv4Gateway = gateway;
  return params;
}

// A set whose reply may be lost when the change moves the web server (HTTP
// port) or the address — no reply is 'unanswered', decided by the checks after.
async function sendSet(at: Target, params: Record<string, string>, creds: Credentials): Promise<'ok' | 'unanswered'> {
  try {
    await sunapi(at, NETWORK_CGI, params, creds);
    return 'ok';
  } catch (e) {
    if (e instanceof SunapiError && e.kind === 'network') return 'unanswered';
    throw e;
  }
}

// ---- Reboot ----

export async function rebootHanwhaDevice(request: RebootRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Hanwha');
  if (!row) return { ok: false, error: 'This device is no longer in the Hanwha results. Scan again and retry.' };
  const at: Target = { host: request.host, port: row.currentPorts?.http ?? row.httpPort ?? 80 };
  const creds: Credentials = { username: request.username, password: request.password };
  try {
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const iface = await readInterface(at, creds);
    if (scannedMac && iface.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was rebooted — rescan and try again.` };
    }
    try {
      await sunapi(at, SYSTEM_CGI, { msubmenu: 'reboot', action: 'control' }, creds);
    } catch (e) {
      // The camera may drop the connection as it goes down — that's the reboot.
      if (!(e instanceof SunapiError && e.kind === 'network')) throw e;
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---- Modify ----

export async function modifyHanwhaDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Hanwha');
  if (!row) return { ok: false, error: 'This device is no longer in the Hanwha results. Scan again and retry.' };
  const creds: Credentials = { username: request.username, password: request.password };
  const net = request.network;
  const wanted = request.ports && Object.keys(request.ports).length > 0 ? request.ports : undefined;
  let at: Target = { host: request.host, port: row.currentPorts?.http ?? row.httpPort ?? 80 };

  const applied: string[] = [];
  const withApplied = (result: ModifyNetworkResult): ModifyNetworkResult => {
    if (applied.length === 0) return result;
    const what = `The ${applied.join(' and ')} ${applied.length > 1 || applied[0].endsWith('s') ? 'were' : 'was'}`;
    if (!result.ok) return { ok: false, error: `${what} already changed, but then: ${result.error}` };
    return result.warning ? { ok: true, warning: `${what} changed. ${result.warning}` } : result;
  };

  try {
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const iface = await readInterface(at, creds);
    if (scannedMac && iface.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was changed — rescan and try again.` };
    }
    const mac = iface.mac ?? scannedMac;

    // Which ports actually change, and to what (reading each submenu's current
    // value). HTTP is applied last, since changing it moves the web server.
    const kinds = wanted ? (Object.keys(wanted) as PortKind[]).filter((k) => wanted[k] !== undefined && PORT_SUBMENU[k]) : [];
    const portChanges: { kind: PortKind; submenu: string; value: number }[] = [];
    for (const kind of kinds) {
      const submenu = PORT_SUBMENU[kind] as string;
      const current = await readPort(at, submenu, creds);
      if (current !== (wanted?.[kind] as number)) portChanges.push({ kind, submenu, value: wanted?.[kind] as number });
    }
    // No two of the changed/kept web ports on the same number.
    const finalPorts = new Map<PortKind, number>();
    for (const kind of ['http', 'https', 'rtsp'] as PortKind[]) {
      const changed = portChanges.find((p) => p.kind === kind);
      const value = changed ? changed.value : await readPort(at, PORT_SUBMENU[kind] as string, creds);
      if (value !== undefined) finalPorts.set(kind, value);
    }
    const seen = new Map<number, PortKind>();
    for (const [kind, value] of finalPorts) {
      const clash = seen.get(value);
      if (clash) return { ok: false, error: `${PORT_LABELS[clash]} and ${PORT_LABELS[kind]} ports can't both be ${value}.` };
      seen.set(value, kind);
    }

    const nonHttp = portChanges.filter((p) => p.kind !== 'http');
    const httpChange = portChanges.find((p) => p.kind === 'http');
    const address = net ? editedAddress(iface, net) : undefined;
    const newHttp = httpChange?.value ?? at.port;

    // ---- Non-HTTP ports (verified at the current address) ----
    for (const change of nonHttp) {
      await sendSet(at, { msubmenu: change.submenu, action: 'set', Port: String(change.value) }, creds);
      const check = await waitForPort(at, change.submenu, change.value, VERIFY_TIMEOUT_MS, creds);
      if (check === 'mismatch') return withApplied({ ok: false, error: `The ${PORT_LABELS[change.kind]} port change didn't take — the camera kept its old port.` });
      if (check === 'unreachable') return withApplied({ ok: true, warning: `The ${PORT_LABELS[change.kind]} port change was sent, but the camera hasn't answered since. Rescan in a minute to check.` });
      applied.push(`${PORT_LABELS[change.kind]} port`);
    }

    // ---- HTTP port (moves the web server) ----
    if (httpChange) {
      await sendSet(at, { msubmenu: 'http', action: 'set', Port: String(httpChange.value) }, creds);
      let check = await waitForPort({ ...at, port: newHttp }, 'http', newHttp, VERIFY_TIMEOUT_MS, creds);
      if (check === 'unreachable') check = await waitForPort(at, 'http', newHttp, 4000, creds); // in case it applied without moving
      if (check === 'match') at = { ...at, port: newHttp };
      else if (check === 'mismatch') return withApplied({ ok: false, error: 'The HTTP port change didn\'t take — the camera kept its old port.' });
      else return withApplied({ ok: true, warning: `The HTTP port change was sent, but the camera hasn't answered on port ${newHttp} since. Rescan in a minute to check.` });
      applied.push('HTTP port');
    }

    if (!address) return { ok: true };

    // ---- Addressing ----
    await sendSet({ ...at }, address, creds);
    if (net?.dhcp) {
      applied.push('DHCP setting');
      return {
        ok: true,
        message: "It was switched to DHCP. Its address now comes from the network's DHCP server — make sure this network has one, and rescan in a minute to find it.",
      };
    }
    applied.push('IP settings');
    const newIp = net!.ip;
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
// read over SUNAPI with the login the user entered. The "Load current
// settings" button.
export async function readHanwhaNetworkForPrefill(
  host: string,
  httpPort: number,
  creds: Credentials,
): Promise<{ subnetMask?: string; gateway?: string; dhcp?: boolean; error?: string }> {
  try {
    const iface = await readInterface({ host, port: httpPort }, creds);
    return { subnetMask: iface.subnetMask, gateway: iface.gateway, dhcp: iface.dhcp };
  } catch (e) {
    if (e instanceof SunapiError) {
      if (e.kind === 'auth') return { error: 'Wrong username or password.' };
      return { error: e.message };
    }
    return { error: e instanceof Error ? e.message : String(e) };
  }
}
