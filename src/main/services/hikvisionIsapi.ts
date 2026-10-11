import type { FactoryResetRequest, ModifyNetworkRequest, ModifyNetworkResult, NetworkSettings, PortKind, PortSettings, RebootRequest } from '../../shared/types';
import { normalizeMac, waitForMacAt } from './arpLookup';
import { deviceHttpRequest } from './deviceHttp';
import { digestAuthorization, pickDigestChallenge } from './httpDigest';
import { hasGateway, isOnLocalSubnet } from './networkInterfaces';
import { discoverHikvisionDevices } from './sadpDiscovery';
import { lastScanMacFor, lastScanRowsFor } from './scanResults';

// Hikvision network settings through ISAPI, the HTTP API the device's own
// web page uses (HTTP Digest). A read-only probe of the test camera (a
// CMIP1042-28 found by SADP) showed why: Hikvision ships with ONVIF off,
// while ISAPI answered 401 with a Digest challenge. SADP's own modify
// command isn't used — how it carries the password isn't documented. Like
// ONVIF, ISAPI is plain HTTP to the device's current address, so it only
// reaches devices inside the PC's own subnet.
//
// Only what the web page itself changes is changed:
//   - IP/mask/gateway: the interface's <IPAddress> document, read and PUT
//     back with just those fields edited (DNS and IPv6 left as reported) —
//     or, for DHCP, just its addressingType set to "dynamic";
//   - ports: /ISAPI/Security/adminAccesses, the device's port list (HTTP,
//     HTTPS, RTSP, and DEV_MANAGE — the "Server Port" that SADP reports as
//     CommandPort), PUT back whole with just the port numbers edited.
// A change the device answers with "Reboot Required" (statusCode 7) is
// saved but not applied until a reboot, so the device is then rebooted —
// the step its web page offers after such a change.

const REQUEST_TIMEOUT_MS = 6000;
const VERIFY_TIMEOUT_MS = 30000;
const VERIFY_AFTER_REBOOT_TIMEOUT_MS = 180000;
// How long a device switched to DHCP gets to turn up with its new address,
// and how long before a reply from its old address counts as the new one
// (the DHCP server may well hand the same address back).
const DHCP_FIND_TIMEOUT_MS = 60000;
const DHCP_SETTLE_MS = 10000;

const INTERFACES_PATH = '/ISAPI/System/Network/interfaces';
const PORTS_PATH = '/ISAPI/Security/adminAccesses';
const REBOOT_PATH = '/ISAPI/System/reboot';

const PORT_PROTOCOLS: Record<PortKind, string> = { http: 'HTTP', https: 'HTTPS', rtsp: 'RTSP', device: 'DEV_MANAGE' };
const PORT_LABELS: Record<string, string> = { HTTP: 'HTTP', HTTPS: 'HTTPS', RTSP: 'RTSP', DEV_MANAGE: 'Device' };

interface Target {
  host: string;
  port: number;
}

interface Credentials {
  username: string;
  password: string;
}

class IsapiError extends Error {
  constructor(
    message: string,
    readonly kind: 'auth' | 'network' | 'refused',
  ) {
    super(message);
  }
}

// ---- XML ----

const XML_TOKEN = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<[?!][^>]*>|<(\/?)(?:[\w.-]+:)?([\w.-]+)[^>]*?(\/?)>/g;

interface ElementRange {
  start: number;
  contentStart: number;
  contentEnd: number;
  end: number;
}

// Every element at `path` — the names of nested child elements below the
// document's root, namespace prefixes ignored. ISAPI documents reuse names
// at different depths (the interface's <ipAddress> and the one inside
// <DefaultGateway>), so elements are found by their place in the tree.
function findElements(xml: string, path: string[]): ElementRange[] {
  const found: ElementRange[] = [];
  const stack: string[] = [];
  let open: { depth: number; start: number; contentStart: number } | undefined;
  for (const m of xml.matchAll(XML_TOKEN)) {
    const [token, closing, name, selfClosing] = m;
    const index = m.index ?? 0;
    if (name === undefined || selfClosing) continue;
    if (closing) {
      if (open && stack.length === open.depth) {
        found.push({ start: open.start, contentStart: open.contentStart, contentEnd: index, end: index + token.length });
        open = undefined;
      }
      stack.pop();
      continue;
    }
    stack.push(name);
    if (!open && stack.length === path.length + 1 && path.every((p, i) => stack[i + 1] === p)) {
      open = { depth: stack.length, start: index, contentStart: index + token.length };
    }
  }
  return found;
}

function childText(xml: string, path: string[]): string | undefined {
  const [element] = findElements(xml, path);
  return element && xml.slice(element.contentStart, element.contentEnd).trim();
}

// `xml` with the text of the (leaf) element at `path` replaced, or
// undefined when there's no such element. The values set here are
// validated IPv4 addresses and port numbers, which need no escaping.
function withText(xml: string, path: string[], value: string): string | undefined {
  const [element] = findElements(xml, path);
  return element && xml.slice(0, element.contentStart) + value + xml.slice(element.contentEnd);
}

// ---- Requests ----

interface IsapiStatus {
  code: number;
  text: string;
  subCode: string;
}

// A <ResponseStatus> reply: statusCode 1 is OK and 7 "Reboot Required";
// anything else is a refusal, explained by statusString/subStatusCode.
function parseStatus(xml: string): IsapiStatus | undefined {
  if (!/<ResponseStatus\b/.test(xml)) return undefined;
  const code = Number(childText(xml, ['statusCode']));
  if (!Number.isInteger(code)) return undefined;
  return { code, text: childText(xml, ['statusString']) ?? '', subCode: childText(xml, ['subStatusCode']) ?? '' };
}

function describeStatus(status: IsapiStatus): string {
  if (status.text && status.subCode) return `${status.text} (${status.subCode})`;
  return status.text || status.subCode || `error ${status.code}`;
}

// Hikvision locks a PC out for a while after a few failed logins; say so,
// with how long or how many tries are left when the device reports it.
function loginRefused(body: string): string {
  if (/<lockStatus>\s*lock\s*<\/lockStatus>/i.test(body)) {
    const seconds = Number(body.match(/<unlockTime>\s*(\d+)\s*</i)?.[1]);
    const wait = seconds > 0 ? `in about ${Math.ceil(seconds / 60)} minute${seconds > 60 ? 's' : ''}` : 'later';
    return `The device has locked out this PC after too many failed logins — try again ${wait}.`;
  }
  const left = Number(body.match(/<retryLoginTime>\s*(\d+)\s*</i)?.[1]);
  return left > 0
    ? `Wrong username or password. The device allows ${left} more attempt${left === 1 ? '' : 's'} before it locks this PC out for a while.`
    : 'Wrong username or password. (After several failed logins, Hikvision devices lock the PC out for a while.)';
}

// One ISAPI call: unauthenticated first, then once with HTTP Digest when
// the device answers 401 with a challenge — never retried with the same
// credentials after a refusal, because of the lockout above. Returns the
// reply body.
async function isapi(at: Target, method: 'GET' | 'PUT', path: string, creds: Credentials, body?: string): Promise<string> {
  const send = async (authorization?: string): Promise<{ status: number; body: string; challenges: string[] }> => {
    try {
      return await deviceHttpRequest(`http://${at.host}:${at.port}${path}`, {
        method,
        headers: {
          ...(body !== undefined ? { 'Content-Type': 'application/xml; charset=UTF-8' } : {}),
          ...(authorization ? { Authorization: authorization } : {}),
        },
        body,
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch (e) {
      throw new IsapiError(`No response from the device (${e instanceof Error ? e.message : String(e)}).`, 'network');
    }
  };

  let res = await send();
  if (res.status === 401) {
    const challenge = pickDigestChallenge(res.challenges);
    // Basic auth would send the password in the clear over plain HTTP.
    if (!challenge) {
      throw new IsapiError("The device didn't offer Digest login (its web authentication may be set to Basic only), so the password wasn't sent.", 'auth');
    }
    res = await send(digestAuthorization(challenge, method, path, creds.username, creds.password));
  }
  if (res.status === 401) throw new IsapiError(loginRefused(res.body), 'auth');
  if (res.status >= 200 && res.status < 300) return res.body;
  const status = parseStatus(res.body);
  if (res.status === 404 || status?.subCode === 'notSupport') throw new IsapiError(`The device doesn't support ${path}.`, 'refused');
  if (status?.subCode === 'lowPrivilege') throw new IsapiError(`The ${creds.username} account isn't allowed to change this — use the admin account.`, 'refused');
  const what = method === 'PUT' ? 'the change' : `the request for ${path}`;
  throw new IsapiError(`The device refused ${what}: ${status ? describeStatus(status) : `HTTP ${res.status}`}.`, 'refused');
}

// A change sent as a PUT. A device switching address, moving its web
// server or rebooting may drop the connection before replying, so no reply
// is 'unanswered' rather than a failure — the checks afterwards decide. An
// empty body is still sent as one (Content-Length: 0), not chunked.
async function sendChange(at: Target, path: string, creds: Credentials, body = ''): Promise<'ok' | 'reboot' | 'unanswered'> {
  let reply: string;
  try {
    reply = await isapi(at, 'PUT', path, creds, body);
  } catch (e) {
    if (e instanceof IsapiError && e.kind === 'network') return 'unanswered';
    throw e;
  }
  const status = parseStatus(reply);
  if (!status || status.code === 1) return 'ok';
  if (status.code === 7) return 'reboot';
  throw new IsapiError(`The device refused the change: ${describeStatus(status)}.`, 'refused');
}

// ---- Network interface ----

interface NetInterface {
  id: string;
  ip?: string;
  mac?: string;
}

// The interface the device was reached on: the one holding the address the
// PC talks to (an NVR can have two), else the scanned MAC's, else the only
// one it has.
async function readInterface(at: Target, creds: Credentials, scannedMac: string | undefined): Promise<NetInterface | undefined> {
  const xml = await isapi(at, 'GET', INTERFACES_PATH, creds);
  const interfaces = findElements(xml, ['NetworkInterface'])
    .map((element): NetInterface => {
      const block = xml.slice(element.start, element.end);
      return { id: childText(block, ['id']) ?? '', ip: childText(block, ['IPAddress', 'ipAddress']), mac: normalizeMac(childText(block, ['Link', 'MACAddress'])) };
    })
    // The id goes into a URL path.
    .filter((iface) => /^\d+$/.test(iface.id));
  return (
    interfaces.find((iface) => iface.ip === at.host) ??
    interfaces.find((iface) => scannedMac !== undefined && iface.mac === scannedMac) ??
    (interfaces.length === 1 ? interfaces[0] : undefined)
  );
}

// The interface's <IPAddress> document set to a static address with the
// new IP, mask and gateway, or to DHCP ("dynamic") — undefined when it
// already has them. A blank or 0.0.0.0 gateway keeps the device's current
// one, as on the other routes.
function editedIpAddress(xml: string, net: NetworkSettings): string | undefined {
  const gateway = hasGateway(net.gateway) ? net.gateway : undefined;
  const currentIp = childText(xml, ['ipAddress']);
  const currentMask = childText(xml, ['subnetMask']);
  const addressing = childText(xml, ['addressingType'])?.toLowerCase() ?? 'static';
  if (net.dhcp) {
    if (addressing === 'dynamic') return undefined;
    const edited = withText(xml, ['addressingType'], 'dynamic');
    if (!edited) throw new IsapiError("The device's IP settings have no addressing-type field, so DHCP can't be turned on from here.", 'refused');
    return edited;
  }
  if (currentIp === undefined || currentMask === undefined) {
    throw new IsapiError("The device's IP settings weren't in the expected format, so nothing was changed.", 'refused');
  }
  if (currentIp === net.ip && currentMask === net.subnetMask && addressing === 'static' && (!gateway || childText(xml, ['DefaultGateway', 'ipAddress']) === gateway)) {
    return undefined;
  }
  let edited = withText(xml, ['addressingType'], 'static') ?? xml;
  edited = withText(edited, ['ipAddress'], net.ip) as string;
  edited = withText(edited, ['subnetMask'], net.subnetMask) as string;
  if (gateway) {
    const withGateway = withText(edited, ['DefaultGateway', 'ipAddress'], gateway);
    if (!withGateway) {
      throw new IsapiError("The device's IP settings have no gateway field, so a gateway can't be set from here — use 0.0.0.0 (none), or set it from its web page.", 'refused');
    }
    edited = withGateway;
  }
  return edited;
}

// ---- Ports ----

interface PortEntry {
  element: ElementRange;
  // As the device names it (e.g. "WebSocket"), and upper-cased for matching.
  name: string;
  protocol: string;
  port: number;
  enabled: boolean;
}

function parsePorts(xml: string): PortEntry[] {
  return findElements(xml, ['AdminAccessProtocol']).map((element) => {
    const block = xml.slice(element.start, element.end);
    const name = childText(block, ['protocol']) ?? '';
    return {
      element,
      name,
      protocol: name.toUpperCase(),
      port: Number(childText(block, ['portNo'])),
      enabled: childText(block, ['enabled'])?.toLowerCase() !== 'false',
    };
  });
}

// The port list with the wanted ports set, and what a read-back should
// then show — undefined when the device already has them.
function editedPorts(xml: string, wanted: PortSettings): { body: string; expected: [string, number][] } | undefined {
  const entries = parsePorts(xml);
  const final = new Map(entries.map((entry) => [entry, entry.port]));
  for (const kind of Object.keys(wanted) as PortKind[]) {
    const entry = entries.find((e) => e.protocol === PORT_PROTOCOLS[kind]);
    if (!entry || !Number.isInteger(entry.port)) {
      throw new IsapiError(`The device doesn't report a ${PORT_LABELS[PORT_PROTOCOLS[kind]]} port setting to change.`, 'refused');
    }
    final.set(entry, wanted[kind] as number);
  }
  const changed = entries.filter((entry) => final.get(entry) !== entry.port);
  if (changed.length === 0) return undefined;

  // No changed port on top of another of the device's enabled services —
  // including the ones not shown here (WebSocket, SRTP, ...).
  const label = (entry: PortEntry): string => PORT_LABELS[entry.protocol] ?? entry.name;
  const enabled = entries.filter((entry) => entry.enabled);
  for (const entry of changed) {
    const clash = enabled.find((other) => other !== entry && final.get(other) === final.get(entry));
    if (clash) throw new IsapiError(`${label(entry)} and ${label(clash)} ports can't both be ${final.get(entry)}.`, 'refused');
  }

  let body = xml;
  for (const entry of [...changed].reverse()) {
    const block = withText(xml.slice(entry.element.start, entry.element.end), ['portNo'], String(final.get(entry))) as string;
    body = body.slice(0, entry.element.start) + block + body.slice(entry.element.end);
  }
  return { body, expected: changed.map((entry) => [entry.protocol, final.get(entry) as number]) };
}

async function waitForPorts(at: Target, creds: Credentials, expected: [string, number][], timeoutMs: number): Promise<'match' | 'mismatch' | 'unreachable'> {
  const deadline = Date.now() + timeoutMs;
  let answered = false;
  while (Date.now() < deadline) {
    try {
      const entries = parsePorts(await isapi(at, 'GET', PORTS_PATH, creds));
      answered = true;
      if (expected.every(([protocol, port]) => entries.some((e) => e.protocol === protocol && e.port === port))) return 'match';
    } catch (e) {
      // A refused login stops the polling (the lockout); anything else is
      // the device restarting — keep polling.
      if (e instanceof IsapiError && e.kind === 'auth') {
        throw new IsapiError("The device refused the login while the change was being checked, so it couldn't be confirmed — check it from its web page.", 'auth');
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return answered ? 'mismatch' : 'unreachable';
}

// Reboots the device to apply saved changes. It may go down before
// finishing its reply, which isn't a failure.
async function reboot(at: Target, creds: Credentials): Promise<void> {
  try {
    await sendChange(at, REBOOT_PATH, creds);
  } catch (e) {
    throw new IsapiError(`the device wouldn't reboot to apply it (${e instanceof Error ? e.message : String(e)}) — reboot it from its web page.`, 'refused');
  }
}

// Where a device switched to DHCP turned up: SADP reports each device's
// MAC and DHCP mode from wherever its new address is. A reply from its old
// address only counts after DHCP_SETTLE_MS — the DHCP server may hand the
// same address back, but right after the switch the device can still be
// answering from its old one.
async function findDhcpAddress(mac: string, oldIp: string, timeoutMs: number): Promise<string | undefined> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const device = (await discoverHikvisionDevices()).find((d) => normalizeMac(d.mac) === mac && d.dhcp === true);
    if (device && (device.host !== oldIp || Date.now() - started >= DHCP_SETTLE_MS)) return device.host;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return undefined;
}

// ---- Reboot ----

// The Actions column's Reboot: the interface is read first, which proves the
// login and checks it's the scanned device before anything is rebooted.
export async function rebootHikvisionDevice(request: RebootRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Hikvision SADP');
  if (!row) return { ok: false, error: 'This device is no longer in the Hikvision search results. Scan again and retry.' };
  const at: Target = { host: request.host, port: row.httpPort ?? 80 };
  const creds: Credentials = { username: request.username, password: request.password };
  try {
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const iface = await readInterface(at, creds, scannedMac);
    if (scannedMac && iface?.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was rebooted — rescan and try again.` };
    }
    await sendChange(at, REBOOT_PATH, creds);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---- Factory reset ----

// ISAPI's own factory-reset endpoint, with ISAPI's recovery modes (the
// query parameter ISAPI documents, not a body):
//   - mode=basic: every parameter EXCEPT the network and user settings
//     restored to default — the 'keep IP and login' reset;
//   - mode=full: everything, the network and login included. The device
//     comes back uninitialized at its factory address and has to be
//     activated with a new password before anyone can use it.
// The interface is read first (as for a reboot) to prove the login and
// check it's the scanned device. The device reboots either way and may go
// down before finishing its reply, so 'unanswered' counts as sent.
const FACTORY_RESET_PATH = '/ISAPI/System/factoryReset';

export async function factoryResetHikvisionDevice(request: FactoryResetRequest): Promise<ModifyNetworkResult> {
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Hikvision SADP');
  if (!row) return { ok: false, error: 'This device is no longer in the Hikvision search results. Scan again and retry.' };
  const at: Target = { host: request.host, port: row.httpPort ?? 80 };
  const creds: Credentials = { username: request.username, password: request.password };
  try {
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const iface = await readInterface(at, creds, scannedMac);
    if (scannedMac && iface?.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was reset — rescan and try again.` };
    }
    await sendChange(at, `${FACTORY_RESET_PATH}?mode=${request.mode === 'full' ? 'full' : 'basic'}`, creds, '');
    return {
      ok: true,
      message:
        request.mode === 'full'
          ? 'The device is factory-resetting. All settings — its network settings and password included — are going back to factory defaults, and it reboots to apply them. When it comes back it is uninitialized, usually at its factory address, and needs activating with a new password.'
          : 'The device is restoring factory defaults and reboots to apply them — it keeps its IP address and login, and should answer again in a minute or two (its other settings are back at factory defaults).',
    };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---- Modify ----

export async function modifyHikvisionDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  // SADP reports at most one device per IP, so this is the edited row.
  const row = lastScanRowsFor(request.host).find((d) => d.discoveryMethod === 'Hikvision SADP');
  if (!row) return { ok: false, error: 'This device is no longer in the Hikvision search results. Scan again and retry.' };
  const creds: Credentials = { username: request.username, password: request.password };
  const net = request.network;
  const wanted = request.ports && Object.keys(request.ports).length > 0 ? request.ports : undefined;
  // Where the device's web server answers, updated as changes take effect.
  let at: Target = { host: request.host, port: row.httpPort ?? 80 };

  // What's already been applied on the device, so a later failure (or an
  // unconfirmed step) never reads as "nothing happened".
  const applied: string[] = [];
  const withApplied = (result: ModifyNetworkResult): ModifyNetworkResult => {
    if (applied.length === 0) return result;
    const what = `The ${applied.join(' and ')} ${applied.length > 1 || applied[0].endsWith('s') ? 'were' : 'was'}`;
    if (!result.ok) return { ok: false, error: `${what} already changed, but then: ${result.error}` };
    return result.warning ? { ok: true, warning: `${what} changed. ${result.warning}` } : result;
  };

  try {
    // Read everything first: proves the login works, checks it's the
    // scanned device, and catches an unexpected format before anything on
    // the device is changed.
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    const iface = await readInterface(at, creds, scannedMac);
    if (!iface) return { ok: false, error: `The device didn't say which of its network interfaces has ${request.host}, so nothing was changed.` };
    if (scannedMac && iface.mac && iface.mac !== scannedMac) {
      return {
        ok: false,
        error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was changed — rescan and try again.`,
      };
    }
    const mac = iface.mac ?? scannedMac;
    const ipPath = `${INTERFACES_PATH}/${iface.id}/ipAddress`;
    const ipBody = net ? editedIpAddress(await isapi(at, 'GET', ipPath, creds), net) : undefined;
    const ports = wanted ? editedPorts(await isapi(at, 'GET', PORTS_PATH, creds), wanted) : undefined;
    const newIp = ipBody !== undefined && net && !net.dhcp ? net.ip : request.host;
    const newHttp = ports?.expected.find(([protocol]) => protocol === 'HTTP')?.[1] ?? at.port;
    let rebootNeeded = false;

    // ---- Ports ----
    if (ports) {
      const outcome = await sendChange(at, PORTS_PATH, creds, ports.body);
      if (outcome === 'reboot') {
        rebootNeeded = true;
      } else {
        // Applied live: the web server may have moved to the new HTTP port
        // already — or, on some firmware, only moves on a reboot. Later
        // steps go to whichever port answers.
        let check = await waitForPorts({ ...at, port: newHttp }, creds, ports.expected, VERIFY_TIMEOUT_MS);
        if (check === 'match') at = { ...at, port: newHttp };
        else if (check === 'unreachable' && newHttp !== at.port) check = await waitForPorts(at, creds, ports.expected, 4000);
        const skipped = ipBody !== undefined ? ` The ${net?.dhcp ? 'DHCP' : 'IP'} change wasn't sent.` : '';
        if (check === 'mismatch') return { ok: false, error: `The device answered but kept its old ports — the change didn't take.${skipped}` };
        if (check === 'unreachable') {
          return {
            ok: true,
            warning: `The port change was sent, but the device hasn't answered since${newHttp !== at.port ? ` (checked HTTP port ${newHttp} and the old one)` : ''}.${skipped} Rescan in a minute to check.`,
          };
        }
      }
      applied.push('ports');
    }

    // ---- DHCP ----
    // The DHCP server picks the new address, so the device is found again
    // afterwards by its MAC through SADP instead of being waited for at a
    // known IP — and a reboot the new ports are waiting for goes first,
    // while the device is still where the PC can reach it.
    if (net?.dhcp) {
      if (rebootNeeded && ports) {
        await reboot(at, creds);
        at = { ...at, port: newHttp };
        const check = await waitForPorts(at, creds, ports.expected, VERIFY_AFTER_REBOOT_TIMEOUT_MS);
        const notSent = ipBody !== undefined ? " DHCP wasn't turned on." : '';
        if (check === 'mismatch') return { ok: false, error: `The device came back from its reboot with its old ports — the port change didn't take.${notSent}` };
        if (check === 'unreachable') {
          return withApplied({ ok: true, warning: `The device rebooted to apply the new ports, but hasn't answered on HTTP port ${newHttp} since.${notSent} Rescan in a minute to check.` });
        }
      }
      if (ipBody === undefined) return { ok: true };
      const outcome = await sendChange(at, ipPath, creds, ipBody);
      applied.push('DHCP setting');
      if (outcome === 'reboot') await reboot(at, creds);
      const found = mac ? await findDhcpAddress(mac, request.host, outcome === 'reboot' ? VERIFY_AFTER_REBOOT_TIMEOUT_MS : DHCP_FIND_TIMEOUT_MS) : undefined;
      if (!found) {
        return withApplied({
          ok: true,
          warning: `The device ${outcome === 'reboot' ? 'is rebooting to switch' : 'switched'} to DHCP, but hasn't turned up with an address from the DHCP server yet — make sure this network has one, and rescan in a minute.`,
        });
      }
      return { ok: true, message: `It switched to DHCP and got the address ${found}${isOnLocalSubnet(found) ? '' : ", which is outside this PC's subnet"}.` };
    }

    // ---- IP ----
    if (ipBody !== undefined) {
      const outcome = await sendChange(at, ipPath, creds, ipBody);
      applied.push('IP settings');
      if (outcome === 'reboot') rebootNeeded = true;
      else at = { ...at, host: newIp };
    }

    // ---- Reboot ----
    let rebooted = false;
    if (rebootNeeded) {
      // An IP change that applied live while the ports wait for a reboot:
      // the reboot has to go to the new address, once the device is there.
      if (at.host !== request.host && (!mac || !isOnLocalSubnet(newIp) || !(await waitForMacAt(newIp, at.port, mac, VERIFY_TIMEOUT_MS)))) {
        return withApplied({
          ok: true,
          warning: `The new ports only take effect after a reboot, and the device couldn't be reached at ${newIp} to reboot it — reboot it from its web page there.`,
        });
      }
      await reboot(at, creds);
      rebooted = true;
      at = { host: newIp, port: newHttp };
    }

    // ---- Confirm ----
    if (ipBody !== undefined) {
      if (!mac || !isOnLocalSubnet(newIp)) {
        return withApplied({
          ok: true,
          warning: `The device accepted the change${rebooted ? ' and is rebooting to apply it' : ''}, but it can't be confirmed from this PC (the new IP is outside this PC's subnet). Its web page should be at ${newIp}.`,
        });
      }
      if (!(await waitForMacAt(newIp, at.port, mac, rebooted ? VERIFY_AFTER_REBOOT_TIMEOUT_MS : VERIFY_TIMEOUT_MS))) {
        return withApplied({ ok: true, warning: `The device accepted the change${rebooted ? ' and rebooted' : ''}, but hasn't shown up at ${newIp} yet. Rescan in a minute to check.` });
      }
    }
    // After a reboot the device's MAC may already be known at the new IP,
    // so the ports get the full reboot time too.
    if (rebooted && ports) {
      const check = await waitForPorts(at, creds, ports.expected, VERIFY_AFTER_REBOOT_TIMEOUT_MS);
      if (check === 'mismatch') {
        return { ok: false, error: `${ipBody !== undefined ? 'The IP settings were changed, but the' : 'The'} device came back from its reboot with its old ports — the port change didn't take.` };
      }
      if (check === 'unreachable') {
        return withApplied({ ok: true, warning: `The device rebooted to apply the change, but hasn't answered on HTTP port ${at.port} since. Rescan in a minute to check.` });
      }
    }
    return { ok: true };
  } catch (e) {
    return withApplied({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
}
