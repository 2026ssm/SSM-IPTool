import { createHash, randomBytes } from 'crypto';
import type { FactoryResetRequest, ModifyNetworkRequest, ModifyNetworkResult, PortKind, PortSettings, RebootRequest } from '../../shared/types';
import { normalizeMac, waitForMacAt } from './arpLookup';
import { deviceHttpRequest } from './deviceHttp';
import { digestAuthorization, pickDigestChallenge } from './httpDigest';
import { hasGateway, isOnLocalSubnet } from './networkInterfaces';
import { onvifDeviceServiceUrl } from './onvifDiscovery';
import { lastScanMacFor } from './scanResults';

// Network settings over ONVIF Device Management (the same standard calls a
// Uniview NVR uses to re-IP third-party cameras) — the route for cameras no
// vendor SDK here can change, e.g. the SSM/IPCY generic-firmware cameras,
// which ignore Uniview's search-level modify command (confirmed live).
// ONVIF is plain HTTP to the camera's current address, so unlike the vendor
// search commands it only reaches cameras inside the PC's own subnet.
//
// Findings from a read-only probe of the test network that shape this:
//   - interface tokens vary ("eth0", "NetworkInterfaceToken_1"), so the
//     token is always read from GetNetworkInterfaces first;
//   - several camera clocks were an hour off UTC, so the WS-Security
//     timestamp is taken from the camera's own GetSystemDateAndTime;
//   - most cameras accept WS-Security UsernameToken, but one gSOAP camera
//     answered 401 + "WWW-Authenticate: Digest", so HTTP Digest is the
//     fallback;
//   - every camera reports its MAC as HwAddress, which is checked against
//     the scanned MAC before anything is changed;
//   - the ONVIF service port isn't always the HTTP port (one camera served
//     ONVIF on 8080 with HTTP on 8081), so after an HTTP port change the
//     service URL only moves when the two were the same.

const REQUEST_TIMEOUT_MS = 6000;
const VERIFY_TIMEOUT_MS = 30000;
const VERIFY_AFTER_REBOOT_TIMEOUT_MS = 120000;

interface Credentials {
  username: string;
  password: string;
  clockOffsetMs: number;
}

interface SoapResponse {
  status: number;
  xml: string;
  // The Digest challenge from a 401, if the camera offered one.
  wwwAuthenticate?: string;
}

class OnvifError extends Error {
  constructor(
    message: string,
    readonly kind: 'auth' | 'fault' | 'network',
  ) {
    super(message);
  }
}

function escapeXml(value: string): string {
  return value.replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' })[c] as string);
}

function tagText(xml: string, tag: string): string | undefined {
  const match = xml.match(new RegExp(`<(?:[\\w-]+:)?${tag}(?:\\s[^>]*)?>([^<]*)</(?:[\\w-]+:)?${tag}>`, 'i'));
  return match?.[1]?.trim();
}

function wsSecurityHeader(creds: Credentials): string {
  const nonce = randomBytes(16);
  const created = new Date(Date.now() + creds.clockOffsetMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const digest = createHash('sha1')
    .update(Buffer.concat([nonce, Buffer.from(created, 'utf8'), Buffer.from(creds.password, 'utf8')]))
    .digest('base64');
  return (
    `<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` +
    `<UsernameToken><Username>${escapeXml(creds.username)}</Username>` +
    `<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</Password>` +
    `<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonce.toString('base64')}</Nonce>` +
    `<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${created}</Created>` +
    `</UsernameToken></Security>`
  );
}

function envelope(body: string, creds?: Credentials): string {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">` +
    `<s:Header>${creds ? wsSecurityHeader(creds) : ''}</s:Header><s:Body>${body}</s:Body></s:Envelope>`
  );
}

async function post(
  url: string,
  action: string,
  body: string,
  creds?: Credentials,
  authorization?: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<SoapResponse> {
  // Any transport failure — including a reply cut off mid-body — is "no
  // response": the Set* steps below treat that as "the camera may have
  // switched already", never as a refusal.
  try {
    const res = await deviceHttpRequest(url, {
      method: 'POST',
      headers: {
        'Content-Type': `application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/${action}"`,
        ...(authorization ? { Authorization: authorization } : {}),
      },
      body: envelope(body, creds),
      timeoutMs,
    });
    return { status: res.status, xml: res.body, wwwAuthenticate: pickDigestChallenge(res.challenges) };
  } catch (e) {
    throw new OnvifError(`No response from the camera (${e instanceof Error ? e.message : String(e)}).`, 'network');
  }
}

async function call(url: string, action: string, body: string, creds?: Credentials, timeoutMs = REQUEST_TIMEOUT_MS): Promise<string> {
  let response = await post(url, action, body, creds, undefined, timeoutMs);
  if (creds && response.status === 401 && response.wwwAuthenticate) {
    response = await post(
      url,
      action,
      body,
      creds,
      digestAuthorization(response.wwwAuthenticate, 'POST', new URL(url).pathname, creds.username, creds.password),
      timeoutMs,
    );
  }
  const isFault = /<(?:[\w-]+:)?Fault[\s>]/.test(response.xml);
  if (response.status === 401 || /NotAuthorized|not\s*authori[sz]ed/i.test(response.xml)) {
    throw new OnvifError(
      "Wrong username or password (or the camera rejected the login — some cameras also refuse it when their clock is far off).",
      'auth',
    );
  }
  if (isFault || response.status >= 400) {
    const reason = tagText(response.xml, 'Text') ?? `HTTP ${response.status}`;
    throw new OnvifError(`The camera refused ${action}: ${reason}`, 'fault');
  }
  return response.xml;
}

// Camera clock minus PC clock. GetSystemDateAndTime is unauthenticated by
// spec; if it can't be read, fall back to the PC's clock.
async function clockOffsetMs(url: string): Promise<number> {
  try {
    const xml = await call(url, 'GetSystemDateAndTime', '<tds:GetSystemDateAndTime/>');
    const utc = xml.match(/<(?:[\w-]+:)?UTCDateTime>([\s\S]*?)<\/(?:[\w-]+:)?UTCDateTime>/i)?.[1];
    if (!utc) return 0;
    const n = (tag: string): number => Number(tagText(utc, tag));
    const cameraMs = Date.UTC(n('Year'), n('Month') - 1, n('Day'), n('Hour'), n('Minute'), n('Second'));
    return Number.isFinite(cameraMs) ? cameraMs - Date.now() : 0;
  } catch {
    return 0;
  }
}

interface InterfaceInfo {
  token: string;
  mac?: string;
  address?: string;
  prefixLength?: number;
  // IPv4 by DHCP, when the camera says.
  dhcp?: boolean;
}

function parseFirstInterface(xml: string): InterfaceInfo | undefined {
  const block = xml.match(/<(?:[\w-]+:)?NetworkInterfaces\b([^>]*)>([\s\S]*?)<\/(?:[\w-]+:)?NetworkInterfaces>/i);
  const token = block?.[1].match(/\btoken="([^"]+)"/)?.[1];
  if (!block || !token) return undefined;
  const prefix = Number(tagText(block[2], 'PrefixLength'));
  // The IPv4 section's own DHCP flag — IPv6 has a DHCP element too.
  const ipv4 = block[2].match(/<(?:[\w-]+:)?IPv4\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?IPv4>/i)?.[1];
  const dhcp = ipv4 === undefined ? undefined : tagText(ipv4, 'DHCP')?.toLowerCase();
  return {
    token,
    mac: normalizeMac(tagText(block[2], 'HwAddress')),
    address: tagText(block[2], 'Address'),
    prefixLength: Number.isInteger(prefix) ? prefix : undefined,
    dhcp: dhcp === 'true' ? true : dhcp === 'false' ? false : undefined,
  };
}

function prefixToMask(prefix: number): string {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [24, 16, 8, 0].map((shift) => (mask >>> shift) & 255).join('.');
}

function maskToPrefix(mask: string): number {
  return mask
    .split('.')
    .map(Number)
    .reduce((bits, octet) => bits + octet.toString(2).replace(/0/g, '').length, 0);
}

interface OnvifProtocol {
  name: string;
  enabled: string;
  port: number;
}

// GetNetworkProtocols' <NetworkProtocols> entries (HTTP/HTTPS/RTSP).
function parseProtocols(xml: string): OnvifProtocol[] {
  return [...xml.matchAll(/<(?:[\w-]+:)?NetworkProtocols>([\s\S]*?)<\/(?:[\w-]+:)?NetworkProtocols>/gi)].map((m) => ({
    name: (tagText(m[1], 'Name') ?? '').toUpperCase(),
    enabled: tagText(m[1], 'Enabled') ?? 'true',
    port: Number(tagText(m[1], 'Port')),
  }));
}

const PROTOCOL_NAMES: Partial<Record<PortKind, string>> = { http: 'HTTP', https: 'HTTPS', rtsp: 'RTSP' };

function protocolsToPorts(protocols: OnvifProtocol[]): PortSettings {
  const ports: PortSettings = {};
  for (const [kind, name] of Object.entries(PROTOCOL_NAMES) as [PortKind, string][]) {
    const found = protocols.find((p) => p.name === name && Number.isInteger(p.port) && p.port > 0);
    if (found) ports[kind] = found.port;
  }
  return ports;
}

// Best-effort, unauthenticated read of the current mask, gateway and ports
// to pre-fill the Edit dialog — several cameras on the test network answer
// these without a login. Anything unreadable is left out.
export async function readOnvifNetwork(host: string): Promise<{ subnetMask?: string; gateway?: string; ports?: PortSettings; dhcp?: boolean }> {
  const url = onvifDeviceServiceUrl(host);
  if (!url) return {};
  const result: { subnetMask?: string; gateway?: string; ports?: PortSettings; dhcp?: boolean } = {};
  try {
    const iface = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>'));
    if (iface?.prefixLength !== undefined) result.subnetMask = prefixToMask(iface.prefixLength);
    if (iface?.dhcp !== undefined) result.dhcp = iface.dhcp;
  } catch {
    // needs a login on this camera — leave it for the user to fill in
  }
  try {
    const gateway = tagText(await call(url, 'GetNetworkDefaultGateway', '<tds:GetNetworkDefaultGateway/>'), 'IPv4Address');
    if (gateway) result.gateway = gateway;
  } catch {
    // same
  }
  try {
    const ports = protocolsToPorts(parseProtocols(await call(url, 'GetNetworkProtocols', '<tds:GetNetworkProtocols/>')));
    if (Object.keys(ports).length > 0) result.ports = ports;
  } catch {
    // same
  }
  return result;
}

// What the scan table shows for an ONVIF camera that its discovery reply
// doesn't carry — its subnet mask, gateway and web (HTTP) port — read the
// way the Edit dialog pre-fills them, without a login, but all three at
// once and with a short timeout, so a silent camera can't hold up the
// scan. A camera that wants a login for these just shows none.
const SCAN_READ_TIMEOUT_MS = 2500;

export async function readOnvifScanInfo(host: string): Promise<{ subnetMask?: string; gateway?: string; httpPort?: number }> {
  const url = onvifDeviceServiceUrl(host);
  if (!url) return {};
  const read = (action: string): Promise<string | undefined> =>
    call(url, action, `<tds:${action}/>`, undefined, SCAN_READ_TIMEOUT_MS).catch(() => undefined);
  const [interfaces, gateway, protocols] = await Promise.all([
    read('GetNetworkInterfaces'),
    read('GetNetworkDefaultGateway'),
    read('GetNetworkProtocols'),
  ]);
  const prefix = interfaces ? parseFirstInterface(interfaces)?.prefixLength : undefined;
  return {
    subnetMask: prefix !== undefined ? prefixToMask(prefix) : undefined,
    gateway: (gateway && tagText(gateway, 'IPv4Address')) || undefined,
    httpPort: protocols ? protocolsToPorts(parseProtocols(protocols)).http : undefined,
  };
}

// The camera's web (HTTP) port as it reports it, without a login where the
// camera allows — for Open, since the ONVIF XAddr port is the ONVIF
// service's, which isn't always the web port (8080 vs 8081 on one camera).
export async function readOnvifHttpPort(host: string): Promise<number | undefined> {
  const url = onvifDeviceServiceUrl(host);
  if (!url) return undefined;
  try {
    return protocolsToPorts(parseProtocols(await call(url, 'GetNetworkProtocols', '<tds:GetNetworkProtocols/>'))).http;
  } catch {
    return undefined;
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// The camera's IPv4 mode over the few seconds after a DHCP request:
// 'dhcp', 'static' (still static every time it was read), or 'unknown' —
// it no longer answers at its old address (it may already have moved), or
// doesn't report the mode.
async function readDhcpMode(url: string, creds: Credentials): Promise<'dhcp' | 'static' | 'unknown'> {
  let mode: 'static' | 'unknown' = 'unknown';
  for (let i = 0; i < 3; i++) {
    await sleep(2500);
    try {
      const dhcp = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>', creds))?.dhcp;
      if (dhcp === undefined) return 'unknown';
      if (dhcp) return 'dhcp';
      mode = 'static';
    } catch {
      return 'unknown';
    }
  }
  return mode;
}

function withPort(url: string, port: number): string {
  const moved = new URL(url);
  moved.port = String(port);
  return moved.toString();
}

function urlPort(url: string): number {
  return Number(new URL(url).port) || 80;
}

type PortCheck = { state: 'match' } | { state: 'mismatch'; reported: OnvifProtocol[] } | { state: 'unreachable' };

// Polls GetNetworkProtocols until the camera reports every requested port.
// "mismatch" means it answered but still reports other values — some
// generic firmwares accept SetNetworkProtocols and change nothing.
async function waitForPorts(url: string, creds: Credentials, wanted: PortSettings, timeoutMs: number): Promise<PortCheck> {
  const deadline = Date.now() + timeoutMs;
  let reported: OnvifProtocol[] | undefined;
  while (Date.now() < deadline) {
    try {
      reported = parseProtocols(await call(url, 'GetNetworkProtocols', '<tds:GetNetworkProtocols/>', creds));
      const current = protocolsToPorts(reported);
      if ((Object.keys(wanted) as PortKind[]).every((kind) => current[kind] === wanted[kind])) return { state: 'match' };
    } catch {
      // still restarting — keep polling
    }
    await sleep(2000);
  }
  return reported ? { state: 'mismatch', reported } : { state: 'unreachable' };
}

function describePorts(protocols: OnvifProtocol[]): string {
  return protocols.map((p) => `${p.name} ${p.port}`).join(', ');
}

// SetNetworkProtocols, then a read-back to confirm — for the ONVIF route,
// and as the fallback for Uniview devices without a LAPI port endpoint.
// Returns the (possibly moved) device-service URL to keep using, or a
// result to return as-is.
async function applyOnvifPorts(
  url: string,
  creds: Credentials,
  wanted: PortSettings,
  ipChangePending: boolean,
): Promise<{ url: string; result?: ModifyNetworkResult }> {
  const protocols = parseProtocols(await call(url, 'GetNetworkProtocols', '<tds:GetNetworkProtocols/>', creds));
  for (const kind of Object.keys(wanted) as PortKind[]) {
    const name = PROTOCOL_NAMES[kind];
    if (!name || !protocols.some((p) => p.name === name)) {
      return { url, result: { ok: false, error: `The camera doesn't report ${name ? `an ${name}` : `a ${kind}`} service to change.` } };
    }
  }
  const updated = protocols.map((p) => {
    const kind = (Object.keys(PROTOCOL_NAMES) as PortKind[]).find((k) => PROTOCOL_NAMES[k] === p.name);
    const port = kind ? wanted[kind] : undefined;
    return port !== undefined ? { ...p, port } : p;
  });
  const inUse = updated.filter((p) => Number.isInteger(p.port) && p.port > 0);
  for (let i = 0; i < inUse.length; i++) {
    for (let j = i + 1; j < inUse.length; j++) {
      if (inUse[i].port === inUse[j].port) {
        return { url, result: { ok: false, error: `${inUse[i].name} and ${inUse[j].name} ports can't both be ${inUse[i].port}.` } };
      }
    }
  }

  // The full list goes back (as a Uniview NVR does), with each protocol's
  // Enabled flag as the camera reported it. A camera restarting its web
  // server for the new port may never send the reply, so no response here
  // isn't a failure — the read-back below decides.
  try {
    await call(
      url,
      'SetNetworkProtocols',
      `<tds:SetNetworkProtocols>${updated
        .map(
          (p) =>
            `<tds:NetworkProtocols><tt:Name>${escapeXml(p.name)}</tt:Name><tt:Enabled>${escapeXml(p.enabled)}</tt:Enabled>` +
            `<tt:Port>${p.port}</tt:Port></tds:NetworkProtocols>`,
        )
        .join('')}</tds:SetNetworkProtocols>`,
      creds,
    );
  } catch (e) {
    if (!(e instanceof OnvifError && e.kind === 'network')) throw e;
  }

  // The device service only moves with the HTTP port when they shared it
  // (not on the camera serving ONVIF on 8080 and its web page on 8081).
  const oldHttp = protocols.find((p) => p.name === 'HTTP')?.port;
  const serviceMoves = wanted.http !== undefined && oldHttp !== undefined && urlPort(url) === oldHttp && wanted.http !== oldHttp;
  const checkUrl = serviceMoves ? withPort(url, wanted.http as number) : url;
  let check = await waitForPorts(checkUrl, creds, wanted, VERIFY_TIMEOUT_MS);
  let answeredUrl = checkUrl;
  if (check.state === 'unreachable' && serviceMoves) {
    // Not answering on the new port — see whether it's still on the old one
    // (some firmware reports the new port but only moves on reboot). Any
    // later step must then go to the old URL, the one actually answering.
    check = await waitForPorts(url, creds, wanted, 4000);
    answeredUrl = url;
  }
  if (check.state === 'match') return { url: answeredUrl };
  const skipped = ipChangePending ? " The IP change wasn't sent." : '';
  if (check.state === 'mismatch') {
    return {
      url,
      result: {
        ok: false,
        error: `The camera answered but kept its old ports (it reports ${describePorts(check.reported)}) — it may not support changing ports over ONVIF.${skipped}`,
      },
    };
  }
  return {
    url,
    result: {
      ok: true,
      warning: `The port change was sent, but the camera hasn't answered since${serviceMoves ? ` (checked HTTP port ${wanted.http} and the old one)` : ''}.${skipped} Rescan in a minute to check.`,
    },
  };
}

// The Actions column's Reboot for everything but Hikvision and TVT NVR/DVRs
// (see ipc/device.ts): GetNetworkInterfaces first, with the login — the
// camera's MAC is checked against the scanned one — then SystemReboot,
// whose reply the camera may not finish sending before it goes down.
export async function rebootOnvifDevice(request: RebootRequest): Promise<ModifyNetworkResult> {
  const url = onvifDeviceServiceUrl(request.host);
  if (!url) return { ok: false, error: "This device doesn't answer ONVIF, so it can't be rebooted from here." };
  const creds: Credentials = { username: request.username, password: request.password, clockOffsetMs: await clockOffsetMs(url) };
  try {
    const iface = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>', creds));
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    if (scannedMac && iface?.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was rebooted — rescan and try again.` };
    }
    try {
      await call(url, 'SystemReboot', '<tds:SystemReboot/>', creds);
    } catch (e) {
      if (!(e instanceof OnvifError && e.kind === 'network')) throw e;
    }
    return { ok: true };
  } catch (e) {
    // Said plainly: ONVIF is the only way the app can reboot this device, and
    // a camera can refuse it a login its web page accepts (the Dahua PTZ on
    // the test network does), so "wrong password" would mislead.
    if (e instanceof OnvifError && e.kind === 'auth') {
      return {
        ok: false,
        error: "The camera refused the login over ONVIF — the only way this app can reboot it. If the same username and password work on its web page, reboot it from there.",
      };
    }
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// Factory reset over ONVIF SetSystemFactoryDefault: the route for brands
// whose own SDK doesn't offer a camera reset (TVT's is documented NVR-only).
// The interface is read first with the login (as for a reboot), which
// checks the MAC, and then the reset is sent — Soft keeps the network and
// the login (the ONVIF Core spec guarantees the device stays reachable at
// the same IP after a soft reset), Hard resets everything including them.
// Either way the camera reboots and may drop its reply mid-send, so no
// response here isn't a failure.
export async function factoryResetOnvifDevice(request: FactoryResetRequest): Promise<ModifyNetworkResult> {
  const url = onvifDeviceServiceUrl(request.host);
  if (!url) return { ok: false, error: "This device doesn't answer ONVIF, so it can't be factory-reset from here." };
  const creds: Credentials = { username: request.username, password: request.password, clockOffsetMs: await clockOffsetMs(url) };
  try {
    const iface = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>', creds));
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    if (scannedMac && iface?.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was reset — rescan and try again.` };
    }
    // The ONVIF wire values: Soft keeps the address/login, Hard doesn't.
    const type = request.mode === 'full' ? 'Hard' : 'Soft';
    try {
      await call(url, 'SetSystemFactoryDefault', `<tds:SetSystemFactoryDefault><tds:FactoryDefaultType>${type}</tds:FactoryDefaultType></tds:SetSystemFactoryDefault>`, creds);
    } catch (e) {
      if (!(e instanceof OnvifError && e.kind === 'network')) throw e;
    }
    return { ok: true };
  } catch (e) {
    // As with the reboot: ONVIF is the only way this app reaches many of
    // these devices, so "wrong password" alone can mislead.
    if (e instanceof OnvifError && e.kind === 'auth') {
      return {
        ok: false,
        error: "The camera refused the login over ONVIF — the only way this app can reset it. If the same username and password work on its web page, reset it from there.",
      };
    }
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export function hasOnvifService(host: string): boolean {
  return onvifDeviceServiceUrl(host) !== undefined;
}

// Ports-only change over ONVIF for a device edited through a vendor row
// (the Uniview fallback): same login check and MAC check as the ONVIF
// route first.
export async function changeOnvifPorts(request: ModifyNetworkRequest, ports: PortSettings): Promise<ModifyNetworkResult> {
  const url = onvifDeviceServiceUrl(request.host);
  if (!url) return { ok: false, error: "This device didn't answer ONVIF discovery, so its ports can't be changed from here." };
  const creds: Credentials = { username: request.username, password: request.password, clockOffsetMs: await clockOffsetMs(url) };
  try {
    const iface = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>', creds));
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    if (scannedMac && iface?.mac && iface.mac !== scannedMac) {
      return { ok: false, error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was changed.` };
    }
    // The caller decides what happens to any IP change afterwards, so this
    // result mustn't claim one was or wasn't sent.
    const { result } = await applyOnvifPorts(url, creds, ports, false);
    return result ?? { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// Order: login check → gateway → ports → IP. Gateway goes first, while the
// camera is still at its current address; ports before IP, since an HTTP
// port change can move the device service and the IP step must follow it.
export async function modifyOnvifDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  let url = onvifDeviceServiceUrl(request.host);
  if (!url) return { ok: false, error: 'This camera is no longer in the ONVIF search results. Scan again and retry.' };
  const net = request.network;
  const wantedPorts = request.ports && Object.keys(request.ports).length > 0 ? request.ports : undefined;
  const creds: Credentials = { username: request.username, password: request.password, clockOffsetMs: await clockOffsetMs(url) };

  // What's already been applied on the camera, so a later failure (or an
  // unconfirmed step) never reads as "nothing happened".
  const applied: string[] = [];
  const withApplied = (result: ModifyNetworkResult): ModifyNetworkResult => {
    if (applied.length === 0) return result;
    const what = `The ${applied.join(' and ')} ${applied.length > 1 || applied[0].endsWith('s') ? 'were' : 'was'}`;
    if (!result.ok) return { ok: false, error: `${what} already changed, but then: ${result.error}` };
    return result.warning ? { ok: true, warning: `${what} changed. ${result.warning}` } : result;
  };

  try {
    // Read first: proves the login works and gets the interface token,
    // before anything on the camera is changed.
    const iface = parseFirstInterface(await call(url, 'GetNetworkInterfaces', '<tds:GetNetworkInterfaces/>', creds));
    if (!iface) return { ok: false, error: "The camera didn't report a network interface to change." };
    // The edited row's own MAC — with several devices on one IP, the first
    // scanned row's MAC could belong to a different device.
    const scannedMac = normalizeMac(request.mac) ?? lastScanMacFor(request.host);
    if (scannedMac && iface.mac && iface.mac !== scannedMac) {
      return {
        ok: false,
        error: `The device answering at ${request.host} (MAC ${iface.mac}) isn't the one the scan found (${scannedMac}). Nothing was changed — rescan and try again.`,
      };
    }
    const mac = iface.mac ?? scannedMac;
    const dhcp = net?.dhcp === true;
    const newIp = net && !dhcp ? net.ip : request.host;
    const prefix = net && !dhcp ? maskToPrefix(net.subnetMask) : iface.prefixLength;
    // Switching DHCP on or off is a change even at the same address.
    const ipChanges =
      net !== undefined && (dhcp ? iface.dhcp !== true : newIp !== request.host || prefix !== iface.prefixLength || iface.dhcp === true);

    // ---- Gateway ----
    // Blank or 0.0.0.0 means "no gateway / keep it": the camera's current
    // gateway is left alone (it may not have been readable to pre-fill).
    // With DHCP the gateway comes from the DHCP server too.
    const gateway = net && !dhcp && hasGateway(net.gateway) ? net.gateway : undefined;
    const setGateway = (serviceUrl: string, address: string): Promise<string> =>
      call(
        serviceUrl,
        'SetNetworkDefaultGateway',
        `<tds:SetNetworkDefaultGateway><tds:IPv4Address>${escapeXml(address)}</tds:IPv4Address></tds:SetNetworkDefaultGateway>`,
        creds,
      );
    // A camera may refuse a gateway outside its *current* subnet (moving it
    // to a new range); then it's set at the new address afterwards instead.
    let gatewayDeferred = false;
    if (gateway) {
      try {
        await setGateway(url, gateway);
        applied.push('gateway');
      } catch (e) {
        const currentMask = iface.prefixLength !== undefined ? prefixToMask(iface.prefixLength) : undefined;
        const outsideCurrentSubnet = currentMask !== undefined && !isOnLocalSubnet(gateway, [{ address: request.host, netmask: currentMask }]);
        if (!(e instanceof OnvifError && e.kind === 'fault' && ipChanges && outsideCurrentSubnet)) throw e;
        gatewayDeferred = true;
      }
    }

    // ---- Ports ----
    if (wantedPorts) {
      const ports = await applyOnvifPorts(url, creds, wantedPorts, ipChanges);
      if (ports.result) return withApplied(ports.result);
      applied.push('ports');
      url = ports.url;
    }

    if (!ipChanges) return withApplied({ ok: true });

    // Many cameras switch address immediately and never send the response,
    // so no reply here isn't a failure — the checks below decide.
    const serviceUrl = url;
    const setInterfaces = async (ipv4: string): Promise<boolean> => {
      try {
        const xml = await call(
          serviceUrl,
          'SetNetworkInterfaces',
          `<tds:SetNetworkInterfaces><tds:InterfaceToken>${escapeXml(iface.token)}</tds:InterfaceToken>` +
            `<tds:NetworkInterface><tt:Enabled>true</tt:Enabled><tt:IPv4><tt:Enabled>true</tt:Enabled>${ipv4}</tt:IPv4></tds:NetworkInterface></tds:SetNetworkInterfaces>`,
          creds,
        );
        return tagText(xml, 'RebootNeeded')?.toLowerCase() === 'true';
      } catch (e) {
        if (!(e instanceof OnvifError && e.kind === 'network')) throw e;
        return false;
      }
    };
    // Same for the reboot: a camera may go down before finishing its reply.
    const reboot = async (): Promise<void> => {
      try {
        await call(serviceUrl, 'SystemReboot', '<tds:SystemReboot/>', creds);
      } catch (e) {
        if (!(e instanceof OnvifError && e.kind === 'network')) throw e;
      }
    };
    const manual = (address: string, prefixLength: number | undefined): string =>
      `<tt:Manual><tt:Address>${escapeXml(address)}</tt:Address><tt:PrefixLength>${prefixLength}</tt:PrefixLength></tt:Manual>`;

    // ---- DHCP ----
    // Some cameras (the SSM/IPCY ones, confirmed live) answer the DHCP
    // request with success and stay on their static address, so the mode is
    // read back. Where it didn't take, the request goes once more with the
    // camera's current address in it — ignored under DHCP by the ONVIF spec,
    // but some implementations don't act on the request without it. The
    // DHCP server picks the new address, so it's the rescan when the dialog
    // closes that finds the camera again (by MAC).
    if (dhcp) {
      const attempts = [''];
      if (iface.address && iface.prefixLength !== undefined) attempts.push(manual(iface.address, iface.prefixLength));
      for (const address of attempts) {
        if (await setInterfaces(`${address}<tt:DHCP>true</tt:DHCP>`)) {
          await reboot();
          return withApplied({ ok: true });
        }
        if ((await readDhcpMode(url, creds)) !== 'static') return withApplied({ ok: true });
      }
      return withApplied({
        ok: false,
        error: "The camera accepted the DHCP setting but stayed on its static address — it doesn't switch to DHCP over ONVIF. Turn DHCP on from its own web page.",
      });
    }

    // ---- IP ----
    const rebootNeeded = await setInterfaces(`${manual(newIp, prefix)}<tt:DHCP>false</tt:DHCP>`);
    if (rebootNeeded) await reboot();

    const gatewayNote = gatewayDeferred
      ? ` The gateway couldn't be set yet (the camera refused one outside its old subnet) — set it to ${gateway} from the camera's web page.`
      : '';
    if (!mac || !isOnLocalSubnet(newIp)) {
      return withApplied({
        ok: true,
        warning: `The camera accepted the change${rebootNeeded ? ' and is rebooting to apply it' : ''}, but it can't be confirmed from this PC (the new IP is outside this PC's subnet). Its web page should be at ${newIp}.${gatewayNote}`,
      });
    }
    const moved = await waitForMacAt(newIp, urlPort(url), mac, rebootNeeded ? VERIFY_AFTER_REBOOT_TIMEOUT_MS : VERIFY_TIMEOUT_MS);
    if (!moved) {
      return withApplied({
        ok: true,
        warning: `The camera accepted the change${rebootNeeded ? ' and rebooted' : ''}, but hasn't shown up at ${newIp} yet. Rescan in a minute to check.${gatewayNote}`,
      });
    }
    if (gatewayDeferred && gateway) {
      const newUrl = new URL(url);
      newUrl.hostname = newIp;
      try {
        await setGateway(newUrl.toString(), gateway);
      } catch {
        return { ok: true, warning: `The camera moved to ${newIp}, but setting the gateway there failed — set it to ${gateway} from the camera's web page.` };
      }
    }
    return { ok: true };
  } catch (e) {
    return withApplied({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
}
