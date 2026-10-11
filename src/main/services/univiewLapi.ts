import type { ModifyNetworkResult, PortSettings } from '../../shared/types';
import { deviceHttpRequest } from './deviceHttp';
import { digestAuthorization, pickDigestChallenge } from './httpDigest';

// Uniview ports through LAPI, the camera's own REST API — exactly what its
// web UI's port page does (read from a test camera's
// script/common/port_config.*.js): GET/PUT /LAPI/V1.0/NetWork/Port with
// { HttpPort, HttpsPort, RtspPort }, the page's reserved-port blacklist,
// and a CheckPort call per port before saving. HTTP Digest auth (the web
// UI's utils.js web_Digest). Used instead of the Uniview SDK, whose port
// command isn't supported over the ONVIF login its manual requires for
// IPCs/NVRs, and preferred over ONVIF, which refused HTTP port changes on a
// test camera ("Action Failed") while accepting RTSP ones.
const PORT_PATH = '/LAPI/V1.0/NetWork/Port';
const CHECK_PORT_PATH = '/LAPI/V1.0/Channel/0/NetWork/CheckPort';
const REQUEST_TIMEOUT_MS = 6000;
const VERIFY_TIMEOUT_MS = 30000;
// Older Uniview firmware reboots to apply an RTSP port change (its web page
// warns before saving); newer firmware applies it live.
const VERIFY_AFTER_RTSP_TIMEOUT_MS = 150000;

// From port_config.js's validPortNotInBlackList — 81 is the camera's own
// SDK port (its login page embeds sdkPort=81).
const RESERVED_PORTS = [23, 81, 82, 85, 3260, 49152];

interface Credentials {
  username: string;
  password: string;
}

class LapiError extends Error {
  constructor(
    message: string,
    readonly kind: 'auth' | 'missing' | 'network' | 'refused',
  ) {
    super(message);
  }
}

// One LAPI call: unauthenticated first, then again with HTTP Digest when
// the camera answers 401 with a challenge. Returns the Response.Data.
async function lapi(host: string, port: number, method: 'GET' | 'PUT', path: string, creds: Credentials, body?: object): Promise<unknown> {
  const url = `http://${host}:${port}${path}`;
  const payload = body === undefined ? undefined : `${JSON.stringify(body)}\r\n`;
  const send = async (authorization?: string): Promise<{ status: number; text: string; challenge?: string }> => {
    try {
      const res = await deviceHttpRequest(url, {
        method,
        headers: { 'Content-Type': 'application/json; charset=UTF-8', ...(authorization ? { Authorization: authorization } : {}) },
        body: payload,
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      return { status: res.status, text: res.body, challenge: pickDigestChallenge(res.challenges) };
    } catch (e) {
      throw new LapiError(`No response from the camera (${e instanceof Error ? e.message : String(e)}).`, 'network');
    }
  };

  let res = await send();
  if (res.status === 401 && res.challenge) {
    res = await send(digestAuthorization(res.challenge, method, path, creds.username, creds.password));
  }
  let parsed: { Response?: { ResponseCode?: number; ResponseString?: string; Data?: unknown } } | undefined;
  try {
    parsed = JSON.parse(res.text);
  } catch {
    parsed = undefined;
  }
  if (!parsed?.Response) {
    throw new LapiError(`The camera doesn't provide ${path} (HTTP ${res.status}).`, 'missing');
  }
  const code = parsed.Response.ResponseCode;
  if (res.status === 401 || code === 3) throw new LapiError('Wrong username or password.', 'auth');
  if (code !== 0) throw new LapiError(parsed.Response.ResponseString || `error ${code}`, 'refused');
  return parsed.Response.Data;
}

type PortConfig = Record<string, unknown> & { HttpPort?: number; HttpsPort?: number; RtspPort?: number };

async function waitForPorts(host: string, port: number, creds: Credentials, wanted: Required<Pick<PortConfig, 'HttpPort' | 'HttpsPort' | 'RtspPort'>>, timeoutMs: number): Promise<'match' | 'mismatch' | 'unreachable'> {
  const deadline = Date.now() + timeoutMs;
  let answered = false;
  while (Date.now() < deadline) {
    try {
      const cfg = (await lapi(host, port, 'GET', PORT_PATH, creds)) as PortConfig;
      answered = true;
      if (Number(cfg.HttpPort) === wanted.HttpPort && Number(cfg.HttpsPort) === wanted.HttpsPort && Number(cfg.RtspPort) === wanted.RtspPort) {
        return 'match';
      }
    } catch {
      // restarting / rebooting — keep polling
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return answered ? 'mismatch' : 'unreachable';
}

// Returns undefined when the device has no LAPI port endpoint at all (so
// the caller can fall back to ONVIF); otherwise the outcome.
export async function changeUniviewPortsViaLapi(
  host: string,
  httpPort: number,
  creds: Credentials,
  wanted: PortSettings,
): Promise<ModifyNetworkResult | undefined> {
  let current: PortConfig;
  try {
    current = (await lapi(host, httpPort, 'GET', PORT_PATH, creds)) as PortConfig;
  } catch (e) {
    if (e instanceof LapiError && e.kind === 'missing') return undefined;
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }

  const final = {
    HttpPort: wanted.http ?? Number(current.HttpPort),
    HttpsPort: wanted.https ?? Number(current.HttpsPort),
    RtspPort: wanted.rtsp ?? Number(current.RtspPort),
  };
  const changed = (Object.keys(final) as (keyof typeof final)[]).filter((k) => final[k] !== Number(current[k]));
  if (changed.length === 0) return { ok: true };

  // The camera's own web page rules: no reserved port, no two the same.
  const label = (k: string): string => k.replace('Port', '').toUpperCase();
  for (const k of changed) {
    if (RESERVED_PORTS.includes(final[k])) {
      return { ok: false, error: `${final[k]} is reserved on Uniview cameras (${RESERVED_PORTS.join(', ')}) and can't be used for the ${label(k)} port.` };
    }
  }
  const entries = Object.entries(final).filter(([, v]) => v > 0);
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      if (entries[i][1] === entries[j][1]) return { ok: false, error: `${label(entries[i][0])} and ${label(entries[j][0])} ports can't both be ${entries[i][1]}.` };
    }
  }

  try {
    // The page asks the camera whether each port is free before saving.
    for (const k of changed) {
      try {
        await lapi(host, httpPort, 'PUT', CHECK_PORT_PATH, creds, { Port: final[k] });
      } catch (e) {
        if (e instanceof LapiError && e.kind === 'refused') {
          return { ok: false, error: `Port ${final[k]} is already in use on the camera — pick a different ${label(k)} port.` };
        }
        if (!(e instanceof LapiError && e.kind === 'missing')) throw e;
      }
    }

    // A camera moving its web server to a new HTTP port may drop the reply,
    // so no response isn't a failure — the read-back below decides.
    try {
      await lapi(host, httpPort, 'PUT', PORT_PATH, creds, { ...current, ...final });
    } catch (e) {
      if (!(e instanceof LapiError && e.kind === 'network')) throw e;
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, error: e instanceof LapiError && e.kind === 'refused' ? `The camera refused the port change: ${message}` : message };
  }

  const rtspChanged = changed.includes('RtspPort');
  const result = await waitForPorts(host, final.HttpPort, creds, final, rtspChanged ? VERIFY_AFTER_RTSP_TIMEOUT_MS : VERIFY_TIMEOUT_MS);
  if (result === 'match') return { ok: true };
  if (result === 'mismatch') {
    return { ok: false, error: "The camera answered but still reports its old ports — the change didn't take." };
  }
  return {
    ok: true,
    warning: `The port change was sent, but the camera hasn't answered on HTTP port ${final.HttpPort} since${rtspChanged ? ' (older Uniview firmware reboots to apply an RTSP change)' : ''}. Rescan in a minute to check.`,
  };
}

// The camera's current IPv4 mask/gateway/DHCP for pre-filling the Edit
// dialog — read over LAPI with the login the user entered, since Uniview
// reveals none of this without one (its LAPI and ONVIF both answer the
// network read with 401). Endpoint from the camera's own web UI
// (ComScript's NetworkInterfaces = /LAPI/V1.0/Network/Interfaces/1). The
// response schema isn't published, so the IPv4 fields are found tolerantly
// by name and validated as real IPv4 before use — this only pre-fills form
// fields, so a missed field just stays blank.
const NETWORK_INTERFACE_PATH = '/LAPI/V1.0/Network/Interfaces/1';

function isIPv4(value: unknown): value is string {
  return typeof value === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

// First value anywhere in the object whose key and value satisfy `match`.
function deepFind(root: unknown, match: (key: string, value: unknown) => boolean): unknown {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    for (const [key, value] of Object.entries(current as Record<string, unknown>)) {
      if (match(key, value)) return value;
      if (value && typeof value === 'object') stack.push(value);
    }
  }
  return undefined;
}

export async function readUniviewNetworkViaLapi(
  host: string,
  httpPort: number,
  creds: Credentials,
): Promise<{ subnetMask?: string; gateway?: string; dhcp?: boolean; error?: string }> {
  let data: unknown;
  try {
    data = await lapi(host, httpPort, 'GET', NETWORK_INTERFACE_PATH, creds);
  } catch (e) {
    if (e instanceof LapiError) {
      if (e.kind === 'auth') return { error: 'Wrong username or password.' };
      if (e.kind === 'missing') return {}; // no such endpoint on this firmware
      return { error: e.message };
    }
    return { error: e instanceof Error ? e.message : String(e) };
  }
  // IPv4 keys only — IPv6 uses different names (Ipv6Address, etc.), so these
  // won't pick up a v6 value by mistake.
  const subnetMask = deepFind(data, (k, v) => /^subnet_?mask$/i.test(k) && isIPv4(v)) as string | undefined;
  const gateway = deepFind(data, (k, v) => /^gateway$/i.test(k) && isIPv4(v)) as string | undefined;
  const dhcpRaw = deepFind(data, (k) => /^dhcp(enable)?$/i.test(k));
  const dhcp = typeof dhcpRaw === 'boolean' ? dhcpRaw : typeof dhcpRaw === 'number' ? dhcpRaw === 1 : undefined;
  return { subnetMask, gateway, dhcp };
}
