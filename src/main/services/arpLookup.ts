import { execFile } from 'child_process';
import { connect, type Socket } from 'net';
import { asPort } from './networkInterfaces';

// MAC lookup via the OS's own ARP table, for devices whose discovery
// protocol doesn't report one — ONVIF WS-Discovery responses carry no MAC
// at all, so SSM-branded and unidentified-brand cameras (which only answer
// ONVIF) otherwise always showed a blank MAC column. This is the device's
// real layer-2 address, not a guess: the ARP table is keyed by IP and only
// ever holds entries for hosts on a directly attached subnet, so a device
// reached through a router simply gets no entry (and no MAC) rather than
// the router's MAC.
const POKE_TIMEOUT_MS = 500;

// A TCP connect attempt forces the OS to ARP-resolve the host first, so
// its entry is guaranteed fresh in the table even if the discovery reply
// alone didn't populate it. Whether the connect succeeds, is refused, or
// times out doesn't matter — resolution has already happened by then.
function poke(host: string, port: number): Promise<void> {
  return new Promise((resolve) => {
    let socket: Socket;
    try {
      socket = connect({ host, port: asPort(port) ?? 80 });
    } catch {
      resolve();
      return;
    }
    const done = (): void => {
      socket.destroy();
      resolve();
    };
    socket.setTimeout(POKE_TIMEOUT_MS, done);
    socket.once('connect', done);
    socket.once('error', done);
  });
}

function readArpTable(): Promise<string> {
  return new Promise((resolve) => {
    // windowsHide keeps a console window from flashing up in the packaged app.
    execFile('arp', ['-a'], { windowsHide: true, timeout: 5000 }, (_error, stdout) => resolve(stdout ?? ''));
  });
}

// Every source formats MACs its own way — Uniview's SDK returns bare hex
// ("3c1a0f123456"), the TVT addon and Windows ARP use dashes, macOS ARP
// uses colons with leading zeros dropped ("0:11:32:8e:d3:ba") — so all
// rows are normalized to one uppercase colon-separated form. Anything
// that doesn't parse as a 6-octet MAC is passed through untouched rather
// than mangled; all-zero/broadcast placeholders become undefined.
export function normalizeMac(raw: string | undefined): string | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) return undefined;
  let octets: string[] | undefined;
  const parts = trimmed.split(/[:.-]/);
  if (parts.length === 6 && parts.every((p) => /^[0-9a-f]{1,2}$/i.test(p))) {
    octets = parts.map((p) => p.padStart(2, '0'));
  } else if (/^[0-9a-f]{12}$/i.test(parts.join(''))) {
    octets = parts.join('').match(/../g) ?? undefined;
  }
  if (!octets) return trimmed;
  const mac = octets.join(':').toUpperCase();
  if (mac === 'FF:FF:FF:FF:FF:FF' || mac === '00:00:00:00:00:00') return undefined;
  return mac;
}

// Handles both Windows ("192.168.1.10   ec-71-db-0a-0b-0c   dynamic") and
// macOS ("? (192.168.1.10) at ec:71:db:a:b:c on en0 ...") output.
function parseArpTable(output: string): Map<string, string> {
  const table = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const ipMatch = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const macMatch = line.match(/\b([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})\b/i);
    if (!ipMatch || !macMatch) continue;
    const mac = normalizeMac(macMatch[1]);
    if (mac && !table.has(ipMatch[1])) table.set(ipMatch[1], mac);
  }
  return table;
}

export async function lookupMacAddresses(targets: { host: string; port?: number }[]): Promise<Map<string, string>> {
  if (targets.length === 0) return new Map();
  await Promise.all(targets.map((t) => poke(t.host, t.port ?? 80)));
  return parseArpTable(await readArpTable());
}

// Confirms a device moved from the PC's side: the new IP answering with the
// device's own MAC in the ARP table. Only possible when the new IP is on
// one of the PC's subnets. Shared by the ONVIF and Hikvision ISAPI routes.
export async function waitForMacAt(ip: string, port: number, mac: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = (await lookupMacAddresses([{ host: ip, port }])).get(ip);
    if (found === mac) return true;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return false;
}
