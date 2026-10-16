import { createSocket, type RemoteInfo } from 'dgram';
import { randomUUID } from 'crypto';
import type { DiscoveredDevice, VendorId } from '../../shared/types';
import { asPort, localIPv4Interfaces } from './networkInterfaces';

// ONVIF WS-Discovery — a UDP multicast probe most DVR/NVR/IP-camera
// vendors respond to regardless of brand. Ported from SSM-VMS's own
// services/discovery.ts (same protocol, same lessons already learned
// there) — kept as its own copy rather than a shared package since these
// are two separate apps/repos.
const MULTICAST_ADDRESS = '239.255.255.250';
const MULTICAST_PORT = 3702;
const SCAN_DURATION_MS = 4000;

function buildProbe(messageId: string): Buffer {
  return Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?>` +
      `<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" ` +
      `xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
      `xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" ` +
      `xmlns:dn="http://www.onvif.org/ver10/network/wsdl">` +
      `<e:Header>` +
      `<w:MessageID>uuid:${messageId}</w:MessageID>` +
      `<w:To e:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>` +
      `<w:Action e:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>` +
      `</e:Header>` +
      `<e:Body>` +
      `<d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>` +
      `</e:Body>` +
      `</e:Envelope>`,
  );
}

// Best-effort only, same as SSM-VMS's own guessVendor — a device very
// often doesn't mention its own brand in ONVIF Scopes/XAddrs text at all
// (confirmed there against real Dahua/TVT hardware), so this deliberately
// does NOT fall back to a generic default when nothing matches. Leaving
// guessedVendor undefined is correct in that case, not a bug to fix.
function guessVendor(text: string): VendorId | undefined {
  const lower = text.toLowerCase();
  if (lower.includes('hikvision') || /\bds-/.test(lower)) return 'hikvision';
  if (lower.includes('dahua')) return 'dahua';
  if (lower.includes('tvt')) return 'tvt';
  if (lower.includes('uniview') || /\bunv\b/.test(lower)) return 'uniview';
  // Axis names its ONVIF scope "AXIS <model>" (onvif://www.onvif.org/name/
  // AXIS_M3065-V), so the brand is right in the WS-Discovery reply.
  if (lower.includes('axis')) return 'axis';
  // Hanwha's scope says manufacturer/Hanwha%20Techwin (confirmed live on an
  // XNV-6011); "techwin" also catches the older Samsung Techwin, "wisenet"
  // the product line.
  if (lower.includes('hanwha') || lower.includes('techwin') || lower.includes('wisenet')) return 'hanwha';
  // Digital Watchdog's scope says manufacturer/Digital%20Watchdog (confirmed
  // live on a DWC-MV72Di28T). DW OEMs its hardware, so its MAC OUI isn't
  // DW-specific — the ONVIF scope is the reliable signal. DW has no native
  // API, so it's edited over the generic ONVIF path (no derived brand row).
  if (lower.includes('watchdog')) return 'dw';
  return undefined;
}

function extractTag(xml: string, tag: string): string {
  const match = xml.match(new RegExp(`<[^:>]*:?${tag}[^>]*>([\\s\\S]*?)<\\/[^:>]*:?${tag}>`, 'i'));
  return match?.[1]?.trim() ?? '';
}

// Each device's ONVIF device-service URL from its last ProbeMatch, by host —
// what the ONVIF network-settings calls (services/onvifNetwork.ts) talk to.
let deviceServiceUrlByHost = new Map<string, string>();

export function onvifDeviceServiceUrl(host: string): string | undefined {
  return deviceServiceUrlByHost.get(host);
}

// XAddrs can list several URLs (confirmed live: http on :83 plus https on
// :443 for one camera). Prefer plain http at the address the reply actually
// came from; if the device advertises some other address (a second NIC, a
// stale config), keep its path and port but point it at the replying host.
function pickDeviceServiceUrl(xaddrs: string, host: string): string | undefined {
  const urls = xaddrs.split(/\s+/).filter((u) => /^https?:\/\//i.test(u));
  const http = urls.filter((u) => u.toLowerCase().startsWith('http://'));
  const exact = http.find((u) => {
    try {
      return new URL(u).hostname === host;
    } catch {
      return false;
    }
  });
  if (exact) return exact;
  const first = http[0];
  if (!first) return undefined;
  try {
    const url = new URL(first);
    url.hostname = host;
    return url.toString();
  } catch {
    return undefined;
  }
}

export function discoverOnvifDevices(): Promise<DiscoveredDevice[]> {
  return new Promise((resolve) => {
    const found = new Map<string, DiscoveredDevice>();
    const serviceUrls = new Map<string, string>();

    const onMessage = (msg: Buffer, rinfo: RemoteInfo): void => {
      const xml = msg.toString('utf-8');
      const scopes = extractTag(xml, 'Scopes');
      const xaddrs = extractTag(xml, 'XAddrs');
      if (!scopes && !xaddrs) return;
      if (found.has(rinfo.address)) return;

      const portMatch = xaddrs.match(/:(\d+)\//);
      const modelMatch = scopes.match(/onvif:\/\/www\.onvif\.org\/hardware\/(\S+)/i);
      const nameMatch = scopes.match(/onvif:\/\/www\.onvif\.org\/name\/(\S+)/i);
      // Many devices (every Uniview seen on the test network) put their own
      // MAC in a macaddr scope — the device's own claim, so used directly.
      const macMatch = scopes.match(/onvif:\/\/www\.onvif\.org\/macaddr\/([0-9a-f:.-]{12,17})(?:\s|$)/i);
      const serviceUrl = pickDeviceServiceUrl(xaddrs, rinfo.address);
      if (serviceUrl) serviceUrls.set(rinfo.address, serviceUrl);

      found.set(rinfo.address, {
        host: rinfo.address,
        httpPort: asPort(portMatch?.[1]),
        model: modelMatch?.[1]?.replace(/_/g, ' '),
        manufacturer: nameMatch?.[1]?.replace(/_/g, ' '),
        mac: macMatch?.[1],
        guessedVendor: guessVendor(`${scopes} ${xaddrs}`),
        discoveryMethod: 'ONVIF',
      });
    };

    // One socket per local interface, each bound to that interface's own
    // address with the multicast interface pinned to it (see
    // localIPv4Interfaces for why). Replies are unicast back to whichever
    // socket's address the probe came from. Note a device OUTSIDE every
    // local subnet usually can't route that unicast reply back at all, so
    // ONVIF alone rarely finds those — the vendor protocols (which reply by
    // broadcast/multicast) are what surface them.
    const sockets = localIPv4Interfaces().map((iface) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      socket.on('message', onMessage);
      socket.on('error', () => {
        // A bad network interface shouldn't crash the scan - just resolve
        // with whatever (if anything) was already found.
      });
      socket.bind({ port: 0, address: iface.address }, () => {
        try {
          socket.setMulticastInterface(iface.address);
          socket.setMulticastTTL(4);
        } catch {
          // best-effort - some network configurations reject these, the
          // probe can still go out without them
        }
        socket.send(buildProbe(randomUUID()), MULTICAST_PORT, MULTICAST_ADDRESS);
      });
      return socket;
    });

    setTimeout(() => {
      for (const socket of sockets) socket.close();
      deviceServiceUrlByHost = serviceUrls;
      resolve(Array.from(found.values()));
    }, SCAN_DURATION_MS);
  });
}
