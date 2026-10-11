import { createSocket } from 'dgram';
import type { DiscoveredDevice } from '../../shared/types';
import { normalizeMac } from './arpLookup';
import { vendorFromMac } from './macVendors';
import { localIPv4Interfaces } from './networkInterfaces';

// Ubiquiti's device discovery — what its Device Discovery tool and the UniFi
// apps use: a 4-byte request to UDP 10001 (version 1 by broadcast, version
// 2 by multicast to 233.89.188.1), answered with type/length/value fields.
// Confirmed live on two NanoStation 5AC locos (airOS 8): their v1 replies
// came back to the request's own port and carried the MAC and IPs
// (0x01/0x02), firmware (0x03), hostname (0x0b), short and full model
// (0x0c/0x14) and SSID (0x0d). Read-only — it only asks devices to say who
// they are.
const DISCOVERY_PORT = 10001;
const MULTICAST_ADDRESS = '233.89.188.1';
const SCAN_DURATION_MS = 3000;
const V1_REQUEST = Buffer.from([0x01, 0x00, 0x00, 0x00]);
const V2_REQUEST = Buffer.from([0x02, 0x08, 0x00, 0x00]);

interface Reply {
  mac?: string;
  model?: string;
}

function formatMac(bytes: Buffer): string | undefined {
  return normalizeMac([...bytes].map((b) => b.toString(16).padStart(2, '0')).join(':'));
}

// The fields this table uses. A reply without a MAC — including a bare
// request like this PC's own, looped back — isn't a device.
function parseReply(msg: Buffer): Reply | undefined {
  const reply: Reply = {};
  let modelShort: string | undefined;
  let modelFull: string | undefined;
  let i = 4;
  while (i + 3 <= msg.length) {
    const type = msg[i];
    const length = msg.readUInt16BE(i + 1);
    const value = msg.subarray(i + 3, i + 3 + length);
    i += 3 + length;
    if (value.length < length) break;
    const text = (): string | undefined => value.toString('utf8').replace(/[^\x20-\x7e]/g, '').trim() || undefined;
    if (type === 0x01 && length === 6) reply.mac ??= formatMac(value);
    else if (type === 0x02 && length === 10) reply.mac ??= formatMac(value.subarray(0, 6));
    else if (type === 0x0c) modelShort = text();
    else if (type === 0x14) modelFull = text();
  }
  reply.model = modelFull ?? modelShort;
  return reply.mac ? reply : undefined;
}

// The subnet's own broadcast address, for networks that drop the
// all-ones one.
function broadcastOf(address: string, netmask: string): string | undefined {
  const a = address.split('.').map(Number);
  const m = netmask.split('.').map(Number);
  if (a.length !== 4 || m.length !== 4) return undefined;
  return a.map((octet, i) => octet | (~m[i] & 255)).join('.');
}

export function discoverUbiquitiDevices(): Promise<DiscoveredDevice[]> {
  return new Promise((resolve) => {
    const found = new Map<string, DiscoveredDevice>();
    // One socket per local interface, pinned like the ONVIF and SADP probes
    // (see localIPv4Interfaces), so the requests go out on the camera LAN.
    const sockets = localIPv4Interfaces().map((iface) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      socket.on('error', () => {
        // a bad interface just contributes nothing
      });
      socket.on('message', (msg, rinfo) => {
        if (found.has(rinfo.address)) return;
        const reply = parseReply(msg);
        if (!reply) return;
        // Brand only from the MAC's registered maker: other makers' gear can
        // answer this protocol too, and would otherwise read as Ubiquiti.
        const ubiquiti = vendorFromMac(reply.mac) === 'ubiquiti';
        found.set(rinfo.address, {
          host: rinfo.address,
          model: reply.model,
          manufacturer: ubiquiti ? 'Ubiquiti' : undefined,
          guessedVendor: ubiquiti ? 'ubiquiti' : undefined,
          mac: reply.mac,
          deviceCategory: 'network',
          discoveryMethod: 'Ubiquiti',
          editUnavailableReason:
            "This app finds Ubiquiti devices but can't change them yet — change its network settings from its own web page (airOS / UniFi).",
        });
      });
      socket.bind({ port: 0, address: iface.address }, () => {
        try {
          socket.setBroadcast(true);
          socket.setMulticastInterface(iface.address);
        } catch {
          // best-effort — the requests can still go out without these
        }
        const send = (request: Buffer, address: string): void => {
          socket.send(request, DISCOVERY_PORT, address, () => undefined);
        };
        send(V1_REQUEST, '255.255.255.255');
        const subnetBroadcast = broadcastOf(iface.address, iface.netmask);
        if (subnetBroadcast) send(V1_REQUEST, subnetBroadcast);
        send(V2_REQUEST, MULTICAST_ADDRESS);
      });
      return socket;
    });

    setTimeout(() => {
      for (const socket of sockets) socket.close();
      resolve(Array.from(found.values()));
    }, SCAN_DURATION_MS);
  });
}
