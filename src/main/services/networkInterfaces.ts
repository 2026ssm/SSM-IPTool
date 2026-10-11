import { networkInterfaces } from 'os';

export interface LocalInterface {
  address: string;
  netmask: string;
}

// Every non-loopback IPv4 address on this PC. Multicast discovery probes
// have to be sent out each of these explicitly — left to itself, Windows
// picks one outgoing interface for multicast (confirmed live on the test
// PC: an ONVIF probe with no interface set got 1 answer, the same probe
// pinned to the Ethernet adapter's address got 17), and on a PC with
// Wi-Fi + Ethernet or a VPN adapter that's often not the camera LAN.
// Link-local 169.254.x.x addresses are kept: a PC with no DHCP lease sits
// on one, and that's exactly when a factory-default camera is being set up.
export function localIPv4Interfaces(): LocalInterface[] {
  const result: LocalInterface[] = [];
  for (const addresses of Object.values(networkInterfaces())) {
    for (const a of addresses ?? []) {
      if (a.family === 'IPv4' && !a.internal) result.push({ address: a.address, netmask: a.netmask });
    }
  }
  return result;
}

function ipToInt(ip: string): number | undefined {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return undefined;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// Whether a host sits inside any of this PC's own subnets — i.e. whether
// the PC can reach it directly. A device found by broadcast/multicast
// discovery while outside every local subnet (typically a camera still on
// its factory-default IP) is visible but not reachable until its IP is
// changed, which is worth flagging rather than leaving the user to find
// out when "Open" fails.
export function isOnLocalSubnet(host: string, interfaces = localIPv4Interfaces()): boolean {
  const target = ipToInt(host);
  if (target === undefined) return true;
  return interfaces.some((iface) => {
    const address = ipToInt(iface.address);
    const mask = ipToInt(iface.netmask);
    return address !== undefined && mask !== undefined && ((target & mask) >>> 0) === ((address & mask) >>> 0);
  });
}

// A TCP port number from a device's reply, or undefined when the reply
// carried something that isn't one (non-numeric, 0, > 65535). Device
// replies come from anything on the LAN, so values used to open sockets or
// build URLs are checked here first — net.connect throws synchronously on a
// bad port, which once took a whole scan down.
export function asPort(value: unknown): number | undefined {
  const port = typeof value === 'number' ? value : Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : undefined;
}

// "No gateway": 0.0.0.0 (what devices on isolated camera LANs report), or
// blank — which each route treats as "keep the current gateway" where it
// can; Uniview's IP command needs an explicit value.
export function hasGateway(gateway: string): boolean {
  const value = gateway.trim();
  return value !== '' && value !== '0.0.0.0';
}
