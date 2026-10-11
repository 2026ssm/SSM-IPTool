import { createSocket, type Socket } from 'dgram';
import type { DiscoveredDevice } from '../../shared/types';
import { localIPv4Interfaces } from './networkInterfaces';

// Wi-Tek (Wireless-Tek) APs announce themselves with a plain UDP broadcast
// — the 15-byte text "Hello,everyone!" to port 5246 — and answer no request
// at all (confirmed live: solicitations of every shape got nothing back,
// only the periodic beacon). The beacon is infrequent (~once every 15-30 s),
// so a short per-scan listen would usually miss it. Instead a listener runs
// for the app's lifetime, remembering which addresses have beaconed, and a
// scan returns the ones heard recently. The beacon carries no MAC or model,
// so the row gets its MAC from the ARP fill-in (which also confirms the
// Wi-Tek OUI, see macVendors) and its web page is read with Open.
const BEACON_PORT = 5246;
const BEACON_TEXT = 'Hello,everyone!';
// How long a device stays listed after its last beacon — several beacon
// intervals, so it doesn't drop out between the ~15-30 s announcements.
const SEEN_WINDOW_MS = 120_000;

const lastSeen = new Map<string, number>();
let sockets: Socket[] | undefined;

// Starts the background listener once (at app startup). Binds UDP 5246 on
// each local interface, like the other per-interface discovery probes, so
// beacons on the camera LAN are heard.
export function startWitekListener(): void {
  if (sockets) return;
  sockets = localIPv4Interfaces().map((iface) => {
    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('error', () => {
      // a bad interface just never hears anything
    });
    socket.on('message', (msg, rinfo) => {
      if (msg.toString('latin1').startsWith(BEACON_TEXT)) lastSeen.set(rinfo.address, Date.now());
    });
    try {
      socket.bind(BEACON_PORT, iface.address);
    } catch {
      // best-effort per interface
    }
    return socket;
  });
}

// The Wi-Tek devices heard within the recent window. Synchronous — it just
// reads what the background listener has already collected.
export function discoverWitekDevices(): DiscoveredDevice[] {
  const now = Date.now();
  const rows: DiscoveredDevice[] = [];
  for (const [host, seen] of lastSeen) {
    if (now - seen > SEEN_WINDOW_MS) {
      lastSeen.delete(host);
      continue;
    }
    rows.push({
      host,
      // The beacon carries no model; its web UI reports "Wi-Tek Wireless"
      // (an AP) but the exact model needs a login, so the row shows a
      // readable name instead of "Unknown device".
      model: 'Wi-Tek AP',
      manufacturer: 'Wi-Tek',
      guessedVendor: 'witek',
      deviceCategory: 'network',
      discoveryMethod: 'Wi-Tek',
      editUnavailableReason: "This app finds Wi-Tek devices but can't change them yet — manage it from its own web page or the Wi-Tek cloud.",
    });
  }
  return rows;
}
