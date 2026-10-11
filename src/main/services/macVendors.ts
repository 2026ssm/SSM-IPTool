import type { VendorId } from '../../shared/types';
import { normalizeMac } from './arpLookup';

// The camera maker a MAC's first three bytes (its OUI) are registered to,
// for devices whose own discovery reply doesn't reliably say — only makers
// this tool has met doing that on real networks:
//   - Dahua (Zhejiang Dahua Technology) — all 27 registered prefixes. The
//     test network's genuine Dahua PTZ (90:02:A9:...) stopped answering
//     Dahua's own search and was left with only an unbranded relayed row.
//   - Sunell (Sunell Electronics) — answers Dahua's search as if it were a
//     Dahua device (see dahuaDiscovery.ts).
//   - Ubiquiti (Ubiquiti Inc.) — all 48 registered 24-bit prefixes. Other
//     makers' gear can answer Ubiquiti's discovery protocol too, so its rows
//     are only branded Ubiquiti by MAC (see ubiquitiDiscovery.ts). One
//     registry entry, 00:50:C2:B0:4, is a small slice of a block IEEE shares
//     among many companies, so it isn't listed.
//   - Wi-Tek (Wireless-Tek Technology) — confirmed live on an AP (54:3D:92).
//     Its beacon (see witekDiscovery.ts) already identifies the brand; this
//     is a second confirmation and covers other paths.
//   - Axis (Axis Communications AB) — all 4 registered 24-bit prefixes. Axis
//     cameras answer ONVIF WS-Discovery (branded by scope there too), but
//     ship with ONVIF control disabled by default, so they're edited over
//     their own VAPIX HTTP API (see axisVapix.ts), not ONVIF.
const PREFIXES: [VendorId, string[]][] = [
  [
    'dahua',
    [
      '08:ED:ED', '14:A7:8B', '24:52:6A', '38:AF:29', '3C:E3:6B', '3C:EF:8C', '4C:11:BF', '5C:F5:1A', '64:FD:29',
      '6C:1C:71', '74:C9:29', '8C:E9:B4', '90:02:A9', '98:F9:CC', '9C:14:63', 'A0:BD:1D', 'B4:4C:3B', 'BC:32:5F',
      'C0:39:5A', 'C4:AA:C4', 'D4:43:0E', 'E0:2E:FE', 'E0:50:8B', 'E4:24:6C', 'F4:B1:C2', 'FC:5F:49', 'FC:B6:9D',
    ],
  ],
  ['sunell', ['00:1C:27']],
  ['witek', ['54:3D:92']],
  ['axis', ['00:40:8C', 'AC:CC:8E', 'B8:A4:4F', 'E8:27:25']],
  [
    'ubiquiti',
    [
      '00:15:6D', '00:27:22', '04:18:D6', '0C:EA:14', '18:E8:29', '1C:0B:8B', '1C:6A:1B', '24:5A:4C', '24:A4:3C', '28:70:4E',
      '2C:E5:BD', '44:D9:E7', '58:D6:1F', '60:22:32', '68:2E:3C', '68:72:51', '68:D7:9A', '6C:63:F8', '70:A7:41', '74:83:C2',
      '74:AC:B9', '74:F9:2C', '74:FA:29', '78:45:58', '78:8A:20', '80:2A:A8', '84:78:48', '8C:30:66', '8C:ED:E1', '90:41:B2',
      '94:2A:6F', '9C:05:D6', 'A4:F8:FF', 'A8:9C:6C', 'AC:8B:A9', 'B4:FB:E4', 'CC:35:D9', 'D0:21:F9', 'D4:89:C1', 'D8:B3:70',
      'D8:C2:62', 'DC:9F:DB', 'E0:63:DA', 'E4:38:83', 'F0:9F:C2', 'F4:92:BF', 'F4:E2:C6', 'FC:EC:DA',
    ],
  ],
];

export function vendorFromMac(mac: string | undefined): VendorId | undefined {
  const prefix = normalizeMac(mac)?.slice(0, 8);
  return prefix ? PREFIXES.find(([, prefixes]) => prefixes.includes(prefix))?.[0] : undefined;
}
