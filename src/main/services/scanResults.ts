import type { DiscoveredDevice } from '../../shared/types';
import { normalizeMac } from './arpLookup';

// The final rows from the most recent scan, after MAC normalization and
// fill-in (ipc/discovery.ts). Lets a modify path use a MAC its own
// discovery didn't report but another source did (sibling row, ONVIF
// scope, ARP) — e.g. ONVIF checks the camera's HwAddress against it before
// changing anything — and lets Open find a device's real web port. Kept
// here rather than in ipc/discovery.ts so the services can read it without
// a circular import.
let lastScan: DiscoveredDevice[] = [];

export function setLastScan(devices: DiscoveredDevice[]): void {
  lastScan = devices;
}

export function lastScanMacFor(host: string): string | undefined {
  return lastScan.find((d) => d.host === host && d.mac)?.mac;
}

export function lastScanRowsFor(host: string): DiscoveredDevice[] {
  return lastScan.filter((d) => d.host === host);
}

export function lastScanHosts(): Set<string> {
  return new Set(lastScan.map((d) => d.host));
}

// The vendor record for the row being edited: the one at `host` whose MAC
// matches the row's — several devices can answer from one IP (two cameras
// still on the same factory default), and a vendor SDK can also relay other
// devices' replies for an IP without a MAC. Without a MAC to match, the
// first record for the host, which is the row the table shows.
export function pickEditedDevice<T extends { host: string; mac: string }>(records: T[], host: string, mac: string | undefined): T | undefined {
  const atHost = records.filter((r) => r.host === host);
  const wanted = normalizeMac(mac);
  if (!wanted) return atHost[0];
  return atHost.find((r) => normalizeMac(r.mac) === wanted);
}
