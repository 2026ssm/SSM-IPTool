import { ipcMain } from 'electron';
import { discoverOnvifDevices } from '../services/onvifDiscovery';
import { discoverHikvisionDevices } from '../services/sadpDiscovery';
import { discoverUniviewDevices } from '../services/univiewDiscovery';
import { discoverTvtDevices } from '../services/tvtDiscovery';
import { discoverDahuaDevices, searchDahuaByIps } from '../services/dahuaDiscovery';
import { discoverUbiquitiDevices } from '../services/ubiquitiDiscovery';
import { discoverWitekDevices, startWitekListener } from '../services/witekDiscovery';
import { lookupMacAddresses, normalizeMac } from '../services/arpLookup';
import { isOnLocalSubnet, localIPv4Interfaces } from '../services/networkInterfaces';
import { vendorFromMac } from '../services/macVendors';
import { readOnvifScanInfo } from '../services/onvifNetwork';
import { setLastScan } from '../services/scanResults';
import type { DiscoveredDevice, FactoryResetCapability } from '../../shared/types';

// Originally left fully unmerged (one row per protocol match, however many
// that turned out to be) — real live testing showed some devices answering
// up to 3 different vendors' own "proprietary" broadcast protocols at
// once (OEM/shared-firmware cross-answering, the same phenomenon already
// documented in SSM-VMS's own discovery work), producing 4 rows for one
// physical device and reading as noise rather than useful signal. Per
// explicit user request, collapsed down to at most 2 rows per host: one
// "brand" match (whichever vendor-proprietary protocol answered) plus the
// separate ONVIF match if present.
//
// There is no algorithmic way to know FOR SURE which vendor is correct
// when more than one protocol answers the same host - TVT/Dahua/Hikvision
// SADP all trust any response as confirmed (their broadcasts are
// genuinely vendor-proprietary, unlike Uniview's, which needs a
// manufacturer-field match). When multiple of those "confirmed" matches
// collide on the same host, this keeps the first one found in a fixed
// priority order (Uniview's field-confirmed match first, since it's the
// most rigorously verified; then Hikvision SADP, TVT, Dahua, Ubiquiti)
// and silently drops the rest - a best-effort simplification, not a fix
// for the underlying cross-protocol-answering ambiguity. Use "Open" to
// check the device's own web UI when the shown brand looks wrong.
function collapseToTwoPerHost(
  onvifResults: DiscoveredDevice[],
  brandCandidatesInPriorityOrder: DiscoveredDevice[],
): DiscoveredDevice[] {
  const brandByHost = new Map<string, DiscoveredDevice>();
  for (const device of brandCandidatesInPriorityOrder) {
    const existing = brandByHost.get(device.host);
    if (!existing) {
      brandByHost.set(device.host, device);
    } else if (!existing.guessedVendor && device.guessedVendor) {
      // A later confirmed match should never lose to an earlier
      // unconfirmed one just because it was processed first.
      brandByHost.set(device.host, device);
    }
  }

  const onvifByHost = new Map<string, DiscoveredDevice>();
  for (const device of onvifResults) {
    if (!onvifByHost.has(device.host)) onvifByHost.set(device.host, device);
  }

  return [...brandByHost.values(), ...onvifByHost.values()];
}

// Axis cameras answer ONVIF WS-Discovery (branded 'axis' by its scope,
// onvif://…/name/AXIS_…), but ship with ONVIF control disabled by default,
// so they're edited over their own VAPIX HTTP API, not ONVIF. For each such
// ONVIF reply, a separate 'Axis' brand row is added (alongside the ONVIF row,
// exactly as a Dahua device shows a Dahua row plus an ONVIF one) carrying the
// VAPIX edit capability; the ONVIF sibling then serves as the retry fallback.
// Axis applies address and port changes without a reboot, so mayReboot is
// left off. The 'network' category isn't set — ONVIF doesn't confirm camera
// vs. other Axis gear, the same "never guess the category" rule as elsewhere.
function deriveAxisRows(onvifResults: DiscoveredDevice[]): DiscoveredDevice[] {
  return onvifResults
    .filter((d) => d.guessedVendor === 'axis')
    .map((d): DiscoveredDevice => ({
      host: d.host,
      httpPort: d.httpPort,
      model: d.model,
      manufacturer: d.manufacturer,
      mac: d.mac,
      guessedVendor: 'axis',
      discoveryMethod: 'Axis',
      currentPorts: d.currentPorts,
      networkEdit: { ports: ['http', 'https', 'rtsp'], dns: false, username: true, dhcp: true },
    }));
}

// Hanwha (Wisenet) cameras answer ONVIF (scope "Hanwha Techwin"), but are
// edited over their own SUNAPI HTTP API (see hanwhaSunapi.ts), not ONVIF —
// same reasoning and shape as deriveAxisRows above. SUNAPI applies IP and port
// changes without a reboot, so mayReboot is left off.
function deriveHanwhaRows(onvifResults: DiscoveredDevice[]): DiscoveredDevice[] {
  return onvifResults
    .filter((d) => d.guessedVendor === 'hanwha')
    .map((d): DiscoveredDevice => ({
      host: d.host,
      httpPort: d.httpPort,
      model: d.model,
      manufacturer: d.manufacturer,
      mac: d.mac,
      guessedVendor: 'hanwha',
      discoveryMethod: 'Hanwha',
      currentPorts: d.currentPorts,
      networkEdit: { ports: ['http', 'https', 'rtsp'], dns: false, username: true, dhcp: true },
    }));
}

// Normalizes every row's MAC to one format (see normalizeMac) and flags
// devices outside every local subnet. Both are pure, so they run before —
// and survive a failure of — the ARP step below.
function normalizeRows(scanned: DiscoveredDevice[]): DiscoveredDevice[] {
  const interfaces = localIPv4Interfaces();
  return scanned.map((device) => ({
    ...device,
    mac: normalizeMac(device.mac),
    otherSubnet: !isOnLocalSubnet(device.host, interfaces) || undefined,
  }));
}

// Fills in MACs for rows whose protocol didn't report one (every ONVIF row,
// plus any vendor row with an empty MAC field) — first from a sibling row
// for the same host whose vendor SDK did report it, then from the OS ARP
// table for whatever's still missing. Devices outside every local subnet
// are skipped for the ARP lookup, since the PC routes to them via its
// gateway and would only ever poke (and ARP) the gateway.
async function fillMissingMacs(devices: DiscoveredDevice[]): Promise<DiscoveredDevice[]> {
  const macByHost = new Map<string, string>();
  for (const device of devices) {
    if (device.mac && !macByHost.has(device.host)) macByHost.set(device.host, device.mac);
  }

  const unresolved = new Map<string, number | undefined>();
  for (const device of devices) {
    if (!device.otherSubnet && !macByHost.has(device.host) && !unresolved.has(device.host)) {
      unresolved.set(device.host, device.httpPort);
    }
  }
  const arpMacs = await lookupMacAddresses([...unresolved].map(([host, port]) => ({ host, port })));
  for (const host of unresolved.keys()) {
    const mac = arpMacs.get(host);
    if (mac) macByHost.set(host, mac);
  }

  return devices.map((device) => (device.mac ? device : { ...device, mac: macByHost.get(device.host) }));
}

// Dahua (and Sunell) devices whose reply to the broadcast search didn't
// reach this PC — the MAC says Dahua, but no Dahua row — are asked directly
// with Dahua's search-by-IP (see searchDahuaByIps); only on the PC's subnet,
// and only when there are such devices. An answer replaces the host's
// unconfirmed brand row, as collapseToTwoPerHost would have, or joins its
// ONVIF row.
async function addDahuaByIp(devices: DiscoveredDevice[]): Promise<DiscoveredDevice[]> {
  const dahuaHosts = new Set(devices.filter((d) => d.discoveryMethod === 'Dahua').map((d) => d.host));
  const candidates = [
    ...new Set(
      devices
        .filter((d) => !d.otherSubnet && !dahuaHosts.has(d.host) && (vendorFromMac(d.mac) === 'dahua' || vendorFromMac(d.mac) === 'sunell'))
        .map((d) => d.host),
    ),
  ];
  const found = new Map((await searchDahuaByIps(candidates)).map((d) => [d.host, { ...d, mac: normalizeMac(d.mac) }]));
  if (found.size === 0) return devices;
  const placed = new Set<string>();
  const result = devices.map((device) => {
    const dahua = found.get(device.host);
    if (!dahua || placed.has(device.host) || device.discoveryMethod === 'ONVIF' || device.guessedVendor) return device;
    placed.add(device.host);
    return dahua;
  });
  for (const [host, dahua] of found) if (!placed.has(host)) result.unshift(dahua);
  return result;
}

// The Subnet Mask, Gateway and HTTP Port columns for rows whose protocol
// didn't report them: from a sibling row for the same host (a vendor search
// that did), else from the camera itself over ONVIF without a login, for
// cameras the PC can reach (readOnvifScanInfo). What a row's own protocol
// reported always wins.
async function fillAddressing(devices: DiscoveredDevice[]): Promise<DiscoveredDevice[]> {
  const onvifHosts = [...new Set(devices.filter((d) => d.discoveryMethod === 'ONVIF' && !d.otherSubnet).map((d) => d.host))];
  const fromOnvif = new Map(await Promise.all(onvifHosts.map(async (host) => [host, await readOnvifScanInfo(host)] as const)));
  return devices.map((device) => {
    const siblings = devices.filter((d) => d.host === device.host);
    const onvif = fromOnvif.get(device.host);
    const http = device.currentPorts?.http ?? onvif?.httpPort;
    return {
      ...device,
      subnetMask: device.subnetMask ?? siblings.find((d) => d.subnetMask)?.subnetMask ?? onvif?.subnetMask,
      gateway: device.gateway ?? siblings.find((d) => d.gateway)?.gateway ?? onvif?.gateway,
      currentPorts: http !== undefined ? { ...device.currentPorts, http } : device.currentPorts,
    };
  });
}

// Rows whose own protocol didn't confirm a brand get the maker their MAC is
// registered to, where that's one of the camera makers in macVendors.ts —
// e.g. a Dahua camera only an unbranded relayed Uniview or ONVIF reply
// found. Runs after the MAC fill-in, which is where those rows get a MAC.
function brandFromMac(devices: DiscoveredDevice[]): DiscoveredDevice[] {
  return devices.map((device) => {
    if (device.guessedVendor) return device;
    const vendor = vendorFromMac(device.mac);
    return vendor ? { ...device, guessedVendor: vendor } : device;
  });
}

// Final pass over edit capabilities, where reachability is known:
//   - ONVIF rows become editable (via services/onvifNetwork.ts) when the PC
//     can reach the camera and no vendor row for the same host already is —
//     the vendor search commands are preferred where they exist, since they
//     also work across subnets and are confirmed on real hardware.
//   - TVT and Uniview change ports through a login / HTTP call to the
//     device's current address, which can't reach a device outside the PC's
//     subnet — and since ports go first, offering them there would abort the
//     search-level IP change that does work. So those rows lose their port
//     fields until the device has been moved into the PC's subnet.
//   - Hikvision changes everything through ISAPI, plain HTTP to the device's
//     current address, so a Hikvision device outside the PC's subnet can't
//     be changed here at all.
//   - Uniview switches to DHCP over ONVIF (its own search-level command has
//     no DHCP setting), so only where the camera answers ONVIF and the PC
//     can reach it.
//   - Sunell cameras answer Dahua's search but ignore its HTTP port, so
//     their web/RTSP ports go over ONVIF — likewise only where the camera
//     answers ONVIF and the PC can reach it.
function adjustEditCapabilities(devices: DiscoveredDevice[]): DiscoveredDevice[] {
  const vendorEditableHosts = new Set(devices.filter((d) => d.networkEdit).map((d) => d.host));
  const onvifHosts = new Set(devices.filter((d) => d.discoveryMethod === 'ONVIF').map((d) => d.host));
  return devices.map((device) => {
    if (device.discoveryMethod === 'ONVIF' && !device.otherSubnet && !vendorEditableHosts.has(device.host)) {
      return { ...device, networkEdit: { ports: ['http', 'https', 'rtsp'], dns: false, username: true, dhcp: true, mayReboot: true } };
    }
    if (device.discoveryMethod === 'Uniview' && device.networkEdit && !device.otherSubnet && onvifHosts.has(device.host)) {
      return { ...device, networkEdit: { ...device.networkEdit, dhcp: true } };
    }
    if (device.guessedVendor === 'sunell' && device.networkEdit && !device.otherSubnet && onvifHosts.has(device.host)) {
      return { ...device, networkEdit: { ...device.networkEdit, ports: ['http', 'https', 'rtsp', 'device'] } };
    }
    if (device.otherSubnet && device.networkEdit && device.discoveryMethod === 'Axis') {
      return {
        ...device,
        networkEdit: undefined,
        editUnavailableReason:
          "This Axis camera is outside this PC's subnet. Its settings are changed through its own VAPIX web API, which only reaches devices on the PC's subnet — put the PC on the device's subnet first.",
      };
    }
    if (device.otherSubnet && device.networkEdit && device.discoveryMethod === 'Hanwha') {
      return {
        ...device,
        networkEdit: undefined,
        editUnavailableReason:
          "This Hanwha camera is outside this PC's subnet. Its settings are changed through its own SUNAPI web API, which only reaches devices on the PC's subnet — put the PC on the device's subnet first.",
      };
    }
    if (device.otherSubnet && device.networkEdit && device.discoveryMethod === 'Hikvision SADP') {
      return {
        ...device,
        networkEdit: undefined,
        editUnavailableReason:
          "This Hikvision device is outside this PC's subnet. Its settings are changed through its own web API, which only reaches devices on the PC's subnet — put the PC on the device's subnet (or use Hikvision's SADP tool) first.",
      };
    }
    if (device.otherSubnet && device.networkEdit && (device.discoveryMethod === 'TVT' || device.discoveryMethod === 'Uniview')) {
      return {
        ...device,
        networkEdit: {
          ...device.networkEdit,
          ports: [],
          portsUnavailableReason: "Ports can be changed once the device is in this PC's subnet — change its IP first, then rescan.",
        },
      };
    }
    return device;
  });
}

// A brand-editable row whose device also answers ONVIF on this subnet can,
// if its own method fails, be retried over ONVIF from the Edit dialog. The
// ONVIF duplicate row itself isn't marked (it's already ONVIF).
function markOnvifFallback(devices: DiscoveredDevice[]): DiscoveredDevice[] {
  const onvifHosts = new Set(devices.filter((d) => d.discoveryMethod === 'ONVIF').map((d) => d.host));
  return devices.map((device) =>
    device.networkEdit && device.discoveryMethod !== 'ONVIF' && !device.otherSubnet && onvifHosts.has(device.host)
      ? { ...device, networkEdit: { ...device.networkEdit, onvifFallback: true } }
      : device,
  );
}

// Which rows the Reboot action can reach (ipc/device.ts picks the route):
// Hikvision over ISAPI where it can be edited (activated, on the PC's
// subnet), a TVT NVR/DVR over its SDK login on the PC's subnet, and
// everything else over ONVIF — the camera has to answer ONVIF and the PC
// has to reach it.
function markRebootable(devices: DiscoveredDevice[]): DiscoveredDevice[] {
  const onvifHosts = new Set(devices.filter((d) => d.discoveryMethod === 'ONVIF').map((d) => d.host));
  return devices.map((device) => {
    if (device.otherSubnet) return device;
    const rebootable =
      device.discoveryMethod === 'Hikvision SADP' || device.discoveryMethod === 'Axis' || device.discoveryMethod === 'Hanwha'
        ? device.networkEdit !== undefined // ISAPI / VAPIX / SUNAPI restart, on the PC's subnet
        : device.discoveryMethod === 'TVT' && device.deviceCategory !== 'ipc'
          ? true
          : onvifHosts.has(device.host);
    return rebootable ? { ...device, rebootable } : device;
  });
}

// Which rows the Factory reset action can reach (ipc/device.ts picks the
// route), and which modes each route offers:
//   - Uniview rows: its own LAPI reset (Mode 0 keeps the network + login,
//     Mode 1 doesn't — on some models it also erases the SD card).
//   - Dahua rows: its SDK's restore-default control (no-network mask) or
//     CLIENT_ResetSystem — both on a logged-in TCP session, so only on the
//     PC's subnet and only for rows the search has a full record for.
//   - Hikvision SADP rows: ISAPI's factoryReset (basic / full) — the same
//     reachability rules as the Edit route (activated, on the PC's subnet).
//   - TVT rows: their SDK's reset is NVR-only, so the camera route is
//     ONVIF's SetSystemFactoryDefault (Soft keeps the network) — offered
//     only where the device also answers ONVIF on this subnet.
// Deliberately hidden from rows known to be DVRs/NVRs (per request); a row
// whose category no protocol confirmed still shows the action — the dialog
// is the confirmation before anything destructive runs.
function markFactoryResettable(devices: DiscoveredDevice[]): DiscoveredDevice[] {
  const onvifHosts = new Set(devices.filter((d) => d.discoveryMethod === 'ONVIF').map((d) => d.host));
  return devices.map((device) => {
    if (device.otherSubnet || device.deviceCategory === 'dvr_nvr') return device;
    let cap: FactoryResetCapability | undefined;
    if (device.discoveryMethod === 'Uniview' || device.discoveryMethod === 'Dahua' || device.discoveryMethod === 'Hikvision SADP') {
      cap = { keepNetwork: true, full: true, mayReboot: true };
      if (device.discoveryMethod === 'Uniview') cap.fullNote = 'A full reset on some Uniview cameras also erases the SD card.';
    } else if (device.discoveryMethod === 'TVT' && onvifHosts.has(device.host)) {
      cap = { keepNetwork: true, full: true, mayReboot: true };
    }
    return cap ? { ...device, factoryReset: cap } : device;
  });
}

// Each protocol runs isolated — one failing (most likely a native addon or
// its SDK runtime DLL failing to load) used to reject the whole
// Promise.all and throw away every other protocol's results, so a single
// broken vendor SDK meant the scan found nothing at all. A failed
// protocol now just contributes no rows.
async function runIsolated(
  protocol: string,
  discover: () => Promise<DiscoveredDevice[]>,
): Promise<DiscoveredDevice[]> {
  try {
    return await discover();
  } catch (error) {
    console.error(`[discovery] ${protocol} scan failed, skipping:`, error);
    return [];
  }
}

export function registerDiscoveryIpcHandlers(): void {
  // Wi-Tek APs only announce themselves with an occasional UDP beacon and
  // answer no request, so a listener runs for the app's lifetime and a scan
  // reports what it's heard (see witekDiscovery.ts).
  startWitekListener();

  ipcMain.handle('discovery:scan', async (): Promise<DiscoveredDevice[]> => {
    const [onvifResults, hikvisionResults, univiewResults, tvtResults, dahuaResults, ubiquitiResults, witekResults] = await Promise.all([
      runIsolated('ONVIF', discoverOnvifDevices),
      runIsolated('Hikvision SADP', discoverHikvisionDevices),
      runIsolated('Uniview', discoverUniviewDevices),
      runIsolated('TVT', discoverTvtDevices),
      runIsolated('Dahua', discoverDahuaDevices),
      runIsolated('Ubiquiti', discoverUbiquitiDevices),
      // Wi-Tek is heard by a background listener (started below), not probed
      // per scan — this just reads what it's collected, so it's instant.
      runIsolated('Wi-Tek', async () => discoverWitekDevices()),
    ]);
    const rows = normalizeRows(
      collapseToTwoPerHost(onvifResults, [
        ...univiewResults,
        ...hikvisionResults,
        ...tvtResults,
        ...dahuaResults,
        ...ubiquitiResults,
        ...witekResults,
        ...deriveAxisRows(onvifResults),
        ...deriveHanwhaRows(onvifResults),
      ]),
    );
    // The MAC fill-in talks to the network and spawns arp — contained like
    // each protocol above, so it can never throw the whole scan away.
    let withMacs = rows;
    try {
      withMacs = await fillMissingMacs(rows);
    } catch (error) {
      console.error('[discovery] MAC fill-in failed, returning results without it:', error);
    }
    // Contained like the MAC fill-in.
    let withDahua = withMacs;
    try {
      withDahua = await addDahuaByIp(withMacs);
    } catch (error) {
      console.error('[discovery] Dahua search-by-IP failed, returning results without it:', error);
    }
    // Contained too: a failure leaves those columns blank.
    let withAddressing = withDahua;
    try {
      withAddressing = await fillAddressing(withDahua);
    } catch (error) {
      console.error('[discovery] mask/gateway fill-in failed, returning results without it:', error);
    }
    const devices = markOnvifFallback(markRebootable(markFactoryResettable(adjustEditCapabilities(brandFromMac(withAddressing)))));
    setLastScan(devices);
    return devices;
  });
}
