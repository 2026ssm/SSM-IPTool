import { join } from 'path';
import { app } from 'electron';
import type { DeviceCategory, DiscoveredDevice, ModifyNetworkRequest, ModifyNetworkResult } from '../../shared/types';
import { changeOnvifPorts, hasOnvifService, modifyOnvifDevice } from './onvifNetwork';
import { changeUniviewPortsViaLapi } from './univiewLapi';
import { isOnLocalSubnet } from './networkInterfaces';
import { pickEditedDevice } from './scanResults';

interface NativeDiscoveredDevice {
  host: string;
  port: number;
  model: string;
  serialNumber: string;
  mac: string;
  name: string;
  manufacturer: string;
  // NETDEV_DEVICE_TYPE_E, straight from NetDEVSDK.h's own enum.
  deviceType: number;
}

// NETDEV_DTYPE_IPC=1, _FISHEYE=2, _ECONOMIC_FISHEYE=3, _ACS=4 (all IPC
// variants); NETDEV_DTYPE_NVR=101, _NVR_BACKUP=102, _HNVR=103 (all NVR
// variants). Everything else (DC/EC/VMS/FG/IPM/EDU ranges, or unknown/0)
// is a real device class this SDK supports but doesn't fit either bucket,
// left uncategorized rather than forced into the wrong one.
function categoryFromDeviceType(deviceType: number): DeviceCategory | undefined {
  if (deviceType >= 1 && deviceType <= 4) return 'ipc';
  if (deviceType >= 101 && deviceType <= 103) return 'dvr_nvr';
  return undefined;
}

interface NativeAddon {
  startDiscovery(onDevice: (device: NativeDiscoveredDevice) => void): void;
  stopDiscovery(): void;
  modifyDevice(params: {
    username: string;
    password: string;
    ip: string;
    gateway: string;
    subnetMask: string;
    serialNumber: string;
    mac: string;
  }): Promise<{ ok: boolean; errorCode?: number }>;
}

// Every record from the most recent search, in arrival order — several
// devices can share an IP, and the SDK also relays other devices' replies
// for an IP without a MAC, so the one being edited is picked by MAC (see
// pickEditedDevice) rather than by host.
let lastSeen: NativeDiscoveredDevice[] = [];

// NETDEV_ModifyDeviceAddr identifies the device by the serial number + MAC
// its discovery reply carried. Devices that answer NETDEV_Discovery with
// only a model name (confirmed live: every SSM/IPCY and generic-firmware
// camera on the test network, plus the Dahua there) give it nothing to
// target, so Edit isn't offered for those rows.
function canModify(device: NativeDiscoveredDevice): boolean {
  return Boolean(device.mac.trim() && device.serialNumber.trim());
}

let cachedNative: NativeAddon | null = null;

function resolveAddonPath(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'native/uniview/build/Release/uniview_native.node');
  }
  return join(__dirname, '../../native/uniview/build/Release/uniview_native.node');
}

function loadNative(): NativeAddon {
  if (!cachedNative) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cachedNative = require(resolveAddonPath()) as NativeAddon;
  }
  return cachedNative;
}

const DISCOVERY_DURATION_MS = 3000;

// NETDEV_Discovery is confirmed live (in SSM-VMS) to be answered by plenty
// of non-Uniview cameras too — many OEM/white-label devices share chipset
// firmware that responds to several vendors' discovery formats. Only trust
// the vendor when the device's own manufacturer field actually says
// "UNV"/"UNIVIEW" — an unconfirmed response still surfaces with real
// host/port/model (better than nothing), just without a vendor claim.
export async function discoverUniviewDevices(): Promise<DiscoveredDevice[]> {
  const results: DiscoveredDevice[] = [];
  const seen: NativeDiscoveredDevice[] = [];
  loadNative().startDiscovery((device) => {
    seen.push(device);
    const isConfirmedUniview = /^(unv|uniview)$/i.test(device.manufacturer.trim());
    results.push({
      host: device.host,
      port: device.port,
      model: device.model,
      manufacturer: isConfirmedUniview ? 'Uniview' : undefined,
      guessedVendor: isConfirmedUniview ? 'uniview' : undefined,
      mac: device.mac || undefined,
      deviceCategory: categoryFromDeviceType(device.deviceType),
      discoveryMethod: 'Uniview',
      // Ports are changed through the camera's own LAPI (or ONVIF), not this
      // SDK — see modifyUniviewDevice.
      networkEdit: canModify(device) ? { ports: ['http', 'https', 'rtsp'], dns: false, username: true } : undefined,
      // On genuine Uniview replies (MAC + serial) the discovery port is the
      // device's HTTP port — it matched every test device's own ONVIF XAddr
      // port (80, 8082, 8086, 84). Not on the MAC-less rows: those are other
      // cameras' ONVIF replies relayed through the SDK, and their port is
      // the ONVIF service's (8080 on a camera whose web port is 8081).
      currentPorts: canModify(device) && device.port > 0 ? { http: device.port } : undefined,
    });
  });
  await new Promise((resolve) => setTimeout(resolve, DISCOVERY_DURATION_MS));
  loadNative().stopDiscovery();
  lastSeen = seen;
  return results;
}

// NETDEV_GetLastError values from NetDEVSDK.h's NETDEV_E_* enum.
const UNIVIEW_ERRORS: Record<number, string> = {
  3: 'The device refused the login (not authorized).',
  5: "That username doesn't exist on the device.",
  102: 'The device rejected one of the settings as invalid.',
  113: "The device doesn't support this.",
  114: 'No response from the device (timed out).',
  200: "Couldn't connect to the device on its web port.",
  11201: 'Wrong password.',
  11202: "That username doesn't exist on the device.",
  11203: "That account doesn't have permission to change network settings.",
  11206: 'Too many users are logged in to the device right now. Try again later.',
  11207: 'The account is locked — too many failed attempts. Wait and try again later.',
  11211: 'The device has temporarily locked out logins from this PC after failed attempts. Wait and try again later.',
  11214: 'The device refuses remote logins until its weak password is changed.',
  11219: 'The device requires its password to be changed before it can be managed.',
  11221: "This PC's IP isn't allowed to log in to the device.",
};

// Ports don't go through this SDK: its manual says IPCs and NVRs only
// accept its ONVIF login, and over that login NETDEV_GET_NETWORK_PORTS
// fails with an undocumented error 8 (the private-protocol login was
// refused with an undocumented 460) — both confirmed live on real Uniview
// IPCs. Instead: the camera's own LAPI port endpoint, exactly as its web
// page uses it (services/univiewLapi.ts); ONVIF only as a fallback for
// devices without that endpoint (ONVIF refused an HTTP port change on a
// test camera while accepting RTSP). Ports first (at the current address),
// then IP settings through NETDEV_ModifyDeviceAddr — each only if changed.
export async function modifyUniviewDevice(request: ModifyNetworkRequest): Promise<ModifyNetworkResult> {
  const device = pickEditedDevice(lastSeen, request.host, request.mac);
  if (!device) return { ok: false, error: 'This device is no longer in the Uniview search results. Scan again and retry.' };
  if (!canModify(device)) {
    return { ok: false, error: "This device didn't report a MAC and serial number to the Uniview search, so it can't be changed this way." };
  }
  // NETDEV_ModifyDeviceAddr needs a gateway (the SDK's own demo refuses an
  // empty one), and Uniview's search doesn't report the current one to keep
  // — so ask rather than guess. Checked before anything is sent.
  if (request.network && !request.network.dhcp && !request.network.gateway) {
    return { ok: false, error: "Enter the gateway — Uniview's IP command needs one (use 0.0.0.0 if the network has none)." };
  }
  // Ports go over HTTP to the device's current address, which can't reach a
  // device outside the PC's subnet — and failing there first would also
  // block the IP change that does work across subnets.
  const wantsPorts = request.ports !== undefined && Object.keys(request.ports).length > 0;
  if (wantsPorts && !isOnLocalSubnet(device.host)) {
    return { ok: false, error: "Ports can only be changed while the device is in this PC's subnet — change its IP first, rescan, then change the ports." };
  }

  let portsChanged = false;
  let portsWarning: string | undefined;
  if (wantsPorts && request.ports) {
    let portsResult = await changeUniviewPortsViaLapi(
      device.host,
      device.port || 80,
      { username: request.username, password: request.password },
      request.ports,
    );
    if (!portsResult) {
      portsResult = hasOnvifService(device.host)
        ? await changeOnvifPorts(request, request.ports)
        : { ok: false, error: "This device doesn't offer a way to change its ports from here (no LAPI port settings, and it doesn't answer ONVIF)." };
    }
    if (!portsResult.ok || !request.network) return portsResult;
    portsChanged = true;
    portsWarning = portsResult.warning;
  }
  if (!request.network) return { ok: true };

  const net = request.network;
  // Uniview's search-level command has no DHCP setting (NETDEV_DEV_ADDR_INFO_S
  // carries only the address), so DHCP goes over ONVIF's standard
  // SetNetworkInterfaces — offered only where the camera answers ONVIF.
  if (net.dhcp) {
    const dhcpResult = hasOnvifService(device.host)
      ? await modifyOnvifDevice({ ...request, ports: undefined })
      : { ok: false as const, error: "This device can't be switched to DHCP from here: Uniview's own command has no DHCP setting, and it doesn't answer ONVIF." };
    if (!dhcpResult.ok) return { ok: false, error: portsChanged ? `The ports were changed, but switching to DHCP failed: ${dhcpResult.error}` : dhcpResult.error };
    const warning = [portsWarning, dhcpResult.warning].filter(Boolean).join(' ');
    return warning ? { ok: true, warning } : dhcpResult;
  }
  const result = await loadNative().modifyDevice({
    username: request.username,
    password: request.password,
    ip: net.ip,
    gateway: net.gateway,
    subnetMask: net.subnetMask,
    serialNumber: device.serialNumber,
    mac: device.mac,
  });
  if (!result.ok) {
    const code = result.errorCode ?? 0;
    const error = UNIVIEW_ERRORS[code] ?? `The device refused the change (Uniview error ${code}).`;
    return { ok: false, error: portsChanged ? `The ports were changed, but the IP change failed: ${error}` : error };
  }
  return portsWarning ? { ok: true, warning: portsWarning } : { ok: true };
}
