// Types shared across main, preload, and renderer (IPC payload shapes).

export type VendorId = 'hikvision' | 'dahua' | 'tvt' | 'uniview' | 'sunell' | 'ubiquiti' | 'witek' | 'axis' | 'hanwha' | 'onvif';

export const VENDOR_LABELS: Record<VendorId, string> = {
  hikvision: 'HIK',
  dahua: 'DAH',
  tvt: 'TVT',
  uniview: 'UNV',
  sunell: 'SUNELL',
  ubiquiti: 'UBNT',
  witek: 'WITEK',
  axis: 'AXIS',
  hanwha: 'HANWHA',
  onvif: 'ONVIF',
};

export type ThemeMode = 'light' | 'dark' | 'auto';

// One entry per discovery PROTOCOL that answered, not one per physical
// device — deliberately different from SSM-VMS's own device list (which
// collapses to one row per host, since it's managing devices to add). This
// tool's whole purpose is surveying a network, so a device that answers
// both its own vendor's broadcast AND ONVIF WS-Discovery is genuinely
// useful information shown as two rows, not noise to hide (see
// project_dvr_scanner_tool memory's own note on why this differs from the
// VMS). `discoveryMethod` is always set (the protocol itself is always
// known); `guessedVendor` is only set when that protocol's own response
// data actually confirmed the brand — never a bare guess from "something
// answered," the same hard-won lesson from SSM-VMS's own discovery work —
// or when the device's MAC is registered to a camera maker the tool knows
// (services/macVendors.ts).
// Coarse device classification for the "Device Type" filter — only set
// when the discovering protocol's own response data genuinely confirms it
// (same "never guess" rule as guessedVendor above), sourced from each
// vendor's own real SDK enum, not inferred from the model string:
//   - Uniview: NETDEV_DISCOVERY_DEVINFO_S.enDevType (NETDEV_DTYPE_IPC*
//     range = 'ipc', NETDEV_DTYPE_NVR*/HNVR range = 'dvr_nvr' — confirmed
//     directly from NetDEVSDK.h's own enum, not a guess).
//   - TVT: NET_SDK_DEVICE_DISCOVERY_INFO.deviceType (NET_SDK_DEVICE_TYPE
//     enum: IPCAMERA = 'ipc', DVR/NVR/SUPERDVR/N_DVR = 'dvr_nvr' —
//     confirmed directly from DVR_NET_SDK.h's own enum. DVS/DECODER don't
//     map cleanly to either bucket, left unset).
//   - Dahua: DEVICE_NET_INFO_EX.szDeviceType — a real field that exists in
//     the struct, but its exact string values are NOT yet confirmed
//     against real hardware (unlike Uniview/TVT's enums, this is a raw
//     string with no doc'd value list for this specific struct — a
//     same-named-but-different field elsewhere in the SDK is documented
//     as literally "IPC"/"DVR"/"NVR" strings, which is why a string-match
//     mapping is used here, but treat this as unconfirmed until a live
//     scan's diagnostic log proves it).
//   - Hikvision (SADP) and ONVIF: not populated at all — SADP's own
//     DeviceType field's exact semantics were never confirmed even via
//     public reverse-engineering docs, and ONVIF's WS-Discovery Types
//     field stays constant across camera and NVR alike, so neither can
//     reliably distinguish the two without further live-hardware research.
//   - 'network' is non-camera network gear (APs, switches): Ubiquiti and
//     Wi-Tek rows, which this tool detects but doesn't manage.
export type DeviceCategory = 'dvr_nvr' | 'ipc' | 'network';

export interface DiscoveredDevice {
  host: string;
  port?: number;
  httpPort?: number;
  model?: string;
  manufacturer?: string;
  mac?: string;
  subnetMask?: string;
  gateway?: string;
  guessedVendor?: VendorId;
  deviceCategory?: DeviceCategory;
  discoveryMethod: string;
  // Set when the device's IP is outside every one of this PC's own
  // subnets — found via broadcast/multicast on the same LAN, but not
  // reachable (Open won't load) until its IP is changed into the PC's
  // range or the PC is given an address in the device's range.
  otherSubnet?: boolean;
  networkEdit?: NetworkEditCapability;
  // Why Edit can't change this row's device, when there's a specific reason
  // the user can act on (e.g. a Hikvision camera that hasn't been activated).
  editUnavailableReason?: string;
  // Port values the discovery reply itself reported, for pre-filling Edit.
  currentPorts?: PortSettings;
  // Whether the device gets its address by DHCP, when the discovery reply
  // says (SADP, Dahua, TVT) — pre-fills Edit's DHCP checkbox.
  dhcp?: boolean;
  // The Reboot action can reach this row's device (see ipc/discovery.ts).
  rebootable?: boolean;
  // The Factory reset action can reach this row's device, and which modes
  // that brand's route offers (see ipc/discovery.ts's markFactoryResettable).
  factoryReset?: FactoryResetCapability;
  // A Hikvision device that reports it supports a forgotten-admin-password
  // reset (SADP's own flags), and which methods — shown as a marker in the
  // table. `importFile` is the export-request-XML / import-signed-XML flow.
  passwordReset?: { importFile: boolean; securityQuestion: boolean };
}

// Ports a device can have changed from the Edit dialog. `device` is the
// vendor's own SDK/data port (TVT's "network port", Dahua's TCP port) —
// what NVRs and VMS software connect to.
export type PortKind = 'http' | 'https' | 'rtsp' | 'device';
export type PortSettings = Partial<Record<PortKind, number>>;

// What the Edit dialog can change on this row's device, and through what.
// Only set on rows where that's genuinely possible; undefined means Edit
// can't change this row's device (yet):
//   - Dahua (CLIENT_ModifyDeviceEx, no login): IP/mask/gateway (or DHCP)
//     plus HTTP and device port, all in the one search-level command.
//   - TVT: IP/mask/gateway/DNS via NET_SDK_SetDeviceIP (no login, admin
//     password only), and DHCP (or back to static) via
//     NET_SDK_ModifyDeviceNetInfo, the same kind of call with the IP mode;
//     ports via login + the device's own NVMS-9000 API
//     (queryNetPortCfg/editNetPortCfg — the same calls its web UI makes).
//   - Uniview (only devices whose Uniview discovery reply carried a MAC +
//     serial number): IP/mask/gateway via NETDEV_ModifyDeviceAddr (no
//     login); ports through the camera's own LAPI (GET/PUT
//     /LAPI/V1.0/NetWork/Port, as its web page does), falling back to ONVIF
//     — the SDK's own port command isn't supported over the ONVIF login its
//     manual requires for IPCs/NVRs (confirmed live); DHCP over ONVIF, where
//     the camera answers it (the SDK's command has no DHCP setting).
//     Devices that answer the Uniview search with just a model name
//     (SSM/IPCY and other generic cameras) ignore its modify command —
//     confirmed live — and use the ONVIF route.
//   - Hikvision (SADP-discovered, activated devices the PC can reach — same
//     subnet only): IP/mask/gateway (or DHCP) and HTTP/HTTPS/RTSP/device ports through
//     ISAPI, the device's own web API (services/hikvisionIsapi.ts). Reboots
//     the device when it says a change needs one.
//   - ONVIF (SetNetworkInterfaces/SetNetworkDefaultGateway/
//     SetNetworkProtocols): IP/mask/gateway (or DHCP) and HTTP/HTTPS/RTSP ports for
//     any ONVIF camera the PC can reach (same subnet only — plain HTTP to
//     the camera), offered only when no vendor row for the same host is
//     editable. May reboot the camera if it says it needs one.
export interface NetworkEditCapability {
  ports: PortKind[];
  dns: boolean;
  username: boolean;
  // The route can switch the device to DHCP (NetworkSettings.dhcp).
  dhcp?: boolean;
  // The device may be rebooted to apply an IP change / a port change.
  mayReboot?: boolean;
  portsMayReboot?: boolean;
  // The device also answers ONVIF and is on this PC's subnet, so if this
  // (brand) method fails, the Edit dialog can offer to retry over ONVIF.
  onvifFallback?: boolean;
  // Why `ports` is empty for this row, when that's a temporary condition
  // the user can resolve (e.g. the device is outside the PC's subnet).
  portsUnavailableReason?: string;
}

export interface NetworkSettings {
  // The device gets its address from the network's DHCP server instead;
  // ip, subnetMask and gateway are then not applied (DNS still is, where
  // the route sets DNS).
  dhcp?: boolean;
  ip: string;
  subnetMask: string;
  gateway: string;
  dns1?: string;
  dns2?: string;
}

// Only what the user actually changed: `network` is omitted when the IP,
// mask, gateway (and DNS) were left alone, and `ports` holds just the ports
// being changed — so a ports-only edit never re-sends IP settings (TVT's IP
// command would also overwrite DNS).
export interface ModifyNetworkRequest {
  host: string;
  discoveryMethod: string;
  // MAC of the row being edited, so each route targets that exact device
  // even when several devices answered from the same IP (e.g. two cameras
  // still on the same factory-default address).
  mac?: string;
  network?: NetworkSettings;
  ports?: PortSettings;
  username: string;
  password: string;
}

// Reboot from the Actions column: the row's device, found the same way as
// for an edit (host + MAC), with its login.
export interface RebootRequest {
  host: string;
  discoveryMethod: string;
  mac?: string;
  username: string;
  password: string;
}

// `warning` on success means the command went out but the result couldn't
// be fully confirmed (see modifyTvtDevice) — shown instead of a plain
// "accepted" message. `message` replaces the dialog's own success text
// with what the route found out (e.g. the address a device got by DHCP).
export type ModifyNetworkResult = { ok: true; warning?: string; message?: string } | { ok: false; error: string };

// The two shapes a factory reset can take, the way every supported brand
// splits it (Uniview LAPI Mode 0/1, Hikvision ISAPI basic/full, ONVIF
// Soft/Hard, Dahua's restore-mask with or without NETWORK):
//   - keep_network: everything returns to factory defaults EXCEPT the IP
//     settings and the admin login — the device reboots and comes straight
//     back at the same address, still answering the same password.
//   - full: everything resets including the IP settings and login. The
//     device comes back at its factory address (often a different subnet)
//     and may need activating with a new password before it's usable.
export type FactoryResetMode = 'keep_network' | 'full';

// Factory reset from the Actions column: the row's device, found the same
// way as a reboot or an edit (host + MAC), with its login and the chosen
// mode.
export interface FactoryResetRequest {
  host: string;
  discoveryMethod: string;
  // MAC of the row being reset, so each route targets that exact device
  // even when several devices answered from the same IP.
  mac?: string;
  mode: FactoryResetMode;
  username: string;
  password: string;
}

// What the Factory reset action can do on this row's device:
//   - keepNetwork/full: which modes the route offers (undefined mode means
//     the button isn't shown for that choice).
//   - mayReboot: the device reboots to apply either reset.
//   - fullNote: a brand-specific warning shown with the full-reset choice
//     (e.g. Uniview's full reset may also erase the SD card).
export interface FactoryResetCapability {
  keepNetwork: boolean;
  full: boolean;
  mayReboot?: boolean;
  fullNote?: string;
}
