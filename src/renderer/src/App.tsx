import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { theme, applyThemeMode, getCurrentThemeMode, THEME_CHANGE_EVENT } from './theme';
import { VENDOR_LABELS } from '../../shared/types';
import type { DeviceCategory, DiscoveredDevice, PortKind, PortSettings } from '../../shared/types';
import logoWhite from './assets/logo-white.png';
import logoNavy from './assets/logo-navy.png';

// Plain SVG (stroke/fill=currentColor) instead of the ☀/🌙 emoji glyphs —
// Windows renders those via its color-emoji font, which blurs/aliases
// against a light background. Same fix as SSM-VMS's shell/icons.tsx.
function SunIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <line x1="12" y1="2" x2="12" y2="4.5" />
      <line x1="12" y1="19.5" x2="12" y2="22" />
      <line x1="2" y1="12" x2="4.5" y2="12" />
      <line x1="19.5" y1="12" x2="22" y2="12" />
      <line x1="4.9" y1="4.9" x2="6.6" y2="6.6" />
      <line x1="17.4" y1="17.4" x2="19.1" y2="19.1" />
      <line x1="4.9" y1="19.1" x2="6.6" y2="17.4" />
      <line x1="17.4" y1="6.6" x2="19.1" y2="4.9" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
      <path d="M20.5 14.7A8.5 8.5 0 1 1 9.3 3.5a7 7 0 0 0 11.2 11.2z" />
    </svg>
  );
}

const GENERIC_MODEL_PATTERN = /^(ip\s*cam(era)?|ipcam|generic|unknown)$/i;

function isUsableModel(model: string | undefined): model is string {
  return Boolean(model && model.trim() && !GENERIC_MODEL_PATTERN.test(model.trim()));
}

function displayName(found: DiscoveredDevice): string {
  return isUsableModel(found.model) ? found.model : 'Unknown device';
}

// An ONVIF row for a host that also has a vendor-protocol row is the
// secondary/duplicate entry for the same device — labelled "ONVIF" per
// explicit request so the pair reads as brand row + ONVIF row, instead of
// both showing the same brand. ONVIF-only hosts keep their normal label.
function brandLabel(found: DiscoveredDevice, vendorRowHosts: Set<string>): string {
  if (found.discoveryMethod === 'ONVIF' && vendorRowHosts.has(found.host)) return VENDOR_LABELS.onvif;
  if (found.guessedVendor) return VENDOR_LABELS[found.guessedVendor];
  if (found.model?.trim().toUpperCase().startsWith('IPCY')) return 'SSM';
  return '—';
}

// Device Type filters BEFORE grouping — narrows the list to a coarse
// category confirmed straight from each vendor's own discovery response
// (see shared/types.ts's DeviceCategory doc comment for exactly which
// vendors/fields this comes from and which don't populate it yet).
// "All" is the only option that shows devices with no confirmed category
// (Hikvision/ONVIF entries, or an unconfirmed Dahua szDeviceType) — picking
// DVR/NVR or IPC specifically only shows devices that field genuinely
// confirmed, same "never guess" rule as everything else in this project.
// The Device Type filter is mostly by DeviceCategory, plus 'onvif' which
// filters by discovery method instead (ONVIF rows carry no category).
type DeviceTypeFilter = 'all' | DeviceCategory | 'onvif';

const DEVICE_TYPE_OPTIONS: { value: DeviceTypeFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'dvr_nvr', label: 'DVR/NVR' },
  { value: 'ipc', label: 'IPC' },
  { value: 'network', label: 'Network' },
  { value: 'onvif', label: 'ONVIF' },
];

function filterByDeviceType(devices: DiscoveredDevice[], filter: DeviceTypeFilter): DiscoveredDevice[] {
  if (filter === 'all') return devices;
  if (filter === 'onvif') return devices.filter((d) => d.discoveryMethod === 'ONVIF');
  return devices.filter((d) => d.deviceCategory === filter);
}

// Click a column header to sort by it — the same sortable-header pattern as
// SSM-VMS's own Device Management tables, replacing the earlier standalone
// "Group by" dropdown per explicit request (see ColumnHeader).
type SortKey = 'brand' | 'model' | 'host' | 'mac';

type ColumnKey = 'brand' | 'model' | 'host' | 'mask' | 'gateway' | 'port' | 'mac' | 'via' | 'actions';

// Starting widths (px), sized to fit the 1100px default window; each column
// can be dragged wider or narrower from its header's right edge (double-
// click that edge to reset it), and the widths are remembered. The last
// column takes whatever room is left.
const COLUMNS: { key: ColumnKey; label: string; sortKey?: SortKey; width: number }[] = [
  { key: 'brand', label: 'Brand', sortKey: 'brand', width: 60 },
  { key: 'model', label: 'Model', sortKey: 'model', width: 132 },
  { key: 'host', label: 'IP Address', sortKey: 'host', width: 132 },
  { key: 'mask', label: 'Subnet Mask', width: 100 },
  { key: 'gateway', label: 'Gateway', width: 98 },
  { key: 'port', label: 'HTTP Port', width: 64 },
  { key: 'mac', label: 'MAC Address', sortKey: 'mac', width: 125 },
  { key: 'via', label: 'Found Via', width: 92 },
  { key: 'actions', label: 'Actions', width: 124 },
];
const MIN_COLUMN_WIDTH = 40;
const COLUMN_GAP_PX = 12;
const ROW_PADDING_X_PX = 14;
const COLUMN_WIDTHS_KEY = 'iptool.columnWidths';
const AUTO_SCAN_KEY = 'iptool.autoScan';
const AUTO_SCAN_INTERVAL_MS = 10000;

function loadAutoScan(): boolean {
  try {
    return localStorage.getItem(AUTO_SCAN_KEY) === '1';
  } catch {
    return false;
  }
}

type ColumnWidths = Record<ColumnKey, number>;

function defaultColumnWidths(): ColumnWidths {
  return Object.fromEntries(COLUMNS.map((c) => [c.key, c.width])) as ColumnWidths;
}

// A per-PC convenience only: unreadable or missing storage just means the
// starting widths.
function loadColumnWidths(): ColumnWidths {
  const widths = defaultColumnWidths();
  try {
    const saved = JSON.parse(localStorage.getItem(COLUMN_WIDTHS_KEY) ?? '{}') as Partial<Record<ColumnKey, unknown>>;
    for (const c of COLUMNS) {
      const w = saved[c.key];
      if (typeof w === 'number' && Number.isFinite(w) && w >= MIN_COLUMN_WIDTH) widths[c.key] = w;
    }
  } catch {
    // keep the defaults
  }
  return widths;
}

function saveColumnWidths(widths: ColumnWidths): void {
  try {
    localStorage.setItem(COLUMN_WIDTHS_KEY, JSON.stringify(widths));
  } catch {
    // not remembered this time
  }
}

function columnStyle(width: number, last: boolean): CSSProperties {
  return { flex: `${last ? 1 : 0} 0 ${width}px`, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };
}

// The web (HTTP) port, wherever the row's protocol keeps it: the search's
// own HTTP port or the one read over ONVIF (currentPorts), a vendor reply's
// HTTP port field, or — on Uniview rows — the discovery port, which is the
// HTTP port on genuine Uniview replies. Never the device/SDK port.
function httpPortOf(found: DiscoveredDevice): number | undefined {
  return found.currentPorts?.http ?? found.httpPort ?? (found.discoveryMethod === 'Uniview' ? found.port : undefined);
}
type SortDir = 'asc' | 'desc';

// Dotted-quad IPv4 -> a single comparable number, so "192.168.1.2" sorts
// before "192.168.1.10" (plain string/localeCompare puts "10" before "2"
// since it compares character-by-character, which looks like random order
// to anyone expecting normal IP ordering). Anything that isn't a clean
// IPv4 (e.g. a stray IPv6 host) falls back to -1 and sorts first/last
// consistently rather than throwing.
function ipToComparable(host: string): number {
  const parts = host.split('.');
  if (parts.length !== 4) return -1;
  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return -1;
    value = value * 256 + octet;
  }
  return value;
}

// Edit on an ONVIF (or other non-editable) row opens the editable vendor
// row for the same host when there is one — it's the same physical
// device, and only the vendor SDK can change it.
function editTargetFor(found: DiscoveredDevice, devices: DiscoveredDevice[]): DiscoveredDevice {
  if (found.networkEdit) return found;
  return devices.find((d) => d.host === found.host && d.networkEdit) ?? found;
}

// The row Reboot acts through: this one, or another row for the same host
// that main marked rebootable (e.g. a relayed Uniview row's ONVIF sibling).
function rebootTargetFor(found: DiscoveredDevice, devices: DiscoveredDevice[]): DiscoveredDevice | undefined {
  if (found.rebootable) return found;
  return devices.find((d) => d.host === found.host && d.rebootable);
}

function vendorRowHostsOf(devices: DiscoveredDevice[]): Set<string> {
  return new Set(devices.filter((d) => d.discoveryMethod !== 'ONVIF').map((d) => d.host));
}

function sortValueFor(found: DiscoveredDevice, key: SortKey, vendorRowHosts: Set<string>): string {
  switch (key) {
    case 'brand':
      return brandLabel(found, vendorRowHosts);
    case 'model':
      return displayName(found);
    case 'host':
      return found.host;
    case 'mac':
      return found.mac ?? '';
  }
}

function sortDevices(
  devices: DiscoveredDevice[],
  sort: { key: SortKey; dir: SortDir } | null,
  vendorRowHosts: Set<string>,
): DiscoveredDevice[] {
  if (!sort) return devices;
  const factor = sort.dir === 'asc' ? 1 : -1;
  if (sort.key === 'host') {
    return [...devices].sort((a, b) => factor * (ipToComparable(a.host) - ipToComparable(b.host)));
  }
  return [...devices].sort(
    (a, b) => factor * sortValueFor(a, sort.key, vendorRowHosts).localeCompare(sortValueFor(b, sort.key, vendorRowHosts)),
  );
}

export function App() {
  const [resolvedThemeMode, setResolvedThemeMode] = useState<'light' | 'dark'>('dark');
  const [windowMaximized, setWindowMaximized] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<DeviceTypeFilter>('all');
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir } | null>(null);
  const [editingDevice, setEditingDevice] = useState<DiscoveredDevice | null>(null);
  const [rebootingDevice, setRebootingDevice] = useState<DiscoveredDevice | null>(null);
  const [sadpResetDevice, setSadpResetDevice] = useState<DiscoveredDevice | null>(null);
  const [columnWidths, setColumnWidths] = useState<ColumnWidths>(loadColumnWidths);
  const columnWidthsRef = useRef(columnWidths);
  columnWidthsRef.current = columnWidths;
  const [autoScan, setAutoScan] = useState<boolean>(loadAutoScan);
  // Refs so the auto-scan timer reads the latest state without restarting.
  const scanningRef = useRef(scanning);
  scanningRef.current = scanning;
  const modalOpenRef = useRef(false);
  modalOpenRef.current = Boolean(editingDevice || rebootingDevice || sadpResetDevice);

  useEffect(() => {
    applyThemeMode('light');
    setResolvedThemeMode(getCurrentThemeMode());
    function onThemeChange(): void {
      setResolvedThemeMode(getCurrentThemeMode());
    }
    window.addEventListener(THEME_CHANGE_EVENT, onThemeChange);
    return () => window.removeEventListener(THEME_CHANGE_EVENT, onThemeChange);
  }, []);

  useEffect(() => {
    window.ipTool.system.isWindowMaximized().then(setWindowMaximized);
    return window.ipTool.system.onWindowMaximizedChanged(setWindowMaximized);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    handleScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(AUTO_SCAN_KEY, autoScan ? '1' : '0');
    } catch {
      // a per-PC convenience only
    }
  }, [autoScan]);

  // Auto-scan: re-run the scan every 10s while the toggle is on, skipping a
  // tick when a scan is already running or an Edit/Reboot/Reset dialog is
  // open (so a background refresh never disrupts what the tech is doing).
  useEffect(() => {
    if (!autoScan) return;
    const id = setInterval(() => {
      if (!scanningRef.current && !modalOpenRef.current) void handleScan();
    }, AUTO_SCAN_INTERVAL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoScan]);

  function toggleTheme(): void {
    applyThemeMode(resolvedThemeMode === 'dark' ? 'light' : 'dark');
  }

  // Columns cycle asc → desc → unsorted, except IP Address, which just
  // flips between asc and desc — its unsorted state is discovery-arrival
  // order, which reads as random IPs (removed per explicit request).
  function toggleSort(key: SortKey): void {
    setSort((current) => {
      if (current?.key !== key) return { key, dir: 'asc' };
      if (current.dir === 'asc') return { key, dir: 'desc' };
      return key === 'host' ? { key, dir: 'asc' } : null;
    });
  }

  // Dragging a header's right edge: the column follows the pointer until the
  // button is released, then the widths are saved.
  function startColumnResize(key: ColumnKey, startX: number): void {
    const startWidth = columnWidthsRef.current[key];
    const onMove = (e: MouseEvent): void =>
      setColumnWidths((widths) => ({ ...widths, [key]: Math.max(MIN_COLUMN_WIDTH, Math.round(startWidth + e.clientX - startX)) }));
    const onUp = (): void => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      saveColumnWidths(columnWidthsRef.current);
    };
    document.body.style.cursor = 'col-resize';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }

  function resetColumnWidth(key: ColumnKey): void {
    const widths = { ...columnWidthsRef.current, [key]: defaultColumnWidths()[key] };
    setColumnWidths(widths);
    saveColumnWidths(widths);
  }

  async function handleScan(): Promise<void> {
    setScanning(true);
    try {
      const results = await window.ipTool.discovery.scan();
      setDevices(results);
    } catch (error) {
      // Keep whatever was listed before rather than leaving the table stuck
      // on "Scanning…" — main already contains each step's own failures.
      console.error('Scan failed:', error);
    } finally {
      setHasScanned(true);
      setScanning(false);
    }
  }

  // Built from the full scan (not the filtered list) so an ONVIF row's
  // label doesn't flip depending on whether its sibling passes the filter.
  const vendorRowHosts = vendorRowHostsOf(devices);
  const visibleDevices = sortDevices(filterByDeviceType(devices, deviceTypeFilter), sort, vendorRowHosts);

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: theme.bg }}>
      <div
        // The window is frameless (see main/index.ts) — this bar stands in
        // for the native OS title bar entirely, so it needs to be
        // draggable itself (WebkitAppRegion: 'drag'); every interactive
        // child then opts back out with 'no-drag'. A true 3-column grid
        // (not flex+spacers) so the clock stays genuinely centered
        // regardless of how wide the app name or icon-button group are —
        // same pattern as SSM-VMS's own AppShell header.
        style={
          {
            display: 'grid',
            gridTemplateColumns: '1fr auto 1fr',
            alignItems: 'center',
            height: '46px',
            flexShrink: 0,
            borderBottom: `1px solid ${theme.border}`,
            background: theme.panel,
            WebkitAppRegion: 'drag',
          } as CSSProperties
        }
        onDoubleClick={() => window.ipTool.system.toggleMaximizeWindow()}
      >
        <span style={{ fontSize: '14px', fontWeight: 700, color: theme.text, paddingLeft: '1.25rem' }}>
          Simplified IP Tool
        </span>

        <span style={{ fontSize: '12px', color: theme.textMuted, whiteSpace: 'nowrap', padding: '0 1rem' }}>
          {now.toLocaleDateString([], { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' })}
          {'  '}
          {now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>

        <div
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', height: '100%', WebkitAppRegion: 'no-drag' } as CSSProperties}
        >
          <IconButton title={resolvedThemeMode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'} onClick={toggleTheme}>
            {resolvedThemeMode === 'dark' ? <SunIcon /> : <MoonIcon />}
          </IconButton>
          <IconButton title="About" onClick={() => setAboutOpen(true)}>
            &#9432;
          </IconButton>

          <div style={{ width: '1px', height: '20px', background: theme.border, margin: '0 0.2rem' }} />

          <TitleBarButton title="Minimize" onClick={() => window.ipTool.system.minimizeWindow()}>
            &#8722;
          </TitleBarButton>
          <TitleBarButton title={windowMaximized ? 'Restore' : 'Maximize'} onClick={() => window.ipTool.system.toggleMaximizeWindow()}>
            {windowMaximized ? '❐' : '□'}
          </TitleBarButton>
          <TitleBarButton title="Close" onClick={() => window.ipTool.system.closeWindow()} danger>
            &#10005;
          </TitleBarButton>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, padding: '1.25rem', display: 'flex', flexDirection: 'column' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr auto 1fr',
            alignItems: 'center',
            marginBottom: '0.6rem',
          }}
        >
          <span style={{ fontSize: '12.5px', fontWeight: 600, color: theme.text }}>
            Devices Found {hasScanned && `(${visibleDevices.length})`}
          </span>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.3rem', justifySelf: 'center' }}>
            <button onClick={handleScan} disabled={scanning} style={{ ...primaryButtonStyle, opacity: scanning ? 0.6 : 1 }}>
              {scanning ? 'Scanning…' : 'Scan Network'}
            </button>
            <label
              title="When on, the network is rescanned automatically every 10 seconds (paused while an Edit, Reboot or Reset dialog is open)."
              style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '11px', color: theme.textMuted, cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} />
              Auto-scan every 10s
            </label>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', justifySelf: 'end' }}>
            <span style={{ fontSize: '11.5px', color: theme.textMuted }}>Device Type</span>
            <select
              value={deviceTypeFilter}
              onChange={(e) => setDeviceTypeFilter(e.target.value as DeviceTypeFilter)}
              style={selectStyle}
            >
              {DEVICE_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div
          // Scrolls sideways only when the columns are dragged wider than the
          // window; header and rows scroll together.
          style={{
            border: `1px solid ${theme.border}`,
            borderRadius: '6px',
            background: theme.panel,
            overflowX: 'auto',
            overflowY: 'hidden',
            flex: 1,
            minHeight: 0,
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div
            style={{
              minWidth: COLUMNS.reduce((sum, c) => sum + columnWidths[c.key], 0) + COLUMN_GAP_PX * (COLUMNS.length - 1) + 2 * ROW_PADDING_X_PX,
              flex: 1,
              minHeight: 0,
              display: 'flex',
              flexDirection: 'column',
            }}
          >
          <div style={{ ...rowStyle(true), flexShrink: 0 }}>
            {COLUMNS.map((column, i) => (
              <ColumnHeader
                key={column.key}
                label={column.label}
                sortKey={column.sortKey}
                width={columnWidths[column.key]}
                last={i === COLUMNS.length - 1}
                sort={sort}
                onSort={toggleSort}
                onResizeStart={(x) => startColumnResize(column.key, x)}
                onResetWidth={() => resetColumnWidth(column.key)}
              />
            ))}
          </div>

          <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
            {!hasScanned && (
              <div style={{ padding: '1.1rem', textAlign: 'center', color: theme.textFaint, fontSize: '12px' }}>
                Scanning the local network…
              </div>
            )}
            {hasScanned && visibleDevices.length === 0 && (
              <div style={{ padding: '1.1rem', textAlign: 'center', color: theme.textFaint, fontSize: '12px' }}>
                No devices found{deviceTypeFilter !== 'all' ? ' for this device type' : ' on the local network'}.
              </div>
            )}
            {visibleDevices.map((found, i) => (
              <div key={`${found.host}-${found.discoveryMethod}-${i}`} style={{ ...rowStyle(false), padding: `0.5rem ${ROW_PADDING_X_PX}px` }}>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.brand, false) }}>{brandLabel(found, vendorRowHosts)}</span>
                <span title={displayName(found)} style={{ ...cellStyle, ...columnStyle(columnWidths.model, false), color: theme.text }}>
                  {displayName(found)}
                </span>
                <span
                  onDoubleClick={() => void window.ipTool.device.openWebPage(found.host)}
                  title="Double-click to open this device's web page"
                  style={{ ...cellStyle, ...columnStyle(columnWidths.host, false), display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', userSelect: 'none' }}
                >
                  {found.host}
                  {found.otherSubnet && (
                    <span
                      title="This device's IP is outside this PC's subnet. It was found on the local network, but Open won't load until its IP is changed into this PC's range (or this PC is given an address in the device's range)."
                      style={otherSubnetBadgeStyle}
                    >
                      Other subnet
                    </span>
                  )}
                </span>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.mask, false) }}>{found.subnetMask ?? '—'}</span>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.gateway, false) }}>{found.gateway ?? '—'}</span>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.port, false) }}>{httpPortOf(found) ?? '—'}</span>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.mac, false) }}>{found.mac ?? '—'}</span>
                <span title={found.discoveryMethod} style={{ ...cellStyle, ...columnStyle(columnWidths.via, false) }}>
                  {found.discoveryMethod}
                </span>
                <span style={{ ...cellStyle, ...columnStyle(columnWidths.actions, true), display: 'flex', gap: '0.75rem' }}>
                  <button
                    onClick={() => void window.ipTool.device.openWebPage(found.host)}
                    style={{ ...linkStyle, background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}
                  >
                    Open
                  </button>
                  <button onClick={() => setEditingDevice(editTargetFor(found, devices))} style={{ ...linkStyle, background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}>
                    Edit
                  </button>
                  {rebootTargetFor(found, devices) && (
                    <button
                      onClick={() => setRebootingDevice(rebootTargetFor(found, devices) ?? null)}
                      style={{ ...linkStyle, background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}
                    >
                      Reboot
                    </button>
                  )}
                  {found.passwordReset && (
                    <button
                      onClick={() => setSadpResetDevice(found)}
                      title={passwordResetHint(found.passwordReset)}
                      style={{ ...linkStyle, background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}
                    >
                      Reset…
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
          </div>
        </div>
      </div>

      {editingDevice && (
        <EditDeviceDialog
          device={editingDevice}
          onClose={() => setEditingDevice(null)}
          onRescan={() => {
            setEditingDevice(null);
            void handleScan();
          }}
        />
      )}
      {rebootingDevice && <RebootDialog device={rebootingDevice} onClose={() => setRebootingDevice(null)} />}
      {sadpResetDevice && <SadpResetDialog device={sadpResetDevice} onClose={() => setSadpResetDevice(null)} />}
      {aboutOpen && <AboutModal themeMode={resolvedThemeMode} onClose={() => setAboutOpen(false)} />}
    </div>
  );
}

function AboutModal({ themeMode, onClose }: { themeMode: 'light' | 'dark'; onClose: () => void }) {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    window.ipTool.system.getAppVersion().then(setVersion);
  }, []);

  return (
    <div
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: 340,
          background: theme.panel,
          border: `1px solid ${theme.border}`,
          borderRadius: '8px',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.5)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '1rem 1.3rem',
            borderBottom: `1px solid ${theme.border}`,
          }}
        >
          <span style={{ fontSize: '14px', fontWeight: 600, color: theme.text }}>About</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: theme.textMuted, fontSize: '16px', cursor: 'pointer' }}>
            &times;
          </button>
        </div>

        <div
          style={{
            padding: '1.5rem 1.3rem',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '0.6rem',
            textAlign: 'center',
          }}
        >
          <img
            src={themeMode === 'light' ? logoNavy : logoWhite}
            alt="Simplified Developers"
            style={{ height: 36, width: 'auto', marginBottom: '0.3rem' }}
          />
          <div style={{ fontSize: '15px', fontWeight: 700, color: theme.text }}>Simplified IP-Tool</div>
          <div style={{ fontSize: '12.5px', color: theme.textMuted }}>Version {version ?? '—'}</div>
          <div style={{ fontSize: '11.5px', color: theme.textFaint, marginTop: '0.5rem', lineHeight: 1.5 }}>
            Unified multi-vendor IP utility
            <br />© {new Date().getFullYear()} Simplified Developers
          </div>
        </div>
      </div>
    </div>
  );
}

// Change the device's own network settings and ports through whatever can
// reach it (see NetworkEditCapability in shared/types.ts for exactly what
// each route can change). This is a write against live hardware — wrong
// settings can leave a device unreachable until it's reset on site — so
// Save always goes through a confirm step first, main re-validates
// everything before any SDK call, and the password is never stored. Only
// what the user actually changed is sent.
type EditStage = 'form' | 'confirm' | 'sending' | 'onvifOffer' | 'done';

const PORT_FIELDS: { kind: PortKind; label: string }[] = [
  { kind: 'http', label: 'HTTP Port' },
  { kind: 'https', label: 'HTTPS Port' },
  { kind: 'rtsp', label: 'RTSP Port' },
  { kind: 'device', label: 'Device Port' },
];

type PortStrings = Record<PortKind, string>;

function portStrings(ports: PortSettings | undefined): PortStrings {
  const value = (kind: PortKind): string => (ports?.[kind] ? String(ports[kind]) : '');
  return { http: value('http'), https: value('https'), rtsp: value('rtsp'), device: value('device') };
}

function EditDeviceDialog({
  device,
  onClose,
  onRescan,
}: {
  device: DiscoveredDevice;
  onClose: () => void;
  onRescan: () => void;
}) {
  const capability = device.networkEdit;
  const [ip, setIp] = useState(device.host);
  // An unknown mask starts blank, not as a guessed 255.255.255.0: a guess
  // counted as "unchanged" would be sent with any IP/gateway edit and could
  // silently re-mask the device (a /16 camera rewritten to /24).
  const [initialNet, setInitialNet] = useState({ subnetMask: device.subnetMask ?? '', gateway: device.gateway ?? '' });
  const [subnetMask, setSubnetMask] = useState(initialNet.subnetMask);
  const [gateway, setGateway] = useState(initialNet.gateway);
  // TVT's IP command always sets DNS too, and its search reply doesn't say
  // what the device currently uses — so these are shown, editable
  // defaults rather than a silent overwrite. Sent only with an IP change.
  const [dns1, setDns1] = useState('8.8.8.8');
  const [dns2, setDns2] = useState('8.8.4.4');
  const [dnsTouched, setDnsTouched] = useState(false);
  // DHCP starts as the device's current mode where its search (or ONVIF)
  // reports it; unknown shows as off, and a static edit sets a static
  // address either way.
  const [initialDhcp, setInitialDhcp] = useState(device.dhcp === true);
  const [dhcp, setDhcp] = useState(initialDhcp);
  // Port fields start at the device's current values where they're known;
  // a blank field means "keep whatever it is now".
  const [initialPorts, setInitialPorts] = useState<PortStrings>(portStrings(device.currentPorts));
  const [ports, setPorts] = useState<PortStrings>(portStrings(device.currentPorts));
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [stage, setStage] = useState<EditStage>('form');
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  // The brand method's error, shown on the "try over ONVIF?" screen.
  const [brandError, setBrandError] = useState<string | null>(null);
  // "Load current settings" for Uniview (mask/gateway need a login).
  const [prefilling, setPrefilling] = useState(false);
  const [prefillNote, setPrefillNote] = useState<string | null>(null);
  const touched = useRef({ subnetMask: false, gateway: false, dhcp: false, ports: new Set<PortKind>() });

  // ONVIF cameras often report their current mask/gateway/ports/DHCP mode
  // without a login; fill them in unless the user has already started
  // typing there. Uniview and Sunell rows too — Uniview's search reports
  // none of it, and Sunell's web/RTSP ports are changed over ONVIF — main
  // reads them over ONVIF when the camera answers that.
  useEffect(() => {
    const readOverOnvif = device.discoveryMethod === 'ONVIF' || device.discoveryMethod === 'Uniview' || device.guessedVendor === 'sunell';
    if (!capability || !readOverOnvif) return;
    let cancelled = false;
    window.ipTool.device.readNetwork(device.host, device.discoveryMethod).then((current) => {
      if (cancelled) return;
      if (current.subnetMask && !touched.current.subnetMask) {
        setSubnetMask(current.subnetMask);
        setInitialNet((prev) => ({ ...prev, subnetMask: current.subnetMask as string }));
      }
      if (current.gateway && !touched.current.gateway) {
        setGateway(current.gateway);
        setInitialNet((prev) => ({ ...prev, gateway: current.gateway as string }));
      }
      if (current.dhcp !== undefined && !touched.current.dhcp) {
        setDhcp(current.dhcp);
        setInitialDhcp(current.dhcp);
      }
      if (current.ports) {
        const read = portStrings(current.ports);
        const untouched = (Object.keys(read) as PortKind[]).filter((k) => read[k] && !touched.current.ports.has(k));
        setPorts((prev) => ({ ...prev, ...Object.fromEntries(untouched.map((k) => [k, read[k]])) }));
        setInitialPorts((prev) => ({ ...prev, ...Object.fromEntries(untouched.map((k) => [k, read[k]])) }));
      }
    });
    return () => {
      cancelled = true;
    };
  }, [capability, device.host, device.discoveryMethod, device.guessedVendor]);

  // With DHCP on, the address fields don't apply; switching DHCP on or off
  // is a change by itself (off with the fields as they are = that static
  // address).
  const dhcpOn = Boolean(capability?.dhcp && dhcp);
  const dhcpSwitched = Boolean(capability?.dhcp) && dhcp !== initialDhcp;
  const addressChanged =
    !dhcpOn && (ip.trim() !== device.host || subnetMask.trim() !== initialNet.subnetMask || gateway.trim() !== initialNet.gateway);
  const networkChanged = dhcpSwitched || addressChanged || Boolean(capability?.dns && dnsTouched);
  const changedPorts = (capability?.ports ?? []).filter((k) => ports[k].trim() !== '' && ports[k].trim() !== initialPorts[k]);
  const hasChanges = networkChanged || changedPorts.length > 0;
  // ONVIF can't change the device port, so it only helps when an IP change
  // or a web port was part of the edit.
  const onvifCanHelp = networkChanged || changedPorts.some((k) => k !== 'device');
  const mayReboot = Boolean((capability?.mayReboot && networkChanged) || (capability?.portsMayReboot && changedPorts.length > 0));

  // Reads the camera's current mask/gateway (and DHCP) over its logged-in
  // API and fills the fields the user hasn't already edited — Uniview only,
  // where that data needs a password.
  async function loadCurrentSettings(): Promise<void> {
    if (!capability) return;
    setPrefilling(true);
    setPrefillNote(null);
    const r = await window.ipTool.device.readNetworkAuth(device.host, device.discoveryMethod, capability.username ? username.trim() : '', password);
    setPrefilling(false);
    if (r.error) {
      setPrefillNote(r.error);
      return;
    }
    if (r.subnetMask && !touched.current.subnetMask) {
      setSubnetMask(r.subnetMask);
      setInitialNet((prev) => ({ ...prev, subnetMask: r.subnetMask as string }));
    }
    if (r.gateway && !touched.current.gateway) {
      setGateway(r.gateway);
      setInitialNet((prev) => ({ ...prev, gateway: r.gateway as string }));
    }
    if (r.dhcp !== undefined && !touched.current.dhcp) {
      setDhcp(r.dhcp);
      setInitialDhcp(r.dhcp);
    }
    setPrefillNote(r.subnetMask || r.gateway ? 'Loaded the current settings.' : "The camera didn't return its mask/gateway.");
  }

  // `via` is undefined for the device's own (brand) method, or 'ONVIF' for
  // the retry offered when the brand method fails. ONVIF can't do the device
  // port, so it's dropped from the retry. The password is kept on a failure
  // so the ONVIF retry still has it; it's cleared on success.
  async function apply(via?: 'ONVIF'): Promise<void> {
    if (!capability) return;
    setStage('sending');
    setError(null);
    const onvif = via === 'ONVIF';
    const portsToSend = onvif ? changedPorts.filter((k) => k !== 'device') : changedPorts;
    const result = await window.ipTool.device.modifyNetwork({
      host: device.host,
      discoveryMethod: onvif ? 'ONVIF' : device.discoveryMethod,
      mac: device.mac,
      network: networkChanged
        ? {
            dhcp: dhcpOn || undefined,
            ip: ip.trim(),
            subnetMask: subnetMask.trim(),
            gateway: gateway.trim(),
            dns1: capability.dns ? dns1.trim() : undefined,
            dns2: capability.dns ? dns2.trim() : undefined,
          }
        : undefined,
      ports: portsToSend.length > 0 ? Object.fromEntries(portsToSend.map((k) => [k, Number(ports[k].trim())])) : undefined,
      username: capability.username ? username.trim() : '',
      password,
    });
    if (result.ok) {
      setPassword('');
      setWarning(result.warning ?? null);
      setMessage(result.message ?? null);
      setStage('done');
    } else if (!onvif && capability.onvifFallback && onvifCanHelp) {
      // Keep the password for the retry; offer ONVIF.
      setBrandError(result.error);
      setStage('onvifOffer');
    } else {
      setError(result.error);
      setStage('form');
    }
  }

  // Enter does what the dialog's main button does at each step — Save, then
  // Apply Changes, then Done — unless a button has focus (it clicks itself).
  // A held-down key doesn't repeat, so saving and applying always take two
  // separate presses.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== 'Enter' || e.repeat || (e.target instanceof HTMLElement && e.target.tagName === 'BUTTON')) return;
      if (!capability) return;
      if (stage === 'form' && password && hasChanges) setStage('confirm');
      else if (stage === 'confirm') void apply();
      else if (stage === 'onvifOffer') void apply('ONVIF');
      else if (stage === 'done') onRescan();
      else return;
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const summary: string[] = [];
  if (networkChanged) {
    summary.push(dhcpOn ? "DHCP — the address comes from the network's DHCP server" : `IP ${ip.trim()} · mask ${subnetMask.trim()} · gateway ${gateway.trim()}`);
    if (capability?.dns) summary.push(`DNS ${[dns1.trim(), dns2.trim()].filter(Boolean).join(', ')}`);
  }
  for (const kind of changedPorts) {
    const label = PORT_FIELDS.find((f) => f.kind === kind)?.label ?? kind;
    summary.push(`${label} ${initialPorts[kind] ? `${initialPorts[kind]} → ` : ''}${ports[kind].trim()}`);
  }

  return (
    <div
      onMouseDown={(e) => {
        // A click outside the dialog only closes it when there's nothing to
        // lose: the view that can't edit this device, or a finished change —
        // where the list is stale (old IP/ports), so closing refreshes it.
        // The form and the confirm step keep what was entered (password
        // included); only Cancel/Back leave them.
        if (e.target !== e.currentTarget) return;
        if (stage === 'done') onRescan();
        else if (!capability) onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: 400,
          maxHeight: '92vh',
          overflowY: 'auto',
          background: theme.panel,
          border: `1px solid ${theme.border}`,
          borderRadius: '8px',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.5)',
        }}
      >
        <div style={{ padding: '1.1rem 1.25rem 0.9rem', borderBottom: `1px solid ${theme.border}` }}>
          <div style={{ fontSize: '14px', fontWeight: 600, color: theme.text }}>Edit Device Network Settings</div>
          <div style={{ fontSize: '11.5px', color: theme.textFaint, marginTop: '0.2rem' }}>
            {displayName(device)} · {device.host} · via {device.discoveryMethod}
          </div>
        </div>

        {!capability && (
          <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.5 }}>
            {device.editUnavailableReason ??
              (device.otherSubnet
                ? "This device is outside this PC's subnet, and its brand's search can't change it here — ONVIF only reaches devices the PC can connect to. Put the PC on the device's subnet (or change the device from its own tools) first."
                : "Changing network settings isn't supported for this device yet.")}
          </div>
        )}

        {capability && stage === 'form' && (
          <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
            {capability.dhcp && (
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '12px', color: theme.text, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={dhcp}
                  onChange={(e) => {
                    touched.current.dhcp = true;
                    const on = e.target.checked;
                    setDhcp(on);
                    // The address fields go back to the device's current
                    // values: with DHCP on they're only shown, not sent.
                    if (on) {
                      setIp(device.host);
                      setSubnetMask(initialNet.subnetMask);
                      setGateway(initialNet.gateway);
                    }
                  }}
                />
                Obtain an IP address automatically (DHCP)
              </label>
            )}
            <Field label="IP Address">
              <input value={ip} onChange={(e) => setIp(e.target.value)} disabled={dhcpOn} style={dhcpOn ? disabledInputStyle : inputStyle} />
            </Field>
            <div style={{ display: 'flex', gap: '0.6rem' }}>
              <Field label="Subnet Mask">
                <input
                  value={subnetMask}
                  onChange={(e) => {
                    touched.current.subnetMask = true;
                    setSubnetMask(e.target.value);
                  }}
                  placeholder="e.g. 255.255.255.0"
                  disabled={dhcpOn}
                  style={dhcpOn ? disabledInputStyle : inputStyle}
                />
              </Field>
              <Field label="Gateway">
                <input
                  value={gateway}
                  onChange={(e) => {
                    touched.current.gateway = true;
                    setGateway(e.target.value);
                  }}
                  placeholder="e.g. 192.168.1.1 (0.0.0.0 = none)"
                  disabled={dhcpOn}
                  style={dhcpOn ? disabledInputStyle : inputStyle}
                />
              </Field>
            </div>
            {capability.dns && (
              <div style={{ display: 'flex', gap: '0.6rem' }}>
                <Field label="Preferred DNS">
                  <input
                    value={dns1}
                    onChange={(e) => {
                      setDnsTouched(true);
                      setDns1(e.target.value);
                    }}
                    style={inputStyle}
                  />
                </Field>
                <Field label="Alternate DNS">
                  <input
                    value={dns2}
                    onChange={(e) => {
                      setDnsTouched(true);
                      setDns2(e.target.value);
                    }}
                    style={inputStyle}
                  />
                </Field>
              </div>
            )}

            {capability.ports.length > 0 ? (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
                  {PORT_FIELDS.filter((f) => capability.ports.includes(f.kind)).map((f) => (
                    <Field key={f.kind} label={f.label}>
                      <input
                        value={ports[f.kind]}
                        onChange={(e) => {
                          touched.current.ports.add(f.kind);
                          const value = e.target.value;
                          setPorts((prev) => ({ ...prev, [f.kind]: value }));
                        }}
                        placeholder="Keep current"
                        style={inputStyle}
                      />
                    </Field>
                  ))}
                </div>
                <div style={{ fontSize: '11px', color: theme.textFaint, lineHeight: 1.45 }}>
                  Leave a port blank to keep its current value.
                  {capability.ports.includes('device') && ' Device Port is the SDK/data port NVRs and VMS software connect to.'}
                </div>
              </>
            ) : (
              <div style={{ fontSize: '11px', color: theme.textFaint }}>
                {capability.portsUnavailableReason ?? "Ports can't be changed on this device from here yet — IP settings only."}
              </div>
            )}

            {capability.username && (
              <Field label="Username">
                <input value={username} onChange={(e) => setUsername(e.target.value)} style={inputStyle} />
              </Field>
            )}
            <Field label={capability.username ? 'Password' : 'Admin Password'}>
              <PasswordInput value={password} onChange={setPassword} />
            </Field>
            {(device.discoveryMethod === 'Uniview' || device.discoveryMethod === 'Axis') && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <button
                  type="button"
                  onClick={loadCurrentSettings}
                  disabled={!password || prefilling}
                  style={{ ...secondaryButtonStyle, opacity: !password || prefilling ? 0.5 : 1 }}
                >
                  {prefilling ? 'Loading…' : 'Load current settings'}
                </button>
                <span style={{ fontSize: '11px', color: prefillNote ? theme.warning : theme.textFaint }}>
                  {prefillNote ?? 'Fills the mask and gateway from the camera (needs the password).'}
                </span>
              </div>
            )}
            {error && <div style={{ fontSize: '11.5px', color: theme.danger }}>{error}</div>}
          </div>
        )}

        {capability && (stage === 'confirm' || stage === 'sending') && (
          <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.55 }}>
            <div style={{ color: theme.text, marginBottom: '0.5rem' }}>Apply these changes to {device.host}?</div>
            {summary.map((line) => (
              <div key={line}>{line}</div>
            ))}
            <div style={{ color: theme.warning, marginTop: '0.7rem' }}>
              If any of these are wrong, the device may become unreachable until it's reset on site.
            </div>
            {dhcpOn && dhcpSwitched && (
              <div style={{ marginTop: '0.5rem' }}>
                The device's IP address will change to whatever the network's DHCP server gives it — only use DHCP if this network has one.
              </div>
            )}
            {mayReboot && (
              <div style={{ marginTop: '0.5rem' }}>If the device says it needs a reboot to apply this, the app will reboot it.</div>
            )}
            {stage === 'sending' && (
              <div style={{ color: theme.textFaint, marginTop: '0.7rem' }}>
                Sending and waiting for the device to confirm. This can take up to{' '}
                {mayReboot ? 'a few minutes if the device reboots' : dhcpOn && networkChanged ? 'about a minute' : 'about 30 seconds'}.
              </div>
            )}
          </div>
        )}

        {capability && stage === 'onvifOffer' && (
          <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.55 }}>
            <div style={{ color: theme.danger, marginBottom: '0.6rem' }}>
              The {device.discoveryMethod} change didn't take: {brandError}
            </div>
            <div style={{ color: theme.text }}>This device also answers ONVIF. Try the same change over ONVIF instead?</div>
            {changedPorts.includes('device') && (
              <div style={{ marginTop: '0.5rem' }}>The Device port can't be changed over ONVIF and will be skipped.</div>
            )}
            <div style={{ marginTop: '0.5rem', color: theme.textFaint }}>ONVIF reaches the device on this subnet only, using the login you entered.</div>
          </div>
        )}

        {capability && stage === 'done' && (
          <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.55 }}>
            {warning ? (
              <div style={{ color: theme.warning }}>{warning}</div>
            ) : (
              <>
                <div style={{ color: theme.success, marginBottom: '0.4rem' }}>The device accepted the change.</div>
                {message ??
                  (dhcpOn && networkChanged
                    ? `It gets its address from the DHCP server now, which can take a minute. The list refreshes when you close this — look for ${device.mac ? `MAC ${device.mac}` : 'it'} if its address changed.`
                    : networkChanged
                      ? `It may take up to a minute to come back at ${ip.trim()}. The list refreshes when you close this.`
                      : 'The list refreshes with the new ports when you close this.')}
              </>
            )}
          </div>
        )}

        <div style={{ padding: '0 1.25rem 1.25rem', display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
          {(!capability || stage === 'form') && (
            <button onClick={onClose} style={secondaryButtonStyle}>
              {capability ? 'Cancel' : 'Close'}
            </button>
          )}
          {capability && stage === 'form' && (
            <button
              onClick={() => setStage('confirm')}
              disabled={!password || !hasChanges}
              title={!hasChanges ? 'Nothing has been changed yet' : undefined}
              style={{ ...primaryButtonStyle, opacity: password && hasChanges ? 1 : 0.5 }}
            >
              Save
            </button>
          )}
          {capability && (stage === 'confirm' || stage === 'sending') && (
            <>
              <button onClick={() => setStage('form')} disabled={stage === 'sending'} style={secondaryButtonStyle}>
                Back
              </button>
              <button onClick={() => void apply()} disabled={stage === 'sending'} style={{ ...primaryButtonStyle, opacity: stage === 'sending' ? 0.6 : 1 }}>
                {stage === 'sending' ? 'Applying…' : 'Apply Changes'}
              </button>
            </>
          )}
          {capability && stage === 'onvifOffer' && (
            <>
              <button onClick={() => setStage('form')} style={secondaryButtonStyle}>
                Back
              </button>
              <button onClick={() => void apply('ONVIF')} style={primaryButtonStyle}>
                Try over ONVIF
              </button>
            </>
          )}
          {capability && stage === 'done' && (
            <button onClick={onRescan} style={primaryButtonStyle}>
              Done
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// A password box with a Show/Hide toggle.
function PasswordInput({ value, onChange, disabled }: { value: string; onChange: (value: string) => void; disabled?: boolean }) {
  const [shown, setShown] = useState(false);
  return (
    <div style={{ position: 'relative' }}>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        type={shown ? 'text' : 'password'}
        placeholder="Device password"
        disabled={disabled}
        style={{ ...inputStyle, paddingRight: '3.4rem' }}
      />
      <button
        type="button"
        onClick={() => setShown((s) => !s)}
        aria-label={shown ? 'Hide password' : 'Show password'}
        style={{
          position: 'absolute',
          right: '0.3rem',
          top: '50%',
          transform: 'translateY(-50%)',
          background: 'none',
          border: 'none',
          padding: '0.2rem 0.4rem',
          color: theme.textMuted,
          fontSize: '11.5px',
          cursor: 'pointer',
        }}
      >
        {shown ? 'Hide' : 'Show'}
      </button>
    </div>
  );
}

// Reboot from the Actions column. The dialog is the confirmation: it says
// what a reboot interrupts, and only the Reboot button sends it. Like Edit,
// a click outside only closes it once it's done; the password is never
// kept.
function RebootDialog({ device, onClose }: { device: DiscoveredDevice; onClose: () => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [stage, setStage] = useState<'form' | 'sending' | 'done'>('form');
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);

  async function reboot(): Promise<void> {
    setStage('sending');
    setError(null);
    const result = await window.ipTool.device.reboot({
      host: device.host,
      discoveryMethod: device.discoveryMethod,
      mac: device.mac,
      username: username.trim(),
      password,
    });
    setPassword('');
    if (result.ok) {
      setWarning(result.warning ?? null);
      setStage('done');
    } else {
      setError(result.error);
      setStage('form');
    }
  }

  // Enter = the main button (Reboot, then Close), as in Edit.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== 'Enter' || e.repeat || (e.target instanceof HTMLElement && e.target.tagName === 'BUTTON')) return;
      if (stage === 'form' && password) void reboot();
      else if (stage === 'done') onClose();
      else return;
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  return (
    <div
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && stage === 'done') onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: 380,
          background: theme.panel,
          border: `1px solid ${theme.border}`,
          borderRadius: '8px',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.5)',
        }}
      >
        <div style={{ padding: '1.1rem 1.25rem 0.9rem', borderBottom: `1px solid ${theme.border}` }}>
          <div style={{ fontSize: '14px', fontWeight: 600, color: theme.text }}>Reboot Device</div>
          <div style={{ fontSize: '11.5px', color: theme.textFaint, marginTop: '0.2rem' }}>
            {displayName(device)} · {device.host} · via {device.discoveryMethod}
          </div>
        </div>

        {stage !== 'done' ? (
          <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
            <div style={{ fontSize: '12px', color: theme.warning, lineHeight: 1.5 }}>
              The device will restart and be offline for a minute or two — live view and recording stop until it's back.
            </div>
            <Field label="Username">
              <input value={username} onChange={(e) => setUsername(e.target.value)} disabled={stage === 'sending'} style={inputStyle} />
            </Field>
            <Field label="Password">
              <PasswordInput value={password} onChange={setPassword} disabled={stage === 'sending'} />
            </Field>
            {error && <div style={{ fontSize: '11.5px', color: theme.danger }}>{error}</div>}
          </div>
        ) : (
          <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.55 }}>
            {warning ? (
              <div style={{ color: theme.warning }}>{warning}</div>
            ) : (
              <>
                <div style={{ color: theme.success, marginBottom: '0.4rem' }}>The device is rebooting.</div>
                It should be back in a minute or two — scan again to see it.
              </>
            )}
          </div>
        )}

        <div style={{ padding: '0 1.25rem 1.25rem', display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
          {stage === 'done' ? (
            <button onClick={onClose} style={primaryButtonStyle}>
              Close
            </button>
          ) : (
            <>
              <button onClick={onClose} disabled={stage === 'sending'} style={secondaryButtonStyle}>
                Cancel
              </button>
              <button
                onClick={reboot}
                disabled={!password || stage === 'sending'}
                style={{ ...primaryButtonStyle, opacity: password && stage !== 'sending' ? 1 : 0.5 }}
              >
                {stage === 'sending' ? 'Rebooting…' : 'Reboot'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', flex: 1, minWidth: 0 }}>
      <span style={{ fontSize: '11.5px', color: theme.textMuted }}>{label}</span>
      {children}
    </label>
  );
}

// Rounded header icon (theme toggle, About) — distinct from TitleBarButton
// below (square, flush against the header, for window controls only).
function IconButton({ title, onClick, children }: { title: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      title={title}
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '28px',
        height: '28px',
        borderRadius: '5px',
        border: 'none',
        background: 'none',
        color: theme.textMuted,
        fontSize: '14px',
        cursor: 'pointer',
        flexShrink: 0,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = theme.text;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = theme.textMuted;
      }}
    >
      {children}
    </button>
  );
}

function TitleBarButton({
  title,
  onClick,
  danger,
  children,
}: {
  title: string;
  onClick: () => void;
  danger?: boolean;
  children: React.ReactNode;
}) {
  const restColor = theme.textMuted;
  const hoverColor = danger ? '#fff' : theme.text;
  const hoverBackground = danger ? theme.danger : theme.surfaceHover;
  return (
    <button
      title={title}
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '44px',
        height: '100%',
        border: 'none',
        background: 'none',
        color: restColor,
        fontSize: '14px',
        cursor: 'pointer',
        flexShrink: 0,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = hoverColor;
        e.currentTarget.style.background = hoverBackground;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = restColor;
        e.currentTarget.style.background = 'none';
      }}
    >
      {children}
    </button>
  );
}

// A column header: sorts on click where the column is sortable, and has a
// drag handle on its right edge (in the gap to the next column) that
// resizes it — double-click the handle to reset. The last column fills the
// remaining room, so it has no handle.
function ColumnHeader({
  label,
  sortKey,
  width,
  last,
  sort,
  onSort,
  onResizeStart,
  onResetWidth,
}: {
  label: string;
  sortKey?: SortKey;
  width: number;
  last: boolean;
  sort: { key: SortKey; dir: SortDir } | null;
  onSort: (key: SortKey) => void;
  onResizeStart: (clientX: number) => void;
  onResetWidth: () => void;
}) {
  const active = sortKey !== undefined && sort?.key === sortKey;
  return (
    <div style={{ ...columnStyle(width, last), position: 'relative', overflow: 'visible' }}>
      <span
        onClick={sortKey ? () => onSort(sortKey) : undefined}
        title={label}
        style={{
          ...cellStyle,
          fontWeight: 600,
          cursor: sortKey ? 'pointer' : 'default',
          userSelect: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: '0.3rem',
          overflow: 'hidden',
          whiteSpace: 'nowrap',
        }}
      >
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
        {sortKey && <span style={{ fontSize: '10px', opacity: active ? 1 : 0.3 }}>{active ? (sort!.dir === 'asc' ? '▲' : '▼') : '▲'}</span>}
      </span>
      {!last && (
        <div
          onMouseDown={(e) => {
            e.preventDefault();
            onResizeStart(e.clientX);
          }}
          onDoubleClick={onResetWidth}
          title="Drag to resize · double-click to reset"
          style={{
            position: 'absolute',
            top: '-0.3rem',
            bottom: '-0.3rem',
            right: `-${COLUMN_GAP_PX / 2 + 4}px`,
            width: '8px',
            cursor: 'col-resize',
            display: 'flex',
            justifyContent: 'center',
            zIndex: 1,
          }}
        >
          <div style={{ width: '1px', background: theme.border }} />
        </div>
      )}
    </div>
  );
}

function rowStyle(header: boolean) {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: `${COLUMN_GAP_PX}px`,
    padding: `0.6rem ${ROW_PADDING_X_PX}px`,
    background: header ? theme.surface : 'transparent',
    borderBottom: `1px solid ${theme.border}`,
  } as const;
}

const cellStyle = {
  fontSize: '12.5px',
  color: theme.textMuted,
};

// The methods a reset-capable Hikvision device reports, for the marker's
// tooltip. The import-file method is the one the app will drive (export the
// request XML, send to Hikvision, import the signed file).
function passwordResetHint(reset: { importFile: boolean; securityQuestion: boolean }): string {
  const methods = [
    reset.importFile ? 'export/import secret key file (via Hikvision)' : undefined,
    reset.securityQuestion ? 'security question' : undefined,
  ].filter(Boolean);
  const list = methods.length ? ` Supported: ${methods.join(', ')}.` : '';
  return `Reset a forgotten admin password — opens Hikvision's SADP tool.${list}`;
}

// Password reset = launch Hikvision's own SADP tool to do the export/import
// there. The app only opens the vendor tool; it never handles the reset
// protocol or the password. Shown only for Hikvision devices that report
// they support a reset.
function SadpResetDialog({ device, onClose }: { device: DiscoveredDevice; onClose: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const canImportFile = device.passwordReset?.importFile ?? false;
  const canSecurityQuestion = device.passwordReset?.securityQuestion ?? false;

  async function openSadp(): Promise<void> {
    setOpening(true);
    setError(null);
    const result = await window.ipTool.device.openSadpTool();
    setOpening(false);
    if (result.ok) onClose();
    else setError(result.error);
  }

  return (
    <div
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
    >
      <div style={{ width: 430, background: theme.panel, border: `1px solid ${theme.border}`, borderRadius: '8px', boxShadow: '0 16px 48px rgba(0, 0, 0, 0.5)' }}>
        <div style={{ padding: '1.1rem 1.25rem 0.9rem', borderBottom: `1px solid ${theme.border}` }}>
          <div style={{ fontSize: '14px', fontWeight: 600, color: theme.text }}>Reset Admin Password</div>
          <div style={{ fontSize: '11.5px', color: theme.textFaint, marginTop: '0.2rem' }}>
            {displayName(device)} · {device.host}
            {device.mac ? ` · ${device.mac}` : ''}
          </div>
        </div>
        <div style={{ padding: '1.25rem', fontSize: '12px', color: theme.textMuted, lineHeight: 1.55 }}>
          <div style={{ marginBottom: '0.6rem', color: theme.text }}>
            A forgotten admin password is reset with Hikvision's own SADP tool. This opens it; then in SADP:
          </div>
          <ol style={{ margin: 0, paddingLeft: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            <li>
              Select this device ({device.host}{device.mac ? `, ${device.mac}` : ''}) and click <b>Forgot Password</b>.
            </li>
            {canImportFile && (
              <li>
                Choose <b>Export/Import Secret Key Mode</b>, click <b>Export</b> to save the key request file, and send it to Hikvision.
              </li>
            )}
            {canImportFile && (
              <li>
                When Hikvision returns the key file, select <b>Import File</b>, pick it, set the new password, and click <b>Confirm</b>.
              </li>
            )}
            {canSecurityQuestion && !canImportFile && (
              <li>
                Choose <b>Security Question Mode</b>, answer the questions set at activation, then set the new password.
              </li>
            )}
            {canSecurityQuestion && canImportFile && (
              <li>Or, if set up at activation, use <b>Security Question Mode</b> instead of the key file.</li>
            )}
          </ol>
          <div style={{ marginTop: '0.7rem', color: theme.textFaint }}>
            The app only opens SADP — it never handles the password itself. After the reset, rescan here.
          </div>
          {error && <div style={{ fontSize: '11.5px', color: theme.danger, marginTop: '0.7rem' }}>{error}</div>}
        </div>
        <div style={{ padding: '0 1.25rem 1.25rem', display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
          <button onClick={onClose} style={secondaryButtonStyle}>
            Close
          </button>
          <button onClick={openSadp} disabled={opening} style={{ ...primaryButtonStyle, opacity: opening ? 0.6 : 1 }}>
            {opening ? 'Opening…' : 'Open SADP Tool'}
          </button>
        </div>
      </div>
    </div>
  );
}

const otherSubnetBadgeStyle = {
  color: theme.warning,
  border: `1px solid ${theme.warning}`,
  borderRadius: '4px',
  padding: '0 0.3rem',
  fontSize: '10.5px',
  fontWeight: 600,
  whiteSpace: 'nowrap' as const,
  cursor: 'help',
};

const linkStyle = {
  color: theme.accentHover,
  fontSize: '13.5px',
  fontWeight: 600,
  textDecoration: 'none',
};

const primaryButtonStyle = {
  padding: '0.45rem 0.9rem',
  borderRadius: '5px',
  border: 'none',
  background: theme.accent,
  color: theme.accentText,
  fontSize: '12.5px',
  fontWeight: 600,
  cursor: 'pointer',
};

const secondaryButtonStyle = {
  padding: '0.45rem 0.7rem',
  borderRadius: '5px',
  border: `1px solid ${theme.borderLight}`,
  background: 'transparent',
  color: theme.text,
  fontSize: '12.5px',
  cursor: 'pointer',
};

const selectStyle: CSSProperties = {
  padding: '0.35rem 0.5rem',
  borderRadius: '5px',
  border: `1px solid ${theme.border}`,
  background: theme.surface,
  color: theme.text,
  fontSize: '12px',
};

const inputStyle: CSSProperties = {
  padding: '0.5rem 0.6rem',
  borderRadius: '5px',
  border: `1px solid ${theme.border}`,
  background: theme.surface,
  color: theme.text,
  fontSize: '12.5px',
  outline: 'none',
  width: '100%',
  boxSizing: 'border-box',
};

const disabledInputStyle: CSSProperties = { ...inputStyle, opacity: 0.45, cursor: 'not-allowed' };
