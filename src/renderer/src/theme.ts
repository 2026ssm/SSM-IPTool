import type { ThemeMode } from '../../shared/types';

// Same CSS-custom-property approach as SSM-VMS (see global.css for the
// real dark/light hex values) — every component reads theme.xxx, the
// browser repaints instantly when the data-theme attribute changes, no
// React re-render involved.
export const theme = {
  bg: 'var(--bg)',
  panel: 'var(--panel)',
  surface: 'var(--surface)',
  surfaceHover: 'var(--surface-hover)',
  border: 'var(--border)',
  borderLight: 'var(--border-light)',
  text: 'var(--text)',
  textMuted: 'var(--text-muted)',
  textFaint: 'var(--text-faint)',
  accent: 'var(--accent)',
  accentHover: 'var(--accent-hover)',
  accentPressed: 'var(--accent-pressed)',
  accentText: 'var(--accent-text)',
  accentFaint: 'var(--accent-faint)',
  accentGlow: 'var(--accent-glow)',
  danger: 'var(--danger)',
  warning: 'var(--warning)',
  success: 'var(--success)',
} as const;

export const THEME_CHANGE_EVENT = 'iptool-theme-changed';

let systemPrefersDark = true;
let currentMode: ThemeMode = 'light';

export function setSystemPrefersDark(prefersDark: boolean): void {
  systemPrefersDark = prefersDark;
}

export function applyThemeMode(mode: ThemeMode): void {
  currentMode = mode;
  const resolved = mode === 'auto' ? (systemPrefersDark ? 'dark' : 'light') : mode;
  document.documentElement.setAttribute('data-theme', resolved);
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}

export function reapplyIfAuto(): void {
  if (currentMode === 'auto') applyThemeMode('auto');
}

export function getCurrentThemeMode(): 'light' | 'dark' {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}
