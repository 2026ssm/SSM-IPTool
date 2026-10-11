import { app, BrowserWindow, session } from 'electron';
import type { AuthInfo, WebContents } from 'electron';

// An in-app browser window for a device's own web UI — the "Open" action.
//
// This deliberately does NOT attach the app's preload (the ipTool bridge),
// and runs sandboxed with Node disabled, so the device's web page — which is
// untrusted content from the camera — can't reach the app's device-control
// functions (modifyNetwork, etc.). That bridge leaking into a plain child
// window is exactly why the original in-app view was removed; this brings it
// back safely. Device sessions live in their own persistent partition, kept
// separate from the app, so logins stick between opens.
const DEVICE_PARTITION = 'persist:device-web';

const ISOLATED_WEB_PREFERENCES = {
  partition: DEVICE_PARTITION,
  sandbox: true,
  contextIsolation: true,
  nodeIntegration: false,
  // No `preload` on purpose — the page must not get window.ipTool.
} as const;

export function openDeviceBrowser(url: string, title: string): void {
  registerDeviceLoginHandler();

  const win = new BrowserWindow({
    width: 1200,
    height: 820,
    title,
    autoHideMenuBar: true,
    backgroundColor: '#ffffff',
    webPreferences: { ...ISOLATED_WEB_PREFERENCES },
  });
  win.setMenuBarVisibility(false);

  // Camera web UIs often open the live view (and other panes) in a popup —
  // allow those, but as further windows with the same bridge-free, sandboxed
  // settings so they're just as isolated.
  win.webContents.setWindowOpenHandler(() => ({
    action: 'allow',
    overrideBrowserWindowOptions: { autoHideMenuBar: true, webPreferences: { ...ISOLATED_WEB_PREFERENCES } },
  }));

  // A failed load showed a blank window before; show a readable message.
  win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
    if (!isMainFrame || errorCode === -3) return; // -3 = ABORTED (e.g. a redirect); ignore
    const body = `<!doctype html><meta charset="utf-8"><body style="font-family:-apple-system,Segoe UI,sans-serif;margin:0;padding:2.5rem;color:#1f2937;background:#f4f5f7">
      <h2 style="margin:0 0 .5rem">Couldn't open ${title}</h2>
      <p style="color:#6b7280">${errorDescription} (${errorCode})</p>
      <p style="color:#6b7280;word-break:break-all">${validatedURL}</p>
      <p style="color:#6b7280">Check the device is reachable and try again, or open it in your own browser.</p></body>`;
    void win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(body));
  });

  void win.loadURL(url);
}

// ---- HTTP authentication ----
//
// Some device web servers (Axis, and other ONVIF cameras) guard their whole
// site with HTTP auth — a 401 with a WWW-Authenticate challenge — rather than
// an HTML login form. Electron cancels those by default, so the page just
// shows the server's "Unauthorized" error. This asks the tech for the login
// and hands it back to Chromium, which answers the challenge (Basic or
// Digest). Scoped to the device partition's windows, so the main app window
// (which has no HTTP auth) is untouched. The credentials go only to the
// camera, are never logged, and aren't stored by the app.
let loginHandlerRegistered = false;
// Per-window, per-realm attempt counts, so a wrong password re-prompts a few
// times and then gives up (showing the server's 401 page) instead of looping.
const authAttempts = new WeakMap<WebContents, Map<string, number>>();
const MAX_ATTEMPTS = 3;

function registerDeviceLoginHandler(): void {
  if (loginHandlerRegistered) return;
  loginHandlerRegistered = true;
  const deviceSession = session.fromPartition(DEVICE_PARTITION);

  app.on('login', (event, webContents, _details, authInfo, callback) => {
    // Only device-browser windows (and their popups), and only the device's
    // own auth — never a proxy's.
    if (!webContents || webContents.session !== deviceSession || authInfo.isProxy) return;
    event.preventDefault();

    const key = `${authInfo.host}:${authInfo.port}:${authInfo.realm}`;
    const counts = authAttempts.get(webContents) ?? new Map<string, number>();
    authAttempts.set(webContents, counts);
    const prior = counts.get(key) ?? 0;
    if (prior >= MAX_ATTEMPTS) {
      counts.delete(key); // give up — let the server's 401 page show
      callback();
      return;
    }
    counts.set(key, prior + 1);

    void promptCredentials(BrowserWindow.fromWebContents(webContents), authInfo, prior > 0).then((creds) => {
      if (!creds) {
        counts.delete(key);
        callback(); // cancelled — show the 401 page
        return;
      }
      callback(creds.username, creds.password);
    });
  });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

// A small modal sign-in window. It carries no preload and no Node; the entered
// values are read back with executeJavaScript (reading the DOM), so the
// password never goes through a URL, the title, or an IPC channel.
function promptCredentials(parent: BrowserWindow | null, authInfo: AuthInfo, retry: boolean): Promise<{ username: string; password: string } | null> {
  return new Promise((resolve) => {
    const win = new BrowserWindow({
      parent: parent ?? undefined,
      modal: Boolean(parent),
      width: 380,
      height: retry ? 278 : 250,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      title: 'Sign in',
      autoHideMenuBar: true,
      backgroundColor: '#ffffff',
      webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false },
    });
    win.setMenuBarVisibility(false);

    let settled = false;
    const finish = async (action: 'submit' | 'cancel'): Promise<void> => {
      if (settled) return;
      settled = true;
      let creds: { username: string; password: string } | null = null;
      if (action === 'submit') {
        const values = (await win.webContents
          .executeJavaScript("[document.getElementById('u').value, document.getElementById('p').value]")
          .catch(() => ['', ''])) as [string, string];
        creds = { username: String(values[0] ?? ''), password: String(values[1] ?? '') };
      }
      resolve(creds);
      if (!win.isDestroyed()) win.close();
    };

    // The form signals its result by setting the document title to a sentinel.
    win.webContents.on('page-title-updated', (_e, title) => {
      if (title === '__submit__') void finish('submit');
      else if (title === '__cancel__') void finish('cancel');
    });
    win.on('closed', () => {
      if (!settled) {
        settled = true;
        resolve(null);
      }
    });

    const where = escapeHtml(`${authInfo.host}${authInfo.port ? `:${authInfo.port}` : ''}`);
    const realm = authInfo.realm ? ` — ${escapeHtml(authInfo.realm)}` : '';
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>
<style>
  :root { color-scheme: light; }
  body { font-family:-apple-system,'Segoe UI',Roboto,sans-serif; margin:0; padding:1.1rem 1.25rem; color:#15202c; background:#eaf2fb; }
  h3 { margin:0 0 .15rem; font-size:14px; }
  .where { margin:0 0 .9rem; font-size:11.5px; color:#4f5e6e; word-break:break-all; }
  .err { margin:0 0 .7rem; font-size:11.5px; color:#b45309; }
  label { display:block; font-size:11px; color:#4f5e6e; margin-bottom:.7rem; }
  input { width:100%; box-sizing:border-box; margin-top:.2rem; padding:.42rem .5rem; font-size:13px; border:1px solid #c7d7e8; border-radius:5px; background:#fff; color:#15202c; }
  .row { display:flex; gap:.5rem; justify-content:flex-end; margin-top:.2rem; }
  button { font-size:12px; padding:.42rem .9rem; border-radius:5px; border:1px solid #c7d7e8; background:#fff; color:#15202c; cursor:pointer; }
  button.primary { background:#00007f; border-color:#00007f; color:#fff; }
</style></head>
<body>
  <form onsubmit="return go()">
    <h3>Sign in to this device</h3>
    <p class="where">${where}${realm}</p>
    ${retry ? '<p class="err">Wrong username or password — try again.</p>' : ''}
    <label>Username<input id="u" autocomplete="off" autofocus></label>
    <label>Password<input id="p" type="password" autocomplete="off"></label>
    <div class="row">
      <button type="button" onclick="document.title='__cancel__'">Cancel</button>
      <button type="submit" class="primary">Sign in</button>
    </div>
  </form>
  <script>function go(){ document.title='__submit__'; return false; }</script>
</body></html>`;
    void win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  });
}
