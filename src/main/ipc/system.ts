import { app, BrowserWindow, ipcMain } from 'electron';

// Window-control handlers for the frameless window's own custom title bar
// (see main/index.ts's frame:false) — same shape as SSM-VMS's own
// ipc/system.ts.
export function registerSystemIpcHandlers(): void {
  ipcMain.handle('system:getAppVersion', (): string => app.getVersion());

  // The renderer's CSP blocks external requests, so the public-IP lookup and
  // the port-forwarding check run here in main (Node) instead.
  ipcMain.handle('system:getPublicIp', async (): Promise<string | null> => {
    for (const url of ['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json']) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
        const data = (await res.json()) as { ip?: string };
        if (data?.ip) return data.ip;
      } catch {
        // try the next service
      }
    }
    return null;
  });

  // Tests whether host:port is reachable from the internet via the external
  // port-checker service (an outside vantage point — the point of a
  // port-forwarding check). Any failure reads as closed.
  ipcMain.handle('system:checkPort', async (_event, host: string, port: number): Promise<'open' | 'closed'> => {
    try {
      const res = await fetch(`https://port-checker.alexgonz00.workers.dev/?host=${encodeURIComponent(host)}&port=${port}`, {
        signal: AbortSignal.timeout(12000),
      });
      const data = (await res.json()) as { status?: string };
      return data?.status === 'open' ? 'open' : 'closed';
    } catch {
      return 'closed';
    }
  });

  ipcMain.handle('system:minimizeWindow', (event): void => {
    BrowserWindow.fromWebContents(event.sender)?.minimize();
  });

  ipcMain.handle('system:toggleMaximizeWindow', (event): void => {
    const win = BrowserWindow.fromWebContents(event.sender);
    if (!win) return;
    if (win.isMaximized()) win.unmaximize();
    else win.maximize();
  });

  ipcMain.handle('system:closeWindow', (event): void => {
    BrowserWindow.fromWebContents(event.sender)?.close();
  });

  ipcMain.handle(
    'system:isWindowMaximized',
    (event): boolean => BrowserWindow.fromWebContents(event.sender)?.isMaximized() ?? false,
  );
}
