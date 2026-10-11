import { app, BrowserWindow, ipcMain } from 'electron';

// Window-control handlers for the frameless window's own custom title bar
// (see main/index.ts's frame:false) — same shape as SSM-VMS's own
// ipc/system.ts.
export function registerSystemIpcHandlers(): void {
  ipcMain.handle('system:getAppVersion', (): string => app.getVersion());

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
