import { join } from 'path';
import { app, BrowserWindow, shell } from 'electron';
import { registerDeviceIpcHandlers } from './ipc/device';
import { registerDiscoveryIpcHandlers } from './ipc/discovery';
import { registerSystemIpcHandlers } from './ipc/system';

let mainWindow: BrowserWindow | null = null;

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 820,
    minHeight: 520,
    show: false,
    // Frameless — the native OS title bar is replaced by App.tsx's own
    // dark header, which draws its own minimize/maximize/close buttons and
    // is made draggable via CSS (-webkit-app-region) instead. Same pattern
    // as SSM-VMS's own main/index.ts.
    frame: false,
    backgroundColor: '#0a0e13',
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false,
    },
  });

  // Any link that would open a new window goes to the user's default
  // browser instead — never a child app window, which would inherit the
  // preload bridge (see ipc/device.ts's device:openWebPage).
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.on('maximize', () => mainWindow?.webContents.send('system:windowMaximizedChanged', true));
  mainWindow.on('unmaximize', () => mainWindow?.webContents.send('system:windowMaximizedChanged', false));

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  }
}

app.whenReady().then(() => {
  registerDiscoveryIpcHandlers();
  registerDeviceIpcHandlers();
  registerSystemIpcHandlers();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
