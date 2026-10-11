import { contextBridge, ipcRenderer } from 'electron';
import type { DiscoveredDevice, FactoryResetRequest, ModifyNetworkRequest, ModifyNetworkResult, PortSettings, RebootRequest } from '../shared/types';

const discovery = {
  scan: (): Promise<DiscoveredDevice[]> => ipcRenderer.invoke('discovery:scan'),
};

const device = {
  modifyNetwork: (request: ModifyNetworkRequest): Promise<ModifyNetworkResult> =>
    ipcRenderer.invoke('device:modifyNetwork', request),
  openWebPage: (host: string): Promise<void> => ipcRenderer.invoke('device:openWebPage', host),
  openSadpTool: (): Promise<ModifyNetworkResult> => ipcRenderer.invoke('device:openSadpTool'),
  reboot: (request: RebootRequest): Promise<ModifyNetworkResult> => ipcRenderer.invoke('device:reboot', request),
  factoryReset: (request: FactoryResetRequest): Promise<ModifyNetworkResult> => ipcRenderer.invoke('device:factoryReset', request),
  readNetwork: (host: string, discoveryMethod: string): Promise<{ subnetMask?: string; gateway?: string; ports?: PortSettings; dhcp?: boolean }> =>
    ipcRenderer.invoke('device:readNetwork', host, discoveryMethod),
  readNetworkAuth: (
    host: string,
    discoveryMethod: string,
    username: string,
    password: string,
  ): Promise<{ subnetMask?: string; gateway?: string; dhcp?: boolean; error?: string }> =>
    ipcRenderer.invoke('device:readNetworkAuth', host, discoveryMethod, username, password),
};

const system = {
  getAppVersion: (): Promise<string> => ipcRenderer.invoke('system:getAppVersion'),
  minimizeWindow: (): Promise<void> => ipcRenderer.invoke('system:minimizeWindow'),
  toggleMaximizeWindow: (): Promise<void> => ipcRenderer.invoke('system:toggleMaximizeWindow'),
  closeWindow: (): Promise<void> => ipcRenderer.invoke('system:closeWindow'),
  isWindowMaximized: (): Promise<boolean> => ipcRenderer.invoke('system:isWindowMaximized'),
  onWindowMaximizedChanged: (callback: (maximized: boolean) => void): (() => void) => {
    const listener = (_event: Electron.IpcRendererEvent, maximized: boolean): void => callback(maximized);
    ipcRenderer.on('system:windowMaximizedChanged', listener);
    return () => ipcRenderer.removeListener('system:windowMaximizedChanged', listener);
  },
};

const api = { discovery, device, system };
export type PreloadApi = typeof api;

contextBridge.exposeInMainWorld('ipTool', api);
