const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('personax', {
  launchChrome: (chromePath, args, profileId) =>
    ipcRenderer.invoke('launch-chrome', chromePath, args, profileId),
  stopChrome: (pid) =>
    ipcRenderer.invoke('stop-chrome', pid),
  isElectron: true,
  focusWindow: () => ipcRenderer.invoke('focus-window'),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  memberLogin: (serverUrl, username, password) => ipcRenderer.invoke('member-login', serverUrl, username, password)
})
