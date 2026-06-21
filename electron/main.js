const { app, BrowserWindow, Menu, ipcMain, dialog } = require('electron')
const { spawn, execFile, exec } = require('child_process')
const { autoUpdater } = require('electron-updater')
const path = require('path')
const fs = require('fs')
const os = require('os')
const http = require('http')

let goProcess = null
let mainWindow = null
let serverPort = null
const chromeProcesses = new Map()

const ANTIDETECT_DIR = path.join(os.homedir(), '.antidetect')
const PORT_FILE = path.join(ANTIDETECT_DIR, '.port')

function getResourcesPath() {
  if (app.isPackaged) {
    return process.resourcesPath
  }
  return path.join(__dirname, '..')
}

function getServerExe() {
  const resPath = getResourcesPath()
  const isWin = process.platform === 'win32'
  const binName = isWin ? 'personax-server.exe' : 'personax-server'
  if (app.isPackaged) {
    return path.join(resPath, binName)
  }
  return path.join(resPath, 'launcher-go', binName)
}

function copyDirSync(src, dest) {
  fs.mkdirSync(dest, { recursive: true })
  const entries = fs.readdirSync(src, { withFileTypes: true })
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name)
    const destPath = path.join(dest, entry.name)
    if (entry.isDirectory()) {
      copyDirSync(srcPath, destPath)
    } else {
      fs.copyFileSync(srcPath, destPath)
    }
  }
}

function setupUserData() {
  fs.mkdirSync(ANTIDETECT_DIR, { recursive: true })

  const resPath = getResourcesPath()

  const proxyDir = path.join(ANTIDETECT_DIR, 'proxies')
  const proxyDest = path.join(proxyDir, 'PROXY.csv')
  if (!fs.existsSync(proxyDest)) {
    const proxySrc = path.join(resPath, 'PROXY.csv')
    if (fs.existsSync(proxySrc)) {
      fs.mkdirSync(proxyDir, { recursive: true })
      fs.copyFileSync(proxySrc, proxyDest)
    }
  }

  const extDest = path.join(ANTIDETECT_DIR, 'builtin-extensions', 'distribte')
  if (!fs.existsSync(path.join(extDest, 'manifest.json'))) {
    const extSrc = path.join(resPath, 'builtin-extensions', 'distribte')
    if (fs.existsSync(path.join(extSrc, 'manifest.json'))) {
      copyDirSync(extSrc, extDest)
    }
  }
}

function waitForPortFile(timeout) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const check = () => {
      try {
        const content = fs.readFileSync(PORT_FILE, 'utf8').trim()
        const port = parseInt(content)
        if (port > 0 && port < 65536) {
          resolve(port)
          return
        }
      } catch (e) {}

      if (Date.now() - start > timeout) {
        reject(new Error('Server did not start in time'))
        return
      }
      setTimeout(check, 150)
    }
    setTimeout(check, 300)
  })
}

async function startServer() {
  setupUserData()

  try { fs.unlinkSync(PORT_FILE) } catch (e) {}

  const serverExe = getServerExe()
  const resPath = getResourcesPath()

  goProcess = spawn(serverExe, ['--server'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
    detached: false,
    shell: false,
    env: {
      ...process.env,
      PERSONAX_SERVER_MODE: '1',
      PERSONAX_RESOURCES: resPath
    }
  })

  goProcess.stderr.on('data', (data) => {
    console.error(`[server] ${data.toString().trim()}`)
  })

  goProcess.on('error', (err) => {
    console.error('Failed to start server:', err)
    app.quit()
  })

  goProcess.on('exit', (code) => {
    console.log(`Server exited with code ${code}`)
    goProcess = null
    if (mainWindow) {
      mainWindow.close()
    }
  })

  const port = await waitForPortFile(15000)
  serverPort = port
  return port
}

function createWindow(port) {
  Menu.setApplicationMenu(null)

  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 600,
    title: 'PERSONAX',
    autoHideMenuBar: true,
    show: false,
    backgroundColor: '#1a1a2e',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  })

  mainWindow.loadURL(`http://127.0.0.1:${port}`)

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
    mainWindow.focus()
  })

  mainWindow.on('page-title-updated', (e) => {
    e.preventDefault()
  })
  mainWindow.setTitle('PERSONAX v' + app.getVersion())

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

function buildCleanEnv() {
  const clean = {}
  for (const [key, val] of Object.entries(process.env)) {
    const upper = key.toUpperCase()
    if (upper.startsWith('ELECTRON') ||
        upper.startsWith('CHROME_') ||
        upper.startsWith('NODE_') ||
        upper.startsWith('ORIGINAL_XDG') ||
        upper.startsWith('PERSONAX_')) {
      continue
    }
    clean[key] = val
  }
  clean.GOOGLE_API_KEY = 'no'
  clean.GOOGLE_DEFAULT_CLIENT_ID = 'no'
  clean.GOOGLE_DEFAULT_CLIENT_SECRET = 'no'
  return clean
}

function setupIPC() {
  ipcMain.handle('launch-chrome', async (event, chromePath, args, profileId) => {
    try {
      const cleanEnv = buildCleanEnv()
      const child = spawn(chromePath, args, {
        detached: true,
        stdio: 'ignore',
        env: cleanEnv
      })
      child.unref()

      const pid = child.pid
      chromeProcesses.set(pid, child)

      child.on('exit', () => {
        chromeProcesses.delete(pid)
        // Notify Go server that profile closed so status updates
        if (serverPort && profileId) {
          const postData = JSON.stringify({ profile_id: profileId, pid: pid, action: 'stopped' })
          const req = http.request({
            hostname: '127.0.0.1',
            port: serverPort,
            path: '/api/electron-notify',
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': postData.length }
          })
          req.on('error', () => {})
          req.write(postData)
          req.end()
        }
      })

      return { ok: true, pid: pid }
    } catch (err) {
      return { ok: false, error: err.message }
    }
  })

  ipcMain.handle('stop-chrome', async (event, pid) => {
    try {
      exec(`taskkill /F /T /PID ${pid}`, () => {})
      chromeProcesses.delete(pid)
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err.message }
    }
  })
}

function killServer() {
  if (!goProcess) return

  if (serverPort) {
    const req = http.get(`http://127.0.0.1:${serverPort}/api/quit`, () => {})
    req.on('error', () => {})
  }

  setTimeout(() => {
    if (goProcess) {
      try { goProcess.kill() } catch (e) {}
      goProcess = null
    }
  }, 2000)
}

function setupAutoUpdate() {
  autoUpdater.autoDownload = false
  autoUpdater.autoInstallOnAppQuit = true

  autoUpdater.on('update-available', (info) => {
    console.log('Update available:', info.version)
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Available',
      message: `PERSONAX v${info.version} is available (you have v${app.getVersion()})`,
      detail: 'Would you like to update now?',
      buttons: ['Update Now', 'Not Right Now'],
      defaultId: 0,
      cancelId: 1
    }).then((result) => {
      if (result.response === 0) {
        if (mainWindow) {
          mainWindow.webContents.executeJavaScript(
            `if(typeof toast==='function') toast('Downloading update v${info.version}...', 'success');`
          )
        }
        autoUpdater.downloadUpdate()
      }
    })
  })

  autoUpdater.on('update-downloaded', (info) => {
    console.log('Update downloaded:', info.version)
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Ready',
      message: `PERSONAX v${info.version} has been downloaded`,
      detail: 'The update will be installed when you restart the app. Restart now?',
      buttons: ['Restart Now', 'Later'],
      defaultId: 0,
      cancelId: 1
    }).then((result) => {
      if (result.response === 0) {
        autoUpdater.quitAndInstall()
      }
    })
  })

  autoUpdater.on('update-not-available', () => {
    console.log('App is up to date: v' + app.getVersion())
  })

  autoUpdater.on('error', (err) => {
    console.error('Auto-update error:', err.message)
  })

  autoUpdater.checkForUpdates()
}

app.whenReady().then(async () => {
  setupIPC()
  try {
    const port = await startServer()
    createWindow(port)
    setupAutoUpdate()
  } catch (err) {
    console.error('Startup failed:', err)
    if (goProcess) {
      try { goProcess.kill() } catch (e) {}
    }
    app.quit()
  }
})

app.on('window-all-closed', () => {
  killServer()
  setTimeout(() => app.quit(), 2500)
})

app.on('before-quit', () => {
  killServer()
})
