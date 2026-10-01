'use strict';

const { app, BrowserWindow, Menu, Tray, nativeImage, shell, ipcMain, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn, execFile } = require('node:child_process');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const LOGS_DIR = path.join(PROJECT_ROOT, 'logs');
const DNS_LOG_PATH = path.join(LOGS_DIR, 'dns.log');
const EGRESS_LOG_PATH = path.join(LOGS_DIR, 'egress.log');
const NETTRACK_LOG_PATH = path.join(LOGS_DIR, 'nettrack.log');

let mainWindow = null;
let tray = null;
let pythonServerProcess = null;
let serverState = {
  running: false,
  pid: null,
  startedAt: null,
  listen: '127.0.0.1',
  port: 53,
  upstreams: ['1.1.1.1', '8.8.8.8'],
  lastError: null,
  privilegeError: false,
};

// Log tail tracking
let dnsLogOffset = 0;
let logWatcherTimer = null;

// Theme configuration
const THEME_META = {
  dark: { bg: '#010102', symbol: '#f8fafc' },
  white: { bg: '#ffffff', symbol: '#1d1d1f' },
  brown: { bg: '#f2f0eb', symbol: '#1f1f1f' },
  pinky: { bg: '#ffffff', symbol: '#ff385c' },
};

function getThemePath() {
  return path.join(app.getPath('userData'), 'theme.json');
}

function loadTheme() {
  try {
    const raw = fs.readFileSync(getThemePath(), 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && THEME_META[parsed.theme]) return parsed.theme;
  } catch {}
  return 'dark';
}

function saveTheme(theme) {
  if (!THEME_META[theme]) return;
  try {
    fs.mkdirSync(path.dirname(getThemePath()), { recursive: true });
    fs.writeFileSync(getThemePath(), JSON.stringify({ theme }), 'utf8');
  } catch (err) {
    console.error('[DNSentinel] Error saving theme:', err.message);
  }
}

function applyThemeToWindow(win, theme) {
  if (!win || win.isDestroyed()) return;
  const meta = THEME_META[theme] || THEME_META.dark;
  try {
    if (process.platform === 'win32') {
      win.setTitleBarOverlay({
        color: meta.bg,
        symbolColor: meta.symbol,
        height: 34,
      });
    }
    win.setBackgroundColor(meta.bg);
  } catch (err) {
    console.error('[DNSentinel] Failed to set window theme:', err.message);
  }
}

// Locate Python command (python3 or python)
function getPythonCommand() {
  if (process.env.PYTHON_PATH && fs.existsSync(process.env.PYTHON_PATH)) {
    return process.env.PYTHON_PATH;
  }
  // Try platform specifics
  if (process.platform === 'win32') {
    return 'python';
  }
  return 'python3';
}

// Call bridge.py synchronously or via promise
function callBridge(args) {
  return new Promise((resolve) => {
    const py = getPythonCommand();
    const bridgeScript = path.join(PROJECT_ROOT, 'bridge.py');
    const proc = spawn(py, [bridgeScript, ...args], {
      cwd: PROJECT_ROOT,
      env: process.env,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
    proc.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

    proc.on('close', (code) => {
      const trimmed = stdout.trim();
      if (!trimmed) {
        return resolve({ ok: false, error: stderr.trim() || `Exit code ${code}` });
      }
      try {
        const parsed = JSON.parse(trimmed);
        resolve(parsed);
      } catch (e) {
        resolve({ ok: false, raw: trimmed, error: stderr.trim() || e.message });
      }
    });

    proc.on('error', (err) => {
      resolve({ ok: false, error: `Failed to spawn Python: ${err.message}` });
    });
  });
}

// Start agent.py serve
async function startDnsProxy() {
  if (pythonServerProcess && !pythonServerProcess.killed) {
    return { ok: true, message: 'Server is already running', state: serverState };
  }

  // Pre-load current config for port & listen info
  const cfgRes = await callBridge(['config-get']);
  if (cfgRes.ok && cfgRes.config) {
    serverState.listen = cfgRes.config.listen || '127.0.0.1';
    serverState.port = cfgRes.config.port || 53;
    serverState.upstreams = cfgRes.config.upstreams || ['1.1.1.1', '8.8.8.8'];
  }

  serverState.lastError = null;
  serverState.privilegeError = false;

  const py = getPythonCommand();
  const agentScript = path.join(PROJECT_ROOT, 'agent.py');

  return new Promise((resolve) => {
    let resolved = false;

    try {
      pythonServerProcess = spawn(py, [agentScript, 'serve'], {
        cwd: PROJECT_ROOT,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      serverState.running = false;
      serverState.lastError = err.message;
      return resolve({ ok: false, error: err.message, state: serverState });
    }

    serverState.pid = pythonServerProcess.pid;
    serverState.startedAt = new Date().toISOString();

    pythonServerProcess.stdout.on('data', (data) => {
      const text = data.toString('utf8');
      console.log('[DNSentinel Core]', text.trim());
      if (text.includes('DNSentinel serving on') && !resolved) {
        resolved = true;
        serverState.running = true;
        serverState.lastError = null;
        broadcastServerStatus();
        resolve({ ok: true, state: serverState });
      }
    });

    pythonServerProcess.stderr.on('data', (data) => {
      const text = data.toString('utf8');
      console.error('[DNSentinel Core ERR]', text.trim());
      serverState.lastError = text.trim();
      if (text.includes('PermissionError') || text.includes('need admin/root for port 53')) {
        serverState.privilegeError = true;
      }
      if (!resolved) {
        resolved = true;
        serverState.running = false;
        broadcastServerStatus();
        resolve({ ok: false, error: text.trim(), state: serverState });
      }
    });

    pythonServerProcess.on('exit', (code, signal) => {
      console.log(`[DNSentinel Core] Exited with code ${code}, signal ${signal}`);
      pythonServerProcess = null;
      serverState.running = false;
      serverState.pid = null;
      serverState.startedAt = null;
      broadcastServerStatus();
    });

    pythonServerProcess.on('error', (err) => {
      console.error('[DNSentinel Core Spawn Error]', err.message);
      serverState.lastError = err.message;
      serverState.running = false;
      broadcastServerStatus();
      if (!resolved) {
        resolved = true;
        resolve({ ok: false, error: err.message, state: serverState });
      }
    });

    // Fallback timer: if after 1500ms it didn't exit and no explicit message, assume started
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        if (pythonServerProcess && !pythonServerProcess.killed && pythonServerProcess.exitCode === null) {
          serverState.running = true;
          broadcastServerStatus();
          resolve({ ok: true, state: serverState });
        } else {
          serverState.running = false;
          broadcastServerStatus();
          resolve({ ok: false, error: serverState.lastError || 'Process terminated immediately', state: serverState });
        }
      }
    }, 1500);
  });
}

// Stop agent.py serve
async function stopDnsProxy() {
  if (!pythonServerProcess || pythonServerProcess.killed) {
    serverState.running = false;
    serverState.pid = null;
    broadcastServerStatus();
    return { ok: true, message: 'Server was not running', state: serverState };
  }

  return new Promise((resolve) => {
    try {
      const pid = pythonServerProcess.pid;
      if (process.platform === 'win32') {
        // Windows graceful taskkill
        execFile('taskkill', ['/pid', String(pid), '/T', '/F'], () => {
          pythonServerProcess = null;
          serverState.running = false;
          serverState.pid = null;
          serverState.startedAt = null;
          broadcastServerStatus();
          resolve({ ok: true, state: serverState });
        });
      } else {
        pythonServerProcess.kill('SIGTERM');
        setTimeout(() => {
          if (pythonServerProcess && !pythonServerProcess.killed) {
            pythonServerProcess.kill('SIGKILL');
          }
          pythonServerProcess = null;
          serverState.running = false;
          serverState.pid = null;
          serverState.startedAt = null;
          broadcastServerStatus();
          resolve({ ok: true, state: serverState });
        }, 500);
      }
    } catch (err) {
      resolve({ ok: false, error: err.message, state: serverState });
    }
  });
}

function broadcastServerStatus() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('server:status-changed', serverState);
  }
}

// Real-time log streamer to UI
function setupLogStreamer() {
  if (fs.existsSync(DNS_LOG_PATH)) {
    try {
      const stat = fs.statSync(DNS_LOG_PATH);
      // Start reading near end (last 30KB or 0)
      dnsLogOffset = Math.max(0, stat.size - 30000);
    } catch {}
  } else {
    dnsLogOffset = 0;
  }

  if (logWatcherTimer) clearInterval(logWatcherTimer);

  logWatcherTimer = setInterval(() => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (!fs.existsSync(DNS_LOG_PATH)) return;

    try {
      const stat = fs.statSync(DNS_LOG_PATH);
      if (stat.size < dnsLogOffset) {
        // Log was truncated or cleared
        dnsLogOffset = 0;
      }
      if (stat.size > dnsLogOffset) {
        const bytesToRead = stat.size - dnsLogOffset;
        const buf = Buffer.alloc(bytesToRead);
        const fd = fs.openSync(DNS_LOG_PATH, 'r');
        fs.readSync(fd, buf, 0, bytesToRead, dnsLogOffset);
        fs.closeSync(fd);
        dnsLogOffset = stat.size;

        const chunk = buf.toString('utf8');
        const lines = chunk.split('\n');
        const parsedEntries = [];
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            parsedEntries.push(JSON.parse(trimmed));
          } catch {
            parsedEntries.push({ raw: trimmed });
          }
        }
        if (parsedEntries.length > 0) {
          mainWindow.webContents.send('stream:dns-queries', parsedEntries);
        }
      }
    } catch (err) {
      // Non-blocking log read error
    }
  }, 800);
}

// Window creation
function createWindow() {
  const currentTheme = loadTheme();
  const themeMeta = THEME_META[currentTheme] || THEME_META.dark;

  mainWindow = new BrowserWindow({
    width: 1040,
    height: 720,
    minWidth: 760,
    minHeight: 520,
    title: 'DNSentinel',
    backgroundColor: themeMeta.bg,
    icon: path.join(__dirname, 'assets', 'icon.png'),
    autoHideMenuBar: true,
    frame: process.platform !== 'win32',
    titleBarStyle: process.platform === 'win32' ? 'hidden' : 'default',
    titleBarOverlay: process.platform === 'win32' ? {
      color: themeMeta.bg,
      symbolColor: themeMeta.symbol,
      height: 34,
    } : false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.removeMenu();
  mainWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('close', (e) => {
    if (!app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'icon.png');
  let iconImg;
  if (fs.existsSync(iconPath)) {
    iconImg = nativeImage.createFromPath(iconPath);
  } else {
    iconImg = nativeImage.createEmpty();
  }

  tray = new Tray(iconImg.resize({ width: 16, height: 16 }));
  tray.setToolTip('DNSentinel - Local DNS Proxy');

  const updateTrayMenu = () => {
    const isRunning = serverState.running;
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Show DNSentinel',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        },
      },
      { type: 'separator' },
      {
        label: `Status: ${isRunning ? 'Running' : 'Stopped'}`,
        enabled: false,
      },
      {
        label: isRunning ? 'Stop DNS Proxy' : 'Start DNS Proxy',
        click: async () => {
          if (isRunning) {
            await stopDnsProxy();
          } else {
            await startDnsProxy();
          }
        },
      },
      { type: 'separator' },
      {
        label: 'Open Logs Folder',
        click: () => {
          if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
          shell.openPath(LOGS_DIR);
        },
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: async () => {
          app.isQuitting = true;
          await stopDnsProxy();
          app.quit();
        },
      },
    ]);
    tray.setContextMenu(contextMenu);
  };

  updateTrayMenu();

  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// IPC Handlers
function setupIpcHandlers() {
  // Theme
  ipcMain.handle('theme:get', () => loadTheme());
  ipcMain.handle('theme:set', (event, theme) => {
    saveTheme(theme);
    const win = BrowserWindow.fromWebContents(event.sender);
    applyThemeToWindow(win, theme);
    return { ok: true, theme };
  });

  // Server management
  ipcMain.handle('server:status', async () => {
    // Also test if port 53 is open or if running
    return { ...serverState };
  });

  ipcMain.handle('server:start', async () => {
    return await startDnsProxy();
  });

  ipcMain.handle('server:stop', async () => {
    return await stopDnsProxy();
  });

  ipcMain.handle('server:check-port', async (event, port, host) => {
    return await callBridge(['check-port', String(port || 53), host || '127.0.0.1']);
  });

  ipcMain.handle('server:test-dns', async (event, domain, host, port) => {
    return await callBridge(['test-dns', domain || 'google.com', host || '127.0.0.1', String(port || 53)]);
  });

  // Config
  ipcMain.handle('config:get', async () => {
    return await callBridge(['config-get']);
  });

  ipcMain.handle('config:set', async (event, configObj) => {
    return await callBridge(['config-set', JSON.stringify(configObj)]);
  });

  // Blocklist
  ipcMain.handle('blocklist:list', async (event, search) => {
    return await callBridge(['block-list', search || '']);
  });

  ipcMain.handle('blocklist:add', async (event, domain) => {
    return await callBridge(['block-add', domain]);
  });

  ipcMain.handle('blocklist:remove', async (event, domain) => {
    return await callBridge(['block-remove', domain]);
  });

  // Logs
  ipcMain.handle('logs:tail', async (event, logType, count) => {
    return await callBridge(['tail-log', logType || 'dns', String(count || 100)]);
  });

  ipcMain.handle('logs:clear', async () => {
    dnsLogOffset = 0;
    return await callBridge(['clear-logs']);
  });

  ipcMain.handle('logs:open-dir', async () => {
    if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
    await shell.openPath(LOGS_DIR);
    return { ok: true, path: LOGS_DIR };
  });

  // Nettrack
  ipcMain.handle('nettrack:snapshot', async () => {
    return await callBridge(['nettrack-snapshot']);
  });

  // Autostart
  ipcMain.handle('autostart:status', async () => {
    return await callBridge(['autostart-status']);
  });

  ipcMain.handle('autostart:toggle', async (event, enable) => {
    const cmd = enable ? 'autostart-enable' : 'autostart-disable';
    return await callBridge([cmd]);
  });

  // Dialog helpers
  ipcMain.handle('dialog:message', async (event, options) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    return await dialog.showMessageBox(win, options);
  });
}

// App Lifecycle
app.whenReady().then(async () => {
  setupIpcHandlers();
  createWindow();
  createTray();
  setupLogStreamer();

  // Load config initial values
  const cfg = await callBridge(['config-get']);
  if (cfg.ok && cfg.config) {
    serverState.listen = cfg.config.listen || '127.0.0.1';
    serverState.port = cfg.config.port || 53;
    serverState.upstreams = cfg.config.upstreams || ['1.1.1.1', '8.8.8.8'];
    broadcastServerStatus();
  }
});

app.on('window-all-closed', () => {
  // Stay running in tray
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  } else {
    mainWindow.show();
  }
});

app.on('before-quit', async () => {
  app.isQuitting = true;
  if (logWatcherTimer) clearInterval(logWatcherTimer);
  await stopDnsProxy();
});

// Single instance lock
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}
