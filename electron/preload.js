'use strict';

const { contextBridge, ipcRenderer } = require('electron');
const path = require('node:path');

let appVersion = '1.1.0';
try {
  appVersion = require(path.join(__dirname, 'package.json')).version || appVersion;
} catch {
  appVersion = process.env.npm_package_version || '1.1.0';
}

contextBridge.exposeInMainWorld('dnsentinel', {
  platform: process.platform,
  version: appVersion,

  // Theme
  getTheme: () => ipcRenderer.invoke('theme:get'),
  setTheme: (theme) => ipcRenderer.invoke('theme:set', theme),

  // Server management
  server: {
    getStatus: () => ipcRenderer.invoke('server:status'),
    start: () => ipcRenderer.invoke('server:start'),
    stop: () => ipcRenderer.invoke('server:stop'),
    checkPort: (port, host) => ipcRenderer.invoke('server:check-port', port, host),
    testDns: (domain, host, port) => ipcRenderer.invoke('server:test-dns', domain, host, port),
    onStatusChanged: (callback) => {
      const sub = (event, data) => callback(data);
      ipcRenderer.on('server:status-changed', sub);
      return () => ipcRenderer.removeListener('server:status-changed', sub);
    },
  },

  // Configuration
  config: {
    get: () => ipcRenderer.invoke('config:get'),
    set: (cfg) => ipcRenderer.invoke('config:set', cfg),
  },

  // Blocklist
  blocklist: {
    list: (search) => ipcRenderer.invoke('blocklist:list', search),
    add: (domain) => ipcRenderer.invoke('blocklist:add', domain),
    remove: (domain) => ipcRenderer.invoke('blocklist:remove', domain),
  },

  // Logs & Streams
  logs: {
    tail: (type, count) => ipcRenderer.invoke('logs:tail', type, count),
    clear: () => ipcRenderer.invoke('logs:clear'),
    openDir: () => ipcRenderer.invoke('logs:open-dir'),
    onDnsStream: (callback) => {
      const sub = (event, data) => callback(data);
      ipcRenderer.on('stream:dns-queries', sub);
      return () => ipcRenderer.removeListener('stream:dns-queries', sub);
    },
  },

  // Network tracking
  nettrack: {
    snapshot: () => ipcRenderer.invoke('nettrack:snapshot'),
  },

  // Autostart
  autostart: {
    status: () => ipcRenderer.invoke('autostart:status'),
    toggle: (enable) => ipcRenderer.invoke('autostart:toggle', enable),
  },

  // Dialogs
  dialog: {
    message: (options) => ipcRenderer.invoke('dialog:message', options),
  },
});
