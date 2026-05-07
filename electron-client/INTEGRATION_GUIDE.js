/**
 * HOW TO INTEGRATE license-client.js INTO YOUR ELECTRON APP
 * ──────────────────────────────────────────────────────────
 * Copy license-client.js into your Electron app root folder
 * Then update your main.js like this:
 */

// ─── Your existing imports ────────────────────────────────────
const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');

// ─── ADD THIS LINE ─────────────────────────────────────────────
const LicenseClient = require('./license-client');
const license = new LicenseClient();

// ─── Your existing createWindow function ──────────────────────
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width:  1200,
    height: 800,
    title:  'Medishop Pharmacy Billing',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile('index.html'); // or loadURL(...)
}

// ─── REPLACE your app.whenReady with this ─────────────────────
app.whenReady().then(async () => {
  createWindow();

  // CHECK LICENSE — this runs silently if already activated,
  // shows activation dialog only if not yet activated or token expired
  const isLicensed = await license.checkOnStartup(mainWindow);

  if (!isLicensed) {
    // User cancelled activation or license invalid
    app.quit();
    return;
  }

  // ✅ License is valid — continue loading the app normally
  // The main window is already open and ready to use
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ─── OPTIONAL: Expose license info to renderer via IPC ────────
const { ipcMain } = require('electron');

ipcMain.handle('get-license-info', () => {
  return license.data ? {
    type:     license.data.type,
    email:    license.data.email,
    daysLeft: license.data.daysLeft
  } : null;
});

// ─── In your renderer/preload you can then show: ──────────────
// const info = await window.electronAPI.getLicenseInfo();
// if (info.type === 'trial') {
//   showStatusBar(`Trial License — ${info.daysLeft} days remaining`);
// }
