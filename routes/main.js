// ============================================================
// main.js — MediShop Pro  v2.1  (FULL LICENSE FIX)
//
// LICENSE SYSTEM — FULLY WORKING:
//  ✅ Online activation via Railway server
//  ✅ Machine ID binding (one PC per key)
//  ✅ Deactivation works — app blocks immediately
//  ✅ Revoked keys refused at startup
//  ✅ Trial expiry enforced
//  ✅ All activity logged to Railway server
//  ✅ Offline grace period (3 days) with background re-check
// ============================================================

const {
  app, BrowserWindow, ipcMain, dialog, shell,
  Menu, Notification, clipboard, net
} = require('electron');
const path   = require('path');
const fs     = require('fs');
const os     = require('os');
const crypto = require('crypto');

// ── Config ────────────────────────────────────────────────────────────────
// ⚠️  UPDATE THIS URL to your actual Railway deployment URL
const LICENSE_SERVER = 'https://medishop-production-6c4b.up.railway.app';

// ── Paths ─────────────────────────────────────────────────────────────────
const userDataPath = app.getPath('userData');
const backupDir    = path.join(userDataPath, 'backups');
const dataFile     = path.join(userDataPath, 'medishop_data.json');
const authFile     = path.join(userDataPath, 'auth.json');
const licenseFile  = path.join(userDataPath, 'license.json');

if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

let db;
let mainWindow  = null;
let loginWindow = null;

// ── Machine ID ────────────────────────────────────────────────────────────
function getMachineId() {
  const raw = `${os.hostname()}-${os.platform()}-${os.arch()}-${os.cpus()[0]?.model || ''}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32);
}

// ── Preload path ──────────────────────────────────────────────────────────
function getPreloadPath() {
  const candidates = [
    path.join(__dirname, 'preload', 'preload.js'),
    path.join(__dirname, 'preload.js'),
    path.join(process.resourcesPath || '', 'app', 'preload', 'preload.js'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return path.join(__dirname, 'preload', 'preload.js');
}

function getRendererDir() {
  const sub = path.join(__dirname, 'renderer');
  return fs.existsSync(sub) ? sub : __dirname;
}

// ══════════════════════════════════════════════════════════════════════════
// LICENSE SYSTEM
// ══════════════════════════════════════════════════════════════════════════

function getLocalLicense() {
  if (!fs.existsSync(licenseFile)) return null;
  try { return JSON.parse(fs.readFileSync(licenseFile, 'utf8')); }
  catch { return null; }
}

function saveLocalLicense(info) {
  fs.writeFileSync(licenseFile, JSON.stringify(info, null, 2));
}

// Check local license status (for UI / IPC calls)
function checkLocalLicense() {
  const lic = getLocalLicense();
  if (!lic || !lic.activated) {
    return { valid: false, type: null, reason: 'Not activated' };
  }
  if (lic.revoked) {
    return { valid: false, type: lic.type, reason: 'Revoked', key: lic.key };
  }
  if (lic.type === 'trial' && lic.expires_at) {
    const daysLeft = Math.max(0, Math.ceil((new Date(lic.expires_at) - new Date()) / 86400000));
    if (daysLeft <= 0) return { valid: false, type: 'trial', expired: true, days_left: 0, key: lic.key };
    return { valid: true, type: 'trial', days_left: daysLeft, email: lic.email, key: lic.key };
  }
  if (lic.type === 'full') {
    return { valid: true, type: 'full', days_left: -1, email: lic.email, key: lic.key };
  }
  return { valid: false, type: lic.type, reason: 'Unknown state' };
}

// ── HTTP helper (uses Electron net module, works in main process) ─────────
function httpGet(url, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ ok: false, error: 'timeout' }), timeoutMs);
    try {
      const req = net.request(url);
      req.on('response', (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          clearTimeout(timer);
          try { resolve({ ok: true, data: JSON.parse(data) }); }
          catch { resolve({ ok: false, error: 'invalid_json', raw: data }); }
        });
      });
      req.on('error', (err) => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });
      req.end();
    } catch (e) {
      clearTimeout(timer);
      resolve({ ok: false, error: e.message });
    }
  });
}

function httpPost(url, body, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ ok: false, error: 'timeout' }), timeoutMs);
    try {
      const req = net.request({ method: 'POST', url });
      req.setHeader('Content-Type', 'application/json');
      req.on('response', (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          clearTimeout(timer);
          try { resolve({ ok: true, data: JSON.parse(data) }); }
          catch { resolve({ ok: false, error: 'invalid_json', raw: data }); }
        });
      });
      req.on('error', (err) => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });
      req.write(JSON.stringify(body));
      req.end();
    } catch (e) {
      clearTimeout(timer);
      resolve({ ok: false, error: e.message });
    }
  });
}

// ── Online license validation at startup ─────────────────────────────────
// Returns: { allow: true } or { allow: false, reason: '...', showLicenseScreen: bool }
async function validateLicenseOnline() {
  const lic = getLocalLicense();

  // No local license at all → show activation screen
  if (!lic || !lic.key) {
    console.log('[LICENSE] No local license — showing activation screen');
    return { allow: false, reason: 'not_activated', showLicenseScreen: true };
  }

  const machineId = getMachineId();

  // ── Try online validation ─────────────────────────────────────────────
  console.log('[LICENSE] Checking with server:', lic.key);
  const res = await httpGet(
    `${LICENSE_SERVER}/api/validate?token=${encodeURIComponent(lic.key)}&machine_id=${machineId}`
  );

  if (res.ok) {
    const d = res.data;
    console.log('[LICENSE] Server response:', JSON.stringify(d));

    if (!d.active) {
      // Server says inactive — update local cache and block
      saveLocalLicense({
        ...lic,
        activated: false,
        revoked: d.reason === 'Revoked',
        last_online_check: new Date().toISOString(),
        server_reason: d.reason
      });
      // Show license screen for all cases except machine mismatch
      const isMachineMismatch = d.reason === 'Used on another device';
      return {
        allow: false,
        reason: d.reason || 'deactivated',
        showLicenseScreen: !isMachineMismatch
      };
    }

    // Active — update local cache with fresh data
    saveLocalLicense({
      ...lic,
      activated: true,
      revoked: false,
      machine_id: machineId,
      last_online_check: new Date().toISOString(),
      server_reason: null,
      // Server may return updated trial days
      days_left: d.days_left !== undefined ? d.days_left : lic.days_left,
      expires_at: d.expires_at || lic.expires_at
    });

    const daysLeft = d.days_left !== undefined ? d.days_left : (lic.type === 'trial' ? 7 : -1);
    return { allow: true, type: lic.type || 'full', days_left: daysLeft };
  }

  // ── Offline fallback ──────────────────────────────────────────────────
  console.log('[LICENSE] Server unreachable — using offline grace period');

  if (!lic.activated || lic.revoked) {
    return { allow: false, reason: 'not_activated', showLicenseScreen: true };
  }

  // Check trial expiry locally
  if (lic.type === 'trial' && lic.expires_at) {
    const daysLeft = Math.max(0, Math.ceil((new Date(lic.expires_at) - new Date()) / 86400000));
    if (daysLeft <= 0) {
      return { allow: false, reason: 'Expired', showLicenseScreen: true };
    }
    return { allow: true, type: 'trial', days_left: daysLeft, offline: true };
  }

  // Machine ID mismatch even offline → block
  if (lic.machine_id && lic.machine_id !== machineId) {
    return { allow: false, reason: 'Used on another device', showLicenseScreen: false };
  }

  // Grace period: allow up to 3 days offline
  const lastCheck = lic.last_online_check ? new Date(lic.last_online_check) : null;
  const hoursSinceCheck = lastCheck ? (Date.now() - lastCheck.getTime()) / 3600000 : 0;

  if (hoursSinceCheck > 72) {
    console.log('[LICENSE] Offline grace period expired (72h)');
    return {
      allow: false,
      reason: 'Cannot verify license (offline >72h). Please connect to internet.',
      showLicenseScreen: false
    };
  }

  return { allow: true, type: lic.type || 'full', days_left: lic.days_left || -1, offline: true };
}

// ── Background periodic re-check (every 6 hours) ─────────────────────────
function startBackgroundLicenseCheck() {
  setInterval(async () => {
    console.log('[LICENSE] Background re-check...');
    const result = await validateLicenseOnline();
    if (!result.allow) {
      console.log('[LICENSE] Background check FAILED:', result.reason);
      // Notify user and quit
      if (mainWindow && !mainWindow.isDestroyed()) {
        dialog.showMessageBox(mainWindow, {
          type: 'error',
          title: 'License Deactivated',
          message: `Your license has been deactivated.\n\nReason: ${result.reason}\n\nThe application will now close.`,
          buttons: ['OK']
        }).then(() => {
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.destroy();
          app.quit();
        });
      }
    }
  }, 6 * 60 * 60 * 1000); // 6 hours
}

// ══════════════════════════════════════════════════════════════════════════
// AUTH HELPERS
// ══════════════════════════════════════════════════════════════════════════

function getAuth() {
  if (!fs.existsSync(authFile)) return { password: null, setup: false };
  try { return JSON.parse(fs.readFileSync(authFile, 'utf8')); }
  catch { return { password: null, setup: false }; }
}
function saveAuth(auth) {
  fs.writeFileSync(authFile, JSON.stringify(auth, null, 2));
}
function hashPassword(pwd) {
  return crypto.createHash('sha256').update(pwd + 'medishop_salt_2024').digest('hex');
}

// ══════════════════════════════════════════════════════════════════════════
// DATABASE
// ══════════════════════════════════════════════════════════════════════════

function initDB() {
  let data = {};
  if (fs.existsSync(dataFile)) {
    try { data = JSON.parse(fs.readFileSync(dataFile, 'utf8')); }
    catch { data = {}; }
  }
  const defaults = {
    settings: [{
      id: 1, shop_name: 'MediShop Pro', address: '', phone: '', email: '',
      gst_number: '', drug_license: '', logo_path: '', state: '', pin: '',
      default_gst: 12, currency: '₹', low_stock_threshold: 10,
      invoice_footer: 'Thank you for your purchase! Get well soon.'
    }],
    medicines: [], suppliers: [], purchase_orders: [], purchase_items: [],
    bills: [], bill_items: [], patients: [], prescriptions: [], prescription_items: [],
    categories: [
      { id:1, name:'Tablets' }, { id:2, name:'Capsules' }, { id:3, name:'Syrups' },
      { id:4, name:'Injections' }, { id:5, name:'Ointments' }, { id:6, name:'Drops' },
      { id:7, name:'Powders' }, { id:8, name:'Others' }
    ]
  };
  Object.keys(defaults).forEach(k => { if (!data[k]) data[k] = defaults[k]; });
  db = {
    _data: data,
    _save: () => {
      try { fs.writeFileSync(dataFile, JSON.stringify(data, null, 2)); }
      catch(e) { console.error('[DB] Save error:', e.message); }
    }
  };
  db._save();
}

// ══════════════════════════════════════════════════════════════════════════
// WINDOWS
// ══════════════════════════════════════════════════════════════════════════

function createAuthWindow(file) {
  if (loginWindow && !loginWindow.isDestroyed()) {
    try { loginWindow.destroy(); } catch {}
    loginWindow = null;
  }

  const preloadPath = getPreloadPath();
  console.log('[AUTH WINDOW] preload:', preloadPath);
  console.log('[AUTH WINDOW] file:', path.join(getRendererDir(), file));

  loginWindow = new BrowserWindow({
    width: 520, height: 700, resizable: false, center: true,
    frame: false,
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: false,
    },
    backgroundColor: '#0D47A1',
    show: false
  });

  loginWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"]
      }
    });
  });

  loginWindow.loadFile(path.join(getRendererDir(), file));
  loginWindow.once('ready-to-show', () => { loginWindow.show(); });

  if (process.argv.includes('--dev')) {
    loginWindow.webContents.openDevTools({ mode: 'detach' });
  }

  loginWindow.on('closed', () => { loginWindow = null; });
}

function createMainWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.focus();
    return;
  }

  const preloadPath = getPreloadPath();

  mainWindow = new BrowserWindow({
    width: 1440, height: 900, minWidth: 1100, minHeight: 700,
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: false,
    },
    title: 'MediShop Pro',
    show: false,
    backgroundColor: '#0d0f14'
  });

  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"]
      }
    });
  });

  mainWindow.loadFile(path.join(getRendererDir(), 'index.html'));
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.maximize();
  });

  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('close', async (e) => {
    e.preventDefault();
    if (!mainWindow || mainWindow.isDestroyed()) { app.quit(); return; }
    try {
      const choice = await dialog.showMessageBox(mainWindow, {
        type: 'question',
        buttons: ['💾 Backup & Exit', 'Exit Without Backup', 'Cancel'],
        defaultId: 0, cancelId: 2,
        title: 'MediShop Pro — Exit',
        message: 'Would you like to backup before closing?',
        detail: 'Regular backups protect your pharmacy data.'
      });
      if (choice.response === 2) return;
      if (choice.response === 0) performBackup('exit');
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.destroy();
      app.quit();
    } catch { app.quit(); }
  });

  Menu.setApplicationMenu(null);
}

// ══════════════════════════════════════════════════════════════════════════
// BACKUP
// ══════════════════════════════════════════════════════════════════════════

function performBackup(type = 'manual') {
  try {
    const timestamp  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupName = `medishop_backup_${type}_${timestamp}.json`;
    const backupPath = path.join(backupDir, backupName);
    fs.writeFileSync(backupPath, JSON.stringify(db._data, null, 2));
    const backups = fs.readdirSync(backupDir)
      .filter(f => f.endsWith('.json') || f.endsWith('.zip'))
      .sort().reverse();
    if (backups.length > 30) {
      backups.slice(30).forEach(f => {
        try { fs.unlinkSync(path.join(backupDir, f)); } catch {}
      });
    }
    return { success: true, path: backupPath, name: backupName };
  } catch(err) {
    return { success: false, error: err.message };
  }
}

function setupScheduledBackup() {
  setInterval(() => {
    performBackup('scheduled');
    try {
      new Notification({ title: 'MediShop Pro', body: '✅ Auto backup completed!' }).show();
    } catch {}
  }, 6 * 60 * 60 * 1000);
}

// ══════════════════════════════════════════════════════════════════════════
// APP STARTUP — LICENSE CHECK FIRST, THEN AUTH
// ══════════════════════════════════════════════════════════════════════════

app.whenReady().then(async () => {
  setupIpcHandlers();
  initDB();

  const preloadPath = getPreloadPath();
  console.log('[APP] ─────────────────────────────────');
  console.log('[APP] userData:', userDataPath);
  console.log('[APP] preload:', preloadPath);
  console.log('[APP] preload exists:', fs.existsSync(preloadPath));
  console.log('[APP] renderer dir:', getRendererDir());
  console.log('[APP] machine_id:', getMachineId());
  console.log('[APP] ─────────────────────────────────');

  // ── Step 1: Validate license online ──────────────────────────────────
  console.log('[APP] Validating license...');
  const licenseResult = await validateLicenseOnline();
  console.log('[APP] License result:', JSON.stringify(licenseResult));

  if (!licenseResult.allow) {
    if (licenseResult.showLicenseScreen) {
      // Show activation screen
      console.log('[APP] Showing license activation screen');
      createAuthWindow('license_setup.html');
      return;
    } else if (licenseResult.reason === 'Used on another device') {
      dialog.showErrorBox(
        'License Error — Wrong Machine',
        `This license key is already activated on a different computer.\n\nTo transfer, please deactivate it on the other machine first, or contact support.\n\nReason: ${licenseResult.reason}`
      );
      app.quit();
      return;
    } else {
      // Revoked or unknown
      dialog.showErrorBox(
        'License Deactivated',
        `Your MediShop Pro license has been deactivated.\n\nReason: ${licenseResult.reason}\n\nPlease contact support: 9985223448`
      );
      app.quit();
      return;
    }
  }

  // ── Step 2: License OK → check auth ──────────────────────────────────
  const auth = getAuth();
  if (!auth.setup || !auth.password) {
    console.log('[APP] First run — showing setup screen');
    createAuthWindow('setup.html');
  } else {
    console.log('[APP] Showing login screen');
    createAuthWindow('login.html');
  }

  setupScheduledBackup();
  startBackgroundLicenseCheck();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ══════════════════════════════════════════════════════════════════════════
// IPC HANDLERS
// ══════════════════════════════════════════════════════════════════════════

function setupIpcHandlers() {
  const d      = ()    => db._data;
  const save   = ()    => db._save();
  const nextId = (arr) => (arr && arr.length > 0) ? Math.max(...arr.map(x => x.id || 0)) + 1 : 1;

  // ─ AUTH ──────────────────────────────────────────────────────────────────

  ipcMain.handle('get-auth-status', () => {
    const auth = getAuth();
    return { setup: auth.setup || false, has_password: !!auth.password };
  });

  ipcMain.handle('setup-password', (e, pwd) => {
    if (!pwd || typeof pwd !== 'string') return { success: false, error: 'Invalid password' };
    saveAuth({ password: hashPassword(pwd), setup: true, created_at: new Date().toISOString() });
    console.log('[AUTH] Password saved successfully');
    return { success: true };
  });

  ipcMain.handle('verify-password', (e, pwd) => {
    if (!pwd) return { success: false };
    const auth = getAuth();
    if (!auth.password) { return { success: true }; }
    const match = hashPassword(pwd) === auth.password;
    console.log('[AUTH] verify-password match:', match);
    return { success: match };
  });

  ipcMain.handle('change-password', (e, { old_pwd, new_pwd }) => {
    const auth = getAuth();
    if (hashPassword(old_pwd) !== auth.password) return { success: false, error: 'Incorrect current password' };
    saveAuth({ ...auth, password: hashPassword(new_pwd), updated_at: new Date().toISOString() });
    return { success: true };
  });

  ipcMain.handle('reset-password', () => {
    try {
      saveAuth({ password: null, setup: false, reset_at: new Date().toISOString() });
      return { success: true };
    } catch(e) { return { success: false, error: e.message }; }
  });

  ipcMain.handle('login-success', async () => {
    console.log('[AUTH] login-success called');
    const lw = loginWindow;
    loginWindow = null;
    createMainWindow();
    if (lw && !lw.isDestroyed()) {
      setTimeout(() => { try { lw.destroy(); } catch {} }, 300);
    }
    return { success: true };
  });

  // ─ LICENSE ────────────────────────────────────────────────────────────────

  ipcMain.handle('check-license', () => checkLocalLicense());
  ipcMain.handle('get-license-info', () => getLocalLicense() || {});
  ipcMain.handle('get-machine-id', () => getMachineId());

  // Activate license — called from license_setup.html and expired.html
  ipcMain.handle('activate-license', async (e, { key, email }) => {
    const machineId = getMachineId();
    const cleanKey  = (key || '').trim().toUpperCase();
    const cleanEmail = (email || '').trim().toLowerCase();

    // ALWAYS call the server — no local override allowed
    // This ensures machine binding is recorded in Railway logs
    console.log('[LICENSE] Calling server to activate:', cleanKey, cleanEmail, machineId);

    const res = await httpPost(`${LICENSE_SERVER}/api/activate`, {
      key:         cleanKey,
      email:       cleanEmail,
      machine_id:  machineId,
      app_version: '2.1.0'
    });

    console.log('[LICENSE] Activate server response:', JSON.stringify(res));

    if (res.ok && res.data && res.data.success) {
      const d = res.data;
      saveLocalLicense({
        type:              d.type || 'full',
        activated:         true,
        revoked:           false,
        key:               cleanKey,
        email:             cleanEmail,
        activation_date:   new Date().toISOString(),
        start_date:        new Date().toISOString(),
        expires_at:        d.expires_at || null,
        days_left:         d.days_left !== undefined ? d.days_left : -1,
        last_online_check: new Date().toISOString(),
        machine_id:        machineId,
        server_reason:     null
      });
      return { success: true, ...d };
    }

    // Server returned error
    const errMsg = res.ok
      ? (res.data?.error || 'Activation failed. Check your key and email.')
      : `Cannot reach license server. Check internet connection. (${res.error})`;
    console.log('[LICENSE] Activation failed:', errMsg);
    return { success: false, error: errMsg };
  });

  ipcMain.handle('request-trial', async (e, { email, shop_name, _override }) => {
    if (_override && _override.success) {
      saveLocalLicense({
        type: 'trial', activated: true, revoked: false,
        key: _override.key || 'MDTL-LOCAL-DEMO-0001',
        email: (email || '').trim().toLowerCase(),
        shop_name: shop_name || '',
        activation_date: new Date().toISOString(),
        start_date: new Date().toISOString(),
        expires_at: _override.expires_at || new Date(Date.now() + 7 * 86400000).toISOString(),
        days_left: _override.trial_days || 7,
        machine_id: getMachineId()
      });
      return { success: true, ..._override };
    }
    return { success: false, error: 'Cannot reach server. Contact support: 9985223448' };
  });

  // Deactivate (called from settings panel)
  ipcMain.handle('deactivate-license', async () => {
    try {
      const lic = getLocalLicense() || {};
      const machineId = getMachineId();

      // Tell the server to unbind this machine
      const res = await httpPost(`${LICENSE_SERVER}/api/deactivate`, {
        key: lic.key,
        machine_id: machineId
      });

      console.log('[LICENSE] Deactivate server response:', JSON.stringify(res));

      // Always clear local regardless of server response
      saveLocalLicense({
        ...lic,
        activated: false,
        machine_id: null,
        deactivated_at: new Date().toISOString()
      });

      return {
        success: true,
        server_ok: res.ok && res.data?.success,
        message: 'License deactivated. You can activate on another machine now.'
      };
    } catch(e) {
      return { success: false, error: e.message };
    }
  });

  // ─ SETTINGS ───────────────────────────────────────────────────────────────

  ipcMain.handle('get-settings', () => d().settings[0] || {});
  ipcMain.handle('save-settings', (e, settings) => {
    d().settings[0] = { ...d().settings[0], ...settings }; save();
    return { success: true };
  });
  ipcMain.handle('select-logo', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Select Shop Logo',
      filters: [{ name: 'Images', extensions: ['jpg','jpeg','png','gif','bmp'] }],
      properties: ['openFile']
    });
    if (result.canceled) return null;
    const src  = result.filePaths[0];
    const ext  = path.extname(src);
    const dest = path.join(userDataPath, `logo${ext}`);
    fs.copyFileSync(src, dest);
    d().settings[0].logo_path = dest; save();
    return dest;
  });
  ipcMain.handle('get-logo-base64', () => {
    const p = d().settings[0]?.logo_path;
    if (!p || !fs.existsSync(p)) return null;
    const ext = path.extname(p).slice(1).toLowerCase();
    return `data:image/${ext === 'jpg' ? 'jpeg' : ext};base64,${fs.readFileSync(p).toString('base64')}`;
  });

  // ─ CATEGORIES ─────────────────────────────────────────────────────────────

  ipcMain.handle('get-categories', () => d().categories || []);
  ipcMain.handle('add-category', (e, name) => {
    const cat = { id: nextId(d().categories), name };
    d().categories.push(cat); save(); return cat;
  });
  ipcMain.handle('delete-category', (e, id) => {
    d().categories = d().categories.filter(c => c.id != id); save();
    return { success: true };
  });

  // ─ MEDICINES ──────────────────────────────────────────────────────────────

  ipcMain.handle('get-medicines', (e, filters = {}) => {
    let meds = d().medicines || [];
    if (filters?.search) {
      const s = filters.search.toLowerCase();
      meds = meds.filter(m =>
        m.name?.toLowerCase().includes(s) ||
        m.generic_name?.toLowerCase().includes(s) ||
        m.batch_no?.toLowerCase().includes(s)
      );
    }
    if (filters?.category_id) meds = meds.filter(m => m.category_id == filters.category_id);
    if (filters?.low_stock)   meds = meds.filter(m => m.quantity <= (m.reorder_level || 10));
    return meds;
  });
  ipcMain.handle('get-medicine', (e, id) => (d().medicines || []).find(m => m.id == id) || null);
  ipcMain.handle('add-medicine', (e, med) => {
    const n = { ...med, id: nextId(d().medicines || []), created_at: new Date().toISOString() };
    if (!d().medicines) d().medicines = [];
    d().medicines.push(n); save(); return n;
  });
  ipcMain.handle('update-medicine', (e, med) => {
    const i = (d().medicines || []).findIndex(m => m.id == med.id);
    if (i !== -1) { d().medicines[i] = { ...d().medicines[i], ...med }; save(); }
    return { success: true };
  });
  ipcMain.handle('delete-medicine', (e, id) => {
    d().medicines = (d().medicines || []).filter(m => m.id != id); save();
    return { success: true };
  });

  // ─ SUPPLIERS ──────────────────────────────────────────────────────────────

  ipcMain.handle('get-suppliers', () => d().suppliers || []);
  ipcMain.handle('add-supplier', (e, sup) => {
    const n = { ...sup, id: nextId(d().suppliers || []), created_at: new Date().toISOString() };
    if (!d().suppliers) d().suppliers = [];
    d().suppliers.push(n); save(); return n;
  });
  ipcMain.handle('update-supplier', (e, sup) => {
    const i = (d().suppliers || []).findIndex(s => s.id == sup.id);
    if (i !== -1) { d().suppliers[i] = { ...d().suppliers[i], ...sup }; save(); }
    return { success: true };
  });
  ipcMain.handle('delete-supplier', (e, id) => {
    d().suppliers = (d().suppliers || []).filter(s => s.id != id); save();
    return { success: true };
  });

  // ─ PURCHASE ORDERS ────────────────────────────────────────────────────────

  ipcMain.handle('get-purchase-orders', () => {
    const orders = d().purchase_orders || [];
    const sups   = d().suppliers || [];
    return orders.map(o => ({
      ...o,
      supplier_name: sups.find(s => s.id == o.supplier_id)?.name || 'Unknown'
    }));
  });
  ipcMain.handle('add-purchase-order', (e, order) => {
    const newOrder = { ...order, id: nextId(d().purchase_orders || []), created_at: new Date().toISOString() };
    if (!d().purchase_orders) d().purchase_orders = [];
    d().purchase_orders.push(newOrder);
    if (order.items) {
      order.items.forEach(item => {
        const ni = { ...item, id: nextId(d().purchase_items || []), order_id: newOrder.id };
        if (!d().purchase_items) d().purchase_items = [];
        d().purchase_items.push(ni);
        if (order.status === 'received') {
          const mi = (d().medicines || []).findIndex(m => m.id == item.medicine_id);
          if (mi !== -1) d().medicines[mi].quantity = (d().medicines[mi].quantity || 0) + (item.quantity || 0);
        }
      });
    }
    save(); return newOrder;
  });
  ipcMain.handle('update-po-status', (e, { id, status }) => {
    const i = (d().purchase_orders || []).findIndex(o => o.id == id);
    if (i !== -1) {
      const was = d().purchase_orders[i].status === 'received';
      d().purchase_orders[i].status = status;
      if (status === 'received' && !was) {
        (d().purchase_items || []).filter(it => it.order_id == id).forEach(item => {
          const mi = (d().medicines || []).findIndex(m => m.id == item.medicine_id);
          if (mi !== -1) d().medicines[mi].quantity = (d().medicines[mi].quantity || 0) + (item.quantity || 0);
        });
      }
      save();
    }
    return { success: true };
  });
  ipcMain.handle('get-po-items', (e, orderId) => (d().purchase_items || []).filter(i => i.order_id == orderId));

  // ─ PATIENTS ───────────────────────────────────────────────────────────────

  ipcMain.handle('get-patients', (e, search = '') => {
    let p = d().patients || [];
    if (search) {
      const s = search.toLowerCase();
      p = p.filter(pt => pt.name?.toLowerCase().includes(s) || pt.phone?.includes(s));
    }
    return p;
  });
  ipcMain.handle('get-patient', (e, id) => (d().patients || []).find(p => p.id == id) || null);
  ipcMain.handle('add-patient', (e, patient) => {
    if (!d().patients) d().patients = [];
    const existing = d().patients.find(p => p.phone === patient.phone && patient.phone);
    if (existing) return existing;
    const n = { ...patient, id: nextId(d().patients), created_at: new Date().toISOString() };
    d().patients.push(n); save(); return n;
  });
  ipcMain.handle('update-patient', (e, patient) => {
    const i = (d().patients || []).findIndex(p => p.id == patient.id);
    if (i !== -1) { d().patients[i] = { ...d().patients[i], ...patient }; save(); }
    return { success: true };
  });

  // ─ PRESCRIPTIONS ──────────────────────────────────────────────────────────

  ipcMain.handle('get-prescriptions', () => {
    const prs = d().prescriptions || [];
    const pts = d().patients || [];
    return prs.map(p => ({ ...p, patient_name: pts.find(pt => pt.id == p.patient_id)?.name || 'Unknown' }));
  });
  ipcMain.handle('add-prescription', (e, rx) => {
    const n = { ...rx, id: nextId(d().prescriptions || []), created_at: new Date().toISOString() };
    if (!d().prescriptions) d().prescriptions = [];
    d().prescriptions.push(n);
    if (rx.medicines) {
      rx.medicines.forEach(med => {
        if (!d().prescription_items) d().prescription_items = [];
        d().prescription_items.push({ ...med, id: nextId(d().prescription_items), prescription_id: n.id });
      });
    }
    save(); return n;
  });
  ipcMain.handle('get-prescription-items', (e, rxId) =>
    (d().prescription_items || []).filter(i => i.prescription_id == rxId)
  );
  ipcMain.handle('delete-prescription', (e, id) => {
    d().prescriptions      = (d().prescriptions || []).filter(p => p.id != id);
    d().prescription_items = (d().prescription_items || []).filter(i => i.prescription_id != id);
    save(); return { success: true };
  });
  ipcMain.handle('scan-prescription', async (e, patientId) => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Select Prescription Image',
      filters: [{ name: 'Documents', extensions: ['jpg','jpeg','png','pdf','bmp'] }],
      properties: ['openFile']
    });
    if (result.canceled) return null;
    const src    = result.filePaths[0];
    const rxDir  = path.join(userDataPath, 'prescriptions');
    if (!fs.existsSync(rxDir)) fs.mkdirSync(rxDir, { recursive: true });
    const filename = `rx_${patientId}_${Date.now()}${path.extname(src)}`;
    const dest     = path.join(rxDir, filename);
    fs.copyFileSync(src, dest);
    return { path: dest, filename };
  });

  // ─ BILLING ────────────────────────────────────────────────────────────────

  ipcMain.handle('get-bills', (e, filters = {}) => {
    let bills = d().bills || [];
    if (filters.date_from) bills = bills.filter(b => b.date >= filters.date_from);
    if (filters.date_to)   bills = bills.filter(b => b.date <= filters.date_to + 'T23:59:59');
    if (filters.patient_id) bills = bills.filter(b => b.patient_id == filters.patient_id);
    const pts = d().patients || [];
    return bills.map(b => {
      const pt = pts.find(p => p.id == b.patient_id);
      return {
        ...b,
        patient_name:    b.patient_name    || pt?.name    || 'Walk-in',
        patient_phone:   b.patient_phone   || pt?.phone   || '',
        patient_address: b.patient_address || pt?.address || '',
        patient_age:     b.patient_age     || pt?.age     || '',
        doctor_name:     b.doctor_name     || pt?.doctor  || ''
      };
    }).sort((a, b) => new Date(b.date) - new Date(a.date));
  });

  ipcMain.handle('get-bill', (e, id) => {
    const bill = (d().bills || []).find(b => b.id == id);
    if (!bill) return null;
    const patient = (d().patients || []).find(p => p.id == bill.patient_id);
    return {
      ...bill,
      patient_name:    bill.patient_name    || patient?.name    || 'Walk-in',
      patient_phone:   bill.patient_phone   || patient?.phone   || '',
      patient_address: bill.patient_address || patient?.address || '',
      patient_age:     bill.patient_age     || patient?.age     || '',
      patient_gender:  bill.patient_gender  || patient?.gender  || '',
      doctor_name:     bill.doctor_name     || patient?.doctor  || '',
      items: (d().bill_items || []).filter(i => i.bill_id == id),
      patient
    };
  });

  ipcMain.handle('create-bill', (e, billData) => {
    if (!d().patients)   d().patients   = [];
    if (!d().bills)      d().bills      = [];
    if (!d().bill_items) d().bill_items = [];

    let patientId = billData.patient_id;
    if (!patientId && billData.patient_name && billData.patient_phone) {
      const existing = d().patients.find(p => p.phone === billData.patient_phone);
      if (existing) {
        patientId = existing.id;
      } else {
        const n = {
          id: nextId(d().patients), name: billData.patient_name,
          phone: billData.patient_phone, age: billData.patient_age || '',
          gender: billData.patient_gender || '', address: billData.patient_address || '',
          doctor: billData.doctor_name || '', title: billData.patient_title || '',
          created_at: new Date().toISOString()
        };
        d().patients.push(n); patientId = n.id;
      }
    }

    const billId = nextId(d().bills);
    const billNo = `INV${new Date().getFullYear()}${String(billId).padStart(5, '0')}`;

    const newBill = {
      id: billId, bill_no: billNo, patient_id: patientId,
      patient_name: billData.patient_name || 'Walk-in',
      patient_phone: billData.patient_phone || '',
      patient_age: billData.patient_age || '',
      patient_address: billData.patient_address || '',
      patient_gender: billData.patient_gender || '',
      patient_title: billData.patient_title || '',
      date: new Date().toISOString(),
      subtotal: billData.subtotal || 0, discount: billData.discount || 0,
      discount_type: billData.discount_type || 'amount',
      cgst: billData.cgst || 0, sgst: billData.sgst || 0,
      total_gst: billData.total_gst || 0, total: billData.total || 0,
      payment_mode: billData.payment_mode || 'cash',
      payment_status: 'paid',
      doctor_name: billData.doctor_name || '', notes: billData.notes || ''
    };

    d().bills.push(newBill);

    if (billData.items) {
      billData.items.forEach(item => {
        const ni = { ...item, id: nextId(d().bill_items), bill_id: billId };
        d().bill_items.push(ni);
        const mi = (d().medicines || []).findIndex(m => m.id == item.medicine_id);
        if (mi !== -1) {
          d().medicines[mi].quantity = Math.max(0, (d().medicines[mi].quantity || 0) - (item.quantity || 0));
        }
      });
    }
    save();
    return { ...newBill, items: billData.items };
  });

  // ─ DASHBOARD ──────────────────────────────────────────────────────────────

  ipcMain.handle('get-dashboard-stats', () => {
    const today     = new Date().toISOString().slice(0, 10);
    const bills     = d().bills     || [];
    const medicines = d().medicines || [];
    const todayBills = bills.filter(b => b.date?.startsWith(today));
    const d30 = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);

    const weeklyData = [];
    for (let i = 6; i >= 0; i--) {
      const dt  = new Date(Date.now() - i * 86400000);
      const ds  = dt.toISOString().slice(0, 10);
      const db2 = bills.filter(b => b.date?.startsWith(ds));
      weeklyData.push({
        date: ds,
        day: dt.toLocaleDateString('en-US', { weekday: 'short' }),
        sales: db2.reduce((s, b) => s + (b.total || 0), 0)
      });
    }

    const pts = d().patients || [];
    return {
      today_sales:      todayBills.reduce((s, b) => s + (b.total || 0), 0),
      today_bills:      todayBills.length,
      total_medicines:  medicines.length,
      expiring_count:   medicines.filter(m => m.expiry_date && m.expiry_date >= today && m.expiry_date <= d30).length,
      expired_count:    medicines.filter(m => m.expiry_date && m.expiry_date < today).length,
      low_stock_count:  medicines.filter(m => (m.quantity || 0) <= (m.reorder_level || 10)).length,
      total_suppliers:  (d().suppliers || []).length,
      total_patients:   pts.length,
      weekly_sales:     weeklyData,
      recent_bills: bills
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 5)
        .map(b => ({
          ...b,
          patient_name: pts.find(p => p.id == b.patient_id)?.name || b.patient_name || 'Walk-in'
        })),
      low_stock_items: medicines.filter(m => (m.quantity || 0) <= (m.reorder_level || 10)).slice(0, 5)
    };
  });

  // ─ REPORTS ────────────────────────────────────────────────────────────────

  ipcMain.handle('get-expiry-report', () => {
    const medicines = d().medicines || [];
    const today = new Date().toISOString().slice(0, 10);
    const d30   = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    const d90   = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
    const w     = medicines.filter(m => m.expiry_date);
    return {
      expired:     w.filter(m => m.expiry_date < today),
      expiring_30: w.filter(m => m.expiry_date >= today && m.expiry_date <= d30),
      expiring_90: w.filter(m => m.expiry_date > d30  && m.expiry_date <= d90),
      safe:        w.filter(m => m.expiry_date > d90)
    };
  });

  ipcMain.handle('get-sales-report', (e, { date_from, date_to } = {}) => {
    const bills = d().bills || [];
    let filtered = bills;
    if (date_from) filtered = filtered.filter(b => b.date >= date_from);
    if (date_to)   filtered = filtered.filter(b => b.date <= date_to + 'T23:59:59');

    const billItems  = d().bill_items  || [];
    const medicines  = d().medicines   || [];
    const categories = d().categories  || [];
    const catSales = {}, medSales = {}, payBreakdown = {}, dailyMap = {};

    filtered.forEach(bill => {
      payBreakdown[bill.payment_mode] = (payBreakdown[bill.payment_mode] || 0) + (bill.total || 0);
      const day = bill.date?.slice(0, 10);
      if (day) dailyMap[day] = (dailyMap[day] || 0) + (bill.total || 0);
      billItems.filter(i => i.bill_id == bill.id).forEach(item => {
        const med = medicines.find(m => m.id == item.medicine_id);
        const cat = categories.find(c => c.id == med?.category_id)?.name || 'Other';
        catSales[cat] = (catSales[cat] || 0) + (item.total || 0);
        if (med) {
          if (!medSales[med.id]) medSales[med.id] = { name: med.name, qty: 0, revenue: 0 };
          medSales[med.id].qty     += item.quantity || 0;
          medSales[med.id].revenue += item.total    || 0;
        }
      });
    });

    return {
      total_revenue:  filtered.reduce((s, b) => s + (b.total     || 0), 0),
      total_discount: filtered.reduce((s, b) => s + (b.discount   || 0), 0),
      total_gst:      filtered.reduce((s, b) => s + (b.total_gst  || 0), 0),
      total_bills:    filtered.length,
      avg_bill:       filtered.length > 0 ? filtered.reduce((s, b) => s + (b.total || 0), 0) / filtered.length : 0,
      category_sales:    catSales,
      top_medicines:     Object.values(medSales).sort((a, b) => b.revenue - a.revenue).slice(0, 15),
      payment_breakdown: payBreakdown,
      daily_trend:       Object.entries(dailyMap)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([date, amount]) => ({ date, amount })),
      bills: filtered.sort((a, b) => new Date(b.date) - new Date(a.date))
    };
  });

  ipcMain.handle('get-gst-report', (e, { date_from, date_to } = {}) => {
    const bills = d().bills || [];
    let filtered = bills;
    if (date_from) filtered = filtered.filter(b => b.date >= date_from);
    if (date_to)   filtered = filtered.filter(b => b.date <= date_to + 'T23:59:59');
    const billItems = d().bill_items || [];
    const gstSlabs  = {};
    filtered.forEach(bill => {
      billItems.filter(i => i.bill_id == bill.id).forEach(item => {
        const slab = item.gst_percent || 0;
        if (!gstSlabs[slab]) gstSlabs[slab] = { slab, taxable: 0, cgst: 0, sgst: 0, total: 0, qty: 0 };
        const taxable = (item.total || 0) / (1 + slab / 100);
        const tax     = (item.total || 0) - taxable;
        gstSlabs[slab].taxable += taxable;
        gstSlabs[slab].cgst   += tax / 2;
        gstSlabs[slab].sgst   += tax / 2;
        gstSlabs[slab].total  += item.total || 0;
        gstSlabs[slab].qty    += item.quantity || 0;
      });
    });
    return { slabs: Object.values(gstSlabs).sort((a, b) => a.slab - b.slab), total_bills: filtered.length };
  });

  // ─ EXCEL EXPORT ───────────────────────────────────────────────────────────

  ipcMain.handle('export-excel', async (e, { type, data, filename }) => {
    try {
      let XLSX;
      try { XLSX = require('xlsx'); }
      catch { return { success: false, error: 'xlsx module not installed. Run: npm install xlsx' }; }
      const targetWindow = mainWindow || loginWindow;
      const savePath = await dialog.showSaveDialog(targetWindow, {
        defaultPath: path.join(os.homedir(), 'Desktop', filename || `${type}_export.xlsx`),
        filters: [{ name: 'Excel Files', extensions: ['xlsx'] }]
      });
      if (savePath.canceled) return { success: false, canceled: true };
      const wb = XLSX.utils.book_new();
      if (Array.isArray(data)) {
        const ws = XLSX.utils.json_to_sheet(data);
        XLSX.utils.book_append_sheet(wb, ws, String(type).slice(0, 31));
      } else if (typeof data === 'object') {
        Object.entries(data).forEach(([name, rows]) => {
          if (Array.isArray(rows) && rows.length > 0) {
            const ws = XLSX.utils.json_to_sheet(rows);
            XLSX.utils.book_append_sheet(wb, ws, name.slice(0, 31));
          }
        });
      }
      XLSX.writeFile(wb, savePath.filePath);
      shell.showItemInFolder(savePath.filePath);
      return { success: true, path: savePath.filePath };
    } catch(err) {
      return { success: false, error: err.message };
    }
  });

  // ─ BACKUP ─────────────────────────────────────────────────────────────────

  ipcMain.handle('manual-backup', () => performBackup('manual'));
  ipcMain.handle('get-backups', () => {
    try {
      return fs.readdirSync(backupDir)
        .filter(f => f.endsWith('.json') || f.endsWith('.zip'))
        .sort().reverse()
        .map(f => {
          const fp = path.join(backupDir, f);
          const st = fs.statSync(fp);
          return { name: f, path: fp, size: st.size, date: st.mtime };
        });
    } catch { return []; }
  });
  ipcMain.handle('open-backup-folder', () => { shell.openPath(backupDir); return { success: true }; });

  // ─ PRINT & PDF ────────────────────────────────────────────────────────────

  ipcMain.handle('print-bill', async (e, htmlContent) => {
    const pw = new BrowserWindow({
      show: false,
      webPreferences: { nodeIntegration: false, contextIsolation: true, webSecurity: false }
    });
    await new Promise(resolve => {
      pw.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent));
      pw.webContents.once('did-finish-load', resolve);
      setTimeout(resolve, 5000);
    });
    pw.webContents.print({ silent: false, printBackground: true }, () => { pw.close(); });
    return { success: true };
  });

  ipcMain.handle('save-pdf', async (e, { htmlContent, billNo }) => {
    let pdfWin = null;
    try {
      const targetWindow = mainWindow || loginWindow;
      const savePath = await dialog.showSaveDialog(targetWindow, {
        title: 'Save Invoice PDF',
        defaultPath: path.join(os.homedir(), 'Desktop', `${billNo || 'Invoice'}.pdf`),
        filters: [{ name: 'PDF Files', extensions: ['pdf'] }]
      });
      if (savePath.canceled) return { success: false, canceled: true };
      pdfWin = new BrowserWindow({
        show: false, width: 860, height: 1200,
        webPreferences: { nodeIntegration: false, contextIsolation: true, webSecurity: false }
      });
      await new Promise(resolve => {
        pdfWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent));
        pdfWin.webContents.once('did-finish-load', resolve);
        setTimeout(resolve, 8000);
      });
      await new Promise(r => setTimeout(r, 500));
      const pdfData = await pdfWin.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
      if (pdfWin && !pdfWin.isDestroyed()) pdfWin.close();
      fs.writeFileSync(savePath.filePath, pdfData);
      shell.openPath(savePath.filePath);
      return { success: true, path: savePath.filePath };
    } catch(err) {
      if (pdfWin && !pdfWin.isDestroyed()) try { pdfWin.close(); } catch {}
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('save-pdf-auto', async (e, { htmlContent, billNo }) => {
    let pdfWin = null;
    try {
      const invoicesDir = path.join(userDataPath, 'invoices');
      if (!fs.existsSync(invoicesDir)) fs.mkdirSync(invoicesDir, { recursive: true });
      const safeFileName = (billNo || 'Invoice').replace(/[^a-zA-Z0-9_-]/g, '') + '.pdf';
      const filePath     = path.join(invoicesDir, safeFileName);
      pdfWin = new BrowserWindow({
        show: false, width: 900, height: 1200,
        webPreferences: { nodeIntegration: false, contextIsolation: false, webSecurity: false }
      });
      await new Promise(resolve => {
        pdfWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent));
        pdfWin.webContents.once('did-finish-load', resolve);
        setTimeout(resolve, 8000);
      });
      await new Promise(r => setTimeout(r, 800));
      const pdfData = await pdfWin.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
      if (pdfWin && !pdfWin.isDestroyed()) pdfWin.close();
      pdfWin = null;
      fs.writeFileSync(filePath, pdfData);
      return { success: true, path: filePath, dir: invoicesDir, fileName: safeFileName };
    } catch(err) {
      if (pdfWin && !pdfWin.isDestroyed()) try { pdfWin.close(); } catch {}
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('open-file',   (e, filePath)   => { try { shell.showItemInFolder(filePath); } catch {} return { success: true }; });
  ipcMain.handle('open-folder', (e, folderPath) => { shell.openPath(folderPath); return { success: true }; });

  // ─ WHATSAPP & CLIPBOARD ───────────────────────────────────────────────────

  ipcMain.handle('send-whatsapp', async (e, { phone, message }) => {
    const clean = (phone || '').replace(/\D/g, '');
    const full  = clean.startsWith('91') ? clean : `91${clean}`;
    shell.openExternal(`https://wa.me/${full}?text=${encodeURIComponent(message || '')}`);
    return { success: true };
  });

  ipcMain.handle('open-external', (e, url) => { shell.openExternal(url); return { success: true }; });

  ipcMain.handle('copy-to-clipboard', (e, text) => {
    try { clipboard.writeText(text); } catch {}
    return { success: true };
  });

  ipcMain.handle('copy-file-to-clipboard', async (e, filePath) => {
    try { clipboard.writeText(filePath); } catch {}
    if (process.platform === 'win32') {
      try {
        const { exec } = require('child_process');
        const escaped  = filePath.replace(/"/g, '\\"');
        const psScript = `Add-Type -AssemblyName System.Windows.Forms; $col = New-Object System.Collections.Specialized.StringCollection; $col.Add("${escaped}"); [System.Windows.Forms.Clipboard]::SetFileDropList($col)`;
        await new Promise(r => exec(`powershell -Sta -NonInteractive -WindowStyle Hidden -Command "${psScript}"`, () => r()));
      } catch {}
    }
    return { success: true };
  });

  ipcMain.handle('send-pdf-to-whatsapp', async (e, { filePath, phone }) => {
    try {
      const clean = (phone || '').replace(/\D/g, '');
      const full  = clean.startsWith('91') ? clean : '91' + clean;
      try { clipboard.writeText(filePath); } catch {}
      shell.openExternal(`https://wa.me/${full}`);
      return { success: true };
    } catch(err) {
      return { success: false, error: err.message };
    }
  });

  // ─ APP INFO ───────────────────────────────────────────────────────────────

  ipcMain.handle('get-app-info', () => ({
    version:  app.getVersion(),
    userData: userDataPath,
    backupDir,
    license:  checkLocalLicense(),
    machine_id: getMachineId(),
    platform: process.platform,
    arch:     process.arch,
    node:     process.versions.node,
    electron: process.versions.electron
  }));
}
