/**
 * license-client.js  —  Medishop Pharmacy Billing (Electron)
 *
 * DROP THIS FILE into your Electron app root folder.
 *
 * FIX 1: Saves token + deviceId to disk (license.json in app data folder)
 *         so the license check on startup is a silent background ping,
 *         NOT a full activation screen.
 *
 * FIX 2: Shows days remaining on the main window title bar / status bar.
 *
 * FIX 3: Adds a "Deactivate License" menu option in Help menu.
 *
 * USAGE in main.js:
 *   const LicenseClient = require('./license-client');
 *   const license = new LicenseClient();
 *
 *   app.whenReady().then(async () => {
 *     const ok = await license.checkOnStartup(mainWindow);
 *     if (!ok) app.quit();
 *   });
 */

const { app, dialog, BrowserWindow, ipcMain, Menu } = require('electron');
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────
//  CONFIGURE THESE TWO LINES
// ─────────────────────────────────────────────────────────────
const LICENSE_SERVER = process.env.LICENSE_SERVER || 'http://localhost:8080';
const APP_VERSION    = require('./package.json').version || '1.0.0';
// ─────────────────────────────────────────────────────────────

class LicenseClient {
  constructor() {
    // Store license data in OS app-data folder so it survives app updates
    const dataDir = path.join(app.getPath('userData'), 'medishop-license');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    this.licenseFile = path.join(dataDir, 'license.json');
    this.deviceId    = this._getOrCreateDeviceId(dataDir);
    this.deviceName  = os.hostname() || 'Medishop-PC';
    this.data        = null; // loaded from disk
  }

  // ── Persistent device ID ─────────────────────────────────
  _getOrCreateDeviceId(dataDir) {
    const idFile = path.join(dataDir, 'device.id');
    if (fs.existsSync(idFile)) {
      const id = fs.readFileSync(idFile, 'utf8').trim();
      if (id && id.length > 8) return id;
    }
    // Generate a stable device fingerprint
    const fp = crypto.createHash('sha256')
      .update(os.hostname() + os.platform() + os.arch() + app.getPath('userData'))
      .digest('hex');
    fs.writeFileSync(idFile, fp);
    return fp;
  }

  // ── Load saved license from disk ─────────────────────────
  _load() {
    try {
      if (fs.existsSync(this.licenseFile)) {
        this.data = JSON.parse(fs.readFileSync(this.licenseFile, 'utf8'));
        return true;
      }
    } catch(e) { console.error('[License] Load error:', e.message); }
    this.data = null;
    return false;
  }

  // ── Save license to disk ──────────────────────────────────
  _save(data) {
    try {
      this.data = data;
      fs.writeFileSync(this.licenseFile, JSON.stringify(data, null, 2));
    } catch(e) { console.error('[License] Save error:', e.message); }
  }

  // ── Clear saved license (deactivate) ─────────────────────
  _clear() {
    try {
      if (fs.existsSync(this.licenseFile)) fs.unlinkSync(this.licenseFile);
      this.data = null;
    } catch(e) {}
  }

  // ── HTTP helper ───────────────────────────────────────────
  _request(endpoint, body) {
    return new Promise((resolve, reject) => {
      const url     = new URL(LICENSE_SERVER + endpoint);
      const payload = JSON.stringify(body);
      const lib     = url.protocol === 'https:' ? https : http;
      const opts = {
        hostname: url.hostname,
        port:     url.port || (url.protocol === 'https:' ? 443 : 80),
        path:     url.pathname,
        method:   'POST',
        headers:  {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 10000
      };
      const req = lib.request(opts, res => {
        let raw = '';
        res.on('data', d => raw += d);
        res.on('end', () => {
          try { resolve(JSON.parse(raw)); }
          catch(e) { reject(new Error('Invalid server response')); }
        });
      });
      req.on('error',   err => reject(err));
      req.on('timeout', ()  => { req.destroy(); reject(new Error('Connection timed out')); });
      req.write(payload);
      req.end();
    });
  }

  // ── Silent background validate (on every startup) ─────────
  async _validate() {
    if (!this.data || !this.data.token) return { valid: false, reason: 'no_token' };
    try {
      const r = await this._request('/api/validate', {
        token:    this.data.token,
        deviceId: this.deviceId
      });
      if (r.success) {
        // Update days left in saved data
        this._save({ ...this.data, daysLeft: r.daysLeft, lastValidated: Date.now() });
        return { valid: true, data: r };
      }
      return { valid: false, reason: r.error || 'server_rejected' };
    } catch(e) {
      // Network error — use grace period (allow offline use for 48h)
      const lastValidated = this.data.lastValidated || 0;
      const hoursSince    = (Date.now() - lastValidated) / 3600000;
      if (hoursSince < 48) {
        console.warn('[License] Server unreachable, using grace period');
        return { valid: true, offline: true, data: this.data };
      }
      return { valid: false, reason: 'offline_too_long' };
    }
  }

  // ── Activate with key + email ─────────────────────────────
  async activate(licenseKey, email) {
    const r = await this._request('/api/activate', {
      licenseKey,
      email,
      deviceId:   this.deviceId,
      deviceName: this.deviceName,
      appVersion: APP_VERSION
    });
    if (r.success) {
      this._save({
        token:         r.token,
        type:          r.type,
        email:         r.email,
        daysLeft:      r.daysLeft,
        activatedAt:   r.activatedAt || Date.now(),
        lastValidated: Date.now()
      });
    }
    return r;
  }

  // ── Deactivate (remove from this device) ─────────────────
  async deactivate() {
    if (!this.data || !this.data.token) {
      this._clear();
      return { success: true };
    }
    try {
      const r = await this._request('/api/deactivate', {
        token:    this.data.token,
        deviceId: this.deviceId
      });
      this._clear();
      return r;
    } catch(e) {
      // Even if server fails, clear locally
      this._clear();
      return { success: true, message: 'Deactivated locally.' };
    }
  }

  // ── Update window title with license info ─────────────────
  _updateWindowTitle(win, licenseData) {
    if (!win || win.isDestroyed()) return;
    const d = licenseData || this.data;
    if (!d) return;
    let suffix = '';
    if (d.type === 'trial' && d.daysLeft != null) {
      suffix = ` — Trial: ${d.daysLeft} day(s) left`;
    } else if (d.type === 'full') {
      suffix = ' — Licensed';
    }
    const current = win.getTitle().replace(/ — (Trial|Licensed)[^)]*$/, '');
    win.setTitle(current + suffix);
  }

  // ── Build Help menu with license info + deactivate ────────
  buildLicenseMenu(win) {
    const d = this.data;
    const licenseInfo = d ? [
      { label: `License: ${d.type === 'full' ? 'Full (Permanent)' : `Trial — ${d.daysLeft ?? '?'} day(s) left`}`, enabled: false },
      { label: `Registered to: ${d.email}`, enabled: false },
      { type: 'separator' },
      {
        label: '🔄 Deactivate License (Transfer to new PC)',
        click: async () => {
          const choice = dialog.showMessageBoxSync(win, {
            type:    'warning',
            title:   'Deactivate License',
            message: 'Deactivate license on this computer?',
            detail:  'You can activate it on another computer afterwards.\n\nThis will close Medishop.',
            buttons: ['Cancel', 'Deactivate'],
            defaultId: 0,
            cancelId:  0
          });
          if (choice === 1) {
            await this.deactivate();
            dialog.showMessageBoxSync(win, {
              type:    'info',
              title:   'Deactivated',
              message: 'License deactivated from this computer.',
              detail:  'You can now activate it on another PC.\nMedishop will now close.',
              buttons: ['OK']
            });
            app.quit();
          }
        }
      }
    ] : [
      { label: 'Not activated', enabled: false }
    ];

    return licenseInfo;
  }

  // ══════════════════════════════════════════════════════════
  //  MAIN ENTRY POINT — call this in app.whenReady()
  // ══════════════════════════════════════════════════════════
  async checkOnStartup(mainWindow) {
    this._load();

    // If we have a saved token, try silent background validation
    if (this.data && this.data.token) {
      const result = await this._validate();
      if (result.valid) {
        console.log(`[License] ✅ Valid ${this.data.type} license for ${this.data.email}`);
        this._updateWindowTitle(mainWindow, result.data);
        this._buildMenu(mainWindow);
        return true;
      }
      // Token invalid — clear and show activation screen
      if (result.reason !== 'offline_too_long') {
        console.warn('[License] Token rejected, clearing saved license');
        this._clear();
      }
    }

    // Show activation dialog
    const activated = await this._showActivationWindow(mainWindow);
    if (activated) {
      this._updateWindowTitle(mainWindow, this.data);
      this._buildMenu(mainWindow);
    }
    return activated;
  }

  // ── Activation window (shown only when no valid token) ────
  _showActivationWindow(parentWindow) {
    return new Promise((resolve) => {
      const win = new BrowserWindow({
        width:          480,
        height:         520,
        resizable:      false,
        frame:          true,
        title:          'Medishop — Activate License',
        parent:         parentWindow,
        modal:          true,
        webPreferences: { nodeIntegration: true, contextIsolation: false }
      });

      win.setMenu(null);
      win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(this._activationHTML()));

      // Listen for activation attempt from the window
      ipcMain.removeAllListeners('ms-activate');
      ipcMain.removeAllListeners('ms-cancel');

      ipcMain.once('ms-activate', async (event, { licenseKey, email }) => {
        win.webContents.send('ms-activating');
        try {
          const r = await this.activate(licenseKey, email);
          if (r.success) {
            win.webContents.send('ms-result', { success: true, message: r.message, daysLeft: r.daysLeft, type: r.type });
            setTimeout(() => { win.close(); resolve(true); }, 1800);
          } else {
            win.webContents.send('ms-result', { success: false, message: r.error });
          }
        } catch(e) {
          win.webContents.send('ms-result', { success: false, message: 'Could not reach license server. Check your internet connection.' });
        }
      });

      ipcMain.once('ms-cancel', () => {
        win.close();
        resolve(false);
      });

      win.on('closed', () => resolve(false));
    });
  }

  // ── Build app menu with license section ───────────────────
  _buildMenu(win) {
    const licenseMenuItems = this.buildLicenseMenu(win);
    const template = Menu.getApplicationMenu()?.items?.map(i => i) || [];

    // Add or replace Help menu
    const helpIdx = template.findIndex(m => m.label === 'Help' || m.role === 'help');
    const licenseMenu = {
      label: 'Help',
      submenu: [
        { label: '💊 About Medishop', click: () => this._showAbout(win) },
        { type: 'separator' },
        ...licenseMenuItems,
        { type: 'separator' },
        { label: 'support@medishop.in', click: () => require('electron').shell.openExternal('mailto:support@medishop.in') }
      ]
    };

    if (helpIdx >= 0) template[helpIdx] = licenseMenu;
    else template.push(licenseMenu);

    Menu.setApplicationMenu(Menu.buildFromTemplate(template));
  }

  _showAbout(win) {
    const d = this.data;
    dialog.showMessageBox(win, {
      type:    'info',
      title:   'About Medishop',
      message: 'Medishop Pharmacy Billing',
      detail:  `Version: ${APP_VERSION}\n` +
               `License: ${d ? d.type.toUpperCase() : 'Not activated'}\n` +
               `Email: ${d ? d.email : '—'}\n` +
               `${d && d.type === 'trial' ? 'Days left: ' + (d.daysLeft ?? '?') + '\n' : ''}` +
               `\nSupport: support@medishop.in`,
      buttons: ['OK']
    });
  }

  // ── Activation window HTML ────────────────────────────────
  _activationHTML() {
    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d19;color:#e2eaf4;
    padding:32px 28px;min-height:100vh;display:flex;flex-direction:column;gap:0}
  h1{font-size:20px;font-weight:700;color:#00c9a7;margin-bottom:4px}
  p{font-size:13px;color:#6b8ab0;margin-bottom:24px}
  label{font-size:11px;font-weight:700;color:#6b8ab0;text-transform:uppercase;letter-spacing:.06em;display:block;margin-bottom:5px}
  input{width:100%;background:#0c1a2e;border:1.5px solid #1a3050;color:#e2eaf4;
    padding:11px 14px;border-radius:8px;font-size:14px;outline:none;margin-bottom:16px;font-family:inherit}
  input:focus{border-color:#00c9a7}
  #keyInput{font-family:monospace;letter-spacing:.08em;text-transform:uppercase}
  .btn{width:100%;padding:12px;border-radius:8px;border:none;cursor:pointer;
    font-size:14px;font-weight:700;margin-top:4px;transition:all .15s}
  .btn-primary{background:#00c9a7;color:#000}
  .btn-primary:hover{background:#00e6be}
  .btn-primary:disabled{opacity:.5;cursor:not-allowed}
  .btn-secondary{background:#0c1a2e;color:#6b8ab0;border:1px solid #1a3050;margin-top:8px}
  #msg{padding:10px 14px;border-radius:8px;font-size:13px;margin-top:12px;display:none;line-height:1.5}
  .ok{background:rgba(34,197,94,.1);border:1px solid #22c55e;color:#22c55e;display:block!important}
  .err{background:rgba(239,68,68,.1);border:1px solid #ef4444;color:#ef4444;display:block!important}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,201,167,.2);
    border-top-color:#00c9a7;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
  .brand-icon{font-size:40px;text-align:center;margin-bottom:16px}
  .server{font-size:10px;color:#1a3050;margin-top:20px;text-align:center}
</style>
</head>
<body>
<div class="brand-icon">💊</div>
<h1>Activate Medishop</h1>
<p>Enter your license key and registered email to activate.</p>

<label>License Key</label>
<input id="keyInput" type="text" placeholder="MEDSHP-FULL-XXXXXX-XXXXXX-XXXXXX"
  oninput="this.value=this.value.toUpperCase().replace(/[^A-Z0-9-]/g,'')"/>

<label>Registered Email</label>
<input id="emailInput" type="email" placeholder="pharmacy@example.com"/>

<button class="btn btn-primary" id="activateBtn" onclick="doActivate()">Activate Medishop</button>
<button class="btn btn-secondary" onclick="doCancel()">Cancel</button>

<div id="msg"></div>
<div class="server">License Server: ${LICENSE_SERVER}</div>

<script>
const { ipcRenderer } = require('electron');

ipcRenderer.on('ms-activating', () => {
  document.getElementById('activateBtn').disabled = true;
  document.getElementById('activateBtn').innerHTML = '<span class="spinner"></span>Verifying…';
  document.getElementById('msg').className = '';
  document.getElementById('msg').style.display = 'none';
});

ipcRenderer.on('ms-result', (e, r) => {
  const btn = document.getElementById('activateBtn');
  const msg = document.getElementById('msg');
  btn.disabled = false;
  btn.textContent = 'Activate Medishop';
  msg.textContent = r.message;
  if (r.success) {
    msg.className = 'ok';
    const extra = r.type === 'trial' ? ' (' + r.daysLeft + ' days remaining)' : '';
    msg.textContent = '✅ ' + r.message + extra;
  } else {
    msg.className = 'err';
    msg.textContent = '❌ ' + r.message;
  }
});

function doActivate() {
  const key   = document.getElementById('keyInput').value.trim();
  const email = document.getElementById('emailInput').value.trim();
  const msg   = document.getElementById('msg');

  if (!key || !email) {
    msg.className = 'err';
    msg.textContent = '❌ Please enter both license key and email.';
    return;
  }
  if (!key.startsWith('MEDSHP-')) {
    msg.className = 'err';
    msg.textContent = '❌ Invalid key format. Key must start with MEDSHP-';
    return;
  }

  ipcRenderer.send('ms-activate', { licenseKey: key, email });
}

function doCancel() {
  ipcRenderer.send('ms-cancel');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') doActivate();
});
</script>
</body>
</html>`;
  }
}

module.exports = LicenseClient;
