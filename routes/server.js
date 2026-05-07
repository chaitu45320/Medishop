// ================================================================
// server.js — MediShop Pro License Server v3.0
// Deploy on Railway. All field names match main.js exactly.
//
//  POST /api/activate   { key, email, machine_id, app_version }
//  GET  /api/validate   ?token=KEY&machine_id=ID
//  POST /api/deactivate { key, machine_id }
//  GET  /admin          Web admin panel
//  POST /api/admin/generate
//  GET  /api/admin/licenses
//  POST /api/admin/revoke
//  POST /api/admin/restore
//  POST /api/admin/release-machine
//  GET  /api/admin/logs
//  GET  /api/admin/stats
// ================================================================

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT      = process.env.PORT || 3000;
const DB_FILE   = path.join(__dirname, 'db.json');
const ADMIN_KEY = process.env.ADMIN_KEY || 'MediAdmin@2024';

// ── DB helpers ──────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const empty = { licenses: [], logs: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { console.error('[DB] Parse error:', e.message); return { licenses: [], logs: [] }; }
}

function saveDB(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { console.error('[DB] Write error:', e.message); }
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress || 'unknown';
}

// Every event printed to Railway console AND stored in db.logs
function addLog(db, action, status, key, machine_id, ip, message) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${action.toUpperCase()} | ${status.toUpperCase()} | key=${key||'-'} | machine=${machine_id||'-'} | ip=${ip} | ${message}`);
  db.logs.unshift({ id: Date.now(), timestamp: ts, action, status, license_key: key||'-', machine_id: machine_id||'-', ip, message });
  if (db.logs.length > 1000) db.logs = db.logs.slice(0, 1000);
}

function genKey(prefix) {
  const p = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${prefix}-${p()}-${p()}-${p()}`;
}

// ── Health ───────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get('/', (_, res) => res.json({ service: 'MediShop Pro License Server', version: '3.0' }));

// ================================================================
// VALIDATE — Called by main.js on every app startup
// GET /api/validate?token=KEY&machine_id=MACHINEID
// ================================================================
app.get('/api/validate', (req, res) => {
  const db         = loadDB();
  const ip         = getIP(req);
  const key        = (req.query.token || '').trim().toUpperCase();
  const machine_id = (req.query.machine_id || '').trim();

  console.log(`\n[VALIDATE REQUEST] key=${key} machine=${machine_id} ip=${ip}`);

  if (!key) {
    addLog(db, 'validate', 'fail', key, machine_id, ip, 'No key provided');
    saveDB(db); return res.json({ active: false, reason: 'No key provided' });
  }

  const lic = db.licenses.find(l => l.key === key);
  if (!lic) {
    addLog(db, 'validate', 'fail', key, machine_id, ip, 'Key not found in database');
    saveDB(db); return res.json({ active: false, reason: 'Invalid key' });
  }

  if (lic.status === 'revoked') {
    addLog(db, 'validate', 'revoked', key, machine_id, ip, `REVOKED key attempted from machine=${machine_id}`);
    saveDB(db); return res.json({ active: false, reason: 'Revoked' });
  }

  // Trial expiry
  if (lic.type === 'trial' && lic.expires_at && new Date() > new Date(lic.expires_at)) {
    lic.status = 'expired';
    addLog(db, 'validate', 'expired', key, machine_id, ip, 'Trial expired');
    saveDB(db); return res.json({ active: false, reason: 'Expired', days_left: 0 });
  }

  // Machine binding
  if (!lic.machine_id) {
    lic.machine_id   = machine_id;
    lic.first_seen   = new Date().toISOString();
    lic.last_seen    = new Date().toISOString();
    lic.last_seen_ip = ip;
    addLog(db, 'validate', 'bound', key, machine_id, ip, `First use — key now BOUND to this machine`);
    saveDB(db);
  } else if (lic.machine_id !== machine_id) {
    addLog(db, 'validate', 'fail', key, machine_id, ip,
      `MACHINE MISMATCH — registered=${lic.machine_id} attempted=${machine_id}`);
    saveDB(db); return res.json({ active: false, reason: 'Used on another device' });
  } else {
    lic.last_seen    = new Date().toISOString();
    lic.last_seen_ip = ip;
    addLog(db, 'validate', 'ok', key, machine_id, ip,
      `Valid | type=${lic.type} | email=${lic.email||'-'} | shop=${lic.shop_name||'-'}`);
    saveDB(db);
  }

  const daysLeft = (lic.type === 'trial' && lic.expires_at)
    ? Math.max(0, Math.ceil((new Date(lic.expires_at) - new Date()) / 86400000)) : -1;

  return res.json({ active: true, type: lic.type||'full', days_left: daysLeft, expires_at: lic.expires_at||null, email: lic.email||'' });
});

// ================================================================
// ACTIVATE — Called when user enters license key in the app
// POST /api/activate  { key, email, machine_id, app_version }
// ================================================================
app.post('/api/activate', (req, res) => {
  const db         = loadDB();
  const ip         = getIP(req);
  // Accept both naming styles
  const key        = (req.body.key || req.body.licenseKey || '').trim().toUpperCase();
  const email      = (req.body.email || '').trim().toLowerCase();
  const machine_id = (req.body.machine_id || req.body.deviceId || '').trim();
  const version    = req.body.app_version || req.body.appVersion || 'unknown';

  console.log(`\n[ACTIVATE REQUEST] key=${key} email=${email} machine=${machine_id} version=${version} ip=${ip}`);

  if (!key) {
    addLog(db, 'activate', 'fail', key, machine_id, ip, 'No key provided');
    saveDB(db); return res.json({ success: false, error: 'License key is required' });
  }

  const lic = db.licenses.find(l => l.key === key);
  if (!lic) {
    addLog(db, 'activate', 'fail', key, machine_id, ip, 'Key not found in database');
    saveDB(db); return res.json({ success: false, error: 'Invalid license key. Check and try again.' });
  }

  if (lic.status === 'revoked') {
    addLog(db, 'activate', 'fail', key, machine_id, ip, 'Tried to activate REVOKED key');
    saveDB(db); return res.json({ success: false, error: 'License key has been revoked. Contact: 9985223448' });
  }

  if (lic.type === 'trial' && lic.expires_at && new Date() > new Date(lic.expires_at)) {
    lic.status = 'expired';
    addLog(db, 'activate', 'fail', key, machine_id, ip, 'Trial expired — activation rejected');
    saveDB(db); return res.json({ success: false, error: 'Trial period has expired. Purchase a full license.' });
  }

  // Machine conflict
  if (lic.machine_id && machine_id && lic.machine_id !== machine_id) {
    addLog(db, 'activate', 'fail', key, machine_id, ip,
      `Machine conflict! Bound to ${lic.machine_id}, request from ${machine_id}`);
    saveDB(db);
    return res.json({ success: false, error: 'Already activated on another machine. Deactivate there first, or contact: 9985223448' });
  }

  // Email check
  if (lic.email && email && lic.email !== email) {
    addLog(db, 'activate', 'fail', key, machine_id, ip,
      `Email mismatch: registered=${lic.email} provided=${email}`);
    saveDB(db);
    return res.json({ success: false, error: 'Email does not match registered email for this key.' });
  }

  // SUCCESS — bind machine and activate
  if (!lic.machine_id && machine_id) lic.machine_id = machine_id;
  if (!lic.email && email)           lic.email      = email;
  lic.status          = 'active';
  lic.activation_date = lic.activation_date || new Date().toISOString();
  lic.last_seen       = new Date().toISOString();
  lic.last_seen_ip    = ip;

  const daysLeft = (lic.type === 'trial' && lic.expires_at)
    ? Math.max(0, Math.ceil((new Date(lic.expires_at) - new Date()) / 86400000)) : -1;

  addLog(db, 'activate', 'ok', key, machine_id, ip,
    `ACTIVATED | type=${lic.type} | email=${email||lic.email||'-'} | shop=${lic.shop_name||'-'} | version=${version}`);
  saveDB(db);

  return res.json({
    success: true, type: lic.type||'full', days_left: daysLeft, expires_at: lic.expires_at||null,
    message: lic.type === 'trial' ? `Trial activated — ${daysLeft} days remaining` : 'License activated successfully!'
  });
});

// ================================================================
// DEACTIVATE — User calls this to release machine binding
// POST /api/deactivate  { key, machine_id }
// ================================================================
app.post('/api/deactivate', (req, res) => {
  const db         = loadDB();
  const ip         = getIP(req);
  const key        = (req.body.key || '').trim().toUpperCase();
  const machine_id = (req.body.machine_id || '').trim();

  console.log(`\n[DEACTIVATE REQUEST] key=${key} machine=${machine_id} ip=${ip}`);

  if (!key) return res.json({ success: false, error: 'No key provided' });

  const lic = db.licenses.find(l => l.key === key);
  if (!lic) {
    addLog(db, 'deactivate', 'fail', key, machine_id, ip, 'Key not found');
    saveDB(db); return res.json({ success: false, error: 'License key not found' });
  }

  if (lic.machine_id && machine_id && lic.machine_id !== machine_id) {
    addLog(db, 'deactivate', 'fail', key, machine_id, ip,
      `Wrong machine: bound=${lic.machine_id} request=${machine_id}`);
    saveDB(db);
    return res.json({ success: false, error: 'Can only deactivate from the machine it was activated on. Contact support to force-release.' });
  }

  const old        = lic.machine_id;
  lic.machine_id   = null;
  lic.deactivation_date = new Date().toISOString();
  addLog(db, 'deactivate', 'ok', key, machine_id, ip, `DEACTIVATED | released machine=${old||'-'}`);
  saveDB(db);

  return res.json({ success: true, message: 'License deactivated. You can now activate on a new machine.' });
});

// ================================================================
// ADMIN APIs
// ================================================================
function adminAuth(req, res, next) {
  const k = req.headers['x-admin-key'] || req.query.admin_key;
  if (k !== ADMIN_KEY) {
    console.log(`[ADMIN] Unauthorized from ${getIP(req)}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.post('/api/admin/generate', adminAuth, (req, res) => {
  const db     = loadDB();
  const ip     = getIP(req);
  const type   = req.body.type || 'full';
  const prefix = type === 'trial' ? 'MDTL' : 'MEDI';
  const key    = genKey(prefix);
  const days   = parseInt(req.body.trial_days) || 7;

  const lic = {
    key, type, status: 'active',
    email:           (req.body.email || '').toLowerCase().trim(),
    shop_name:       (req.body.shop_name || '').trim(),
    phone:           (req.body.phone || '').trim(),
    machine_id:      null,
    created_at:      new Date().toISOString(),
    activation_date: null,
    last_seen:       null,
    last_seen_ip:    null,
    expires_at:      type === 'trial' ? new Date(Date.now() + days * 86400000).toISOString() : null,
    trial_days:      type === 'trial' ? days : null
  };

  db.licenses.unshift(lic);
  addLog(db, 'generate', 'ok', key, '-', ip,
    `GENERATED | type=${type} | email=${lic.email||'-'} | shop=${lic.shop_name||'-'} | days=${type==='trial'?days:'unlimited'}`);
  saveDB(db);
  console.log(`[ADMIN] NEW KEY: ${key}`);
  return res.json({ success: true, key, license: lic });
});

app.get('/api/admin/licenses', adminAuth, (req, res) => {
  const db = loadDB();
  res.json({ licenses: db.licenses, total: db.licenses.length });
});

app.post('/api/admin/revoke', adminAuth, (req, res) => {
  const db  = loadDB();
  const ip  = getIP(req);
  const key = (req.body.key || '').toUpperCase();
  const lic = db.licenses.find(l => l.key === key);
  if (!lic) return res.json({ success: false, error: 'Not found' });
  lic.status = 'revoked'; lic.revoked_at = new Date().toISOString();
  addLog(db, 'revoke', 'ok', key, lic.machine_id||'-', ip, `REVOKED by admin | email=${lic.email||'-'}`);
  saveDB(db);
  return res.json({ success: true });
});

app.post('/api/admin/restore', adminAuth, (req, res) => {
  const db  = loadDB();
  const ip  = getIP(req);
  const key = (req.body.key || '').toUpperCase();
  const lic = db.licenses.find(l => l.key === key);
  if (!lic) return res.json({ success: false, error: 'Not found' });
  lic.status = 'active'; lic.revoked_at = null;
  addLog(db, 'restore', 'ok', key, lic.machine_id||'-', ip, 'Restored by admin');
  saveDB(db);
  return res.json({ success: true });
});

app.post('/api/admin/release-machine', adminAuth, (req, res) => {
  const db  = loadDB();
  const ip  = getIP(req);
  const key = (req.body.key || '').toUpperCase();
  const lic = db.licenses.find(l => l.key === key);
  if (!lic) return res.json({ success: false, error: 'Not found' });
  const old = lic.machine_id;
  lic.machine_id = null; lic.deactivation_date = new Date().toISOString();
  addLog(db, 'release', 'ok', key, old||'-', ip, `Admin force-released machine | was=${old||'none'}`);
  saveDB(db);
  return res.json({ success: true, released_machine: old });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const db = loadDB();
  res.json({ stats: {
    total: db.licenses.length,
    active: db.licenses.filter(l => l.status === 'active').length,
    revoked: db.licenses.filter(l => l.status === 'revoked').length,
    expired: db.licenses.filter(l => l.status === 'expired').length,
    full: db.licenses.filter(l => l.type === 'full').length,
    trial: db.licenses.filter(l => l.type === 'trial').length,
    bound: db.licenses.filter(l => !!l.machine_id).length,
    unbound: db.licenses.filter(l => !l.machine_id).length,
    logs: db.logs.length
  }});
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
  const db = loadDB(); const limit = parseInt(req.query.limit) || 200;
  res.json({ logs: db.logs.slice(0, limit), total: db.logs.length });
});

// ================================================================
// ADMIN WEB PANEL
// ================================================================
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>MediShop License Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',sans-serif}
body{background:#0f172a;color:#e2e8f0;min-height:100vh}
.hdr{background:linear-gradient(135deg,#1e3a5f,#1565C0);padding:16px 28px;display:flex;align-items:center;gap:12px}
.hdr h1{font-size:20px;font-weight:800}.hdr small{font-size:12px;color:#90CAF9;display:block;margin-top:2px}
.wrap{max-width:1200px;margin:24px auto;padding:0 20px}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:80vh}
.card{background:#1e293b;border-radius:14px;padding:22px;border:1px solid #334155;margin-bottom:18px}
input,select{background:#0f172a;border:1.5px solid #334155;color:#e2e8f0;padding:9px 12px;border-radius:7px;font-size:13px;outline:none;font-family:inherit;width:100%}
input:focus,select:focus{border-color:#1565C0}
.btn{padding:9px 16px;border-radius:7px;border:none;font-size:13px;font-weight:700;cursor:pointer;font-family:inherit}
.bp{background:#1565C0;color:#fff}.bp:hover{background:#0d47a1}
.bg{background:#2e7d32;color:#fff}.bg:hover{background:#1b5e20}
.br{background:#c62828;color:#fff}.br:hover{background:#b71c1c}
.bw{background:#e65100;color:#fff}.bw:hover{background:#bf360c}
.bs{padding:5px 10px;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:20px}
.stat{background:#1e293b;border-radius:10px;padding:14px;border:1px solid #334155;text-align:center}
.stat .n{font-size:28px;font-weight:800}.stat .l{font-size:11px;color:#64748b;margin-top:3px}
.tabs{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
.tab{padding:8px 16px;border-radius:8px;border:1.5px solid #334155;background:#1e293b;color:#94a3b8;cursor:pointer;font-size:13px;font-weight:600}
.tab.on{background:#1565C0;border-color:#1565C0;color:#fff}
.tp{display:none}.tp.on{display:block}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#1e293b;color:#94a3b8;padding:9px 10px;text-align:left;border-bottom:1px solid #334155;font-weight:600;white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid #1a2744;color:#cbd5e1;vertical-align:top}
tr:hover td{background:#1e293b}
.b{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.ba{background:#1b5e20;color:#a5d6a7}.brev{background:#7f1d1d;color:#fca5a5}
.bexp{background:#44403c;color:#fcd34d}.bful{background:#1e3a5f;color:#93c5fd}
.btrl{background:#451a03;color:#fed7aa}.bbnd{background:#1e3a5f;color:#7dd3fc}
.lok{color:#4ade80}.lfail{color:#f87171}.lwarn{color:#fbbf24}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.fg{margin-bottom:10px}
label{display:block;font-size:11px;color:#94a3b8;margin-bottom:4px;text-transform:uppercase;font-weight:600}
.msg{padding:10px;border-radius:7px;margin-top:10px;font-size:13px;display:none}
.mok{background:#1b5e20;color:#a5d6a7}.merr{background:#7f1d1d;color:#fca5a5}
.mono{font-family:monospace;font-size:11px}
.kres{background:#0f172a;border-radius:8px;padding:14px;border:1px solid #1565C0;margin-top:12px;display:none}
.kbig{font-family:monospace;font-size:22px;font-weight:800;color:#60a5fa;letter-spacing:3px;word-break:break-all}
.srow{display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap}
.srow input,.srow select{flex:unset;width:auto}
.srow input{flex:1;min-width:180px}
</style></head><body>
<div class="hdr">
  <span style="font-size:30px">&#x1F48A;</span>
  <div><h1>MediShop Pro &mdash; License Admin v3.0</h1>
  <small>All activate/validate/deactivate events logged to Railway console &amp; stored here</small></div>
</div>

<div id="lw" class="login-wrap">
  <div class="card" style="width:320px">
    <h2 style="margin-bottom:16px;font-size:16px">&#x1F510; Admin Login</h2>
    <div class="fg"><label>Admin Key</label>
    <input type="password" id="ak" placeholder="Enter admin key" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <button class="btn bp" style="width:100%;margin-top:4px" onclick="doLogin()">Login &rarr;</button>
    <div id="lerr" class="msg merr"></div>
  </div>
</div>

<div id="pnl" style="display:none"><div class="wrap">
  <div id="sb" class="stats"></div>
  <div class="tabs">
    <div class="tab on" onclick="tab('lic')">&#x1F4CB; Licenses</div>
    <div class="tab" onclick="tab('gen')">&#x2795; Generate Key</div>
    <div class="tab" onclick="tab('log')">&#x1F4CA; Activity Logs</div>
  </div>

  <div id="tp-lic" class="tp on">
    <div class="srow">
      <input id="ls" placeholder="Search key, email, shop..." oninput="fLic()" style="flex:1">
      <button class="btn bp bs" onclick="loadAll()">&#x21BB; Refresh</button>
    </div>
    <div id="lt"></div>
  </div>

  <div id="tp-gen" class="tp">
    <div class="card" style="max-width:500px">
      <h2 style="margin-bottom:16px;font-size:15px">&#x26A1; Generate New License Key</h2>
      <div class="row2">
        <div class="fg"><label>Customer Email</label><input id="ge" type="email" placeholder="customer@email.com"></div>
        <div class="fg"><label>Shop Name</label><input id="gs" placeholder="Pharmacy name"></div>
      </div>
      <div class="row2">
        <div class="fg"><label>Phone</label><input id="gp" placeholder="9xxxxxxxxx"></div>
        <div class="fg"><label>License Type</label>
          <select id="gt" onchange="document.getElementById('gdr').style.display=this.value==='trial'?'block':'none'">
            <option value="full">Full License (Unlimited)</option>
            <option value="trial">Trial License</option>
          </select>
        </div>
      </div>
      <div id="gdr" style="display:none" class="fg">
        <label>Trial Days</label><input id="gd" type="number" value="7" min="1" max="365" style="width:120px">
      </div>
      <button class="btn bg" style="width:100%;margin-top:4px" onclick="genKey()">&#x26A1; Generate Key</button>
      <div id="gm" class="msg"></div>
      <div id="gr" class="kres">
        <div style="font-size:11px;color:#64748b;margin-bottom:8px">NEW KEY &mdash; SEND THIS TO CUSTOMER</div>
        <div id="gk" class="kbig"></div>
        <button class="btn bp bs" style="margin-top:10px" onclick="copyKey()">&#x1F4CB; Copy Key</button>
      </div>
    </div>
  </div>

  <div id="tp-log" class="tp">
    <div class="srow">
      <select id="la" onchange="fLog()" style="width:140px">
        <option value="">All actions</option>
        <option value="validate">validate</option>
        <option value="activate">activate</option>
        <option value="deactivate">deactivate</option>
        <option value="revoke">revoke</option>
        <option value="restore">restore</option>
        <option value="generate">generate</option>
        <option value="bound">bound (status)</option>
        <option value="release">release</option>
      </select>
      <select id="lst" onchange="fLog()" style="width:120px">
        <option value="">All statuses</option>
        <option value="ok">ok</option>
        <option value="fail">fail</option>
        <option value="bound">bound</option>
        <option value="revoked">revoked</option>
        <option value="expired">expired</option>
      </select>
      <input id="lq" placeholder="Search key, machine, IP, message..." oninput="fLog()">
      <button class="btn bp bs" onclick="loadAll()">&#x21BB; Refresh</button>
    </div>
    <div id="lgt"></div>
  </div>
</div></div>

<script>
var AK='',aL=[],aLg=[],lastK='';
function doLogin(){AK=document.getElementById('ak').value.trim();if(AK)loadAll();}
async function api(u,o={}){
  const r=await fetch(u,{...o,headers:{'Content-Type':'application/json','x-admin-key':AK,...(o.headers||{})}});
  return r.json();
}
async function loadAll(){
  try{
    const [s,l,g]=await Promise.all([api('/api/admin/stats'),api('/api/admin/licenses'),api('/api/admin/logs?limit=300')]);
    if(s.error){var e=document.getElementById('lerr');e.textContent='Wrong admin key';e.style.display='block';return;}
    document.getElementById('lw').style.display='none';
    document.getElementById('pnl').style.display='block';
    document.getElementById('lerr').style.display='none';
    var st=s.stats,cs=['#60a5fa','#4ade80','#f87171','#fbbf24','#818cf8','#fde68a','#34d399','#94a3b8','#a78bfa'];
    var its=[['Total',st.total],['Active',st.active],['Revoked',st.revoked],['Expired',st.expired],
             ['Full',st.full],['Trial',st.trial],['Bound',st.bound],['Unbound',st.unbound],['Logs',st.logs]];
    document.getElementById('sb').innerHTML=its.map(function(x,i){
      return '<div class="stat"><div class="n" style="color:'+cs[i]+'">'+x[1]+'</div><div class="l">'+x[0]+'</div></div>';
    }).join('');
    aL=l.licenses||[];aLg=g.logs||[];rL(aL);rLg(aLg);
  }catch(e){var el=document.getElementById('lerr');el.textContent='Error: '+e.message;el.style.display='block';}
}
function rL(lics){
  if(!lics.length){document.getElementById('lt').innerHTML='<p style="color:#64748b;padding:20px">No licenses yet.</p>';return;}
  document.getElementById('lt').innerHTML='<table><thead><tr><th>Key</th><th>Type</th><th>Status</th><th>Email</th><th>Shop</th><th>Machine ID (first 18 chars)</th><th>Activated</th><th>Last Seen</th><th>Actions</th></tr></thead><tbody>'+
  lics.map(function(l){
    var bd=!!l.machine_id;
    return '<tr>'+
    '<td class="mono" style="font-weight:700">'+l.key+'</td>'+
    '<td><span class="b b'+l.type.slice(0,3)+'">'+l.type+'</span></td>'+
    '<td><span class="b b'+({'active':'a','revoked':'rev','expired':'exp'}[l.status]||'a')+'">'+l.status+'</span>'+
      (bd?'<span class="b bbnd" style="margin-left:3px">&#x1F512; bound</span>':'')+'</td>'+
    '<td style="font-size:11px">'+(l.email||'&mdash;')+'</td>'+
    '<td style="font-size:11px">'+(l.shop_name||'&mdash;')+'</td>'+
    '<td class="mono" style="font-size:10px">'+(l.machine_id?l.machine_id.slice(0,18)+'...':'&mdash;')+'</td>'+
    '<td style="font-size:10px">'+(l.activation_date?new Date(l.activation_date).toLocaleString():'Never')+'</td>'+
    '<td style="font-size:10px">'+(l.last_seen?new Date(l.last_seen).toLocaleString():'Never')+'</td>'+
    '<td style="white-space:nowrap">'+
      (l.status==='active'
        ?'<button class="btn br bs" onclick="rev(\''+l.key+'\')">Revoke</button>'
        :'<button class="btn bg bs" onclick="rst(\''+l.key+'\')">Restore</button>')+
      (bd?'<button class="btn bw bs" style="margin-left:4px" onclick="rel(\''+l.key+'\')">Release Machine</button>':'')+
    '</td></tr>';
  }).join('')+'</tbody></table>';
}
function rLg(logs){
  if(!logs.length){document.getElementById('lgt').innerHTML='<p style="color:#64748b;padding:20px">No logs yet.</p>';return;}
  document.getElementById('lgt').innerHTML='<table><thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Key</th><th>Machine ID</th><th>IP</th><th>Message</th></tr></thead><tbody>'+
  logs.map(function(l){
    var sc={'ok':'lok','fail':'lfail','bound':'lwarn','revoked':'lfail','expired':'lwarn'}[l.status]||'';
    return '<tr><td style="font-size:10px;white-space:nowrap">'+new Date(l.timestamp).toLocaleString()+'</td>'+
    '<td style="font-weight:700">'+l.action+'</td>'+
    '<td><span class="'+sc+'">'+l.status+'</span></td>'+
    '<td class="mono" style="font-size:11px">'+l.license_key+'</td>'+
    '<td class="mono" style="font-size:10px">'+(l.machine_id!=='-'?l.machine_id.slice(0,16)+'...':'&mdash;')+'</td>'+
    '<td style="font-size:11px">'+l.ip+'</td>'+
    '<td style="font-size:11px">'+l.message+'</td></tr>';
  }).join('')+'</tbody></table>';
}
function fLic(){var q=document.getElementById('ls').value.toLowerCase();rL(aL.filter(function(l){return l.key.toLowerCase().includes(q)||(l.email||'').includes(q)||(l.shop_name||'').toLowerCase().includes(q);}));}
function fLog(){
  var a=document.getElementById('la').value,s=document.getElementById('lst').value,q=document.getElementById('lq').value.toLowerCase();
  rLg(aLg.filter(function(l){return(!a||l.action===a||l.status===a)&&(!s||l.status===s)&&(!q||l.license_key.toLowerCase().includes(q)||l.machine_id.toLowerCase().includes(q)||l.ip.includes(q)||l.message.toLowerCase().includes(q));}));
}
async function rev(key){if(!confirm('REVOKE '+key+'?\nApp will stop working at next startup.'))return;var d=await api('/api/admin/revoke',{method:'POST',body:JSON.stringify({key})});if(d.success)loadAll();else alert('Error: '+d.error);}
async function rst(key){var d=await api('/api/admin/restore',{method:'POST',body:JSON.stringify({key})});if(d.success)loadAll();else alert('Error: '+d.error);}
async function rel(key){if(!confirm('Release machine binding for '+key+'?\nUser can then activate on a new machine.'))return;var d=await api('/api/admin/release-machine',{method:'POST',body:JSON.stringify({key})});if(d.success){alert('Machine released! User can activate on new machine.');loadAll();}else alert('Error: '+d.error);}
async function genKey(){
  var email=document.getElementById('ge').value.trim(),shop=document.getElementById('gs').value.trim(),
      phone=document.getElementById('gp').value.trim(),type=document.getElementById('gt').value,
      days=document.getElementById('gd').value,msg=document.getElementById('gm');
  msg.style.display='none';document.getElementById('gr').style.display='none';
  var d=await api('/api/admin/generate',{method:'POST',body:JSON.stringify({email,shop_name:shop,phone,type,trial_days:days})});
  if(d.success){lastK=d.key;document.getElementById('gk').textContent=d.key;document.getElementById('gr').style.display='block';msg.className='msg mok';msg.textContent='Key generated successfully!';msg.style.display='block';loadAll();}
  else{msg.className='msg merr';msg.textContent='Error: '+(d.error||'failed');msg.style.display='block';}
}
function copyKey(){navigator.clipboard.writeText(lastK).then(function(){alert('Copied: '+lastK);});}
function tab(n){
  var names=['lic','gen','log'];
  document.querySelectorAll('.tab').forEach(function(t,i){t.classList.toggle('on',names[i]===n);});
  document.querySelectorAll('.tp').forEach(function(t){t.classList.remove('on');});
  document.getElementById('tp-'+n).classList.add('on');
}
</script></body></html>`);
});

// ================================================================
app.listen(PORT, () => {
  console.log('');
  console.log('=================================================');
  console.log(' MediShop Pro License Server v3.0');
  console.log(` Port    : ${PORT}`);
  console.log(` DB file : ${DB_FILE}`);
  console.log(` Admin   : http://localhost:${PORT}/admin`);
  console.log(` Admin key set: ${ADMIN_KEY !== 'MediAdmin@2024' ? 'YES (from env)' : 'DEFAULT — set ADMIN_KEY env var!'}`);
  console.log('=================================================');
  const db = loadDB();
  console.log(` DB: ${db.licenses.length} licenses, ${db.logs.length} log entries`);
  console.log('');
});
