/**
 * server.js — Medishop License Server
 * Deployed on Railway at: https://medishop-production-6c4b.up.railway.app
 *
 * EXACT API CONTRACT (matches main.js client):
 *
 *   POST /api/activate
 *        Body: { licenseKey, email, deviceId, deviceName, appVersion }
 *        Returns: { success, token, type, daysLeft, message }
 *
 *   POST /api/validate
 *        Body: { token, deviceId }
 *        Returns: { success, valid, type, daysLeft, email }
 *
 *   POST /api/deactivate
 *        Body: { token, deviceId }
 *        Returns: { success, message }
 *
 *   GET  /health
 *        Returns: { status: 'ok', service, version }
 *
 *   GET  /                → Admin dashboard (requires ?token=ADMIN_SECRET)
 *   POST /admin/keys/generate
 *   GET  /admin/keys
 *   POST /admin/keys/:hash/revoke
 *   POST /admin/keys/:hash/restore
 *   POST /admin/devices/:hash/transfer-all
 */

const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');

const app  = express();
app.use(express.json());

const PORT         = process.env.PORT || 8080;
const DB_FILE      = path.join(__dirname, 'data', 'licenses.db.json');
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ms_admin_2024_secure';
const JWT_SECRET   = process.env.JWT_SECRET   || 'MS_JWT_Medishop_2024_Ultra_Secure_Key_99';
const LIC_SECRET   = process.env.LIC_SECRET   || 'MS@Medishop#2024!PharmacyBilling$Key@Secure99';
const TRIAL_DAYS   = parseInt(process.env.TRIAL_DAYS || '30');
const APP_PREFIX   = 'MEDSHP';
const CHARS        = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// ── Ensure data dir exists ─────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// ── DB helpers ─────────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { keys: {}, activations: {}, logs: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { keys: {}, activations: {}, logs: [] }; }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function addLog(db, keyHash, deviceId, ip, action, result, detail) {
  if (!db.logs) db.logs = [];
  db.logs.push({ keyHash, deviceId: deviceId||'', ip: ip||'', action, result, detail: detail||'', ts: Date.now() });
  // Keep last 2000 logs only
  if (db.logs.length > 2000) db.logs = db.logs.slice(-2000);
}

// ── Key helpers ────────────────────────────────────────────────────────────
function hmacSeg(data, len) {
  const bytes = crypto.createHmac('sha256', LIC_SECRET).update(data).digest();
  let r = '';
  for (let i = 0; i < bytes.length && r.length < len; i++)
    r += CHARS[bytes[i] % CHARS.length];
  return r;
}

function validateKeyFormat(licenseKey) {
  const parts = licenseKey.trim().toUpperCase().split('-');
  if (parts.length !== 5)                       return { valid: false, reason: 'Need 5 segments' };
  if (parts[0] !== APP_PREFIX)                  return { valid: false, reason: 'Invalid prefix' };
  if (!['FULL','TRAL'].includes(parts[1]))      return { valid: false, reason: 'Invalid type segment' };
  if ([parts[2],parts[3],parts[4]].some(s => s.length !== 6))
                                                return { valid: false, reason: 'Each segment must be 6 chars' };
  const [, typeCode, seg1, seg2, seg3] = parts;
  if (seg3 !== hmacSeg(`${seg1}-${seg2}`, 6))  return { valid: false, reason: 'Checksum mismatch — key is invalid' };
  if (typeCode === 'FULL' && seg1[0] !== 'F')   return { valid: false, reason: 'Type flag mismatch' };
  if (typeCode === 'TRAL' && seg1[0] !== 'T')   return { valid: false, reason: 'Type flag mismatch' };
  return { valid: true, type: typeCode === 'FULL' ? 'full' : 'trial' };
}

function hashKey(key) {
  return crypto.createHmac('sha256', LIC_SECRET).update(key.toUpperCase()).digest('hex');
}

function signJWT(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '365d' });
}

function verifyJWT(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function getDaysLeft(activatedAt, type) {
  if (type === 'full') return null;
  if (!activatedAt) return TRIAL_DAYS;
  return Math.max(0, Math.ceil(((activatedAt + TRIAL_DAYS * 86400000) - Date.now()) / 86400000));
}

function isTrialExpired(activatedAt, type) {
  if (type === 'full' || !activatedAt) return false;
  return Date.now() > activatedAt + TRIAL_DAYS * 86400000;
}

// ── Auth middleware for admin routes ──────────────────────────────────────
function adminAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '') ||
                req.query.token || req.headers['x-admin-key'];
  if (token !== ADMIN_SECRET)
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  next();
}

// ═══════════════════════════════════════════════════════════════════════════
//  POST /api/activate
//  Body: { licenseKey, email, deviceId, deviceName, appVersion }
//  Returns: { success, token (JWT), type, daysLeft, message }
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/activate', (req, res) => {
  const { licenseKey, email, deviceId, deviceName, appVersion } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  console.log('[ACTIVATE] key:', licenseKey, '| email:', email, '| deviceId:', deviceId, '| ip:', ip);

  // ── Input validation ────────────────────────────────────────────────────
  if (!licenseKey) return res.status(400).json({ success: false, error: 'licenseKey is required' });
  if (!email)      return res.status(400).json({ success: false, error: 'email is required' });
  if (!deviceId)   return res.status(400).json({ success: false, error: 'deviceId is required' });

  const key     = licenseKey.trim().toUpperCase();
  const emailLc = email.trim().toLowerCase();

  // ── Validate key format + HMAC checksum ────────────────────────────────
  const fmt = validateKeyFormat(key);
  if (!fmt.valid) {
    console.warn('[ACTIVATE] Bad format:', fmt.reason);
    return res.status(400).json({ success: false, error: 'Invalid license key: ' + fmt.reason });
  }

  const keyHash = hashKey(key);
  const db      = loadDB();

  // ── Key must exist in DB (admin must have generated it first) ──────────
  const keyRecord = db.keys[keyHash];
  if (!keyRecord) {
    addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Key not found');
    saveDB(db);
    console.warn('[ACTIVATE] Key not found in DB:', key);
    return res.status(404).json({
      success: false,
      error: 'License key not found. Please contact Medishop support.'
    });
  }

  // ── Key must be active ─────────────────────────────────────────────────
  if (!keyRecord.isActive) {
    addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Revoked');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'This license has been revoked.' });
  }

  // ── Email must match ───────────────────────────────────────────────────
  if (keyRecord.email !== emailLc) {
    addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Email mismatch');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'This key is registered to a different email address.' });
  }

  // ── Ensure activations map exists ──────────────────────────────────────
  if (!db.activations) db.activations = {};
  if (!db.activations[keyHash]) db.activations[keyHash] = {};

  const deviceActivations = db.activations[keyHash];
  const existing          = deviceActivations[deviceId];

  // ── Same device re-activation ──────────────────────────────────────────
  if (existing) {
    if (existing.isRevoked) {
      addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Device revoked');
      saveDB(db);
      return res.status(403).json({ success: false, error: 'This device has been revoked.' });
    }

    // Check trial expiry using original activation time
    if (keyRecord.type === 'trial' && isTrialExpired(existing.activatedAt, 'trial')) {
      addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Trial expired');
      saveDB(db);
      return res.status(403).json({ success: false, error: 'Trial license has expired. Please upgrade to a full license.' });
    }

    // Refresh token, keep original activatedAt for trial countdown
    const token    = signJWT({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
    const daysLeft = getDaysLeft(existing.activatedAt, keyRecord.type);

    existing.lastSeen   = Date.now();
    existing.deviceName = deviceName || existing.deviceName;
    existing.appVersion = appVersion || existing.appVersion;

    addLog(db, keyHash, deviceId, ip, 'reactivate', 'ok', deviceName || '');
    saveDB(db);

    console.log('[ACTIVATE] Re-activation OK — daysLeft:', daysLeft);
    return res.json({
      success:  true,
      token,
      type:     keyRecord.type,
      daysLeft,
      email:    emailLc,
      message:  'License verified successfully'
    });
  }

  // ── Trial expiry check for first-ever activation ───────────────────────
  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issuedAt, 'trial')) {
    addLog(db, keyHash, deviceId, ip, 'activate', 'fail', 'Trial expired before use');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'Trial license has expired.' });
  }

  // ── Device limit check ─────────────────────────────────────────────────
  const activeDevices = Object.values(deviceActivations).filter(d => !d.isRevoked);
  if (activeDevices.length >= (keyRecord.maxDevices || 1)) {
    const names = activeDevices.map(d => d.deviceName || d.deviceId).join(', ');
    addLog(db, keyHash, deviceId, ip, 'activate', 'fail_limit', 'Device limit: ' + names);
    saveDB(db);
    return res.status(409).json({
      success: false,
      error: `License already active on ${activeDevices.length} device(s): ${names}. Contact support to transfer.`,
      code: 'DEVICE_LIMIT'
    });
  }

  // ── New activation ─────────────────────────────────────────────────────
  const now      = Date.now();
  const token    = signJWT({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
  const daysLeft = getDaysLeft(now, keyRecord.type);

  deviceActivations[deviceId] = {
    deviceId,
    deviceName:  deviceName || 'Unknown Device',
    appVersion:  appVersion || '1.0.0',
    activatedAt: now,
    lastSeen:    now,
    isRevoked:   false
  };

  addLog(db, keyHash, deviceId, ip, 'activate', 'ok', deviceName || '');
  saveDB(db);

  console.log('[ACTIVATE] New activation OK — type:', keyRecord.type, 'daysLeft:', daysLeft);

  return res.json({
    success:     true,
    token,
    type:        keyRecord.type,
    daysLeft,
    activatedAt: now,
    email:       emailLc,
    message:     keyRecord.type === 'full'
                   ? 'Full license activated successfully!'
                   : `Trial license activated — ${daysLeft} day(s) remaining.`
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  POST /api/validate
//  Body: { token (JWT), deviceId }
//  Returns: { success, valid, type, daysLeft, email }
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/validate', (req, res) => {
  const { token, deviceId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token || !deviceId)
    return res.status(400).json({ success: false, error: 'token and deviceId are required' });

  // Verify JWT signature
  const payload = verifyJWT(token);
  if (!payload || payload.deviceId !== deviceId) {
    console.warn('[VALIDATE] Invalid JWT from deviceId:', deviceId);
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }

  const { keyHash } = payload;
  const db = loadDB();

  // Check activation record
  const activation = db.activations?.[keyHash]?.[deviceId];
  if (!activation || activation.isRevoked) {
    addLog(db, keyHash, deviceId, ip, 'validate', 'fail', 'Not activated or revoked');
    saveDB(db);
    return res.status(401).json({ success: false, error: 'Device not authorized' });
  }

  // Check key record
  const keyRecord = db.keys?.[keyHash];
  if (!keyRecord || !keyRecord.isActive) {
    addLog(db, keyHash, deviceId, ip, 'validate', 'fail', 'Key inactive or not found');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'License deactivated' });
  }

  // Check trial expiry using ORIGINAL activation time
  if (keyRecord.type === 'trial' && isTrialExpired(activation.activatedAt, 'trial')) {
    addLog(db, keyHash, deviceId, ip, 'validate', 'fail', 'Trial expired');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'Trial license has expired' });
  }

  // Update last seen
  activation.lastSeen = Date.now();
  addLog(db, keyHash, deviceId, ip, 'validate', 'ok', '');
  saveDB(db);

  const daysLeft = getDaysLeft(activation.activatedAt, keyRecord.type);
  console.log('[VALIDATE] OK — type:', keyRecord.type, 'daysLeft:', daysLeft);

  return res.json({
    success:  true,
    valid:    true,
    type:     keyRecord.type,
    daysLeft,
    email:    keyRecord.email
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  POST /api/deactivate
//  Body: { token (JWT), deviceId }
//  Returns: { success, message }
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/deactivate', (req, res) => {
  const { token, deviceId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token || !deviceId)
    return res.status(400).json({ success: false, error: 'token and deviceId required' });

  const payload = verifyJWT(token);
  if (!payload || payload.deviceId !== deviceId)
    return res.status(401).json({ success: false, error: 'Invalid token' });

  const { keyHash } = payload;
  const db = loadDB();

  if (db.activations?.[keyHash]?.[deviceId]) {
    delete db.activations[keyHash][deviceId];
    addLog(db, keyHash, deviceId, ip, 'deactivate', 'ok', 'Self deactivated');
    saveDB(db);
  }

  console.log('[DEACTIVATE] Device freed:', deviceId);
  return res.json({ success: true, message: 'Device deactivated. License slot is now free.' });
});

// ═══════════════════════════════════════════════════════════════════════════
//  GET /health
// ═══════════════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  const db = loadDB();
  res.json({
    status:    'ok',
    service:   'Medishop License Server',
    version:   '2.0.0',
    timestamp: new Date().toISOString(),
    keys:      Object.keys(db.keys || {}).length,
    activations: Object.values(db.activations || {}).reduce((n, d) => n + Object.keys(d).length, 0)
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES — require Authorization: Bearer ADMIN_SECRET
// ═══════════════════════════════════════════════════════════════════════════

// Generate a new key and register it
app.post('/admin/keys/generate', adminAuth, (req, res) => {
  const { email, type, maxDevices, notes } = req.body;

  if (!email || !type)
    return res.status(400).json({ success: false, error: 'email and type are required' });
  if (!['full','trial'].includes(type))
    return res.status(400).json({ success: false, error: 'type must be full or trial' });

  // Generate key
  const typeCode = type === 'full' ? 'FULL' : 'TRAL';
  const typeFlag = type === 'full' ? 'F'    : 'T';
  function randSeg(prefix) {
    let r = prefix || '';
    while (r.length < 6) r += CHARS[Math.floor(Math.random() * CHARS.length)];
    return r.substring(0, 6);
  }
  const seg1 = randSeg(typeFlag);
  const seg2 = randSeg();
  const seg3 = hmacSeg(`${seg1}-${seg2}`, 6);
  const key  = `${APP_PREFIX}-${typeCode}-${seg1}-${seg2}-${seg3}`;

  const keyHash   = hashKey(key);
  const db        = loadDB();
  if (!db.keys)   db.keys = {};

  db.keys[keyHash] = {
    key,
    email:      email.trim().toLowerCase(),
    type,
    maxDevices: parseInt(maxDevices) || 1,
    isActive:   true,
    issuedAt:   Date.now(),
    notes:      notes || ''
  };

  saveDB(db);
  console.log('[ADMIN] Key generated:', key, '|', type, '|', email);
  return res.json({ success: true, key, type, email: email.trim().toLowerCase(), maxDevices: parseInt(maxDevices)||1 });
});

// List all keys
app.get('/admin/keys', adminAuth, (req, res) => {
  const db   = loadDB();
  const keys = Object.entries(db.keys || {}).map(([hash, k]) => {
    const deviceActivations = db.activations?.[hash] || {};
    const activeDevices     = Object.values(deviceActivations).filter(d => !d.isRevoked);
    const firstActivated    = activeDevices.length
      ? Math.min(...activeDevices.map(d => d.activatedAt))
      : null;
    return {
      hash,
      key:          k.key,
      email:        k.email,
      type:         k.type,
      maxDevices:   k.maxDevices,
      isActive:     k.isActive,
      issuedAt:     k.issuedAt,
      notes:        k.notes,
      deviceCount:  activeDevices.length,
      daysLeft:     getDaysLeft(firstActivated, k.type),
      isExpired:    k.type === 'trial' ? isTrialExpired(firstActivated, 'trial') : false
    };
  });
  keys.sort((a, b) => b.issuedAt - a.issuedAt);
  return res.json({ success: true, keys, total: keys.length });
});

// Get key detail
app.get('/admin/keys/:hash', adminAuth, (req, res) => {
  const db  = loadDB();
  const key = db.keys?.[req.params.hash];
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });

  const devices  = Object.values(db.activations?.[req.params.hash] || {});
  const firstAt  = devices.filter(d => !d.isRevoked).length
    ? Math.min(...devices.filter(d => !d.isRevoked).map(d => d.activatedAt))
    : null;
  const logs     = (db.logs || []).filter(l => l.keyHash === req.params.hash).slice(-50).reverse();

  return res.json({
    success: true,
    key: { ...key, hash: req.params.hash, daysLeft: getDaysLeft(firstAt, key.type) },
    devices,
    logs
  });
});

// Revoke key
app.post('/admin/keys/:hash/revoke', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys?.[req.params.hash])
    return res.status(404).json({ success: false, error: 'Key not found' });
  db.keys[req.params.hash].isActive = false;
  addLog(db, req.params.hash, '', req.ip, 'admin_revoke', 'ok', 'Admin revoked');
  saveDB(db);
  return res.json({ success: true, message: 'License revoked.' });
});

// Restore key
app.post('/admin/keys/:hash/restore', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys?.[req.params.hash])
    return res.status(404).json({ success: false, error: 'Key not found' });
  db.keys[req.params.hash].isActive = true;
  addLog(db, req.params.hash, '', req.ip, 'admin_restore', 'ok', 'Admin restored');
  saveDB(db);
  return res.json({ success: true, message: 'License restored.' });
});

// Free all device slots (transfer to new machine)
app.post('/admin/devices/:hash/transfer-all', adminAuth, (req, res) => {
  const db = loadDB();
  if (db.activations?.[req.params.hash])
    db.activations[req.params.hash] = {};
  addLog(db, req.params.hash, '', req.ip, 'admin_transfer_all', 'ok', 'All devices cleared');
  saveDB(db);
  return res.json({ success: true, message: 'All device slots freed.' });
});

// Revoke single device
app.post('/admin/devices/:hash/:deviceId/revoke', adminAuth, (req, res) => {
  const db = loadDB();
  const d  = db.activations?.[req.params.hash]?.[req.params.deviceId];
  if (d) { d.isRevoked = true; saveDB(db); }
  return res.json({ success: true, message: 'Device revoked.' });
});

// Free single device slot
app.post('/admin/devices/:hash/:deviceId/transfer', adminAuth, (req, res) => {
  const db = loadDB();
  if (db.activations?.[req.params.hash]?.[req.params.deviceId])
    delete db.activations[req.params.hash][req.params.deviceId];
  saveDB(db);
  return res.json({ success: true, message: 'Device slot freed.' });
});

// Export
app.get('/admin/export', adminAuth, (req, res) => {
  const db = loadDB();
  res.setHeader('Content-Disposition', `attachment; filename="medishop-licenses-${Date.now()}.json"`);
  res.json({ exportedAt: new Date().toISOString(), ...db });
});

// Dashboard stats
app.get('/admin/dashboard', adminAuth, (req, res) => {
  const db          = loadDB();
  const keys        = Object.values(db.keys || {});
  const allDevices  = Object.values(db.activations || {}).flatMap(d => Object.values(d));
  const recentLogs  = (db.logs || []).slice(-20).reverse();
  return res.json({
    success: true,
    stats: {
      totalKeys:    keys.length,
      fullKeys:     keys.filter(k => k.type === 'full').length,
      trialKeys:    keys.filter(k => k.type === 'trial').length,
      activeKeys:   keys.filter(k => k.isActive).length,
      totalDevices: allDevices.filter(d => !d.isRevoked).length
    },
    todayActivations: (db.logs||[]).filter(l => l.action === 'activate' && l.result === 'ok' && l.ts > Date.now() - 86400000).length,
    recentLogs
  });
});

// ── Admin dashboard HTML ───────────────────────────────────────────────────
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['x-admin-key'];
  if (token !== ADMIN_SECRET)
    return res.status(401).send(`<html><body style="font-family:sans-serif;padding:40px;background:#060d19;color:#e2eaf4">
      <h2 style="color:#00c9a7">💊 Medishop License Server</h2>
      <p>Access requires admin token: <code style="background:#111;padding:4px 8px;border-radius:4px">/?token=YOUR_SECRET</code></p>
    </body></html>`);

  res.send(`<!DOCTYPE html>
<html><head><title>Medishop License Admin</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#060d19;color:#e2eaf4;padding:24px}
h1{color:#00c9a7;margin-bottom:20px}h2{font-size:16px;margin:20px 0 12px;color:#7dd3fc}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.stat{background:#0c1a2e;border:1px solid #1a3050;border-radius:10px;padding:16px 20px;min-width:130px}
.stat-label{font-size:11px;color:#6b8ab0;text-transform:uppercase;font-weight:700;margin-bottom:6px}
.stat-val{font-size:26px;font-weight:800;color:#00c9a7}
.card{background:#0c1a2e;border:1px solid #1a3050;border-radius:10px;padding:20px;margin-bottom:20px}
input,select{background:#111f35;border:1px solid #1a3050;color:#e2eaf4;padding:9px 12px;border-radius:7px;font-size:13px;outline:none;margin-right:8px;margin-bottom:8px}
input:focus{border-color:#00c9a7}
.btn{padding:9px 16px;border-radius:7px;border:none;cursor:pointer;font-size:13px;font-weight:700;margin-right:6px;margin-bottom:6px}
.btn-green{background:#00c9a7;color:#000}.btn-red{background:#ef4444;color:#fff}
.btn-blue{background:#0ea5e9;color:#fff}.btn-gray{background:#1a3050;color:#e2eaf4}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:8px 10px;text-align:left;color:#6b8ab0;font-size:10px;text-transform:uppercase;border-bottom:1px solid #1a3050}
td{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.04)}
tr:hover td{background:rgba(0,201,167,.03)}
.badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.badge-full{background:rgba(34,197,94,.12);color:#22c55e}
.badge-trial{background:rgba(245,158,11,.14);color:#f59e0b}
.badge-ok{background:rgba(0,201,167,.12);color:#00c9a7}
.badge-revoked{background:rgba(239,68,68,.12);color:#ef4444}
.mono{font-family:monospace;color:#00c9a7;font-size:11px}
#keyOut{background:#111f35;border:2px solid #00c9a7;border-radius:8px;padding:16px;margin-top:14px;display:none;text-align:center}
#keyText{font-family:monospace;font-size:20px;font-weight:700;color:#00c9a7;letter-spacing:.06em;word-break:break-all}
</style></head>
<body>
<h1>💊 Medishop License Admin</h1>
<div id="stats" class="stats">Loading...</div>

<div class="card">
  <h2>✨ Generate License Key</h2>
  <input type="email" id="genEmail" placeholder="customer@email.com" style="min-width:220px">
  <select id="genType"><option value="full">Full License (Permanent)</option><option value="trial">Trial (${TRIAL_DAYS} Days)</option></select>
  <input type="number" id="genDevices" value="1" min="1" max="10" style="width:70px" placeholder="Devices">
  <input type="text" id="genNotes" placeholder="Notes (shop name, city...)" style="min-width:200px">
  <button class="btn btn-green" onclick="genKey()">✨ Generate &amp; Register</button>
  <div id="keyOut"><div id="keyText"></div>
    <div id="keyMeta" style="font-size:12px;color:#6b8ab0;margin-top:8px"></div>
    <button class="btn btn-gray" style="margin-top:10px;width:100%" onclick="copyKey()">📋 Copy Key</button>
  </div>
</div>

<div class="card">
  <h2>🔑 All License Keys</h2>
  <button class="btn btn-blue" onclick="loadKeys()">↻ Refresh</button>
  <div class="table-wrap" style="overflow-x:auto;margin-top:12px">
  <table><thead><tr><th>Key</th><th>Email</th><th>Type</th><th>Devices</th><th>Days Left</th><th>Status</th><th>Actions</th></tr></thead>
  <tbody id="keysTable"><tr><td colspan="7" style="text-align:center;padding:20px;color:#6b8ab0">Loading...</td></tr></tbody></table>
  </div>
</div>

<script>
const TOKEN = '${ADMIN_SECRET}';
const BASE  = location.origin;
function api(method, path, body) {
  return fetch(BASE + path, {
    method, headers: { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  }).then(r => r.json());
}
function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(+ts).toLocaleDateString('en-IN');
}

async function loadStats() {
  const r = await api('GET', '/admin/dashboard');
  if (!r.success) return;
  const s = r.stats;
  document.getElementById('stats').innerHTML = [
    ['Total Keys', s.totalKeys], ['Full', s.fullKeys], ['Trial', s.trialKeys],
    ['Active Devices', s.totalDevices], ["Today's Activations", r.todayActivations]
  ].map(([l,v]) => '<div class="stat"><div class="stat-label">'+l+'</div><div class="stat-val">'+v+'</div></div>').join('');
}

async function loadKeys() {
  const r = await api('GET', '/admin/keys');
  const tbody = document.getElementById('keysTable');
  if (!r.success || !r.keys.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;color:#6b8ab0">No keys yet</td></tr>';
    return;
  }
  tbody.innerHTML = r.keys.map(k => {
    const typeBadge = k.type === 'full' ? '<span class="badge badge-full">FULL</span>' : '<span class="badge badge-trial">TRIAL</span>';
    const statusBadge = k.isActive ? '<span class="badge badge-ok">Active</span>' : '<span class="badge badge-revoked">Revoked</span>';
    const days = k.type === 'trial' ? (k.isExpired ? '<span style="color:#ef4444">Expired</span>' : (k.daysLeft ?? '—') + 'd') : '♾';
    return '<tr>' +
      '<td class="mono">' + k.key + '</td>' +
      '<td style="color:#6b8ab0">' + k.email + '</td>' +
      '<td>' + typeBadge + '</td>' +
      '<td style="text-align:center">' + k.deviceCount + '/' + k.maxDevices + '</td>' +
      '<td>' + days + '</td>' +
      '<td>' + statusBadge + '</td>' +
      '<td>' +
        (k.isActive
          ? '<button class="btn btn-red" onclick="revokeKey(\''+k.hash+'\')">Revoke</button>'
          : '<button class="btn btn-green" onclick="restoreKey(\''+k.hash+'\')">Restore</button>') +
        '<button class="btn btn-gray" onclick="freeSlots(\''+k.hash+'\')">Free Slots</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

async function genKey() {
  const email = document.getElementById('genEmail').value.trim();
  const type  = document.getElementById('genType').value;
  const max   = document.getElementById('genDevices').value;
  const notes = document.getElementById('genNotes').value.trim();
  if (!email) { alert('Email required'); return; }
  const r = await api('POST', '/admin/keys/generate', { email, type, maxDevices: max, notes });
  if (r.success) {
    document.getElementById('keyText').textContent = r.key;
    document.getElementById('keyMeta').textContent = type.toUpperCase() + ' | ' + r.email + ' | ' + r.maxDevices + ' device(s)';
    document.getElementById('keyOut').style.display = 'block';
    loadKeys(); loadStats();
  } else { alert('Error: ' + r.error); }
}

function copyKey() {
  navigator.clipboard.writeText(document.getElementById('keyText').textContent)
    .then(() => alert('Key copied to clipboard!'));
}

async function revokeKey(hash) {
  if (!confirm('Revoke this license?')) return;
  await api('POST', '/admin/keys/' + hash + '/revoke');
  loadKeys();
}

async function restoreKey(hash) {
  await api('POST', '/admin/keys/' + hash + '/restore');
  loadKeys();
}

async function freeSlots(hash) {
  if (!confirm('Remove all device activations for this key?')) return;
  await api('POST', '/admin/devices/' + hash + '/transfer-all');
  loadKeys();
}

loadStats(); loadKeys();
</script>
</body></html>`);
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════╗`);
  console.log(`║   💊  Medishop License Server v2.0            ║`);
  console.log(`╠══════════════════════════════════════════════╣`);
  console.log(`║  Port   : ${PORT}`);
  console.log(`║  Health : http://localhost:${PORT}/health`);
  console.log(`║  Admin  : http://localhost:${PORT}/?token=${ADMIN_SECRET}`);
  console.log(`╚══════════════════════════════════════════════╝\n`);
});
