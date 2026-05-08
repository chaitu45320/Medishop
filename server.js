/**
 * server.js — Medishop License Server v3.1
 * Single file, zero native deps (only express + jsonwebtoken).
 * Procfile: web: node server.js
 *
 * Railway env vars used:
 *   PORT            — set automatically by Railway
 *   API_SECRET      — admin dashboard password  (MediShop@Chaitanya2024)
 *   ADMIN_KEY       — same as API_SECRET alias   (MediShop@Admin2024)
 *   LICENSE_SECRET  — HMAC key for key generation
 *   JWT_SECRET      — JWT signing key
 *   TRIAL_DAYS      — default 30
 *   MAX_DEVICES     — default 1
 *
 * API CONTRACT (Electron client ↔ server):
 *   POST /api/activate      { licenseKey, email, deviceId, deviceName, appVersion }
 *   POST /api/validate      { token, deviceId }
 *   GET  /api/validate      ?token=...&machine_id=...   (legacy fallback)
 *   POST /api/deactivate    { token, deviceId }
 *   GET  /health
 *
 * ADMIN (Authorization: Bearer API_SECRET or ADMIN_KEY):
 *   GET  /admin/dashboard
 *   GET  /admin/keys
 *   GET  /admin/keys/:hash
 *   POST /admin/keys/generate
 *   POST /admin/keys/:hash/revoke
 *   POST /admin/keys/:hash/restore
 *   POST /admin/devices/:hash/transfer-all
 *   POST /admin/devices/:hash/:did/revoke
 *   POST /admin/devices/:hash/:did/transfer
 *   POST /admin/verify
 *   GET  /admin/suspicious
 *   GET  /admin/logs
 *   GET  /admin/export
 *   GET  /  (dashboard HTML, ?token=API_SECRET)
 */

'use strict';

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ── Config — reads from Railway env vars ────────────────────────────────────
const PORT           = process.env.PORT           || 3000;
// Accept either API_SECRET or ADMIN_KEY as the admin password
const API_SECRET     = process.env.API_SECRET     || process.env.ADMIN_KEY || 'ms_admin_2024_secure';
const ADMIN_KEY      = process.env.ADMIN_KEY      || API_SECRET;
const JWT_SECRET     = process.env.JWT_SECRET     || 'MS_JWT_Medishop_2024_Ultra_Secure_Key_99';
const LIC_SECRET     = process.env.LICENSE_SECRET || 'MS@Medishop#2024!PharmacyBilling$Key@Secure99';
const TRIAL_DAYS     = parseInt(process.env.TRIAL_DAYS   || '30');
const MAX_DEVICES    = parseInt(process.env.MAX_DEVICES  || '1');
const APP_PREFIX     = 'MEDSHP';
const CHARS          = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// ── CORS ────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Key');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

// ── Logger ──────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path !== '/health' && req.path !== '/favicon.ico')
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ── Data directory + JSON DB ─────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const DB_FILE = path.join(dataDir, 'licenses.db.json');

/**
 * DB schema:
 * {
 *   keys: {
 *     [keyHash]: {
 *       key, email, type, maxDevices, isActive, issuedAt, notes,
 *       activations: {
 *         [deviceId]: { deviceId, deviceName, appVersion, activatedAt, lastSeen, isRevoked }
 *       }
 *     }
 *   },
 *   logs: [{ keyHash, deviceId, ip, action, result, detail, ts }]
 * }
 */
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { keys: {}, logs: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { console.error('[DB] Parse error, resetting:', e.message); return { keys: {}, logs: [] }; }
}

function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
  catch(e) { console.error('[DB] Save error:', e.message); }
}

function dbLog(db, keyHash, deviceId, ip, action, result, detail) {
  if (!db.logs) db.logs = [];
  db.logs.unshift({
    keyHash:  keyHash  || '',
    deviceId: deviceId || '',
    ip:       ip       || '',
    action, result,
    detail:   detail   || '',
    ts: Date.now()
  });
  if (db.logs.length > 3000) db.logs = db.logs.slice(0, 3000);
}

// ── Crypto helpers ───────────────────────────────────────────────────────────
function hmacSeg(data, len) {
  const bytes = crypto.createHmac('sha256', LIC_SECRET).update(data).digest();
  let r = '';
  for (let i = 0; i < bytes.length && r.length < len; i++)
    r += CHARS[bytes[i] % CHARS.length];
  return r;
}

function randSeg(prefix) {
  let r = prefix || '';
  while (r.length < 6) r += CHARS[Math.floor(Math.random() * CHARS.length)];
  return r.substring(0, 6);
}

function generateKey(type) {
  const typeCode = type === 'full' ? 'FULL' : 'TRAL';
  const typeFlag = type === 'full' ? 'F'    : 'T';
  const seg1 = randSeg(typeFlag);
  const seg2 = randSeg();
  const seg3 = hmacSeg(`${seg1}-${seg2}`, 6);
  return `${APP_PREFIX}-${typeCode}-${seg1}-${seg2}-${seg3}`;
}

function validateKeyFormat(licenseKey) {
  const parts = licenseKey.trim().toUpperCase().split('-');
  if (parts.length !== 5)
    return { valid: false, reason: 'Key must have 5 segments (e.g. MEDSHP-FULL-XXXXXX-XXXXXX-XXXXXX)' };
  if (parts[0] !== APP_PREFIX)
    return { valid: false, reason: `Key must start with ${APP_PREFIX}` };
  if (!['FULL', 'TRAL'].includes(parts[1]))
    return { valid: false, reason: 'Second segment must be FULL or TRAL' };
  if ([parts[2], parts[3], parts[4]].some(s => s.length !== 6))
    return { valid: false, reason: 'Each segment must be exactly 6 characters' };
  const [, typeCode, seg1, seg2, seg3] = parts;
  if (seg3 !== hmacSeg(`${seg1}-${seg2}`, 6))
    return { valid: false, reason: 'Invalid key — checksum mismatch' };
  if (typeCode === 'FULL' && seg1[0] !== 'F')
    return { valid: false, reason: 'Type flag mismatch' };
  if (typeCode === 'TRAL' && seg1[0] !== 'T')
    return { valid: false, reason: 'Type flag mismatch' };
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

// ── Admin auth — accepts API_SECRET or ADMIN_KEY ─────────────────────────────
function adminAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim()
    || (req.headers['x-admin-key'] || '').trim()
    || (req.query.token || '').trim();
  if (token === API_SECRET || token === ADMIN_KEY) { next(); return; }
  res.status(401).json({ success: false, error: 'Unauthorized — invalid admin token' });
}

// ── Enrich key for admin responses ───────────────────────────────────────────
function enrichKey(keyHash, keyRec, db) {
  const activations = Object.values(keyRec.activations || {});
  const activeDevs  = activations.filter(d => !d.isRevoked);
  const firstAt     = activeDevs.length ? Math.min(...activeDevs.map(d => d.activatedAt)) : null;
  const failCount   = (db.logs || []).filter(l => l.keyHash === keyHash && l.result.startsWith('fail')).length;
  return {
    key_hash:       keyHash,
    key_display:    keyRec.key,
    email:          keyRec.email,
    type:           keyRec.type,
    max_devices:    keyRec.maxDevices || MAX_DEVICES,
    is_active:      keyRec.isActive ? 1 : 0,
    issued_at:      keyRec.issuedAt,
    notes:          keyRec.notes || '',
    active_devices: activeDevs.length,
    fail_count:     failCount,
    daysLeft:       getDaysLeft(firstAt, keyRec.type),
    isExpired:      keyRec.type === 'trial' ? isTrialExpired(firstAt, 'trial') : false
  };
}

// ════════════════════════════════════════════════════════════════════════════
//  PUBLIC API ROUTES
// ════════════════════════════════════════════════════════════════════════════

// ── POST /api/activate ───────────────────────────────────────────────────────
app.post('/api/activate', (req, res) => {
  const { licenseKey, email, deviceId, deviceName, appVersion } = req.body;
  const ip = req.ip || '';

  console.log('[ACTIVATE]', licenseKey, '|', email, '|', deviceId);

  if (!licenseKey) return res.status(400).json({ success: false, error: 'licenseKey is required' });
  if (!email)      return res.status(400).json({ success: false, error: 'email is required' });
  if (!deviceId)   return res.status(400).json({ success: false, error: 'deviceId is required' });

  const key     = licenseKey.trim().toUpperCase();
  const emailLc = email.trim().toLowerCase();
  const fmt     = validateKeyFormat(key);

  if (!fmt.valid)
    return res.status(400).json({ success: false, error: 'Invalid license key: ' + fmt.reason });

  const db      = loadDB();
  const keyHash = hashKey(key);
  const keyRec  = db.keys?.[keyHash];

  if (!keyRec) {
    dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_notfound', 'Key not found');
    saveDB(db);
    return res.status(404).json({
      success: false,
      error: 'License key not found. Contact Medishop support at 9985223448.'
    });
  }

  if (!keyRec.isActive) {
    dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_revoked', 'Key revoked');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'This license has been revoked. Contact support.' });
  }

  if (keyRec.email !== emailLc) {
    dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_email', 'Email mismatch');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'This key is registered to a different email address.' });
  }

  if (!keyRec.activations) keyRec.activations = {};
  const existing = keyRec.activations[deviceId];

  // ── Re-activation on same device ──────────────────────────────────────────
  if (existing) {
    if (existing.isRevoked) {
      dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_device_revoked', 'Device revoked');
      saveDB(db);
      return res.status(403).json({ success: false, error: 'This device has been revoked. Contact support.' });
    }
    if (keyRec.type === 'trial' && isTrialExpired(existing.activatedAt, 'trial')) {
      dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_expired', 'Trial expired');
      saveDB(db);
      return res.status(403).json({
        success: false,
        error: 'Trial license has expired. Upgrade to a full license — call 9985223448.'
      });
    }
    const token    = signJWT({ keyHash, deviceId, type: keyRec.type, email: emailLc });
    const daysLeft = getDaysLeft(existing.activatedAt, keyRec.type);
    existing.lastSeen   = Date.now();
    existing.deviceName = deviceName || existing.deviceName;
    existing.appVersion = appVersion || existing.appVersion;
    dbLog(db, keyHash, deviceId, ip, 'reactivate', 'ok', deviceName || '');
    saveDB(db);
    console.log('[ACTIVATE] Re-activation OK — type:', keyRec.type, 'daysLeft:', daysLeft);
    return res.json({ success: true, token, type: keyRec.type, daysLeft, email: emailLc,
      message: 'License verified successfully' });
  }

  // ── First activation — check trial not expired before any use ─────────────
  if (keyRec.type === 'trial' && isTrialExpired(keyRec.issuedAt, 'trial')) {
    dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_expired', 'Trial expired before use');
    saveDB(db);
    return res.status(403).json({ success: false, error: 'Trial license has expired before first use.' });
  }

  // ── Device limit check ────────────────────────────────────────────────────
  const activeDevs = Object.values(keyRec.activations).filter(d => !d.isRevoked);
  const maxDevs    = keyRec.maxDevices || MAX_DEVICES;
  if (activeDevs.length >= maxDevs) {
    const names = activeDevs.map(d => d.deviceName || d.deviceId).join(', ');
    dbLog(db, keyHash, deviceId, ip, 'activate', 'fail_limit', 'Device limit: ' + names);
    saveDB(db);
    return res.status(409).json({
      success: false, code: 'DEVICE_LIMIT',
      error: `License already active on ${activeDevs.length} device(s): ${names}. Contact support to transfer.`
    });
  }

  // ── New activation ────────────────────────────────────────────────────────
  const now      = Date.now();
  const token    = signJWT({ keyHash, deviceId, type: keyRec.type, email: emailLc });
  const daysLeft = getDaysLeft(now, keyRec.type);

  keyRec.activations[deviceId] = {
    deviceId,
    deviceName:  deviceName || 'Unknown Device',
    appVersion:  appVersion || '1.0.0',
    activatedAt: now,
    lastSeen:    now,
    isRevoked:   false
  };

  dbLog(db, keyHash, deviceId, ip, 'activate', 'ok', deviceName || '');
  saveDB(db);
  console.log('[ACTIVATE] New activation — type:', keyRec.type, 'daysLeft:', daysLeft);

  return res.json({
    success: true, token, type: keyRec.type, daysLeft,
    activatedAt: now, email: emailLc,
    message: keyRec.type === 'full'
      ? 'Full license activated successfully!'
      : `Trial license activated — ${daysLeft} day(s) remaining.`
  });
});

// ── Validate handler (shared by POST and GET) ────────────────────────────────
function handleValidate(tokenStr, deviceId, res, db, ip) {
  if (!tokenStr || !deviceId)
    return res.status(400).json({ success: false, active: false, error: 'token and deviceId are required' });

  const payload = verifyJWT(tokenStr);
  if (!payload || payload.deviceId !== deviceId)
    return res.status(401).json({ success: false, active: false, error: 'Invalid or expired token' });

  const { keyHash } = payload;
  const keyRec      = db.keys?.[keyHash];
  const activation  = keyRec?.activations?.[deviceId];

  if (!activation || activation.isRevoked) {
    dbLog(db, keyHash, deviceId, ip, 'validate', 'fail_device', 'Not activated or revoked');
    saveDB(db);
    return res.status(401).json({ success: false, active: false, error: 'Device not authorized' });
  }

  if (!keyRec || !keyRec.isActive) {
    dbLog(db, keyHash, deviceId, ip, 'validate', 'fail_inactive', 'License inactive');
    saveDB(db);
    return res.status(403).json({ success: false, active: false, error: 'License has been deactivated' });
  }

  if (keyRec.type === 'trial' && isTrialExpired(activation.activatedAt, 'trial')) {
    dbLog(db, keyHash, deviceId, ip, 'validate', 'fail_expired', 'Trial expired');
    saveDB(db);
    return res.status(403).json({ success: false, active: false, error: 'Trial license has expired' });
  }

  activation.lastSeen = Date.now();
  dbLog(db, keyHash, deviceId, ip, 'validate', 'ok', '');
  saveDB(db);

  const daysLeft = getDaysLeft(activation.activatedAt, keyRec.type);
  console.log('[VALIDATE] OK — type:', keyRec.type, 'daysLeft:', daysLeft);
  return res.json({ success: true, valid: true, active: true,
    type: keyRec.type, daysLeft, email: keyRec.email });
}

// ── POST /api/validate  { token, deviceId } ──────────────────────────────────
app.post('/api/validate', (req, res) => {
  const db = loadDB();
  handleValidate(req.body.token, req.body.deviceId, res, db, req.ip || '');
});

// ── GET /api/validate?token=...&machine_id=...  (legacy Electron client) ──────
app.get('/api/validate', (req, res) => {
  const db = loadDB();
  handleValidate(
    req.query.token,
    req.query.machine_id || req.query.deviceId,
    res, db, req.ip || ''
  );
});

// ── POST /api/deactivate  { token, deviceId } ────────────────────────────────
app.post('/api/deactivate', (req, res) => {
  const { token, deviceId } = req.body;
  if (!token || !deviceId)
    return res.status(400).json({ success: false, error: 'token and deviceId are required' });

  const payload = verifyJWT(token);
  if (!payload || payload.deviceId !== deviceId)
    return res.status(401).json({ success: false, error: 'Invalid token' });

  const db = loadDB();
  const { keyHash } = payload;
  if (db.keys?.[keyHash]?.activations?.[deviceId]) {
    delete db.keys[keyHash].activations[deviceId];
    dbLog(db, keyHash, deviceId, req.ip || '', 'deactivate', 'ok', 'Self deactivated');
    saveDB(db);
  }
  console.log('[DEACTIVATE] Device freed:', deviceId);
  return res.json({ success: true, message: 'Device deactivated. License slot is now free.' });
});

// ── GET /health ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  const db    = loadDB();
  const keys  = Object.values(db.keys || {});
  const devs  = keys.reduce((n, k) => n + Object.values(k.activations || {}).filter(d => !d.isRevoked).length, 0);
  res.json({
    status:      'ok',
    service:     'Medishop License Server',
    version:     '3.1.0',
    timestamp:   new Date().toISOString(),
    keys:        keys.length,
    activations: devs,
    trial_days:  TRIAL_DAYS,
    max_devices: MAX_DEVICES
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════════════════════════════════

// ── GET /admin/dashboard ─────────────────────────────────────────────────────
app.get('/admin/dashboard', adminAuth, (req, res) => {
  const db     = loadDB();
  const keys   = Object.values(db.keys || {});
  const allDevs = keys.flatMap(k => Object.values(k.activations || {}));
  const today   = Date.now() - 86400000;
  const todayActs = (db.logs || []).filter(l => l.action === 'activate' && l.result === 'ok' && l.ts > today).length;
  const recentKeys = Object.entries(db.keys || {})
    .sort((a, b) => b[1].issuedAt - a[1].issuedAt)
    .slice(0, 10)
    .map(([h, k]) => enrichKey(h, k, db));

  res.json({
    success: true,
    stats: {
      totalKeys:    keys.length,
      fullKeys:     keys.filter(k => k.type === 'full').length,
      trialKeys:    keys.filter(k => k.type === 'trial').length,
      activeKeys:   keys.filter(k => k.isActive).length,
      totalDevices: allDevs.filter(d => !d.isRevoked).length
    },
    todayActivations: todayActs,
    recentKeys
  });
});

// ── GET /admin/keys ──────────────────────────────────────────────────────────
app.get('/admin/keys', adminAuth, (req, res) => {
  const db   = loadDB();
  const keys = Object.entries(db.keys || {})
    .map(([h, k]) => enrichKey(h, k, db))
    .sort((a, b) => b.issued_at - a.issued_at);
  res.json({ success: true, keys, total: keys.length });
});

// ── GET /admin/keys/:hash ────────────────────────────────────────────────────
app.get('/admin/keys/:hash', adminAuth, (req, res) => {
  const db     = loadDB();
  const keyRec = db.keys?.[req.params.hash];
  if (!keyRec) return res.status(404).json({ success: false, error: 'Key not found' });

  const activations = Object.values(keyRec.activations || {});
  const activeDevs  = activations.filter(d => !d.isRevoked);
  const firstAt     = activeDevs.length ? Math.min(...activeDevs.map(d => d.activatedAt)) : null;
  const logs        = (db.logs || []).filter(l => l.keyHash === req.params.hash).slice(0, 50);

  const devices = activations.map(d => ({
    device_id:    d.deviceId,
    device_name:  d.deviceName,
    app_version:  d.appVersion,
    activated_at: d.activatedAt,
    last_seen:    d.lastSeen,
    is_revoked:   d.isRevoked ? 1 : 0
  }));

  res.json({
    success: true,
    key: {
      key_hash:    req.params.hash,
      key_display: keyRec.key,
      email:       keyRec.email,
      type:        keyRec.type,
      max_devices: keyRec.maxDevices || MAX_DEVICES,
      is_active:   keyRec.isActive ? 1 : 0,
      issued_at:   keyRec.issuedAt,
      notes:       keyRec.notes || '',
      daysLeft:    getDaysLeft(firstAt, keyRec.type),
      isExpired:   keyRec.type === 'trial' ? isTrialExpired(firstAt, 'trial') : false
    },
    devices,
    logs
  });
});

// ── POST /admin/keys/generate ────────────────────────────────────────────────
// NOTE: this route MUST be defined before /admin/keys/:hash to avoid conflict
app.post('/admin/keys/generate', adminAuth, (req, res) => {
  const { email, type, maxDevices, notes } = req.body;
  if (!email || !type)
    return res.status(400).json({ success: false, error: 'email and type are required' });
  if (!['full', 'trial'].includes(type))
    return res.status(400).json({ success: false, error: 'type must be "full" or "trial"' });

  const key     = generateKey(type);
  const keyHash = hashKey(key);
  const db      = loadDB();
  if (!db.keys) db.keys = {};

  const maxDev = parseInt(maxDevices) || MAX_DEVICES;
  db.keys[keyHash] = {
    key,
    email:       email.trim().toLowerCase(),
    type,
    maxDevices:  maxDev,
    isActive:    true,
    issuedAt:    Date.now(),
    notes:       notes || '',
    activations: {}
  };

  saveDB(db);
  console.log('[ADMIN] Generated:', key, '|', type, '|', email);
  res.json({ success: true, key, type, email: email.trim().toLowerCase(), maxDevices: maxDev });
});

// ── POST /admin/keys/:hash/revoke ────────────────────────────────────────────
app.post('/admin/keys/:hash/revoke', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys?.[req.params.hash])
    return res.status(404).json({ success: false, error: 'Key not found' });
  db.keys[req.params.hash].isActive = false;
  dbLog(db, req.params.hash, '', req.ip || '', 'admin_revoke', 'ok', 'Admin revoked');
  saveDB(db);
  res.json({ success: true, message: 'License revoked. Devices will be blocked on next check.' });
});

// ── POST /admin/keys/:hash/restore ───────────────────────────────────────────
app.post('/admin/keys/:hash/restore', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys?.[req.params.hash])
    return res.status(404).json({ success: false, error: 'Key not found' });
  db.keys[req.params.hash].isActive = true;
  dbLog(db, req.params.hash, '', req.ip || '', 'admin_restore', 'ok', 'Admin restored');
  saveDB(db);
  res.json({ success: true, message: 'License restored.' });
});

// ── POST /admin/devices/:hash/transfer-all ───────────────────────────────────
app.post('/admin/devices/:hash/transfer-all', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys?.[req.params.hash])
    return res.status(404).json({ success: false, error: 'Key not found' });
  db.keys[req.params.hash].activations = {};
  dbLog(db, req.params.hash, '', req.ip || '', 'admin_transfer_all', 'ok', 'All devices cleared');
  saveDB(db);
  res.json({ success: true, message: 'All device slots freed. Ready for fresh activation.' });
});

// ── POST /admin/devices/:hash/:did/revoke ────────────────────────────────────
app.post('/admin/devices/:hash/:did/revoke', adminAuth, (req, res) => {
  const db  = loadDB();
  const dev = db.keys?.[req.params.hash]?.activations?.[req.params.did];
  if (dev) {
    dev.isRevoked = true;
    dbLog(db, req.params.hash, req.params.did, req.ip || '', 'admin_device_revoke', 'ok', 'Revoked');
    saveDB(db);
  }
  res.json({ success: true, message: 'Device revoked.' });
});

// ── POST /admin/devices/:hash/:did/transfer ──────────────────────────────────
app.post('/admin/devices/:hash/:did/transfer', adminAuth, (req, res) => {
  const db = loadDB();
  if (db.keys?.[req.params.hash]?.activations?.[req.params.did]) {
    delete db.keys[req.params.hash].activations[req.params.did];
    dbLog(db, req.params.hash, req.params.did, req.ip || '', 'admin_transfer', 'ok', 'Slot freed');
    saveDB(db);
  }
  res.json({ success: true, message: 'Device slot freed.' });
});

// ── POST /admin/verify ───────────────────────────────────────────────────────
app.post('/admin/verify', adminAuth, (req, res) => {
  const key = (req.body.licenseKey || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ success: false, error: 'licenseKey required' });

  const fmt = validateKeyFormat(key);
  if (!fmt.valid) return res.status(400).json({ success: false, error: 'Invalid format: ' + fmt.reason });

  const db      = loadDB();
  const keyHash = hashKey(key);
  const keyRec  = db.keys?.[keyHash];
  if (!keyRec)
    return res.status(404).json({ success: false, error: 'Key not found. Generate it in admin first.' });

  const activations = Object.values(keyRec.activations || {});
  const activeDevs  = activations.filter(d => !d.isRevoked);
  const firstAt     = activeDevs.length ? Math.min(...activeDevs.map(d => d.activatedAt)) : null;

  res.json({
    success:     true,
    type:        keyRec.type,
    email:       keyRec.email,
    daysLeft:    getDaysLeft(firstAt, keyRec.type),
    isExpired:   isTrialExpired(firstAt, keyRec.type),
    isActive:    !!keyRec.isActive,
    deviceCount: activeDevs.length,
    maxDevices:  keyRec.maxDevices || MAX_DEVICES,
    keyHash,
    devices: activations.map(d => ({
      deviceId:    d.deviceId,
      deviceName:  d.deviceName,
      activatedAt: d.activatedAt,
      lastSeen:    d.lastSeen,
      isRevoked:   d.isRevoked
    }))
  });
});

// ── GET /admin/suspicious ────────────────────────────────────────────────────
app.get('/admin/suspicious', adminAuth, (req, res) => {
  const db      = loadDB();
  const failMap = {};
  (db.logs || []).filter(l => l.result.startsWith('fail')).forEach(l => {
    const h = l.keyHash || 'unknown';
    if (!failMap[h]) failMap[h] = { keyHash: h, failCount: 0, lastAttempt: 0, ips: new Set() };
    failMap[h].failCount++;
    if (l.ts > failMap[h].lastAttempt) failMap[h].lastAttempt = l.ts;
    if (l.ip) failMap[h].ips.add(l.ip);
  });

  const suspicious = Object.values(failMap)
    .filter(e => e.failCount >= 3)
    .sort((a, b) => b.failCount - a.failCount)
    .map(e => {
      const k = db.keys?.[e.keyHash];
      return {
        key_hash:     e.keyHash,
        key_display:  k?.key || e.keyHash.substring(0, 12) + '…',
        email:        k?.email || '—',
        type:         k?.type  || '—',
        fail_count:   e.failCount,
        last_attempt: e.lastAttempt,
        ips:          [...e.ips].join(', ')
      };
    });

  res.json({ success: true, suspicious, count: suspicious.length });
});

// ── GET /admin/logs ──────────────────────────────────────────────────────────
app.get('/admin/logs', adminAuth, (req, res) => {
  const db     = loadDB();
  const limit  = Math.min(parseInt(req.query.limit) || 200, 1000);
  const action = req.query.action || '';
  let logs     = db.logs || [];
  if (action) logs = logs.filter(l => l.action === action);
  res.json({
    success: true,
    logs:    logs.slice(0, limit).map(l => ({ ...l, key_hash: l.keyHash, device_id: l.deviceId })),
    count:   Math.min(logs.length, limit)
  });
});

// ── GET /admin/export ────────────────────────────────────────────────────────
app.get('/admin/export', adminAuth, (req, res) => {
  const db = loadDB();
  res.setHeader('Content-Disposition', `attachment; filename="medishop-licenses-${Date.now()}.json"`);
  res.json({ exportedAt: new Date().toISOString(), application: 'Medishop License Server v3.1', ...db });
});

// ════════════════════════════════════════════════════════════════════════════
//  ADMIN DASHBOARD HTML  GET /
// ════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  const token = (req.query.token || req.headers['x-admin-key'] || '').trim();
  if (token !== API_SECRET && token !== ADMIN_KEY) {
    return res.status(401).send(`<!DOCTYPE html>
<html><head><title>Medishop License Admin</title>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{background:#060d19;color:#e2e8f0;font-family:'Segoe UI',sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px;text-align:center;padding:24px}
h2{font-size:22px;color:#00c9a7}p{color:#6b8ab0;font-size:14px;max-width:420px}
code{background:#0c1a2e;padding:4px 10px;border-radius:6px;font-family:monospace;color:#7dd3fc;font-size:13px}
</style></head><body>
<div style="font-size:52px">💊</div>
<h2>Medishop License Admin</h2>
<p>Access requires a valid admin token.</p>
<p>URL format:<br><code>https://your-app.railway.app/?token=YOUR_API_SECRET</code></p>
</body></html>`);
  }

  // Check if external dashboard.html exists (from public/ folder)
  const dashFile = path.join(__dirname, 'public', 'dashboard.html');
  if (fs.existsSync(dashFile)) return res.sendFile(dashFile);

  // Inline dashboard
  res.send(`<!DOCTYPE html>
<html><head><title>Medishop License Admin</title>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#060d19;color:#e2eaf4;padding:24px}
h1{color:#00c9a7;margin-bottom:20px;font-size:22px}h2{font-size:15px;margin:18px 0 10px;color:#7dd3fc}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.stat{background:#0c1a2e;border:1px solid #1a3050;border-radius:10px;padding:14px 18px;min-width:120px;border-top:3px solid #00c9a7}
.sl{font-size:10px;color:#6b8ab0;text-transform:uppercase;font-weight:700;margin-bottom:4px}
.sv{font-size:24px;font-weight:800;color:#00c9a7}
.card{background:#0c1a2e;border:1px solid #1a3050;border-radius:10px;padding:18px;margin-bottom:16px}
input,select{background:#111f35;border:1px solid #1a3050;color:#e2eaf4;padding:8px 11px;border-radius:7px;font-size:13px;outline:none;margin:3px}
input:focus{border-color:#00c9a7}
.btn{padding:8px 14px;border-radius:7px;border:none;cursor:pointer;font-size:13px;font-weight:700;margin:3px;transition:opacity .15s}
.btn:hover{opacity:.85}
.g{background:#00c9a7;color:#000}.r{background:#ef4444;color:#fff}
.b{background:#0ea5e9;color:#fff}.gr{background:#1a3050;color:#e2eaf4}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:7px 8px;text-align:left;color:#6b8ab0;font-size:10px;text-transform:uppercase;border-bottom:1px solid #1a3050}
td{padding:8px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
tr:hover td{background:rgba(0,201,167,.03)}
.mono{font-family:monospace;color:#00c9a7;font-size:11px}
.bf{background:rgba(34,197,94,.12);color:#22c55e;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:700}
.bt{background:rgba(245,158,11,.14);color:#f59e0b;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:700}
.ba{background:rgba(0,201,167,.12);color:#00c9a7;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:700}
.br{background:rgba(239,68,68,.12);color:#ef4444;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:700}
#kOut{background:#111f35;border:2px solid #00c9a7;border-radius:8px;padding:14px;margin-top:12px;display:none;text-align:center}
#kTxt{font-family:monospace;font-size:17px;font-weight:700;color:#00c9a7;word-break:break-all;letter-spacing:.04em}
.alert{padding:10px 14px;border-radius:8px;font-size:13px;margin-top:8px;display:none}
.alert.ok{background:rgba(34,197,94,.1);border:1px solid #22c55e;color:#22c55e;display:block}
.alert.err{background:rgba(239,68,68,.1);border:1px solid #ef4444;color:#ef4444;display:block}
.spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(0,201,167,.2);
  border-top-color:#00c9a7;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:5px}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head>
<body>
<h1>💊 Medishop License Admin</h1>
<div id="stats" class="stats">
  <div class="stat"><div class="sl">Loading…</div><div class="sv">…</div></div>
</div>

<div class="card">
  <h2>✨ Generate New License Key</h2>
  <input type="email" id="gEmail" placeholder="customer@email.com" style="min-width:200px"/>
  <select id="gType">
    <option value="full">Full License (Permanent)</option>
    <option value="trial">Trial (${TRIAL_DAYS} Days)</option>
  </select>
  <input type="number" id="gDev" value="${MAX_DEVICES}" min="1" max="5" style="width:65px" title="Max Devices"/>
  <input type="text" id="gNotes" placeholder="Notes (shop name, city…)" style="min-width:180px"/>
  <button class="btn g" id="gBtn" onclick="genKey()">✨ Generate &amp; Register</button>
  <div id="gAlert" class="alert"></div>
  <div id="kOut">
    <div id="kTxt"></div>
    <div id="kMeta" style="font-size:12px;color:#6b8ab0;margin-top:6px"></div>
    <button class="btn gr" style="margin-top:10px;width:100%" onclick="copyKey()">📋 Copy Key to Clipboard</button>
    <button class="btn g"  style="margin-top:6px;width:100%" onclick="waShare()">📱 Share via WhatsApp</button>
  </div>
</div>

<div class="card">
  <h2>🔑 All License Keys
    <button class="btn b" onclick="loadKeys()" style="font-size:11px;padding:4px 10px;margin-left:8px">↻ Refresh</button>
    <button class="btn gr" onclick="exportData()" style="font-size:11px;padding:4px 10px">⬇ Export</button>
  </h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>License Key</th><th>Email / Notes</th><th>Type</th>
      <th style="text-align:center">Devices</th><th>Days Left</th><th>Status</th><th>Actions</th>
    </tr></thead>
    <tbody id="kBody">
      <tr><td colspan="7" style="text-align:center;padding:20px;color:#6b8ab0">
        <span class="spinner"></span> Loading…
      </td></tr>
    </tbody>
  </table>
  </div>
</div>

<script>
const SECRET = '${API_SECRET}';
const BASE   = location.origin;

function api(m, p, b) {
  return fetch(BASE + '/admin' + p, {
    method: m,
    headers: { 'Authorization': 'Bearer ' + SECRET, 'Content-Type': 'application/json' },
    body: b ? JSON.stringify(b) : undefined
  }).then(r => r.json()).catch(e => ({ success: false, error: e.message }));
}

function fd(ts) {
  if (!ts) return '—';
  return new Date(+ts).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });
}

async function loadStats() {
  const r = await api('GET', '/dashboard');
  if (!r.success) return;
  const s = r.stats;
  document.getElementById('stats').innerHTML = [
    ['Total Keys',    s.totalKeys,    '#00c9a7'],
    ['Full',          s.fullKeys,     '#22c55e'],
    ['Trial',         s.trialKeys,    '#f59e0b'],
    ['Active Devices',s.totalDevices, '#0ea5e9'],
    ["Today's Acts",  r.todayActivations, '#a78bfa']
  ].map(([l,v,c]) =>
    '<div class="stat" style="border-top-color:'+c+'"><div class="sl">'+l+'</div><div class="sv" style="color:'+c+'">'+v+'</div></div>'
  ).join('');
}

async function loadKeys() {
  document.getElementById('kBody').innerHTML =
    '<tr><td colspan="7" style="text-align:center;padding:20px;color:#6b8ab0"><span class="spinner"></span> Loading…</td></tr>';
  const r = await api('GET', '/keys');
  if (!r.success || !r.keys.length) {
    document.getElementById('kBody').innerHTML =
      '<tr><td colspan="7" style="text-align:center;padding:20px;color:#6b8ab0">No keys yet. Generate one above.</td></tr>';
    return;
  }
  document.getElementById('kBody').innerHTML = r.keys.map(k => {
    const tb = k.type === 'full'
      ? '<span class="bf">✓ FULL</span>'
      : '<span class="bt">⏱ TRIAL</span>';
    const sb = k.is_active
      ? '<span class="ba">● Active</span>'
      : '<span class="br">● Revoked</span>';
    const dl = k.type === 'full' ? '♾' :
      (k.daysLeft <= 0 ? '<span style="color:#ef4444">Expired</span>' : k.daysLeft + 'd');
    const fails = k.fail_count > 2
      ? '<br><span style="color:#ef4444;font-size:10px">⚠ ' + k.fail_count + ' fails</span>' : '';
    return '<tr>' +
      '<td class="mono">' + k.key_display + '</td>' +
      '<td style="font-size:11px;color:#6b8ab0">' + k.email + (k.notes ? '<br><span style="color:#1a3050">' + k.notes + '</span>' : '') + '</td>' +
      '<td>' + tb + '</td>' +
      '<td style="text-align:center;font-weight:700">' + (k.active_devices||0) + '/' + k.max_devices + fails + '</td>' +
      '<td>' + dl + '</td>' +
      '<td>' + sb + '</td>' +
      '<td>' +
        (k.is_active
          ? '<button class="btn r" onclick="rk(\\''+k.key_hash+'\\')">Revoke</button>'
          : '<button class="btn g" onclick="rsk(\\''+k.key_hash+'\\')">Restore</button>') +
        '<button class="btn gr" onclick="ft(\\''+k.key_hash+'\\')">Free Slots</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

async function genKey() {
  const a = document.getElementById('gAlert');
  a.className = 'alert';
  const email = document.getElementById('gEmail').value.trim();
  if (!email) { a.textContent = 'Customer email is required.'; a.className = 'alert err'; return; }
  const btn = document.getElementById('gBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Generating…';
  const r = await api('POST', '/keys/generate', {
    email, type: document.getElementById('gType').value,
    maxDevices: document.getElementById('gDev').value,
    notes: document.getElementById('gNotes').value.trim()
  });
  btn.disabled = false; btn.textContent = '✨ Generate & Register';
  if (!r.success) { a.textContent = '❌ ' + r.error; a.className = 'alert err'; return; }
  document.getElementById('kTxt').textContent = r.key;
  document.getElementById('kMeta').textContent = r.type.toUpperCase() + ' | ' + r.email + ' | ' + r.maxDevices + ' device(s)';
  document.getElementById('kOut').style.display = 'block';
  a.textContent = '✅ Key generated and registered!'; a.className = 'alert ok';
  loadKeys(); loadStats();
}

function copyKey() {
  const k = document.getElementById('kTxt').textContent;
  navigator.clipboard.writeText(k).then(() => alert('Key copied: ' + k));
}

function waShare() {
  const k = document.getElementById('kTxt').textContent;
  const m = 'Your MediShop Pro license key:\\n\\n*' + k + '*\\n\\nActivate in the app under License Setup.\\nSupport: 9985223448';
  window.open('https://wa.me/?text=' + encodeURIComponent(m), '_blank');
}

function exportData() { window.open(BASE + '/admin/export', '_blank'); }

async function rk(h) {
  if (!confirm('Revoke this license? Devices will be blocked on next check.')) return;
  const r = await api('POST', '/keys/' + h + '/revoke');
  if (r.success) loadKeys();
}
async function rsk(h) {
  const r = await api('POST', '/keys/' + h + '/restore');
  if (r.success) loadKeys();
}
async function ft(h) {
  if (!confirm('Remove all device activations? Customer can activate on new device.')) return;
  const r = await api('POST', '/devices/' + h + '/transfer-all');
  if (r.success) loadKeys();
}

loadStats(); loadKeys();
</script>
</body></html>`);
});

// ── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) =>
  res.status(404).json({ success: false, error: 'Not found', path: req.path })
);

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n╔══════════════════════════════════════════════╗`);
  console.log(`║   💊  Medishop License Server v3.1            ║`);
  console.log(`╠══════════════════════════════════════════════╣`);
  console.log(`║  PORT         : ${PORT}`);
  console.log(`║  TRIAL_DAYS   : ${TRIAL_DAYS}`);
  console.log(`║  MAX_DEVICES  : ${MAX_DEVICES}`);
  console.log(`║  Health       : /health`);
  console.log(`║  Admin        : /?token=<API_SECRET>`);
  console.log(`╚══════════════════════════════════════════════╝\n`);
  console.log('  API_SECRET   set:', !!process.env.API_SECRET);
  console.log('  JWT_SECRET   set:', !!process.env.JWT_SECRET);
  console.log('  LIC_SECRET   set:', !!process.env.LICENSE_SECRET);
  console.log('');
});
