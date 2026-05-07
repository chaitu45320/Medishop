/**
 * routes/admin.js — Medishop Admin API
 * All endpoints require Bearer token
 *
 * POST /admin/keys/generate          — create new license key
 * GET  /admin/keys                   — list all keys
 * GET  /admin/keys/:hash             — single key detail + device history
 * POST /admin/keys/:hash/revoke      — revoke entire license
 * POST /admin/keys/:hash/restore     — restore revoked license
 * POST /admin/devices/:hash/:did/revoke    — revoke one device
 * POST /admin/devices/:hash/:did/transfer  — free up device slot
 * POST /admin/devices/:hash/transfer-all   — free all device slots
 * GET  /admin/suspicious             — keys with multiple failed activations
 * GET  /admin/dashboard              — stats + recent activity
 * GET  /admin/logs                   — full validation log
 * GET  /admin/export                 — download full DB as JSON
 * POST /admin/verify                 — verify a key manually
 */

const express = require('express');
const router  = express.Router();
const db      = require('../models/db');
const {
  generateKey, validateKey, hashKey, getDaysLeft, isTrialExpired, TRIAL_DAYS
} = require('../utils/license');

const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || '1');

// ── Auth middleware ───────────────────────────────────────────
router.use((req, res, next) => {
  const auth = req.headers['authorization'] || '';
  if (auth !== `Bearer ${process.env.API_SECRET || 'ms_admin_2024_secure'}`)
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  next();
});

// ── POST /admin/keys/generate ─────────────────────────────────
router.post('/keys/generate', (req, res) => {
  const { email, type, maxDevices, notes } = req.body;
  if (!email || !type)
    return res.status(400).json({ success: false, error: 'email and type required' });
  if (!['full','trial'].includes(type))
    return res.status(400).json({ success: false, error: 'type must be full or trial' });

  const key     = generateKey(type);
  const keyHash = hashKey(key);
  const max     = parseInt(maxDevices) || MAX_DEVICES;

  db.run(
    `INSERT INTO license_keys (key_hash,key_display,type,email,max_devices,is_active,issued_at,notes)
     VALUES (?,?,?,?,?,1,?,?)`,
    [keyHash, key, type, email.trim().toLowerCase(), max, Date.now(), notes || '']
  );

  console.log(`[KEY GENERATED] ${key} | ${type} | ${email}`);
  return res.json({
    success: true, key, type,
    email:   email.trim().toLowerCase(),
    maxDevices: max
  });
});

// ── POST /admin/verify ───────────────────────────────────────
router.post('/verify', (req, res) => {
  const key = (req.body.licenseKey || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ success: false, error: 'licenseKey required' });

  const v = validateKey(key);
  if (!v.valid) return res.status(400).json({ success: false, error: 'Invalid key format: ' + v.reason });

  const keyHash   = hashKey(key);
  const keyRecord = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [keyHash]);
  if (!keyRecord)
    return res.status(404).json({ success: false, error: 'Key not found. Generate it first via admin dashboard.' });

  const devices   = db.all('SELECT * FROM activations WHERE key_hash = ? ORDER BY activated_at DESC', [keyHash]);
  const daysLeft  = getDaysLeft(keyRecord.issued_at, keyRecord.type);
  const isExpired = keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at);

  return res.json({
    success:     true,
    type:        keyRecord.type,
    email:       keyRecord.email,
    daysLeft,
    isExpired,
    isActive:    !!keyRecord.is_active,
    deviceCount: devices.filter(d => !d.is_revoked).length,
    maxDevices:  keyRecord.max_devices,
    keyHash,
    devices:     devices.map(d => ({
      deviceId:    d.device_id,
      deviceName:  d.device_name,
      activatedAt: d.activated_at,
      lastSeen:    d.last_seen,
      isRevoked:   !!d.is_revoked
    }))
  });
});

// ── GET /admin/keys ───────────────────────────────────────────
router.get('/keys', (req, res) => {
  const keys = db.all(`
    SELECT k.*,
      (SELECT COUNT(*) FROM activations a WHERE a.key_hash=k.key_hash AND a.is_revoked=0) as active_devices,
      (SELECT COUNT(*) FROM validation_log l WHERE l.key_hash=k.key_hash AND l.result LIKE 'fail%') as fail_count
    FROM license_keys k ORDER BY k.issued_at DESC
  `);
  const result = keys.map(k => ({
    ...k,
    daysLeft:  getDaysLeft(k.issued_at, k.type),
    isExpired: k.type === 'trial' && isTrialExpired(k.issued_at),
    is_active: !!k.is_active
  }));
  return res.json({ success: true, keys: result, total: result.length });
});

// ── GET /admin/keys/:hash ─────────────────────────────────────
router.get('/keys/:hash', (req, res) => {
  const key = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });

  const devices = db.all('SELECT * FROM activations WHERE key_hash = ? ORDER BY activated_at DESC', [req.params.hash]);
  const logs    = db.all('SELECT * FROM validation_log WHERE key_hash = ? ORDER BY ts DESC LIMIT 50', [req.params.hash]);

  return res.json({
    success: true,
    key: {
      ...key,
      daysLeft:  getDaysLeft(key.issued_at, key.type),
      isExpired: key.type === 'trial' && isTrialExpired(key.issued_at)
    },
    devices,
    logs
  });
});

// ── POST /admin/keys/:hash/revoke ─────────────────────────────
router.post('/keys/:hash/revoke', (req, res) => {
  const key = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  db.run('UPDATE license_keys SET is_active = 0 WHERE key_hash = ?', [req.params.hash]);
  db.log(req.params.hash, '', req.ip, 'admin_revoke', 'ok', 'Admin revoked entire license');
  console.log(`[REVOKED] ${key.key_display}`);
  return res.json({ success: true, message: 'License revoked. All devices will be locked on next validation.' });
});

// ── POST /admin/keys/:hash/restore ────────────────────────────
router.post('/keys/:hash/restore', (req, res) => {
  const key = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  db.run('UPDATE license_keys SET is_active = 1 WHERE key_hash = ?', [req.params.hash]);
  db.log(req.params.hash, '', req.ip, 'admin_restore', 'ok', 'Admin restored license');
  return res.json({ success: true, message: 'License restored successfully.' });
});

// ── POST /admin/devices/:hash/:did/revoke ─────────────────────
router.post('/devices/:hash/:did/revoke', (req, res) => {
  db.run('UPDATE activations SET is_revoked = 1 WHERE key_hash = ? AND device_id = ?',
    [req.params.hash, req.params.did]);
  db.log(req.params.hash, req.params.did, req.ip, 'admin_device_revoke', 'ok', 'Admin revoked device');
  return res.json({ success: true, message: 'Device revoked.' });
});

// ── POST /admin/devices/:hash/:did/transfer ───────────────────
router.post('/devices/:hash/:did/transfer', (req, res) => {
  db.run('DELETE FROM activations WHERE key_hash = ? AND device_id = ?',
    [req.params.hash, req.params.did]);
  db.log(req.params.hash, req.params.did, req.ip, 'admin_transfer', 'ok', 'Device slot freed');
  return res.json({ success: true, message: 'Device removed. License slot free for new device.' });
});

// ── POST /admin/devices/:hash/transfer-all ────────────────────
router.post('/devices/:hash/transfer-all', (req, res) => {
  db.run('DELETE FROM activations WHERE key_hash = ?', [req.params.hash]);
  db.log(req.params.hash, '', req.ip, 'admin_transfer_all', 'ok', 'All devices removed');
  return res.json({ success: true, message: 'All devices removed. License ready for fresh activation.' });
});

// ── GET /admin/suspicious ─────────────────────────────────────
router.get('/suspicious', (req, res) => {
  const suspicious = db.all(`
    SELECT l.key_hash, k.key_display, k.email, k.type,
           COUNT(*) as fail_count,
           MAX(l.ts) as last_attempt,
           GROUP_CONCAT(DISTINCT l.ip) as ips
    FROM validation_log l
    LEFT JOIN license_keys k ON k.key_hash = l.key_hash
    WHERE l.result LIKE 'fail%'
    GROUP BY l.key_hash
    HAVING fail_count >= 3
    ORDER BY fail_count DESC
  `);
  return res.json({ success: true, suspicious, count: suspicious.length });
});

// ── GET /admin/dashboard ──────────────────────────────────────
router.get('/dashboard', (req, res) => {
  const totalKeys    = db.get('SELECT COUNT(*) as n FROM license_keys')?.n || 0;
  const fullKeys     = db.get("SELECT COUNT(*) as n FROM license_keys WHERE type='full'")?.n || 0;
  const trialKeys    = db.get("SELECT COUNT(*) as n FROM license_keys WHERE type='trial'")?.n || 0;
  const activeKeys   = db.get('SELECT COUNT(*) as n FROM license_keys WHERE is_active=1')?.n || 0;
  const totalDevices = db.get('SELECT COUNT(*) as n FROM activations WHERE is_revoked=0')?.n || 0;
  const todayActs    = db.all(
    `SELECT * FROM validation_log WHERE action='activate' AND result='ok' AND ts > ? ORDER BY ts DESC`,
    [Date.now() - 86400000]
  );
  const recentFails  = db.all(`SELECT * FROM validation_log WHERE result LIKE 'fail%' ORDER BY ts DESC LIMIT 20`);
  const recentKeys   = db.all('SELECT * FROM license_keys ORDER BY issued_at DESC LIMIT 10');

  return res.json({
    success: true,
    stats: { totalKeys, fullKeys, trialKeys, activeKeys, totalDevices },
    todayActivations: todayActs.length,
    recentFails,
    recentKeys: recentKeys.map(k => ({ ...k, daysLeft: getDaysLeft(k.issued_at, k.type) }))
  });
});

// ── GET /admin/logs ───────────────────────────────────────────
router.get('/logs', (req, res) => {
  const limit  = parseInt(req.query.limit) || 100;
  const filter = req.query.action || '';
  const logs   = filter
    ? db.all('SELECT * FROM validation_log WHERE action = ? ORDER BY ts DESC LIMIT ?', [filter, limit])
    : db.all('SELECT * FROM validation_log ORDER BY ts DESC LIMIT ?', [limit]);
  return res.json({ success: true, logs, count: logs.length });
});

// ── GET /admin/export ─────────────────────────────────────────
router.get('/export', (req, res) => {
  const keys        = db.all('SELECT * FROM license_keys ORDER BY issued_at DESC');
  const activations = db.all('SELECT * FROM activations ORDER BY activated_at DESC');
  const logs        = db.all('SELECT * FROM validation_log ORDER BY ts DESC LIMIT 1000');
  const exportData  = {
    exportedAt:   new Date().toISOString(),
    application:  'Medishop Pharmacy Billing License Server v1.0',
    keys, activations, logs
  };
  res.setHeader('Content-Disposition', `attachment; filename="medishop-licenses-${Date.now()}.json"`);
  res.setHeader('Content-Type', 'application/json');
  return res.send(JSON.stringify(exportData, null, 2));
});

module.exports = router;
