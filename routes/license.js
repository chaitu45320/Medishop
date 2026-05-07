/**
 * routes/license.js — Medishop client-facing license endpoints
 *   POST /api/activate    — first activation or re-activation
 *   POST /api/validate    — periodic ping to verify token
 *   POST /api/deactivate  — remove this device
 */
const express = require('express');
const router  = express.Router();
const db      = require('../models/db');
const {
  validateKey, hashKey, hashToken,
  signToken, verifyToken, getDaysLeft, isTrialExpired
} = require('../utils/license');

// ── POST /api/activate ────────────────────────────────────────
router.post('/activate', async (req, res) => {
  const { licenseKey, email, deviceId, deviceName, deviceFp, appVersion } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!licenseKey) return res.status(400).json({ success: false, error: 'License key is required' });
  if (!email)      return res.status(400).json({ success: false, error: 'Email is required' });
  if (!deviceId)   return res.status(400).json({ success: false, error: 'Device ID is required' });

  const key = licenseKey.trim().toUpperCase();

  const validation = validateKey(key);
  if (!validation.valid) {
    db.log('', deviceId, ip, 'activate', 'fail', 'Invalid key: ' + validation.reason);
    return res.status(400).json({ success: false, error: 'Invalid license key: ' + validation.reason });
  }

  const keyHash = hashKey(key);
  const emailLc = email.trim().toLowerCase();

  const keyRecord = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [keyHash]);
  if (!keyRecord) {
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Key not in issued list');
    return res.status(404).json({
      success: false,
      error: 'License key not found. Contact Medishop Support: support@medishop.in'
    });
  }

  if (!keyRecord.is_active) {
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Revoked key');
    return res.status(403).json({
      success: false,
      error: 'This license has been revoked. Contact Medishop Support.'
    });
  }

  if (keyRecord.email !== emailLc) {
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Email mismatch');
    return res.status(403).json({
      success: false,
      error: 'This license key is registered to a different email address.'
    });
  }

  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at)) {
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Trial expired');
    return res.status(403).json({
      success: false,
      error: 'Trial license has expired. Contact Medishop to upgrade to full license.'
    });
  }

  const existing = db.get(
    'SELECT * FROM activations WHERE key_hash = ? AND device_id = ?',
    [keyHash, deviceId]
  );

  if (existing) {
    if (existing.is_revoked) {
      db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Device revoked');
      return res.status(403).json({
        success: false,
        error: 'This device has been revoked. Contact Medishop Support.'
      });
    }
    // Re-activation — refresh token
    const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
    db.run(
      'UPDATE activations SET last_seen=?, token_hash=?, device_name=?, app_version=? WHERE key_hash=? AND device_id=?',
      [Date.now(), hashToken(token), deviceName || existing.device_name, appVersion || existing.app_version, keyHash, deviceId]
    );
    db.log(keyHash, deviceId, ip, 'reactivate', 'ok', deviceName);
    const daysLeft = getDaysLeft(keyRecord.issued_at, keyRecord.type);
    return res.json({ success: true, type: keyRecord.type, email: emailLc, daysLeft, token, message: 'License verified' });
  }

  // Check device limit
  const activeDevices = db.all(
    'SELECT * FROM activations WHERE key_hash = ? AND is_revoked = 0',
    [keyHash]
  );
  if (activeDevices.length >= keyRecord.max_devices) {
    const names = activeDevices.map(d => d.device_name || d.device_id).join(', ');
    db.log(keyHash, deviceId, ip, 'activate', 'fail_limit', `Devices: ${names}`);
    return res.status(409).json({
      success: false,
      error: `License already active on ${activeDevices.length} device(s): ${names}. Contact Medishop Support to transfer.`,
      code: 'DEVICE_LIMIT'
    });
  }

  // New activation
  const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
  db.run(
    `INSERT INTO activations (key_hash,device_id,device_name,device_fp,app_version,activated_at,last_seen,token_hash)
     VALUES (?,?,?,?,?,?,?,?)`,
    [keyHash, deviceId, deviceName || 'Unknown Device', deviceFp || '', appVersion || '1.0.0', Date.now(), Date.now(), hashToken(token)]
  );

  db.log(keyHash, deviceId, ip, 'activate', 'ok', deviceName);
  const daysLeft = getDaysLeft(keyRecord.issued_at, keyRecord.type);

  console.log(`[ACTIVATED] ${key} | ${emailLc} | ${deviceName} | ${ip}`);

  return res.json({
    success: true,
    type:    keyRecord.type,
    email:   emailLc,
    daysLeft,
    token,
    message: keyRecord.type === 'full'
      ? 'Medishop full license activated successfully!'
      : `Medishop trial license: ${daysLeft} day(s) remaining.`
  });
});

// ── POST /api/validate ────────────────────────────────────────
router.post('/validate', async (req, res) => {
  const { token, deviceId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token || !deviceId)
    return res.status(400).json({ success: false, error: 'token and deviceId required' });

  const payload = verifyToken(token);
  if (!payload || payload.deviceId !== deviceId) {
    db.log('', deviceId, ip, 'validate', 'fail', 'Invalid JWT');
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }

  const { keyHash } = payload;

  const activation = db.get(
    'SELECT * FROM activations WHERE key_hash = ? AND device_id = ?',
    [keyHash, deviceId]
  );
  if (!activation || activation.is_revoked) {
    db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Not activated or revoked');
    return res.status(401).json({ success: false, error: 'Device not authorized' });
  }

  const keyRecord = db.get('SELECT * FROM license_keys WHERE key_hash = ?', [keyHash]);
  if (!keyRecord || !keyRecord.is_active) {
    db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Key inactive');
    return res.status(403).json({ success: false, error: 'License deactivated' });
  }

  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at)) {
    db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Trial expired');
    return res.status(403).json({ success: false, error: 'Trial expired' });
  }

  db.run(
    'UPDATE activations SET last_seen = ? WHERE key_hash = ? AND device_id = ?',
    [Date.now(), keyHash, deviceId]
  );
  db.log(keyHash, deviceId, ip, 'validate', 'ok', '');

  return res.json({
    success:  true,
    type:     keyRecord.type,
    email:    keyRecord.email,
    daysLeft: getDaysLeft(keyRecord.issued_at, keyRecord.type),
    valid:    true
  });
});

// ── POST /api/deactivate ──────────────────────────────────────
router.post('/deactivate', async (req, res) => {
  const { token, deviceId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token || !deviceId)
    return res.status(400).json({ success: false, error: 'token and deviceId required' });

  const payload = verifyToken(token);
  if (!payload || payload.deviceId !== deviceId)
    return res.status(401).json({ success: false, error: 'Invalid token' });

  db.run(
    'DELETE FROM activations WHERE key_hash = ? AND device_id = ?',
    [payload.keyHash, deviceId]
  );
  db.log(payload.keyHash, deviceId, ip, 'deactivate', 'ok', 'Self deactivated');

  return res.json({
    success: true,
    message: 'Device deactivated. License slot is now free for another device.'
  });
});

module.exports = router;
