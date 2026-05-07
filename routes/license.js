/**
 * routes/license.js  —  Medishop Pharmacy Billing
 * Client-facing API endpoints:
 *   POST /api/activate    — first activation or re-activation on same device
 *   POST /api/validate    — periodic ping from running app
 *   POST /api/deactivate  — customer voluntarily removes this device
 *
 * FIXES:
 *  - getDaysLeft now passes activated_at (first activation time) not issued_at
 *  - Re-activation on same device does NOT reset the trial countdown
 *  - All error messages rebranded to Medishop
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
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Key not found');
    return res.status(404).json({
      success: false,
      error: 'License key not found. Contact Medishop Support.'
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
      error: 'This key is registered to a different email address.'
    });
  }

  // Check if this device already has an activation record
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

    // FIX: Check trial expiry using the ORIGINAL activated_at (first activation time)
    //      This means re-opening the app doesn't reset the trial timer
    if (keyRecord.type === 'trial' && isTrialExpired(existing.activated_at, keyRecord.type)) {
      db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Trial expired');
      return res.status(403).json({
        success: false,
        error: 'Trial license has expired. Contact Medishop to upgrade to a full license.'
      });
    }

    // Re-activation on same device — refresh token but keep original activated_at
    const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
    db.run(
      'UPDATE activations SET last_seen=?, token_hash=?, device_name=?, app_version=? WHERE key_hash=? AND device_id=?',
      [Date.now(), hashToken(token), deviceName || existing.device_name, appVersion || existing.app_version, keyHash, deviceId]
    );
    db.log(keyHash, deviceId, ip, 'reactivate', 'ok', deviceName);

    // FIX: Pass existing.activated_at (original first activation) for correct days left
    const daysLeft = getDaysLeft(existing.activated_at, keyRecord.type);
    return res.json({
      success: true,
      type:    keyRecord.type,
      email:   emailLc,
      daysLeft,
      token,
      activatedAt: existing.activated_at,
      message: 'License verified successfully'
    });
  }

  // Brand new device — check trial expiry against issued_at for first-time activation
  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at, keyRecord.type)) {
    db.log(keyHash, deviceId, ip, 'activate', 'fail', 'Trial expired before first use');
    return res.status(403).json({
      success: false,
      error: 'Trial license has expired. Contact Medishop to upgrade.'
    });
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
      code:  'DEVICE_LIMIT'
    });
  }

  // First activation on this device
  const now   = Date.now();
  const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
  db.run(
    `INSERT INTO activations (key_hash,device_id,device_name,device_fp,app_version,activated_at,last_seen,token_hash)
     VALUES (?,?,?,?,?,?,?,?)`,
    [keyHash, deviceId, deviceName || 'Unknown Device', deviceFp || '', appVersion || '1.0.0', now, now, hashToken(token)]
  );

  db.log(keyHash, deviceId, ip, 'activate', 'ok', deviceName);

  // FIX: Pass 'now' as activatedAt so trial countdown starts from first activation
  const daysLeft = getDaysLeft(now, keyRecord.type);

  console.log(`[ACTIVATED] ${key} | ${emailLc} | ${deviceName} | ${ip}`);

  return res.json({
    success:     true,
    type:        keyRecord.type,
    email:       emailLc,
    daysLeft,
    token,
    activatedAt: now,
    message:     keyRecord.type === 'full'
      ? 'Medishop full license activated successfully!'
      : `Trial license activated — ${daysLeft} day(s) remaining.`
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

  // FIX: Use activation.activated_at for trial expiry check
  if (keyRecord.type === 'trial' && isTrialExpired(activation.activated_at, keyRecord.type)) {
    db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Trial expired');
    return res.status(403).json({ success: false, error: 'Trial license expired' });
  }

  db.run(
    'UPDATE activations SET last_seen = ? WHERE key_hash = ? AND device_id = ?',
    [Date.now(), keyHash, deviceId]
  );
  db.log(keyHash, deviceId, ip, 'validate', 'ok', '');

  // FIX: Pass activated_at for correct days remaining
  const daysLeft = getDaysLeft(activation.activated_at, keyRecord.type);

  return res.json({
    success:     true,
    type:        keyRecord.type,
    email:       keyRecord.email,
    daysLeft,
    activatedAt: activation.activated_at,
    valid:       true
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
    message: 'Device deactivated successfully. License slot is now free.'
  });
});

module.exports = router;
