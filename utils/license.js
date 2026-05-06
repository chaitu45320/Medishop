/**
 * utils/license.js
 * Medishop key generation, HMAC hashing, JWT token signing/verification
 * Key format: MEDSHP-FULL-XXXXXX-XXXXXX-XXXXXX
 */
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

const SECRET_KEY = process.env.LICENSE_SECRET || 'MS@Medishop#2024!PharmacyBilling$Key@Secure99';
const JWT_SECRET = process.env.JWT_SECRET     || 'MS_JWT_Medishop_2024_Ultra_Secure_Key_99';
const APP_PREFIX = 'MEDSHP';
const CHARS      = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const TRIAL_DAYS = parseInt(process.env.TRIAL_DAYS || '10');

// ── Key Generation ─────────────────────────────────────────────
function randSeg(prefix) {
  let r = prefix || '';
  while (r.length < 6) r += CHARS[Math.floor(Math.random() * CHARS.length)];
  return r.substring(0, 6);
}

function hmacSeg(data, len) {
  const bytes = crypto.createHmac('sha256', SECRET_KEY).update(data).digest();
  let r = '';
  for (let i = 0; i < bytes.length && r.length < len; i++)
    r += CHARS[bytes[i] % CHARS.length];
  return r;
}

function generateKey(type) {
  const typeCode = type === 'full' ? 'FULL' : 'TRAL';
  const typeFlag = type === 'full' ? 'F'    : 'T';
  const seg1 = randSeg(typeFlag);
  const seg2 = randSeg();
  const seg3 = hmacSeg(`${seg1}-${seg2}`, 6);
  return `${APP_PREFIX}-${typeCode}-${seg1}-${seg2}-${seg3}`;
}

// ── Key Validation ────────────────────────────────────────────
function validateKey(licenseKey) {
  const parts = licenseKey.trim().toUpperCase().split('-');
  if (parts.length !== 5)                       return { valid: false, reason: 'Invalid format (need 5 segments)' };
  if (parts[0] !== APP_PREFIX)                  return { valid: false, reason: 'Invalid prefix — must start with MEDSHP' };
  if (!['FULL','TRAL'].includes(parts[1]))      return { valid: false, reason: 'Invalid license type segment' };
  if ([parts[2],parts[3],parts[4]].some(s => s.length !== 6))
                                                return { valid: false, reason: 'Each segment must be 6 characters' };
  const [, typeCode, seg1, seg2, seg3] = parts;
  if (seg3 !== hmacSeg(`${seg1}-${seg2}`, 6))  return { valid: false, reason: 'Key checksum mismatch — key may be tampered' };
  if (typeCode === 'FULL' && seg1[0] !== 'F')   return { valid: false, reason: 'License type flag mismatch' };
  if (typeCode === 'TRAL' && seg1[0] !== 'T')   return { valid: false, reason: 'License type flag mismatch' };
  return { valid: true, type: typeCode === 'FULL' ? 'full' : 'trial' };
}

// ── Secure hashing ────────────────────────────────────────────
function hashKey(key) {
  return crypto.createHmac('sha256', SECRET_KEY).update(key.toUpperCase()).digest('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ── JWT tokens ────────────────────────────────────────────────
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '365d' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch(e) { return null; }
}

// ── Trial expiry ──────────────────────────────────────────────
function getDaysLeft(activatedAt, type) {
  if (type === 'full') return null;
  return Math.max(0, Math.ceil((activatedAt + TRIAL_DAYS * 86400000 - Date.now()) / 86400000));
}

function isTrialExpired(activatedAt) {
  return Date.now() > activatedAt + TRIAL_DAYS * 86400000;
}

module.exports = {
  generateKey, validateKey, hashKey, hashToken,
  signToken, verifyToken, getDaysLeft, isTrialExpired, TRIAL_DAYS
};
