const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const SECRET = process.env.LICENSE_SECRET || 'MS@Medishop#2024!PharmacyBilling$Key@Secure99';
const JWT_SECRET = process.env.JWT_SECRET || 'MS_JWT_Medishop_2024_Ultra_Secure_Key_99';

function generateKey(type = 'full') {
  const prefix = `MEDSHP-${type.toUpperCase().substring(0, 4)}`;
  const random = crypto.randomBytes(9).toString('hex').toUpperCase();
  const segments = random.match(/.{1,6}/g).join('-');
  const hmac = crypto.createHmac('sha256', SECRET).update(`${prefix}-${segments}`).digest('hex').substring(0, 6).toUpperCase();
  return `${prefix}-${segments}-${hmac}`;
}

function validateKey(key) {
  const parts = key.split('-');
  if (parts.length !== 5) return { valid: false };
  const checkString = parts.slice(0, 4).join('-');
  const providedHmac = parts[4];
  const expectedHmac = crypto.createHmac('sha256', SECRET).update(checkString).digest('hex').substring(0, 6).toUpperCase();
  return { valid: providedHmac === expectedHmac, type: parts[1] };
}

module.exports = { generateKey, validateKey };
