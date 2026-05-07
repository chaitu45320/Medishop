const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { generateKey } = require('../utils/license');

// Auth Middleware
router.use((req, res, next) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  if (token !== (process.env.API_SECRET || 'ms_admin_2024_secure')) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  next();
});

router.get('/dashboard', async (req, res) => {
  const stats = {
    totalKeys: db.all('SELECT COUNT(*) as count FROM license_keys')[0].count,
    activeDevices: db.all('SELECT COUNT(*) as count FROM devices')[0].count,
    recentLogs: db.all('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5')
  };
  res.json({ success: true, stats });
});

router.post('/keys/generate', async (req, res) => {
  const { type, email } = req.body;
  const key = generateKey(type || 'full');
  db.run('INSERT INTO license_keys (key_display, email, type, is_active) VALUES (?, ?, ?, 1)', [key, email, type]);
  res.json({ success: true, key });
});

module.exports = router;
