const express = require('express');
const router = express.Router();
const db = require('../models/db');

// Security Middleware
router.use((req, res, next) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  if (token !== (process.env.API_SECRET || 'ms_admin_2024_secure')) {
    return res.status(403).json({ success: false, error: 'Invalid Token' });
  }
  next();
});

// Dashboard Stats Route
router.get('/dashboard', (req, res) => {
  try {
    const stats = {
      total: db.all('SELECT COUNT(*) as count FROM license_keys')[0].count,
      full: db.all("SELECT COUNT(*) as count FROM license_keys WHERE type='full'")[0].count,
      trial: db.all("SELECT COUNT(*) as count FROM license_keys WHERE type='trial'")[0].count,
      devices: db.all('SELECT COUNT(*) as count FROM devices')[0].count
    };
    const recent = db.all('SELECT * FROM license_keys ORDER BY issued_at DESC LIMIT 5');
    
    res.json({ success: true, stats, recent });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
