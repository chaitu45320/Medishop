require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./models/db');

const PORT = process.env.PORT || 8080;
const app = express();

// ── Security & Proxy ──────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', true); // Vital for Railway IP detection

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ── Static Files ──────────────────────────────────────────────
// This line allows your dashboard to load CSS/JS from the public folder
app.use('/public', express.static(path.join(__dirname, 'public')));

// ── Routes ────────────────────────────────────────────────────
const licenseRoutes = require('./routes/license');
const adminRoutes   = require('./routes/admin');

app.use('/api',   licenseRoutes);
app.use('/admin', adminRoutes);

// ── Health Check (Restored) ───────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Medishop License Server',
    timestamp: new Date().toISOString()
  });
});

// ── Test Page (Restored) ──────────────────────────────────────
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// ── Main Admin Portal Entry ───────────────────────────────────
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  const secret = process.env.API_SECRET || 'ms_admin_2024_secure';

  if (token !== secret) {
    return res.status(401).send(`
      <html><body style="background:#0d1b2a;color:#e2e8f0;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;">
        <h2>Access Denied</h2>
        <p>Please use your secure admin URL with the correct token.</p>
      </body></html>`);
  }
  
  res.sendFile(path.resolve(__dirname, 'public', 'dashboard.html'));
});

// ── Start Server ──────────────────────────────────────────────
db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Medishop Server live at: http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
