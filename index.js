/**
 * Medishop Pharmacy Billing — License Server v1.0
 * support@medishop.in | helpline: 1800-MED-SHOP
 *
 * Run:       node index.js
 * Dashboard: http://localhost:8080/?token=YOUR_SECRET
 */

require('dotenv').config();

const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const db        = require('./models/db');

const PORT = process.env.PORT || 8080;
const app  = express();

// ── Security Headers ──────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// ── Body Parser ───────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ── Trust proxy ───────────────────────────────────────────────
app.set('trust proxy', false);

// ── Request logger ────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/admin')) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// ── Rate Limiting ─────────────────────────────────────────────
const activationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message:  { success: false, error: 'Too many activation attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    (req) => req.ip || 'unknown'
});

const validationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max:      200,
  message:  { success: false, error: 'Validation rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders:   false
});

const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max:      100,
  message:  { success: false, error: 'Admin rate limit exceeded.' }
});

app.use('/api/activate', activationLimiter);
app.use('/api/validate', validationLimiter);
app.use('/admin',        adminLimiter);

// ── CORS ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  next();
});

// ── Routes ────────────────────────────────────────────────────
const licenseRoutes = require('./routes/license');
const adminRoutes   = require('./routes/admin');

app.use('/api',   licenseRoutes);
app.use('/admin', adminRoutes);

// ── Static files ──────────────────────────────────────────────
app.use('/public', express.static(path.join(__dirname, 'public')));

// ── Test page ─────────────────────────────────────────────────
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// ── Admin Dashboard ───────────────────────────────────────────
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  if (token !== (process.env.API_SECRET || 'ms_admin_2024_secure')) {
    return res.status(401).send(`
      <!DOCTYPE html>
      <html><head><title>Medishop License Admin</title>
      <meta name="viewport" content="width=device-width,initial-scale=1"/>
      <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:#0d1b2a;color:#e2e8f0;font-family:'Segoe UI',sans-serif;
             display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}
        .icon{font-size:56px;margin-bottom:8px}
        h2{font-size:24px;font-weight:700;color:#38bdf8}
        p{color:#94a3b8;font-size:14px;text-align:center;max-width:400px}
        code{background:#1e3a5f;padding:4px 10px;border-radius:6px;font-family:monospace;color:#7dd3fc}
        .brand{position:absolute;top:24px;left:24px;color:#38bdf8;font-weight:700;font-size:18px}
      </style></head>
      <body>
        <div class="brand">💊 Medishop</div>
        <div class="icon">🔑</div>
        <h2>License Admin Portal</h2>
        <p>Access requires a valid admin token</p>
        <p style="margin-top:8px">URL format:<br>
        <code>http://your-server:8080/?token=YOUR_SECRET</code></p>
        <p style="margin-top:16px;color:#64748b;font-size:12px">Medishop Pharmacy Billing System</p>
      </body></html>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ── Health Check ──────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    service:   'Medishop License Server',
    version:   '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ── 404 ───────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

// ── Error handler ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────
db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`╔══════════════════════════════════════════════╗`);
    console.log(`║   💊 Medishop License Server v1.0             ║`);
    console.log(`╠══════════════════════════════════════════════╣`);
    console.log(`║  Port   : ${PORT}                              `);
    console.log(`║  Health : http://localhost:${PORT}/health`);
    const secret = process.env.API_SECRET || 'ms_admin_2024_secure';
    console.log(`║  Admin  : http://localhost:${PORT}/?token=${secret}`);
    console.log(`╚══════════════════════════════════════════════╝`);
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
