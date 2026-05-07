/**
 * Medishop Pharmacy Billing — License Server v1.0
 * support@medishop.in
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

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.set('trust proxy', false);

app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/admin'))
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

const activationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { success: false, error: 'Too many activation attempts. Please wait 15 minutes.' },
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: req => req.ip || 'unknown'
});
const validationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 300,
  message: { success: false, error: 'Validation rate limit exceeded.' },
  standardHeaders: true, legacyHeaders: false
});
const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 200,
  message: { success: false, error: 'Admin rate limit exceeded.' }
});

app.use('/api/activate', activationLimiter);
app.use('/api/validate', validationLimiter);
app.use('/admin',        adminLimiter);

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  next();
});

const licenseRoutes = require('./routes/license');
const adminRoutes   = require('./routes/admin');
app.use('/api',   licenseRoutes);
app.use('/admin', adminRoutes);

app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/test', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'test.html'))
);

app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  if (token !== (process.env.API_SECRET || 'ms_admin_2024_secure')) {
    return res.status(401).send(`<!DOCTYPE html>
<html><head><title>Medishop License Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#060d19;color:#e2e8f0;font-family:'Segoe UI',sans-serif;
  display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px;text-align:center;padding:24px}
h2{font-size:22px;color:#00c9a7}p{color:#6b8ab0;font-size:14px;max-width:420px}
code{background:#0c1a2e;padding:4px 10px;border-radius:6px;font-family:monospace;color:#7dd3fc;font-size:13px}
</style></head>
<body>
<div style="font-size:52px">💊</div>
<h2>Medishop License Admin</h2>
<p>Access requires a valid admin token.</p>
<p style="margin-top:8px">URL format:<br><code>http://your-server:8080/?token=YOUR_SECRET</code></p>
</body></html>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/health', (req, res) =>
  res.json({ status: 'ok', service: 'Medishop License Server', version: '1.0.0', timestamp: new Date().toISOString() })
);

app.use((req, res) =>
  res.status(404).json({ success: false, error: 'Not found' })
);

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    const secret = process.env.API_SECRET || 'ms_admin_2024_secure';
    console.log(`\n╔══════════════════════════════════════════════╗`);
    console.log(`║   💊  Medishop License Server v1.0            ║`);
    console.log(`╠══════════════════════════════════════════════╣`);
    console.log(`║  Port    : ${PORT}`);
    console.log(`║  Health  : http://localhost:${PORT}/health`);
    console.log(`║  Admin   : http://localhost:${PORT}/?token=${secret}`);
    console.log(`╚══════════════════════════════════════════════╝\n`);
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
