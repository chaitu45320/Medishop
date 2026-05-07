require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./models/db');

const PORT = process.env.PORT || 8080;
const app = express();

// Security and Proxy Setup
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', true); // Critical for Railway

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Rate limit exceeded.' }
});
app.use('/admin', limiter);

// Routes
const licenseRoutes = require('./routes/license');
const adminRoutes = require('./routes/admin');

app.use('/api', licenseRoutes);
app.use('/admin', adminRoutes);

// Main Admin Portal Entry
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  const secret = process.env.API_SECRET || 'ms_admin_2024_secure'; //

  if (token !== secret) {
    return res.status(401).send(`
      <html><body style="background:#0d1b2a;color:#e2e8f0;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;">
        <h2>Access Denied</h2>
        <p>Please use your secure admin URL.</p>
      </body></html>`);
  }
  // Serves the clean dashboard without redirects
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Medishop License Server active on port ${PORT}`);
  });
});
