require('dotenv').config();
const express = require('express');
const path = require('path');
const db = require('./models/db');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());
// Serve static files so dashboard.html can find its CSS/JS
app.use('/public', express.static(path.join(__dirname, 'public')));

// API Routes
app.use('/api', require('./routes/license'));
app.use('/admin', require('./routes/admin'));

// The Login Entry Point
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  const secret = process.env.API_SECRET || 'ms_admin_2024_secure';

  if (token !== secret) {
    return res.status(401).send(`
      <body style="background:#0d1b2a;color:white;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;">
        <div style="text-align:center;">
          <h1>🔒 Access Denied</h1>
          <p>Please use your secure link: <code>?token=YOUR_SECRET</code></p>
        </div>
      </body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Medishop Server active on port ${PORT}`);
  });
}).catch(err => {
  console.error('DB Fail:', err);
});
