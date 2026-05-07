const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;
const DB_FILE = path.join(__dirname, 'db.json');

// Helper to manage the JSON database
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { licenses: [], logs: [] };
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Validation & Hardware Binding API
app.get('/api/validate', (req, res) => {
  const { token, machine_id } = req.query;
  const db = loadDB();
  const lic = db.licenses.find(l => l.key === token);

  if (!lic) return res.json({ active: false, reason: 'Invalid license key' });
  if (lic.status === 'revoked') return res.json({ active: false, reason: 'License has been revoked' });

  // Hardware Locking: Bind to machine_id on first use
  if (!lic.machine_id) {
    lic.machine_id = machine_id;
    saveDB(db);
  } else if (lic.machine_id !== machine_id) {
    return res.json({ active: false, reason: 'License active on another device' });
  }

  return res.json({ active: true, type: lic.type || 'full' });
});

app.listen(PORT, () => console.log(`License Server running on port ${PORT}`));
