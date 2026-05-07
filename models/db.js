const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const DB_PATH = path.join(__dirname, '../data/medishop_licenses.db');
let db;

/**
 * Initializes the SQLite database and creates tables if they don't exist.
 * Required by index.js
 */
async function init() {
  const SQL = await initSqlJs();
  
  // Ensure data directory exists
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
    createTables();
    save();
  }
  console.log('📦 Database initialized successfully');
}

function createTables() {
  // Table for License Keys
  db.run(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_display TEXT UNIQUE,
      email TEXT,
      type TEXT,
      is_active INTEGER DEFAULT 1,
      issued_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Table for Device Registrations
  db.run(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key_id INTEGER,
      device_id TEXT,
      device_name TEXT,
      activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(license_key_id) REFERENCES license_keys(id)
    )
  `);

  // Table for Activity Logs
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT,
      details TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

/**
 * Persists the in-memory database to the file system.
 */
function save() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

/**
 * Executes a query and returns all results.
 * Used by admin routes and CLI
 */
function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

/**
 * Executes a command (INSERT/UPDATE/DELETE) and saves changes.
 */
function run(sql, params = []) {
  db.run(sql, params);
  save();
}

module.exports = { init, all, run };
