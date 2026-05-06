/**
 * models/db.js — SQLite via sql.js (pure JS, no native compilation)
 * Tables: license_keys | activations | validation_log
 */
const initSqlJs = require('sql.js');
const fs   = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH  = path.join(DATA_DIR, 'medishop_licenses.db');
let db;

async function init() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const SQL = await initSqlJs();
  db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  db.run(`CREATE TABLE IF NOT EXISTS license_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT UNIQUE NOT NULL,
    key_display TEXT NOT NULL,
    type        TEXT NOT NULL CHECK(type IN ('full','trial')),
    email       TEXT NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1,
    is_active   INTEGER NOT NULL DEFAULT 1,
    issued_at   INTEGER NOT NULL,
    notes       TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS activations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    device_name  TEXT,
    device_fp    TEXT,
    app_version  TEXT,
    activated_at INTEGER NOT NULL,
    last_seen    INTEGER,
    is_revoked   INTEGER NOT NULL DEFAULT 0,
    token_hash   TEXT,
    UNIQUE(key_hash, device_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS validation_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash  TEXT NOT NULL,
    device_id TEXT,
    ip        TEXT,
    action    TEXT NOT NULL,
    result    TEXT NOT NULL,
    detail    TEXT,
    ts        INTEGER NOT NULL
  )`);

  save();
  console.log('[DB] Medishop DB Ready →', DB_PATH);
}

function save() {
  try {
    const data = db.export();
    fs.writeFile(DB_PATH, Buffer.from(data), (err) => {
      if (err) console.error('[DB] Save error:', err.message);
    });
  } catch(e) { console.error('[DB] Export error:', e.message); }
}

function run(sql, p = []) { db.run(sql, p); save(); }
function get(sql, p = []) {
  const s = db.prepare(sql); s.bind(p);
  const r = s.step() ? s.getAsObject() : null;
  s.free(); return r;
}
function all(sql, p = []) {
  const s = db.prepare(sql), rows = []; s.bind(p);
  while (s.step()) rows.push(s.getAsObject());
  s.free(); return rows;
}
function log(keyHash, deviceId, ip, action, result, detail = '') {
  run(`INSERT INTO validation_log (key_hash,device_id,ip,action,result,detail,ts) VALUES (?,?,?,?,?,?,?)`,
      [keyHash, deviceId||'', ip||'', action, result, detail, Date.now()]);
}

module.exports = { init, run, get, all, log, save };
