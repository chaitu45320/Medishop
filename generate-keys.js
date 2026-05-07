#!/usr/bin/env node
/**
 * generate-keys.js — Medishop License Key Generator CLI
 * Usage:
 *   node generate-keys.js                        — generate 1 full key
 *   node generate-keys.js trial                  — generate 1 trial key
 *   node generate-keys.js full 5 name@email.com  — generate 5 full keys for email
 *   node generate-keys.js list                   — list all keys from DB
 *   node generate-keys.js export                 — export all keys to JSON
 */
require('dotenv').config();
const { generateKey, validateKey } = require('./utils/license');
const fs   = require('fs');
const path = require('path');

const [,, typeArg, countArg, emailArg] = process.argv;

if (typeArg === 'list' || typeArg === 'export') {
  const db = require('./models/db');
  db.init().then(() => {
    const keys = db.all('SELECT * FROM license_keys ORDER BY issued_at DESC');
    if (typeArg === 'list') {
      console.log('\n💊 Medishop License Keys\n' + '─'.repeat(60));
      keys.forEach(k => {
        console.log(`[${k.type.toUpperCase()}] ${k.key_display} | ${k.email} | active:${!!k.is_active}`);
      });
      console.log(`\nTotal: ${keys.length} keys`);
    } else {
      const outFile = `medishop-keys-export-${Date.now()}.json`;
      fs.writeFileSync(outFile, JSON.stringify(keys, null, 2));
      console.log(`✅ Exported ${keys.length} keys to ${outFile}`);
    }
    process.exit(0);
  });
} else {
  const type  = typeArg || 'full';
  const count = parseInt(countArg) || 1;

  if (!['full','trial'].includes(type)) {
    console.error('❌ Type must be "full" or "trial"');
    process.exit(1);
  }

  console.log(`\n💊 Medishop License Key Generator`);
  console.log(`Generating ${count} ${type} key(s)...\n`);

  for (let i = 0; i < count; i++) {
    const key = generateKey(type);
    const v   = validateKey(key);
    const status = v.valid ? '✅' : '❌';
    console.log(`${status} ${key}${emailArg ? ` | ${emailArg}` : ''}`);
  }

  console.log(`\n⚠️  These keys are NOT registered in the database yet.`);
  console.log(`   Use the Admin Dashboard to generate & register keys properly.`);
}
