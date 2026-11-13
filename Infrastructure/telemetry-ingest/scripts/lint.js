'use strict';

/** Minimal lint: syntax-check every .js (node --check), parse every .json, forbid secrets-looking literals. */
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const skip = new Set(['node_modules', '.data', '.git']);
let failures = 0;

function walk(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (skip.has(ent.name)) continue;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(full);
    else if (ent.name.endsWith('.js')) check(full);
    else if (ent.name.endsWith('.json')) {
      try {
        JSON.parse(fs.readFileSync(full, 'utf8'));
      } catch (e) {
        failures++;
        console.error(`JSON error in ${full}: ${e.message}`);
      }
    }
  }
}

function check(file) {
  const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (r.status !== 0) {
    failures++;
    console.error(`Syntax error in ${file}\n${r.stderr}`);
  }
  const src = fs.readFileSync(file, 'utf8');
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(src)) {
    failures++;
    console.error(`Private key material in ${file}`);
  }
  if (/\bconsole\.log\(.*(installId|x-forwarded-for|remoteAddress)/i.test(src) && !file.includes(`${path.sep}scripts${path.sep}`)) {
    failures++;
    console.error(`Possible PII logging in ${file}`);
  }
}

walk(root);
if (failures) {
  console.error(`lint: ${failures} problem(s)`);
  process.exit(1);
}
console.log('lint: ok');
