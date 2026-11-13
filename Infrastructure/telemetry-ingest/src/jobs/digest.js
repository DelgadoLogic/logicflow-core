'use strict';

/**
 * Cloud Run Job / CLI entry: generate the daily digest.
 *   node src/jobs/digest.js [--date YYYY-MM-DD]      (default: yesterday, UTC)
 * Env: LF_STORAGE=gcs LF_BUCKET=... (or LF_STORAGE=fs LF_DATA_DIR=...)
 */
const { loadConfig } = require('../config');
const { createStorage } = require('../storage');
const { EventStore, utcDate, addDays } = require('../eventStore');
const { generateDigest } = require('../digest');

async function main() {
  const argv = process.argv.slice(2);
  const i = argv.indexOf('--date');
  const date = i >= 0 ? argv[i + 1] : addDays(utcDate(), -1);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`bad --date "${date}" (expected YYYY-MM-DD)`);
  const cfg = loadConfig();
  const store = new EventStore(createStorage(cfg), cfg);
  const res = await generateDigest(store, cfg, { date });
  process.stdout.write(JSON.stringify({ severity: 'INFO', message: 'digest_written', date, summary: res.summary }) + '\n');
}

main().catch((e) => {
  process.stderr.write(JSON.stringify({ severity: 'ERROR', message: 'digest_failed', err: e.message }) + '\n');
  process.exit(1);
});
