'use strict';

/**
 * Local emulator: filesystem storage, dev-only ingest key, short flush.
 *   npm run dev            -> http://localhost:8080/v1/telemetry/healthz
 *   node scripts/send-sample.js   (signs & sends fixture events)
 *   node src/jobs/digest.js --date <today>   with the same LF_DATA_DIR
 */
const path = require('node:path');
process.env.LF_STORAGE = process.env.LF_STORAGE || 'fs';
process.env.LF_DATA_DIR = process.env.LF_DATA_DIR || path.join(__dirname, '..', '.data');
process.env.LF_INGEST_KEYS = process.env.LF_INGEST_KEYS || 'dev-local-ingest-key-DO-NOT-USE-IN-PROD';
process.env.LF_ADMIN_TOKEN = process.env.LF_ADMIN_TOKEN || 'dev-admin-token';
process.env.LF_FLUSH_INTERVAL_MS = process.env.LF_FLUSH_INTERVAL_MS || '2000';
process.env.LF_STATS_FLUSH_MS = process.env.LF_STATS_FLUSH_MS || '5000';
console.log(`[dev] data dir: ${process.env.LF_DATA_DIR}`);
require('../src/server.js');
