'use strict';

const path = require('node:path');
const crypto = require('node:crypto');

const SCHEMA_VERSION = 1;
const SERVICE_VERSION = '1.0.0';

function int(v, d) {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : d;
}

function list(v) {
  return String(v || '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Build the runtime configuration from environment variables.
 * Nothing secret has a default: with no ingest keys the service starts but
 * fails closed (503 not_configured) for every signed endpoint.
 */
function loadConfig(env = process.env) {
  const storage = (env.LF_STORAGE || 'fs').toLowerCase();
  if (storage !== 'fs' && storage !== 'gcs') {
    throw new Error(`LF_STORAGE must be "fs" or "gcs" (got "${storage}")`);
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    serviceVersion: SERVICE_VERSION,
    port: int(env.PORT, 8080),
    host: env.HOST || '0.0.0.0',
    storage,
    dataDir: path.resolve(env.LF_DATA_DIR || path.join(process.cwd(), '.data')),
    bucket: env.LF_BUCKET || '',
    // Per-build ingest keys (current + rotation list). Secret Manager -> env.
    ingestKeys: list(env.LF_INGEST_KEYS),
    // Bearer-style token guarding POST /internal/digest (Scheduler/ops). Empty = endpoint disabled.
    adminToken: env.LF_ADMIN_TOKEN || '',
    instanceId: (env.K_REVISION || 'local') + '-' + crypto.randomBytes(3).toString('hex'),

    // Limits
    maxBodyBytes: int(env.LF_MAX_BODY_BYTES, 1024 * 1024), // wire bytes
    maxDecodedBytes: int(env.LF_MAX_DECODED_BYTES, 5 * 1024 * 1024),
    maxEventsPerRequest: int(env.LF_MAX_EVENTS_PER_REQUEST, 200),
    maxEventBytes: int(env.LF_MAX_EVENT_BYTES, 64 * 1024),
    maxClockSkewFutureMs: int(env.LF_MAX_FUTURE_SKEW_MS, 24 * 3600 * 1000),
    maxEventAgeMs: int(env.LF_MAX_EVENT_AGE_MS, 30 * 24 * 3600 * 1000),

    // Rate limits (events / requests per window)
    rate: {
      installEventsPerHour: int(env.LF_RATE_INSTALL_EVENTS_HOUR, 600),
      installRequestsPerMin: int(env.LF_RATE_INSTALL_REQ_MIN, 30),
      ipRequestsPerMin: int(env.LF_RATE_IP_REQ_MIN, 120),
      ipEventsPerHour: int(env.LF_RATE_IP_EVENTS_HOUR, 3000),
      saltRotateMs: int(env.LF_IP_SALT_ROTATE_MS, 6 * 3600 * 1000),
    },
    // How many trailing X-Forwarded-For hops are trusted proxies (Firebase Hosting + Google front end).
    trustProxyHops: int(env.LF_TRUST_PROXY_HOPS, 1),

    // Buffering
    flushBytes: int(env.LF_FLUSH_BYTES, 1024 * 1024),
    flushEvents: int(env.LF_FLUSH_EVENTS, 5000),
    flushIntervalMs: int(env.LF_FLUSH_INTERVAL_MS, 30000), // 0 = write-through
    statsFlushMs: int(env.LF_STATS_FLUSH_MS, 60000),
    dedupeMax: int(env.LF_DEDUPE_MAX, 200000),
    dedupeTtlMs: int(env.LF_DEDUPE_TTL_MS, 24 * 3600 * 1000),

    // Retention
    rawRetentionDays: int(env.LF_RAW_RETENTION_DAYS, 90),
    rollupRetentionDays: int(env.LF_ROLLUP_RETENTION_DAYS, 395), // ~13 months
  };
}

module.exports = { loadConfig, SCHEMA_VERSION, SERVICE_VERSION };
