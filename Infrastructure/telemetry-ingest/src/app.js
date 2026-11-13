'use strict';

const http = require('node:http');
const zlib = require('node:zlib');
const { loadConfig, SCHEMA_VERSION, SERVICE_VERSION } = require('./config');
const { createValidator } = require('./validate');
const { RateLimiter, DedupeSet } = require('./ratelimit');
const { createStorage } = require('./storage');
const { EventStore, hashInstall, utcDate, addDays } = require('./eventStore');
const { WriteBuffer } = require('./buffer');
const { Stats } = require('./stats');
const { verifySignature, safeEqualStr } = require('./auth');
const { ingestBatch, normalizeConsent } = require('./ingest');
const { purgePendingErasures } = require('./erasure');
const { generateDigest } = require('./digest');

const BASE = '/v1/telemetry';
const INSTALL_RE = /^[A-Za-z0-9_-]{16,64}$/;
const VERSION_RE = /^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(\.[0-9]{1,5})?([-+][0-9A-Za-z.-]{1,24})?$/;

function makeLogger(quiet) {
  return (level, msg, fields = {}) => {
    if (quiet && level !== 'error') return;
    // Structured JSON for Cloud Logging. NEVER pass IPs, install ids or payloads here.
    process.stdout.write(JSON.stringify({ severity: level.toUpperCase(), message: msg, ...fields }) + '\n');
  };
}

class HttpError extends Error {
  constructor(status, code, extra = {}) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function sendJson(res, status, body, headers = {}) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': data.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(data);
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const declared = Number.parseInt(req.headers['content-length'] || '0', 10);
    if (declared > max) return reject(new HttpError(413, 'payload_too_large'));
    const chunks = [];
    let total = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      total += c.length;
      if (total > max) {
        done = true;
        chunks.length = 0;
        reject(new HttpError(413, 'payload_too_large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) {
        done = true;
        resolve(Buffer.concat(chunks, total));
      }
    });
    req.on('error', (e) => {
      if (!done) {
        done = true;
        reject(e);
      }
    });
  });
}

function clientIp(req, cfg) {
  const fastly = req.headers['fastly-client-ip'];
  if (typeof fastly === 'string' && fastly) return fastly.trim();
  const xff = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (xff.length === 0) return req.socket.remoteAddress || 'unknown';
  const idx = Math.max(0, xff.length - Math.max(1, cfg.trustProxyHops));
  return xff[idx];
}

function decodeBody(buf, req, cfg) {
  const enc = String(req.headers['content-encoding'] || '').toLowerCase();
  if (!enc || enc === 'identity') return buf;
  if (enc !== 'gzip') throw new HttpError(415, 'unsupported_content_encoding');
  try {
    return zlib.gunzipSync(buf, { maxOutputLength: cfg.maxDecodedBytes });
  } catch (e) {
    if (e && e.code === 'ERR_BUFFER_TOO_LARGE') throw new HttpError(413, 'payload_too_large');
    throw new HttpError(400, 'bad_encoding');
  }
}

/** Parse JSON array / single object / NDJSON into an array of event candidates. */
function parseEvents(buf, contentType) {
  const text = buf.toString('utf8');
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('ndjson') || ct.includes('jsonl') || ct.includes('x-ndjson')) {
    const out = [];
    for (const line of text.split('\n')) {
      const l = line.trim();
      if (!l) continue;
      try {
        out.push(JSON.parse(l));
      } catch {
        out.push(Symbol.for('malformed'));
      }
    }
    return out;
  }
  if (!ct.includes('json') && ct !== '') throw new HttpError(415, 'unsupported_media_type');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'malformed_json');
  }
  return Array.isArray(parsed) ? parsed : [parsed];
}

function createApp(overrides = {}) {
  const cfg = overrides.cfg || loadConfig();
  const log = overrides.log || makeLogger(overrides.quiet);
  const storage = overrides.storage || createStorage(cfg);
  const store = new EventStore(storage, cfg);
  const validator = createValidator();
  const limiter = new RateLimiter(cfg.rate);
  const dedupe = new DedupeSet(cfg.dedupeMax, cfg.dedupeTtlMs);
  const buffer = new WriteBuffer(store, cfg, log);
  const stats = new Stats(store, cfg, log);
  const erasedCache = new Map(); // installId -> {erased:boolean, exp:number}
  const background = new Set();

  const app = { cfg, log, storage, store, validator, limiter, dedupe, buffer, stats, background };

  function track(p) {
    background.add(p);
    p.finally(() => background.delete(p));
    return p;
  }

  async function isErased(installId) {
    const now = Date.now();
    const c = erasedCache.get(installId);
    if (c && c.exp > now) return c.erased;
    const erased = await store.hasTombstone(installId);
    erasedCache.set(installId, { erased, exp: now + (erased ? 24 * 3600 * 1000 : 5 * 60 * 1000) });
    if (erasedCache.size > 50000) erasedCache.clear();
    return erased;
  }

  async function handleIngest(req, res, endpoint, ipKey) {
    // Cheap IP limiter first (before any crypto / parsing).
    const rl = limiter.checkIpRequest(ipKey);
    if (!rl.ok) throw new HttpError(429, 'rate_limited_ip', { retryAfter: rl.retryAfterSec });
    if (cfg.ingestKeys.length === 0) throw new HttpError(503, 'not_configured');

    const wire = await readBody(req, cfg.maxBodyBytes);
    stats.request(endpoint, wire.length);

    if (String(req.headers['x-lf-schema'] || '') !== String(SCHEMA_VERSION)) throw new HttpError(400, 'unsupported_schema');
    const headerInstallId = String(req.headers['x-lf-install-id'] || '');
    if (!INSTALL_RE.test(headerInstallId)) throw new HttpError(400, 'bad_install_id');
    if (!VERSION_RE.test(String(req.headers['x-lf-version'] || ''))) throw new HttpError(400, 'bad_version');

    // Authenticate on the wire bytes BEFORE decompressing / parsing.
    const sig = verifySignature(cfg.ingestKeys, wire, req.headers['x-lf-sig']);
    if (!sig.ok) throw new HttpError(401, sig.reason === 'not_configured' ? 'not_configured' : 'invalid_signature');

    const il = limiter.checkInstallRequest(headerInstallId);
    if (!il.ok) throw new HttpError(429, 'rate_limited_install', { retryAfter: il.retryAfterSec });

    // Consent gate: no / invalid consent => nothing is processed.
    const consent = normalizeConsent(req.headers['x-lf-consent']);
    if (!consent) throw new HttpError(403, 'consent_required');

    if (await isErased(headerInstallId)) throw new HttpError(410, 'install_erased');

    const decoded = decodeBody(wire, req, cfg);
    const events = parseEvents(decoded, req.headers['content-type']);
    if (events.length > cfg.maxEventsPerRequest) throw new HttpError(413, 'too_many_events');

    const budget = limiter.checkEvents({ ipKey, installId: headerInstallId }, events.length);
    if (!budget.ok) {
      stats.rejected(`rate_limited_${budget.scope}`, events.length);
      throw new HttpError(429, `rate_limited_${budget.scope}`, { retryAfter: budget.retryAfterSec, rejected: events.length });
    }

    const malformed = events.filter((e) => e === Symbol.for('malformed')).length;
    const valid = events.filter((e) => e !== Symbol.for('malformed'));
    const result = ingestBatch(app, { events: valid, consent, headerInstallId, endpoint });
    if (malformed) {
      result.rejected += malformed;
      result.reasons.malformed_json = malformed;
      stats.rejected('malformed_json', malformed);
    }

    if (cfg.flushIntervalMs === 0) await buffer.flushDue();
    else track(buffer.flushDue().catch((e) => log('error', 'flush_failed', { err: e.message })));

    const body = { accepted: result.accepted, rejected: result.rejected, schema: SCHEMA_VERSION };
    if (result.rejected > 0) body.reasons = result.reasons;
    return { status: 200, body };
  }

  async function handleDelete(req, res, ipKey) {
    const rl = limiter.checkIpRequest(ipKey);
    if (!rl.ok) throw new HttpError(429, 'rate_limited_ip', { retryAfter: rl.retryAfterSec });
    if (cfg.ingestKeys.length === 0) throw new HttpError(503, 'not_configured');
    const wire = await readBody(req, 16 * 1024);
    stats.request('delete', wire.length);
    if (String(req.headers['x-lf-schema'] || '') !== String(SCHEMA_VERSION)) throw new HttpError(400, 'unsupported_schema');
    const sig = verifySignature(cfg.ingestKeys, wire, req.headers['x-lf-sig']);
    if (!sig.ok) throw new HttpError(401, sig.reason === 'not_configured' ? 'not_configured' : 'invalid_signature');
    let body;
    try {
      body = JSON.parse(decodeBody(wire, req, cfg).toString('utf8'));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, 'malformed_json');
    }
    const installId = body && body.installId;
    if (typeof installId !== 'string' || !INSTALL_RE.test(installId)) throw new HttpError(400, 'bad_install_id');
    const headerId = String(req.headers['x-lf-install-id'] || '');
    if (headerId && headerId !== installId) throw new HttpError(400, 'install_mismatch');
    const il = limiter.checkInstallRequest(installId);
    if (!il.ok) throw new HttpError(429, 'rate_limited_install', { retryAfter: il.retryAfterSec });

    // 1) tombstone first: from this moment the install is excluded everywhere (ingest, digest, BQ views)
    await store.writeTombstone(installId, 'pending');
    erasedCache.set(installId, { erased: true, exp: Date.now() + 24 * 3600 * 1000 });
    // 2) drop anything still buffered in memory
    buffer.dropInstall(installId);
    // 3) physical purge of raw objects (background; the daily digest job re-runs it if this is interrupted)
    track(
      (async () => {
        try {
          await buffer.flushAll();
          await purgePendingErasures(store);
        } catch (e) {
          log('error', 'erasure_purge_failed', { err: e.message });
        }
      })()
    );
    return { status: 202, body: { accepted: 1, rejected: 0, schema: SCHEMA_VERSION, status: 'erasure_queued' } };
  }

  async function handleDigest(req, url) {
    if (!cfg.adminToken) throw new HttpError(404, 'not_found');
    const auth = String(req.headers.authorization || '');
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token || !safeEqualStr(token, cfg.adminToken)) throw new HttpError(401, 'unauthorized');
    await buffer.flushAll();
    await stats.flush();
    const date = url.searchParams.get('date') || addDays(utcDate(), -1);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new HttpError(400, 'bad_date');
    const digest = await generateDigest(store, cfg, { date });
    return { status: 200, body: { accepted: 1, rejected: 0, schema: SCHEMA_VERSION, date, summary: digest.summary } };
  }

  async function route(req, res) {
    const url = new URL(req.url, 'http://local');
    let path = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method;
    const ipKey = limiter.ipKey(clientIp(req, cfg));

    if ((path === '/healthz' || path === `${BASE}/healthz`) && method === 'GET') {
      return { status: 200, body: { status: 'ok', schema: SCHEMA_VERSION, service: 'lf-telemetry-ingest', version: SERVICE_VERSION, storage: storage.kind, pending: buffer.pending } };
    }
    if (path === `${BASE}/schema` && method === 'GET') {
      return { status: 200, body: validator.schema, headers: { 'Cache-Control': 'public, max-age=3600' } };
    }
    const postRoutes = { [`${BASE}/events`]: 'events', [`${BASE}/crash`]: 'crash', [`${BASE}/baseline`]: 'baseline' };
    if (postRoutes[path]) {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed', { allow: 'POST' });
      return handleIngest(req, res, postRoutes[path], ipKey);
    }
    if (path === `${BASE}/delete`) {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed', { allow: 'POST' });
      return handleDelete(req, res, ipKey);
    }
    if (path === '/internal/digest') {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed', { allow: 'POST' });
      return handleDigest(req, url);
    }
    throw new HttpError(404, 'not_found');
  }

  const server = http.createServer(async (req, res) => {
    try {
      const out = await route(req, res);
      stats.status(out.status);
      sendJson(res, out.status, out.body, out.headers);
    } catch (err) {
      let status = 500;
      let code = 'internal_error';
      const extra = {};
      if (err instanceof HttpError) {
        status = err.status;
        code = err.code;
        if (err.extra.retryAfter) extra['Retry-After'] = String(err.extra.retryAfter);
        if (err.extra.allow) extra.Allow = err.extra.allow;
      } else {
        // Never leak internals to clients; log class only (no payloads, no IPs).
        log('error', 'unhandled', { err: err && err.message ? String(err.message).slice(0, 200) : 'unknown' });
      }
      stats.status(status);
      const body = { accepted: 0, rejected: err instanceof HttpError && err.extra.rejected ? err.extra.rejected : 0, schema: SCHEMA_VERSION, error: code };
      if (status === 413) extra.Connection = 'close';
      sendJson(res, status, body, extra);
    }
  });
  server.headersTimeout = 20000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 5000;

  app.server = server;

  app.start = () => {
    buffer.start();
    stats.start();
    const sweep = setInterval(() => limiter.sweep(), 60_000);
    sweep.unref();
    app._sweep = sweep;
  };

  app.listen = (port = cfg.port, host = cfg.host) =>
    new Promise((resolve) => {
      app.start();
      server.listen(port, host, () => resolve(server.address()));
    });

  app.drain = async () => {
    await Promise.allSettled([...background]);
  };

  app.shutdown = async () => {
    buffer.stop();
    stats.stop();
    if (app._sweep) clearInterval(app._sweep);
    await new Promise((resolve) => server.close(() => resolve()));
    await app.drain();
    await buffer.flushAll();
    await stats.flush();
  };

  return app;
}

module.exports = { createApp, HttpError, hashInstall };
