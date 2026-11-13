'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { signBody } = require('../src/auth');

const KEY = 'test-ingest-key-1';
const OLD_KEY = 'test-ingest-key-0';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lf-ingest-'));
}

function uuid() {
  return crypto.randomUUID();
}

function mkEvent(over = {}) {
  return {
    schema: 1,
    eventId: uuid(),
    type: 'usage',
    ts: new Date().toISOString(),
    installId: 'inst_test_0000000001',
    appVersion: '1.0.0',
    osBuild: '10.0.26100.1742',
    arch: 'x64',
    tier: 'community',
    region: 'US',
    payload: { feature: 'junk-cleaner', action: 'run', count: 1 },
    ...over,
  };
}

function mkCrash(over = {}, payloadOver = {}) {
  return mkEvent({
    type: 'crash',
    payload: {
      exceptionType: 'System.NullReferenceException',
      message: 'boom',
      frames: [
        'LogicFlow.Core.Services.JunkCleaner.ScanAsync(CancellationToken ct) in C:\\src\\JunkCleaner.cs:line 140',
        'LogicFlow.Dashboard.ViewModels.CleanupViewModel.RunAsync() in C:\\src\\CleanupViewModel.cs:line 77',
        'System.Threading.Tasks.Task.Execute()',
      ],
      ...payloadOver,
    },
    ...over,
  });
}

async function startApp(cfgEnv = {}) {
  const dir = tmpDir();
  const cfg = loadConfig({
    LF_STORAGE: 'fs',
    LF_DATA_DIR: dir,
    LF_INGEST_KEYS: `${KEY},${OLD_KEY}`,
    LF_ADMIN_TOKEN: 'admin-test-token',
    LF_FLUSH_INTERVAL_MS: '0', // write-through for deterministic tests
    LF_STATS_FLUSH_MS: '0',
    LF_RATE_IP_REQ_MIN: '0',
    ...cfgEnv,
  });
  const app = createApp({ cfg, quiet: true });
  const addr = await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${addr.port}`;
  return { app, dir, base, cfg };
}

async function stopApp(ctx) {
  await ctx.app.shutdown();
  fs.rmSync(ctx.dir, { recursive: true, force: true });
}

async function post(base, endpoint, events, opts = {}) {
  const { gzip = false, ndjson = false, consent = 'extended', key = KEY, installId, headers = {}, raw, version } = opts;
  const arr = Array.isArray(events) ? events : [events];
  let body;
  if (raw !== undefined) body = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  else if (ndjson) body = Buffer.from(arr.map((e) => JSON.stringify(e)).join('\n'));
  else body = Buffer.from(JSON.stringify(arr));
  if (gzip) body = zlib.gzipSync(body);
  const h = {
    'Content-Type': ndjson ? 'application/x-ndjson' : 'application/json',
    'X-LF-Schema': '1',
    'X-LF-Install-Id': installId || (arr[0] && arr[0].installId) || 'inst_test_0000000001',
    'X-LF-Version': version || (arr[0] && arr[0].appVersion) || '1.0.0',
    'X-LF-Sig': signBody(key, body),
    ...(gzip ? { 'Content-Encoding': 'gzip' } : {}),
    ...headers,
  };
  if (consent) h['X-LF-Consent'] = consent;
  const res = await fetch(`${base}/v1/telemetry/${endpoint}`, { method: 'POST', headers: h, body });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  return { status: res.status, json, text, headers: res.headers };
}

module.exports = { KEY, OLD_KEY, tmpDir, uuid, mkEvent, mkCrash, startApp, stopApp, post };
