'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { startApp, stopApp, post, mkEvent, mkCrash, KEY, OLD_KEY } = require('./helpers');
const { utcDate, parseNdjsonGz, hashInstall } = require('../src/eventStore');
const { signBody } = require('../src/auth');

function readAllEvents(dir) {
  const out = [];
  const walk = (d) => {
    if (!fs.existsSync(d)) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (p.endsWith('.ndjson.gz')) out.push(...parseNdjsonGz(fs.readFileSync(p)));
    }
  };
  walk(path.join(dir, 'v1', 'events'));
  return out;
}

test('healthz and schema endpoints return JSON', async () => {
  const ctx = await startApp();
  try {
    for (const p of ['/healthz', '/v1/telemetry/healthz']) {
      const r = await fetch(ctx.base + p);
      assert.equal(r.status, 200);
      assert.match(r.headers.get('content-type'), /application\/json/);
      assert.equal((await r.json()).status, 'ok');
    }
    const s = await fetch(`${ctx.base}/v1/telemetry/schema`);
    assert.equal((await s.json()).title.includes('schema v1'), true);
  } finally {
    await stopApp(ctx);
  }
});

test('never returns HTML: 404/405/bad input are JSON with accepted/rejected/schema', async () => {
  const ctx = await startApp();
  try {
    const nf = await fetch(`${ctx.base}/nope`);
    assert.equal(nf.status, 404);
    assert.match(nf.headers.get('content-type'), /json/);
    const j = await nf.json();
    assert.deepEqual([j.accepted, j.rejected, j.schema], [0, 0, 1]);
    const m = await fetch(`${ctx.base}/v1/telemetry/events`);
    assert.equal(m.status, 405);
    assert.match(m.headers.get('content-type'), /json/);
    const r = await post(ctx.base, 'events', mkEvent(), { raw: '{not json' });
    assert.equal(r.status, 400);
    assert.ok(r.json && r.json.error);
  } finally {
    await stopApp(ctx);
  }
});

test('accepts batch JSON (plain + gzip) and NDJSON, stores partitioned gzip NDJSON', async () => {
  const ctx = await startApp();
  try {
    const a = [mkEvent(), mkEvent({ type: 'scan', payload: { scanType: 'oneclick', healthScore: 80 } })];
    const r1 = await post(ctx.base, 'events', a);
    assert.equal(r1.status, 200);
    assert.deepEqual(r1.json, { accepted: 2, rejected: 0, schema: 1 });
    const r2 = await post(ctx.base, 'events', [mkEvent()], { gzip: true });
    assert.equal(r2.json.accepted, 1);
    const r3 = await post(ctx.base, 'events', [mkEvent(), mkEvent()], { ndjson: true });
    assert.equal(r3.json.accepted, 2);
    const r4 = await post(ctx.base, 'events', [mkEvent(), mkEvent()], { ndjson: true, gzip: true });
    assert.equal(r4.json.accepted, 2);

    const today = utcDate();
    assert.ok(fs.existsSync(path.join(ctx.dir, 'v1', 'events', `dt=${today}`, 'type=usage')));
    assert.ok(fs.existsSync(path.join(ctx.dir, 'v1', 'events', `dt=${today}`, 'type=scan')));
    const evs = readAllEvents(ctx.dir);
    assert.equal(evs.length, 7);
    for (const e of evs) {
      assert.equal(e.dt, today);
      assert.equal(e.consent, 'extended');
      assert.ok(e.receivedAt && e.ingestId);
    }
  } finally {
    await stopApp(ctx);
  }
});

test('server fields cannot be overridden by the client; PII scrubbed server-side; fingerprint set', async () => {
  const ctx = await startApp();
  try {
    const e = mkCrash({ receivedAt: '1999-01-01T00:00:00Z', fingerprint: 'evil', consent: 'extended', dt: '1999-01-01', ingestId: 'evil', client_ip: '1.2.3.4' }, { message: 'user bob@evil.com at C:\\Users\\Bob\\x.txt ip 10.1.2.3' });
    const r = await post(ctx.base, 'crash', e, { consent: 'standard' });
    assert.equal(r.json.accepted, 1);
    const [row] = readAllEvents(ctx.dir);
    assert.notEqual(row.receivedAt, '1999-01-01T00:00:00Z');
    assert.match(row.fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(row.consent, 'standard');
    assert.equal(row.dt, utcDate());
    assert.notEqual(row.ingestId, 'evil');
    assert.equal('client_ip' in row, false);
    assert.ok(!/bob|Bob|10\.1\.2\.3/.test(JSON.stringify(row)));
  } finally {
    await stopApp(ctx);
  }
});

test('auth: missing / bad signature -> 401; rotated old key accepted; unconfigured -> 503', async () => {
  const ctx = await startApp();
  try {
    const bad = await post(ctx.base, 'events', mkEvent(), { key: 'wrong-key' });
    assert.equal(bad.status, 401);
    const miss = await post(ctx.base, 'events', mkEvent(), { headers: { 'X-LF-Sig': '' } });
    assert.equal(miss.status, 401);
    const old = await post(ctx.base, 'events', mkEvent(), { key: OLD_KEY });
    assert.equal(old.status, 200);
    assert.equal(readAllEvents(ctx.dir).length, 1);
  } finally {
    await stopApp(ctx);
  }
  const ctx2 = await startApp({ LF_INGEST_KEYS: '' });
  try {
    const r = await post(ctx2.base, 'events', mkEvent());
    assert.equal(r.status, 503);
    assert.equal(r.json.error, 'not_configured');
  } finally {
    await stopApp(ctx2);
  }
});

test('consent gate: none / invalid -> 403 and nothing stored; standard allows usage/scan/crash/error but cannot carry baseline; extended can', async () => {
  const ctx = await startApp();
  try {
    const none = await post(ctx.base, 'events', mkEvent(), { consent: null });
    assert.equal(none.status, 403);
    assert.equal(none.json.error, 'consent_required');
    const inv = await post(ctx.base, 'events', mkEvent(), { consent: 'maybe' });
    assert.equal(inv.status, 403);
    assert.equal(readAllEvents(ctx.dir).length, 0);
    const std = await post(
      ctx.base,
      'events',
      [mkEvent(), mkEvent({ type: 'scan', payload: { scanType: 's' } }), mkEvent({ type: 'baseline', payload: {} })],
      { consent: 'standard' }
    );
    assert.deepEqual([std.json.accepted, std.json.rejected], [2, 1]);
    assert.equal(std.json.reasons.consent_level_insufficient, 1);
    const stdBase = await post(ctx.base, 'baseline', mkEvent({ type: 'baseline', payload: {} }), { consent: 'standard' });
    assert.deepEqual([stdBase.json.accepted, stdBase.json.rejected], [0, 1]);
    assert.equal(stdBase.json.reasons.consent_level_insufficient, 1);
    const ext = await post(ctx.base, 'baseline', mkEvent({ type: 'baseline', payload: {} }), { consent: 'extended' });
    assert.equal(ext.json.accepted, 1);
  } finally {
    await stopApp(ctx);
  }
});

test('rejections: tier=free, install mismatch, schema/payload invalid, stale ts, duplicate eventId, wrong endpoint', async () => {
  const ctx = await startApp();
  try {
    const dupe = mkEvent();
    const r = await post(ctx.base, 'events', [
      mkEvent({ tier: 'free' }),
      mkEvent({ installId: 'inst_other_00000000099' }),
      mkEvent({ region: 'XYZ' }),
      mkEvent({ payload: { feature: 'x' } }),
      mkEvent({ ts: new Date(Date.now() - 40 * 86400000).toISOString() }),
      mkEvent({ ts: new Date(Date.now() + 3 * 86400000).toISOString() }),
      dupe,
      dupe,
      mkEvent({ type: 'baseline', payload: {} }),
    ]);
    assert.equal(r.status, 200);
    assert.equal(r.json.accepted, 2); // dupe once + baseline via /events
    assert.equal(r.json.rejected, 7);
    assert.deepEqual(
      Object.keys(r.json.reasons).sort(),
      ['duplicate', 'install_mismatch', 'payload_invalid', 'schema_invalid', 'tier_free_not_allowed', 'timestamp_out_of_range'].sort()
    );
    const wrong = await post(ctx.base, 'crash', mkEvent());
    assert.equal(wrong.json.reasons.wrong_endpoint_for_type, 1);
    const wrong2 = await post(ctx.base, 'baseline', mkEvent({ type: 'crash', payload: mkCrash().payload }));
    assert.equal(wrong2.json.reasons.wrong_endpoint_for_type, 1);
  } finally {
    await stopApp(ctx);
  }
});

test('limits: oversize body 413, too many events 413, oversized single event rejected, gzip bomb 413', async () => {
  const ctx = await startApp({ LF_MAX_BODY_BYTES: '4000', LF_MAX_EVENTS_PER_REQUEST: '3', LF_MAX_EVENT_BYTES: '600', LF_MAX_DECODED_BYTES: '20000' });
  try {
    const big = await post(ctx.base, 'events', mkEvent(), { raw: 'x'.repeat(5000) });
    assert.equal(big.status, 413);
    assert.equal(big.json.error, 'payload_too_large');
    const many = await post(ctx.base, 'events', [mkEvent(), mkEvent(), mkEvent(), mkEvent()]);
    assert.equal(many.status, 413);
    const bigEvent = await post(ctx.base, 'events', mkEvent({ payload: { feature: 'f', action: 'a', props: Array.from({ length: 16 }, (_, i) => ({ k: 'key' + i, v: 'v'.repeat(60) })) } }));
    assert.equal(bigEvent.json.reasons.event_too_large, 1);
    const bomb = zlib.gzipSync(Buffer.alloc(200000, 0x20));
    const bm = await post(ctx.base, 'events', mkEvent(), { raw: bomb, headers: { 'Content-Encoding': 'gzip', 'Content-Type': 'application/json' } });
    assert.equal(bm.status, 413);
  } finally {
    await stopApp(ctx);
  }
});

test('rate limiting: per-install requests and events -> 429 with Retry-After, JSON body', async () => {
  const ctx = await startApp({ LF_RATE_INSTALL_REQ_MIN: '2', LF_RATE_INSTALL_EVENTS_HOUR: '4' });
  try {
    assert.equal((await post(ctx.base, 'events', [mkEvent(), mkEvent(), mkEvent()])).status, 200);
    const over = await post(ctx.base, 'events', [mkEvent(), mkEvent()]);
    assert.equal(over.status, 429);
    assert.equal(over.json.error, 'rate_limited_install');
    assert.equal(over.json.rejected, 2);
    assert.ok(over.headers.get('retry-after'));
    const third = await post(ctx.base, 'events', [mkEvent()]);
    assert.equal(third.status, 429);
  } finally {
    await stopApp(ctx);
  }
  const ip = await startApp({ LF_RATE_IP_REQ_MIN: '2' });
  try {
    await post(ip.base, 'events', mkEvent());
    await post(ip.base, 'events', mkEvent());
    const r = await post(ip.base, 'events', mkEvent());
    assert.equal(r.status, 429);
    assert.equal(r.json.error, 'rate_limited_ip');
  } finally {
    await stopApp(ip);
  }
});

test('buffering: events are held until flush thresholds, then written as one part; shutdown flushes', async () => {
  const ctx = await startApp({ LF_FLUSH_INTERVAL_MS: '60000', LF_FLUSH_EVENTS: '3' });
  try {
    await post(ctx.base, 'events', [mkEvent(), mkEvent()]);
    assert.equal(readAllEvents(ctx.dir).length, 0);
    assert.equal(ctx.app.buffer.pending, 2);
    await post(ctx.base, 'events', [mkEvent(), mkEvent()]);
    await ctx.app.drain();
    assert.equal(readAllEvents(ctx.dir).length, 4);
    await post(ctx.base, 'events', [mkEvent()]);
    assert.equal(ctx.app.buffer.pending, 1);
    await ctx.app.buffer.flushAll();
    assert.equal(readAllEvents(ctx.dir).length, 5);
  } finally {
    await stopApp(ctx);
  }
});

test('right to erasure: /delete tombstones, purges raw rows, blocks future events (410), is signed, idempotent', async () => {
  const ctx = await startApp();
  try {
    const victim = 'inst_victim_000000001';
    const other = 'inst_bystander_00000001';
    await post(ctx.base, 'events', [mkEvent({ installId: victim }), mkEvent({ installId: victim })]);
    await post(ctx.base, 'events', [mkEvent({ installId: other })]);
    assert.equal(readAllEvents(ctx.dir).length, 3);

    const body = Buffer.from(JSON.stringify({ installId: victim }));
    const unsigned = await fetch(`${ctx.base}/v1/telemetry/delete`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-LF-Schema': '1', 'X-LF-Sig': signBody('bad', body) }, body });
    assert.equal(unsigned.status, 401);

    const hdr = { 'Content-Type': 'application/json', 'X-LF-Schema': '1', 'X-LF-Install-Id': victim, 'X-LF-Sig': signBody(KEY, body) };
    const del = await fetch(`${ctx.base}/v1/telemetry/delete`, { method: 'POST', headers: hdr, body });
    assert.equal(del.status, 202);
    const dj = await del.json();
    assert.deepEqual([dj.accepted, dj.rejected, dj.schema], [1, 0, 1]);
    await ctx.app.drain();

    const left = readAllEvents(ctx.dir);
    assert.equal(left.length, 1);
    assert.equal(left[0].installId, other);
    const tombFile = path.join(ctx.dir, 'v1', 'erasures', `${hashInstall(victim)}.json`);
    const tomb = JSON.parse(fs.readFileSync(tombFile, 'utf8'));
    assert.equal(tomb.status, 'completed');
    assert.ok(!fs.readFileSync(tombFile, 'utf8').includes(victim), 'raw installId never stored in tombstone');

    const again = await post(ctx.base, 'events', mkEvent({ installId: victim }));
    assert.equal(again.status, 410);
    assert.equal(again.json.error, 'install_erased');
    const del2 = await fetch(`${ctx.base}/v1/telemetry/delete`, { method: 'POST', headers: hdr, body });
    assert.equal(del2.status, 202);
    assert.equal((await post(ctx.base, 'events', mkEvent({ installId: other }))).status, 200);
  } finally {
    await stopApp(ctx);
  }
});

test('/delete drops events still sitting in the memory buffer', async () => {
  const ctx = await startApp({ LF_FLUSH_INTERVAL_MS: '60000' });
  try {
    const id = 'inst_buffered_00000001';
    await post(ctx.base, 'events', [mkEvent({ installId: id })]);
    assert.equal(ctx.app.buffer.pending, 1);
    const body = Buffer.from(JSON.stringify({ installId: id }));
    await fetch(`${ctx.base}/v1/telemetry/delete`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-LF-Schema': '1', 'X-LF-Install-Id': id, 'X-LF-Sig': signBody(KEY, body) }, body });
    await ctx.app.drain();
    await ctx.app.buffer.flushAll();
    assert.equal(readAllEvents(ctx.dir).length, 0);
  } finally {
    await stopApp(ctx);
  }
});

test('stats are persisted for the digest (accepted/rejected/reasons/http status)', async () => {
  const ctx = await startApp();
  try {
    await post(ctx.base, 'events', [mkEvent(), mkEvent({ tier: 'free' })]);
    await post(ctx.base, 'events', mkEvent(), { key: 'bad' });
    await ctx.app.stats.flush();
    const docs = await ctx.app.store.readStats(utcDate());
    assert.equal(docs.length, 1);
    const c = docs[0].counters;
    assert.equal(c.accepted, 1);
    assert.equal(c.rejected, 1);
    assert.equal(c.rejectReasons.tier_free_not_allowed, 1);
    assert.equal(c.httpStatus['401'], 1);
    assert.ok(!JSON.stringify(docs).includes('127.0.0.1'));
  } finally {
    await stopApp(ctx);
  }
});

test('schema mismatch header and bad install id headers -> 400 JSON', async () => {
  const ctx = await startApp();
  try {
    assert.equal((await post(ctx.base, 'events', mkEvent(), { headers: { 'X-LF-Schema': '2' } })).status, 400);
    assert.equal((await post(ctx.base, 'events', mkEvent(), { headers: { 'X-LF-Install-Id': 'x' } })).status, 400);
    assert.equal((await post(ctx.base, 'events', mkEvent(), { version: 'abc' })).status, 400);
  } finally {
    await stopApp(ctx);
  }
});

test('digest endpoint requires admin token', async () => {
  const ctx = await startApp();
  try {
    await post(ctx.base, 'crash', mkCrash());
    const no = await fetch(`${ctx.base}/internal/digest?date=${utcDate()}`, { method: 'POST' });
    assert.equal(no.status, 401);
    const ok = await fetch(`${ctx.base}/internal/digest?date=${utcDate()}`, { method: 'POST', headers: { Authorization: 'Bearer admin-test-token' } });
    assert.equal(ok.status, 200);
    const j = await ok.json();
    assert.equal(j.summary.crashEvents, 1);
    assert.ok(fs.existsSync(path.join(ctx.dir, 'v1', 'digests', 'latest.md')));
    const off = await startApp({ LF_ADMIN_TOKEN: '' });
    try {
      assert.equal((await fetch(`${off.base}/internal/digest`, { method: 'POST' })).status, 404);
    } finally {
      await stopApp(off);
    }
  } finally {
    await stopApp(ctx);
  }
});

test('send-sample.js CLI integration exercises events, crash, baseline, and --with-delete against live server', async () => {
  const { execFile } = require('node:child_process');
  const { promisify } = require('node:util');
  const execFileAsync = promisify(execFile);
  const ctx = await startApp();
  try {
    const script = path.join(__dirname, '..', 'scripts', 'send-sample.js');
    const { stdout: out } = await execFileAsync(process.execPath, [script, '--with-delete', ctx.base, KEY], { encoding: 'utf8' });
    assert.match(out, /^events 200 /m);
    assert.match(out, /^crash 200 /m);
    assert.match(out, /^baseline 200 /m);
    assert.match(out, /^delete 202 /m);
    await ctx.app.drain();
    const tombFile = path.join(ctx.dir, 'v1', 'erasures', `${hashInstall('inst_ephemeral_delete_01')}.json`);
    assert.ok(fs.existsSync(tombFile), 'erasure tombstone written by --with-delete');
  } finally {
    await stopApp(ctx);
  }
});

