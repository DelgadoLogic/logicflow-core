'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('../src/config');
const { FsStorage } = require('../src/storage/fs');
const { EventStore, addDays, hashInstall, PREFIX } = require('../src/eventStore');
const { generateDigest, cmpVersion } = require('../src/digest');
const { fingerprintEvent } = require('../src/fingerprint');
const { tmpDir, mkEvent, mkCrash } = require('./helpers');

function mkStore() {
  const dir = tmpDir();
  const cfg = loadConfig({ LF_STORAGE: 'fs', LF_DATA_DIR: dir });
  const store = new EventStore(new FsStorage(dir), cfg);
  return { dir, cfg, store };
}

/** Build a stored record (server fields included) for `day`. */
function rec(day, ev, extra = {}) {
  const e = { ...ev, payload: ev.payload };
  const consent = ev.type === 'baseline' ? 'extended' : 'standard';
  return { ...e, ts: `${day}T10:00:00.000Z`, receivedAt: `${day}T10:00:01.000Z`, dt: day, consent, fingerprint: fingerprintEvent(e), ingestId: 'test', ...extra };
}

async function put(store, day, events) {
  const byType = {};
  for (const e of events) (byType[e.type] ||= []).push(rec(day, e));
  for (const [t, rows] of Object.entries(byType)) await store.writePart(day, t, rows);
}

const DAY = '2026-09-20';

test('cmpVersion orders numerically', () => {
  assert.equal(cmpVersion('1.10.0', '1.9.0'), 1);
  assert.equal(cmpVersion('1.0.0', '1.0.0.0'), 0);
  assert.equal(cmpVersion('1.0.1', '1.1.0'), -1);
});

test('digest: new crash groups, scan/usage/baseline stats, files + latest written, README dictionary', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    await put(store, DAY, [
      mkCrash({ installId: 'inst_a_000000000001' }),
      mkCrash({ installId: 'inst_b_000000000002' }),
      mkCrash({ installId: 'inst_c_000000000003', appVersion: '1.0.1', osBuild: '10.0.22631.4317' }, { exceptionType: 'System.IO.IOException' }),
      mkEvent({ type: 'scan', installId: 'inst_a_000000000001', payload: { scanType: 'oneclick', healthScore: 70, durationMs: 1000, issues: [{ id: 'junk.temp', count: 5 }], bytesReclaimable: 1000 } }),
      mkEvent({ type: 'scan', installId: 'inst_b_000000000002', payload: { scanType: 'oneclick', healthScore: 90, durationMs: 3000 } }),
      mkEvent({ installId: 'inst_a_000000000001', tier: 'pro' }),
      mkEvent({ type: 'baseline', installId: 'inst_a_000000000001', payload: { hardware: { ramGb: 16, gpus: [{ vendor: 'NVIDIA', name: 'RTX', driverVersion: '1.2' }] } } }),
    ]);
    const { json, markdown } = await generateDigest(store, cfg, { date: DAY, now: new Date(`${DAY}T23:59:00Z`) });
    assert.equal(json.summary.events, 7);
    assert.equal(json.summary.activeInstalls, 3);
    assert.equal(json.summary.crashEvents, 3);
    assert.equal(json.summary.distinctCrashGroups, 2);
    assert.equal(json.summary.newCrashGroups, 2);
    assert.equal(json.topCrashGroups[0].count, 2);
    assert.equal(json.topCrashGroups[0].installs, 2);
    assert.equal(json.scan.count, 2);
    assert.equal(json.scan.avgHealthScore, 80);
    assert.equal(json.scan.topIssues[0].key, 'junk.temp');
    assert.equal(json.baseline.gpuVendors[0].key, 'NVIDIA');
    assert.equal(json.versionHealth[0].version, '1.0.1');
    assert.ok(json.affectedOsBuilds.length === 2);
    assert.ok(json.suggestedPrompts.length >= 2);
    assert.match(markdown, /# LogicFlow telemetry digest — 2026-09-20/);
    assert.match(markdown, /Top new crash groups/);
    for (const f of ['v1/digests/2026-09-20.md', 'v1/digests/2026-09-20.json', 'v1/digests/latest.md', 'v1/digests/latest.json', 'v1/README.md', `v1/rollups/daily/dt=${DAY}.json`, 'v1/crash_groups/state.json']) {
      assert.ok(fs.existsSync(path.join(dir, ...f.split('/'))), f);
    }
    const state = JSON.parse(fs.readFileSync(path.join(dir, 'v1', 'crash_groups', 'state.json'), 'utf8'));
    assert.ok(!JSON.stringify(state).includes('inst_a'), 'crash state never contains installIds');
    const rollup = fs.readFileSync(path.join(dir, 'v1', 'rollups', 'daily', `dt=${DAY}.json`), 'utf8');
    assert.ok(!rollup.includes('inst_a'), 'rollup never contains installIds');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('digest: idempotent for the same date; older date never overwrites latest', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    const d1 = '2026-09-21';
    const d2 = '2026-09-22';
    await put(store, d1, [mkCrash()]);
    await put(store, d2, [mkCrash()]);
    await generateDigest(store, cfg, { date: d2, now: new Date(`${d2}T23:00:00Z`) });
    await generateDigest(store, cfg, { date: d1, now: new Date(`${d2}T23:00:00Z`) });
    const latest = JSON.parse(fs.readFileSync(path.join(dir, 'v1', 'digests', 'latest.json'), 'utf8'));
    assert.equal(latest.date, d2);
    const before = JSON.parse(fs.readFileSync(path.join(dir, 'v1', 'crash_groups', 'state.json'), 'utf8'));
    await generateDigest(store, cfg, { date: d2, now: new Date(`${d2}T23:30:00Z`) });
    const after = JSON.parse(fs.readFileSync(path.join(dir, 'v1', 'crash_groups', 'state.json'), 'utf8'));
    const fp = Object.keys(after.groups)[0];
    assert.equal(after.groups[fp].totalEvents, before.groups[fp].totalEvents, 'no double counting');
    assert.equal(after.groups[fp].totalEvents, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('digest: regressions - fixed_but_seen (triage), new_in_version, reappeared after dormancy', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    const days = ['2026-08-01', '2026-08-02', '2026-09-10', '2026-09-11'];
    // same defect throughout (same fingerprint)
    await put(store, days[0], [mkCrash({ appVersion: '1.0.0' })]);
    await generateDigest(store, cfg, { date: days[0], now: new Date(`${days[0]}T23:00:00Z`) });
    const fp = fingerprintEvent(mkCrash());
    await store.putJson(`${PREFIX.triage}/crash_groups.json`, { [fp]: { status: 'fixed', fixedIn: '1.0.1', note: 'null check added' } });

    // new version still crashing + also seen after 14+ days dormancy
    await put(store, days[2], [mkCrash({ appVersion: '1.0.1' })]);
    const d = await generateDigest(store, cfg, { date: days[2], now: new Date(`${days[2]}T23:00:00Z`) });
    const types = d.json.regressions.map((r) => r.type).sort();
    assert.deepEqual(types, ['fixed_but_seen', 'new_in_version', 'reappeared']);
    const fixed = d.json.regressions.find((r) => r.type === 'fixed_but_seen');
    assert.equal(fixed.fixedIn, '1.0.1');
    assert.deepEqual(fixed.seenInVersions, ['1.0.1']);
    assert.equal(d.json.summary.newCrashGroups, 0);
    assert.match(d.markdown, /fixed in 1\.0\.1/);

    // a brand-new group on the next day is "new", not a regression
    await put(store, days[3], [mkCrash({ appVersion: '1.0.1' }, { exceptionType: 'System.OutOfMemoryException' })]);
    const d2 = await generateDigest(store, cfg, { date: days[3], now: new Date(`${days[3]}T23:00:00Z`) });
    assert.equal(d2.json.summary.newCrashGroups, 1);
    assert.equal(d2.json.regressions.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('digest: anomalies - crash spike vs 7-day baseline, dominant group, high reject rate, version crash rate', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    const D = '2026-09-30';
    for (let i = 1; i <= 5; i++) {
      const d = addDays(D, -i);
      await put(store, d, [mkEvent(), mkEvent(), mkCrash()]);
      await generateDigest(store, cfg, { date: d, now: new Date(`${d}T23:59:00Z`) });
    }
    const events = [];
    for (let i = 0; i < 40; i++) events.push(mkCrash({ installId: `inst_spike_${String(i).padStart(10, '0')}`, appVersion: '2.0.0' }));
    for (let i = 0; i < 5; i++) events.push(mkEvent({ installId: `inst_ok_${String(i).padStart(12, '0')}`, appVersion: '2.0.0' }));
    await put(store, D, events);
    await store.writeStats(D, { requests: 100, accepted: 45, rejected: 30, bytesIn: 1, byEndpoint: {}, byType: {}, rejectReasons: { schema_invalid: 30 }, httpStatus: { 200: 70, 401: 25, 429: 25 } });
    const { json } = await generateDigest(store, cfg, { date: D, now: new Date(`${D}T23:59:00Z`) });
    const codes = json.anomalies.map((a) => a.code);
    for (const c of ['volume_spike', 'dominant_group', 'reject_rate_high', 'invalid_signatures', 'rate_limited', 'version_crash_rate']) {
      assert.ok(codes.includes(c), `${c} in ${codes.join(',')}`);
    }
    assert.equal(json.ingestHealth.accepted, 45);
    assert.equal(json.ingestHealth.rejectReasons.schema_invalid, 30);
    assert.ok(json.suggestedPrompts.some((p) => p.startsWith('Anomaly')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('digest: erased installs are excluded and pending erasures are purged by the job', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    const D = '2026-09-25';
    await put(store, D, [mkCrash({ installId: 'inst_gone_00000000001' }), mkCrash({ installId: 'inst_stay_00000000002' })]);
    await store.writeTombstone('inst_gone_00000000001', 'pending');
    const { json } = await generateDigest(store, cfg, { date: D, now: new Date(`${D}T23:00:00Z`) });
    assert.equal(json.summary.crashEvents, 1);
    assert.equal(json.ingestHealth.erasuresProcessed, 1);
    const tomb = JSON.parse(fs.readFileSync(path.join(dir, 'v1', 'erasures', `${hashInstall('inst_gone_00000000001')}.json`), 'utf8'));
    assert.equal(tomb.status, 'completed');
    const rows = [];
    for await (const e of store.readEvents(D, undefined, { skipErased: false })) rows.push(e.installId);
    assert.deepEqual(rows, ['inst_stay_00000000002']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('digest on an empty day still produces valid output with a no_events note', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    const { json, markdown } = await generateDigest(store, cfg, { date: '2026-09-01', now: new Date('2026-09-02T00:10:00Z') });
    assert.equal(json.summary.events, 0);
    assert.ok(json.anomalies.some((a) => a.code === 'no_events'));
    assert.match(markdown, /No events/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('fs retention removes raw partitions older than the window (GCS uses lifecycle rules)', async () => {
  const { dir, cfg, store } = mkStore();
  try {
    await put(store, '2026-01-01', [mkEvent()]);
    await put(store, '2026-09-01', [mkEvent()]);
    await generateDigest(store, cfg, { date: '2026-09-01', now: new Date('2026-09-02T00:10:00Z') });
    assert.equal((await store.listPartKeys('2026-01-01')).length, 0);
    assert.equal((await store.listPartKeys('2026-09-01')).length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
