'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scrubString, scrubValue } = require('../src/scrub');
const { fingerprintEvent, normalizeFrame, topFrames } = require('../src/fingerprint');
const { createValidator } = require('../src/validate');
const { verifySignature, signBody } = require('../src/auth');
const { RateLimiter, DedupeSet } = require('../src/ratelimit');
const { mkEvent, mkCrash } = require('./helpers');

test('scrub: user profile paths, emails, IPs, hosts, SIDs, licence keys', () => {
  const s = scrubString(
    'fail at C:\\Users\\John Smith\\Documents\\a.txt mail john.doe@example.com ip 192.168.1.20 fe80::1ff:fe23:4567:890a host DESKTOP-AB12CD3 sid S-1-5-21-1111111111-2222222222-3333333333-1001 key DL-PRO-0123456789AB'
  );
  assert.ok(!/John|Smith|john\.doe|192\.168|DESKTOP-AB12CD3|S-1-5-21|0123456789AB|fe80/.test(s), s);
  assert.ok(s.includes('<UserProfile>') && s.includes('<email>') && s.includes('<ip>') && s.includes('<host>') && s.includes('<sid>') && s.includes('<license>'));
});

test('scrub: other absolute paths keep only the file name; system roots keep a label', () => {
  assert.equal(scrubString('open D:\\secret\\stuff\\report.xlsx failed'), 'open <path>\\report.xlsx failed');
  assert.ok(scrubString('C:\\Program Files\\LogicFlow\\lf.exe crashed').startsWith('<ProgramFiles>\\LogicFlow\\lf.exe'));
  assert.ok(scrubString('\\\\NAS01\\share\\file.txt').includes('<host>'));
  assert.ok(!scrubString('/home/alice/.config/x').includes('alice'));
});

test('scrub: deep value traversal and non-strings untouched', () => {
  const v = scrubValue({ a: 'x@y.com', n: 5, b: [{ c: 'C:\\Users\\bob\\z' }], t: true });
  assert.deepEqual(v, { a: '<email>', n: 5, b: [{ c: '<UserProfile>\\z' }], t: true });
});

test('fingerprint: stable across line numbers, generics, lambdas; differs by exception type', () => {
  const a = mkCrash();
  const b = mkCrash({}, {
    frames: [
      'LogicFlow.Core.Services.JunkCleaner.ScanAsync(CancellationToken ct) in C:\\other\\path\\JunkCleaner.cs:line 999',
      'LogicFlow.Dashboard.ViewModels.CleanupViewModel.RunAsync() in C:\\x\\CleanupViewModel.cs:line 1',
      'System.Runtime.CompilerServices.TaskAwaiter.ThrowForNonSuccess(Task task)',
    ],
  });
  assert.equal(fingerprintEvent(a), fingerprintEvent(b));
  const c = mkCrash({}, { exceptionType: 'System.InvalidOperationException' });
  assert.notEqual(fingerprintEvent(a), fingerprintEvent(c));
  assert.match(fingerprintEvent(a), /^[0-9a-f]{64}$/);
  assert.equal(fingerprintEvent(mkEvent()), null);
});

test('fingerprint: framework frames skipped when in-app frames exist; top 3 only', () => {
  const frames = ['System.Linq.Enumerable.First()', 'LogicFlow.A.B()', 'LogicFlow.C.D()', 'LogicFlow.E.F()', 'LogicFlow.G.H()'];
  assert.deepEqual(topFrames(frames), ['LogicFlow.A.B()', 'LogicFlow.C.D()', 'LogicFlow.E.F()']);
  assert.equal(normalizeFrame('at Foo.Bar<>c__DisplayClass12_0.<Run>b__3_1(String p) in C:\\x.cs:line 5'), 'Foo.Bar<>c__DisplayClass.<Run>b__(String p)');
});

test('validate: accepts a good event, strips client-supplied server fields and unknown payload keys', () => {
  const { validateEvent } = createValidator();
  const e = mkEvent({ receivedAt: 'x', consent: 'extended', fingerprint: 'f', ingestId: 'i', dt: '1999-01-01' });
  e.payload.sneaky = 'x';
  const r = validateEvent(e);
  assert.equal(r.ok, true);
  for (const k of ['receivedAt', 'consent', 'fingerprint', 'ingestId', 'dt']) assert.equal(k in r.event, false, k);
  assert.equal('sneaky' in r.event.payload, false);
});

test('validate: rejects bad enum, ids, versions, regions, oversize strings', () => {
  const { validateEvent } = createValidator();
  assert.equal(validateEvent(mkEvent({ type: 'nope' })).ok, false);
  assert.equal(validateEvent(mkEvent({ installId: 'short' })).ok, false);
  assert.equal(validateEvent(mkEvent({ appVersion: 'latest' })).ok, false);
  assert.equal(validateEvent(mkEvent({ region: 'usa' })).ok, false);
  assert.equal(validateEvent(mkEvent({ schema: 2 })).ok, false);
  assert.equal(validateEvent(mkEvent({ ts: 'yesterday' })).ok, false);
  const big = mkCrash({}, { message: 'x'.repeat(1001) });
  assert.equal(validateEvent(big).reason, 'payload_invalid');
  assert.equal(validateEvent(null).ok, false);
  assert.equal(validateEvent([]).ok, false);
});

test('auth: HMAC verify, key rotation list, bad/missing/malformed signatures', () => {
  const body = Buffer.from('{"x":1}');
  const sig = signBody('k1', body);
  assert.equal(verifySignature(['k0', 'k1'], body, sig).ok, true);
  assert.equal(verifySignature(['k0', 'k1'], body, `sha256=${sig.toUpperCase()}`).ok, true);
  assert.equal(verifySignature(['k0'], body, sig).reason, 'bad_signature');
  assert.equal(verifySignature(['k1'], body, undefined).reason, 'missing_signature');
  assert.equal(verifySignature(['k1'], body, 'zz').reason, 'bad_signature');
  assert.equal(verifySignature([], body, sig).reason, 'not_configured');
  assert.equal(verifySignature(['k1'], Buffer.from('{"x":2}'), sig).ok, false);
});

test('ratelimit: per-install events, per-IP requests, salt rotation drops IP buckets, never stores raw IP', () => {
  let t = 1_000_000;
  const clock = () => t;
  const rl = new RateLimiter({ installEventsPerHour: 10, installRequestsPerMin: 2, ipRequestsPerMin: 3, ipEventsPerHour: 100, saltRotateMs: 1000 }, clock);
  const k = rl.ipKey('203.0.113.9');
  assert.ok(!k.includes('203'));
  assert.equal(rl.checkIpRequest(k).ok, true);
  assert.equal(rl.checkIpRequest(k).ok, true);
  assert.equal(rl.checkIpRequest(k).ok, true);
  assert.equal(rl.checkIpRequest(k).ok, false);
  assert.equal(rl.checkEvents({ ipKey: k, installId: 'a' }, 10).ok, true);
  const over = rl.checkEvents({ ipKey: k, installId: 'a' }, 1);
  assert.equal(over.ok, false);
  assert.equal(over.scope, 'install');
  assert.equal(rl.checkInstallRequest('b').ok, true);
  assert.equal(rl.checkInstallRequest('b').ok, true);
  assert.equal(rl.checkInstallRequest('b').ok, false);
  t += 2000; // salt rotates
  const k2 = rl.ipKey('203.0.113.9');
  assert.notEqual(k, k2);
  assert.equal(rl.checkIpRequest(k2).ok, true);
  assert.equal(new RateLimiter({ ipRequestsPerMin: 0 }, clock).checkIpRequest('x').ok, true, 'limit 0 disables');
});

test('dedupe: remembers within ttl, evicts oldest past max', () => {
  let t = 0;
  const d = new DedupeSet(10, 1000, () => t);
  assert.equal(d.seen('a'), false);
  assert.equal(d.seen('a'), true);
  t = 2000;
  assert.equal(d.seen('a'), false, 'expired');
  for (let i = 0; i < 30; i++) d.seen('k' + i);
  assert.ok(d.size <= 11);
});
