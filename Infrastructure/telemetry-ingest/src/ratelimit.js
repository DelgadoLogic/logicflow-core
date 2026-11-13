'use strict';

const crypto = require('node:crypto');

/**
 * Sliding-window-ish counters keyed by an opaque string.
 * IPs are NEVER stored: callers pass `ipKey()` output, an HMAC of the IP with a
 * random in-memory salt that is rotated (and old buckets dropped) periodically.
 */
class Counter {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this.map = new Map(); // key -> {start, count}
  }
  /** Try to consume n units against `limit`. Returns {ok, retryAfterSec}. */
  take(key, n, limit, now = Date.now()) {
    if (!(limit > 0)) return { ok: true, retryAfterSec: 0 }; // limit <= 0 disables
    let b = this.map.get(key);
    if (!b || now - b.start >= this.windowMs) {
      b = { start: now, count: 0 };
      this.map.set(key, b);
    }
    if (b.count + n > limit) {
      return { ok: false, retryAfterSec: Math.max(1, Math.ceil((b.start + this.windowMs - now) / 1000)) };
    }
    b.count += n;
    return { ok: true, retryAfterSec: 0 };
  }
  sweep(now = Date.now()) {
    for (const [k, b] of this.map) if (now - b.start >= this.windowMs) this.map.delete(k);
  }
  get size() {
    return this.map.size;
  }
}

class RateLimiter {
  constructor(cfg, clock = Date.now) {
    this.cfg = cfg;
    this.clock = clock;
    this.installReqMin = new Counter(60_000);
    this.installEventsHr = new Counter(3_600_000);
    this.ipReqMin = new Counter(60_000);
    this.ipEventsHr = new Counter(3_600_000);
    this.salt = crypto.randomBytes(16);
    this.saltBorn = clock();
  }

  /** In-memory, rotating-salt hash of the client IP. Never logged or persisted. */
  ipKey(ip) {
    const now = this.clock();
    if (now - this.saltBorn >= this.cfg.saltRotateMs) {
      this.salt = crypto.randomBytes(16);
      this.saltBorn = now;
      this.ipReqMin.map.clear();
      this.ipEventsHr.map.clear();
    }
    return crypto.createHmac('sha256', this.salt).update(String(ip || 'unknown')).digest('hex').slice(0, 24);
  }

  checkIpRequest(ipKey) {
    const a = this.ipReqMin.take(ipKey, 1, this.cfg.ipRequestsPerMin, this.clock());
    return a.ok ? { ok: true } : { ok: false, scope: 'ip', retryAfterSec: a.retryAfterSec };
  }

  checkInstallRequest(installId) {
    const b = this.installReqMin.take(installId, 1, this.cfg.installRequestsPerMin, this.clock());
    return b.ok ? { ok: true } : { ok: false, scope: 'install', retryAfterSec: b.retryAfterSec };
  }

  checkRequest({ ipKey, installId }) {
    const now = this.clock();
    const a = this.ipReqMin.take(ipKey, 1, this.cfg.ipRequestsPerMin, now);
    if (!a.ok) return { ok: false, scope: 'ip', retryAfterSec: a.retryAfterSec };
    if (installId) {
      const b = this.installReqMin.take(installId, 1, this.cfg.installRequestsPerMin, now);
      if (!b.ok) return { ok: false, scope: 'install', retryAfterSec: b.retryAfterSec };
    }
    return { ok: true };
  }

  /** Consume event budget; returns how many of `n` are allowed (all-or-nothing per scope). */
  checkEvents({ ipKey, installId }, n) {
    const now = this.clock();
    const a = this.ipEventsHr.take(ipKey, n, this.cfg.ipEventsPerHour, now);
    if (!a.ok) return { ok: false, scope: 'ip', retryAfterSec: a.retryAfterSec };
    const b = this.installEventsHr.take(installId, n, this.cfg.installEventsPerHour, now);
    if (!b.ok) return { ok: false, scope: 'install', retryAfterSec: b.retryAfterSec };
    return { ok: true };
  }

  sweep() {
    for (const c of [this.installReqMin, this.installEventsHr, this.ipReqMin, this.ipEventsHr]) c.sweep(this.clock());
  }
}

/** Bounded TTL set used for eventId dedupe. */
class DedupeSet {
  constructor(max, ttlMs, clock = Date.now) {
    this.max = max;
    this.ttlMs = ttlMs;
    this.clock = clock;
    this.map = new Map(); // id -> expiry
  }
  /** @returns true if `id` was already seen (duplicate). Records it otherwise. */
  seen(id) {
    const now = this.clock();
    const exp = this.map.get(id);
    if (exp !== undefined && exp > now) return true;
    if (exp !== undefined) this.map.delete(id);
    this.map.set(id, now + this.ttlMs);
    if (this.map.size > this.max) {
      // Map preserves insertion order -> drop oldest.
      const it = this.map.keys();
      for (let i = 0; i < Math.ceil(this.max * 0.1); i++) {
        const k = it.next();
        if (k.done) break;
        this.map.delete(k.value);
      }
    }
    return false;
  }
  forget(id) {
    this.map.delete(id);
  }
  get size() {
    return this.map.size;
  }
}

module.exports = { RateLimiter, DedupeSet, Counter };
