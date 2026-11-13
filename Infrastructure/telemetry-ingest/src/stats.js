'use strict';

const { utcDate } = require('./eventStore');

/**
 * In-process ingest counters, periodically persisted as small JSON files so
 * the digest can report ingest health (accepted / rejected by reason) without
 * any database. Never records IPs, install ids or payloads.
 */
class Stats {
  constructor(eventStore, cfg, log = () => {}) {
    this.store = eventStore;
    this.cfg = cfg;
    this.log = log;
    this.reset();
    this.timer = null;
  }

  reset() {
    this.dt = utcDate();
    this.c = { requests: 0, accepted: 0, rejected: 0, bytesIn: 0, byEndpoint: {}, byType: {}, rejectReasons: {}, httpStatus: {}, stripped: 0 };
  }

  _inc(obj, key, n = 1) {
    obj[key] = (obj[key] || 0) + n;
  }

  request(endpoint, bytes) {
    this.c.requests += 1;
    this.c.bytesIn += bytes || 0;
    this._inc(this.c.byEndpoint, endpoint);
  }
  accepted(type) {
    this.c.accepted += 1;
    this._inc(this.c.byType, type);
  }
  rejected(reason, n = 1) {
    this.c.rejected += n;
    this._inc(this.c.rejectReasons, reason, n);
  }
  status(code) {
    this._inc(this.c.httpStatus, String(code));
  }

  hasData() {
    return this.c.requests > 0;
  }

  async flush() {
    if (!this.hasData()) return null;
    const snapshot = this.c;
    const dt = this.dt;
    this.reset();
    try {
      return await this.store.writeStats(dt, snapshot);
    } catch (e) {
      // Merge back so nothing is lost if storage is briefly unavailable.
      this.log('error', 'stats_flush_failed', { err: e.message });
      for (const [k, v] of Object.entries(snapshot)) {
        if (typeof v === 'number') this.c[k] += v;
        else for (const [kk, vv] of Object.entries(v)) this._inc(this.c[k], kk, vv);
      }
      return null;
    }
  }

  start() {
    if (this.cfg.statsFlushMs > 0 && !this.timer) {
      this.timer = setInterval(() => this.flush().catch(() => {}), this.cfg.statsFlushMs);
      this.timer.unref();
    }
  }
  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

module.exports = { Stats };
