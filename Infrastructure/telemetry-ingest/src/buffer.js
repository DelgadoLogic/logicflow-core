'use strict';

/**
 * Batches accepted records per (dt,type) and flushes them as one gzip NDJSON
 * part file when a size/count/age threshold is hit, on shutdown, or on demand.
 * flushIntervalMs = 0 means write-through (one part per request batch).
 *
 * Durability note: records are acknowledged to the client once buffered. With
 * flushIntervalMs > 0 up to that interval of events can be lost if the
 * container is killed hard. SIGTERM triggers a final flush; for stronger
 * guarantees run with LF_FLUSH_INTERVAL_MS=0.
 */
class WriteBuffer {
  constructor(eventStore, cfg, log = () => {}) {
    this.store = eventStore;
    this.cfg = cfg;
    this.log = log;
    this.buckets = new Map(); // `${dt}|${type}` -> {dt,type,lines:[],bytes,born}
    this.timer = null;
    this.flushing = Promise.resolve();
  }

  start() {
    if (this.cfg.flushIntervalMs > 0 && !this.timer) {
      this.timer = setInterval(() => {
        this.flushDue().catch((e) => this.log('error', 'flush_timer_failed', { err: e.message }));
      }, Math.max(1000, Math.floor(this.cfg.flushIntervalMs / 2)));
      this.timer.unref();
    }
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  add(record) {
    const dt = record.dt;
    const key = `${dt}|${record.type}`;
    let b = this.buckets.get(key);
    if (!b) {
      b = { dt, type: record.type, records: [], bytes: 0, born: Date.now() };
      this.buckets.set(key, b);
    }
    const line = JSON.stringify(record);
    b.records.push(record);
    b.bytes += line.length + 1;
  }

  /** Remove buffered rows of an installId (used by /delete before disk purge). */
  dropInstall(installId) {
    let removed = 0;
    for (const b of this.buckets.values()) {
      const before = b.records.length;
      b.records = b.records.filter((r) => r.installId !== installId);
      removed += before - b.records.length;
    }
    return removed;
  }

  _due(b, now) {
    if (this.cfg.flushIntervalMs === 0) return true;
    return b.bytes >= this.cfg.flushBytes || b.records.length >= this.cfg.flushEvents || now - b.born >= this.cfg.flushIntervalMs;
  }

  async flushDue() {
    const now = Date.now();
    const due = [...this.buckets.entries()].filter(([, b]) => b.records.length > 0 && this._due(b, now));
    await this._flushBuckets(due);
  }

  async flushAll() {
    await this._flushBuckets([...this.buckets.entries()].filter(([, b]) => b.records.length > 0));
  }

  _flushBuckets(entries) {
    // Serialise flushes; swap buckets out first so new adds go to fresh buffers.
    const taken = [];
    for (const [k, b] of entries) {
      this.buckets.delete(k);
      taken.push(b);
    }
    this.flushing = this.flushing.then(async () => {
      for (const b of taken) {
        try {
          await this.store.writePart(b.dt, b.type, b.records);
        } catch (e) {
          // Put the records back so the next flush retries; surface the error.
          const key = `${b.dt}|${b.type}`;
          const cur = this.buckets.get(key);
          if (cur) {
            cur.records = b.records.concat(cur.records);
            cur.bytes += b.bytes;
          } else {
            this.buckets.set(key, b);
          }
          this.log('error', 'flush_failed', { dt: b.dt, type: b.type, n: b.records.length, err: e.message });
          throw e;
        }
      }
    });
    return this.flushing;
  }

  get pending() {
    let n = 0;
    for (const b of this.buckets.values()) n += b.records.length;
    return n;
  }
}

module.exports = { WriteBuffer };
