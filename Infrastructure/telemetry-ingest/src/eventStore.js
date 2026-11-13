'use strict';

const zlib = require('node:zlib');
const crypto = require('node:crypto');

/**
 * Storage layout (all keys relative to the bucket / data dir):
 *
 *   v1/events/dt=YYYY-MM-DD/type=<type>/part-<HHMMSS>-<instance>-<seq>.ndjson.gz   raw events (90 d lifecycle)
 *   v1/stats/dt=YYYY-MM-DD/stats-<instance>-<ts>.json                              ingest counters (90 d)
 *   v1/erasures/<sha256(installId)>.json                                           erasure tombstones (no raw id)
 *   v1/rollups/daily/dt=YYYY-MM-DD.json                                            aggregated, no installIds (13 mo)
 *   v1/crash_groups/state.json                                                     crash groups, no installIds (forever)
 *   v1/digests/YYYY-MM-DD.{md,json} + latest.{md,json}                             daily digest for humans/agents
 *   v1/triage/crash_groups.json                                                    optional manual triage overrides
 */
const PREFIX = {
  events: 'v1/events',
  stats: 'v1/stats',
  erasures: 'v1/erasures',
  rollups: 'v1/rollups/daily',
  crashGroups: 'v1/crash_groups',
  digests: 'v1/digests',
  triage: 'v1/triage',
};

function utcDate(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function addDays(dateStr, delta) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + delta);
  return utcDate(d);
}

function hashInstall(installId) {
  return crypto.createHash('sha256').update(String(installId), 'utf8').digest('hex');
}

function gzipLines(lines) {
  return zlib.gzipSync(Buffer.from(lines.join('\n') + '\n', 'utf8'), { level: 6 });
}

function parseNdjsonGz(buf) {
  const text = zlib.gunzipSync(buf).toString('utf8');
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      /* skip corrupt line; never fail a digest because of one bad row */
    }
  }
  return out;
}

class EventStore {
  constructor(storage, cfg) {
    this.storage = storage;
    this.cfg = cfg;
    this.seq = 0;
  }

  eventsKey(dt, type) {
    this.seq += 1;
    const t = new Date().toISOString().slice(11, 19).replace(/:/g, '');
    return `${PREFIX.events}/dt=${dt}/type=${type}/part-${t}-${this.cfg.instanceId}-${String(this.seq).padStart(5, '0')}.ndjson.gz`;
  }

  /** Write one part file; returns its key. */
  async writePart(dt, type, records) {
    const key = this.eventsKey(dt, type);
    await this.storage.put(key, gzipLines(records.map((r) => JSON.stringify(r))));
    return key;
  }

  async listPartKeys(dt, type) {
    const prefix = type ? `${PREFIX.events}/dt=${dt}/type=${type}/` : `${PREFIX.events}/dt=${dt}/`;
    return (await this.storage.list(prefix)).filter((k) => k.endsWith('.ndjson.gz'));
  }

  /** Async-iterate all events of a day (optionally one type), minus erased installs. */
  async *readEvents(dt, type, { skipErased = true } = {}) {
    const erased = skipErased ? await this.erasedSet() : new Set();
    for (const key of await this.listPartKeys(dt, type)) {
      const buf = await this.storage.get(key);
      if (!buf) continue;
      for (const ev of parseNdjsonGz(buf)) {
        if (erased.size && erased.has(hashInstall(ev.installId))) continue;
        yield ev;
      }
    }
  }

  // ---- stats ------------------------------------------------------------
  async writeStats(dt, counters) {
    const key = `${PREFIX.stats}/dt=${dt}/stats-${this.cfg.instanceId}-${Date.now()}.json`;
    await this.storage.put(key, JSON.stringify({ schema: 1, dt, instance: this.cfg.instanceId, counters }));
    return key;
  }

  async readStats(dt) {
    const keys = (await this.storage.list(`${PREFIX.stats}/dt=${dt}/`)).filter((k) => k.endsWith('.json'));
    const docs = [];
    for (const k of keys) {
      const buf = await this.storage.get(k);
      if (!buf) continue;
      try {
        docs.push(JSON.parse(buf.toString('utf8')));
      } catch {
        /* ignore */
      }
    }
    return docs;
  }

  // ---- erasure ----------------------------------------------------------
  tombstoneKey(installId) {
    return `${PREFIX.erasures}/${hashInstall(installId)}.json`;
  }

  async writeTombstone(installId, status = 'pending') {
    const doc = { schema: 1, installIdHash: hashInstall(installId), requestedAt: new Date().toISOString(), status };
    await this.storage.put(this.tombstoneKey(installId), JSON.stringify(doc));
    return doc;
  }

  async hasTombstone(installId) {
    return this.storage.exists(this.tombstoneKey(installId));
  }

  async listTombstones() {
    const keys = (await this.storage.list(`${PREFIX.erasures}/`)).filter((k) => k.endsWith('.json'));
    const out = [];
    for (const k of keys) {
      const buf = await this.storage.get(k);
      if (!buf) continue;
      try {
        out.push(JSON.parse(buf.toString('utf8')));
      } catch {
        /* ignore */
      }
    }
    return out;
  }

  async erasedSet() {
    return new Set((await this.listTombstones()).map((t) => t.installIdHash));
  }

  /**
   * Right-to-erasure: rewrite every raw part file in the retention window,
   * dropping rows whose installId matches. `hash` mode lets the digest job
   * re-run pending tombstones when only the hash is known.
   * @returns {{filesScanned:number, filesRewritten:number, filesDeleted:number, rowsRemoved:number}}
   */
  async purgeInstall({ installId, installIdHash, today = utcDate() }) {
    const wantHash = installIdHash || hashInstall(installId);
    const res = { filesScanned: 0, filesRewritten: 0, filesDeleted: 0, rowsRemoved: 0 };
    const days = this.cfg.rawRetentionDays + 2;
    for (let i = 0; i <= days; i++) {
      const dt = addDays(today, -i);
      for (const key of await this.listPartKeys(dt)) {
        res.filesScanned += 1;
        const buf = await this.storage.get(key);
        if (!buf) continue;
        const rows = parseNdjsonGz(buf);
        const kept = rows.filter((r) => hashInstall(r.installId) !== wantHash);
        const removed = rows.length - kept.length;
        if (removed === 0) continue;
        res.rowsRemoved += removed;
        if (kept.length === 0) {
          await this.storage.delete(key);
          res.filesDeleted += 1;
        } else {
          await this.storage.put(key, gzipLines(kept.map((r) => JSON.stringify(r))));
          res.filesRewritten += 1;
        }
      }
    }
    return res;
  }

  async markTombstoneDone(installIdHash, result) {
    const key = `${PREFIX.erasures}/${installIdHash}.json`;
    const doc = { schema: 1, installIdHash, completedAt: new Date().toISOString(), status: 'completed', result };
    const prev = await this.storage.get(key);
    let requestedAt = doc.completedAt;
    try {
      requestedAt = JSON.parse(prev.toString('utf8')).requestedAt || requestedAt;
    } catch {
      /* ignore */
    }
    await this.storage.put(key, JSON.stringify({ ...doc, requestedAt }));
  }

  // ---- generic JSON helpers --------------------------------------------
  async getJson(key) {
    const buf = await this.storage.get(key);
    if (!buf) return null;
    try {
      return JSON.parse(buf.toString('utf8'));
    } catch {
      return null;
    }
  }

  async putJson(key, obj) {
    await this.storage.put(key, JSON.stringify(obj, null, 2));
  }

  async putText(key, text) {
    await this.storage.put(key, Buffer.from(text, 'utf8'));
  }
}

module.exports = { EventStore, PREFIX, utcDate, addDays, hashInstall, gzipLines, parseNdjsonGz };
