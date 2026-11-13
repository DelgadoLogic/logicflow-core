'use strict';

/**
 * Process every erasure tombstone that has not yet been physically purged.
 * Safe to run repeatedly (idempotent). Called right after POST /delete (best
 * effort, background) and again by the daily digest job.
 */
async function purgePendingErasures(store, { today } = {}) {
  const tombstones = await store.listTombstones();
  const results = [];
  for (const t of tombstones) {
    if (t.status === 'completed') continue;
    const result = await store.purgeInstall({ installIdHash: t.installIdHash, today });
    await store.markTombstoneDone(t.installIdHash, result);
    results.push({ installIdHash: t.installIdHash.slice(0, 8) + '…', ...result });
  }
  return results;
}

module.exports = { purgePendingErasures };
