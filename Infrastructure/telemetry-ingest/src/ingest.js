'use strict';

const { scrubValue } = require('./scrub');
const { fingerprintEvent } = require('./fingerprint');
const { utcDate } = require('./eventStore');

/** Which event types each consent level may carry. */
const CONSENT_TYPES = {
  standard: new Set(['crash', 'error', 'usage', 'scan']),
  extended: new Set(['crash', 'error', 'usage', 'scan', 'baseline']),
};

/** Which event types each endpoint accepts. */
const ENDPOINT_TYPES = {
  events: new Set(['crash', 'error', 'scan', 'baseline', 'usage']),
  crash: new Set(['crash', 'error']),
  baseline: new Set(['baseline']),
};

function normalizeConsent(v) {
  const s = String(v || '').trim().toLowerCase();
  return s === 'standard' || s === 'extended' ? s : null;
}

/**
 * Validate, gate, scrub, fingerprint and buffer a batch of already-parsed events.
 * Server-controlled fields are written LAST so a client can never override them.
 *
 * @returns {{accepted:number, rejected:number, reasons:Object<string,number>}}
 */
function ingestBatch(app, { events, consent, headerInstallId, endpoint, now = new Date() }) {
  const { cfg, validator, dedupe, buffer, stats } = app;
  const reasons = {};
  let accepted = 0;
  let rejected = 0;
  const allowedByConsent = CONSENT_TYPES[consent];
  const allowedByEndpoint = ENDPOINT_TYPES[endpoint] || ENDPOINT_TYPES.events;
  const receivedAt = now.toISOString();
  const dt = utcDate(now);

  const reject = (reason) => {
    rejected += 1;
    reasons[reason] = (reasons[reason] || 0) + 1;
    stats.rejected(reason);
  };

  for (const raw of events) {
    // Size guard on the serialised event (cheap; events are already parsed).
    let size = 0;
    try {
      size = Buffer.byteLength(JSON.stringify(raw));
    } catch {
      reject('schema_invalid');
      continue;
    }
    if (size > cfg.maxEventBytes) {
      reject('event_too_large');
      continue;
    }

    const v = validator.validateEvent(raw);
    if (!v.ok) {
      reject(v.reason);
      continue;
    }
    const ev = v.event;

    if (ev.tier === 'free') {
      reject('tier_free_not_allowed');
      continue;
    }
    if (headerInstallId && ev.installId !== headerInstallId) {
      reject('install_mismatch');
      continue;
    }
    if (!allowedByConsent || !allowedByConsent.has(ev.type)) {
      reject('consent_level_insufficient');
      continue;
    }
    if (!allowedByEndpoint.has(ev.type)) {
      reject('wrong_endpoint_for_type');
      continue;
    }
    const tsMs = Date.parse(ev.ts);
    if (!Number.isFinite(tsMs) || tsMs > now.getTime() + cfg.maxClockSkewFutureMs || tsMs < now.getTime() - cfg.maxEventAgeMs) {
      reject('timestamp_out_of_range');
      continue;
    }
    if (dedupe.seen(ev.eventId.toLowerCase())) {
      reject('duplicate');
      continue;
    }

    const payload = scrubValue(ev.payload);
    const scrubbed = { ...ev, payload };
    const fingerprint = fingerprintEvent(scrubbed);

    // Server-owned fields: assigned last, from scratch.
    const record = {
      schema: 1,
      eventId: ev.eventId.toLowerCase(),
      type: ev.type,
      ts: ev.ts,
      installId: ev.installId,
      appVersion: ev.appVersion,
      osBuild: ev.osBuild,
      arch: ev.arch,
      tier: ev.tier,
      region: ev.region,
      payload,
      receivedAt,
      dt,
      consent,
      fingerprint,
      ingestId: cfg.instanceId,
    };
    buffer.add(record);
    stats.accepted(ev.type);
    accepted += 1;
  }

  return { accepted, rejected, reasons };
}

module.exports = { ingestBatch, normalizeConsent, CONSENT_TYPES, ENDPOINT_TYPES };
