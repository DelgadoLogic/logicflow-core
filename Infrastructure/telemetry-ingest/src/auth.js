'use strict';

const crypto = require('node:crypto');

/**
 * X-LF-Sig = HMAC-SHA256(key, wireBody) as lowercase hex (optionally "sha256=" prefixed).
 * `wireBody` is the request body exactly as received on the wire (i.e. after
 * gzip compression if the client gzips) so the signature can be verified
 * BEFORE decompression (gzip-bomb safe).
 * `keys` is the current key plus any rotation keys; any match passes.
 */
function signBody(key, bodyBuf) {
  return crypto.createHmac('sha256', key).update(bodyBuf).digest('hex');
}

function verifySignature(keys, bodyBuf, header) {
  if (!Array.isArray(keys) || keys.length === 0) return { ok: false, reason: 'not_configured' };
  if (typeof header !== 'string' || header.length === 0) return { ok: false, reason: 'missing_signature' };
  const hex = header.trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return { ok: false, reason: 'bad_signature' };
  const given = Buffer.from(hex, 'hex');
  let match = false;
  for (const key of keys) {
    const expected = crypto.createHmac('sha256', key).update(bodyBuf).digest();
    // Evaluate every key (no early exit) to keep timing independent of position.
    if (crypto.timingSafeEqual(expected, given)) match = true;
  }
  return match ? { ok: true } : { ok: false, reason: 'bad_signature' };
}

function safeEqualStr(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = { signBody, verifySignature, safeEqualStr };
