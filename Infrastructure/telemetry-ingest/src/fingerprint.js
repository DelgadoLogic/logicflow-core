'use strict';

const crypto = require('node:crypto');

/**
 * Crash fingerprinting.
 *   crash : sha256( "crash\n" + exceptionType + "\n" + top3 normalized frames )
 *   error : sha256( "error\n" + code + "\n" + component + "\n" + normalized message template )
 *
 * Frames are normalised so the same defect groups together across builds:
 *  - source locations (":line 42", "in <path>:line 42", "(File.cs:42)") dropped
 *  - hex addresses / IL offsets (+0x1f, 0x7ff6...) dropped
 *  - compiler generated suffixes (<>c__DisplayClass12_0, b__3_1, <Method>d__5) collapsed
 *  - generic arity / type args collapsed
 * Framework frames (System.*, Microsoft.*, WinRT, ...) are skipped when at
 * least one in-app frame exists, so BCL churn does not split groups.
 */

const IN_APP_PREFIXES = ['LogicFlow', 'DelgadoLogic', 'OmniLicense', 'OmniCore', 'Lazarus', 'HyperStore', 'Sentinel'];
const FRAMEWORK_PREFIXES = ['System.', 'Microsoft.', 'Windows.', 'WinRT.', 'MS.Internal.', 'MS.Win32.', 'Interop.', 'WpfApp'];

function normalizeFrame(frame) {
  let f = String(frame || '').trim();
  f = f.replace(/^\s*at\s+/i, '');
  f = f.replace(/\s+in\s+(?:<path>\\|<[A-Za-z]+>\\)?[^\s]*?(?::line\s*\d+)?\s*$/i, '');
  f = f.replace(/:line\s*\d+/gi, '');
  f = f.replace(/\([^()]*\.(?:cs|vb|fs|cpp|h):\d+(?::\d+)?\)/gi, '');
  f = f.replace(/\+0x[0-9a-f]+/gi, '');
  f = f.replace(/\b0x[0-9a-f]{4,}\b/gi, '');
  f = f.replace(/<>c__DisplayClass\d+_\d+/g, '<>c__DisplayClass');
  f = f.replace(/<>c\b/g, '<>c');
  f = f.replace(/b__\d+_\d+/g, 'b__');
  f = f.replace(/>d__\d+/g, '>d__');
  f = f.replace(/`\d+/g, '');
  f = f.replace(/\[\[[^\]]*\]\]/g, '');
  f = f.replace(/\s+/g, ' ').trim();
  return f;
}

function isInApp(frame) {
  return IN_APP_PREFIXES.some((p) => frame.startsWith(p));
}
function isFramework(frame) {
  return FRAMEWORK_PREFIXES.some((p) => frame.startsWith(p));
}

function topFrames(frames, n = 3) {
  const norm = (Array.isArray(frames) ? frames : []).map(normalizeFrame).filter(Boolean);
  const inApp = norm.filter(isInApp);
  const chosen = inApp.length > 0 ? inApp : norm.filter((f) => !isFramework(f));
  const pool = chosen.length > 0 ? chosen : norm;
  return pool.slice(0, n);
}

function normalizeMessage(msg) {
  return String(msg || '')
    .toLowerCase()
    .replace(/<[a-z]+>(?:\\[^\s]*)?/g, '<x>')
    .replace(/0x[0-9a-f]+/g, 'N')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, 'GUID')
    .replace(/\d+/g, 'N')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** @returns {string|null} 64 hex chars for crash/error events, null otherwise. */
function fingerprintEvent(event) {
  const p = event && event.payload;
  if (!p) return null;
  if (event.type === 'crash') {
    const top = topFrames(p.frames, 3);
    return sha256Hex(['crash', String(p.exceptionType || ''), ...top].join('\n'));
  }
  if (event.type === 'error') {
    const top = topFrames(p.frames, 3);
    return sha256Hex(['error', String(p.code || ''), String(p.component || ''), normalizeMessage(p.message), ...top].join('\n'));
  }
  return null;
}

module.exports = { fingerprintEvent, normalizeFrame, topFrames, normalizeMessage, sha256Hex };
