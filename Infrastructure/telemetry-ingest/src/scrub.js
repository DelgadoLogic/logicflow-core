'use strict';

/**
 * Server-side PII scrubber. Defence in depth: the client is expected to scrub
 * too, but the server never trusts it. Applied to every string in `payload`.
 *
 * Removes / replaces:
 *  - user profile paths (C:\Users\<name>, /home/<name>, /Users/<name>)
 *  - UNC hosts (\\HOST\share)
 *  - remaining absolute Windows paths (directory dropped, file name kept)
 *  - e-mail addresses
 *  - IPv4 / IPv6 addresses
 *  - Windows SIDs
 *  - default Windows machine names (DESKTOP-XXXXXXX, LAPTOP-..., WIN-...)
 *  - LogicFlow licence keys
 *  - long hex/base64 looking secrets (>= 32 chars of key material)
 *
 * It cannot detect arbitrary free-text names ("Hello John") - the schema
 * therefore keeps free-text fields short and typed, and docs forbid sending them.
 */

const SYSTEM_ROOTS = [
  [/^[A-Za-z]:[\\/]Program Files \(x86\)[\\/]/i, '<ProgramFilesX86>\\'],
  [/^[A-Za-z]:[\\/]Program Files[\\/]/i, '<ProgramFiles>\\'],
  [/^[A-Za-z]:[\\/]Windows[\\/]/i, '<Windows>\\'],
  [/^[A-Za-z]:[\\/]ProgramData[\\/]/i, '<ProgramData>\\'],
];

const RE_USER_PROFILE = /[A-Za-z]:[\\/]+Users[\\/]+[^\\/\r\n"'<>|]+/gi;
const RE_UNIX_HOME = /(?:\/home|\/Users)\/[^/\s"'<>|]+/g;
const RE_UNC = /\\\\[^\\\s"'<>|]+(?:\\[^\s"'<>|]*)?/g;
const RE_EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const RE_IPV6 = /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:(?:[A-Fa-f0-9]{1,4})?\b/g;
const RE_SID = /\bS-1-\d+(?:-\d+){1,15}\b/g;
const RE_HOST = /\b(?:DESKTOP|LAPTOP|WIN|PC|NB)-[A-Z0-9]{5,10}\b/g;
const RE_LICENSE = /\bDL-[A-Z]{2,16}-[0-9A-F]{12}\b/g;
const RE_SECRETISH = /\b(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/_-]{48,}={0,2})\b/g;
// Remaining absolute drive-letter paths (after user/system-root handling).
const RE_ABS_PATH = /[A-Za-z]:[\\/](?:[^\\/\r\n"'<>|:*?]+[\\/])*[^\\/\r\n"'<>|:*?\s]*/g;

function scrubString(input) {
  if (typeof input !== 'string' || input.length === 0) return input;
  let s = input;

  s = s.replace(RE_USER_PROFILE, '<UserProfile>');
  s = s.replace(RE_UNIX_HOME, '<UserProfile>');
  s = s.replace(RE_UNC, '\\\\<host>\\<share>');
  s = s.replace(RE_EMAIL, '<email>');
  s = s.replace(RE_SID, '<sid>');
  s = s.replace(RE_IPV4, '<ip>');
  s = s.replace(RE_IPV6, '<ip>');
  s = s.replace(RE_HOST, '<host>');
  s = s.replace(RE_LICENSE, '<license>');

  // Known system roots keep their (non-identifying) prefix.
  s = s.replace(/[A-Za-z]:[\\/](?:Program Files \(x86\)|Program Files|Windows|ProgramData)[\\/][^\r\n"'<>|:*?]*/gi, (m) => {
    for (const [re, label] of SYSTEM_ROOTS) {
      if (re.test(m)) return label + m.replace(re, '').replace(/\//g, '\\');
    }
    return m;
  });

  // Everything else that still looks like an absolute path: keep only basename.
  s = s.replace(RE_ABS_PATH, (m) => {
    const parts = m.split(/[\\/]/).filter(Boolean);
    const base = parts.length > 1 ? parts[parts.length - 1] : '';
    return base ? `<path>\\${base}` : '<path>';
  });

  s = s.replace(RE_SECRETISH, '<redacted>');
  return s;
}

/** Deep-scrub every string in a JSON-like value. Returns a new value. */
function scrubValue(v) {
  if (typeof v === 'string') return scrubString(v);
  if (Array.isArray(v)) return v.map(scrubValue);
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = scrubValue(val);
    return out;
  }
  return v;
}

module.exports = { scrubString, scrubValue };
