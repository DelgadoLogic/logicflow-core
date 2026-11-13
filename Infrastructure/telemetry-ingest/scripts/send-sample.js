'use strict';

/**
 * Sends fixture events to a running service (signed with HMAC-SHA256).
 *   node scripts/send-sample.js [baseUrl] [ingestKey]
 */
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { signBody } = require('../src/auth');

const rawArgs = process.argv.slice(2);
const withDelete = rawArgs.includes('--with-delete');
const positional = rawArgs.filter((a) => !a.startsWith('--'));
const base = positional[0] || 'http://localhost:8080';
const key = positional[1] || process.env.LF_INGEST_KEY || 'dev-local-ingest-key-DO-NOT-USE-IN-PROD';
const fx = path.join(__dirname, '..', 'test', 'fixtures');

async function post(endpoint, events, { gzip = true, consent = 'standard' } = {}) {
  const json = Buffer.from(JSON.stringify(events));
  const body = gzip ? zlib.gzipSync(json) : json;
  const res = await fetch(`${base}/v1/telemetry/${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(gzip ? { 'Content-Encoding': 'gzip' } : {}),
      'X-LF-Schema': '1',
      'X-LF-Install-Id': events[0].installId,
      'X-LF-Version': events[0].appVersion,
      'X-LF-Consent': consent,
      'X-LF-Sig': signBody(key, body),
    },
    body,
  });
  console.log(endpoint, res.status, await res.text());
  if (!res.ok) process.exitCode = 1;
}

(async () => {
  const now = new Date().toISOString();
  const load = (f) => JSON.parse(fs.readFileSync(path.join(fx, f), 'utf8')).map((e, i) => ({ ...e, ts: now, eventId: e.eventId.replace(/.{4}$/, String(1000 + i)) }));
  await post('events', load('events.sample.json'), { consent: 'standard' });
  await post('crash', load('crash.sample.json'), { consent: 'standard' });
  await post('baseline', load('baseline.sample.json'), { consent: 'extended' });
  if (withDelete) {
    const body = Buffer.from(JSON.stringify({ installId: 'inst_ephemeral_delete_01' }));
    const res = await fetch(`${base}/v1/telemetry/delete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-LF-Schema': '1',
        'X-LF-Install-Id': 'inst_ephemeral_delete_01',
        'X-LF-Sig': signBody(key, body),
      },
      body,
    });
    console.log('delete', res.status, await res.text());
    if (!res.ok) process.exitCode = 1;
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
