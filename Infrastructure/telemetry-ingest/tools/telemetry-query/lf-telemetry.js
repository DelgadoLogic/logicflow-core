#!/usr/bin/env node
'use strict';
/**
 * lf-telemetry - read the daily digest and run canned BigQuery queries.
 *
 *   node tools/telemetry-query/lf-telemetry.js digest [latest|YYYY-MM-DD] [--format md|json]
 *        [--dir <local data dir>] | [--bucket <gcs bucket>]
 *   node tools/telemetry-query/lf-telemetry.js query <name> [--days 7] [--print]
 *        [--project P] [--dataset D]
 *   node tools/telemetry-query/lf-telemetry.js list
 *
 * Environment fallbacks: LF_BUCKET, LF_DATA_DIR, LF_BQ_PROJECT, LF_BQ_DATASET.
 * Digest from GCS uses Application Default Credentials (roles/storage.objectViewer on the bucket).
 * `query` shells out to the `bq` CLI (roles/bigquery.jobUser + dataViewer); --print only renders SQL.
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const QUERY_DIR = path.resolve(__dirname, '..', '..', 'bigquery', 'queries');

function parseArgs(argv) {
  const pos = [];
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--print') opt.print = true;
    else if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`--${k} needs a value`);
      opt[k] = v;
      i++;
    } else pos.push(a);
  }
  return { pos, opt };
}

function fail(msg, code = 1) {
  process.stderr.write(`lf-telemetry: ${msg}\n`);
  process.exit(code);
}

function listQueries() {
  return fs.readdirSync(QUERY_DIR).filter((f) => f.endsWith('.sql')).map((f) => f.slice(0, -4)).sort();
}

function renderQuery(name, project, dataset) {
  const file = path.join(QUERY_DIR, `${name}.sql`);
  if (!/^[a-z0-9-]+$/.test(name) || !fs.existsSync(file)) throw new Error(`unknown query "${name}". Available: ${listQueries().join(', ')}`);
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project || '')) throw new Error('--project (or LF_BQ_PROJECT) must be a valid GCP project id');
  if (!/^[A-Za-z0-9_]{1,1024}$/.test(dataset || '')) throw new Error('--dataset (or LF_BQ_DATASET) must be a valid dataset name');
  return fs.readFileSync(file, 'utf8').replaceAll('__PROJECT__', project).replaceAll('__DATASET__', dataset);
}

async function readDigest(which, ext, opt) {
  const rel = `v1/digests/${which}.${ext}`;
  const dir = opt.dir || (!opt.bucket && !process.env.LF_BUCKET ? process.env.LF_DATA_DIR : '');
  if (dir) {
    const p = path.join(dir, rel);
    if (!fs.existsSync(p)) throw new Error(`digest not found: ${p}`);
    return fs.readFileSync(p, 'utf8');
  }
  const bucket = opt.bucket || process.env.LF_BUCKET;
  if (!bucket) throw new Error('give --dir (local emulator data) or --bucket (GCS)');
  let Storage;
  try {
    ({ Storage } = require(path.resolve(__dirname, '..', '..', 'node_modules', '@google-cloud/storage')));
  } catch {
    throw new Error('@google-cloud/storage not installed: run npm install in telemetry-ingest, or use scripts/fetch-digest.ps1');
  }
  const [buf] = await new Storage().bucket(bucket).file(rel).download();
  return buf.toString('utf8');
}

async function main() {
  const { pos, opt } = parseArgs(process.argv.slice(2));
  const cmd = pos[0];
  if (cmd === 'list') {
    process.stdout.write(listQueries().join('\n') + '\n');
    return;
  }
  if (cmd === 'digest') {
    const which = pos[1] || 'latest';
    if (which !== 'latest' && !/^\d{4}-\d{2}-\d{2}$/.test(which)) throw new Error('digest date must be "latest" or YYYY-MM-DD');
    const fmt = opt.format || 'md';
    if (fmt !== 'md' && fmt !== 'json') throw new Error('--format must be md or json');
    process.stdout.write(await readDigest(which, fmt, opt));
    return;
  }
  if (cmd === 'query') {
    if (!pos[1]) throw new Error(`query name required. Available: ${listQueries().join(', ')}`);
    const days = Number.parseInt(opt.days || '7', 10);
    if (!Number.isInteger(days) || days < 1 || days > 90) throw new Error('--days must be 1..90');
    const sql = renderQuery(pos[1], opt.project || process.env.LF_BQ_PROJECT, opt.dataset || process.env.LF_BQ_DATASET || 'logicflow_telemetry');
    if (opt.print) {
      process.stdout.write(sql.replaceAll('@days', String(days)));
      return;
    }
    const r = spawnSync('bq', ['query', '--use_legacy_sql=false', '--format=prettyjson', `--parameter=days:INT64:${days}`, `--project_id=${opt.project || process.env.LF_BQ_PROJECT}`, sql], { stdio: ['ignore', 'inherit', 'inherit'], shell: process.platform === 'win32' });
    if (r.error) throw new Error(`could not run bq: ${r.error.message}`);
    process.exit(r.status ?? 1);
  }
  fail('usage: lf-telemetry.js <digest [latest|YYYY-MM-DD] | query <name> | list> [options]  (see header of this file)', 2);
}

main().catch((e) => fail(e.message));
