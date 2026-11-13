# LogicFlow telemetry ingest

Cloud Run service (Node 22, no database) that receives LogicFlow telemetry and crash reports, stores them as
partitioned gzip NDJSON in GCS, and produces a daily digest an engineer (or AI agent) can read in one minute.
Contract: [`Docs/TELEMETRY_API.md`](../../Docs/TELEMETRY_API.md). Public path: `https://api.delgadologic.tech/v1/telemetry/*`.

```
app --HMAC-signed JSON/NDJSON--> Firebase Hosting rewrite --> Cloud Run (this service)
                                                              |-- validate (Ajv, schema v1), consent gate, PII scrub, fingerprint, dedupe, rate limit
                                                              `-- buffered gzip NDJSON  -->  gs://<bucket>/v1/events/dt=.../type=.../part-*.ndjson.gz
Cloud Scheduler -> Cloud Run Job (src/jobs/digest.js) -> v1/digests/YYYY-MM-DD.{md,json}, latest.*, rollups, crash_groups/state.json
BigQuery external tables/views over the same bucket (bigquery/ddl.sql)
```

## Layout

| Path | What |
| --- | --- |
| `src/` | service (`app.js` routes, `ingest.js` pipeline, `validate.js`, `scrub.js`, `fingerprint.js`, `ratelimit.js`, `auth.js`, `eventStore.js`, `digest.js`, `storage/{fs,gcs}.js`) |
| `schema/v1/event.schema.json` | the versioned JSON Schema (served at `/v1/telemetry/schema`) |
| `test/` | `node:test` unit, HTTP (real server, FS storage) and digest tests with fixtures |
| `scripts/` | `dev.js` emulator, `send-sample.js`, `lint.js`, `fetch-digest.ps1`, `query.ps1` |
| `tools/telemetry-query/lf-telemetry.js` | CLI: print digests, run canned BigQuery queries |
| `bigquery/` | `ddl.sql` + `queries/*.sql` (not executed by this repo) |
| `deploy/` | `deploy.ps1` (dry run by default), `lifecycle.json`, `iam.md` |

## Run locally (emulator)

```powershell
npm install
npm run dev            # FS storage in .data, dev key, http://localhost:8080
node scripts/send-sample.js
npm run digest -- --date (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')   # LF_DATA_DIR must match (default .data)
npm test
npm run lint
```

## Configuration (environment)

| Variable | Default | Notes |
| --- | --- | --- |
| `LF_STORAGE` | `fs` | `gcs` in Cloud Run |
| `LF_BUCKET` / `LF_DATA_DIR` | - / `./.data` | |
| `LF_INGEST_KEYS` | none | comma-separated HMAC keys (Secret Manager). Empty => every signed endpoint returns 503 `not_configured` (fails closed) |
| `LF_ADMIN_TOKEN` | none | enables `POST /internal/digest`; empty => 404 |
| `LF_MAX_BODY_BYTES`, `LF_MAX_DECODED_BYTES`, `LF_MAX_EVENTS_PER_REQUEST`, `LF_MAX_EVENT_BYTES` | 1 MiB, 5 MiB, 200, 64 KiB | |
| `LF_RATE_INSTALL_REQ_MIN`, `LF_RATE_INSTALL_EVENTS_HOUR`, `LF_RATE_IP_REQ_MIN`, `LF_RATE_IP_EVENTS_HOUR` | 30, 600, 120, 3000 | a value <= 0 disables that limit |
| `LF_IP_SALT_ROTATE_MS` | 6 h | rotating in-memory salt for IP hashing; IPs are never stored |
| `LF_TRUST_PROXY_HOPS` | 1 | see "Client IP" |
| `LF_FLUSH_INTERVAL_MS`, `LF_FLUSH_EVENTS`, `LF_FLUSH_BYTES` | 30000, 5000, 1 MiB | `LF_FLUSH_INTERVAL_MS=0` = write-through |
| `LF_RAW_RETENTION_DAYS`, `LF_ROLLUP_RETENTION_DAYS` | 90, 395 | applied by the digest job only in FS mode; GCS uses `deploy/lifecycle.json` |

## Operational notes and trade-offs

* **Durability vs cost.** Events are buffered in memory and flushed every 30 s / 5000 events / 1 MiB and on SIGTERM. A hard
  crash can lose up to ~30 s of events per instance. Deploy uses `--min-instances 1 --no-cpu-throttling` so timers run;
  for zero loss set `LF_FLUSH_INTERVAL_MS=0` (one GCS object per request, more objects/cost).
* **Dedupe is per instance** (in-memory, 24 h). The BigQuery `events` view dedupes by `eventId` across instances; the digest
  counts events as stored (duplicates across instances are rare, only on cross-instance client retries).
* **Client IP.** Prefers `fastly-client-ip`, else the X-Forwarded-For entry `LF_TRUST_PROXY_HOPS` from the right. Behind
  Firebase Hosting + Google front end this is *believed* to be 1 but was **not verified against a live deployment**. If it is
  wrong all users share one IP bucket and get rate limited: after first deploy check `rate_limited_ip` in the digest and
  set `LF_RATE_IP_REQ_MIN=0` if needed. Per-install limits keep working.
* **Hosting project.** Firebase `run` rewrites need the Cloud Run service in the Hosting project (`manuel-portfolio-2026`).
  `logicflow-guardian` returned PERMISSION_DENIED when checked, so the project id is a deploy parameter.
* **Erasure** is logical immediately (tombstone -> 410 for new events, digest and views exclude) and physical shortly after
  (background rewrite, repeated by the digest job). GCS object versioning must stay **off** or old generations survive.

## Deploy

```powershell
.\deploy\deploy.ps1 -ProjectId manuel-portfolio-2026 -Bucket manuel-portfolio-2026-lf-telemetry            # prints plan only
.\deploy\deploy.ps1 -ProjectId manuel-portfolio-2026 -Bucket manuel-portfolio-2026-lf-telemetry -Execute   # applies
```

Then add secret versions (see `deploy/iam.md`), and deploy Firebase Hosting for the `/v1/telemetry/**` rewrite.
Verify: `curl https://api.delgadologic.tech/v1/telemetry/healthz` -> `{"status":"ok",...}`.
