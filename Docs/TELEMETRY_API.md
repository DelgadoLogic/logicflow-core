# LogicFlow Telemetry API (schema v1)

Contract between the LogicFlow desktop app and the telemetry ingest service
(`Products/LogicFlow/Infrastructure/telemetry-ingest`). Public base URL:

```
https://api.delgadologic.tech/v1/telemetry/
```

Everything the service returns is **JSON, never HTML**. The live JSON Schema is served at
`GET /v1/telemetry/schema` (and is shown on <https://delgadologic.tech/telemetry>).

## 1. Principles

| Rule | Detail |
| --- | --- |
| Opt-in per tier | `free` tier **never** sends telemetry (server rejects `tier=free`). `community` requires it (consent is a licence condition). `pro` is optional and **off by default**. |
| Consent is explicit | Every request carries `X-LF-Consent`. Missing or invalid -> `403`, nothing is stored. |
| No PII by design | Client must not send user names, paths, emails, IPs, hostnames, licence keys. The server scrubs again; the client is not trusted. |
| Server owns server fields | `receivedAt`, `dt`, `consent`, `fingerprint`, `ingestId` are always overwritten. |
| IPs are never stored | Used only for rate limiting, hashed with an in-memory salt that rotates (default 6 h). |
| Right to erasure | `POST /delete` removes an install's data (see 8). |

## 2. Endpoints

| Method + path | Purpose | Allowed event types |
| --- | --- | --- |
| `POST /events` | Batch of events (JSON array or NDJSON) | crash, error, scan, baseline, usage |
| `POST /crash` | Crash / error reports | crash, error |
| `POST /baseline` | One-time device baseline | baseline |
| `POST /delete` | Erase everything for an install id | n/a (body `{"installId": "..."}`) |
| `GET /healthz` | Liveness (also `GET /healthz` at service root) | n/a |
| `GET /schema` | The JSON Schema (cacheable 1 h) | n/a |
| `POST /internal/digest` | Ops only: build a digest. `Authorization: Bearer <LF_ADMIN_TOKEN>`. 404 if not configured. Not reachable by the app. | n/a |

All paths above are relative to `https://api.delgadologic.tech/v1/telemetry`.

### 2.1 Request headers (all POST endpoints except `/internal/digest`)

| Header | Required | Value |
| --- | --- | --- |
| `X-LF-Schema` | yes | `1` |
| `X-LF-Install-Id` | events/crash/baseline: yes; delete: optional (must equal body id if sent) | `^[A-Za-z0-9_-]{16,64}$` |
| `X-LF-Version` | events/crash/baseline | app version, e.g. `1.0.0` or `1.0.0.154` |
| `X-LF-Consent` | events/crash/baseline | `standard` or `extended` |
| `X-LF-Sig` | yes | hex HMAC-SHA256 of the body (see 3) |
| `Content-Type` | yes | `application/json` or `application/x-ndjson` |
| `Content-Encoding` | optional | `gzip` (only gzip is supported) |

Body: JSON array of envelopes, or NDJSON (one envelope per line). A single object is also accepted.

### 2.2 Success response

```json
{ "accepted": 3, "rejected": 1, "schema": 1, "reasons": { "duplicate": 1 } }
```

`reasons` is present only if `rejected > 0`. A `200` with `rejected > 0` means some events were
bad; the client must **not** retry rejected events (they will be rejected again). Retry only on
`429`, `5xx`, or network errors, with exponential backoff and jitter, and re-use the same `eventId`s
(dedupe makes retries safe). `/delete` returns `202` with `"status": "erasure_queued"`.

### 2.3 Status codes

| Code | `error` | Meaning |
| --- | --- | --- |
| 200 | - | Processed (check `accepted` / `rejected`) |
| 202 | - | `/delete` queued |
| 400 | `unsupported_schema`, `bad_install_id`, `bad_version`, `malformed_json`, `bad_encoding`, `install_mismatch`, `bad_date` | Fix the request, do not retry as-is |
| 401 | `invalid_signature` | Missing / wrong HMAC. Possible retired key: ship a new build |
| 403 | `consent_required` | No/invalid consent header. Nothing stored |
| 404 | `not_found` | Unknown path |
| 405 | `method_not_allowed` | Wrong method (`Allow` header set) |
| 410 | `install_erased` | This install id was erased; stop sending, generate a new install id only after a fresh consent |
| 413 | `payload_too_large`, `too_many_events` | Split the batch |
| 415 | `unsupported_media_type`, `unsupported_content_encoding` | |
| 429 | `rate_limited_install`, `rate_limited_ip` | Obey `Retry-After` |
| 503 | `not_configured` | Server has no signing keys (fails closed). Retry later |

## 3. Request signing

`X-LF-Sig = hex( HMAC-SHA256( buildKey, bodyBytes ) )`, lowercase hex, optional `sha256=` prefix.

* `bodyBytes` are the bytes **exactly as sent on the wire**. If you gzip, sign the **compressed** bytes
  (the server verifies before decompressing, so a gzip bomb can never be decompressed unauthenticated).
* `buildKey` is a per-build secret embedded in the release (it is a spam gate, not a user secret: anyone who
  reverse-engineers a build can obtain it). The server accepts a **list** of keys (`LF_INGEST_KEYS`, comma
  separated) so keys can be rotated: add the new key, ship builds with it, remove the old key after the old
  builds age out. Signature comparison is constant time over all keys.
* Because the key is extractable, abuse is bounded by consent gating, schema validation, size limits and
  rate limits; nothing in the pipeline treats a valid signature as proof of identity.

C# reference:

```csharp
static string Sign(byte[] key, byte[] wireBody)
{
    using var h = new System.Security.Cryptography.HMACSHA256(key);
    return Convert.ToHexString(h.ComputeHash(wireBody)).ToLowerInvariant();
}
// key bytes = UTF-8 bytes of the key string exactly as stored in Secret Manager.
```

## 4. Event envelope

```json
{
  "schema": 1,
  "eventId": "3f0c4a8e-5b1d-4a77-9c52-0d6b8e1a2f33",
  "type": "crash",
  "ts": "2026-10-10T16:58:06Z",
  "installId": "inst_9fK2xQ7mL0aP4vZ8",
  "appVersion": "1.0.0",
  "osBuild": "10.0.26100.1742",
  "arch": "x64",
  "tier": "community",
  "region": "US",
  "payload": { }
}
```

| Field | Type | Rules |
| --- | --- | --- |
| `schema` | const `1` | |
| `eventId` | UUID | dedupe key; generate once per event, reuse on retry |
| `type` | `crash` `error` `usage` `scan` `baseline` | |
| `ts` | RFC 3339 UTC | informational; must be within 30 days past / 24 h future of server time |
| `installId` | string 16-64 `[A-Za-z0-9_-]` | random, pseudonymous; rotate on consent change and every 90 days; must equal `X-LF-Install-Id` |
| `appVersion` | `major.minor.patch[.build][-pre]` | |
| `osBuild` | string <= 64 | e.g. `10.0.26100.1742` |
| `arch` | `x64` `arm64` `x86` | |
| `tier` | `free` `community` `pro` | `free` is rejected |
| `region` | `US`-style ISO 3166-1 alpha-2, or `unknown` | from OS regional settings, never from IP |
| `payload` | object | per-type, see below. Unknown properties are **stripped**, not rejected |

### 4.1 Consent levels

| `X-LF-Consent` | Allowed types |
| --- | --- |
| `standard` | crash, error, usage, scan |
| `extended` | all of the above + `baseline` |

A type not allowed by the declared consent level is rejected per event (`consent_level_insufficient`).

### 4.2 Payloads

**crash** (required `exceptionType`, `frames`)

| Field | Type | Notes |
| --- | --- | --- |
| `exceptionType` | string <= 200 | e.g. `System.NullReferenceException` |
| `message` | string <= 1000 | scrubbed server-side |
| `hresult` | `0x[0-9A-F]{1,8}` | |
| `frames` | string[] <= 64, each <= 300 | stack frames, top first |
| `inner` | `{exceptionType, message?}[]` <= 5 | |
| `component` | string <= 64 | module name |
| `isFatal` | bool | |
| `uptimeSec` | uint | |

**error** (required `code`, `component`): `code` (<= 64), `component`, `severity` (`info|warning|error`), `message`, `hresult`, `frames`.

**usage** (required `feature`, `action`): `feature`, `action` (<= 64), `durationMs`, `count`, `props` = array of `{k,v}` (<= 16, key <= 32, value <= 64 chars). Never put user content in `props`.

**scan** (required `scanType`): `scanType`, `durationMs`, `itemsFound`, `bytesReclaimable`, `healthScore` (0-100), `modulesRun` (string[] <= 64), `issues` (`{id, count?}[]` <= 50).

**baseline** (extended only; all optional): `windows {edition, displayVersion, ubr}`; `hardware {cpuName, cpuCores, ramGb, gpus[<=4]{vendor,name,driverVersion,driverDate}, biosVendor, biosVersion, boardVendor, boardModel, diskTypes[nvme|ssd|hdd|usb|other]}`; `drivers[<=200]{class,vendor,name,version,date,hwidClass}`; `kbs[<=500]` (`KB1234567`); `securityProducts[<=16]`; `servicesRunning`. No serial numbers, MAC addresses, machine names, or user accounts.

The authoritative definition is `schema/v1/event.schema.json`.

## 5. Server-side processing

1. Rate limit per IP (hashed) -> verify `X-LF-Schema` / headers -> **verify HMAC on wire bytes** -> per-install rate limit.
2. Consent header -> erased-install check (410) -> decompress (size capped) -> parse.
3. Per event: size cap -> JSON Schema validation (versioned, Ajv 2020) -> tier / install / consent / endpoint
   gating -> timestamp window -> dedupe by `eventId`.
4. **PII scrub** of every string in the payload: Windows user-profile paths -> `<user>`, other absolute paths ->
   `<path>\file`, UNC shares, e-mail addresses, IPv4/IPv6, SIDs, `DESKTOP-xxxx`-style host names, licence-key
   shaped tokens, long opaque secrets.
5. Crash fingerprint = `sha256("crash\n" + exceptionType + "\n" + top 3 normalised in-app frames)`. Normalisation strips line
   numbers, source paths, hex offsets, generic arity/type args, and lambda/async suffixes, so one defect = one group across builds.
6. Server fields written last; the event is appended to a write buffer and flushed as one gzip NDJSON part.

Limits (defaults, env-tunable): body 1 MiB on the wire, 5 MiB decoded, 200 events / request, 64 KiB / event,
30 requests / min and 600 events / h per install, 120 requests / min and 3000 events / h per IP.

## 6. Storage layout (GCS bucket, or local dir in emulator mode)

```
v1/events/dt=YYYY-MM-DD/type=<type>/part-<HHMMSS>-<instance>-<seq>.ndjson.gz   raw, 90 days
v1/stats/dt=YYYY-MM-DD/stats-*.json                                            ingest counters, 90 days
v1/erasures/<sha256(installId)>.json                                           erasure tombstones (no raw id)
v1/rollups/daily/dt=YYYY-MM-DD.json                                            aggregates, 13 months, no install ids
v1/crash_groups/state.json                                                     crash groups, indefinite, no install ids
v1/digests/YYYY-MM-DD.{md,json}  +  latest.{md,json}                           daily digest
v1/triage/crash_groups.json                                                    optional manual triage (status/fixedIn/note)
v1/README.md                                                                   data dictionary for agents
```

BigQuery: dataset `logicflow_telemetry` (see `bigquery/ddl.sql`) with external table `events_raw`, and views
`events` (deduped, erasure-filtered), `crash_groups`, `baseline_devices`, `driver_index`.

## 7. Daily digest

Cloud Run Job `lf-telemetry-digest` (Cloud Scheduler, 06:15 UTC) writes the previous UTC day. Same-day re-runs are
idempotent; an older date never overwrites `latest.*`. Read it with:

```powershell
scripts\fetch-digest.ps1 -Bucket <bucket>                       # latest.md
scripts\fetch-digest.ps1 -Bucket <bucket> -Date 2026-10-01 -Format json
node tools/telemetry-query/lf-telemetry.js digest latest --bucket <bucket>
```

JSON keys: `digestSchema`, `date`, `generatedAt`, `summary` (events, activeInstalls, crashEvents, distinctCrashGroups,
newCrashGroups, regressions, anomalies, accepted, rejected), `breakdown`, `newCrashGroups[]`, `topCrashGroups[]`,
`topErrorGroups[]`, `regressions[]` (`fixed_but_seen`, `reappeared`, `new_in_version`), `versionHealth[]`,
`affectedOsBuilds[]`, `scan`, `usage`, `baseline`, `anomalies[]`
(`volume_spike`, `volume_drop`, `dominant_group`, `version_crash_rate`, `reject_rate_high`,
`invalid_signatures`, `rate_limited`, ...), `ingestHealth` (accepted/rejected/reasons/http status),
`suggestedPrompts[]` (copy-paste investigation prompts for an AI agent). The Markdown is the same content for
people. `v1/README.md` explains every field.

To mark a crash group fixed (enables `fixed_but_seen` regression detection), write
`v1/triage/crash_groups.json`: `{ "<fingerprint>": { "status": "fixed", "fixedIn": "1.0.1", "note": "..." } }`.

Canned BigQuery queries: `top-crashes`, `regressions`, `version-health`, `os-builds`, `scan-stats`,
`usage-features`, `driver-fleet`, `erasure-check` (`scripts\query.ps1 -List`).

## 8. Retention and erasure

| Data | Retention |
| --- | --- |
| Raw events + stats | 90 days (GCS lifecycle) |
| Daily rollups | 13 months (395 days) |
| Crash groups | indefinite, **never contain install ids** |
| Digests | dated files 90 days; `latest.*` replaced daily |

`POST /delete` with `{"installId":"..."}` (signed like any request; `X-LF-Install-Id` optional):

1. Writes a tombstone keyed by `sha256(installId)` (the raw id is never stored). From this moment new events for that
   install return `410`, and the digest and BigQuery views exclude any remaining rows (logical erasure is immediate).
2. Drops events still in the memory buffer.
3. Rewrites the raw partitions without that install in the background (and again from the digest job).
4. Returns `202 {"accepted":1,"rejected":0,"schema":1,"status":"erasure_queued"}`; idempotent.

The app should call it when the user withdraws consent or uses "delete my telemetry", then rotate to a new
`installId` only after a new opt-in. Website data-request form: <https://delgadologic.tech/data-requests>.

## 9. Hosting and domain

Firebase Hosting (`api-service` target, site `delgadologic-api`) rewrites `/v1/telemetry/**` to Cloud Run service
`lf-telemetry-ingest` (region `us-central1`) **before** the existing `/v1/**` -> `sovereignProxy` rewrite. Hosting `run`
rewrites require the Cloud Run service to be in the same project as the Hosting site (`manuel-portfolio-2026`).
If you must host elsewhere, map `api.delgadologic.tech` with a Cloud Run domain mapping or an HTTPS load balancer.

Client IP: the service uses `fastly-client-ip` when present, otherwise the X-Forwarded-For entry
`LF_TRUST_PROXY_HOPS` hops from the right (default 1). Wrong hop count collapses all clients to one IP bucket.
Verify after first deploy (look at `rate_limited_ip` counts in the digest); set `LF_RATE_IP_REQ_MIN=0` to disable
the per-IP limit if it misbehaves (per-install limits still apply).

## 10. Local emulator

```powershell
cd Products\LogicFlow\Infrastructure\telemetry-ingest
npm install
npm run dev                     # http://localhost:8080/v1/telemetry/healthz, FS storage in .data, dev-only key
node scripts/send-sample.js     # signs and sends test/fixtures/*.sample.json (key: dev-local-ingest-key-DO-NOT-USE-IN-PROD)
npm run digest                  # writes .data/v1/digests/latest.md for yesterday
npm test ; npm run lint
```

## 11. Checklist for the app (client) implementer

- [ ] Send nothing when tier is `free`, or when consent is not recorded. Community: refuse to run without consent
      (licence condition). Pro: default off.
- [ ] Generate `installId` randomly (>= 16 chars, `[A-Za-z0-9_-]`); never derive it from hardware/user data.
- [ ] Sign the **wire bytes** (after gzip) with the build key; send all headers in 2.1.
- [ ] Batch <= 200 events, gzip bodies > 1 KiB, flush on exit and every few minutes; persist unsent events to disk with a size cap.
- [ ] Retry only `429`/`5xx`/network errors with backoff; honour `Retry-After`; stop on `403`/`410`.
- [ ] Do not put paths, names, emails, serials, MACs, IPs, or licence keys into any field.
- [ ] Call `/delete` on consent withdrawal.
- [ ] Mirror the schema from `GET /v1/telemetry/schema` in a unit test so the app cannot drift.
