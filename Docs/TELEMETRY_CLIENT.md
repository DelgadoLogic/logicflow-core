# LogicFlow Telemetry — Desktop Client

Client side of the contract in [`TELEMETRY_API.md`](TELEMETRY_API.md) (server side). Code: `src/OmniPulse` and the
consent UI in `src/LogicFlow.Dashboard` (`ConsentWindow`, Settings → Security & Privacy).

Entity: Delgado Creative Enterprises LLC d/b/a DelgadoLogic. Contact: support@delgadologic.tech.

## 1. Who sends what

| Edition | Telemetry | Notes |
| --- | --- | --- |
| Free | **Never** | Nothing is queued, no network calls to the telemetry host. |
| Community | **Mandatory Standard** (licence condition) | Declining drops the user to Free. Outside EU/EEA/UK/CH the Extended baseline is part of the condition; inside it, Extended is a *separate optional checkbox*. |
| Pro | Optional, **off by default** | Settings → Diagnostics sharing toggles. Activating a Pro licence resets the level to *None* until the user opts in. |

Levels (`ConsentLevel`): `None`, `Standard` (crash/error reports, feature usage, scan counts), `Extended`
(Standard + one-time system baseline: services, BIOS/firmware, devices/drivers, installed KBs, and a weekly
driver/health digest — powers the crowd-sourced driver index).

Data is **pseudonymous** (random install ID), never described as anonymous.

## 2. Consent store (`OmniPulse.ConsentStore`)

* File: `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json` — **per user**, never HKLM-only.
* Records: edition choice, level, region group + confirmation, policy version, EULA version, **EULA SHA-256**, accept/decision timestamps, install ID, pending-delete ID, server kill-until.
* Fails closed: missing/corrupt file, undecided first run, stale `PolicyVersion` (user is re-prompted), machine policy, active kill-switch ⇒ `EffectiveLevel() == None`.
* IT off-switch: `HKLM|HKCU\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled=1` (also legacy `...\DelgadoLogic\LogicFlow\TelemetryEnabled=0`).
* Install ID: 128-bit random hex, **never** derived from hardware; rotatable (Settings → *Reset install ID*) and deletable (*Delete my data*). A fresh ID is issued whenever sharing starts from *None*.
* Region: from the Windows region setting, **confirmed by the user** on the first-run "Where are you?" question. No IP lookup. Sent as a coarse label `EU` / `GB` / `CH` / `unknown` (server pattern `^([A-Z]{2}|unknown)$`).

## 3. Pipeline (`OmniPulse.PulseClient`)

1. `Track*()` → consent check (`Level >= required`) → envelope appended to `event_queue.jsonl` (cap 512 KB, oldest half dropped).
2. `FlushAsync()` runs 1 min after start and hourly. With level `None` it **deletes the queue** instead of sending.
3. Crashes → `POST /crash`; baseline → `POST /baseline`; everything else → `POST /events` (NDJSON batches ≤ 100 events / 256 KB).
4. Body is gzipped; `X-LF-Sig` = lowercase-hex HMAC-SHA256 of the **gzip bytes exactly as sent on the wire** (the server verifies before decompressing) using the per-build ingest key (`AssemblyMetadata LogicFlowIngestKey`, set with `/p:LogicFlowIngestKey=…` at release build).
5. Headers: `X-LF-Schema: 1`, `X-LF-Install-Id`, `X-LF-Version`, `X-LF-Consent: standard|extended`, `X-LF-Sig`.
6. Success = HTTP 2xx **and** a JSON object with integer `accepted >= 0` **and** `schema == 1`. HTML/empty/garbage `200` is a failure and the events stay queued.
7. Retry: network errors, 408, 429, 5xx → exponential back-off (1 min doubling, max 24 h). Other 4xx → batch dropped (retry cannot help). `410` or `X-LF-Kill` or `{"kill":true}` → kill-switch for 30 days and the queue is wiped.
8. Nothing is sent on splash/startup before consent; the splash screen no longer starts telemetry.


## 4. Scrubbing (`OmniPulse.TelemetryScrubber`)

Before queueing, free text is scrubbed of: `C:\Users\<name>` profile names, drive and UNC paths, URL query strings, e-mail addresses, SIDs, IPv4/IPv6, 32+ char opaque tokens, the current user name and machine name; truncated to 512 chars. Stacks are reduced to `Namespace.Type.Method` (no arguments, files or line numbers; max 30 frames).
Local fingerprint helper = `SHA-256(exceptionType + first 3 in-app normalized frames)` (server also computes its own canonical fingerprint on ingest).

## 5. Envelope & Payloads (`Infrastructure/telemetry-ingest/schema/v1/event.schema.json`)

```json
{ "schema":1, "eventId":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "type":"crash|error|usage|scan|baseline",
  "ts":"2026-10-11T12:00:00.0000000Z", "installId":"…", "appVersion":"1.0.0", "osBuild":"10.0.x",
  "arch":"x64|arm64|x86", "tier":"free|community|pro", "region":"EU|GB|CH|unknown", "payload":{ } }
```

* `payload.crash`: `{ exceptionType, message?, hresult?, frames[], inner?[], component?, isFatal?, uptimeSec? }`
* `payload.error`: `{ code, component, severity?, message?, hresult?, frames?[] }`
* `payload.usage`: `{ feature, action, durationMs?, count?, props?: [{ k, v }] }`
* `payload.scan`: `{ scanType, durationMs?, itemsFound?, bytesReclaimable?, healthScore?, modulesRun?[], issues?: [{ id, count? }] }`
* `payload.baseline`: `{ windows?: { edition, displayVersion, ubr }, hardware?: { cpuName, cpuCores, ramGb, gpus?[], biosVendor, biosVersion, boardVendor?, boardModel?, diskTypes?[] }, drivers?: [{ class, vendor?, name, version?, date?, hwidClass }], kbs?[], securityProducts?[], servicesRunning? }`

## 6. User controls (Settings → Security & Privacy)

* **Diagnostics sharing** toggles (Standard / Extended): Pro optional; Community locked on (Extended optional only in EU/EEA/UK/CH); Free disabled.
* **View what is sent** — `PulseClient.BuildPreview()`: level, install ID, queued events, baseline copy path.
* **Reset install ID**, **Delete my data** (`PulseClient.DeleteMyDataAsync()`: wipes queue/baseline/state/config cache, retires the ID, `POST /delete {installId}`; if offline the request is persisted and retried on later flushes).
* **Change edition or region…** re-opens the first-run consent screen.

## 7. Tests

`tests/LogicFlow.Tests/TelemetryAndEditionTests.cs`: consent policy and persistence, fail-closed paths, scrubber, PulseClient (consent gating, signature header, HTML-200 rejection, schema=1 validation, back-off, kill-switch, opt-out wipe, delete + retry, and `event.schema.json` contract conformance for all 5 payload types).
