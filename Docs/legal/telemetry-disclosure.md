# Telemetry & Diagnostics Technical Disclosure

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity / Data Controller**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Applies To**: LogicFlow v1.0 Desktop Application (`LogicFlow.exe`), CLI (`lf.exe`), Background Service (`LogicFlowAgent.exe`), and Telemetry Ingest Service (`https://api.delgadologic.tech/v1/telemetry`)

---

## 1. Plain-English Summary

LogicFlow is built on **verifiable technical transparency**. We never hide what our software sends over the network, and we never use blanket "no-telemetry" slogans across all editions or mislabel pseudonymous identifiers as "anonymous."

1. **Nothing Is Sent Before First-Run Consent**: No telemetry is queued or transmitted during installation or on the splash screen. Telemetry only begins if and after you complete the first-run edition and diagnostics dialog (`ConsentWindow`) and choose a telemetry-enabled option.
2. **Tier-Specific Telemetry Architecture**:
   - **LogicFlow Free Edition ($0)**: Read-only diagnostic scanning and health preview. **Telemetry is disabled (`ConsentLevel.None`)**—nothing is queued or transmitted.
   - **LogicFlow Community Edition ($0)**: Unlocks interactive core cleanup, system optimization, registry repair with `.reg` backup, WOF game compression, and security hardening for personal non-commercial use in exchange for **pseudonymous diagnostic telemetry**:
     - **Standard Telemetry** is required across all regions for the Community Edition.
     - **Extended System Baseline** (hardware/driver/KB inventory for our crowd-sourced driver compatibility index) is **optional** in every region:
       - **Strict Opt-In Regions (`ConsentStore.IsStrict() == true` — European Union / EEA, United Kingdom, Switzerland, Canada, Brazil, Japan, South Korea, and India)**: Presented as a **separate, optional, un-prechecked checkbox** on first run (in compliance with GDPR Article 7(4), ePrivacy Directive Article 5(3), UK PECR, PIPEDA, LGPD, APPI, PIPA, and DPDP Act).
       - **Non-Strict Regions (`ConsentStore.IsStrict() == false` — United States, Mexico, Australia / New Zealand, and Other / Rest of world)**: **Pre-selected by default** when choosing Community Edition on first run, and can be unchecked before continuing or disabled at any time in **Settings → Security & Privacy** without losing Community Edition access.
     - Declining or withdrawing `Standard` telemetry on a Community installation transitions the app to the **Free Edition** (`ConsentLevel.None`).
   - **LogicFlow Pro ($29.99 regular / $19.99 launch promo, 3 Devices) & Team 10-Pack ($149.00, 10 Devices)**: Unlocks all Community features plus **Background Automation** (`LogicFlowAgent`, HyperStore autonomous worker & Game Guard, Game Vault auto-compact), **Advanced Recovery** (Lazarus deep sector carving & NTFS MFT record recovery), commercial use rights, and 24h priority support. **Telemetry is optional and OFF by default (`ConsentLevel.None`)**. Activating a Pro/Team license automatically resets telemetry sharing to `None` unless you explicitly opt in via **Settings → Security & Privacy**.
3. **Pseudonymous by Design**: Every telemetry event carries a randomly generated 128-bit cryptographic token (`installId`, matching `^[A-Za-z0-9_-]{16,64}$`), never derived from hardware serial numbers, MAC addresses, or user accounts. Because events can be linked across a single installation until the ID rotates, we classify all telemetry as **pseudonymous data**.
4. **Dual-Layer PII Scrubbing & No IP Storage**: Both the desktop client (`OmniPulse.TelemetryScrubber`) and our Cloud Run ingest server (`lf-telemetry-ingest`) strip user paths, filenames, emails, IP literals, SIDs, hostnames, and secrets. Source IP addresses are hashed in volatile RAM with a 6-hour rotating salt solely for rate limiting and are **never written to disk or cloud storage**.

---

## 2. Edition Comparison & Network Behavior Matrix

| Network Activity | Free Edition ($0) | Community Edition ($0) | Pro ($29.99 / $19.99) & Team ($149) |
| :--- | :--- | :--- | :--- |
| **Pseudonymous Telemetry** (`POST https://api.delgadologic.tech/v1/telemetry/*`) | **Disabled (`ConsentLevel.None`)** | **Mandatory `Standard`** (`Extended` unchecked opt-in in **EU/EEA, UK, Switzerland, Canada, Brazil, Japan, South Korea, India**; pre-selected by default and uncheckable anytime in **US, Mexico, Australia/NZ, Rest of world**) | **Disabled (`ConsentLevel.None`) by default** (Optional opt-in in Settings) |
| **Signed Update Manifest Check** (`GET https://api.delgadologic.tech/v1/update/logicflow/stable`) | Manual only (`LogicFlowAgent` skips background network checks on Free / undecided installations) | Enabled after consent (configurable in Settings) | Enabled after consent (configurable in Settings) |
| **Online License Activation / Validation** (`https://api.delgadologic.tech/activate` & `/validate`) | Not used | Community activation token | Used when activating or validating a paid Pro/Team seat (`HWID` never linked to `installId`) |

---

## 3. Telemetry Levels & Exact Event Schema (`schema: 1`)

The authoritative JSON Schema is served live at `GET https://api.delgadologic.tech/v1/telemetry/schema` and stored in `Products/LogicFlow/Infrastructure/telemetry-ingest/schema/v1/event.schema.json`.

### 3.1 Consent Levels (`ConsentLevel`)

| Level | Wire Header (`X-LF-Consent`) | Allowed Event Types | Purpose |
| :--- | :--- | :--- | :--- |
| **`None`** | *(No requests sent)* | None (local queue deleted) | Default for Free, Pro, Team, and undecided first-run state. |
| **`Standard`** | `standard` | `crash`, `error`, `scan`, `usage` | Crash/exception stability tracking, error codes, aggregate scan durations/scores, and pseudonymous feature usage counts. |
| **`Extended`** | `extended` | `crash`, `error`, `scan`, `usage`, `baseline` | Adds one-time system configuration `baseline` snapshot and weekly driver/health digest to power the crowd-sourced driver compatibility index. |

### 3.2 Wire Envelope Example

```json
{
  "schema": 1,
  "eventId": "3f0c4a8e-5b1d-4a77-9c52-0d6b8e1a2f33",
  "type": "scan",
  "ts": "2026-10-13T18:30:00Z",
  "installId": "inst_9fK2xQ7mL0aP4vZ8",
  "appVersion": "1.0.0",
  "osBuild": "10.0.26100.1742",
  "arch": "x64",
  "tier": "community",
  "region": "US",
  "payload": {
    "scanType": "full_health_check",
    "durationMs": 412,
    "itemsFound": 38,
    "bytesReclaimable": 148291584,
    "healthScore": 92,
    "modulesRun": ["Guardian.JunkCleaner", "Registry.Analyzer", "Sentinel.Hardening"]
  }
}
```

### 3.3 Payload Specifications by Event Type

1. **`crash`** (`POST /v1/telemetry/crash` or `/events`):
   - `exceptionType` (e.g., `System.NullReferenceException`), PII-scrubbed `message` (≤ 512 chars client / ≤ 1000 server), `hresult` (`0x[0-9A-F]{1,8}`), `frames` (up to 30 normalized `Namespace.Type.Method` stack frames with all file paths, line numbers, and arguments stripped), `inner` exceptions (up to 5), `component`, `isFatal`, and `uptimeSec`.
2. **`error`** (`POST /v1/telemetry/crash` or `/events`):
   - `code`, `component`, `severity` (`info` | `warning` | `error`), scrubbed `message`, `hresult`, and normalized `frames`.
3. **`scan`** (`POST /v1/telemetry/events`):
   - `scanType`, `durationMs`, `itemsFound`, `bytesReclaimable`, `healthScore` (`0–100`), `modulesRun`, and `issues` (`{id, count}[]`).
4. **`usage`** (`POST /v1/telemetry/events`):
   - `feature`, `action`, `durationMs`, `count`, and bounded `props` (`{k, v}[]` — never user content or paths).
5. **`baseline`** (`POST /v1/telemetry/baseline` or `/events` — **`Extended` consent level only**):
   - `windows`: `{ edition, displayVersion, ubr }`
   - `hardware`: `{ cpuName, cpuCores, ramGb, gpus[<=4]{vendor, name, driverVersion, driverDate}, biosVendor, biosVersion, boardVendor, boardModel, diskTypes[nvme|ssd|hdd|usb|other] }`
   - `drivers` (up to 200): `{ class, vendor, name, version, date, hwidClass }` (generic PnP hardware ID prefix only — **never device serial numbers**)
   - `kbs` (up to 500): Installed Windows Update KB identifiers (e.g., `KB5034441`)
   - `securityProducts` (up to 16) and `servicesRunning` count/names.

---

## 4. What Is NEVER Collected or Transmitted (Technical Guardrails)

Both `OmniPulse.TelemetryScrubber` (client-side C#) and `src/scrub.js` (server-side Node.js in `lf-telemetry-ingest`) enforce deterministic redaction before queueing or storage:

| Prohibited Data Category | Technical Enforcement Mechanism |
| :--- | :--- |
| **Windows Usernames & User Profile Paths** | Replaced on client and server (`C:\Users\<Username>\...` → `<user>`). |
| **Arbitrary File Names, Documents & UNC Paths** | Replaced with `<path>\file` or `<unc>`; personal file contents are never read by `OmniPulse`. |
| **Registry Backup Snapshots (`.reg`)** | Stored strictly locally in `%LOCALAPPDATA%\LogicFlow\RegistryBackups\`; never transmitted. |
| **Hardware Serial Numbers & License `HWID`** | The 4-component WMI `HWID` is used exclusively by `OmniLicense` for paid seat activation and is **never** accessible to or linked with `OmniPulse` (`installId`). |
| **Email Addresses, URLs with Query Strings & Secrets** | Stripped via regex (`<email>`, `<redacted>`, `<token>`) on both client and server. |
| **Client IP Addresses & Precise Geolocation** | Source IPs are hashed in-memory with a 6-hour rotating salt solely for rate limiting (`120 req/min` per IP) and **never written to disk or GCS**. Region (`EU`, `GB`, `CH`, `US`, `unknown`) is read from local Windows `RegionInfo` and confirmed by the user on first run—never via IP lookup. |

---

## 5. Wire Authentication, Storage & Retention Schedule

1. **HMAC-SHA256 Wire Signing (`X-LF-Sig`)**: Every request body is gzip-compressed and signed with the per-build ingest key (`HMAC-SHA256` over the exact compressed wire bytes). The server verifies `X-LF-Sig` in constant time **before** decompressing, preventing unauthenticated gzip-bomb attacks.
2. **Retention Schedule**:
   - **Raw Events & Ingest Stats** (`GCS v1/events/`, `v1/stats/`): **90 calendar days** (enforced via Google Cloud Storage Object Lifecycle rules).
   - **Daily Aggregated Rollups** (`GCS v1/rollups/daily/`): **13 months (395 days)** (contains zero `installId` values).
   - **Deduplicated Crash Groups** (`GCS v1/crash_groups/`): **Indefinite** (keyed by stack SHA-256 fingerprint; contains zero `installId` values).

---

## 6. User Controls, IT Group Policy & Instant Self-Service Erasure

### 6.1 In-App Controls (**Settings → Security & Privacy**)
- **View what is sent**: Calls `PulseClient.BuildPreview()` to display your current `ConsentLevel`, active `installId`, queued events in `%LOCALAPPDATA%\LogicFlow\Pulse\event_queue.jsonl`, and last baseline snapshot (`system_baseline.json`).
- **Reset install ID**: Immediately generates a fresh 128-bit random `installId`.
- **Delete my data**: Calls `PulseClient.DeleteMyDataAsync()`, which wipes all local queue/baseline files, retires the current `installId`, and sends a signed `POST https://api.delgadologic.tech/v1/telemetry/delete` request. The server immediately writes a `sha256(installId)` tombstone (returning `410 Gone` for any future events under that ID), excludes the ID from all BigQuery views/digests, and rewrites raw GCS partitions in the background.

### 6.2 IT / Enterprise Group Policy Override
System administrators can force telemetry OFF across any machine or user profile by setting:
- `HKLM\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled = 1` (`REG_DWORD`)
- `HKCU\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled = 1` (`REG_DWORD`)
- Or legacy `HKLM\SOFTWARE\DelgadoLogic\LogicFlow\TelemetryEnabled = 0` (`REG_DWORD`)

When set, `ConsentStore.IsDisabledByPolicy()` returns `true` and `EffectiveLevel()` evaluates to `ConsentLevel.None` regardless of local file state.

---

## 7. Contact Information

- **Privacy & Data Subject Requests**: `privacy@delgadologic.tech` or <https://delgadologic.tech/data-requests>
- **Security & Vulnerability Reports**: `security@delgadologic.tech`
- **General Support**: `support@delgadologic.tech`
- **Postal Address**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic, 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA
