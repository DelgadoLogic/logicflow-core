# LogicFlow v1.0 — Project Architecture & Engineering Guide (`PROJECT.md`)

**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic (`https://delgadologic.tech`)  
**Solution**: `Products/LogicFlow/LogicFlow.sln` (**17 Projects**: 16 `src/` + 1 `tests/`)  
**Target Framework**: `.NET 8.0` (`net8.0` / `net8.0-windows`, `win-x64`)  
**Last Updated**: October 13, 2026

---

## 1. Architectural Principles

1. **Native .NET 8 & Win32/NT P/Invoke Execution**: Core system operations (`EmptyWorkingSet`, `NtSetSystemInformation`, `DeviceIoControl` with `FSCTL_SET_EXTERNAL_BACKING` and `FSCTL_DUPLICATE_EXTENTS_TO_FILE`, `PowerSetActiveScheme`, S.M.A.R.T. IOCTLs, raw volume sector reads) use direct P/Invoke bindings in `LogicFlow.Native` with official Windows CLI integration (`pnputil`, `netsh`, `sfc`, `DISM`, `winget`) where Windows requires standard user-mode tool invocation.
2. **Safety-First Mutation Model**: Every registry modification saves a timestamped `.reg` snapshot to `%LOCALAPPDATA%\LogicFlow\RegistryBackups\` before modifying keys (`lf reg rollback`). File cleaners and deduplicators enforce strict protected-path rules, mutable-document exclusion whitelists, and `FileAttributes.ReparsePoint` symlink/junction traversal guards.
3. **Consent-Gated, Dual-Scrubbed Pseudonymous Telemetry (`OmniPulse`)**: Nothing is queued or sent before first-run consent (`ConsentWindow`). Free ($0) and default Pro ($29.99 / $19.99 launch) run at `ConsentLevel.None`. When enabled (Community Edition or opt-in Pro), events are scrubbed on-device by `OmniPulse.TelemetryScrubber`, signed with HMAC-SHA256 (`X-LF-Sig`), validated and scrubbed again by `lf-telemetry-ingest` (`https://api.delgadologic.tech/v1/telemetry`), and retained for **90 days** (raw events), **13 months** (daily rollups without `installId`), or **indefinitely** (deduplicated crash groups without `installId`).
4. **Offline RSA-2048 Licensing & Ed25519 Signed Updates**: Paid Pro and Team licenses are verified offline via RSA-2048 (`SHA-256`) bound to a 4-component WMI `HWID` (`OmniLicense`), while update manifests are verified via Ed25519 + SHA-256 (`OmniCore.Engine`).

---

## 2. Solution Map (`LogicFlow.sln` — 17 Projects)

### 2.1 User Interfaces & Background Service
- **`LogicFlow.Dashboard` (`src/LogicFlow.Dashboard` → `LogicFlow.exe`)**:
  - Primary WPF desktop GUI (`WPF-UI 4.3.0`), DWM backdrop, interactive system tray (`TrayIconManager`), 8 primary module views (`Dashboard`, `Sentinel — Security`, `Guardian — Performance`, `HyperStore — Storage Armor`, `Resource Monitor`, `Toolbox — Utilities`, `Lazarus — Recovery`, `Registry Surgeon`) + `Settings` and `ConsentWindow`.
- **`LogicFlow.CLI` (`src/LogicFlow.CLI` → `lf.exe`)**:
  - Command-line interface exposing **10 command groups, 53 subcommands**, and **6 top-level aliases** (`boost`, `turbo`, `optimize`, `rollback`, `status`, `discover`), with `--json`, `--silent`, `--force`, and `--elevate`.
- **`OmniService` (`src/OmniService` → `LogicFlowAgent.exe`)**:
  - Background Windows Service (`LogicFlowAgent`) for Pro scheduled maintenance (30-min check interval) and 24-hour signed update checks.

### 2.2 Performance, Storage, Security, Recovery & Registry Engines
- **`LogicFlow.Guardian` (`src/LogicFlow.Guardian` → `LogicFlow.Guardian.dll`)**:
  - `JunkCleanerEngine`, `MemoryOptimizer`, `TurboMode`, `GameCompression` (WOF), `VolumeAwareDeduplicator` (ReFS Block Cloning + NTFS Hard Links), `HyperStoreBackgroundWorker`, `FullScreenGameGuard`, `DriverAuditor`, `WinGetUpdaterEngine`, `Debloat`, `StartupOptimizer`, `WindowsTweakEngine` (92 reversible tweaks), `SmartDiskHealth`, `DiskSpaceAnalyzer`, `DuplicateFileFinder`, `FileShredder`, `SystemRestore`.
- **`LogicFlow.Storage.Engine` (`src/LogicFlow.Storage.Engine` → `LogicFlow.Storage.Engine.dll`)**:
  - **HyperStore (V-Dense)** core library: `FastCdcChunker` (8–64 KB variable chunks), 256-bit `Blake3` (`3.0.2`) SIMD hashing, `MinHashClusterer`, `DualTierZstdCompressor` (`ZstdSharp.Port 0.8.4`, Hot L3 / Cold L19 + dictionary), `.lfc` container `LfcWriter`/`LfcReader`.
- **`LogicFlow.Sentinel` (`src/LogicFlow.Sentinel` → `LogicFlow.Sentinel.dll`)**:
  - `DefenderHardenerEngine` (16 ASR rules, Controlled Folder Access, PUA), `PersistenceScannerEngine` (WMI, Tasks, IFEO, `AppInit_DLLs`), `DnsHostsGuardEngine`, `NetworkScanner`, `VulnerabilityScanner`, `StartupAuditor`, `Remediation`.
- **`LogicFlow.Lazarus` (`src/LogicFlow.Lazarus` → `LogicFlow.Lazarus.dll`)**:
  - `LazarusEngine`, `NtfsMftEngine` (NTFS Master File Table record undelete), `SectorScanner`, `FileCarver` (25+ file signatures, forensic 3-column hex dump, document/media visual extractors), and `MtpBridge`.
- **`LogicFlow.Registry` (`src/LogicFlow.Registry` → `LogicFlow.Registry.dll`)**:
  - `RegistryAnalyzer` & `RepairEngine` (10-category registry scan, automatic `.reg` backup snapshots in `%LOCALAPPDATA%\LogicFlow\RegistryBackups`, 1-click rollback).

### 2.3 Core Foundation, Telemetry, Updates & Licensing
- **`DelgadoLogic.Core` (`src/DelgadoLogic.Core` → `DelgadoLogic.Core.dll`)**:
  - Shared runtime contracts, `CloudLicenseBridge`, `SharedUpdateEngine`, product identity.
- **`LogicFlow.Native` (`src/LogicFlow.Native` → `LogicFlow.Native.dll`)**:
  - Win32/NT P/Invoke bindings (`kernel32`, `ntdll`, `powrprof`, `setupapi`, `iphlpapi`, `wofutil`, SMART IOCTLs, ReFS `FSCTL_DUPLICATE_EXTENTS_TO_FILE`).
- **`OmniPulse` (`src/OmniPulse` → `OmniPulse.dll`)**:
  - Local hardware profiler (`SystemProfiler`) + consent-gated pseudonymous telemetry client (`PulseClient`, `ConsentStore`, `TelemetryScrubber`, `CrashGuard`).
- **`OmniCore.Engine` (`src/OmniCore.Engine` → `OmniCore.Engine.dll`)**:
  - `AutoUpdateEngine` (Ed25519 manifest signature + SHA-256 verification) and `SmartRollbackEngine`.
- **`OmniLicense` (`src/OmniLicense` → `OmniLicense.dll`)** & **`OmniLicense.Commerce` (`src/OmniLicense.Commerce` → `OmniLicense.Commerce.dll`)**:
  - Offline RSA-2048 license token validator, 4-component WMI `HwidGenerator`, tier entitlements (`Free`, `Community`, `Pro`, `Team`), and commercial catalog/order models.
- **`LogicFlow.Scraper` (`src/LogicFlow.Scraper` → `LogicFlow.Scraper.dll`)**:
  - Windows event log harvester and known KB/CVE issue correlator (`IssueHarvester`, `RepoAnalyzer`).
- **`LogicFlow.VoiceAgent` (`src/LogicFlow.VoiceAgent` → `LogicFlow.VoiceAgent.dll`)**:
  - Deferred experimental Gemini Live voice command dispatcher (`1.0.0-preview`). Excluded from v1.0 commercial distribution.

### 2.4 Automated Test Suite
- **`LogicFlow.Tests` (`tests/LogicFlow.Tests` → `LogicFlow.Tests.dll`)**:
  - **51 test `.cs` files** containing **994 test methods** (`889 [Fact]` + `105 [Theory]` with `768 [InlineData]` rows).

---

## 3. Cloud Infrastructure (`Website/` & `Infrastructure/`)

- **Website (`Website/site`)**: React 18 + Vite 6 + Framer Motion SPA deployed to Firebase Hosting (`https://delgadologic.tech`).
- **Commerce & Licensing Functions (`Website/functions`)**: Firebase Cloud Functions v2 (Node.js 22) handling PayPal Orders & Webhooks (`createCheckoutOrder`, `captureCheckoutOrder`, `handlePayPalWebhook`), license activation (`activateLicense`, `activateCommunityLicense`, `validateLicense`), DSR requests (`submitDataRequest`), and waitlist (`joinWaitlist`).
- **Telemetry Ingestion Service (`Products/LogicFlow/Infrastructure/telemetry-ingest`)**: Stateless Node.js 22 HTTP service on Google Cloud Run (`lf-telemetry-ingest` behind `https://api.delgadologic.tech/v1/telemetry`) with HMAC-SHA256 wire verification, Ajv 2020 JSON Schema validation, server-side PII scrubbing (`src/scrub.js`), in-memory salted-hash rate limiting, `POST /delete` tombstone erasure, and GCS 90-day lifecycle deletion.
