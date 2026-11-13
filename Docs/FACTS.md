# LogicFlow — Canonical Single Source of Truth (`FACTS.md`)

**Last Updated**: November 11, 2026 (EST)  
**Status**: Locked Canonical Reference — All product documentation, legal agreements, website copy, and installer metadata MUST align 100% with this document.

---

## 1. Corporate Identity, Jurisdiction & Contacts

| Attribute | Canonical Value |
| :--- | :--- |
| **Legal Entity Name** | `Delgado Creative Enterprises LLC d/b/a DelgadoLogic` |
| **Entity Type & Jurisdiction** | District of Columbia Limited Liability Company (Trade Name / DBA `DelgadoLogic` registered with the DC Department of Licensing and Consumer Protection [DLCP] prior to public commercial release) |
| **Founder & Principal** | Manuel Alejandro Delgado (`Chronolapse411`) |
| **Governing Law & Venue** | Laws of the District of Columbia, United States of America (without regard to conflict-of-law principles); exclusive jurisdiction and venue in the state and federal courts located in Washington, D.C. |
| **Postal Address** *( strictly for legal pages, EULA, and CAN-SPAM email footers only )* | `6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA` |
| **Primary Support Email** | `support@delgadologic.tech` |
| **Role Mailboxes** *(all route/forward to `support@delgadologic.tech`)* | `privacy@delgadologic.tech` (Data Protection & Privacy)<br>`legal@delgadologic.tech` (Legal, Terms & DMCA)<br>`security@delgadologic.tech` (Vulnerability Disclosure & PSIRT / CRA)<br>`billing@delgadologic.tech` (Orders, Refunds & Licensing) |
| **Support Hours & Response SLA** | **Monday–Friday, 9:00 AM – 5:00 PM EST** (excluding US federal holidays).<br>• **Free & Community**: Self-service documentation + community issue tracker (48 business hours target for billing/privacy inquiries).<br>• **Pro & Team**: Priority email support with **24 business hours** response target (48 business hours maximum). |
| **Minimum User Age** | **16+ years of age** to purchase, download, install, or use LogicFlow. Not directed to children under 13 (zero knowing collection under COPPA). |

---

## 2. Commercial Editions, Pricing & Licensing

| Edition / SKU | Price (USD) | Devices | Commercial Use | Telemetry Policy | Key Entitlements & Scope |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LogicFlow Free** (`LF-FREE`) | **$0.00** | 1 Device | No (Personal only) | **None** (`ConsentLevel.None` — never queued or sent) | Read-only diagnostic scanning and system health preview across all modules; manual inspection without automated remediation. |
| **LogicFlow Community** (`LF-COMM`) | **$0.00** | 1 Device | No (Personal non-commercial only) | **Mandatory Pseudonymous Telemetry Condition** (`Standard` required across all regions; `Extended` baseline is **pre-selected by default** in non-strict regions [`United States`, `Mexico`, `Australia / New Zealand`, `Other / Rest of world`] and can be unchecked on first run or disabled anytime in Settings while keeping Community access, and is presented as an **unchecked opt-in checkbox** across all 8 strict `PrivacyRegion` jurisdictions [`EU/EEA`, `United Kingdom`, `Switzerland`, `Canada`, `Brazil`, `Japan`, `South Korea`, `India`]). Declining or withdrawing `Standard` telemetry drops to **Free**. | Unlocks interactive core cleanup, optimization, registry repair with automatic backup, WOF game compression, and security hardening for personal use. |
| **LogicFlow Pro** (`LF-PRO`) | **$29.99** one-time<br>*(Launch Promo: **$19.99** for 60 days; **14-day Pro Trial** available)* | **3 Devices** | **Yes** (Commercial & professional use permitted) | **Optional & OFF by default** (`ConsentLevel.None` unless user explicitly opts in via Settings) | Everything in Community + **Background Automation** (`LogicFlowAgent` scheduled scans/auto-fix, HyperStore autonomous worker & Game Guard, Game Vault auto-compact), **Advanced Recovery** (Lazarus deep sector carving & NTFS MFT record recovery), **All v1.x Updates Included**, and **24h Priority Support**. Zero-Hostage Revert keeps all rollback, `.lfc` unpack, WOF decompress, and `/boost off` revert actions unlocked even after trial expiry. |
| **Extra Seat Add-On** (`LF-SEAT`) | **$9.99** one-time | +1 Device | Matches base Pro license | Matches base Pro license | Adds 1 additional device activation seat to an existing LogicFlow Pro license. |
| **LogicFlow Team 10-Pack** (`LF-TEAM10`) | **$149.00** one-time | **10 Devices** | **Yes** (Commercial & enterprise fleet use) | **Optional & OFF by default** (configurable via Group Policy / Registry `TelemetryDisabled=1`) | All Pro entitlements for up to 10 machines, CLI headless deployment (`lf.exe --json`), and priority 24h support. |

### Locked Licensing & Commercial Rules
1. **"Lifetime" v1.x Scope**: One-time purchase grants a perpetual license to use LogicFlow v1.x and includes all minor and patch updates throughout the **v1.x major release lifecycle** (`1.0` through `1.x`). Future major architectural releases (e.g., `v2.0`) may be offered as an optional paid upgrade (estimated at `~$14.99` for existing Pro customers) and are never required to keep `v1.x` functioning.
2. **Retired SKUs**: The legacy *Founder Pass* ($149 all-future-products pass), *Sovereign Suite* ($49/$59 bundle), *Family Tier*, and *$9.99 AI Health Audit Upsell* are **retired** for the LogicFlow v1.0 commercial release.
3. **60-Day Money-Back Guarantee**: Every purchase of LogicFlow Pro, Extra Seat, or Team 10-Pack is backed by a **60-day no-questions-asked money-back guarantee** from the date of transaction. Upon refund, the associated cryptographic license key and seats are deactivated.
4. **EU/EEA/UK 14-Day Withdrawal Waiver**: At checkout, buyers in the EU, EEA, and UK must actively tick an un-prechecked box consenting to immediate digital delivery/license issuance and acknowledging waiver of their 14-day statutory cooling-off withdrawal right under EU Directive 2011/83/EU Article 16(m) (and UK Consumer Contracts Regulations 2013 Reg. 37), while retaining DelgadoLogic's contractual **60-day no-questions-asked refund guarantee**.
5. **Cryptographic License Binding (`OmniLicense`)**:
   - **Algorithm**: Offline dual-algorithm signature verification supporting both **Ed25519** (64-byte signature) and **RSA-2048** (`PKCS#1 v1.5` with `SHA-256`, 256-byte signature) against DelgadoLogic's pinned public keys, with outer/inner `kid` binding and fail-closed validation.
   - **Hardware Fingerprint (`HWID`)**: 44-character Base64 string encoding `SHA-256(Win32_Processor.ProcessorId + Win32_BaseBoard.SerialNumber + Win32_BIOS.SerialNumber + Win32_DiskDrive.SerialNumber)`.
   - **Privacy Separation**: The license `HWID` is used exclusively for license activation/seat validation (`activateLicense` / `validateLicense`) and is **never** used as or linked to the telemetry `installId`.

---

## 3. Telemetry & Data Privacy Specification (`OmniPulse`)

| Dimension | Canonical Specification |
| :--- | :--- |
| **Terminology** | Always described as **pseudonymous** diagnostic telemetry (never "anonymous" and never a blanket "no-telemetry" slogan for the entire product; only `Free` and default `Pro` have telemetry disabled). |
| **Ingest Base URL** | `https://api.delgadologic.tech/v1/telemetry` (`POST /events`, `POST /crash`, `POST /baseline`, `POST /delete`, `GET /schema`, `GET /healthz`) |
| **Install Identifier (`installId`)** | Random 128-bit cryptographic token (`^[A-Za-z0-9_-]{16,64}$`), stored per-user in `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`. **Never derived from hardware serials, MAC addresses, or user accounts.** Rotated automatically on consent transition and every 90 days, or manually via Settings → *Reset Install ID*. |
| **Consent Storage** | Per-user JSON file at `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`. Records edition, `ConsentLevel` (`None`, `Standard`, `Extended`), region code, user region confirmation, policy version, EULA version, **EULA SHA-256**, and decision timestamps. Fails closed to `ConsentLevel.None` if missing, corrupt, or outdated. |
| **IT / Enterprise Policy Override** | Administrators can force telemetry off machine-wide or per-user via `HKLM\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled = 1` (or `HKCU`), as well as legacy `HKLM\SOFTWARE\DelgadoLogic\LogicFlow\TelemetryEnabled = 0`. |
| **Region Determination** | Read locally from the Windows OS region setting (`RegionInfo.CurrentRegion.TwoLetterISORegionName`) and explicitly confirmed by the user on the first-run dialog (`ConsentStore.PrivacyRegion`). **No IP geolocation lookup is performed.** `ConsentStore.IsStrict()` enforces strict opt-in (`Extended` unchecked by default) across **8 region groups**: `European Union / EEA`, `United Kingdom`, `Switzerland`, `Canada`, `Brazil`, `Japan`, `South Korea`, and `India`; in the **4 non-strict region groups** (`United States`, `Mexico`, `Australia / New Zealand`, `Other / Rest of world`), `Extended` is pre-selected by default when choosing Community and remains optional/uncheckable at any time. Transmitted on the wire only as a coarse region code (`EU`, `GB`, `CH`, `US`, or `unknown`). |
| **Standard Level Payload** | Allowed event types: `crash` (exception type, scrubbed message, top 30 normalized `Namespace.Type.Method` stack frames, SHA-256 crash fingerprint), `error` (error code, module component, severity, HRESULT), `scan` (scan type, duration ms, count of items found, bytes reclaimable, composite health score 0–100), and `usage` (feature name, action verb, duration ms). |
| **Extended Level Payload** | Includes `Standard` plus a one-time `baseline` snapshot and weekly health/driver digest: OS edition/build/UBR, CPU model/core count, RAM GB, GPU vendor/name/driver version/date (up to 4), BIOS vendor/version, baseboard vendor/model, disk media types (`nvme`/`ssd`/`hdd`), installed PnP driver inventory (up to 200: class, vendor, name, version, date, hardware ID class — **no device serial numbers**), installed Windows Update KB numbers (up to 500), registered security product names, and running service names/states. Powers the crowd-sourced driver compatibility index. |
| **Dual-Layer PII Scrubbing** | Both client (`OmniPulse.TelemetryScrubber`) and server (`lf-telemetry-ingest`) strip `C:\Users\<username>` paths, arbitrary file/UNC paths, URL query strings, email addresses, IPv4/IPv6 literals, Windows SIDs, machine hostnames, and 32+ character opaque tokens/keys before queueing or storage. |
| **IP Address Handling** | **Never written to disk or telemetry storage.** Client IPs are hashed in-memory on the server using a 6-hour rotating random salt strictly for abuse rate-limiting. |
| **Retention Schedule** | • **Raw Events & Ingest Stats** (`GCS v1/events/`, `v1/stats/`): **90 days** (enforced via GCS object lifecycle rules).<br>• **Daily Aggregated Rollups** (`GCS v1/rollups/daily/`): **13 months (395 days)** (contains zero `installId` values).<br>• **Deduplicated Crash Groups** (`GCS v1/crash_groups/`): **Indefinite** (keyed by stack fingerprint; contains zero `installId` values). |
| **Right to Erasure (`Delete My Data`)** | Users can erase all telemetry linked to their `installId` at any time via:<br>1. In-app **Settings → Security & Privacy → Delete My Data** (wipes local queue/baseline, retires `installId`, sends signed `POST /v1/telemetry/delete`).<br>2. Direct API: `POST https://api.delgadologic.tech/v1/telemetry/delete` with `{"installId": "<id>"}`.<br>3. Web portal: `https://delgadologic.tech/data-requests` or email to `privacy@delgadologic.tech`.<br>Server immediately writes a `sha256(installId)` tombstone (returning HTTP `410 Gone` for any future events under that ID), excludes the ID from all BigQuery views/digests, and rewrites raw GCS partitions in the background. |

---

## 4. Supported Operating Systems & Platform Scope

| Requirement | Canonical Specification |
| :--- | :--- |
| **Supported Client OS** | **Windows 10 (Version 1607 / Build 14393 minimum; Version 2004 / Build 19041+ recommended)** and **Windows 11 (all releases, including 22H2, 23H2, 24H2)** |
| **Supported Server OS** | **Windows Server 2019** and **Windows Server 2022** |
| **Launch Architecture** | **64-bit (`win-x64`)** self-contained `.NET 8.0` deployment (no external .NET runtime installation required) |
| **Packaged Installer (`LogicFlowSetup.exe`)** | **`174,744,576` bytes (`166.6 MB` / `166.6 MiB`)** — SHA-256: `7FC3FAC70FBA7964C9A87038A160FB6D20E59D85F37623E7E2CFB02B8B487F74` |
| **Multi-Architecture Packaging** | `package_and_deploy.ps1` packages `win-x64` (`LogicFlowSetup.exe`, the shipped v1.0 architecture; `win-arm64` is planned; legacy 32-bit `win-x86` is retired) |
| **Unsupported Legacy OS** | **Pre-Windows 10 desktop releases (NT 6.1 / 6.2 / 6.3 and earlier) are NOT supported.** (All legacy pre-Windows 10 claims are retired due to the `.NET 8` OS floor and modern Win32/WOF/Defender ASR kernel APIs). |
| **AI & Voice Engine (`GemmaAiEngine`)** | **Hybrid `Gemma 4 E2B` (`gemma-4-E2B-it`, Apache 2.0) Engine**: Supports optional user-downloaded local on-device GGUF sidecar (`llama-server.exe` `b12283` MIT on `127.0.0.1` + `gemma-4-E2B-it-Q4_K_M.gguf` Apache-2.0, verified against pinned SHA-256 checksums and auto-unloaded on game detection) and opt-in Argon-vLLM OpenAI-compatible cloud endpoint (`AllowHybridCloudFallback = false` by default), powering `PulseQueryEngine`, `TurboMode` Smart Boost, `DriverDatabase` Event Log crash correlation, and `LogicFlow.VoiceAgent` (`NAudio` 2.2.1 MIT) 12-tool dispatch. |

---

## 5. Verified Codebase Metrics (v1.0.0 Baseline)

### 5.1 Solution Projects (`LogicFlow.sln` — 17 Total Projects: 16 `src/` + 1 `tests/`)

| # | Project Name | Assembly / Output | Target Framework | Shipped in v1.0 | Purpose |
| :--- | :--- | :--- | :--- | :---: | :--- |
| 1 | `DelgadoLogic.Core` | `DelgadoLogic.Core.dll` | `net8.0-windows` | Yes | Shared runtime contracts, `CloudLicenseBridge`, `SharedUpdateEngine`, product identity. |
| 2 | `LogicFlow.Dashboard` | `LogicFlow.exe` | `net8.0-windows` | Yes | Primary WPF desktop GUI (WPF-UI 4.3.0, DWM backdrop, system tray, 8 module views + Settings, `ConsentWindow`). |
| 3 | `LogicFlow.CLI` | `lf.exe` | `net8.0-windows` | Yes | Command-line interface: **10 command groups, 58 subcommands**, + 6 legacy top-level aliases; `--json`, `--silent`, `--force`, `--elevate`. |
| 4 | `LogicFlow.Guardian` | `LogicFlow.Guardian.dll` | `net8.0-windows` | Yes | Performance, AI & maintenance engines: `GemmaAiEngine` (`gemma-4-E2B-it` hybrid local sidecar + cloud), `BrowserPrivacyCleanerEngine` (per-browser SQLite cookie whitelist & WAL-aware `VACUUM`), `BootPerformanceAnalyzer` (Event IDs 100–110 boot critical-path flamegraph), JunkCleaner (with weekly scheduled task), MemoryOptimizer, TurboMode (8 profiles + AI Smart Boost), GameCompression (WOF), VolumeAwareDeduplicator, HyperStoreBackgroundWorker, FullScreenGameGuard (with PID exclusion), DriverAuditor & `DriverDatabase` (Windows Event Log crash digest + AI correlation), WinGetUpdater, Debloat, StartupOptimizer, WindowsTweakEngine (92 tweaks), SmartDiskHealth, `DiskSpaceAnalyzer` (with squarified treemap layout), DuplicateFileFinder, FileShredder, `SystemRestoreEngine` (with VSS shadow copy file browser, live-disk diffing, & single-file restore). |
| 5 | `LogicFlow.Sentinel` | `LogicFlow.Sentinel.dll` | `net8.0-windows` | Yes | Security & hardening engines: DefenderHardenerEngine (16 ASR rules, CFA, PUA), PersistenceScannerEngine (WMI, Tasks, IFEO, AppInit), DnsHostsGuardEngine, NetworkScanner, VulnerabilityScanner, StartupAuditor (Authenticode + Scheduled Tasks), Remediation. |
| 6 | `LogicFlow.Storage.Engine` | `LogicFlow.Storage.Engine.dll` | `net8.0-windows;net8.0` | Yes | **HyperStore (V-Dense)** core library: `FastCdcChunker` (8–64 KB variable chunks), 256-bit `Blake3` SIMD hashing, `MinHashClusterer`, `DualTierZstdCompressor` (Hot L3 / Cold L19 + dictionary), `.lfc` container `LfcWriter`/`LfcReader`. |
| 7 | `LogicFlow.Lazarus` | `LogicFlow.Lazarus.dll` | `net8.0-windows` | Yes | Data recovery engine: `NtfsMftEngine` (NTFS Master File Table record undelete), `SectorScanner`, `FileCarver` (25+ file signatures, forensic 3-column hex dump), and `MtpBridge` device enumeration. |
| 8 | `LogicFlow.Registry` | `LogicFlow.Registry.dll` | `net8.0-windows` | Yes | `RegistryAnalyzer` & `RepairEngine`: 10-category registry scan, automatic `.reg` backup snapshots in `%LOCALAPPDATA%\LogicFlow\RegistryBackups`, 1-click rollback. |
| 9 | `LogicFlow.Native` | `LogicFlow.Native.dll` | `net8.0-windows` | Yes | Win32/NT P/Invoke bindings (`kernel32`, `ntdll`, `powrprof`, `setupapi`, `iphlpapi`, `wofutil`, SMART IOCTLs, ReFS `FSCTL_DUPLICATE_EXTENTS_TO_FILE`). |
| 10 | `OmniPulse` | `OmniPulse.dll` | `net8.0-windows` | Yes | Local hardware profiler (`SystemProfiler`) + consent-gated pseudonymous telemetry client (`PulseClient`, `ConsentStore`, `TelemetryScrubber`, `CrashGuard`). |
| 11 | `OmniCore.Engine` | `OmniCore.Engine.dll` | `net8.0` | Yes | `AutoUpdateEngine` (Ed25519 manifest signature + SHA-256 verification) and `SmartRollbackEngine`. |
| 12 | `OmniService` | `LogicFlowAgent.exe` | `net8.0-windows` | Yes | Background Windows Service (`LogicFlowAgent`) for Pro scheduled maintenance (30-min check interval) and 24-hour signed update checks. |
| 13 | `OmniLicense` | `OmniLicense.dll` | `net8.0` | Yes | Offline dual Ed25519 + RSA-2048 license token validator, 4-component WMI `HwidGenerator`, tier entitlements (`Free`, `Community`, `Pro`, `Team`). |
| 14 | `OmniLicense.Commerce` | `OmniLicense.Commerce.dll` | `net8.0` | Yes | Commercial order/catalog models and payment gateway client helpers (server-side secrets only). |
| 15 | `LogicFlow.Scraper` | `LogicFlow.Scraper.dll` | `net8.0` | Yes | Windows event log harvester and known KB/CVE issue correlator (`IssueHarvester`, `RepoAnalyzer`). |
| 16 | `LogicFlow.VoiceAgent` | `LogicFlow.VoiceAgent.dll` | `net8.0-windows` | **Yes** | Hybrid `Gemma 4 E2B` (`gemma-4-E2B-it`) + cloud voice & natural-language tool dispatcher (`VoiceAgentEngine`, `LogicFlowFunctionDispatcher` with 12 system tools). |
| 17 | `LogicFlow.Tests` | `LogicFlow.Tests.dll` | `net8.0-windows` | N/A *(Test Suite)* | Automated xUnit test suite: **54 test `.cs` files, 1,839 passing test executions** (`0` failures, `0` skipped across the full Release test suite). |

---

### 5.2 Dashboard Navigation Modules (8 Primary Modules + Settings)

1. **Dashboard** — Composite System Health Score (0–100), live hardware telemetry gauges, OmniPulse `Gemma 4 E2B` AI Command Bar, and 1-Click Maintenance.
2. **Sentinel — Security** — Microsoft Defender Enterprise Hardening (16 ASR rules, Controlled Folder Access, PUA protection), Persistence Threat Hunter (WMI, Scheduled Tasks, IFEO, AppInit_DLLs), DNS & Hosts Watchdog, Network/Port Scanner, Vulnerability Scanner, and AI & Copilot Privacy Guard.
3. **Guardian — Performance** — Multi-threaded Junk Cleaner (Temp, GPU shader caches, Windows Update cache, browser caches, Recycle Bin, weekly schedule), Memory Optimizer (Working Set trim & Standby List purge), Turbo/Game Mode (8 profiles + `Gemma 4 E2B` Smart Boost), Boot-Time Critical Path Flamegraph (Event IDs 100–110), Startup Optimizer, Windows Tweak Engine (92 safe reversible tweaks), Driver Auditor + AI Crash Correlator, WinGet Package Updater, and UWP Debloater.
4. **HyperStore — Storage Armor** — Content-defined chunking (`FastCDC`), 256-bit `BLAKE3` hashing, `MinHash` similarity clustering, Dual-Tier Zstandard `.lfc` container packaging & unpacking (`LfcWriter`/`LfcReader`), Volume-Aware Host Deduplication (ReFS Block Cloning + NTFS Hard Links with mutable-document whitelist protection), Game Vault WOF transparent compression (`XPRESS4K`/`8K`/`16K`, `LZX`) with DirectStorage bypass, Full-Screen Game Guard (`<250 ms` target / `<500 ms` hard SLA pause), and Autonomous Background Worker (Pro).
5. **Resource Monitor** — Real-time CPU, RAM, Disk I/O, and per-process resource consumption telemetry.
6. **Toolbox — Utilities** — Per-Browser SQLite Cookie/Session Whitelist & WAL-Aware Vacuum Cleaner (Chrome, Edge, Brave, Opera, Vivaldi, Firefox), Interactive Squarified Disk Space Treemap UI (`DiskSpaceAnalyzer`), VSS Shadow Copy File Browser & Single-File Restore (`SystemRestoreEngine`), Secure File Shredder (1-pass Quick, 3-pass/7-pass DoD 5220.22-M, Random PRNG), SHA-256 Duplicate File Finder, and Game Compression manager.
7. **Lazarus — Recovery** — Dual-phase data recovery combining NTFS Master File Table (`MFT`) record undelete with raw sector signature carving (`25+` file signatures), 4-mode live forensic preview (Visual, Structure, 3-Column Hex Dump, Metadata), and MTP portable device enumeration. *(Deep sector carving & MFT recovery gated to Pro).*
8. **Registry Surgeon** — 10-category Windows Registry analyzer, automatic `.reg` backup snapshots (`%LOCALAPPDATA%\LogicFlow\RegistryBackups`), 1-click rollback, WMI repository repair, and DISM/SFC system integrity repair.
9. **Settings** — General preferences, startup behavior, AI Engine (`Gemma 4 E2B` mode selector, on-demand local model download/delete), Security & Privacy (Diagnostics Sharing toggles, *View What Is Sent*, *Reset Install ID*, *Delete My Data*), License activation, and About/Third-Party Notices.

---

### 5.3 CLI Command Inventory (`lf.exe` — 10 Groups, 58 Subcommands + 6 Top-Level Aliases)

| Group | Subcommand Count | Subcommands |
| :--- | :---: | :--- |
| **`sys`** (`system`) | **15** | `status`, `telemetry-dump`, `health-check`, `trace`, `optimize-all`, `smart-health`, `apply-safe-tweaks`, `run-all-scans`, `turbo [on\|off]`, `standby-purge`, `shader-clean`, `boot-analyze`, `vss-list`, `vss-browse <shadow> [path]`, `vss-restore <shadow> <relPath> <destPath>` |
| **`reg`** | **4** | `optimize`, `rollback [backupId]`, `wmi-repair`, `repair-sfc` |
| **`sec`** | **10** | `privacy-shield [enable\|disable]`, `ai-guard [status\|disable\|enable]`, `defender-harden [status\|enable-all\|revert]`, `persistence-audit [scan\|remediate]`, `hosts-check [status\|restore-default]`, `firewall-sync`, `hardening-check`, `vuln-scan`, `disable-exposed`, `privacy-scrub` |
| **`app`** | **4** | `startup-audit`, `bloatware-purge`, `winget [list\|upgrade <id>\|upgrade-all]`, `game-compact [list\|compress\|decompress\|decay-audit\|recompact]` |
| **`net`** | **4** | `dns-flush`, `reset-winsock`, `optimize`, `tune-tcp` |
| **`driver`** | **6** | `list`, `audit`, `check`, `export <path>`, `rollback <deviceId>`, `update` |
| **`lazarus`** | **3** | `drives`, `mtp`, `carve [<driveIndex>] [--drive <n>] [--sectors <count>]` |
| **`toolbox`** | **7** | `game-compact`, `file-shredder <path> [--method quick\|dod3\|dod7\|random] --force`, `junk-clean`, `optimize-ram`, `disk-analyze <drive>`, `duplicate-scan <path>`, `browser-clean [--whitelist <domains>] [--add-domain <d>] [--remove-domain <d>] [--vacuum] [--clear-history] [--dry-run]` |
| **`agent`** | **1** | `discover` *(outputs machine-readable JSON tool schema across all 10 groups)* |
| **`store`** | **4** | `scan <path> [--min-size <bytes>]`, `dedup <path> [--dry-run] [--preserve-mutable] [--force]`, `pack <input-dir> <output.lfc> [--tier <hot\|cold>] [--dict] [--force]`, `unpack <input.lfc> <output-dir> [--no-verify] [--force]` |
| **TOTAL** | **58** | **58 unique subcommands** (`61` total group command routes, as `vss-list`, `vss-browse`, and `vss-restore` are registered under both `sys` and `toolbox`), plus **6 top-level aliases**: `boost` (`/boost`, `--boost`), `turbo`, `optimize`, `rollback`, `status`, `discover` |

**Standard CLI Exit Codes**:
- `0`: Success
- `1`: General execution error / unhandled failure
- `2`: Privilege elevation required (Administrator required), Edition / License tier required (`EDITION_REQUIRED`), or invalid command arguments (`store` group)
- `3`: Operation cancelled by user (`store` group)

---

## 6. Retired Marketing Claims (Do Not Use in Any Document or UI)

1. **Blanket "no-telemetry" slogans across all tiers**: Replaced with accurate tier-specific disclosure (*Free*: telemetry disabled; *Community*: mandatory pseudonymous telemetry condition; *Pro*: telemetry optional and OFF by default).
2. **Unqualified "anonymous" telemetry claims**: Always specify **pseudonymous** (or pseudonymous random `installId`) since events carry a rotatable 128-bit random `installId` token.
3. **Two-word spaced brand capitalization or legacy `.Tech` / `Systems LLC` entity suffixes**: Always use `DelgadoLogic` (single PascalCase word) for the brand and `Delgado Creative Enterprises LLC d/b/a DelgadoLogic` for the legal entity.
4. **Legacy pre-Windows 10 OS or 32-bit x86 compatibility claims**: LogicFlow v1.0 requires 64-bit Windows 10 (1607+) or Windows 11.
5. **Ring-0 / kernel-mode WFP callout driver or "sovereign" OS claims**: LogicFlow operates in user/admin mode (`requireAdministrator`); it does not install a ring-0 Windows Filtering Platform callout driver, and instead configures Windows Firewall rules and Microsoft Defender ASR policies via official system APIs.
6. **"Self-evolving" neural hype or silent background AI transmission**: `GemmaAiEngine` defaults to local deterministic diagnostics unless the user explicitly downloads the optional SHA-256-pinned `llama.cpp` (`b12283`, MIT) + `Gemma 4 E2B` (`gemma-4-E2B-it`, Apache-2.0) local sidecar or explicitly enables cloud inference (`AllowHybridCloudFallback = false` by default). `LogicFlow.VoiceAgent` (`NAudio` 2.2.1 MIT) ships as an opt-in push-to-talk/session voice dispatcher and never listens passively in the background.
