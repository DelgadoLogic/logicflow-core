# LogicFlow v1.0

**High-Performance Windows 10 & Windows 11 System Optimization, Storage Deduplication, Security Hardening & Data Recovery Suite**  
**Developed by**: Delgado Creative Enterprises LLC d/b/a **DelgadoLogic** (`https://delgadologic.tech`)  
**Runtime**: .NET 8.0 (`net8.0-windows`, `win-x64`) | **Desktop GUI**: `LogicFlow.exe` (`WPF-UI 4.3.0`) | **CLI**: `lf.exe` (10 Command Groups, 58 Subcommands + 6 Aliases) | **Service**: `LogicFlowAgent.exe`

---

## 1. Overview

**LogicFlow v1.0** is a native .NET 8.0 Windows system engineering suite that unifies multi-threaded system maintenance (`LogicFlow.Guardian`), content-defined storage deduplication and archiving (`LogicFlow.Storage.Engine` — `FastCDC` + `BLAKE3` + `MinHash` + Dual-Tier `Zstandard`), transparent NTFS WOF game compression, Microsoft Defender Attack Surface Reduction (ASR) & privacy hardening (`LogicFlow.Sentinel`), dual-phase NTFS MFT and raw-sector file recovery (`LogicFlow.Lazarus`), and 10-category registry repair (`LogicFlow.Registry`) into a responsive dark-mode WPF desktop application (`LogicFlow.exe`) and scriptable CLI (`lf.exe`).

For canonical product facts, pricing, and architecture specifications, see [`Docs/FACTS.md`](Docs/FACTS.md). For our 12-document 2026 legal and privacy suite, see [`Docs/legal/README.md`](Docs/legal/README.md).

---

## 2. System Requirements

- **Client Operating System**: 64-bit (`win-x64`) **Windows 10** (Version 1607 / Build 14393 minimum; Version 2004 / Build 19041+ recommended) or **Windows 11** (all releases, including 22H2, 23H2, 24H2).
- **Server Operating System**: **Windows Server 2019** and **Windows Server 2022**.
- **Unsupported Legacy OS**: Pre-Windows 10 releases (NT 6.1 / 6.2 / 6.3 and earlier) are not supported.
- **Privileges**: Windows Administrator (`requireAdministrator`) is required for registry modifications, raw disk sector recovery (`\\.\PhysicalDriveN`), NTFS WOF compression, ReFS/NTFS extent deduplication, Defender ASR hardening, and Standby Memory List purging.
- **Runtime**: Self-contained `.NET 8.0` (`win-x64`) deployment (no external .NET runtime installation required).

---

## 3. Editions, Pricing & Transparent Telemetry Model

LogicFlow v1.0 operates on a transparent **Three-Tier Value Exchange** with **no recurring subscriptions** and **no adware**, backed by a **60-day no-questions-asked money-back guarantee**:

| Edition / SKU | Price (USD) | Devices | Commercial Use | Telemetry Policy (`OmniPulse`) | Key Entitlements & Scope |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LogicFlow Free** (`LF-FREE`) | **$0.00** | 1 Device | No (Personal only) | **None** (`ConsentLevel.None` — never queued or sent) | Read-only diagnostic scanning and system health preview across all modules; manual inspection without automated remediation. |
| **LogicFlow Community** (`LF-COMM`) | **$0.00** | 1 Device | No (Personal non-commercial only) | **Mandatory Pseudonymous Telemetry Condition** (`Standard` required; `Extended` unchecked opt-in in **EU/EEA, UK, Switzerland, Canada, Brazil, Japan, South Korea, India**; pre-selected by default and uncheckable anytime in **US, Mexico, Australia/NZ, Rest of world**). Declining or withdrawing `Standard` drops to **Free**. | Unlocks interactive core cleanup, optimization, registry repair with automatic `.reg` backup, WOF game compression, and security hardening for personal use. |
| **LogicFlow Pro** (`LF-PRO`) | **$29.99** one-time<br>*(Launch Promo: **$19.99** for 60 days; **14-day Pro Trial** included)* | **3 Devices** | **Yes** | **Optional & OFF by default** (`ConsentLevel.None` unless user opts in via Settings) | Everything in Community + **Background Automation** (`LogicFlowAgent` scheduled scans/auto-fix, HyperStore autonomous worker & Game Guard, Game Vault auto-compact), **Advanced Recovery** (Lazarus deep sector carving & NTFS MFT record recovery), **All v1.x Updates Included**, and **24h Priority Support**. Offline dual **Ed25519 + RSA-2048** signed tokens + Zero-Hostage Revert. |
| **Extra Seat Add-On** (`LF-SEAT`) | **$9.99** one-time | +1 Device | Matches Pro license | Matches Pro license | Adds 1 additional device activation seat to an existing LogicFlow Pro license. |
| **LogicFlow Team 10-Pack** (`LF-TEAM10`) | **$149.00** one-time | **10 Devices** | **Yes** (Enterprise & fleet use) | **Optional & OFF by default** (Group Policy `TelemetryDisabled=1` supported) | All Pro entitlements for up to 10 machines, CLI headless deployment (`lf.exe --json`), and priority 24h support. |

### Verifiable Telemetry Transparency (`OmniPulse`)
- Nothing is queued or sent during installation or on the splash screen before first-run consent (`ConsentWindow`).
- All telemetry is **pseudonymous** (keyed to a rotatable 128-bit random `installId` stored in `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`, never derived from hardware serials or linked to license `HWID`).
- Client (`OmniPulse.TelemetryScrubber`) and server (`lf-telemetry-ingest` at `https://api.delgadologic.tech/v1/telemetry`) enforce dual-layer PII scrubbing, never persist client IP addresses, enforce a **90-day raw retention limit**, and support instant self-service erasure via **Settings → Security & Privacy → Delete my data** (`POST /v1/telemetry/delete`).
- See [`Docs/legal/telemetry-disclosure.md`](Docs/legal/telemetry-disclosure.md), [`Docs/TELEMETRY_CLIENT.md`](Docs/TELEMETRY_CLIENT.md), and [`Docs/TELEMETRY_API.md`](Docs/TELEMETRY_API.md) for the complete specification.

---

## 4. Core Architecture (`LogicFlow.sln` — 17 Projects)

```text
Products/LogicFlow/
├── src/
│   ├── DelgadoLogic.Core/            # Shared runtime contracts, CloudLicenseBridge, SharedUpdateEngine
│   ├── LogicFlow.Dashboard/          # WPF desktop GUI (LogicFlow.exe, 8 modules + Settings, ConsentWindow)
│   ├── LogicFlow.CLI/                # Command-line interface (lf.exe: 10 groups, 58 subcommands + 6 aliases)
│   ├── LogicFlow.Guardian/           # Performance, cleanup, WOF compression, deduplication, GemmaAiEngine & 92 tweaks
│   ├── LogicFlow.Sentinel/           # Defender 16-rule ASR hardening, persistence hunter, DNS/hosts & privacy guard
│   ├── LogicFlow.Storage.Engine/     # HyperStore: FastCdcChunker, Blake3, MinHashClusterer, DualTierZstd .lfc
│   ├── LogicFlow.Lazarus/            # Dual-phase recovery: NtfsMftEngine + 25-signature FileCarver + 3-col hex dump
│   ├── LogicFlow.Registry/           # 10-category RegistryAnalyzer & RepairEngine with automatic .reg backups
│   ├── LogicFlow.Native/             # Win32/NT P/Invoke bindings (kernel32, ntdll, powrprof, wofutil, SMART, ReFS)
│   ├── OmniPulse/                    # SystemProfiler + consent-gated pseudonymous telemetry client & scrubber
│   ├── OmniCore.Engine/              # AutoUpdateEngine (canonical Ed25519 + SHA-256 verification) & SmartRollbackEngine
│   ├── OmniService/                  # Windows Service (LogicFlowAgent.exe) for Pro scheduled maintenance
│   ├── OmniLicense/                  # Offline dual Ed25519 + RSA-2048 license validator, 14-day TrialManager & HwidGenerator
│   ├── OmniLicense.Commerce/         # Commercial catalog/order DTOs & payment gateway client helpers
│   ├── LogicFlow.Scraper/            # Windows event log harvester & known KB/CVE issue correlator
│   └── LogicFlow.VoiceAgent/         # Opt-in voice & natural-language tool dispatcher (12 system tools, NAudio MIT)
└── tests/
    └── LogicFlow.Tests/              # 54 test .cs files executing 1,817 automated xUnit test runs
```

---

## 5. The 8 Desktop Dashboard Modules (+ Settings)

1. **Dashboard**: Composite System Health Score (`0–100`), live hardware telemetry gauges, and 1-Click Maintenance.
2. **Sentinel — Security**: Microsoft Defender Enterprise Hardening (16 ASR rules, Controlled Folder Access, PUA protection), Persistence Threat Hunter (WMI, Scheduled Tasks, IFEO, `AppInit_DLLs`), DNS & Hosts Watchdog, Network/Port Scanner, Vulnerability Scanner, and AI & Copilot Privacy Guard.
3. **Guardian — Performance**: Multi-threaded Junk Cleaner (Temp, GPU shader caches, Windows Update cache, browser caches for Chrome/Edge/Firefox/Brave/Opera, Recycle Bin), Memory Optimizer (Working Set trim & Standby List purge), Turbo/Game Mode, Startup Optimizer, Windows Tweak Engine (92 safe reversible tweaks), Driver Auditor, WinGet Package Updater, and UWP Debloater.
4. **HyperStore — Storage Armor**: Content-defined chunking (`FastCDC`), 256-bit `BLAKE3` hashing, `MinHash` similarity clustering, Dual-Tier Zstandard `.lfc` container packaging, Volume-Aware Host Deduplication (ReFS Block Cloning + NTFS Hard Links with mutable-document whitelist protection), Game Vault WOF transparent compression (`XPRESS4K`/`8K`/`16K`, `LZX`) with DirectStorage bypass, Full-Screen Game Guard (`<250 ms` target / `<500 ms` hard SLA pause), and Autonomous Background Worker (Pro).
5. **Resource Monitor**: Real-time CPU, RAM, Disk I/O, and per-process resource consumption telemetry.
6. **Toolbox — Utilities**: Secure File Shredder (1-pass Quick, 3-pass/7-pass DoD 5220.22-M, Random PRNG), Disk Space Analyzer, SHA-256 Duplicate File Finder, Game Compression manager, and System Restore point manager.
7. **Lazarus — Recovery**: Dual-phase data recovery combining NTFS Master File Table (`MFT`) record undelete with raw sector signature carving (`25+` file signatures), 4-mode live forensic preview (Visual, Structure, 3-Column Hex Dump, Metadata), and MTP portable device enumeration. *(Deep sector carving & MFT recovery gated to Pro).*
8. **Registry Surgeon**: 10-category Windows Registry analyzer, automatic `.reg` backup snapshots (`%LOCALAPPDATA%\LogicFlow\RegistryBackups`), 1-click rollback, WMI repository repair, and DISM/SFC system integrity repair.
9. **Settings**: General preferences, startup/tray behavior, Security & Privacy (Diagnostics Sharing toggles, *View what is sent*, *Reset install ID*, *Delete my data*), License activation, and About/Third-Party Notices.

---

## 6. Command-Line Interface (`lf.exe`) Quick Reference

`lf.exe` exposes **10 command groups**, **58 unique subcommands** (`61` total group command routes), and **6 top-level aliases** (`boost`, `turbo`, `optimize`, `rollback`, `status`, `discover`):

```powershell
# System & Turbo Optimization
lf sys status
lf sys optimize-all
lf sys turbo on
lf sys standby-purge
lf sys shader-clean

# HyperStore Deduplication & .lfc Container Archiving (FastCDC + BLAKE3 + Zstd)
lf store scan "C:\Projects" --min-size 4096
lf store dedup "C:\Projects" --dry-run --preserve-mutable
lf store pack "C:\Projects\Assets" "C:\Backups\assets.lfc" --tier cold --dict
lf store unpack "C:\Backups\assets.lfc" "C:\Restored\Assets"

# Game Vault WOF Compression
lf app game-compact list
lf app game-compact compress "C:\Program Files (x86)\Steam\steamapps\common\MyGame"
lf app game-compact decay-audit "C:\Program Files (x86)\Steam\steamapps\common\MyGame"
lf app game-compact recompact "C:\Program Files (x86)\Steam\steamapps\common\MyGame"

# Registry Surgeon & Safety Rollback
lf reg optimize
lf reg rollback

# Sentinel Security & Privacy Hardening
lf sec hardening-check
lf sec privacy-shield enable
lf sec ai-guard disable
lf sec defender-harden enable-all
lf sec persistence-audit scan

# Lazarus Recovery
lf lazarus drives
lf lazarus carve 0 --sectors 2048

# Machine-Readable JSON Tool Schema for Local Automation
lf agent discover
```

See [`Docs/API.md`](Docs/API.md) for the complete CLI and C# assembly reference.

---

## 7. Building & Running Tests

```powershell
# Build entire solution in Release mode
dotnet build Products/LogicFlow/LogicFlow.sln -c Release

# Run the 1,817 automated unit & integration test executions (54 test files)
dotnet test Products/LogicFlow/tests/LogicFlow.Tests/LogicFlow.Tests.csproj -c Release
```

---

## 8. Documentation Index

- **Canonical Fact Sheet**: [`Docs/FACTS.md`](Docs/FACTS.md)
- **API & CLI Reference**: [`Docs/API.md`](Docs/API.md)
- **Feature Completeness Assessment**: [`Docs/FEATURES_ASSESSMENT.md`](Docs/FEATURES_ASSESSMENT.md)
- **Commercial Pricing & MoR Rationale**: [`Docs/PRICING_RATIONALE.md`](Docs/PRICING_RATIONALE.md)
- **Production Launch Checklist**: [`Docs/LAUNCH_CHECKLIST.md`](Docs/LAUNCH_CHECKLIST.md)
- **Telemetry Client & Ingest API**: [`Docs/TELEMETRY_CLIENT.md`](Docs/TELEMETRY_CLIENT.md) | [`Docs/TELEMETRY_API.md`](Docs/TELEMETRY_API.md)
- **Legal & Privacy Suite**: [`Docs/legal/README.md`](Docs/legal/README.md) (`eula.md`, `terms.md`, `privacy.md`, `refund.md`, `telemetry-disclosure.md`, `security-policy.md`, `third-party-notices.md`, etc.)

---

*Copyright © 2026 Delgado Creative Enterprises LLC d/b/a DelgadoLogic. All rights reserved.*
