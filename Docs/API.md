# LogicFlow v1.0 — CLI (`lf.exe`) & C# Assembly Reference

**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic (`https://delgadologic.tech`)  
**Executable**: `lf.exe` (`src/LogicFlow.CLI/LogicFlow.CLI.csproj`)  
**Target Runtime**: `.NET 8.0` (`net8.0-windows`, `win-x64`)  
**Last Updated**: October 13, 2026

---

## 1. CLI Overview (`lf.exe`)

`lf.exe` is the native command-line interface for LogicFlow v1.0. It exposes **10 command groups**, **58 unique subcommands** (`61` total group routes), and **6 top-level aliases** (`boost`, `turbo`, `optimize`, `rollback`, `status`, `discover`), with global flags `--json`, `--silent`, `--force`, and `--elevate`.

### 1.1 Standard Exit Codes
| Exit Code | Meaning |
| ---: | :--- |
| `0` | Success |
| `1` | General execution error or unhandled failure |
| `2` | Privilege elevation required (`requireAdministrator`) or invalid command arguments (`store` group) |
| `3` | Operation cancelled by user (`store` group) |

### 1.2 Top-Level Aliases (6)
```powershell
lf boost        # Alias for quick system optimization (also supports /boost, --boost)
lf turbo        # Alias for `lf sys turbo on`
lf optimize     # Alias for `lf reg optimize`
lf rollback     # Alias for `lf reg rollback`
lf status       # Alias for `lf sys status`
lf discover     # Alias for `lf agent discover` (outputs machine-readable JSON tool schema)
```

---

## 2. Complete Command Group Reference (10 Groups, 58 Subcommands)

### 2.1 Group 1: `sys` — System & Memory Optimization (15 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf sys status` | Displays OS build, CPU/RAM working-set metrics, active edition tier, and System Health Score (`0–100`). |
| `lf sys telemetry-dump` | Dumps current hardware performance counters (`SystemProfiler`) and local telemetry consent state (`ConsentLevel`, `installId`). |
| `lf sys health-check` | Runs a non-destructive diagnostic check across disk space, memory pressure, startup items, and services. |
| `lf sys trace` | Captures a short diagnostic trace of top CPU/RAM-consuming processes and DPC latency indicators. |
| `lf sys optimize-all` | Runs full safe temp cleanup, working-set trim, and standby memory purge. |
| `lf sys smart-health` | Queries physical disk S.M.A.R.T. health status (`PredictFailure`, temperature, wear indicators) via WMI/Storage IOCTLs. |
| `lf sys apply-safe-tweaks` | Applies reversible responsiveness tweaks via `WindowsTweakEngine`. |
| `lf sys run-all-scans` | Executes junk cleaner scan, registry scan, startup audit, and security hardening check in sequence. |
| `lf sys turbo [on\|off]` | Activates or deactivates `TurboMode` (High-Performance power scheme, standby purge, non-essential background service suspension). |
| `lf sys standby-purge` | Purges the Windows Standby Memory List via `NtSetSystemInformation` (requires Administrator). |
| `lf sys shader-clean` | Cleans DirectX (`D3DSCache`), NVIDIA (`DXCache`/`GLCache`), and AMD (`DxCache`) compiled shader caches. |

---

### 2.2 Group 2: `reg` — Registry Surgeon & System Integrity (4 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf reg optimize` | Scans and repairs orphaned registry references across 10 categories after saving a timestamped `.reg` snapshot to `%LOCALAPPDATA%\LogicFlow\RegistryBackups\`. |
| `lf reg rollback [backupId]` | Restores registry keys from the most recent `.reg` backup snapshot (or a specified `backupId`). |
| `lf reg wmi-repair` | Verifies and repairs the Windows Management Instrumentation (`winmgmt`) repository. |
| `lf reg repair-sfc` | Invokes Windows System File Checker (`sfc /scannow`) and DISM component store health checks. |

---

### 2.3 Group 3: `sec` — Sentinel Security & Privacy Hardening (10 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf sec privacy-shield [enable\|disable]` | Applies or reverts Windows OS diagnostic telemetry, advertising ID, and activity history policy locks. |
| `lf sec ai-guard [status\|disable\|enable]` | Audits, disables, or re-enables Windows Recall (`DisableAIDataAnalysis`) and Windows Copilot (`TurnOffWindowsCopilot`) policies. |
| `lf sec defender-harden [status\|enable-all\|revert]` | Audits, enables, or reverts 16 Microsoft Defender Attack Surface Reduction (ASR) rules, PUA protection, and Controlled Folder Access (`DefenderHardenerEngine`). |
| `lf sec persistence-audit [scan\|remediate]` | Scans WMI subscriptions, Scheduled Tasks, IFEO, `AppInit_DLLs`, and Registry Run keys for suspicious persistence vectors (`PersistenceScannerEngine`). |
| `lf sec hosts-check [status\|restore-default]` | Audits `C:\Windows\System32\drivers\etc\hosts` for hijacked entries or restores a clean baseline (`DnsHostsGuardEngine`). |
| `lf sec firewall-sync` | Synchronizes outbound Windows Firewall rules (`netsh advfirewall`) blocking known OS telemetry endpoints. |
| `lf sec hardening-check` | Computes an overall Security Hardening Score across UAC, Secure Boot, HVCI/VBS, Defender ASR, SMBv1, and RDP exposure. |
| `lf sec vuln-scan` | Scans installed software and OS configuration for known CVE/KB vulnerabilities (`VulnerabilityScanner`). |
| `lf sec disable-exposed` | Disables risky exposed local services (Remote Registry, SMBv1, Telnet, UPnP host). |
| `lf sec privacy-scrub` | Scrubs Windows Recent Files, Jump Lists, Explorer Run MRU, and clipboard history. |

---

### 2.4 Group 4: `app` — Applications & Game Vault WOF Compression (4 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf app startup-audit` | Lists and scores startup applications by boot impact (`StartupOptimizer` / `StartupAuditor`). |
| `lf app bloatware-purge` | Removes pre-installed consumer UWP/Appx bloatware packages while preserving Xbox Gaming Services and Microsoft Store (`Debloat`). |
| `lf app winget [list\|upgrade <id>\|upgrade-all]` | Wraps `winget` to list outdated packages (`list`), upgrade a specific package (`upgrade <id>`), or upgrade all desktop applications silently (`upgrade-all`, `WinGetUpdaterEngine`). |
| `lf app game-compact [list\|compress\|decompress\|decay-audit\|recompact] [<path>]` | Manages transparent Windows Overlay Filter (`wofutil` / `FSCTL_SET_EXTERNAL_BACKING`) compression (`XPRESS4K`/`8K`/`16K`, `LZX`) with DirectStorage bypass, cluster decay auditing (`decay-audit`), and selective recompaction (`recompact`). |

---

### 2.5 Group 5: `net` — Network Stack Optimization (4 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf net dns-flush` | Flushes the Windows DNS resolver cache (`ipconfig /flushdns`). |
| `lf net reset-winsock` | Resets the Winsock catalog and TCP/IP stack (`netsh winsock reset` / `netsh int ip reset`). |
| `lf net optimize` | Applies low-latency adapter registry settings and sets privacy-first DNS resolvers (Cloudflare `1.1.1.1` / Quad9 `9.9.9.9`). |
| `lf net tune-tcp` | Configures TCP Receive Window Auto-Tuning, RSS, ECN capability, and Nagle's algorithm (`TcpAckFrequency` / `TcpNoDelay`). |

---

### 2.6 Group 6: `driver` — PnP Driver Auditor & Backup (6 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf driver list` | Enumerates installed third-party PnP drivers via WMI (`Win32_PnPSignedDriver`). |
| `lf driver audit` | Flags unsigned drivers, legacy kernel drivers, and devices reporting nonzero `ConfigManagerErrorCode` (`DriverAuditor`). |
| `lf driver check` | Compares installed GPU/chipset/network driver versions against the reference compatibility index. |
| `lf driver export <path>` | Exports all third-party drivers to `<path>` via `pnputil /export-driver *`. |
| `lf driver rollback <deviceId>` | Rolls back a problematic driver for the specified PnP `<deviceId>`. |
| `lf driver update` | Queries available WHQL driver updates for flagged hardware IDs. |

---

### 2.7 Group 7: `lazarus` — NTFS MFT & Raw Sector Data Recovery (3 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf lazarus drives` | Lists physical disks (`\\.\PhysicalDriveN`) and logical volumes (`\\.\C:`) available for recovery scanning. |
| `lf lazarus mtp` | Enumerates connected MTP portable devices (`MtpBridge`) for media recovery inspection. |
| `lf lazarus carve [<driveIndex>] [--drive <driveIndex>] [--sectors <sectorCount>]` | Performs sector-aligned raw reads on `\\.\PhysicalDrive<driveIndex>` (default `0`, default `2048` sectors) and carves deleted files across 25+ magic-byte signatures (`SectorScanner` & `FileCarver`; gated to Pro). |

---

### 2.8 Group 8: `toolbox` — Disk, File & Memory Utilities (6 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf toolbox game-compact` | Shortcut to the interactive Game Vault WOF compression workflow. |
| `lf toolbox file-shredder <path> [--method <quick\|dod3\|dod7\|random>] --force` | Securely overwrites `<path>` (1-pass `quick`, 3-pass `dod3`, 7-pass `dod7` DoD 5220.22-M, or `random` PRNG) before unlinking (`FileShredder`; requires `--force`). |
| `lf toolbox junk-clean` | Performs a fast multi-threaded sweep of temporary directories, shader caches, browser caches, and Recycle Bin (`JunkCleanerEngine`). |
| `lf toolbox optimize-ram` | Trims non-essential process working sets via `EmptyWorkingSet` (`MemoryOptimizer`). |
| `lf toolbox disk-analyze <drive>` | Computes directory tree size breakdown and largest file hotspots on `<drive>` (`DiskSpaceAnalyzer`). |
| `lf toolbox duplicate-scan <path>` | Identifies byte-identical duplicate files under `<path>` using size pre-filtering + SHA-256 hashing (`DuplicateFileFinder`). |

---

### 2.9 Group 9: `agent` — Automation & Tool Discovery (1 Subcommand)
| Command | Description |
| :--- | :--- |
| `lf agent discover` | Outputs a machine-readable JSON manifest of all 10 CLI groups, 58 subcommands, parameters, and required privilege levels for local scripts and automation harnesses. |

---

### 2.10 Group 10: `store` — HyperStore (`FastCDC` + `BLAKE3` + `Zstandard`) Engine (4 Subcommands)
| Command | Description |
| :--- | :--- |
| `lf store scan <path> [--min-size <bytes>]` | Scans `<path>` using `FastCdcChunker` (8–64 KB chunks) and 256-bit `Blake3` hashing to report exact chunk-level and file-level deduplication savings. |
| `lf store dedup <path> [--dry-run] [--preserve-mutable] [--force]` | Deduplicates identical extents/files in `<path>` via `VolumeAwareDeduplicator` (ReFS `FSCTL_DUPLICATE_EXTENTS_TO_FILE` block cloning or NTFS hard links) while protecting mutable document formats. |
| `lf store pack <input-dir> <output.lfc> [--tier <hot\|cold>] [--dict] [--force]` | Packs `<input-dir>` into a deduplicated, Dual-Tier Zstandard-compressed `.lfc` container (`LfcWriter`, Hot L3 / Cold L19 + optional trained dictionary) with `MinHashClusterer` ordering and `BLAKE3` verification. |
| `lf store unpack <input.lfc> <output-dir> [--no-verify] [--force]` | Extracts an `.lfc` archive into `<output-dir>` via `LfcReader`, verifying every reconstructed chunk against its 256-bit `BLAKE3` digest unless `--no-verify` is specified. |

---

## 3. Solution Assembly Reference (`LogicFlow.sln` — 17 Projects)

| Assembly | Project Path | Key Classes & Contracts |
| :--- | :--- | :--- |
| `DelgadoLogic.Core.dll` | `src/DelgadoLogic.Core` | `CloudLicenseBridge`, `SharedUpdateEngine`, core product metadata. |
| `LogicFlow.exe` | `src/LogicFlow.Dashboard` | `MainWindow`, `ConsentWindow`, `SettingsManager`, `TrayIconManager`. |
| `lf.exe` | `src/LogicFlow.CLI` | `Program`, `StoreCommands`, 10 command groups / 58 subcommands. |
| `LogicFlow.Guardian.dll` | `src/LogicFlow.Guardian` | `JunkCleanerEngine`, `MemoryOptimizer`, `TurboMode`, `GameCompressionEngine`, `VolumeAwareDeduplicator`, `HyperStoreBackgroundWorker`, `FullScreenGameGuard`, `WindowsTweakEngine`, `DriverAuditor`, `WinGetUpdaterEngine`, `FileShredder`. |
| `LogicFlow.Sentinel.dll` | `src/LogicFlow.Sentinel` | `DefenderHardenerEngine`, `PersistenceScannerEngine`, `DnsHostsGuardEngine`, `NetworkScanner`, `VulnerabilityScanner`, `StartupAuditor`. |
| `LogicFlow.Storage.Engine.dll` | `src/LogicFlow.Storage.Engine` | `FastCdcChunker`, `Hash256` (`Blake3`), `MinHashClusterer`, `DualTierZstdCompressor`, `LfcWriter`, `LfcReader`. |
| `LogicFlow.Lazarus.dll` | `src/LogicFlow.Lazarus` | `LazarusEngine`, `NtfsMftEngine`, `SectorScanner`, `FileCarver`, `MtpBridge`. |
| `LogicFlow.Registry.dll` | `src/LogicFlow.Registry` | `RegistryAnalyzer`, `RepairEngine` (`.reg` backup & rollback). |
| `LogicFlow.Native.dll` | `src/LogicFlow.Native` | Win32/NT P/Invoke declarations (`kernel32`, `ntdll`, `powrprof`, `wofutil`, SMART IOCTLs, ReFS ioctls). |
| `OmniPulse.dll` | `src/OmniPulse` | `SystemProfiler`, `PulseClient`, `ConsentStore`, `TelemetryScrubber`, `CrashGuard`. |
| `OmniCore.Engine.dll` | `src/OmniCore.Engine` | `AutoUpdateEngine` (Ed25519 + SHA-256), `SmartRollbackEngine`. |
| `LogicFlowAgent.exe` | `src/OmniService` | Windows Service background worker for Pro scheduled maintenance and update checks. |
| `OmniLicense.dll` | `src/OmniLicense` | `LicenseEngine`, `HwidGenerator` (4-component WMI SHA-256 Base64), `LicenseTier`. |
| `OmniLicense.Commerce.dll` | `src/OmniLicense.Commerce` | `CommerceEngine`, catalog/order DTOs. |
| `LogicFlow.Scraper.dll` | `src/LogicFlow.Scraper` | `IssueHarvester`, `RepoAnalyzer`. |
| `LogicFlow.VoiceAgent.dll` | `src/LogicFlow.VoiceAgent` | Opt-in hybrid `Gemma 4 E2B` + cloud voice & natural-language tool dispatcher (12 system tools). |
| `LogicFlow.Tests.dll` | `tests/LogicFlow.Tests` | 54 test `.cs` files, 1,839 automated xUnit test runs. |
