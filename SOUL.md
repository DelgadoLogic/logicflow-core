# LogicFlow v1.0 — Product Philosophy & Engineering Ethos (`SOUL.md`)

**Entity**: Delgado Creative Enterprises LLC d/b/a **DelgadoLogic** (`https://delgadologic.tech`)  
**Product**: LogicFlow v1.0  
**Last Updated**: November 13, 2026

---

## 1. Why LogicFlow Exists

For two decades, Windows system maintenance utilities have degraded into bloatware:
- Legacy cleaners bundle adware, browser toolbars, and Electron processes that consume more RAM than they free.
- Subscription-trap utilities charge $50–$90 every year while displaying exaggerated "CRITICAL WARNING" scareware screens to frighten non-technical users.
- Opacity has replaced engineering: tools mutate registry keys without backups and silently transmit unencrypted user data without consent.

**LogicFlow v1.0** was built by **Delgado Creative Enterprises LLC d/b/a DelgadoLogic** to restore honest systems engineering to Windows 10 and Windows 11 workstation maintenance.

---

## 2. Five Non-Negotiable Engineering Commitments

### I. Native Performance & Low Overhead
LogicFlow targets `.NET 8.0` (`net8.0-windows`, `win-x64`) with native Win32/NT P/Invoke bindings (`LogicFlow.Native`), SIMD-accelerated 256-bit `BLAKE3` hashing, `FastCDC` content-defined chunking, `MinHash` similarity clustering, and Dual-Tier `Zstandard` `.lfc` compression (`LogicFlow.Storage.Engine`). The desktop UI (`LogicFlow.exe`) uses hardware-accelerated WPF (`WPF-UI 4.3.0`)—never Electron.

### II. Reversibility & Deterministic Safety
Every destructive or state-changing operation has a verifiable safety net:
- `LogicFlow.Registry` (`RepairEngine`) writes a timestamped `.reg` snapshot to `%LOCALAPPDATA%\LogicFlow\RegistryBackups\` before modifying a single registry key (`lf reg rollback`).
- `VolumeAwareDeduplicator`, `GameCompression`, and `JunkCleanerEngine` enforce strict protected-path rules, mutable-document exclusion whitelists, and `FileAttributes.ReparsePoint` symlink/junction guards.
- `FullScreenGameGuard` automatically pauses background HyperStore workers within `<250 ms` target (`<500 ms` hard SLA) whenever a full-screen game launches.

### III. Honest, Verifiable Telemetry & Pricing (`OmniPulse`)
We never use deceptive marketing slogans, blanket "no-telemetry" claims across all tiers, or false "anonymous" labels:
- Nothing is sent before first-run consent (`ConsentWindow`).
- Users choose their own transparent value exchange:
  - **Free Edition ($0, 1 Device)**: Read-only diagnostic scanning and system health preview with **telemetry disabled (`ConsentLevel.None`)**.
  - **Community Edition ($0, 1 Device, Personal Non-Commercial)**: Unlocks interactive core cleanup, optimization, registry repair, WOF game compression, and security hardening in exchange for **pseudonymous diagnostic telemetry** (`Standard` required; `Extended` baseline included outside EU/EEA/UK/CH and presented as a separate optional checkbox inside EU/EEA/UK/CH).
  - **Pro Edition ($29.99 regular / $19.99 launch promo, 3 Devices, Commercial Use)** & **Team 10-Pack ($149.00, 10 Devices)**: Unlocks all Community features plus **Background Automation** (`LogicFlowAgent`, HyperStore autonomous worker & Game Guard, Game Vault auto-compact), **Advanced Recovery** (Lazarus deep sector carving & NTFS MFT record recovery), and 24h priority support—with **telemetry optional and OFF by default (`ConsentLevel.None`)**.
- Both client (`OmniPulse.TelemetryScrubber`) and server (`lf-telemetry-ingest`) strip PII, never persist client IP addresses, enforce a **90-day raw retention limit**, and support instant self-service erasure (**Settings → Security & Privacy → Delete my data** / `POST /v1/telemetry/delete`).

### IV. Honest Technical Boundaries
We document our exact technical architecture without exaggeration:
- LogicFlow operates in user/Administrator mode (`requireAdministrator`) and configures native Windows Firewall and Microsoft Defender Attack Surface Reduction (ASR) rules via official system APIs—never claiming a ring-0 kernel WFP callout driver.
- In-app diagnostics use deterministic local heuristics (`IssueHarvester`), and `LogicFlow.VoiceAgent` ships as an opt-in voice command module backed by deterministic local command dispatch and authenticated cloud speech/LLM proxying.

### V. CLI-First Scriptability (`lf.exe`)
Every capability in the WPF Dashboard is backed by a scriptable command in `lf.exe` (**11 command groups, 58 subcommands, 6 top-level aliases**, plus `lf agent discover` for structured JSON tool introspection). Power users, sysadmins, and local automation scripts never have to click through a GUI to maintain a machine.
