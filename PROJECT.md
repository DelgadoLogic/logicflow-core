# Project: LogicFlow Upgrades & Redesign

## Architecture
LogicFlow is a modular system utilities suite built on .NET 8. The application is structured around a central command interface and graphical dashboard delegating to independent C# engines:
- **OmniCore & DelgadoLogic.Core**: Manifest validation, licensing, and auto-updates.
- **LogicFlow.Guardian**: System optimization, temporary file cleaning, and CPU/GPU resource scheduling.
- **LogicFlow.Sentinel**: Port scanning, network adapter analysis, and privacy scrubbing.
- **LogicFlow.Registry**: System registry integrity audits and repairs.
- **LogicFlow.Lazarus**: Low-level disk sector block recovery and file carving.

## Code Layout
- `/src` — C# .NET 8 source code projects
  - `/src/DelgadoLogic.Core` — Shared core library
  - `/src/LogicFlow.Guardian` — System cleanup and resource optimization
  - `/src/LogicFlow.Sentinel` — Port scanner and network audit
  - `/src/LogicFlow.Registry` — Registry scanning and surgery
  - `/src/LogicFlow.Dashboard` — WPF Dashboard UI
- `/public` — Web distribution assets
  - `/public/redesign` — Premium visual and UI/UX redesign web prototype
- `/Docs` — Project documentation and strategic playbooks
  - `/Docs/refactoring_roadmap.md` — C# software architecture refactoring plan
  - `/Docs/marketing_playbook.md` — Go-to-market and monetization strategy

## Milestones
| # | Name | Scope | Dependencies | Status | Conv ID |
|---|------|-------|-------------|--------|---------|
| 1 | C# Codebase Refactoring Analysis | Deep inspection of 12 C# modules for performance bottlenecks | None | DONE | fd82fca2-ab35-4859-8850-4d6e78592b76 |
| 2 | Technical Refactoring Roadmap | Generate `Docs/refactoring_roadmap.md` outlining optimizations | M1 | DONE | 4ca2f99e-bf15-41d7-984a-4549649ceef1 |
| 3 | Go-to-Market Marketing Playbook | Formulate strategy and save to `Docs/marketing_playbook.md` | None | DONE | affe78e7-4b14-416a-8dc0-fee5fde0d3be |
| 4 | Premium Dashboard Web Prototype | Build premium HTML/CSS/JS interface in `public/redesign/` | None | DONE | 8e92881b-8647-4585-a178-e99d745b2340 |
| 5 | final_milestone | Final E2E checks and artifact compliance validation | M2, M3, M4 | DONE | e8f1bc7d-a3a2-4e4b-a5fa-41b44a748c32 |
| 6 | Dashboard UI Overhaul | Refactor WPF columns, resolve background bleed, layout header grids, enrich settings | None | DONE | 7dc512a7-fce7-47de-bbba-e715e683e357 |

## Interface Contracts
### LogicFlow.Guardian ↔ LogicFlow.Dashboard / CLI
- `JunkCleanerEngine.Scan()`: Returns lists of `JunkScanResult` detailing paths, sizes, and file types without making disk changes.
- `JunkCleanerEngine.Clean(List<JunkScanResult>)`: Performs asynchronous deletion, returning `CleanResult` with counts of deleted/failed files and freed bytes.
- `TurboMode.Activate(TurboProfile)`: Disables background bloat, swaps power plans, sets scheduling priority, and returns a detailed `TurboResult`.
- `TurboMode.Deactivate()`: Reverts system settings to their original state and returns restoration status.

### LogicFlow.Sentinel ↔ LogicFlow.Dashboard / CLI
- `NetworkScanner.FullScanAsync(CancellationToken)`: Triggers parallel port scans, ARP discoveries, DNS checks, and firewall audits. Returns `NetworkScanReport` with calculated risk scores.
