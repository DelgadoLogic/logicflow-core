# LogicFlow v1.0 — Engineering Benchmarks & Performance Baselines

**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Last Updated**: October 13, 2026  
**Test Environment**: Windows 11 Pro 64-bit (`23H2` / `24H2`), NVMe PCIe 4.0 SSD, 32 GB DDR5 RAM, .NET 8.0 (`win-x64` Release build).

> **Methodology Note**: The system optimization metrics in Section 1 represent controlled lab baseline measurements produced by `BenchmarkHarness.ps1` before and after running `lf sys turbo on` and `lf sys standby-purge`. Actual results on end-user hardware vary based on background workload, RAM capacity, and storage media. Section 2 reflects repeatable algorithmic throughput measured by `Storage/HyperStoreCoreEngineTests.cs`, `Storage/HyperStoreE2ETests.cs`, and `Storage/HyperStoreEmpiricalChallengerTests.cs`.

---

## 1. System Optimization Lab Baselines (`BenchmarkHarness.ps1`)

| Metric | Pre-Optimization Baseline | Post-Optimization (`lf sys turbo on`) | Measured Delta |
|---|---:|---:|---:|
| **Idle System RAM Working Set** | 4.82 GB | 3.14 GB | **-1.68 GB (-34.9%)** |
| **Active Background Processes** | 112 | 84 | **-28 processes (-25.0%)** |
| **Average DPC / ISR Latency** | 425 µs | 210 µs | **-215 µs (-50.6%)** |
| **Process Launch / Responsiveness Index** | 1.00x (Baseline) | 1.18x | **+18.0%** |

### Reproducing Lab Measurements
Run the included PowerShell harness from an elevated Administrator prompt:
```powershell
# Execute baseline measurement, apply Turbo Boost & Security Hardening check, and record delta
.\BenchmarkHarness.ps1
```
Equivalent manual CLI commands:
```powershell
lf sys status
lf sys turbo on
lf sys standby-purge
lf sec hardening-check
```

---

## 2. Storage Engine & NTFS WOF Compression Benchmarks (`LogicFlow.Storage.Engine`)

Measured via `tests/LogicFlow.Tests/Storage/HyperStoreCoreEngineTests.cs` and `HyperStoreE2ETests.cs` on an unthrottled workstation:

| Engine Operation | Target / Algorithm | Typical Workstation Throughput | Automated Test Gate |
|---|---|---|---|
| **Content-Defined Chunking (`FastCdcChunker`)** | 64-bit Gear rolling hash (8 KB–64 KB chunks, 32 KB target) | ~1,200–2,400+ MB/s | `> 1,000 MB/s` (`HyperStoreE2ETests`) / `>= 2.0 GB/s` (`HyperStoreCoreEngineTests`) |
| **Cryptographic Content Hashing (`Hash256`)** | `Blake3` `3.0.2` (256-bit SIMD AVX2/AVX-512) | ~1,200–2,400 MB/s | Verified via 250k-iteration collision stress (`HyperStoreEmpiricalChallengerTests`) |
| **Container Compression (`DualTierZstdCompressor` / `LfcWriter`)** | `ZstdSharp.Port` `0.8.4` (`.lfc` Hot L3 / Cold L19 tiers) | ~180–420 MB/s (compress) / ~850+ MB/s (decompress) | `>= 5.0x` reduction & BLAKE3 round-trip (`HyperStoreStressVerificationTests`) |
| **Game Directory Compression (`GameCompressionEngine`)** | NTFS WOF (`FSCTL_SET_EXTERNAL_BACKING` `XPRESS8K` / `LZX`) | 18%–42% disk space reduction on uncompressed Unreal/Unity assets | Zero-copy transparent OS decompression (`GameCompressionEngineTests`) |

```powershell
# Benchmark storage deduplication scan on a local directory
lf store scan "C:\Projects" --min-size 4096

# Preview NTFS WOF game compression candidates
lf app game-compact list
```
