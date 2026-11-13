# LogicFlow API Reference

## Architecture

LogicFlow is built as a modular .NET 8 solution with 12 independent projects:

```
OmniCore.Engine      → AutoUpdateEngine orchestrating sovereign updates and signature checks
LogicFlow.Dashboard  → Premium WPF glassmorphism UI
LogicFlow.Guardian   → Performance optimization, junk cleaning, and CPU/GPU scheduling
LogicFlow.Lazarus    → Deep-sector block data recovery and file carving
LogicFlow.Sentinel   → Vulnerability scanner, network port auditor, and privacy scrubbing
OmniLicense          → Offline RSA-2048 license engine binding to HWID
OmniLicense.Commerce → PayPal Pro transaction fulfillment and webhook bridge
OmniService          → Windows background service handling updates and diagnostics
LogicFlow.Native     → Direct Win32 P/Invoke layer for disk/registry and sector operations
OmniPulse            → Real-time telemetry monitoring via direct WMI and kernel memory APIs
LogicFlow.Registry   → Registry surgeon with automatic backups and rollback
LogicFlow.Scraper    → Automated issue harvester tracking KB bugs, CVEs, and event logs
```

## Core Services

### EventTriggerService
WMI event subscription manager. Monitors process creation, service changes, USB insertion.
```csharp
var triggers = new EventTriggerService(logger);
triggers.RegisterDefaultEvents();
triggers.OnSystemEvent += (s, e) => Console.WriteLine($"Event: {e.EventName}");
```

### SystemProfiler
Hardware fingerprinting and real-time system telemetry.
```csharp
var profiler = new SystemProfiler(logger);
var snapshot = profiler.CaptureSnapshot();
// snapshot.Cpu, .Memory, .Gpu, .Os, .Disks, .Motherboard
```

## Module APIs

### Sentinel
```csharp
var scanner = new VulnerabilityScanner(logger);
var result = await scanner.ScanAsync();
// result.Vulnerabilities — known problematic KBs
// result.ExposedServices — risky running services
// result.TelemetryStatus — current telemetry level

var scrubber = new PrivacyScrubber(logger);
var report = scrubber.Scrub();
// report.TotalBytesCleared, .TotalFilesCleared
```

### Guardian
```csharp
var drivers = new SmartDriverEngine(logger);
var reports = drivers.ScanDrivers();
// reports[i].Status = Healthy|Outdated|Missing|Unsigned

var debloat = new DebloatEngine(logger);
var bloatware = debloat.ScanBloatware();

var startup = new StartupOptimizer(logger);
var items = startup.AnalyzeStartupItems();
// items sorted by ImpactScore (1-10)

var power = new PowerPlanAutomation(logger);
bool hasNpu = power.HasNeuralProcessor();
```

### Lazarus
```csharp
var scanner = new SectorScanner(logger);
scanner.OpenDrive(0); // PhysicalDrive0
await foreach (var chunk in scanner.ScanRangeAsync(0, 1000000))
{
    var carver = new FileCarver(logger);
    var headers = carver.ScanBuffer(chunk.Data, chunk.ByteOffset);
    // headers[i].Extension, .FileType, .ByteOffset
}

var mtp = new MtpBridge(logger);
var devices = mtp.EnumerateDevices();
```

### Registry
```csharp
var analyzer = new RegistryAnalyzer(logger);
var result = analyzer.Scan();
// result.OrphanedSoftwareKeys, .BrokenFileAssociations,
// .InvalidPaths, .ObsoleteRunEntries
```

### Licensing
```csharp
var hwid = new HwidGenerator().GenerateHwid();
var validator = new RsaLicenseValidator(logger, publicKeyXml);
var validation = validator.Validate(new LicenseToken(payload, signature));

var trial = new TrialManager(logger, appDataPath);
var status = trial.GetStatus();
// status.IsActive, .DaysRemaining
```

### Commerce
```csharp
var service = new PayPalFulfillmentService(httpClient, logger, config);
// Validate a completed PayPal transaction and generate a signed license key
var licenseKey = await service.FulfillOrderAsync(payPalTransactionId, userHwid);
```

## Pricing Tiers

| Tier | Price | Model | Devices |
|------|-------|-------|---------|
| Free | $0 | Diagnostics (Scan system manually, see issues, pay to fix) | 1 |
| Community | $0 | Telemetry Opt-in (Full Pro access in exchange for anonymous system error reports) | 1 |
| Pro | $29.99 | One-time Payment (All 12 modules unlocked, lifetime sovereign updates) | 1 |
| Multi-seat | Bulk | MULTIPC code (Multi-seat discounts applied at checkout) | Custom |
