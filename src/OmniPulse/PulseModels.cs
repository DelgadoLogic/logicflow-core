// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — Telemetry Data Models
// Anonymous, privacy-first data structures for crash reports, usage stats,
// and system health digests. No PII is ever collected.
// ─────────────────────────────────────────────────────────────────────────────

using System.Text.Json.Serialization;

namespace OmniPulse;

// ─── User Consent ─────────────────────────────────────────────────────────

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TelemetryLevel
{
    /// <summary>Nothing is sent. Fully offline.</summary>
    Off = 0,
    /// <summary>App crashes + minimal system specs only.</summary>
    CrashesOnly = 1,
    /// <summary>Crashes + performance + feature usage + optimization results.</summary>
    Full = 2
}

// ─── Pulse Event Envelope ─────────────────────────────────────────────────

/// <summary>
/// Every telemetry record is wrapped in this envelope.
/// </summary>
public sealed class PulseEvent
{
    public string EventId { get; init; } = Guid.NewGuid().ToString("N");
    public string EventType { get; init; } = "";
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string AppVersion { get; init; } = "";
    public string InstallId { get; init; } = "";
    public object? Payload { get; init; }
}

// ─── Crash Report ─────────────────────────────────────────────────────────

/// <summary>
/// Sent immediately when the app crashes (unhandled exception).
/// </summary>
public sealed class CrashReport
{
    public string ExceptionType { get; init; } = "";
    public string Message { get; init; } = "";
    public string StackTrace { get; init; } = "";
    public string? InnerExceptionType { get; init; }
    public string? InnerMessage { get; init; }
    public string ActivePage { get; init; } = "";
    public string LastAction { get; init; } = "";
    public long MemoryUsageMB { get; init; }
    public TimeSpan Uptime { get; init; }
    public SystemProfile? System { get; init; }

    /// <summary>
    /// Snapshot of installed drivers at crash time.
    /// Enables AI crash-to-driver correlation on the server.
    /// </summary>
    public DriverFingerprint? Drivers { get; init; }

    // ── Enhanced crash context ─────────────────────────────────────
    /// <summary>Total committed memory at crash time (helps distinguish OOM vs driver crash).</summary>
    public long CommittedMemoryMB { get; init; }
    /// <summary>Available physical memory at crash time.</summary>
    public long AvailableMemoryMB { get; init; }
    /// <summary>GC heap size at crash time (managed memory pressure).</summary>
    public long GcHeapSizeMB { get; init; }
    /// <summary>Which Guardian engine ran last before crash (regression detection).</summary>
    public string? LastOptimizationEngine { get; init; }
    /// <summary>How long ago the last optimization ran (helps detect post-optimization crashes).</summary>
    public TimeSpan? TimeSinceLastOptimization { get; init; }
}

// ─── System Profile (Anonymous) ───────────────────────────────────────────

/// <summary>
/// Anonymous hardware/software profile. NO usernames, file paths, or PII.
/// </summary>
public sealed record SystemProfile
{
    // ── Core (existing) ────────────────────────────────────────────
    public string OsVersion { get; init; } = "";       // "Windows 11 23H2"
    public string OsBuild { get; init; } = "";          // "22631.3007"
    public string DotNetVersion { get; init; } = "";    // "8.0.4"
    public string CpuName { get; init; } = "";          // "AMD Ryzen 9 7950X"
    public int CpuCores { get; init; }                  // 16
    public int CpuThreads { get; init; }                // 32
    public long RamTotalMB { get; init; }               // 32768
    public string GpuName { get; init; } = "";          // "NVIDIA RTX 4090"
    public long GpuVramMB { get; init; }                // 24576
    public string DiskType { get; init; } = "";         // "SSD" / "HDD" / "NVMe"
    public long DiskTotalGB { get; init; }              // 1000
    public long DiskFreeGB { get; init; }               // 450
    public bool IsLaptop { get; init; }
    public bool IsServer { get; init; }
    public string Locale { get; init; } = "";           // "en-US" (language only, no location)

    // ── HIGH VALUE: Windows Update Status ──────────────────────────
    public int PendingUpdateCount { get; init; }         // Queued Windows updates
    public DateTimeOffset? LastUpdateDate { get; init; } // When Windows last updated
    public int DaysSinceLastUpdate { get; init; }        // Quick staleness check

    // ── HIGH VALUE: Startup / Power ────────────────────────────────
    public int StartupProgramCount { get; init; }        // Just the count, not names
    public string PowerPlan { get; init; } = "";         // "Balanced" / "High Performance" / "Power Saver"

    // ── HIGH VALUE: Security State ─────────────────────────────────
    public bool SecureBootEnabled { get; init; }
    public bool TpmPresent { get; init; }
    public string TpmVersion { get; init; } = "";        // "2.0" / "1.2" / ""

    // ── HIGH VALUE: Thermal ────────────────────────────────────────
    public int CpuTempCelsius { get; init; }             // 0 if unavailable
    public bool IsThermalThrottling { get; init; }       // CPU throttling detected

    // ── MEDIUM VALUE: Display Config ───────────────────────────────
    public int MonitorCount { get; init; }               // Number of displays
    public string PrimaryResolution { get; init; } = ""; // "3840x2160"
    public int RefreshRateHz { get; init; }              // 60, 144, 240

    // ── MEDIUM VALUE: Memory Config ───────────────────────────────
    public long PagefileSizeMB { get; init; }            // Virtual memory size
    public long PagefileFreeSpaceMB { get; init; }       // How much is available

    // ── MEDIUM VALUE: Security Software ────────────────────────────
    public string AntivirusProduct { get; init; } = "";  // "Windows Defender" (name only)
    public bool AntivirusEnabled { get; init; }

    // ── MEDIUM VALUE: Boot / Network ──────────────────────────────
    public string BootType { get; init; } = "";          // "UEFI" / "Legacy"
    public string NetworkType { get; init; } = "";       // "WiFi" / "Ethernet" / "Unknown"
}

// ─── Usage Digest (Weekly) ────────────────────────────────────────────────

/// <summary>
/// Aggregated weekly usage summary. Sent as a batch.
/// </summary>
public sealed class UsageDigest
{
    public DateTimeOffset PeriodStart { get; init; }
    public DateTimeOffset PeriodEnd { get; init; }
    public int AppLaunchCount { get; init; }
    public TimeSpan TotalActiveTime { get; init; }
    public double AvgStartupTimeMs { get; init; }
    public double AvgMemoryUsageMB { get; init; }
    public int UiFrameDrops { get; init; }
    public Dictionary<string, int> FeatureUsage { get; init; } = new();
    public SystemProfile? System { get; init; }

    /// <summary>
    /// Snapshot of installed drivers — included in weekly digests to
    /// crowd-source driver version data and improve the driver index.
    /// </summary>
    public DriverFingerprint? Drivers { get; init; }
}

// ─── Optimization Result ──────────────────────────────────────────────────

/// <summary>
/// Sent after each optimization action (junk clean, memory optimize, etc.)
/// </summary>
public sealed class OptimizationEvent
{
    public string ToolName { get; init; } = "";        // "JunkCleaner", "MemoryOptimizer"
    public bool Succeeded { get; init; }
    public long DurationMs { get; init; }
    public Dictionary<string, string> Metrics { get; init; } = new();
    // e.g. { "BytesCleaned": "52428800", "FilesDeleted": "342" }
}

// ─── Engine Error ─────────────────────────────────────────────────────────

/// <summary>
/// Non-fatal errors from engines (WMI timeout, access denied, etc.)
/// </summary>
public sealed class EngineError
{
    public string EngineName { get; init; } = "";
    public string MethodName { get; init; } = "";
    public string ErrorType { get; init; } = "";
    public string ErrorMessage { get; init; } = "";
    public string? Context { get; init; }
}

// ─── AI Self-Improvement Signals ──────────────────────────────────────────

/// <summary>
/// Tracks whether users followed AI driver recommendations.
/// Server aggregates: "Gemini said update NVIDIA with 0.9 confidence,
/// but 70% of users skipped it" → AI learns to lower that confidence.
/// </summary>
public sealed class AiRecommendationFeedback
{
    public string RecommendationId { get; init; } = "";
    public string HardwareId { get; init; } = "";
    public string Severity { get; init; } = "";          // "critical" / "recommended" / "optional"
    public double AiConfidence { get; init; }              // What Gemini assigned (0.0–1.0)
    public string UserAction { get; init; } = "";         // "accepted" / "skipped" / "deferred"
    public bool SuccessAfterAction { get; init; }          // Was it stable after install?
    public int CrashesBeforeAction { get; init; }          // Crashes related to this driver
    public int CrashesAfterAction { get; init; }           // Crashes after updating (0 = success)
}

/// <summary>
/// Tracks when users revert optimizations or tweaks.
/// High revert rate on a specific tweak = AI should stop recommending it.
/// </summary>
public sealed class TweakFeedback
{
    public string TweakCategory { get; init; } = "";     // "Privacy" / "Performance" / "Network"
    public string TweakId { get; init; } = "";            // Anonymized tweak identifier
    public string Action { get; init; } = "";             // "applied" / "reverted" / "skipped"
    public TimeSpan? TimeBeforeRevert { get; init; }      // How long before user reverted
    public string? RevertReason { get; init; }             // Optional: why they reverted
}

/// <summary>
/// Tracks scan/engine performance — helps optimize scan speed over time.
/// </summary>
public sealed class ScanPerformanceEvent
{
    public string EngineName { get; init; } = "";         // "DriverDatabase" / "JunkCleaner" / etc.
    public string OperationType { get; init; } = "";      // "full_scan" / "quick_scan" / "install"
    public long DurationMs { get; init; }                  // How long the operation took
    public int ItemsProcessed { get; init; }               // Items scanned/cleaned/etc.
    public bool Succeeded { get; init; }
    public string? FailureCategory { get; init; }          // "timeout" / "access_denied" / "wmi_error"
    public string HardwareClass { get; init; } = "";      // "Display" / "Net" — for driver scans
}

/// <summary>
/// Anonymous session flow — which pages users visit and in what order.
/// Helps discover features users never find → improve UX and onboarding.
/// No page content or user data — just page names and timestamps.
/// </summary>
public sealed class SessionFlow
{
    public List<string> PageSequence { get; init; } = new(); // ["Dashboard", "Drivers", "Settings"]
    public TimeSpan SessionDuration { get; init; }
    public int TotalClicks { get; init; }
    public Dictionary<string, TimeSpan> TimePerPage { get; init; } = new(); // Anonymous dwell time
    public string? ExitPage { get; init; }                  // Last page before close/crash
}

// ─── Telemetry Batch ──────────────────────────────────────────────────────

/// <summary>
/// The weekly upload payload — a batch of all queued events.
/// </summary>
public sealed class PulseBatch
{
    public string InstallId { get; init; } = "";
    public string AppVersion { get; init; } = "";
    public DateTimeOffset SentAt { get; init; } = DateTimeOffset.UtcNow;
    public List<PulseEvent> Events { get; init; } = new();
}

// ─── Server Response ──────────────────────────────────────────────────────

/// <summary>
/// Response from the Pulse ingest API — may contain hotfix configs.
/// </summary>
public sealed class PulseResponse
{
    public bool Accepted { get; init; }
    public string? Message { get; init; }
    public List<HotfixConfig> Hotfixes { get; init; } = new();
    public List<KnownIssue> KnownIssues { get; init; } = new();
}

public sealed class HotfixConfig
{
    public string Id { get; init; } = "";
    public string Description { get; init; } = "";
    public string TargetEngine { get; init; } = "";
    public Dictionary<string, string> Config { get; init; } = new();
}

public sealed class KnownIssue
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Severity { get; init; } = "";
    public string? Workaround { get; init; }
}

// ─── First-Install System Baseline ────────────────────────────────────────

/// <summary>
/// Comprehensive system snapshot captured on first install ("day zero").
/// Sent once to Pulse to seed the driver DB, train AI profiles, and
/// enable pre/post improvement tracking. Zero PII.
/// </summary>
public sealed record SystemBaseline
{
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public string InstallId { get; init; } = "";
    public string AppVersion { get; init; } = "";

    // Existing profiles (reused)
    public SystemProfile? System { get; init; }
    public DriverFingerprint? Drivers { get; init; }

    // ── NEW: BIOS / Firmware ─────────────────────────────────────
    public BiosInfo? Bios { get; init; }

    // ── NEW: Services Snapshot ───────────────────────────────────
    /// <summary>Total count of Windows services.</summary>
    public int TotalServiceCount { get; init; }
    public int RunningServiceCount { get; init; }
    public int StoppedServiceCount { get; init; }
    /// <summary>Only service names + status (no args/paths). Privacy-safe.</summary>
    public List<ServiceSnapshot> Services { get; init; } = [];

    // ── NEW: Problem Devices ────────────────────────────────────
    /// <summary>Devices with errors (yellow/red bang in Device Manager).</summary>
    public List<ProblemDevice> ProblemDevices { get; init; } = [];

    // ── NEW: Installed Hotfixes ─────────────────────────────────
    /// <summary>KB numbers only — public information, no PII.</summary>
    public List<HotfixEntry> Hotfixes { get; init; } = [];

    // ── NEW: Error History Summary ──────────────────────────────
    /// <summary>Aggregated crash counts from Windows Error Reporting (no dump contents).</summary>
    public ErrorHistorySummary? ErrorHistory { get; init; }

    // ── NEW: Physical Memory Slots ──────────────────────────────
    /// <summary>RAM module details — helps recommend upgrades.</summary>
    public List<MemorySlot> MemorySlots { get; init; } = [];

    // ── NEW: Storage Controllers ────────────────────────────────
    /// <summary>NVMe/AHCI/IDE mode detection for disk optimization.</summary>
    public List<string> StorageControllers { get; init; } = [];
}

public sealed record BiosInfo
{
    public string Manufacturer { get; init; } = "";
    public string Version { get; init; } = "";
    public string ReleaseDate { get; init; } = "";
    public string SmbiosVersion { get; init; } = "";
    public bool IsUefi { get; init; }
}

public sealed record ServiceSnapshot
{
    /// <summary>Service name (e.g., "SysMain", "WSearch").</summary>
    public string Name { get; init; } = "";
    /// <summary>Display name (e.g., "Superfetch").</summary>
    public string DisplayName { get; init; } = "";
    /// <summary>"Running", "Stopped", "Disabled".</summary>
    public string Status { get; init; } = "";
    /// <summary>"Auto", "Manual", "Disabled", "Boot".</summary>
    public string StartMode { get; init; } = "";
}

public sealed record ProblemDevice
{
    /// <summary>Hardware ID (e.g., "PCI\VEN_10DE&DEV_2684").</summary>
    public string HardwareId { get; init; } = "";
    /// <summary>Device class (e.g., "Display", "Net").</summary>
    public string DeviceClass { get; init; } = "";
    /// <summary>Friendly name if available.</summary>
    public string Name { get; init; } = "";
    /// <summary>Error code from ConfigManagerErrorCode.</summary>
    public int ErrorCode { get; init; }
    /// <summary>Human-readable error description.</summary>
    public string ErrorDescription { get; init; } = "";
}

public sealed record HotfixEntry
{
    /// <summary>KB number (e.g., "KB5034441").</summary>
    public string HotfixId { get; init; } = "";
    /// <summary>"Update", "Security Update", "Hotfix".</summary>
    public string Description { get; init; } = "";
    public DateTimeOffset? InstalledOn { get; init; }
}

public sealed class ErrorHistorySummary
{
    /// <summary>Total application errors in the last 30 days.</summary>
    public int AppErrorsLast30Days { get; init; }
    /// <summary>Total application hangs in the last 30 days.</summary>
    public int AppHangsLast30Days { get; init; }
    /// <summary>Total blue screens (BugCheck) in the last 30 days.</summary>
    public int BlueScreensLast30Days { get; init; }
    /// <summary>Most frequent crashing app (name only, no path).</summary>
    public string TopCrashingApp { get; init; } = "";
    public int TopCrashingAppCount { get; init; }
}

public sealed record MemorySlot
{
    /// <summary>Slot label (e.g., "DIMM 0", "SODIMM 1").</summary>
    public string Slot { get; init; } = "";
    /// <summary>Capacity in MB.</summary>
    public long CapacityMB { get; init; }
    /// <summary>Clock speed in MHz.</summary>
    public int SpeedMHz { get; init; }
    /// <summary>Memory type (e.g., "DDR4", "DDR5").</summary>
    public string MemoryType { get; init; } = "";
    /// <summary>Manufacturer (e.g., "Samsung", "Corsair").</summary>
    public string Manufacturer { get; init; } = "";
}

// ─── Driver Fingerprint (Crowd-Sourced Telemetry) ─────────────────────────

/// <summary>
/// Compact snapshot of all installed drivers. Sent with crash reports and
/// weekly digests to crowd-source driver version data. This data helps:
///   1. Discover new hardware IDs not yet in the curated index
///   2. Track version distribution → know which versions are common
///   3. Correlate crashes with specific driver versions
///   4. Automatically suggest new entries for the driver_index
/// NO PII: uses hardware IDs and version strings only.
/// </summary>
public sealed class DriverFingerprint
{
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalDriverCount { get; init; }
    public int SignedCount { get; init; }
    public int UnsignedCount { get; init; }

    /// <summary>
    /// Only the "important" drivers — GPU, Audio, Network, WiFi, Bluetooth,
    /// Storage, Chipset. We skip System/HID/Printer to save bandwidth.
    /// </summary>
    public List<DriverSnapshot> KeyDrivers { get; init; } = new();

    /// <summary>
    /// BIOS/UEFI firmware version if available.
    /// </summary>
    public string FirmwareVersion { get; init; } = "";
    public string FirmwareManufacturer { get; init; } = "";
}

/// <summary>
/// A single driver entry in the fingerprint. Kept minimal (~100 bytes each)
/// to avoid bloating telemetry payloads.
/// </summary>
public sealed record DriverSnapshot
{
    /// <summary> Hardware ID (e.g., "PCI\VEN_10DE&DEV_2684"). </summary>
    public string HwId { get; init; } = "";
    /// <summary> Device class (e.g., "Display", "Net"). </summary>
    public string Class { get; init; } = "";
    /// <summary> Driver version string. </summary>
    public string Version { get; init; } = "";
    /// <summary> Driver provider/manufacturer. </summary>
    public string Provider { get; init; } = "";
    /// <summary> Whether the driver is WHQL signed. </summary>
    public bool Signed { get; init; }
}
