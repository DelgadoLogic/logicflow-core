// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — Windows Reliability & WER Reader
// Reads from Windows Reliability Monitor (Win32_ReliabilityRecords)
// and Problem Reports (WER) to capture system-wide crash/failure data.
// This gives the AI engine full context: driver crashes, BSODs,
// Windows Update failures, app hangs — not just LogicFlow exceptions.
// ─────────────────────────────────────────────────────────────────────────────

using System.Management;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Reads Windows Reliability Monitor records and WER Problem Reports.
/// These contain system-level failures that our own exception handlers can't capture:
///   • Blue Screens (BugCheck)
///   • Driver crashes
///   • Windows Update failures
///   • Application hangs / crashes (any app)
///   • Hardware errors
/// This data helps the AI engine understand the full system health picture.
/// </summary>
public sealed class WindowsReliabilityReader
{
    private readonly ILogger<WindowsReliabilityReader>? _logger;

    public WindowsReliabilityReader(ILogger<WindowsReliabilityReader>? logger = null)
        => _logger = logger;

    // ─── Reliability Monitor ────────────────────────────────────────────

    /// <summary>
    /// Reads recent Reliability Monitor events (last N days).
    /// Source: Control Panel → System and Security → Security and Maintenance → Reliability Monitor
    /// WMI Class: Win32_ReliabilityRecords
    /// </summary>
    public List<ReliabilityRecord> GetReliabilityRecords(int daysBack = 14)
    {
        var records = new List<ReliabilityRecord>();
        _logger?.LogInformation("Reading Reliability Monitor records (last {Days} days)...", daysBack);

        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-daysBack);
            var cutoffWmi = ManagementDateTimeConverter.ToDmtfDateTime(cutoff);

            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                $"SELECT * FROM Win32_ReliabilityRecords WHERE TimeGenerated > '{cutoffWmi}'");

            foreach (var obj in searcher.Get())
            {
                var record = new ReliabilityRecord
                {
                    EventIdentifier = obj["EventIdentifier"]?.ToString() ?? "",
                    ProductName = obj["ProductName"]?.ToString() ?? "",
                    SourceName = obj["SourceName"]?.ToString() ?? "",
                    Message = SanitizeMessage(obj["Message"]?.ToString() ?? ""),
                    RecordNumber = Convert.ToInt32(obj["RecordNumber"] ?? 0),
                    LogFile = obj["Logfile"]?.ToString() ?? "",
                    ComputerName = "", // Redacted — no PII
                };

                // Parse the timestamp
                var timeStr = obj["TimeGenerated"]?.ToString();
                if (!string.IsNullOrEmpty(timeStr))
                {
                    try
                    {
                        record.TimeGenerated = ManagementDateTimeConverter.ToDateTime(timeStr);
                    }
                    catch { record.TimeGenerated = DateTime.UtcNow; }
                }

                // Classify the event type
                record.Category = ClassifyEvent(record.SourceName, record.Message);

                records.Add(record);
            }

            _logger?.LogInformation("Found {Count} reliability records in last {Days} days",
                records.Count, daysBack);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read Reliability Monitor records");
        }

        return records.OrderByDescending(r => r.TimeGenerated).ToList();
    }

    /// <summary>
    /// Gets the system stability index from Reliability Monitor.
    /// Score from 1 (unstable) to 10 (rock solid).
    /// Source: Win32_ReliabilityStabilityMetrics
    /// </summary>
    public ReliabilityScore GetStabilityScore()
    {
        var score = new ReliabilityScore();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT * FROM Win32_ReliabilityStabilityMetrics");

            // Get the most recent metric
            ManagementBaseObject? latest = null;
            DateTime latestTime = DateTime.MinValue;

            foreach (var obj in searcher.Get())
            {
                var timeStr = obj["TimeGenerated"]?.ToString();
                if (!string.IsNullOrEmpty(timeStr))
                {
                    var time = ManagementDateTimeConverter.ToDateTime(timeStr);
                    if (time > latestTime)
                    {
                        latestTime = time;
                        latest = obj;
                    }
                }
            }

            if (latest != null)
            {
                score.StabilityIndex = Convert.ToDouble(latest["SystemStabilityIndex"] ?? 0.0);
                score.MeasuredAt = latestTime;

                // Get per-category failure counts
                score.ApplicationFailures = TryGetInt(latest, "EndDate") > 0 ? 0 : 0; // Category-level not in WMI; derive from records
                score.Assessment = score.StabilityIndex switch
                {
                    >= 9.0 => "Excellent — system is very stable",
                    >= 7.0 => "Good — minor issues detected",
                    >= 5.0 => "Fair — some instability, review recommended",
                    >= 3.0 => "Poor — frequent failures, attention needed",
                    _ => "Critical — system is highly unstable"
                };
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read stability score");
        }

        // Supplement with failure counts from records
        try
        {
            var recentRecords = GetReliabilityRecords(7);
            score.ApplicationFailures = recentRecords.Count(r => r.Category == EventCategory.ApplicationCrash);
            score.HardwareFailures = recentRecords.Count(r => r.Category == EventCategory.HardwareError);
            score.WindowsFailures = recentRecords.Count(r => r.Category == EventCategory.WindowsFailure);
            score.MiscFailures = recentRecords.Count(r =>
                r.Category == EventCategory.DriverCrash || r.Category == EventCategory.Other);
        }
        catch { }

        return score;
    }

    // ─── WER Problem Reports ────────────────────────────────────────────

    /// <summary>
    /// Reads Windows Error Reporting (WER) Problem Reports.
    /// Source: Control Panel → System and Security → Security and Maintenance → Problem Reports
    /// These contain crash dumps, hang reports, and solution responses from Microsoft.
    /// </summary>
    public List<ProblemReport> GetProblemReports(int maxAge = 30)
    {
        var reports = new List<ProblemReport>();
        _logger?.LogInformation("Reading WER Problem Reports (last {Days} days)...", maxAge);

        try
        {
            // WER stores reports in two locations
            var werPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "WER", "ReportQueue"),
                Path.Combine(@"C:\ProgramData\Microsoft\Windows\WER\ReportArchive"),
                Path.Combine(@"C:\ProgramData\Microsoft\Windows\WER\ReportQueue")
            };

            var cutoff = DateTime.UtcNow.AddDays(-maxAge);

            foreach (var basePath in werPaths)
            {
                if (!Directory.Exists(basePath)) continue;

                foreach (var reportDir in Directory.GetDirectories(basePath))
                {
                    try
                    {
                        var dirInfo = new DirectoryInfo(reportDir);
                        if (dirInfo.CreationTimeUtc < cutoff) continue;

                        var reportIni = Path.Combine(reportDir, "Report.wer");
                        if (!File.Exists(reportIni)) continue;

                        var report = ParseWerReport(reportIni, dirInfo.CreationTimeUtc);
                        if (report != null) reports.Add(report);
                    }
                    catch { /* Skip unreadable reports */ }
                }
            }

            _logger?.LogInformation("Found {Count} WER problem reports", reports.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read WER Problem Reports");
        }

        return reports.OrderByDescending(r => r.Timestamp).ToList();
    }

    /// <summary>
    /// Builds a comprehensive system health digest combining Reliability Monitor + WER data.
    /// This is what gets sent to the Pulse AI engine for analysis.
    /// </summary>
    public SystemHealthDigest BuildHealthDigest()
    {
        var digest = new SystemHealthDigest
        {
            CapturedAt = DateTimeOffset.UtcNow,
            StabilityScore = GetStabilityScore(),
            RecentReliabilityEvents = GetReliabilityRecords(7), // Last week
            RecentProblemReports = GetProblemReports(7)
        };

        // Summarize by category
        digest.CrashSummary = new()
        {
            { "Application Crashes", digest.RecentReliabilityEvents.Count(e => e.Category == EventCategory.ApplicationCrash) },
            { "Driver Crashes", digest.RecentReliabilityEvents.Count(e => e.Category == EventCategory.DriverCrash) },
            { "Windows Failures", digest.RecentReliabilityEvents.Count(e => e.Category == EventCategory.WindowsFailure) },
            { "Hardware Errors", digest.RecentReliabilityEvents.Count(e => e.Category == EventCategory.HardwareError) },
            { "WER Reports", digest.RecentProblemReports.Count }
        };

        // Top crashing apps
        digest.TopCrashingApps = digest.RecentReliabilityEvents
            .Where(e => !string.IsNullOrEmpty(e.ProductName))
            .GroupBy(e => e.ProductName)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => new CrashingApp { Name = g.Key, CrashCount = g.Count() })
            .ToList();

        return digest;
    }

    // ─── Internal Helpers ───────────────────────────────────────────────

    private ProblemReport? ParseWerReport(string reportPath, DateTime created)
    {
        try
        {
            var lines = File.ReadAllLines(reportPath);
            var report = new ProblemReport { Timestamp = created };

            foreach (var line in lines)
            {
                var parts = line.Split('=', 2);
                if (parts.Length != 2) continue;

                var key = parts[0].Trim();
                var value = parts[1].Trim();

                switch (key)
                {
                    case "EventType": report.EventType = value; break;
                    case "Sig[0]": report.AppName = SanitizePath(value); break;
                    case "Sig[1]": report.AppVersion = value; break;
                    case "Sig[2]": report.ModuleName = SanitizePath(value); break;
                    case "Sig[3]": report.ModuleVersion = value; break;
                    case "Sig[6]": report.ExceptionCode = value; break;
                    case "FriendlyEventName": report.FriendlyName = value; break;
                    case "AppPath": report.AppPath = SanitizePath(value); break;
                    case "ReportDescription": report.Description = value; break;
                }
            }

            // Only include if it looks like a real crash/failure
            if (string.IsNullOrEmpty(report.EventType) &&
                string.IsNullOrEmpty(report.AppName)) return null;

            return report;
        }
        catch { return null; }
    }

    /// <summary>
    /// Strips full file paths from messages to avoid PII leakage.
    /// Keeps only filenames, no directory structure.
    /// </summary>
    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "";

        // Strip file paths (C:\Users\xxx\...) but keep filenames
        return System.Text.RegularExpressions.Regex.Replace(
            message,
            @"[A-Z]:\\(?:Users\\[^\\]+\\|[^""'\s]*\\)+",
            "[path]\\",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// Strips directory paths, keeps only the filename.
    /// </summary>
    private static string SanitizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        try { return Path.GetFileName(path); }
        catch { return path; }
    }

    private static EventCategory ClassifyEvent(string source, string message)
    {
        var combined = $"{source} {message}".ToLowerInvariant();

        if (combined.Contains("bluescreen") || combined.Contains("bugcheck") ||
            combined.Contains("kernel") || combined.Contains("shutdown unexpected"))
            return EventCategory.WindowsFailure;

        if (combined.Contains("driver") || combined.Contains("display adapter") ||
            combined.Contains("nvlddmkm") || combined.Contains("atikmdag"))
            return EventCategory.DriverCrash;

        if (combined.Contains("hardware") || combined.Contains("disk") ||
            combined.Contains("memory") || combined.Contains("whea"))
            return EventCategory.HardwareError;

        if (combined.Contains("application") || combined.Contains("stopped working") ||
            combined.Contains("hang") || combined.Contains("crash"))
            return EventCategory.ApplicationCrash;

        if (combined.Contains("update") || combined.Contains("windows update") ||
            combined.Contains("hotfix"))
            return EventCategory.WindowsUpdate;

        return EventCategory.Other;
    }

    private static int TryGetInt(ManagementBaseObject obj, string prop)
    {
        try { return Convert.ToInt32(obj[prop] ?? 0); } catch { return 0; }
    }
}

// ─── Data Models ────────────────────────────────────────────────────────

public enum EventCategory
{
    ApplicationCrash,
    DriverCrash,
    WindowsFailure,
    HardwareError,
    WindowsUpdate,
    Other
}

public sealed class ReliabilityRecord
{
    public string EventIdentifier { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string SourceName { get; set; } = "";
    public string Message { get; set; } = "";
    public int RecordNumber { get; set; }
    public string LogFile { get; set; } = "";
    public string ComputerName { get; set; } = ""; // Always redacted
    public DateTime TimeGenerated { get; set; }
    public EventCategory Category { get; set; }
}

public sealed class ReliabilityScore
{
    public double StabilityIndex { get; set; } // 1.0 - 10.0
    public string Assessment { get; set; } = "";
    public DateTime MeasuredAt { get; set; }
    public int ApplicationFailures { get; set; }
    public int HardwareFailures { get; set; }
    public int WindowsFailures { get; set; }
    public int MiscFailures { get; set; }
}

public sealed class ProblemReport
{
    public string EventType { get; set; } = "";
    public string AppName { get; set; } = "";        // Filename only — no paths
    public string AppVersion { get; set; } = "";
    public string ModuleName { get; set; } = "";      // Filename only
    public string ModuleVersion { get; set; } = "";
    public string ExceptionCode { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string AppPath { get; set; } = "";         // Filename only — sanitized
    public string Description { get; set; } = "";
    public DateTime Timestamp { get; set; }
}

public sealed class SystemHealthDigest
{
    public DateTimeOffset CapturedAt { get; set; }
    public ReliabilityScore StabilityScore { get; set; } = new();
    public List<ReliabilityRecord> RecentReliabilityEvents { get; set; } = new();
    public List<ProblemReport> RecentProblemReports { get; set; } = new();
    public Dictionary<string, int> CrashSummary { get; set; } = new();
    public List<CrashingApp> TopCrashingApps { get; set; } = new();
}

public sealed class CrashingApp
{
    public string Name { get; set; } = "";
    public int CrashCount { get; set; }
}
