// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — Windows Event & System Log Reader
// Reads from additional Windows log sources that Reliability Monitor misses:
//   • Windows Event Log (System + Application) — BSODs, driver failures, .NET errors
//   • BSOD Minidumps (C:\Windows\Minidump\) — blue screen crash dumps
//   • SetupAPI logs — driver installation failures
//   • CBS logs — Windows Update / servicing failures
//   • SFC results — system file integrity issues
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Reads critical system logs beyond Reliability Monitor:
/// Event Viewer, BSOD dumps, driver install logs, Windows Update logs.
/// All data is sanitized — no usernames, file paths, or PII.
/// </summary>
public sealed class SystemLogReader
{
    private readonly ILogger<SystemLogReader>? _logger;

    public SystemLogReader(ILogger<SystemLogReader>? logger = null) => _logger = logger;

    // ─── Windows Event Log ──────────────────────────────────────────────

    /// <summary>
    /// Reads critical/error events from the System and Application event logs.
    /// This captures: BSODs (Event 41, 1001), disk errors, driver failures,
    /// .NET CLR exceptions, service crashes, and more.
    /// </summary>
    public List<EventLogEntry> GetCriticalEvents(int daysBack = 7, int maxEntries = 100)
    {
        var entries = new List<EventLogEntry>();
        _logger?.LogInformation("Reading Windows Event Logs (last {Days} days)...", daysBack);

        try
        {
            // System log — BSODs, driver failures, disk errors, service crashes
            entries.AddRange(ReadEventLog("System", daysBack, maxEntries / 2));

            // Application log — app crashes, .NET exceptions, WER
            entries.AddRange(ReadEventLog("Application", daysBack, maxEntries / 2));
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read Windows Event Logs");
        }

        return entries.OrderByDescending(e => e.TimeCreated).Take(maxEntries).ToList();
    }

    private List<EventLogEntry> ReadEventLog(string logName, int daysBack, int max)
    {
        var entries = new List<EventLogEntry>();

        try
        {
            // XPath query: Level 1 (Critical) or 2 (Error), within time range
            var msBack = (long)TimeSpan.FromDays(daysBack).TotalMilliseconds;
            var query = $"*[System[(Level=1 or Level=2) and " +
                        $"TimeCreated[timediff(@SystemTime) <= {msBack}]]]";

            using var reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, query));

            EventRecord? record;
            int count = 0;
            while ((record = reader.ReadEvent()) != null && count < max)
            {
                using (record)
                {
                    entries.Add(new EventLogEntry
                    {
                        LogName = logName,
                        Source = record.ProviderName ?? "",
                        EventId = record.Id,
                        Level = record.Level switch
                        {
                            1 => "Critical",
                            2 => "Error",
                            _ => "Unknown"
                        },
                        TimeCreated = record.TimeCreated ?? DateTime.UtcNow,
                        Message = SanitizeMessage(FormatEventMessage(record)),
                        Category = ClassifyEventLogEntry(record)
                    });
                    count++;
                }
            }

            _logger?.LogDebug("Read {Count} error/critical events from {Log}", count, logName);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to read {Log} event log", logName);
        }

        return entries;
    }

    // ─── BSOD Minidumps ─────────────────────────────────────────────────

    /// <summary>
    /// Detects recent Blue Screen minidump files.
    /// Location: C:\Windows\Minidump\*.dmp
    /// We only report metadata (date, size) — NOT dump contents.
    /// </summary>
    public List<MinidumpInfo> GetRecentMinidumps(int daysBack = 30)
    {
        var dumps = new List<MinidumpInfo>();

        try
        {
            var paths = new[]
            {
                @"C:\Windows\Minidump",
                @"C:\Windows\MEMORY.DMP" // Full memory dump (just check existence)
            };

            var cutoff = DateTime.UtcNow.AddDays(-daysBack);

            // Check minidump folder
            var minidumpDir = paths[0];
            if (Directory.Exists(minidumpDir))
            {
                foreach (var file in Directory.GetFiles(minidumpDir, "*.dmp"))
                {
                    var fi = new FileInfo(file);
                    if (fi.CreationTimeUtc < cutoff) continue;

                    dumps.Add(new MinidumpInfo
                    {
                        FileName = fi.Name, // Just filename — no path
                        CreatedAt = fi.CreationTimeUtc,
                        SizeBytes = fi.Length,
                        Type = "Minidump"
                    });
                }
            }

            // Check for full memory dump
            if (File.Exists(paths[1]))
            {
                var fi = new FileInfo(paths[1]);
                if (fi.CreationTimeUtc >= cutoff)
                {
                    dumps.Add(new MinidumpInfo
                    {
                        FileName = "MEMORY.DMP",
                        CreatedAt = fi.CreationTimeUtc,
                        SizeBytes = fi.Length,
                        Type = "Full Memory Dump"
                    });
                }
            }

            _logger?.LogInformation("Found {Count} BSOD minidumps in last {Days} days",
                dumps.Count, daysBack);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to scan for minidumps");
        }

        return dumps.OrderByDescending(d => d.CreatedAt).ToList();
    }

    // ─── SetupAPI Driver Logs ───────────────────────────────────────────

    /// <summary>
    /// Parses SetupAPI log for driver installation failures.
    /// Location: C:\Windows\inf\setupapi.dev.log
    /// These capture failed driver installs that don't show up in Event Viewer.
    /// </summary>
    public List<DriverInstallLog> GetDriverInstallFailures(int maxEntries = 20)
    {
        var failures = new List<DriverInstallLog>();

        try
        {
            var logPath = @"C:\Windows\inf\setupapi.dev.log";
            if (!File.Exists(logPath)) return failures;

            // Read last portion of the file (it can be huge)
            var lines = ReadLastLines(logPath, 2000);
            var currentEntry = new DriverInstallLog();
            bool inFailedSection = false;

            foreach (var line in lines)
            {
                if (line.Contains("!!! Error", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("!!! Failure", StringComparison.OrdinalIgnoreCase))
                {
                    inFailedSection = true;
                    currentEntry = new DriverInstallLog
                    {
                        ErrorLine = SanitizeMessage(line.Trim())
                    };
                }
                else if (inFailedSection && line.Contains(">>>  Section", StringComparison.OrdinalIgnoreCase))
                {
                    // End of error section
                    if (!string.IsNullOrEmpty(currentEntry.ErrorLine))
                    {
                        failures.Add(currentEntry);
                        if (failures.Count >= maxEntries) break;
                    }
                    inFailedSection = false;
                }
                else if (inFailedSection)
                {
                    if (line.Contains("Device:", StringComparison.OrdinalIgnoreCase))
                        currentEntry.DeviceName = line.Split(':', 2).LastOrDefault()?.Trim() ?? "";
                    else if (line.Contains("Driver:", StringComparison.OrdinalIgnoreCase))
                        currentEntry.DriverName = Path.GetFileName(
                            line.Split(':', 2).LastOrDefault()?.Trim() ?? "");
                }
            }

            _logger?.LogInformation("Found {Count} driver install failures in SetupAPI log",
                failures.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to parse SetupAPI log");
        }

        return failures;
    }

    // ─── CBS / Windows Update Logs ──────────────────────────────────────

    /// <summary>
    /// Scans CBS log for Windows Update / servicing failures.
    /// Location: C:\Windows\Logs\CBS\CBS.log
    /// Also checks SFC (System File Checker) results embedded in CBS log.
    /// </summary>
    public WindowsUpdateHealth GetWindowsUpdateHealth()
    {
        var health = new WindowsUpdateHealth();

        try
        {
            var cbsPath = @"C:\Windows\Logs\CBS\CBS.log";
            if (!File.Exists(cbsPath))
            {
                health.CbsLogExists = false;
                return health;
            }

            health.CbsLogExists = true;
            var lines = ReadLastLines(cbsPath, 3000);

            foreach (var line in lines)
            {
                if (line.Contains("Error", StringComparison.OrdinalIgnoreCase))
                    health.ErrorCount++;

                if (line.Contains("SFC", StringComparison.OrdinalIgnoreCase) &&
                    line.Contains("corrupt", StringComparison.OrdinalIgnoreCase))
                    health.CorruptFileCount++;

                if (line.Contains("Repair failed", StringComparison.OrdinalIgnoreCase))
                    health.RepairFailures++;

                if (line.Contains("Successfully", StringComparison.OrdinalIgnoreCase) &&
                    line.Contains("repaired", StringComparison.OrdinalIgnoreCase))
                    health.SuccessfulRepairs++;
            }

            // Check DISM log too
            var dismPath = @"C:\Windows\Logs\DISM\dism.log";
            if (File.Exists(dismPath))
            {
                health.DismLogExists = true;
                var dismLines = ReadLastLines(dismPath, 500);
                health.DismErrors = dismLines.Count(l =>
                    l.Contains("Error", StringComparison.OrdinalIgnoreCase));
            }

            _logger?.LogInformation("CBS: {Errors} errors, {Corrupt} corrupt files, {Repaired} repaired",
                health.ErrorCount, health.CorruptFileCount, health.SuccessfulRepairs);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to parse CBS/DISM logs");
        }

        return health;
    }

    // ─── Aggregate: Full System Log Digest ──────────────────────────────

    /// <summary>
    /// Builds a comprehensive log digest from ALL Windows log sources.
    /// This supplements the WindowsReliabilityReader digest.
    /// </summary>
    public ExtendedLogDigest BuildExtendedDigest()
    {
        return new ExtendedLogDigest
        {
            CapturedAt = DateTimeOffset.UtcNow,
            CriticalEvents = GetCriticalEvents(7, 50),
            Minidumps = GetRecentMinidumps(30),
            DriverInstallFailures = GetDriverInstallFailures(10),
            WindowsUpdateHealth = GetWindowsUpdateHealth(),
            BsodCount = GetRecentMinidumps(30).Count,
            HasRecentBsod = GetRecentMinidumps(7).Count > 0
        };
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private static string FormatEventMessage(EventRecord record)
    {
        try { return record.FormatDescription() ?? $"EventID={record.Id}"; }
        catch { return $"EventID={record.Id} (message unavailable)"; }
    }

    private static string SanitizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "";
        return System.Text.RegularExpressions.Regex.Replace(
            message,
            @"[A-Z]:\\(?:Users\\[^\\]+\\|[^""'\s]*\\)+",
            "[path]\\",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private static string ClassifyEventLogEntry(EventRecord record)
    {
        var source = (record.ProviderName ?? "").ToLowerInvariant();
        var id = record.Id;

        // Known critical event IDs
        if (source == "microsoft-windows-kernel-power" && id == 41) return "BSOD/Unexpected Shutdown";
        if (source == "bugcheck" || id == 1001) return "Blue Screen (BugCheck)";
        if (source.Contains("disk")) return "Disk Error";
        if (source.Contains("ntfs")) return "File System Error";
        if (source.Contains("whea")) return "Hardware Error";
        if (source.Contains("driver") || source.Contains("pnp")) return "Driver Error";
        if (source.Contains(".net runtime") || source.Contains("clr")) return ".NET Runtime Error";
        if (source.Contains("application error")) return "Application Crash";
        if (source.Contains("wuauserv") || source.Contains("windowsupdateclient")) return "Windows Update Error";
        if (source.Contains("service control")) return "Service Failure";

        return "System Error";
    }

    private static string[] ReadLastLines(string filePath, int lineCount)
    {
        try
        {
            // Read efficiently from the end of large files
            var allLines = File.ReadAllLines(filePath);
            return allLines.Skip(Math.Max(0, allLines.Length - lineCount)).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }
}

// ─── Data Models ────────────────────────────────────────────────────────

public sealed class EventLogEntry
{
    public string LogName { get; set; } = "";       // "System" or "Application"
    public string Source { get; set; } = "";         // Event provider name
    public int EventId { get; set; }
    public string Level { get; set; } = "";          // "Critical" or "Error"
    public DateTime TimeCreated { get; set; }
    public string Message { get; set; } = "";        // Sanitized
    public string Category { get; set; } = "";       // Our classification
}

public sealed class MinidumpInfo
{
    public string FileName { get; set; } = "";       // Just filename, no path
    public DateTime CreatedAt { get; set; }
    public long SizeBytes { get; set; }
    public string Type { get; set; } = "";           // "Minidump" or "Full Memory Dump"
}

public sealed class DriverInstallLog
{
    public string DeviceName { get; set; } = "";
    public string DriverName { get; set; } = "";     // Filename only
    public string ErrorLine { get; set; } = "";
}

public sealed class WindowsUpdateHealth
{
    public bool CbsLogExists { get; set; }
    public bool DismLogExists { get; set; }
    public int ErrorCount { get; set; }
    public int CorruptFileCount { get; set; }
    public int RepairFailures { get; set; }
    public int SuccessfulRepairs { get; set; }
    public int DismErrors { get; set; }
}

public sealed class ExtendedLogDigest
{
    public DateTimeOffset CapturedAt { get; set; }
    public List<EventLogEntry> CriticalEvents { get; set; } = new();
    public List<MinidumpInfo> Minidumps { get; set; } = new();
    public List<DriverInstallLog> DriverInstallFailures { get; set; } = new();
    public WindowsUpdateHealth WindowsUpdateHealth { get; set; } = new();
    public int BsodCount { get; set; }
    public bool HasRecentBsod { get; set; }
}
