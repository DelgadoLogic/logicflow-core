// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — Health Digest Aggregator
// Merges WindowsReliabilityReader + SystemLogReader into a single,
// DEDUPLICATED health digest. The same crash can appear in Reliability
// Monitor, WER, AND Event Viewer — this ensures each event is sent once.
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Single entry point for collecting all Windows health data.
/// Merges Reliability Monitor + WER + Event Logs + minidumps + CBS
/// and deduplicates events that appear in multiple sources.
/// </summary>
public sealed class HealthDigestAggregator
{
    private readonly WindowsReliabilityReader _reliability;
    private readonly SystemLogReader _systemLogs;
    private readonly ILogger<HealthDigestAggregator>? _logger;

    public HealthDigestAggregator(ILogger<HealthDigestAggregator>? logger = null)
    {
        _logger = logger;
        _reliability = new WindowsReliabilityReader();
        _systemLogs = new SystemLogReader();
    }

    /// <summary>
    /// Builds a comprehensive, deduplicated health digest from ALL sources.
    /// This is what the weekly Pulse batch sends to the AI engine.
    /// </summary>
    public AggregatedHealthDigest BuildDigest(int daysBack = 7)
    {
        _logger?.LogInformation("Building aggregated health digest (last {Days} days)...", daysBack);

        // ─── Collect from all sources ──────────────────────────────
        var reliabilityDigest = _reliability.BuildHealthDigest();
        var extendedDigest = _systemLogs.BuildExtendedDigest();

        // ─── Merge & Deduplicate Events ────────────────────────────
        var allEvents = new List<UnifiedEvent>();

        // Add Reliability Monitor events
        foreach (var r in reliabilityDigest.RecentReliabilityEvents)
        {
            allEvents.Add(new UnifiedEvent
            {
                Timestamp = r.TimeGenerated,
                Source = $"ReliabilityMonitor:{r.SourceName}",
                Category = r.Category.ToString(),
                ProductName = r.ProductName,
                Message = r.Message,
                OriginalSource = "ReliabilityMonitor"
            });
        }

        // Add WER Problem Reports
        foreach (var p in reliabilityDigest.RecentProblemReports)
        {
            allEvents.Add(new UnifiedEvent
            {
                Timestamp = p.Timestamp,
                Source = $"WER:{p.EventType}",
                Category = "ApplicationCrash",
                ProductName = p.AppName,
                Message = $"{p.FriendlyName}: {p.AppName} {p.AppVersion} ({p.ExceptionCode})",
                OriginalSource = "WER"
            });
        }

        // Add Event Log entries
        foreach (var e in extendedDigest.CriticalEvents)
        {
            allEvents.Add(new UnifiedEvent
            {
                Timestamp = e.TimeCreated,
                Source = $"EventLog:{e.Source}",
                Category = e.Category,
                ProductName = e.Source,
                Message = e.Message,
                OriginalSource = $"EventLog:{e.LogName}"
            });
        }

        // ─── Deduplicate ───────────────────────────────────────────
        var deduped = DeduplicateEvents(allEvents);

        _logger?.LogInformation(
            "Health digest: {Total} total events → {Deduped} after dedup ({Removed} duplicates removed)",
            allEvents.Count, deduped.Count, allEvents.Count - deduped.Count);

        // ─── Build final digest ────────────────────────────────────
        return new AggregatedHealthDigest
        {
            CapturedAt = DateTimeOffset.UtcNow,
            PeriodDays = daysBack,

            // Deduplicated events
            Events = deduped,

            // Stability score (from Reliability Monitor only — no duplication risk)
            StabilityIndex = reliabilityDigest.StabilityScore.StabilityIndex,
            StabilityAssessment = reliabilityDigest.StabilityScore.Assessment,

            // BSOD data (from minidumps only — unique source)
            BsodCount = extendedDigest.BsodCount,
            HasRecentBsod = extendedDigest.HasRecentBsod,
            Minidumps = extendedDigest.Minidumps,

            // Driver install failures (from SetupAPI only — unique source)
            DriverInstallFailures = extendedDigest.DriverInstallFailures,

            // Windows Update health (from CBS only — unique source)
            WindowsUpdateHealth = extendedDigest.WindowsUpdateHealth,

            // Crash summary (from deduplicated events)
            CrashSummary = deduped
                .GroupBy(e => e.Category)
                .ToDictionary(g => g.Key, g => g.Count()),

            // Top crashing apps (from deduplicated events)
            TopCrashingApps = deduped
                .Where(e => !string.IsNullOrEmpty(e.ProductName))
                .GroupBy(e => e.ProductName)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new CrashingApp { Name = g.Key, CrashCount = g.Count() })
                .ToList()
        };
    }

    /// <summary>
    /// Deduplicates events by generating a fingerprint from:
    ///   • Timestamp (rounded to nearest minute — same crash logged at slightly different times)
    ///   • Source keyword (normalized — "Kernel-Power" matches across Event Log and Reliability)
    ///   • Message hash (first 100 chars to handle truncation differences)
    /// </summary>
    private List<UnifiedEvent> DeduplicateEvents(List<UnifiedEvent> events)
    {
        var seen = new HashSet<string>();
        var deduped = new List<UnifiedEvent>();

        // Sort by timestamp so we keep the earliest occurrence
        foreach (var evt in events.OrderBy(e => e.Timestamp))
        {
            var fingerprint = GenerateFingerprint(evt);
            if (seen.Add(fingerprint))
            {
                deduped.Add(evt);
            }
            else
            {
                // Duplicate found — note which sources reported it
                var existing = deduped.FirstOrDefault(e => GenerateFingerprint(e) == fingerprint);
                if (existing != null && !existing.AlsoReportedBy.Contains(evt.OriginalSource))
                    existing.AlsoReportedBy.Add(evt.OriginalSource);
            }
        }

        return deduped;
    }

    /// <summary>
    /// Generates a dedup fingerprint. Events within 2 minutes of each other
    /// with matching source keywords and similar messages are considered the same.
    /// </summary>
    private static string GenerateFingerprint(UnifiedEvent evt)
    {
        // Round timestamp to nearest 2-minute window
        var roundedTime = new DateTime(
            evt.Timestamp.Year, evt.Timestamp.Month, evt.Timestamp.Day,
            evt.Timestamp.Hour, evt.Timestamp.Minute / 2 * 2, 0);

        // Normalize source (strip prefixes like "EventLog:", "ReliabilityMonitor:")
        var normalizedSource = evt.Source
            .Replace("ReliabilityMonitor:", "")
            .Replace("EventLog:", "")
            .Replace("WER:", "")
            .ToLowerInvariant()
            .Trim();

        // Hash first 100 chars of message for fuzzy matching
        var msgKey = (evt.Message.Length > 100 ? evt.Message[..100] : evt.Message)
            .ToLowerInvariant();
        var msgHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(msgKey)))[..12];

        return $"{roundedTime:yyyyMMddHHmm}|{normalizedSource}|{msgHash}";
    }
}

// ─── Data Models ────────────────────────────────────────────────────────

/// <summary>
/// A single event unified from any source (Reliability Monitor, WER, Event Log).
/// Contains provenance info to track where it was originally reported.
/// </summary>
public sealed class UnifiedEvent
{
    public DateTime Timestamp { get; set; }
    public string Source { get; set; } = "";
    public string Category { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string Message { get; set; } = "";
    public string OriginalSource { get; set; } = "";  // Which source reported this first
    public List<string> AlsoReportedBy { get; set; } = new(); // Cross-source confirmation
}

/// <summary>
/// The final, deduplicated health digest sent to the Pulse AI engine weekly.
/// </summary>
public sealed class AggregatedHealthDigest
{
    public DateTimeOffset CapturedAt { get; set; }
    public int PeriodDays { get; set; }

    // Deduplicated error events from all sources
    public List<UnifiedEvent> Events { get; set; } = new();

    // Reliability Monitor stability score (1-10)
    public double StabilityIndex { get; set; }
    public string StabilityAssessment { get; set; } = "";

    // BSOD data
    public int BsodCount { get; set; }
    public bool HasRecentBsod { get; set; }
    public List<MinidumpInfo> Minidumps { get; set; } = new();

    // Driver install failures (unique to SetupAPI)
    public List<DriverInstallLog> DriverInstallFailures { get; set; } = new();

    // Windows Update / servicing health (unique to CBS)
    public WindowsUpdateHealth WindowsUpdateHealth { get; set; } = new();

    // Aggregated stats
    public Dictionary<string, int> CrashSummary { get; set; } = new();
    public List<CrashingApp> TopCrashingApps { get; set; } = new();
}
