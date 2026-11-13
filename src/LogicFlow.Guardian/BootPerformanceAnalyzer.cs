// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — BootPerformanceAnalyzer
// Boot-Time Critical Path Flamegraph & Diagnostics (Event IDs 100–110 in
// Microsoft-Windows-Diagnostics-Performance/Operational) with deterministic
// StartupOptimizer + ServiceController critical-path synthesis fallback.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LogicFlow.Guardian;

public sealed class BootPerformanceAnalyzer
{
    public const string OperationalLogName = "Microsoft-Windows-Diagnostics-Performance/Operational";

    private readonly ILogger<BootPerformanceAnalyzer>? _logger;
    private readonly StartupOptimizer _startupOptimizer;

    public BootPerformanceAnalyzer(
        ILogger<BootPerformanceAnalyzer>? logger = null,
        StartupOptimizer? startupOptimizer = null)
    {
        _logger = logger;
        _startupOptimizer = startupOptimizer ?? new StartupOptimizer(NullLogger<StartupOptimizer>.Instance);
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public sealed class BootCriticalPathEntry
    {
        public int EventId { get; init; }
        public string Name { get; init; } = "";
        public string FriendlyName { get; init; } = "";
        public string Path { get; init; } = "";
        public string Phase { get; init; } = "Startup App"; // "Kernel/Driver", "System Service", "Startup App"
        public long DurationMs { get; init; }
        public long DegradationMs { get; init; }
        public double PercentOfBoot { get; set; }
        public double BarWidthPx { get; set; }
        public string Severity => ClassifySeverity(DurationMs);
        public string ColorHex => GetSeverityColorHex(DurationMs);
        public string DurationFormatted => DurationMs >= 1000
            ? $"{DurationMs / 1000.0:F2} s ({DurationMs:N0} ms)"
            : $"{DurationMs:N0} ms";
    }

    public sealed class BootAnalysisReport
    {
        public string TelemetrySource { get; set; } = "Diagnostics-Performance/Operational";
        public bool UsedFallbackSynthesis { get; set; }
        public DateTime LastBootTimeUtc { get; set; }
        public int BootTsVersion { get; set; } = 2;
        public long TotalBootTimeMs { get; set; }
        public long MainPathBootTimeMs { get; set; }
        public long PostBootTimeMs { get; set; }
        public long DriverInitTimeMs { get; set; }
        public long ExplorerInitTimeMs { get; set; }
        public double TotalBootSeconds => Math.Round(TotalBootTimeMs / 1000.0, 2);
        public double MainPathSeconds => Math.Round(MainPathBootTimeMs / 1000.0, 2);
        public double PostBootSeconds => Math.Round(PostBootTimeMs / 1000.0, 2);
        public double MainPathPercent => TotalBootTimeMs > 0
            ? Math.Round((double)MainPathBootTimeMs / TotalBootTimeMs * 100.0, 1)
            : 55.0;
        public double PostBootPercent => TotalBootTimeMs > 0
            ? Math.Round(100.0 - MainPathPercent, 1)
            : 45.0;
        public List<BootCriticalPathEntry> CriticalPathEntries { get; set; } = new();
    }

    // ─── Analyze Boot Critical Path ──────────────────────────────────────

    public BootAnalysisReport Analyze(double maxBarWidthPx = 420.0)
    {
        var report = new BootAnalysisReport
        {
            LastBootTimeUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64)
        };

        try
        {
            string xpath = "*[System[(EventID >= 100 and EventID <= 110)]]";
            var query = new EventLogQuery(OperationalLogName, PathType.LogName, xpath)
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            bool foundEvent100 = false;
            var entries = new List<BootCriticalPathEntry>();
            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int recordsRead = 0;

            for (EventRecord? record = reader.ReadEvent();
                 record != null && recordsRead < 200 && (!foundEvent100 || entries.Count < 40);
                 record = reader.ReadEvent(), recordsRead++)
            {
                using (record)
                {
                    string xml = record.ToXml();
                    if (record.Id == 100 && !foundEvent100)
                    {
                        if (TryParseEvent100Xml(xml, record.TimeCreated?.ToUniversalTime(), report))
                        {
                            foundEvent100 = true;
                        }
                    }
                    else if (record.Id is >= 101 and <= 110 && entries.Count < 40)
                    {
                        var parsed = TryParseDegradationEventXml(xml, record.Id);
                        if (parsed != null && seenNames.Add($"{parsed.Phase}:{parsed.Name}"))
                        {
                            entries.Add(parsed);
                        }
                    }
                }
            }

            if (foundEvent100 || entries.Count > 0)
            {
                if (entries.Count == 0)
                {
                    entries.AddRange(SynthesizePhaseEntriesFromSummary(report));
                }

                if (!foundEvent100)
                {
                    long sumMs = entries.Sum(e => e.DurationMs);
                    report.MainPathBootTimeMs = Math.Max(3500, (long)(sumMs * 0.55));
                    report.PostBootTimeMs = Math.Max(2500, (long)(sumMs * 0.45));
                    report.TotalBootTimeMs = report.MainPathBootTimeMs + report.PostBootTimeMs;
                }

                report.CriticalPathEntries = entries
                    .OrderByDescending(e => e.DurationMs)
                    .ToList();

                PopulateFlamegraphMetrics(report, maxBarWidthPx);
                return report;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Operational boot diagnostics log unavailable; synthesizing critical path from StartupOptimizer and Services.");
        }

        return BuildFallbackReport(maxBarWidthPx);
    }

    // ─── Event XML Parsing (Testable & Deterministic) ────────────────────

    public static bool TryParseEvent100Xml(string eventXml, DateTime? timeCreatedUtc, BootAnalysisReport targetReport)
    {
        if (string.IsNullOrWhiteSpace(eventXml) || targetReport is null)
            return false;

        try
        {
            var doc = XDocument.Parse(eventXml);
            var dataMap = ExtractEventDataDictionary(doc);

            long bootTime = GetLong(dataMap, "BootTime");
            long mainPath = GetLong(dataMap, "MainPathBootTime");
            long postBoot = GetLong(dataMap, "BootPostBootTime");
            long driverInit = GetLong(dataMap, "BootDriverInitTime");
            long explorerInit = GetLong(dataMap, "BootExplorerInitTime");
            int tsVersion = (int)GetLong(dataMap, "BootTsVersion", 2);

            if (bootTime <= 0 && mainPath <= 0 && postBoot <= 0)
                return false;

            if (bootTime <= 0)
                bootTime = mainPath + postBoot;
            if (mainPath <= 0 && bootTime > postBoot)
                mainPath = bootTime - postBoot;
            if (postBoot <= 0 && bootTime > mainPath)
                postBoot = bootTime - mainPath;

            targetReport.TotalBootTimeMs = bootTime;
            targetReport.MainPathBootTimeMs = mainPath;
            targetReport.PostBootTimeMs = postBoot;
            targetReport.DriverInitTimeMs = driverInit;
            targetReport.ExplorerInitTimeMs = explorerInit;
            targetReport.BootTsVersion = tsVersion > 0 ? tsVersion : 2;
            if (timeCreatedUtc.HasValue)
                targetReport.LastBootTimeUtc = timeCreatedUtc.Value;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static BootCriticalPathEntry? TryParseDegradationEventXml(string eventXml, int eventId = 101)
    {
        if (string.IsNullOrWhiteSpace(eventXml))
            return null;

        try
        {
            var doc = XDocument.Parse(eventXml);
            var dataMap = ExtractEventDataDictionary(doc);

            string name = GetString(dataMap, "Name", "FileName", "ServiceName", "DriverName", "AppName");
            string friendly = GetString(dataMap, "FriendlyName", "DisplayName", "Description");
            string path = GetString(dataMap, "Path", "FilePath", "ImagePath");

            long totalTime = GetLong(dataMap, "TotalTime", 0);
            long degTime = GetLong(dataMap, "DegradationTime", 0);
            long duration = Math.Max(totalTime, degTime);

            if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(path))
                name = Path.GetFileName(path);
            if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(friendly))
                name = friendly;
            if (string.IsNullOrWhiteSpace(name) || duration <= 0)
                return null;

            string phase = ClassifyPhase(eventId, name, path);

            return new BootCriticalPathEntry
            {
                EventId = eventId,
                Name = name,
                FriendlyName = string.IsNullOrWhiteSpace(friendly) ? name : friendly,
                Path = path,
                Phase = phase,
                DurationMs = duration,
                DegradationMs = degTime > 0 ? degTime : duration
            };
        }
        catch
        {
            return null;
        }
    }

    public static void PopulateFlamegraphMetrics(BootAnalysisReport report, double maxBarWidthPx = 420.0)
    {
        if (report is null || report.CriticalPathEntries.Count == 0)
            return;

        double clampedMaxPx = Math.Max(40.0, maxBarWidthPx);
        long maxEntryMs = Math.Max(1L, report.CriticalPathEntries.Max(e => e.DurationMs));
        long totalBootMs = Math.Max(report.TotalBootTimeMs, maxEntryMs);

        foreach (var entry in report.CriticalPathEntries)
        {
            entry.PercentOfBoot = Math.Round((double)entry.DurationMs / totalBootMs * 100.0, 1);
            double rawPx = ((double)entry.DurationMs / maxEntryMs) * clampedMaxPx;
            entry.BarWidthPx = Math.Round(Math.Clamp(rawPx, 18.0, clampedMaxPx), 1);
        }
    }

    public static string ClassifySeverity(long durationMs)
    {
        if (durationMs > 2000) return "Critical";
        if (durationMs >= 500) return "Moderate";
        return "Fast";
    }

    public static string GetSeverityColorHex(long durationMs)
    {
        if (durationMs > 2000) return "#EF4444"; // Red (>2000ms)
        if (durationMs >= 500) return "#F59E0B";  // Amber (500–2000ms)
        return "#00E5FF";                         // Cyan (<500ms)
    }

    public static string ClassifyPhase(int eventId, string name, string path)
    {
        string lowerName = (name ?? "").ToLowerInvariant();
        string lowerPath = (path ?? "").ToLowerInvariant();

        if (eventId is 102 or 106 or 107 || lowerName.EndsWith(".sys") || lowerPath.Contains(@"\drivers\"))
            return "Kernel/Driver";

        if (eventId is 103 or 108 or 109 || lowerName.Contains("svc") || lowerName.Contains("service"))
            return "System Service";

        return "Startup App";
    }

    // ─── Fallback Synthesis ──────────────────────────────────────────────

    public BootAnalysisReport BuildFallbackReport(double maxBarWidthPx = 420.0)
    {
        var entries = new List<BootCriticalPathEntry>();

        // 1. Baseline Kernel / Driver initialization stages
        entries.Add(new BootCriticalPathEntry
        {
            EventId = 102,
            Name = "ntoskrnl.exe & Boot Drivers",
            FriendlyName = "Windows Kernel & Storage/GPU Boot Drivers (NVMe/PCIe/DXGKrnl)",
            Path = Path.Combine(Environment.SystemDirectory, "ntoskrnl.exe"),
            Phase = "Kernel/Driver",
            DurationMs = 2450,
            DegradationMs = 420
        });

        entries.Add(new BootCriticalPathEntry
        {
            EventId = 100,
            Name = "smss.exe / winlogon.exe / explorer.exe",
            FriendlyName = "Session Manager, Winlogon & Explorer Shell Initialization",
            Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
            Phase = "System Service",
            DurationMs = 1680,
            DegradationMs = 310
        });

        // 2. Startup applications from StartupOptimizer
        try
        {
            var startupItems = _startupOptimizer.AnalyzeStartupItems();
            foreach (var item in startupItems.Take(10))
            {
                long estimatedMs = item.ImpactScore switch
                {
                    >= 8 => 2350,
                    7 => 1650,
                    >= 5 => 920,
                    4 => 580,
                    _ => 320
                };

                entries.Add(new BootCriticalPathEntry
                {
                    EventId = 101,
                    Name = item.Name,
                    FriendlyName = $"{item.Name} ({item.Source})",
                    Path = item.Command,
                    Phase = "Startup App",
                    DurationMs = estimatedMs,
                    DegradationMs = Math.Max(100, estimatedMs - 250)
                });
            }
        }
        catch { }

        // 3. Running non-core Windows services
        try
        {
            var notableServices = new (string ServiceName, string Label, long EstMs)[]
            {
                ("WinDefend", "Microsoft Defender Antivirus Service", 840),
                ("WSearch", "Windows Search Indexer", 720),
                ("SysMain", "SysMain / Superfetch Prefetcher", 610),
                ("Spooler", "Print Spooler Service", 340),
                ("DiagTrack", "Connected User Experiences and Telemetry", 480)
            };

            foreach (var (svcName, label, estMs) in notableServices)
            {
                try
                {
                    using var sc = new ServiceController(svcName);
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        entries.Add(new BootCriticalPathEntry
                        {
                            EventId = 103,
                            Name = svcName,
                            FriendlyName = label,
                            Path = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            Phase = "System Service",
                            DurationMs = estMs,
                            DegradationMs = Math.Max(80, estMs / 3)
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        entries = entries.OrderByDescending(e => e.DurationMs).ToList();

        long mainPathMs = entries
            .Where(e => e.Phase is "Kernel/Driver" or "System Service")
            .Sum(e => e.DurationMs);
        long postBootMs = entries
            .Where(e => e.Phase == "Startup App")
            .Sum(e => e.DurationMs);

        if (mainPathMs <= 0) mainPathMs = 4130;
        if (postBootMs <= 0) postBootMs = 2850;

        var report = new BootAnalysisReport
        {
            TelemetrySource = "Heuristic Startup & Service Critical-Path Synthesis",
            UsedFallbackSynthesis = true,
            LastBootTimeUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64),
            BootTsVersion = 2,
            MainPathBootTimeMs = mainPathMs,
            PostBootTimeMs = postBootMs,
            TotalBootTimeMs = mainPathMs + postBootMs,
            DriverInitTimeMs = 2450,
            ExplorerInitTimeMs = 1680,
            CriticalPathEntries = entries
        };

        PopulateFlamegraphMetrics(report, maxBarWidthPx);
        return report;
    }

    private static List<BootCriticalPathEntry> SynthesizePhaseEntriesFromSummary(BootAnalysisReport report)
    {
        var list = new List<BootCriticalPathEntry>();
        if (report.DriverInitTimeMs > 0)
        {
            list.Add(new BootCriticalPathEntry
            {
                EventId = 102,
                Name = "BootDriverInit",
                FriendlyName = "Kernel & Device Driver Initialization Phase",
                Path = Path.Combine(Environment.SystemDirectory, "drivers"),
                Phase = "Kernel/Driver",
                DurationMs = report.DriverInitTimeMs,
                DegradationMs = report.DriverInitTimeMs / 4
            });
        }

        if (report.MainPathBootTimeMs > report.DriverInitTimeMs)
        {
            long remMain = report.MainPathBootTimeMs - report.DriverInitTimeMs;
            list.Add(new BootCriticalPathEntry
            {
                EventId = 100,
                Name = "SessionAndServicesInit",
                FriendlyName = "Session Manager, Winlogon & Core System Services",
                Path = Environment.SystemDirectory,
                Phase = "System Service",
                DurationMs = remMain,
                DegradationMs = remMain / 4
            });
        }

        if (report.PostBootTimeMs > 0)
        {
            list.Add(new BootCriticalPathEntry
            {
                EventId = 101,
                Name = "PostBootDesktopApps",
                FriendlyName = "Desktop Shell & Auto-Start Applications",
                Path = Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Phase = "Startup App",
                DurationMs = report.PostBootTimeMs,
                DegradationMs = report.PostBootTimeMs / 3
            });
        }

        return list;
    }

    private static Dictionary<string, string> ExtractEventDataDictionary(XDocument doc)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dataElem in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
        {
            var nameAttr = dataElem.Attribute("Name")?.Value;
            if (!string.IsNullOrWhiteSpace(nameAttr))
            {
                dict[nameAttr] = dataElem.Value?.Trim() ?? "";
            }
        }
        return dict;
    }

    private static long GetLong(Dictionary<string, string> map, string key, long defaultValue = 0)
    {
        if (map.TryGetValue(key, out var raw) && long.TryParse(raw, out var val))
            return val;
        return defaultValue;
    }

    private static string GetString(Dictionary<string, string> map, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (map.TryGetValue(k, out var val) && !string.IsNullOrWhiteSpace(val))
                return val;
        }
        return string.Empty;
    }
}
