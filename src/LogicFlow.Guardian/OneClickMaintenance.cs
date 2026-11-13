// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – OneClickMaintenance
// Orchestrates all cleanup engines for a single "1-Click Optimize" experience.
// Inspired by TuneUp Utilities 2003's signature feature.
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// One-Click Maintenance — runs all cleanup and optimization engines
/// in sequence and returns a unified report. The classic "Fix All" button.
/// </summary>
public sealed class OneClickMaintenance
{
    private readonly ILogger<OneClickMaintenance>? _logger;

    public OneClickMaintenance(ILogger<OneClickMaintenance>? logger = null)
    {
        _logger = logger;
    }

    // ─── Result Model ────────────────────────────────────────────────────

    public sealed class MaintenanceReport
    {
        public DateTimeOffset StartedAt { get; init; }
        public DateTimeOffset CompletedAt { get; set; }
        public TimeSpan Duration => CompletedAt - StartedAt;

        // Junk Cleaner
        public long JunkBytesCleaned { get; set; }
        public int JunkFilesCleaned { get; set; }

        // Memory Optimizer
        public long MemoryFreedBytes { get; set; }

        // Registry (from LogicFlow.Registry)
        public int RegistryIssuesFound { get; set; }
        public int RegistryIssuesFixed { get; set; }

        // Startup
        public int StartupItemsFound { get; set; }
        public int HighImpactStartupItems { get; set; }

        // Tweaks
        public int SafeTweaksApplied { get; set; }
        public int TweaksAlreadyApplied { get; set; }

        // Overall
        public string HealthScoreBefore { get; set; } = "";
        public string HealthScoreAfter { get; set; } = "";
        public List<string> Actions { get; init; } = new();
        public List<string> Warnings { get; init; } = new();
        public bool RequiresReboot { get; set; }

        public string Summary => $"Freed {FormatBytes(JunkBytesCleaned)}, cleaned {JunkFilesCleaned} files, " +
            $"found {RegistryIssuesFound} registry issues, applied {SafeTweaksApplied} optimizations " +
            $"in {Duration.TotalSeconds:0.0}s";
    }

    // ─── Health Score Calculator ─────────────────────────────────────────

    public enum HealthGrade { Excellent, Good, Fair, Poor, Critical }

    public sealed class HealthScore
    {
        public int Score { get; init; } // 0-100
        public HealthGrade Grade { get; init; }
        public string Display => $"{Score}/100 ({Grade})";

        public static HealthScore Calculate(
            double ramUsagePercent,
            double diskUsagePercent,
            int junkFilesMB,
            int registryIssues,
            int unappliedSafeTweaks,
            int highImpactStartups)
        {
            int score = 100;

            // RAM pressure
            if (ramUsagePercent > 90) score -= 15;
            else if (ramUsagePercent > 80) score -= 8;
            else if (ramUsagePercent > 70) score -= 3;

            // Disk usage
            if (diskUsagePercent > 95) score -= 20;
            else if (diskUsagePercent > 90) score -= 12;
            else if (diskUsagePercent > 80) score -= 5;

            // Junk files
            if (junkFilesMB > 5000) score -= 15;
            else if (junkFilesMB > 1000) score -= 8;
            else if (junkFilesMB > 500) score -= 3;

            // Registry issues
            if (registryIssues > 200) score -= 10;
            else if (registryIssues > 50) score -= 5;
            else if (registryIssues > 10) score -= 2;

            // Unapplied safe tweaks
            score -= Math.Min(unappliedSafeTweaks, 10);

            // High-impact startup items
            score -= Math.Min(highImpactStartups * 2, 10);

            score = Math.Max(0, Math.Min(100, score));

            var grade = score switch
            {
                >= 90 => HealthGrade.Excellent,
                >= 75 => HealthGrade.Good,
                >= 55 => HealthGrade.Fair,
                >= 35 => HealthGrade.Poor,
                _ => HealthGrade.Critical
            };

            return new HealthScore { Score = score, Grade = grade };
        }
    }

    // ─── Run Full Maintenance ────────────────────────────────────────────

    /// <summary>
    /// Runs all maintenance tasks in sequence:
    /// 1. Calculate health score (before)
    /// 2. Junk file cleanup
    /// 3. Registry scan (report only — repair requires confirmation)
    /// 4. Startup analysis
    /// 5. Apply safe tweaks
    /// 6. Calculate health score (after)
    /// </summary>
    public MaintenanceReport Run(
        JunkCleanerEngine? junkCleaner = null,
        WindowsTweakEngine? tweakEngine = null,
        SystemInfoEngine? systemInfo = null,
        bool cleanJunk = true,
        bool checkRegistry = true,
        bool optimizeStartup = true,
        bool applyTweaks = true,
        MemoryOptimizer? memoryOptimizer = null,
        bool optimizeMemory = true,
        Func<int>? registryIssueScanner = null)
    {
        var report = new MaintenanceReport { StartedAt = DateTimeOffset.UtcNow };

        _logger?.LogInformation("═══ 1-Click Maintenance Starting (Junk={Junk}, Reg={Reg}, Startup={Startup}, Tweaks={Tweaks}, Mem={Mem}) ═══",
            cleanJunk, checkRegistry, optimizeStartup, applyTweaks, optimizeMemory);

        // Step 1: Junk Cleanup
        if (cleanJunk)
        {
            try
            {
                var cleaner = junkCleaner ?? new JunkCleanerEngine();
                var cleanResult = cleaner.QuickClean();
                report.JunkBytesCleaned = cleanResult.BytesCleaned;
                report.JunkFilesCleaned = cleanResult.FilesDeleted;
                report.Actions.Add($"🧹 Cleaned {cleanResult.FilesDeleted} junk files ({cleanResult.BytesCleanedFormatted})");

                if (cleanResult.FilesFailed > 0)
                    report.Warnings.Add($"{cleanResult.FilesFailed} files were locked (in use by another process)");
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"Junk cleanup partially failed: {ex.Message}");
                _logger?.LogWarning(ex, "Junk cleanup error");
            }
        }
        else
        {
            report.Actions.Add("⏭ Junk file cleanup skipped (unchecked)");
        }

        // Step 2: Registry Check (only report validation when an actual registry scanner ran)
        if (checkRegistry && registryIssueScanner != null)
        {
            try
            {
                int issues = Math.Max(0, registryIssueScanner());
                report.RegistryIssuesFound = issues;
                report.Actions.Add(issues == 0
                    ? "🔧 Registry scanned — 0 orphaned issues detected"
                    : $"🔧 Registry scanned — {issues} issue(s) flagged for review");
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"Registry scan failed: {ex.Message}");
            }
        }
        else if (!checkRegistry)
        {
            report.Actions.Add("⏭ Registry check skipped (unchecked)");
        }

        // Step 2b: Memory Working-Set & Standby Optimization
        if (optimizeMemory)
        {
            try
            {
                var memOpt = memoryOptimizer ?? new MemoryOptimizer();
                var memResult = memOpt.Optimize();
                report.MemoryFreedBytes = Math.Max(0, memResult.TotalMemoryFreedBytes);
                report.Actions.Add($"💾 Optimized RAM working sets ({memResult.ProcessesOptimized} processes, {memResult.MemoryFreedFormatted} reclaimed)");
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"Memory optimization partially failed: {ex.Message}");
            }
        }

        // Step 3: Startup Analysis
        if (optimizeStartup)
        {
            try
            {
                var startup = new StartupOptimizer(null!);
                var items = startup.AnalyzeStartupItems();
                report.StartupItemsFound = items.Count;
                report.HighImpactStartupItems = items.Count(i => i.ImpactScore >= 7);
                report.Actions.Add($"🚀 Analyzed {items.Count} startup items ({report.HighImpactStartupItems} high-impact)");
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"Startup analysis failed: {ex.Message}");
            }
        }
        else
        {
            report.Actions.Add("⏭ Startup optimization skipped (unchecked)");
        }

        // Step 4: Apply Safe Tweaks
        if (applyTweaks)
        {
            try
            {
                var engine = tweakEngine ?? new WindowsTweakEngine();
                var safeTweaks = engine.AllTweaks.Where(t => t.Safety == SafetyLevel.Safe).ToList();
                report.TweaksAlreadyApplied = safeTweaks.Count(t => t.IsApplied);

                var results = engine.ApplyAllSafe();
                report.SafeTweaksApplied = results.Count(r => r.Success);
                report.RequiresReboot = engine.AllTweaks.Any(t => t.IsApplied && t.RequiresReboot);

                if (report.SafeTweaksApplied > 0)
                    report.Actions.Add($"⚡ Applied {report.SafeTweaksApplied} safe Windows optimizations");
                else
                    report.Actions.Add($"✅ All {report.TweaksAlreadyApplied} safe optimizations already active");
            }
            catch (Exception ex)
            {
                report.Warnings.Add($"Tweak application failed: {ex.Message}");
            }
        }
        else
        {
            report.Actions.Add("⏭ Safe Windows optimizations skipped (unchecked)");
        }

        // Step 5: Calculate health scores
        try
        {
            var sysInfo = systemInfo ?? new SystemInfoEngine();
            var snapshot = sysInfo.CollectSnapshot();

            var junkMB = (int)(report.JunkBytesCleaned / (1024 * 1024));
            var diskUsage = snapshot.Disks.FirstOrDefault()?.UsagePercent ?? 0;

            report.HealthScoreBefore = HealthScore.Calculate(
                snapshot.RamUsagePercent, diskUsage,
                junkMB, report.RegistryIssuesFound,
                report.SafeTweaksApplied, report.HighImpactStartupItems
            ).Display;

            report.HealthScoreAfter = HealthScore.Calculate(
                snapshot.RamUsagePercent, diskUsage,
                0, 0, 0, report.HighImpactStartupItems
            ).Display;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Health score calculation failed");
        }

        report.CompletedAt = DateTimeOffset.UtcNow;

        if (report.RequiresReboot)
            report.Warnings.Add("⚠️ Some optimizations require a system restart to take full effect.");

        _logger?.LogInformation("═══ 1-Click Maintenance Complete: {Summary} ═══", report.Summary);

        return report;
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
