using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian;

namespace LogicFlow.CLI.Commands
{
    public static class SystemCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "status":
                    return HandleStatus(ctx);
                case "telemetry-dump":
                    return HandleTelemetryDump(ctx);
                case "health-check":
                    return HandleHealthCheck(ctx);
                case "trace":
                    return HandleTrace(ctx);
                case "optimize-all":
                    return HandleOptimizeAll(ctx);
                case "smart-health":
                    return HandleSmartHealth(ctx);
                case "apply-safe-tweaks":
                    return HandleApplySafeTweaks(ctx);
                case "run-all-scans":
                    return HandleRunAllScans(ctx);
                case "turbo":
                    return HandleTurbo(ctx);
                case "standby-purge":
                    return HandleStandbyPurge(ctx);
                case "shader-clean":
                    return HandleShaderClean(ctx);
                case "boot-analyze":
                    return HandleBootAnalyze(ctx);
                case "vss-list":
                    return HandleVssList(ctx);
                case "vss-browse":
                    return HandleVssBrowse(ctx);
                case "vss-restore":
                    return HandleVssRestore(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown sys command: '{command}'. Available: status, telemetry-dump, health-check, trace, optimize-all, smart-health, apply-safe-tweaks, run-all-scans, turbo, standby-purge, shader-clean, boot-analyze, vss-list, vss-browse, vss-restore", new { error = "UNKNOWN_COMMAND", group = "sys", command });
                    return 1;
            }
        }

        private static int HandleStatus(CliContext ctx)
        {
            var payload = new { status = "OPERATIONAL", lastScan = DateTime.UtcNow };
            OutputFormatter.Write(ctx, "[OK] Core Daemon Operational.", payload, ConsoleColor.Green);
            return 0;
        }

        private static int HandleTelemetryDump(CliContext ctx)
        {
            try
            {
                var engine = new SystemInfoEngine();
                var snapshot = engine.CollectSnapshot();
                int totalThreads = 0;
                try
                {
                    totalThreads = Process.GetProcesses().Sum(p => { try { return p.Threads.Count; } catch { return 0; } });
                }
                catch { }

                var payload = new
                {
                    cpuName = snapshot.CpuName,
                    cpuCores = snapshot.CpuCores,
                    cpuThreads = snapshot.CpuThreads,
                    cpuUsage = snapshot.CpuUsagePercent,
                    memoryUsageMb = Math.Round((snapshot.TotalRamBytes - snapshot.AvailableRamBytes) / (1024.0 * 1024.0), 0),
                    totalMemoryMb = Math.Round(snapshot.TotalRamBytes / (1024.0 * 1024.0), 0),
                    threadCount = totalThreads,
                    osVersion = $"{snapshot.OsName} ({snapshot.OsBuild})",
                    uptime = snapshot.UptimeFormatted,
                    gpu = snapshot.GpuName,
                    disks = snapshot.Disks.Select(d => new { d.Name, d.TotalBytes, d.FreeBytes, d.UsagePercent }).ToList()
                };

                OutputFormatter.Write(ctx, $"[TELEMETRY] CPU: {snapshot.CpuUsagePercent:F1}% ({snapshot.CpuName}) | RAM: {snapshot.UsedRamFormatted} / {snapshot.TotalRamFormatted} | Threads: {totalThreads} | OS: {snapshot.OsName}", payload, ConsoleColor.DarkCyan);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Telemetry gathering failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleHealthCheck(CliContext ctx)
        {
            try
            {
                var sysInfo = new SystemInfoEngine();
                var snapshot = sysInfo.CollectSnapshot();

                var disk = snapshot.Disks.FirstOrDefault();
                double diskUsage = disk?.UsagePercent ?? 0;

                var startup = new StartupOptimizer(null!);
                var startupItems = startup.AnalyzeStartupItems();
                int highImpactStartups = startupItems.Count(i => i.ImpactScore >= 7);

                var tweakEngine = new WindowsTweakEngine();
                int unappliedSafeTweaks = tweakEngine.AllTweaks.Count(t => t.Safety == SafetyLevel.Safe && !t.IsApplied);

                var health = OneClickMaintenance.HealthScore.Calculate(
                    snapshot.RamUsagePercent,
                    diskUsage,
                    junkFilesMB: 0,
                    registryIssues: 0,
                    unappliedSafeTweaks: unappliedSafeTweaks,
                    highImpactStartups: highImpactStartups
                );

                var payload = new
                {
                    overallScore = health.Score,
                    grade = health.Grade.ToString(),
                    ramUsagePercent = snapshot.RamUsagePercent,
                    diskUsagePercent = diskUsage,
                    highImpactStartups = highImpactStartups,
                    unappliedSafeTweaks = unappliedSafeTweaks,
                    optimal = health.Score >= 80
                };

                OutputFormatter.Write(ctx, $"[HEALTH] System Health Audit Complete: {health.Display}. RAM: {snapshot.RamUsagePercent:F1}%, Disk: {diskUsage:F1}%, High-Impact Startups: {highImpactStartups}.", payload, health.Score >= 80 ? ConsoleColor.Green : ConsoleColor.Yellow);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Health check failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleTrace(CliContext ctx)
        {
            if (ctx.RemainingArgs.Length < 3) 
            {
                OutputFormatter.WriteError(ctx, "Usage: lf sys trace <process_id_or_name>", new { error = "MISSING_ARG_PROCESS" });
                return 1;
            }
            string procTarget = ctx.RemainingArgs[2];

            try
            {
                Process? targetProc = null;
                if (int.TryParse(procTarget, out int pid))
                {
                    try { targetProc = Process.GetProcessById(pid); } catch { }
                }

                if (targetProc == null)
                {
                    var matches = Process.GetProcessesByName(procTarget.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? procTarget[..^4] : procTarget);
                    if (matches.Length > 0) targetProc = matches[0];
                }

                if (targetProc == null)
                {
                    var all = Process.GetProcesses();
                    targetProc = all.FirstOrDefault(p => p.ProcessName.Contains(procTarget, StringComparison.OrdinalIgnoreCase));
                }

                if (targetProc == null)
                {
                    OutputFormatter.WriteError(ctx, $"Process '{procTarget}' not found.", new { error = "PROCESS_NOT_FOUND", target = procTarget });
                    return 1;
                }

                var payload = new
                {
                    status = "TRACED",
                    processName = targetProc.ProcessName,
                    pid = targetProc.Id,
                    workingSetMB = Math.Round(targetProc.WorkingSet64 / (1024.0 * 1024.0), 1),
                    privateBytesMB = Math.Round(targetProc.PrivateMemorySize64 / (1024.0 * 1024.0), 1),
                    threads = targetProc.Threads.Count,
                    responding = targetProc.Responding
                };

                OutputFormatter.Write(ctx, $"[TRACE] Process '{targetProc.ProcessName}' (PID: {targetProc.Id}) — Working Set: {payload.workingSetMB} MB, Threads: {payload.threads}, Responding: {targetProc.Responding}", payload, ConsoleColor.Magenta);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to trace process '{procTarget}': {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleOptimizeAll(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[SYS] Executing 1-Click System Optimization...", null, ConsoleColor.Yellow);
                var engine = new OneClickMaintenance();
                var exclusions = CliEditionGate.LoadScanExclusions(ctx.AppDataRootOverride);
                var cleaner = new JunkCleanerEngine { ExcludedPaths = exclusions.ToList() };
                var report = engine.Run(junkCleaner: cleaner, checkRegistry: false, optimizeMemory: true);

                var payload = new
                {
                    status = "SUCCESS",
                    junkFilesCleaned = report.JunkFilesCleaned,
                    junkBytesCleaned = report.JunkBytesCleaned,
                    startupItemsFound = report.StartupItemsFound,
                    highImpactStartupItems = report.HighImpactStartupItems,
                    safeTweaksApplied = report.SafeTweaksApplied,
                    tweaksAlreadyApplied = report.TweaksAlreadyApplied,
                    healthBefore = report.HealthScoreBefore,
                    healthAfter = report.HealthScoreAfter,
                    durationSeconds = report.Duration.TotalSeconds,
                    requiresReboot = report.RequiresReboot,
                    actions = report.Actions,
                    warnings = report.Warnings
                };

                OutputFormatter.Write(ctx, $"[SYS] 1-Click Maintenance Complete in {report.Duration.TotalSeconds:F1}s. Health: {report.HealthScoreBefore} -> {report.HealthScoreAfter}. {report.Summary}", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"1-Click Optimization failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleSmartHealth(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[SYS] Checking S.M.A.R.T Disk Health across all drives...", null, ConsoleColor.Yellow);
                var diskHealth = new SmartDiskHealth();
                var drives = diskHealth.ScanDrives();

                bool isAdmin = SmartDiskHealth.IsRunningAsAdmin();
                var payload = new
                {
                    status = "SUCCESS",
                    driveCount = drives.Count,
                    hasUnmeasuredDrives = drives.Any(d => d.HealthScore < 0),
                    requiresElevation = !isAdmin && drives.Any(d => d.HealthScore < 0),
                    drives = drives.Select(d => new
                    {
                        model = d.Model,
                        driveLetter = d.DriveLetter,
                        driveLetters = d.DriveLetters,
                        size = d.SizeFormatted,
                        status = d.Status.ToString(),
                        healthScore = d.HealthScore >= 0 ? (object)d.HealthScore : "Unmeasured",
                        healthGrade = d.HealthGrade,
                        temperatureC = d.Temperature > 0 ? (object)d.Temperature : "Unmeasured",
                        tempStatus = d.TempStatus.ToString(),
                        mediaType = d.MediaType,
                        ssdLifeRemaining = d.SsdLifeRemaining >= 0 ? (object)d.SsdLifeRemaining : "Unmeasured",
                        powerOnHours = d.PowerOnFormatted,
                        reallocatedSectors = d.ReallocatedSectors,
                        pendingSectors = d.PendingSectors,
                        uncorrectableErrors = d.UncorrectableErrors,
                        telemetrySource = d.HealthSummary.Contains("synchronized from elevated") ? "AgentService" : (isAdmin ? "DirectHardware" : "LimitedUserToken")
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[SYS] S.M.A.R.T scan completed for {drives.Count} drive(s):", payload, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var d in drives)
                    {
                        var col = d.Status == SmartDiskHealth.DiskHealthStatus.Healthy ? ConsoleColor.Green : (d.HealthScore < 0 ? ConsoleColor.DarkYellow : ConsoleColor.Red);
                        Console.ForegroundColor = col;
                        var scoreStr = d.HealthScore >= 0 ? $"{d.HealthScore}%" : "Unmeasured";
                        var tempStr = d.Temperature > 0 ? $"{d.Temperature}°C" : "Unmeasured";
                        Console.WriteLine($"  [{d.HealthGrade}] {d.Model} ({d.SizeFormatted}) — Health: {scoreStr}, Temp: {tempStr}, Status: {d.Status}");
                        Console.ResetColor();
                    }

                    if (drives.Any(d => d.HealthScore < 0) && !isAdmin)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("  💡 Tip: Direct physical drive S.M.A.R.T. telemetry requires Administrator privileges. Run with 'lf sys smart-health --elevate' or install the LogicFlow Agent background service.");
                        Console.ResetColor();
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"SMART Disk Health check failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleApplySafeTweaks(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[SYS] Applying safe Windows system tweaks...", null, ConsoleColor.Yellow);
                var engine = new WindowsTweakEngine();
                var results = engine.ApplyAllSafe();
                int successCount = results.Count(r => r.Success);
                bool rebootNeeded = engine.AllTweaks.Any(t => t.IsApplied && t.RequiresReboot);

                var payload = new
                {
                    status = "SUCCESS",
                    totalAttempted = results.Count,
                    successCount,
                    requiresReboot = rebootNeeded,
                    tweaks = results.Select(r => new { r.TweakId, r.TweakName, r.Success, r.Error }).ToList()
                };

                OutputFormatter.Write(ctx, $"[SYS] Applied {successCount} of {results.Count} safe Windows optimizations. Reboot required: {rebootNeeded}.", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Applying safe tweaks failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleRunAllScans(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[SYS] Triggering comprehensive full system scan across all engines...", null, ConsoleColor.Yellow);

                // 1. Junk scan
                var junkEngine = new JunkCleanerEngine();
                var junkScan = junkEngine.Scan();
                long totalJunkBytes = junkScan.Sum(j => j.TotalBytes);
                int totalJunkFiles = junkScan.Sum(j => j.FileCount);

                // 2. Registry scan
                var regAnalyzer = new LogicFlow.Registry.RegistryAnalyzer(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Registry.RegistryAnalyzer>.Instance);
                var regScan = regAnalyzer.Scan();

                // 3. Startup scan
                var startupOptimizer = new StartupOptimizer(null!);
                var startupItems = startupOptimizer.AnalyzeStartupItems();

                // 4. SMART disk health
                var diskHealth = new SmartDiskHealth();
                var disks = diskHealth.ScanDrives();

                // 5. Driver scan
                var driverAuditor = new DriverAuditorEngine();
                var driverReport = driverAuditor.AuditDrivers();

                var payload = new
                {
                    status = "SCAN_COMPLETE",
                    junk = new { filesFound = totalJunkFiles, totalBytes = totalJunkBytes, formatted = FormatBytes(totalJunkBytes) },
                    registry = new { totalIssues = regScan.TotalIssues, categorySummary = regScan.CategorySummary },
                    startup = new { totalItems = startupItems.Count, highImpact = startupItems.Count(i => i.ImpactScore >= 7) },
                    disks = new { count = disks.Count, healthy = disks.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Healthy) },
                    drivers = new { total = driverReport.TotalDrivers, outdated = driverReport.OutdatedCount, unsigned = driverReport.UnsignedCount, problemDevices = driverReport.ProblemDeviceCount }
                };

                OutputFormatter.Write(ctx, $"[SYS] Full Scan Complete: Junk: {FormatBytes(totalJunkBytes)} ({totalJunkFiles} files) | Registry: {regScan.TotalIssues} issues | Startup: {startupItems.Count} items | Disks: {disks.Count} | Drivers: {driverReport.TotalDrivers} ({driverReport.OutdatedCount} outdated).", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Comprehensive scan failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleTurbo(CliContext ctx)
        {
            string mode = CliEditionGate.ResolveTurboMode(ctx.RemainingArgs);
            if (!CliEditionGate.IsValidTurboMode(mode))
            {
                OutputFormatter.WriteError(ctx, "Invalid turbo mode. Must be on, gaming, streaming, rendering, benchmarking, minimum, work, battery, server, smart, status, or off.", new { error = "INVALID_MODE", mode });
                return 1;
            }

            try
            {
                var turbo = new TurboMode();
                if (mode == "status")
                {
                    var state = turbo.GetPersistedState();
                    bool active = state?.Active ?? false;
                    var statusPayload = new
                    {
                        turboMode = active ? state!.ProfileName : "off",
                        status = active ? "TURBO_ACTIVE" : "TURBO_INACTIVE",
                        active,
                        profile = state?.ProfileName,
                        activatedAtUtc = state?.ActivatedAtUtc,
                        stoppedServicesCount = state?.StoppedServices.Count ?? 0,
                        boostedProcessId = state?.BoostedProcessId ?? -1
                    };
                    string humanMsg = active
                        ? $"[TURBO] Active profile: {state!.ProfileName} (since {state.ActivatedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}, {state.StoppedServices.Count} services paused)."
                        : "[TURBO] Inactive. Standard Windows power scheme and background services are active.";
                    OutputFormatter.Write(ctx, humanMsg, statusPayload, active ? ConsoleColor.Green : ConsoleColor.Cyan);
                    return 0;
                }
                else if (mode == "off")
                {
                    var deactivateResult = turbo.Deactivate();
                    var payload = new { turboMode = "off", status = "TURBO_DISENGAGED", result = deactivateResult };
                    OutputFormatter.Write(ctx, "[TURBO] Turbo mode deactivated. Restored prior Windows power scheme, notification settings, and background services.", payload, ConsoleColor.Cyan);
                    return 0;
                }
                else
                {
                    TurboMode.TurboProfile profile;
                    string? smartRationale = null;
                    string? preBoostBottleneck = null;
                    string? postBoostSummary = null;
                    List<string>? excludedProcs = null;
                    bool usedAi = false;
                    TurboMode.TurboResult result;

                    if (mode is "smart" or "auto")
                    {
                        var rec = turbo.SelectAndApplySmartProfileAsync().GetAwaiter().GetResult();
                        profile = rec.Profile;
                        mode = rec.ProfileKey.ToLowerInvariant();
                        smartRationale = rec.Rationale;
                        preBoostBottleneck = rec.PreBoostBottleneck;
                        postBoostSummary = rec.PostBoostSummary;
                        excludedProcs = rec.DynamicExcludedProcesses;
                        usedAi = rec.UsedAiEngine;
                        result = rec.ActivationResult ?? turbo.Activate(profile);
                    }
                    else
                    {
                        profile = TurboMode.GetProfileByName(mode);
                        result = turbo.Activate(profile);
                    }

                    var payload = new
                    {
                        turboMode = mode,
                        status = "TURBO_ENGAGED",
                        profile = profile.Name,
                        smartRationale,
                        preBoostBottleneck,
                        postBoostSummary,
                        excludedProcesses = excludedProcs,
                        usedAiEngine = usedAi,
                        activated = result.Activated,
                        servicesDisabled = result.ServicesDisabled,
                        processesKilled = result.ProcessesKilled,
                        memoryFreed = result.MemoryFreedFormatted,
                        actions = result.Actions
                    };

                    var prefixMsg = smartRationale != null
                        ? $"[SMART BOOST] Selected {profile.Name} ({smartRationale}) [{preBoostBottleneck}] -> "
                        : "[TURBO] ";

                    OutputFormatter.Write(ctx, $"{prefixMsg}Engaged {profile.Name}: {result.ServicesDisabled} services stopped, {result.ProcessesKilled} processes stopped, {result.MemoryFreedFormatted} RAM freed.", payload, ConsoleColor.Cyan);
                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        foreach (var action in result.Actions)
                        {
                            Console.WriteLine($"  {action}");
                        }
                        if (result.ServicesDisabled == 0 && profile.ServicesToStop.Length > 0 && !SmartDiskHealth.IsRunningAsAdmin())
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("  💡 Tip: To suspend background Windows services and boost GPU scheduling priority, run with '--elevate'.");
                            Console.ResetColor();
                        }
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to toggle Turbo mode: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleStandbyPurge(CliContext ctx)
        {
            var mem = new MemoryOptimizer();
            var result = mem.Optimize();
            double freedMB = result.TotalMemoryFreedBytes / (1024.0 * 1024.0);
            double beforeMB = result.Before.UsedPhysicalBytes / (1024.0 * 1024.0);
            double afterMB = result.After.UsedPhysicalBytes / (1024.0 * 1024.0);

            var payload = new
            {
                freedMB = freedMB,
                beforeMB = beforeMB,
                afterMB = afterMB,
                processesOptimized = result.ProcessesOptimized,
                standbyListCleared = result.StandbyListCleared,
                isAdmin = result.IsAdmin
            };

            OutputFormatter.Write(ctx, $"[MEMORY] Standby List & Working Sets purged: {freedMB:F1} MB freed ({beforeMB:F0} MB -> {afterMB:F0} MB in use).", payload, ConsoleColor.Green);
            return 0;
        }

        private static int HandleShaderClean(CliContext ctx)
        {
            var cleaner = new JunkCleanerEngine();
            var scan = cleaner.Scan();
            var shaderItem = scan.FirstOrDefault(s => s.Category == JunkCleanerEngine.JunkCategory.GpuShaderCache);

            if (shaderItem == null || shaderItem.FileCount == 0)
            {
                OutputFormatter.Write(ctx, "[SHADER] GPU shader caches are already clean.", new { cleanedBytes = 0 }, ConsoleColor.Green);
                return 0;
            }

            var cleanResult = cleaner.Clean(new List<JunkCleanerEngine.JunkScanResult> { shaderItem });
            OutputFormatter.Write(ctx, $"[SHADER] Cleaned {cleanResult.FilesDeleted} shader cache files ({cleanResult.BytesCleanedFormatted}).", new { files = cleanResult.FilesDeleted, bytes = cleanResult.BytesCleaned }, ConsoleColor.Green);
            return 0;
        }

        private static int HandleBootAnalyze(CliContext ctx)
        {
            try
            {
                var analyzer = new BootPerformanceAnalyzer();
                var report = analyzer.Analyze();

                var payload = new
                {
                    status = "SUCCESS",
                    telemetrySource = report.TelemetrySource,
                    usedFallbackSynthesis = report.UsedFallbackSynthesis,
                    lastBootTimeUtc = report.LastBootTimeUtc,
                    totalBootTimeMs = report.TotalBootTimeMs,
                    totalBootSeconds = report.TotalBootSeconds,
                    mainPathBootTimeMs = report.MainPathBootTimeMs,
                    mainPathSeconds = report.MainPathSeconds,
                    mainPathPercent = report.MainPathPercent,
                    postBootTimeMs = report.PostBootTimeMs,
                    postBootSeconds = report.PostBootSeconds,
                    postBootPercent = report.PostBootPercent,
                    criticalPathEntries = report.CriticalPathEntries.Select(e => new
                    {
                        eventId = e.EventId,
                        name = e.Name,
                        friendlyName = e.FriendlyName,
                        path = e.Path,
                        phase = e.Phase,
                        durationMs = e.DurationMs,
                        degradationMs = e.DegradationMs,
                        percentOfBoot = e.PercentOfBoot,
                        barWidthPx = e.BarWidthPx,
                        severity = e.Severity,
                        colorHex = e.ColorHex
                    }).ToList()
                };

                OutputFormatter.Write(
                    ctx,
                    $"[BOOT FLAMEGRAPH] Total Boot: {report.TotalBootSeconds:F2}s ({report.TotalBootTimeMs:N0} ms) | Main Path (Kernel/Drivers): {report.MainPathSeconds:F2}s ({report.MainPathPercent:F1}%) | Post-Boot (Apps): {report.PostBootSeconds:F2}s ({report.PostBootPercent:F1}%) | Critical Path Entries: {report.CriticalPathEntries.Count} [{report.TelemetrySource}]",
                    payload,
                    ConsoleColor.Cyan);

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var entry in report.CriticalPathEntries.Take(10))
                    {
                        Console.ForegroundColor = entry.DurationMs > 2000 ? ConsoleColor.Red : (entry.DurationMs >= 500 ? ConsoleColor.Yellow : ConsoleColor.Cyan);
                        Console.WriteLine($"  [{entry.Phase,-14}] {entry.Name,-30} {entry.DurationMs,6:N0} ms ({entry.PercentOfBoot,4:F1}%) — {entry.FriendlyName}");
                        Console.ResetColor();
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Boot critical-path analysis failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleVssList(CliContext ctx)
        {
            try
            {
                var engine = new SystemRestoreEngine();
                var shadows = engine.ListShadowCopies();

                var payload = new
                {
                    status = "SUCCESS",
                    count = shadows.Count,
                    shadows = shadows.Select(s => new
                    {
                        index = s.Index,
                        shadowId = s.ShadowId,
                        deviceObject = s.DeviceObject,
                        volumeName = s.VolumeName,
                        installDate = s.InstallDate,
                        description = s.Description
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[VSS] Discovered {shadows.Count} Volume Shadow Copy snapshot(s).", payload, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var s in shadows)
                    {
                        Console.WriteLine($"  #{s.Index}: {s.InstallDate:yyyy-MM-dd HH:mm:ss} | {s.VolumeName} | {s.DeviceObject}");
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"VSS snapshot listing failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleVssBrowse(CliContext ctx)
        {
            try
            {
                var posArgs = ctx.RemainingArgs
                    .Where(a => !a.StartsWith("-") &&
                                !a.Equals("sys", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("system", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("toolbox", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("vss-browse", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (posArgs.Count == 0)
                {
                    OutputFormatter.WriteError(ctx, "Usage: lf sys vss-browse <shadowDeviceOrIndex> [relativePath]", new { error = "MISSING_SHADOW_TARGET" });
                    return 1;
                }

                var engine = new SystemRestoreEngine();
                var (targetDevice, liveRoot) = ResolveShadowTarget(engine, posArgs[0]);
                string relativePath = posArgs.Count > 1 ? posArgs[1] : "";

                var entries = engine.BrowseShadowCopyDirectory(targetDevice, relativePath, liveRoot);
                var payload = new
                {
                    status = "SUCCESS",
                    deviceObject = targetDevice,
                    relativePath,
                    entryCount = entries.Count,
                    deletedOnLiveCount = entries.Count(e => e.DiffStatus == VssDiffStatus.DeletedOnLiveDisk),
                    modifiedCount = entries.Count(e => e.DiffStatus == VssDiffStatus.ModifiedSinceSnapshot),
                    entries = entries.Select(e => new
                    {
                        name = e.Name,
                        relativePath = e.RelativePath,
                        isDirectory = e.IsDirectory,
                        sizeBytes = e.SizeBytes,
                        sizeFormatted = e.SizeFormatted,
                        diffStatus = e.DiffStatus.ToString(),
                        statusBadge = e.StatusBadge
                    }).ToList()
                };

                OutputFormatter.Write(
                    ctx,
                    $"[VSS BROWSE] {targetDevice}\\{relativePath} — {entries.Count} item(s) ({payload.deletedOnLiveCount} deleted on live disk, {payload.modifiedCount} modified).",
                    payload,
                    ConsoleColor.Cyan);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"VSS snapshot browse failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleVssRestore(CliContext ctx)
        {
            try
            {
                bool overwrite = ctx.IsForce || ctx.RemainingArgs.Any(a => a.Equals("--overwrite", StringComparison.OrdinalIgnoreCase));
                var posArgs = ctx.RemainingArgs
                    .Where(a => !a.StartsWith("-") &&
                                !a.Equals("sys", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("system", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("toolbox", StringComparison.OrdinalIgnoreCase) &&
                                !a.Equals("vss-restore", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (posArgs.Count < 3)
                {
                    OutputFormatter.WriteError(ctx, "Usage: lf sys vss-restore <shadowDeviceOrIndex> <relativePath> <destinationPath> [--overwrite|--force]", new { error = "MISSING_VSS_RESTORE_ARGS" });
                    return 1;
                }

                var engine = new SystemRestoreEngine();
                var (targetDevice, _) = ResolveShadowTarget(engine, posArgs[0]);
                string relativePath = posArgs[1];
                string destPath = posArgs[2];

                var res = engine.RestoreFileFromShadowCopy(targetDevice, relativePath, destPath, overwrite);
                var payload = new
                {
                    status = res.Success ? "SUCCESS" : "FAILED",
                    sourceShadowPath = res.SourceShadowPath,
                    destinationPath = res.DestinationPath,
                    filesRestored = res.FilesRestored,
                    bytesRestored = res.BytesRestored,
                    message = res.Message
                };

                if (!res.Success)
                {
                    OutputFormatter.WriteError(ctx, $"[VSS RESTORE] {res.Message}", payload);
                    return 1;
                }

                OutputFormatter.Write(ctx, $"[VSS RESTORE] {res.Message}", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"VSS file restore failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static (string DeviceObject, string LiveVolumeRoot) ResolveShadowTarget(SystemRestoreEngine engine, string deviceOrIndex)
        {
            string defaultRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            if (int.TryParse(deviceOrIndex, out int idx))
            {
                var shadows = engine.ListShadowCopies();
                var match = shadows.FirstOrDefault(s => s.Index == idx);
                if (match != null)
                    return (match.DeviceObject, SystemRestoreEngine.NormalizeLiveVolumeRoot(match.VolumeName));
                return ($@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{idx}", defaultRoot);
            }
            return (deviceOrIndex, defaultRoot);
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
}
