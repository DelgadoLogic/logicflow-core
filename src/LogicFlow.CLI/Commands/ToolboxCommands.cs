using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian;

namespace LogicFlow.CLI.Commands
{
    public static class ToolboxCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "game-compact":
                    return AppCommands.Run(ctx, "game-compact");
                case "file-shredder":
                    return HandleFileShredder(ctx);
                case "junk-clean":
                    return HandleJunkClean(ctx);
                case "optimize-ram":
                    return HandleOptimizeRam(ctx);
                case "disk-analyze":
                    return HandleDiskAnalyze(ctx);
                case "duplicate-scan":
                    return HandleDuplicateScan(ctx);
                case "browser-clean":
                    return HandleBrowserClean(ctx);
                case "vss-list":
                case "vss-browse":
                case "vss-restore":
                    return SystemCommands.Run(ctx, command);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown toolbox command: '{command}'. Available: game-compact, file-shredder, junk-clean, optimize-ram, disk-analyze, duplicate-scan, browser-clean, vss-list, vss-browse, vss-restore", new { error = "UNKNOWN_COMMAND", group = "toolbox", command });
                    return 1;
            }
        }

        private static int HandleFileShredder(CliContext ctx)
        {
            if (!ctx.IsForce)
            {
                OutputFormatter.WriteError(ctx, "Destructive action. You must supply --force to execute file shredder.", new { error = "MISSING_FORCE_FLAG" });
                return 1;
            }

            var files = new List<string>();
            var method = FileShredder.ShredMethod.DoD3Pass;

            for (int i = 0; i < ctx.RemainingArgs.Length; i++)
            {
                string arg = ctx.RemainingArgs[i];
                if (arg.Equals("--method", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                {
                    string m = ctx.RemainingArgs[++i].ToLowerInvariant();
                    method = m switch
                    {
                        "quick" or "quickzero" => FileShredder.ShredMethod.QuickZero,
                        "dod7" => FileShredder.ShredMethod.DoD7Pass,
                        "random" or "random3" => FileShredder.ShredMethod.Random3Pass,
                        _ => FileShredder.ShredMethod.DoD3Pass
                    };
                }
                else if (arg.Equals("--file", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                {
                    files.Add(ctx.RemainingArgs[++i]);
                }
                else if (!arg.StartsWith("-") && !arg.Equals("file-shredder", StringComparison.OrdinalIgnoreCase) && !arg.Equals("toolbox", StringComparison.OrdinalIgnoreCase))
                {
                    files.Add(arg);
                }
            }

            if (files.Count == 0)
            {
                OutputFormatter.WriteError(ctx, "Usage: lf toolbox file-shredder <file_path1> [file_path2...] --force [--method <quick|dod3|dod7|random>]", new { error = "MISSING_FILE_ARG" });
                return 1;
            }

            try
            {
                var shredder = new FileShredder();
                var result = shredder.Shred(files, method);

                var payload = new
                {
                    status = result.FilesFailed == 0 ? "SUCCESS" : (result.FilesShredded > 0 ? "PARTIAL_SUCCESS" : "FAILED"),
                    filesShredded = result.FilesShredded,
                    filesFailed = result.FilesFailed,
                    bytesOverwritten = result.TotalBytesOverwritten,
                    method = result.MethodUsed.ToString(),
                    errors = result.Errors
                };

                ConsoleColor color = result.FilesFailed == 0 ? ConsoleColor.Green : (result.FilesShredded > 0 ? ConsoleColor.Yellow : ConsoleColor.Red);
                OutputFormatter.Write(ctx, $"[SHREDDER] Securely shredded {result.FilesShredded} file(s) ({result.TotalBytesOverwritten:N0} bytes overwritten via {result.MethodUsed}). Failed: {result.FilesFailed}", payload, color);
                return (result.FilesFailed > 0 && result.FilesShredded == 0) ? 1 : 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"File shredder execution failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleJunkClean(CliContext ctx)
        {
            try
            {
                var cleaner = new JunkCleanerEngine
                {
                    ExcludedPaths = CliEditionGate.LoadScanExclusions(ctx.AppDataRootOverride)
                };
                var cleanResult = cleaner.QuickClean();

                var payload = new
                {
                    status = "SUCCESS",
                    filesDeleted = cleanResult.FilesDeleted,
                    filesFailed = cleanResult.FilesFailed,
                    bytesCleaned = cleanResult.BytesCleaned,
                    bytesCleanedFormatted = cleanResult.BytesCleanedFormatted,
                    errors = cleanResult.Errors
                };

                OutputFormatter.Write(ctx, $"[JUNK] Cleaned {cleanResult.FilesDeleted} junk files ({cleanResult.BytesCleanedFormatted}). Locked/skipped: {cleanResult.FilesFailed}", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Junk cleaning failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleOptimizeRam(CliContext ctx)
        {
            try
            {
                var optimizer = new MemoryOptimizer();
                var result = optimizer.Optimize();

                double freedMB = result.TotalMemoryFreedBytes / (1024.0 * 1024.0);
                double beforeMB = result.Before.UsedPhysicalBytes / (1024.0 * 1024.0);
                double afterMB = result.After.UsedPhysicalBytes / (1024.0 * 1024.0);

                var payload = new
                {
                    status = "SUCCESS",
                    freedMB = Math.Round(freedMB, 1),
                    beforeMB = Math.Round(beforeMB, 0),
                    afterMB = Math.Round(afterMB, 0),
                    processesOptimized = result.ProcessesOptimized,
                    standbyListCleared = result.StandbyListCleared,
                    isAdmin = result.IsAdmin
                };

                OutputFormatter.Write(ctx, $"[MEMORY] RAM optimization complete: {freedMB:F1} MB freed ({beforeMB:F0} MB -> {afterMB:F0} MB). Processes optimized: {result.ProcessesOptimized}.", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"RAM optimization failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleDiskAnalyze(CliContext ctx)
        {
            try
            {
                string targetDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

                for (int i = 0; i < ctx.RemainingArgs.Length; i++)
                {
                    string arg = ctx.RemainingArgs[i];
                    if (arg.Equals("--path", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        targetDrive = ctx.RemainingArgs[++i];
                    }
                    else if (!arg.StartsWith("-") && !arg.Equals("disk-analyze", StringComparison.OrdinalIgnoreCase) && !arg.Equals("toolbox", StringComparison.OrdinalIgnoreCase))
                    {
                        targetDrive = arg;
                    }
                }

                var analyzer = new DiskSpaceAnalyzer
                {
                    ExcludedPaths = CliEditionGate.LoadScanExclusions(ctx.AppDataRootOverride)
                };
                var report = analyzer.Analyze(targetDrive, maxDepth: 3, topFilesCount: 15);
                var treemapTiles = analyzer.ComputeTreemapLayout(report.RootNode, 1000, 600, maxDepth: 2);

                var payload = new
                {
                    status = "SUCCESS",
                    drive = report.DrivePath,
                    totalBytes = report.TotalBytes,
                    usedBytes = report.UsedBytes,
                    freeBytes = report.FreeBytes,
                    filesScanned = report.TotalFilesScanned,
                    foldersScanned = report.TotalFoldersScanned,
                    durationMs = report.ScanDuration.TotalMilliseconds,
                    largestFiles = report.LargestFiles.Select(f => new
                    {
                        path = f.Path,
                        sizeBytes = f.SizeBytes,
                        formatted = f.SizeFormatted
                    }).ToList(),
                    treemapTiles = treemapTiles.Select(t => new
                    {
                        name = t.Name,
                        fullPath = t.FullPath,
                        sizeBytes = t.SizeBytes,
                        formattedSize = t.FormattedSize,
                        category = t.Category,
                        colorHex = t.ColorHex,
                        x = Math.Round(t.X, 1),
                        y = Math.Round(t.Y, 1),
                        width = Math.Round(t.Width, 1),
                        height = Math.Round(t.Height, 1),
                        percentOfRoot = t.PercentOfRoot,
                        isDirectory = t.IsDirectory
                    }).ToList()
                };

                double usedGB = report.UsedBytes / (1024.0 * 1024.0 * 1024.0);
                double totalGB = report.TotalBytes / (1024.0 * 1024.0 * 1024.0);
                double freeGB = report.FreeBytes / (1024.0 * 1024.0 * 1024.0);

                OutputFormatter.Write(ctx, $"[DISK] Analyzed {report.DrivePath}: {report.TotalFilesScanned} files scanned ({report.ScanDuration.TotalSeconds:F1}s). Used: {usedGB:F1} GB / {totalGB:F1} GB. Free: {freeGB:F1} GB. Treemap tiles: {treemapTiles.Count}.", payload, ConsoleColor.Cyan);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Disk analysis failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleDuplicateScan(CliContext ctx)
        {
            try
            {
                string targetPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

                for (int i = 0; i < ctx.RemainingArgs.Length; i++)
                {
                    string arg = ctx.RemainingArgs[i];
                    if (arg.Equals("--path", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        targetPath = ctx.RemainingArgs[++i];
                    }
                    else if (!arg.StartsWith("-") && !arg.Equals("duplicate-scan", StringComparison.OrdinalIgnoreCase) && !arg.Equals("toolbox", StringComparison.OrdinalIgnoreCase))
                    {
                        targetPath = arg;
                    }
                }

                var finder = new DuplicateFileFinder();
                var report = finder.Scan(new[] { targetPath }, minSizeBytes: 1048576);

                var payload = new
                {
                    status = "SUCCESS",
                    scannedPath = targetPath,
                    totalFilesScanned = report.TotalFilesScanned,
                    duplicateGroups = report.Groups.Count,
                    totalDuplicates = report.TotalDuplicates,
                    totalWastedBytes = report.TotalWastedBytes,
                    wastedFormatted = report.WastedFormatted,
                    durationMs = report.ScanDuration.TotalMilliseconds
                };

                OutputFormatter.Write(ctx, $"[DUPLICATES] Scan complete for {targetPath}. Scanned: {report.TotalFilesScanned} files. Found {report.TotalDuplicates} duplicates across {report.Groups.Count} groups ({report.WastedFormatted} recoverable).", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Duplicate file scan failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleBrowserClean(CliContext ctx)
        {
            try
            {
                var engine = new BrowserPrivacyCleanerEngine();
                bool dryRun = ctx.RemainingArgs.Any(a => a.Equals("--dry-run", StringComparison.OrdinalIgnoreCase) || a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
                bool vacuum = !ctx.RemainingArgs.Any(a => a.Equals("--no-vacuum", StringComparison.OrdinalIgnoreCase));
                bool clearHistory = ctx.RemainingArgs.Any(a => a.Equals("--clear-history", StringComparison.OrdinalIgnoreCase));
                List<string>? overrideWhitelist = null;

                for (int i = 0; i < ctx.RemainingArgs.Length; i++)
                {
                    string arg = ctx.RemainingArgs[i];
                    if (arg.Equals("--whitelist", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        overrideWhitelist = ctx.RemainingArgs[++i]
                            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries)
                            .Select(BrowserPrivacyCleanerEngine.NormalizeDomain)
                            .Where(d => !string.IsNullOrWhiteSpace(d))
                            .ToList();
                    }
                    else if ((arg.Equals("--add-whitelist", StringComparison.OrdinalIgnoreCase) ||
                              arg.Equals("--add-domain", StringComparison.OrdinalIgnoreCase)) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        engine.AddWhitelistedDomain(ctx.RemainingArgs[++i]);
                    }
                    else if ((arg.Equals("--remove-whitelist", StringComparison.OrdinalIgnoreCase) ||
                              arg.Equals("--remove-domain", StringComparison.OrdinalIgnoreCase)) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        engine.RemoveWhitelistedDomain(ctx.RemainingArgs[++i]);
                    }
                    else if (arg.Equals("--vacuum", StringComparison.OrdinalIgnoreCase))
                    {
                        vacuum = true;
                    }
                }

                var report = engine.CleanProfiles(vacuumDatabases: vacuum, dryRun: dryRun, overrideWhitelist: overrideWhitelist, clearHistory: clearHistory);

                var payload = new
                {
                    status = "SUCCESS",
                    dryRun = report.DryRun,
                    vacuumExecuted = report.VacuumExecuted,
                    whitelistedDomains = report.WhitelistedDomains,
                    profilesScanned = report.TotalProfilesScanned,
                    profilesCleaned = report.ProfilesCleaned,
                    profilesSkippedRunning = report.ProfilesSkippedRunning,
                    cookiesRemoved = report.TotalCookiesRemoved,
                    cookiesPreserved = report.TotalCookiesPreserved,
                    databasesVacuumed = report.TotalDatabasesVacuumed,
                    bytesReclaimed = report.TotalBytesReclaimed,
                    bytesReclaimedFormatted = report.TotalBytesReclaimedFormatted,
                    profiles = report.Profiles.Select(p => new
                    {
                        browser = p.BrowserName,
                        profile = p.ProfileName,
                        skippedRunning = p.SkippedBecauseRunning,
                        cookiesRemoved = p.CookiesRemoved,
                        cookiesPreserved = p.CookiesPreserved,
                        databasesVacuumed = p.DatabasesVacuumed,
                        bytesReclaimed = p.BytesReclaimed,
                        bytesReclaimedFormatted = p.BytesReclaimedFormatted,
                        messages = p.Messages
                    }).ToList()
                };

                string modeTag = dryRun ? "[BROWSER PRIVACY DRY-RUN]" : "[BROWSER PRIVACY CLEAN]";
                OutputFormatter.Write(
                    ctx,
                    $"{modeTag} Scanned {report.TotalProfilesScanned} profile(s): {report.TotalCookiesRemoved} tracking cookies removed, {report.TotalCookiesPreserved} whitelisted cookies preserved, {report.TotalDatabasesVacuumed} SQLite DB(s) vacuumed ({report.TotalBytesReclaimedFormatted} reclaimed). Skipped running: {report.ProfilesSkippedRunning}.",
                    payload,
                    ConsoleColor.Green);

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Browser privacy cleaning failed: {ex.Message}", new { error = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }
    }
}

