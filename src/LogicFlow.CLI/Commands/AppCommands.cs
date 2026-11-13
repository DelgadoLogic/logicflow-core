using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian;
using LogicFlow.Native;

namespace LogicFlow.CLI.Commands
{
    public static class AppCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "startup-audit":
                    return HandleStartupAudit(ctx);
                case "bloatware-purge":
                    return HandleBloatwarePurge(ctx);
                case "winget":
                    return HandleWinGet(ctx);
                case "game-compact":
                    return HandleGameCompact(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown app command: '{command}'. Available: startup-audit, bloatware-purge, winget, game-compact", new { error = "UNKNOWN_COMMAND", group = "app", command });
                    return 1;
            }
        }

        private static readonly HashSet<string> KnownBloatware = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "OneDrive",
            "TeamsMachineInstaller",
            "AdobeGCClient",
            "Skype",
            "SpotifyWebHelper",
            "WebCompanion",
            "CCleaner Smart Cleaning"
        };

        private static int HandleStartupAudit(CliContext ctx)
        {
            try
            {
                var optimizer = new LogicFlow.Guardian.StartupOptimizer(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Guardian.StartupOptimizer>.Instance);
                var items = optimizer.AnalyzeStartupItems();
                var highImpact = items.Where(i => i.ImpactScore >= 7).ToList();

                var payload = new 
                { 
                    status = "SCANNED",
                    totalItems = items.Count,
                    highImpactCount = highImpact.Count,
                    highImpact = highImpact.Select(i => i.Name).ToArray(),
                    items = items.Select(i => new
                    {
                        name = i.Name,
                        command = i.Command,
                        source = i.Source,
                        impactScore = i.ImpactScore,
                        isHighImpact = i.ImpactScore >= 7
                    }).ToList()
                };

                ConsoleColor color = highImpact.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
                string msg = highImpact.Count > 0 
                    ? $"[STARTUP] Found {items.Count} startup programs ({highImpact.Count} High Impact on boot time)." 
                    : $"[STARTUP] Found {items.Count} startup programs. All have acceptable boot impact.";
                
                OutputFormatter.Write(ctx, msg, payload, color);

                if (!ctx.IsJson && !ctx.IsSilent && items.Count > 0)
                {
                    Console.WriteLine("\n  Startup Applications:");
                    foreach (var itm in items)
                    {
                        var col = itm.ImpactScore >= 7 ? ConsoleColor.Red : (itm.ImpactScore >= 5 ? ConsoleColor.Yellow : ConsoleColor.Gray);
                        Console.ForegroundColor = col;
                        Console.WriteLine($"    [Impact: {itm.ImpactScore,2}/10] {itm.Name,-30} ({itm.Source})");
                        Console.ResetColor();
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to analyze startup programs: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleBloatwarePurge(CliContext ctx)
        {
            try
            {
                var engine = new LogicFlow.Guardian.DebloatEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Guardian.DebloatEngine>.Instance);
                var candidates = engine.ScanBloatware();

                bool scanOnly = ctx.RemainingArgs.Any(a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase));
                if (scanOnly || (!ctx.IsForce && candidates.Count > 0))
                {
                    var payload = new
                    {
                        status = "SCANNED",
                        count = candidates.Count,
                        packages = candidates.Select(p => new { name = p.Name, vendor = p.Publisher, version = p.Version }).ToList(),
                        requiresForce = !ctx.IsForce
                    };

                    string msg = candidates.Count > 0
                        ? $"[BLOATWARE] Found {candidates.Count} removable bloatware package(s). Re-run with --force to purge."
                        : "[BLOATWARE] System is clean. No pre-installed bloatware packages detected.";

                    OutputFormatter.Write(ctx, msg, payload, candidates.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
                    return 0;
                }

                if (candidates.Count == 0)
                {
                    var cleanPayload = new { status = "CLEAN", removedCount = 0, packages = Array.Empty<string>() };
                    OutputFormatter.Write(ctx, "[BLOATWARE] System is clean. No bloatware packages found to purge.", cleanPayload, ConsoleColor.Green);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[PURGE] Purging {candidates.Count} bloatware packages...", new { status = "PURGING", count = candidates.Count }, ConsoleColor.Yellow);
                var packageNames = candidates.Select(c => c.Name).ToList();
                int removed = engine.RemoveBloatwarePackages(packageNames);

                var resultPayload = new
                {
                    status = "PURGED",
                    totalCandidates = candidates.Count,
                    removedPackages = removed,
                    packages = packageNames
                };

                OutputFormatter.Write(ctx, $"[PURGE] Successfully removed {removed}/{candidates.Count} AppX bloatware packages.", resultPayload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Bloatware purge failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleWinGet(CliContext ctx)
        {
            var engine = new LogicFlow.Guardian.WinGetUpdaterEngine();
            string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "list";

            if (sub == "upgrade-all")
            {
                OutputFormatter.Write(ctx, "[WINGET] Upgrading all third-party packages...", new { status = "UPGRADE_ALL_INITIATED" }, ConsoleColor.Yellow);
                var result = engine.UpgradeAllAsync().GetAwaiter().GetResult();
                if (result.Success)
                {
                    OutputFormatter.Write(ctx, "[WINGET] Successfully completed package upgrades.", result, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[WINGET] Upgrade encountered errors: {result.ErrorMessage}", result);
                    return 1;
                }
            }
            else if (sub == "upgrade" && ctx.RemainingArgs.Length > 3)
            {
                string id = ctx.RemainingArgs[3];
                OutputFormatter.Write(ctx, $"[WINGET] Upgrading package '{id}'...", new { status = "UPGRADE_INITIATED", id }, ConsoleColor.Yellow);
                var result = engine.UpgradePackageAsync(id).GetAwaiter().GetResult();
                if (result.Success)
                {
                    OutputFormatter.Write(ctx, $"[WINGET] Successfully upgraded '{id}'.", result, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[WINGET] Upgrade failed: {result.ErrorMessage}", result);
                    return 1;
                }
            }
            else
            {
                OutputFormatter.Write(ctx, "[WINGET] Scanning for available application updates...", new { status = "SCANNING" }, ConsoleColor.Cyan);
                var packages = engine.ScanUpgradableAppsAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, $"[WINGET] Found {packages.Count} upgradable applications:", new { count = packages.Count, packages }, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var pkg in packages)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write($"  {pkg.Name,-30} ");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write($"[{pkg.Id}] ");
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write($"{pkg.CurrentVersion} -> ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"{pkg.AvailableVersion}");
                        Console.ResetColor();
                    }
                }
                return 0;
            }
        }

        #region Game Compact Implementation

        private static int HandleGameCompact(CliContext ctx)
        {
            int gcIndex = -1;
            for (int i = 0; i < ctx.RemainingArgs.Length; i++)
            {
                if (ctx.RemainingArgs[i].Equals("game-compact", StringComparison.OrdinalIgnoreCase))
                {
                    gcIndex = i;
                    break;
                }
            }

            string action = "list";
            int startIndex;
            if (gcIndex >= 0)
            {
                if (gcIndex + 1 < ctx.RemainingArgs.Length && !ctx.RemainingArgs[gcIndex + 1].StartsWith("-"))
                {
                    action = ctx.RemainingArgs[gcIndex + 1].ToLowerInvariant();
                    startIndex = gcIndex + 2;
                }
                else
                {
                    action = "list";
                    startIndex = gcIndex + 1;
                }
            }
            else
            {
                if (ctx.RemainingArgs.Length > 0 && !ctx.RemainingArgs[0].StartsWith("-"))
                {
                    action = ctx.RemainingArgs[0].ToLowerInvariant();
                    startIndex = 1;
                }
                else
                {
                    action = "list";
                    startIndex = 0;
                }
            }

            string? target = null;
            string algoStr = "lzx";
            bool skipDirectStorage = !ctx.IsForce;
            var positionalTokens = new List<string>();

            for (int i = startIndex; i < ctx.RemainingArgs.Length; i++)
            {
                string arg = ctx.RemainingArgs[i];
                if (arg.Equals("--algo", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                {
                    algoStr = ctx.RemainingArgs[++i];
                }
                else if (arg.StartsWith("--algo=", StringComparison.OrdinalIgnoreCase))
                {
                    algoStr = arg.Substring("--algo=".Length);
                }
                else if (arg.Equals("--skip-directstorage", StringComparison.OrdinalIgnoreCase))
                {
                    skipDirectStorage = true;
                }
                else if (arg.Equals("--no-skip-directstorage", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--force", StringComparison.OrdinalIgnoreCase))
                {
                    skipDirectStorage = false;
                }
                else if (!arg.StartsWith("-"))
                {
                    positionalTokens.Add(arg);
                }
            }

            if (positionalTokens.Count > 0)
            {
                target = string.Join(" ", positionalTokens);
            }

            switch (action)
            {
                case "list":
                    return HandleGameCompactList(ctx);
                case "compress":
                    return HandleGameCompactCompress(ctx, target, algoStr, skipDirectStorage);
                case "decompress":
                    return HandleGameCompactDecompress(ctx, target);
                case "decay-audit":
                    return HandleGameCompactDecayAudit(ctx);
                case "recompact" or "re-compact":
                    return HandleGameCompactRecompact(ctx, target, algoStr, skipDirectStorage);
                case "help" or "--help" or "-h":
                    return HandleGameCompactHelp(ctx);
                default:
                    OutputFormatter.WriteError(ctx,
                        $"Unknown game-compact subcommand: '{action}'. Available: list, compress, decompress, decay-audit, recompact",
                        new { error = "UNKNOWN_SUBCOMMAND", group = "app", command = "game-compact", subcommand = action });
                    return 1;
            }
        }

        private static int HandleGameCompactHelp(CliContext ctx)
        {
            var helpModel = new
            {
                command = "game-compact",
                description = "Native Win32/WOF transparent NTFS game & application compression engine",
                subcommands = new[]
                {
                    new { name = "list", description = "Enumerate installed games across Steam, Epic, GOG, and custom directories with storage footprints and DirectStorage status" },
                    new { name = "compress <name|all>", description = "Execute transparent NTFS compression with optional --algo <lzx|xpress8k|xpress16k|xpress4k> and --skip-directstorage" },
                    new { name = "decompress <name|all>", description = "Safely decompress games back to standard NTFS clusters with pre-flight free space safety verification" },
                    new { name = "decay-audit", description = "Audit tracked games for compression decay caused by game updates, patches, or DLC" },
                    new { name = "recompact <name|all>", description = "Targeted delta re-compaction of newly updated uncompressed files" }
                }
            };

            OutputFormatter.Write(ctx, "[GAME-COMPACT] Native Win32/WOF Transparent Compression Engine\n" +
                "Usage: lf app game-compact [list|compress|decompress|decay-audit|recompact] [options]\n\n" +
                "Subcommands:\n" +
                "  list                       List detected games, disk usage, savings, and DirectStorage status\n" +
                "  compress <name|all>        Compress target game or all eligible games\n" +
                "                             Options: --algo <lzx|xpress8k|xpress16k|xpress4k> (default: lzx)\n" +
                "                                      --skip-directstorage (default: true)\n" +
                "  decompress <name|all>      Decompress game files back to standard uncompressed NTFS\n" +
                "  decay-audit                Audit tracked games for uncompressed game updates/patches\n" +
                "  recompact <name|all>       Re-compact newly updated or modified files for a game\n",
                helpModel, ConsoleColor.Cyan);
            return 0;
        }

        private static int HandleGameCompactList(CliContext ctx)
        {
            try
            {
                var detector = SteamLibraryDetector.Instance;
                var games = detector.DetectAllGames();

                long totalSizeBytes = games.Sum(g => g.SizeOnDiskBytes);
                long totalEstimatedSavingsBytes = games.Sum(g => g.EstimatedSavingsBytes);

                var jsonModel = new
                {
                    status = "SUCCESS",
                    count = games.Count,
                    totalGames = games.Count,
                    totalSizeBytes = totalSizeBytes,
                    totalSizeOnDiskBytes = totalSizeBytes,
                    formattedTotalSize = FormatBytes(totalSizeBytes),
                    formattedTotalSizeOnDisk = FormatBytes(totalSizeBytes),
                    totalEstimatedSavingsBytes = totalEstimatedSavingsBytes,
                    formattedTotalEstimatedSavings = FormatBytes(totalEstimatedSavingsBytes),
                    games = games.Select(g => new
                    {
                        gameId = g.GameId,
                        title = g.Title,
                        launcher = g.Launcher.ToString(),
                        installDirectory = g.InstallDirectory,
                        sizeOnDiskBytes = g.SizeOnDiskBytes,
                        formattedSize = g.FormattedSizeOnDisk,
                        estimatedSavingsBytes = g.EstimatedSavingsBytes,
                        formattedEstimatedSavings = g.FormattedEstimatedSavings,
                        hasDirectStorage = g.HasDirectStorage,
                        isCompressed = g.IsCompressed,
                        compressedFileCount = g.CompressedFileCount,
                        candidateFileCount = g.CandidateFileCount,
                        isRunning = g.IsRunning
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[GAME-COMPACT] Detected {games.Count} installed game(s) (Total: {FormatBytes(totalSizeBytes)}, Estimated Recoverable: ~{FormatBytes(totalEstimatedSavingsBytes)}):", jsonModel, ConsoleColor.Cyan);

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    if (games.Count == 0)
                    {
                        Console.WriteLine("  No games detected in standard Steam, Epic, GOG, or Custom libraries.");
                    }
                    else
                    {
                        Console.WriteLine("  " + "Launcher".PadRight(10) + "Status".PadRight(16) + "DirectStorage".PadRight(16) + "Size".PadRight(12) + "Est. Savings".PadRight(16) + "Title");
                        Console.WriteLine("  " + new string('─', 82));
                        foreach (var g in games)
                        {
                            string statusStr = g.IsCompressed ? "[COMPRESSED]" : "[UNCOMPRESSED]";
                            string dsStr = g.HasDirectStorage ? "[DSTORAGE:YES]" : "[SAFE: NO]";
                            Console.ForegroundColor = g.IsCompressed ? ConsoleColor.Green : ConsoleColor.Gray;
                            Console.Write($"  {g.Launcher.ToString().PadRight(10)}");
                            Console.ForegroundColor = g.IsCompressed ? ConsoleColor.Green : ConsoleColor.Yellow;
                            Console.Write($"{statusStr.PadRight(16)}");
                            Console.ForegroundColor = g.HasDirectStorage ? ConsoleColor.Magenta : ConsoleColor.DarkCyan;
                            Console.Write($"{dsStr.PadRight(16)}");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.Write($"{g.FormattedSizeOnDisk.PadRight(12)}");
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.Write($"{g.FormattedEstimatedSavings.PadRight(16)}");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.WriteLine($"{g.Title} ({g.GameId})");
                            Console.ResetColor();
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to enumerate installed games: {ex.Message}",
                    new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleGameCompactCompress(CliContext ctx, string? target, string algoStr, bool skipDirectStorage)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                OutputFormatter.WriteError(ctx,
                    "Missing target game name or 'all'. Usage: lf app game-compact compress <gameName|all> [--algo lzx|xpress8k|xpress16k|xpress4k] [--skip-directstorage]",
                    new { error = "MISSING_TARGET", status = "ERROR", command = "compress" });
                return 1;
            }

            uint algorithm;
            try
            {
                algorithm = ParseAlgorithm(algoStr);
            }
            catch (ArgumentException ex)
            {
                OutputFormatter.WriteError(ctx, ex.Message,
                    new { error = "INVALID_ALGORITHM", status = "ERROR", algorithm = algoStr, details = "Available algorithms: lzx, xpress8k, xpress16k, xpress4k" });
                return 1;
            }

            var detector = SteamLibraryDetector.Instance;
            var engine = GameCompressionEngine.Instance;
            var allGames = detector.DetectAllGames();

            if (!TryResolveGame(ctx, target, allGames, out var resolvedGame, out bool isAll))
            {
                return 1;
            }

            var options = new GameCompressionOptions(algorithm, MaxParallelism: null, SkipDirectStorage: skipDirectStorage);

            if (isAll)
            {
                if (allGames.Count == 0)
                {
                    OutputFormatter.WriteError(ctx, "No games detected to compress.",
                        new { status = "NO_GAMES_FOUND", error = "NO_GAMES_FOUND", totalGames = 0 });
                    return 1;
                }

                var results = new List<GameCompressionSummary>();
                long totalOrig = 0, totalComp = 0, totalSaved = 0;
                int succeededCount = 0;
                var swTotal = Stopwatch.StartNew();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[COMPACT] Starting batch compression across {allGames.Count} game(s) (Algo: {algoStr.ToUpperInvariant()}, Skip DirectStorage: {skipDirectStorage})...");
                    Console.ResetColor();
                }

                foreach (var g in allGames)
                {
                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n[COMPACT] Processing '{g.Title}' [{g.Launcher}]...");
                        Console.ResetColor();
                    }

                    var progress = CreateProgressReporter(ctx, g.Title, "Compressing");
                    var summary = engine.CompressGameAsync(g, options, progress).GetAwaiter().GetResult();
                    results.Add(summary);

                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        Console.WriteLine();
                        if (summary.Success)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[COMPACT] '{g.Title}' completed: {summary.FormattedSavedBytes} saved ({summary.SpaceSavedPercent:F1}% reduction) in {summary.Duration.TotalSeconds:F1}s ({summary.FormattedThroughput}).");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[COMPACT] '{g.Title}' failed: {summary.ErrorMessage}");
                            Console.ResetColor();
                        }
                    }

                    totalOrig += summary.OriginalBytes;
                    totalComp += summary.CompressedBytes;
                    totalSaved += summary.SavedBytes;
                    if (summary.Success) succeededCount++;
                }
                swTotal.Stop();

                var batchModel = new
                {
                    status = "SUCCESS",
                    totalGames = allGames.Count,
                    totalGamesProcessed = allGames.Count,
                    totalGamesSucceeded = succeededCount,
                    totalOriginalBytes = totalOrig,
                    totalCompressedBytes = totalComp,
                    totalSavedBytes = totalSaved,
                    formattedTotalOriginal = FormatBytes(totalOrig),
                    formattedTotalCompressed = FormatBytes(totalComp),
                    formattedTotalSaved = FormatBytes(totalSaved),
                    totalDurationSeconds = Math.Round(swTotal.Elapsed.TotalSeconds, 1),
                    durationMs = Math.Round(swTotal.Elapsed.TotalMilliseconds, 1),
                    results = results.Select(r => new
                    {
                        gameId = r.GameId,
                        title = r.Title,
                        success = r.Success,
                        filesProcessed = r.FilesProcessed,
                        filesCompressed = r.FilesCompressed,
                        filesSkipped = r.FilesSkipped,
                        originalBytes = r.OriginalBytes,
                        compressedBytes = r.CompressedBytes,
                        savedBytes = r.SavedBytes,
                        formattedSaved = r.FormattedSavedBytes,
                        spaceSavedPercent = Math.Round(r.SpaceSavedPercent, 1),
                        durationSeconds = Math.Round(r.Duration.TotalSeconds, 1),
                        errorMessage = r.ErrorMessage
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[COMPACT] Batch compression complete: {FormatBytes(totalSaved)} reclaimed across {succeededCount}/{allGames.Count} game(s) in {swTotal.Elapsed.TotalSeconds:F1}s.", batchModel, ConsoleColor.Green);
                return (allGames.Count > 0 && succeededCount == 0) ? 1 : 0;
            }
            else
            {
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[COMPACT] Compressing '{resolvedGame!.Title}' via {algoStr.ToUpperInvariant()} (Concurrency: {options.EffectiveParallelism}, Skip DirectStorage: {skipDirectStorage})...");
                    Console.ResetColor();
                }

                var progress = CreateProgressReporter(ctx, resolvedGame!.Title, "Compressing");
                var summary = engine.CompressGameAsync(resolvedGame!, options, progress).GetAwaiter().GetResult();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.WriteLine();
                }

                var singleModel = new
                {
                    status = summary.Success ? "SUCCESS" : "FAILED",
                    gameId = summary.GameId,
                    title = summary.Title,
                    success = summary.Success,
                    algorithm = algoStr.ToUpperInvariant(),
                    filesProcessed = summary.FilesProcessed,
                    filesCompressed = summary.FilesCompressed,
                    filesSkipped = summary.FilesSkipped,
                    originalBytes = summary.OriginalBytes,
                    compressedBytes = summary.CompressedBytes,
                    savedBytes = summary.SavedBytes,
                    formattedOriginal = summary.FormattedOriginalBytes,
                    formattedOriginalBytes = summary.FormattedOriginalBytes,
                    formattedCompressed = summary.FormattedCompressedBytes,
                    formattedCompressedBytes = summary.FormattedCompressedBytes,
                    formattedSaved = summary.FormattedSavedBytes,
                    formattedSavedBytes = summary.FormattedSavedBytes,
                    spaceSavedPercent = Math.Round(summary.SpaceSavedPercent, 1),
                    compressionRatio = Math.Round(summary.Ratio, 2),
                    throughputMBs = Math.Round(summary.ThroughputMBs, 1),
                    durationSeconds = Math.Round(summary.Duration.TotalSeconds, 1),
                    durationMs = Math.Round(summary.Duration.TotalMilliseconds, 1),
                    errorMessage = summary.ErrorMessage
                };

                if (summary.Success)
                {
                    string msg = $"[COMPACT] '{summary.Title}' compressed successfully in {summary.Duration.TotalSeconds:F1}s! Recovered: {summary.FormattedSavedBytes} ({summary.SpaceSavedPercent:F1}% reduction, {summary.FormattedThroughput}).";
                    OutputFormatter.Write(ctx, msg, singleModel, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"Compression failed for '{summary.Title}': {summary.ErrorMessage}", singleModel);
                    return 1;
                }
            }
        }

        private static int HandleGameCompactDecompress(CliContext ctx, string? target)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                OutputFormatter.WriteError(ctx,
                    "Missing target game name or 'all'. Usage: lf app game-compact decompress <gameName|all>",
                    new { error = "MISSING_TARGET", status = "ERROR", command = "decompress" });
                return 1;
            }

            var detector = SteamLibraryDetector.Instance;
            var engine = GameCompressionEngine.Instance;
            var allGames = detector.DetectAllGames();

            if (!TryResolveGame(ctx, target, allGames, out var resolvedGame, out bool isAll))
            {
                return 1;
            }

            if (isAll)
            {
                if (allGames.Count == 0)
                {
                    OutputFormatter.WriteError(ctx, "No games detected to decompress.",
                        new { status = "NO_GAMES_FOUND", error = "NO_GAMES_FOUND", totalGames = 0 });
                    return 1;
                }

                var results = new List<GameDecompressionSummary>();
                int succeededCount = 0;
                long totalRestored = 0;
                var swTotal = Stopwatch.StartNew();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[RESTORE] Starting batch decompression across {allGames.Count} game(s)...");
                    Console.ResetColor();
                }

                foreach (var g in allGames)
                {
                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n[RESTORE] Decompressing '{g.Title}' [{g.Launcher}]...");
                        Console.ResetColor();
                    }

                    var progress = CreateProgressReporter(ctx, g.Title, "Decompressing");
                    var summary = engine.DecompressGameAsync(g, progress).GetAwaiter().GetResult();
                    results.Add(summary);

                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        Console.WriteLine();
                        if (summary.Success)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[RESTORE] '{g.Title}' completed: {summary.FormattedRestoredBytes} restored ({summary.FilesDecompressed} files) in {summary.Duration.TotalSeconds:F1}s.");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[RESTORE] '{g.Title}' failed: {summary.ErrorMessage}");
                            Console.ResetColor();
                        }
                    }

                    totalRestored += summary.RestoredBytes;
                    if (summary.Success) succeededCount++;
                }
                swTotal.Stop();

                var batchModel = new
                {
                    status = "SUCCESS",
                    totalGames = allGames.Count,
                    totalGamesProcessed = allGames.Count,
                    totalGamesSucceeded = succeededCount,
                    totalRestoredBytes = totalRestored,
                    formattedTotalRestored = FormatBytes(totalRestored),
                    totalDurationSeconds = Math.Round(swTotal.Elapsed.TotalSeconds, 1),
                    durationMs = Math.Round(swTotal.Elapsed.TotalMilliseconds, 1),
                    results = results.Select(r => new
                    {
                        gameId = r.GameId,
                        title = r.Title,
                        success = r.Success,
                        filesProcessed = r.FilesProcessed,
                        filesDecompressed = r.FilesDecompressed,
                        restoredBytes = r.RestoredBytes,
                        formattedRestored = r.FormattedRestoredBytes,
                        durationSeconds = Math.Round(r.Duration.TotalSeconds, 1),
                        errorMessage = r.ErrorMessage
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[RESTORE] Batch decompression complete: {FormatBytes(totalRestored)} restored across {succeededCount}/{allGames.Count} game(s) in {swTotal.Elapsed.TotalSeconds:F1}s.", batchModel, ConsoleColor.Green);
                return (allGames.Count > 0 && succeededCount == 0) ? 1 : 0;
            }
            else
            {
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[RESTORE] Decompressing '{resolvedGame!.Title}' back to standard uncompressed NTFS...");
                    Console.ResetColor();
                }

                var progress = CreateProgressReporter(ctx, resolvedGame!.Title, "Decompressing");
                var summary = engine.DecompressGameAsync(resolvedGame!, progress).GetAwaiter().GetResult();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.WriteLine();
                }

                var singleModel = new
                {
                    status = summary.Success ? "SUCCESS" : "FAILED",
                    gameId = summary.GameId,
                    title = summary.Title,
                    success = summary.Success,
                    filesProcessed = summary.FilesProcessed,
                    filesDecompressed = summary.FilesDecompressed,
                    restoredBytes = summary.RestoredBytes,
                    formattedRestored = summary.FormattedRestoredBytes,
                    formattedRestoredBytes = summary.FormattedRestoredBytes,
                    throughputMBs = Math.Round(summary.ThroughputMBs, 1),
                    durationSeconds = Math.Round(summary.Duration.TotalSeconds, 1),
                    durationMs = Math.Round(summary.Duration.TotalMilliseconds, 1),
                    errorMessage = summary.ErrorMessage
                };

                if (summary.Success)
                {
                    string msg = $"[RESTORE] '{summary.Title}' decompressed successfully in {summary.Duration.TotalSeconds:F1}s: {summary.FormattedRestoredBytes} restored across {summary.FilesDecompressed} files ({summary.FormattedThroughput}).";
                    OutputFormatter.Write(ctx, msg, singleModel, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, summary.ErrorMessage ?? $"Decompression failed for '{summary.Title}'.", singleModel);
                    return 1;
                }
            }
        }

        private static int HandleGameCompactDecayAudit(CliContext ctx)
        {
            try
            {
                var detector = SteamLibraryDetector.Instance;
                var engine = GameCompressionEngine.Instance;
                var games = detector.DetectAllGames();
                var report = engine.AuditDecay(games);

                var auditModel = new
                {
                    status = "SUCCESS",
                    hasDecay = report.HasDecay,
                    totalGamesAudited = report.TotalGamesAudited,
                    gamesWithDecay = report.GamesWithDecay,
                    totalDecayedFiles = report.CalculatedTotalDecayedFiles,
                    totalDecayedBytes = report.TotalUncompressedBytesEligible,
                    formattedTotalDecayedBytes = report.FormattedTotalUncompressedBytes,
                    decayedGames = report.DecayedGames.Select(d => new
                    {
                        gameId = d.GameId,
                        title = d.Title,
                        launcher = d.Launcher.ToString(),
                        installDirectory = d.InstallDirectory,
                        decayedFileCount = d.DecayedFileCount,
                        newOrModifiedFileCount = d.NewOrModifiedFileCount,
                        uncompressedBytesEligible = d.UncompressedBytesEligible,
                        formattedDecayedBytes = d.FormattedDecayedBytes,
                        formattedUncompressedBytes = d.FormattedUncompressedBytes,
                        newFilesCount = d.NewFilesCount,
                        modifiedFilesCount = d.ModifiedFilesCount,
                        deletedFilesCount = d.DeletedFilesCount,
                        lastCompressedUtc = d.LastCompressedUtc,
                        previousAlgorithm = d.PreviousAlgorithm,
                        recommendedCommand = $"lf app game-compact recompact \"{d.Title}\""
                    }).ToList()
                };

                if (!report.HasDecay)
                {
                    OutputFormatter.Write(ctx, "[DECAY-AUDIT] All tracked game installations are fully compressed. No compression decay detected.", auditModel, ConsoleColor.Green);
                }
                else
                {
                    string msg = $"[DECAY-AUDIT] Audited {report.TotalGamesAudited} game(s). Found {report.GamesWithDecay} game(s) with compression decay ({report.CalculatedTotalDecayedFiles} files, {report.FormattedTotalUncompressedBytes} eligible for compaction):";
                    OutputFormatter.Write(ctx, msg, auditModel, ConsoleColor.Yellow);

                    if (!ctx.IsJson && !ctx.IsSilent)
                    {
                        foreach (var d in report.DecayedGames)
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"  * {d.Title} [{d.Launcher}]");
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.WriteLine($"    Directory: {d.InstallDirectory}");
                            Console.WriteLine($"    Decayed Files: {d.DecayedFileCount} ({d.NewFilesCount} new, {d.ModifiedFilesCount} modified) | Eligible Space: {d.FormattedDecayedBytes}");
                            if (d.LastCompressedUtc.HasValue)
                            {
                                Console.WriteLine($"    Last Compressed: {d.LastCompressedUtc.Value:yyyy-MM-dd HH:mm} UTC");
                            }
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"    Run 'lf app game-compact recompact \"{d.Title}\"' to re-compact updated files.");
                            Console.ResetColor();
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to perform compression decay audit: {ex.Message}",
                    new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleGameCompactRecompact(CliContext ctx, string? target, string algoStr, bool skipDirectStorage)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                OutputFormatter.WriteError(ctx,
                    "Missing target game name or 'all'. Usage: lf app game-compact recompact <gameName|all> [--algo lzx|xpress8k|xpress16k|xpress4k] [--skip-directstorage]",
                    new { error = "MISSING_TARGET", status = "ERROR", command = "recompact" });
                return 1;
            }

            uint algorithm;
            try
            {
                algorithm = ParseAlgorithm(algoStr);
            }
            catch (ArgumentException ex)
            {
                OutputFormatter.WriteError(ctx, ex.Message,
                    new { error = "INVALID_ALGORITHM", status = "ERROR", algorithm = algoStr });
                return 1;
            }

            var detector = SteamLibraryDetector.Instance;
            var engine = GameCompressionEngine.Instance;
            var allGames = detector.DetectAllGames();

            if (!TryResolveGame(ctx, target, allGames, out var resolvedGame, out bool isAll))
            {
                return 1;
            }

            var options = new GameCompressionOptions(algorithm, MaxParallelism: null, SkipDirectStorage: skipDirectStorage);

            if (isAll)
            {
                var results = new List<GameCompressionSummary>();
                long totalOrig = 0, totalComp = 0, totalSaved = 0;
                int succeededCount = 0;
                var swTotal = Stopwatch.StartNew();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[RECOMPACT] Recompacting updates across all {allGames.Count} detected game(s)...");
                    Console.ResetColor();
                }

                foreach (var g in allGames)
                {
                    var progress = CreateProgressReporter(ctx, g.Title, "Recompacting");
                    var summary = engine.RecompactUpdatesAsync(g, options, progress).GetAwaiter().GetResult();
                    results.Add(summary);

                    if (!ctx.IsJson && !ctx.IsSilent && summary.FilesCompressed > 0)
                    {
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[RECOMPACT] '{g.Title}': {summary.FilesCompressed} updated files recompacted ({summary.FormattedSavedBytes} saved).");
                        Console.ResetColor();
                    }

                    totalOrig += summary.OriginalBytes;
                    totalComp += summary.CompressedBytes;
                    totalSaved += summary.SavedBytes;
                    if (summary.Success) succeededCount++;
                }
                swTotal.Stop();

                var batchModel = new
                {
                    status = "SUCCESS",
                    totalGames = allGames.Count,
                    totalGamesProcessed = allGames.Count,
                    totalGamesSucceeded = succeededCount,
                    totalOriginalBytes = totalOrig,
                    totalCompressedBytes = totalComp,
                    totalSavedBytes = totalSaved,
                    formattedTotalOriginal = FormatBytes(totalOrig),
                    formattedTotalCompressed = FormatBytes(totalComp),
                    formattedTotalSaved = FormatBytes(totalSaved),
                    totalDurationSeconds = Math.Round(swTotal.Elapsed.TotalSeconds, 1),
                    results = results.Select(r => new
                    {
                        gameId = r.GameId,
                        title = r.Title,
                        success = r.Success,
                        filesProcessed = r.FilesProcessed,
                        filesCompressed = r.FilesCompressed,
                        savedBytes = r.SavedBytes,
                        formattedSaved = r.FormattedSavedBytes,
                        errorMessage = r.ErrorMessage
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[RECOMPACT] Batch recompaction complete: {FormatBytes(totalSaved)} reclaimed across {succeededCount}/{allGames.Count} game(s).", batchModel, ConsoleColor.Green);
                return 0;
            }
            else
            {
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[RECOMPACT] Recompacting updates for '{resolvedGame!.Title}'...");
                    Console.ResetColor();
                }

                var progress = CreateProgressReporter(ctx, resolvedGame!.Title, "Recompacting");
                var summary = engine.RecompactUpdatesAsync(resolvedGame!, options, progress).GetAwaiter().GetResult();

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.WriteLine();
                }

                var singleModel = new
                {
                    status = summary.Success ? "SUCCESS" : "FAILED",
                    gameId = summary.GameId,
                    title = summary.Title,
                    success = summary.Success,
                    filesProcessed = summary.FilesProcessed,
                    filesCompressed = summary.FilesCompressed,
                    filesSkipped = summary.FilesSkipped,
                    originalBytes = summary.OriginalBytes,
                    compressedBytes = summary.CompressedBytes,
                    savedBytes = summary.SavedBytes,
                    formattedOriginal = summary.FormattedOriginalBytes,
                    formattedCompressed = summary.FormattedCompressedBytes,
                    formattedSaved = summary.FormattedSavedBytes,
                    formattedSavedBytes = summary.FormattedSavedBytes,
                    durationSeconds = Math.Round(summary.Duration.TotalSeconds, 1),
                    errorMessage = summary.ErrorMessage
                };

                if (summary.Success)
                {
                    string msg = summary.FilesCompressed > 0
                        ? $"[RECOMPACT] '{summary.Title}' recompacted {summary.FilesCompressed} delta file(s) ({summary.FormattedSavedBytes} saved) in {summary.Duration.TotalSeconds:F1}s."
                        : $"[RECOMPACT] '{summary.Title}' is already fully compressed. 0 delta files required compaction.";
                    OutputFormatter.Write(ctx, msg, singleModel, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"Recompaction failed for '{summary.Title}': {summary.ErrorMessage}", singleModel);
                    return 1;
                }
            }
        }

        private static uint ParseAlgorithm(string algoStr) =>
            algoStr.ToLowerInvariant() switch
            {
                "lzx" => WofNative.ALGORITHM_LZX,
                "xpress8k" or "xpress8" or "8k" => WofNative.ALGORITHM_XPRESS8K,
                "xpress16k" or "xpress16" or "16k" => WofNative.ALGORITHM_XPRESS16K,
                "xpress4k" or "xpress4" or "4k" or "xpress" => WofNative.ALGORITHM_XPRESS4K,
                _ => throw new ArgumentException($"Unknown compression algorithm '{algoStr}'. Available: lzx, xpress8k, xpress16k, xpress4k")
            };

        private static bool TryResolveGame(
            CliContext ctx,
            string target,
            IReadOnlyList<DetectedGame> allGames,
            out DetectedGame? game,
            out bool isAll)
        {
            game = null;
            isAll = false;

            if (string.Equals(target, "all", StringComparison.OrdinalIgnoreCase))
            {
                isAll = true;
                return true;
            }

            // 1. Exact GameId match
            var exactId = allGames.FirstOrDefault(g => string.Equals(g.GameId, target, StringComparison.OrdinalIgnoreCase));
            if (exactId != null) { game = exactId; return true; }

            // 2. Exact Title match
            var exactTitle = allGames.FirstOrDefault(g => string.Equals(g.Title, target, StringComparison.OrdinalIgnoreCase));
            if (exactTitle != null) { game = exactTitle; return true; }

            // 3. Numeric ID match (e.g. 730 matching steam_730)
            if (target.All(char.IsDigit))
            {
                var idMatch = allGames.FirstOrDefault(g => g.GameId.EndsWith($"_{target}", StringComparison.OrdinalIgnoreCase));
                if (idMatch != null) { game = idMatch; return true; }
            }

            // 4. Substring match on Title
            var titleMatches = allGames.Where(g => g.Title.Contains(target, StringComparison.OrdinalIgnoreCase)).ToList();
            if (titleMatches.Count == 1) { game = titleMatches[0]; return true; }
            if (titleMatches.Count > 1)
            {
                var matchPayload = titleMatches.Select(m => new { gameId = m.GameId, title = m.Title }).ToList();
                OutputFormatter.WriteError(ctx,
                    $"Multiple games matched '{target}'. Please specify exact title or GameId:\n" +
                    string.Join("\n", titleMatches.Select(m => $"  - {m.Title} ({m.GameId})")),
                    new { status = "AMBIGUOUS_MATCH", error = "AMBIGUOUS_MATCH", target, matches = matchPayload });
                return false;
            }

            // 5. Substring match on GameId
            var idMatches = allGames.Where(g => g.GameId.Contains(target, StringComparison.OrdinalIgnoreCase)).ToList();
            if (idMatches.Count == 1) { game = idMatches[0]; return true; }
            if (idMatches.Count > 1)
            {
                var matchPayload = idMatches.Select(m => new { gameId = m.GameId, title = m.Title }).ToList();
                OutputFormatter.WriteError(ctx,
                    $"Multiple games matched '{target}'. Please specify exact title or GameId:\n" +
                    string.Join("\n", idMatches.Select(m => $"  - {m.Title} ({m.GameId})")),
                    new { status = "AMBIGUOUS_MATCH", error = "AMBIGUOUS_MATCH", target, matches = matchPayload });
                return false;
            }

            OutputFormatter.WriteError(ctx,
                $"Game '{target}' not found. Run 'lf app game-compact list' to view detected games.",
                new { status = "GAME_NOT_FOUND", error = "GAME_NOT_FOUND", target });
            return false;
        }

        private static IProgress<CompressionProgress>? CreateProgressReporter(CliContext ctx, string title, string label = "Compressing")
        {
            if (ctx.IsJson || ctx.IsSilent) return null;

            return new Progress<CompressionProgress>(p =>
            {
                try
                {
                    int consoleWidth = 80;
                    try
                    {
                        if (!Console.IsOutputRedirected)
                        {
                            consoleWidth = Math.Max(Console.WindowWidth, 60);
                        }
                    }
                    catch { }

                    int barWidth = 20;
                    double percent = Math.Clamp(p.PercentComplete, 0.0, 100.0);
                    int filled = (int)Math.Round((percent / 100.0) * barWidth);
                    filled = Math.Clamp(filled, 0, barWidth);
                    string bar = new string('█', filled) + new string('░', barWidth - filled);

                    string fileName = p.CurrentFile ?? "";
                    if (fileName.Length > 20)
                    {
                        fileName = "..." + fileName.Substring(fileName.Length - 17);
                    }

                    string throughput = p.ThroughputMBs > 0 ? $"{p.ThroughputMBs,5:F1} MB/s" : "   -- MB/s";
                    string saved = p.FormattedBytesSaved;

                    string line = $"  [{bar}] {percent,5:F1}% | {throughput} | Saved: {saved,-8} | {fileName}";
                    if (line.Length >= consoleWidth)
                    {
                        line = line.Substring(0, consoleWidth - 1);
                    }
                    else
                    {
                        line = line.PadRight(consoleWidth - 1);
                    }

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"\r{line}");
                    Console.ResetColor();
                }
                catch { /* Never crash on progress rendering */ }
            });
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            double d = bytes;
            while (d >= 1024.0 && i < units.Length - 1)
            {
                d /= 1024.0;
                i++;
            }
            return $"{d:0.##} {units[i]}";
        }

        #endregion
    }
}
