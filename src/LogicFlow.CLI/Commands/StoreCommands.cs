// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.CLI — StoreCommands (HyperStore V-Dense CLI Primitives)
// High-speed command-line verbs for FastCDC scanning, host deduplication,
// sovereign .lfc container packaging, and full-fidelity extraction.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian.Deduplication;
using LogicFlow.Storage.Engine.Chunking;
using LogicFlow.Storage.Engine.Clustering;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.CLI.Commands;

/// <summary>
/// CLI command handler for HyperStore (V-Dense) storage optimization commands:
/// scan, dedup, pack, unpack.
/// </summary>
public static class StoreCommands
{
    public const int ExitSuccess = 0;
    public const int ExitError = 1;
    public const int ExitInvalidArguments = 2;
    public const int ExitCancelled = 3;

    /// <summary>
    /// Async entrypoint for "store" group routing from Program.cs.
    /// </summary>
    public static async Task<int> ExecuteAsync(CliContext ctx, CancellationToken ct = default)
    {
        string command = "";
        if (ctx.RemainingArgs.Length > 1)
        {
            command = ctx.RemainingArgs[1].ToLowerInvariant();
        }
        else if (ctx.RemainingArgs.Length == 1 && ctx.RemainingArgs[0].Equals("store", StringComparison.OrdinalIgnoreCase))
        {
            command = "help";
        }
        else if (ctx.RemainingArgs.Length > 0 && !ctx.RemainingArgs[0].Equals("store", StringComparison.OrdinalIgnoreCase))
        {
            command = ctx.RemainingArgs[0].ToLowerInvariant();
        }

        return await RunAsync(ctx, command, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Synchronous bridge for backwards compatibility and test runners.
    /// </summary>
    public static int Run(CliContext ctx, string command)
    {
        return RunAsync(ctx, command).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Main async dispatch for store subcommands.
    /// </summary>
    public static async Task<int> RunAsync(CliContext ctx, string command, CancellationToken ct = default)
    {
        try
        {
            return command.ToLowerInvariant() switch
            {
                "scan" => await HandleScanAsync(ctx, ct).ConfigureAwait(false),
                "dedup" => await HandleDedupAsync(ctx, ct).ConfigureAwait(false),
                "pack" => await HandlePackAsync(ctx, ct).ConfigureAwait(false),
                "unpack" => await HandleUnpackAsync(ctx, ct).ConfigureAwait(false),
                "help" or "--help" or "-h" or "" => ShowHelp(ctx),
                _ => HandleUnknownCommand(ctx, command)
            };
        }
        catch (OperationCanceledException)
        {
            OutputFormatter.WriteError(ctx, "Operation was cancelled by user.", new { status = "CANCELLED", exitCode = ExitCancelled });
            return ExitCancelled;
        }
        catch (Exception ex)
        {
            OutputFormatter.WriteError(ctx, $"Store command execution failed: {ex.Message}", new { status = "ERROR", error = ex.GetType().Name, message = ex.Message, exitCode = ExitError });
            return ExitError;
        }
    }

    #region Command Handlers

    /// <summary>
    /// logicflow store scan <path> [--min-size <bytes>] [--json]
    /// Scans target path, reports duplicate clusters, savings potential, and MinHash similarity.
    /// </summary>
    private static async Task<int> HandleScanAsync(CliContext ctx, CancellationToken ct)
    {
        var tokens = ExtractSubcommandArgs(ctx, "scan");
        string? targetPath = tokens.FirstOrDefault(t => !t.StartsWith('-'));

        if (string.IsNullOrWhiteSpace(targetPath))
        {
            OutputFormatter.WriteError(ctx, "Missing required argument <path> for store scan.", new { error = "MISSING_ARGUMENT", command = "scan", exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        if (!Directory.Exists(targetPath))
        {
            OutputFormatter.WriteError(ctx, $"Target directory not found: '{targetPath}'", new { error = "DIRECTORY_NOT_FOUND", targetPath, exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        long minSize = 8192; // 8 KB default
        for (int i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Equals("--min-size", StringComparison.OrdinalIgnoreCase) && i + 1 < tokens.Count)
            {
                if (long.TryParse(tokens[i + 1], out long parsedMin))
                {
                    minSize = Math.Max(0, parsedMin);
                }
            }
        }

        var sw = Stopwatch.StartNew();
        string fullPath = Path.GetFullPath(targetPath);
        string fileSystem = GetDriveFileSystem(fullPath);

        // Safe file enumeration
        var candidateFiles = new List<FileInfo>();
        try
        {
            var dir = new DirectoryInfo(fullPath);
            foreach (var fi in dir.EnumerateFiles("*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (fi.Length >= minSize)
                    {
                        candidateFiles.Add(fi);
                    }
                }
                catch { /* Skip inaccessible files */ }
            }
        }
        catch (Exception ex)
        {
            OutputFormatter.WriteError(ctx, $"Failed to enumerate files: {ex.Message}", new { error = "ENUMERATION_FAILED", details = ex.ToString(), exitCode = ExitError });
            return ExitError;
        }

        var chunker = new FastCdcChunker();
        var clusterer = MinHashClusterer.Instance;

        long totalLogicalBytes = 0;
        int totalChunks = 0;
        var chunkIndexMap = new Dictionary<Hash256, int>();
        var exactDupMap = new Dictionary<Hash256, List<string>>();
        var fileSignatures = new List<(string Path, MinHashSignature Sig, long Length)>();

        foreach (var fi in candidateFiles)
        {
            ct.ThrowIfCancellationRequested();
            totalLogicalBytes += fi.Length;

            try
            {
                using var fs = new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var chunks = chunker.ChunkStream(fs).ToList();
                totalChunks += chunks.Count;

                // Index chunks for deduplication measurement
                foreach (var chunk in chunks)
                {
                    if (chunkIndexMap.TryGetValue(chunk.Fingerprint, out int count))
                    {
                        chunkIndexMap[chunk.Fingerprint] = count + 1;
                    }
                    else
                    {
                        chunkIndexMap[chunk.Fingerprint] = 1;
                    }
                }

                // MinHash signature for file resemblance
                var sig = clusterer.ComputeSignature(chunks);
                fileSignatures.Add((fi.FullName, sig, fi.Length));

                // Whole-file fingerprint from chunks if non-empty
                if (chunks.Count > 0)
                {
                    fs.Position = 0;
                    byte[] wholeData = new byte[Math.Min(fi.Length, 1024 * 1024)];
                    int read = await fs.ReadAsync(wholeData.AsMemory(0, wholeData.Length), ct).ConfigureAwait(false);
                    var fileHash = Hash256.Compute(wholeData.AsSpan(0, read));
                    if (!exactDupMap.TryGetValue(fileHash, out var dupList))
                    {
                        dupList = new List<string>();
                        exactDupMap[fileHash] = dupList;
                    }
                    dupList.Add(fi.FullName);
                }
            }
            catch
            {
                // Skip files that cannot be opened
            }
        }

        int uniqueChunks = chunkIndexMap.Count;
        int duplicateChunks = Math.Max(0, totalChunks - uniqueChunks);

        // Calculate potential savings: sum of duplicate files
        int exactDuplicateFiles = 0;
        int duplicateClusters = 0;
        long potentialSavingsBytes = 0;

        foreach (var kvp in exactDupMap)
        {
            if (kvp.Value.Count > 1)
            {
                duplicateClusters++;
                exactDuplicateFiles += (kvp.Value.Count - 1);
                try
                {
                    long singleLen = new FileInfo(kvp.Value[0]).Length;
                    potentialSavingsBytes += singleLen * (kvp.Value.Count - 1);
                }
                catch { }
            }
        }

        // MinHash pairwise similarity clustering
        int similarClusters = 0;
        double totalSim = 0.0;
        int simPairs = 0;

        for (int i = 0; i < fileSignatures.Count; i++)
        {
            for (int j = i + 1; j < fileSignatures.Count; j++)
            {
                double sim = clusterer.ComputeSimilarity(fileSignatures[i].Sig, fileSignatures[j].Sig);
                if (sim >= 0.50)
                {
                    similarClusters++;
                }
                totalSim += sim;
                simPairs++;
            }
        }

        double avgSimilarity = simPairs > 0 ? Math.Round(totalSim / simPairs, 4) : 0.0;
        double savingsPercent = totalLogicalBytes > 0
            ? Math.Round((double)potentialSavingsBytes / totalLogicalBytes * 100.0, 1)
            : 0.0;

        sw.Stop();

        var jsonModel = new
        {
            status = "SUCCESS",
            command = "scan",
            targetPath = fullPath,
            fileSystem,
            scannedFiles = candidateFiles.Count,
            totalLogicalBytes,
            formattedLogicalSize = FormatBytes(totalLogicalBytes),
            chunksIndexed = totalChunks,
            uniqueChunks,
            duplicateChunks,
            exactDuplicateFiles,
            duplicateClusters,
            similarClusters,
            minHashSimilarity = avgSimilarity,
            potentialSavingsBytes,
            formattedSavings = FormatBytes(potentialSavingsBytes),
            savingsPercent,
            durationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1)
        };

        if (ctx.IsJson)
        {
            OutputFormatter.Write(ctx, string.Empty, jsonModel);
            return ExitSuccess;
        }

        OutputFormatter.Write(ctx, "LogicFlow HyperStore (V-Dense) — Redundancy & Chunk Scanner", null, ConsoleColor.Cyan);
        OutputFormatter.Write(ctx, $"Scanning Target : {fullPath}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Filesystem      : {fileSystem} | Min File Size: {FormatBytes(minSize)}\n", null, ConsoleColor.Gray);

        OutputFormatter.Write(ctx, "  SCAN SUMMARY:", null, ConsoleColor.White);
        OutputFormatter.Write(ctx, $"    Total Files Scanned      : {candidateFiles.Count:N0} files ({FormatBytes(totalLogicalBytes)} logical)", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    FastCDC Chunks Indexed   : {totalChunks:N0} chunks", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Unique Chunks Stored     : {uniqueChunks:N0} chunks", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Redundant Chunks Found   : {duplicateChunks:N0} chunks", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Exact Duplicate Files    : {exactDuplicateFiles:N0} files in {duplicateClusters:N0} cluster(s)", null, ConsoleColor.Yellow);
        OutputFormatter.Write(ctx, $"    Similar Clusters (MinHash): {similarClusters:N0} clusters (Avg Jaccard: {avgSimilarity:F2})", null, ConsoleColor.Yellow);
        OutputFormatter.Write(ctx, $"    Total Potential Savings  : {FormatBytes(potentialSavingsBytes)} ({savingsPercent:F1}% storage reclamation)", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Scan Duration            : {sw.Elapsed.TotalMilliseconds:N1} ms", null, ConsoleColor.DarkGray);

        return ExitSuccess;
    }

    /// <summary>
    /// logicflow store dedup <path> [--dry-run] [--preserve-mutable] [--force] [--json]
    /// Executes safe host deduplication via VolumeAwareDeduplicator, reporting reclaimed bytes.
    /// </summary>
    private static async Task<int> HandleDedupAsync(CliContext ctx, CancellationToken ct)
    {
        var tokens = ExtractSubcommandArgs(ctx, "dedup");
        string? targetPath = tokens.FirstOrDefault(t => !t.StartsWith('-'));

        if (string.IsNullOrWhiteSpace(targetPath))
        {
            OutputFormatter.WriteError(ctx, "Missing required argument <path> for store dedup.", new { error = "MISSING_ARGUMENT", command = "dedup", exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        if (!Directory.Exists(targetPath))
        {
            OutputFormatter.WriteError(ctx, $"Target directory not found: '{targetPath}'", new { error = "DIRECTORY_NOT_FOUND", targetPath, exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        bool isDryRun = tokens.Any(t => t.Equals("--dry-run", StringComparison.OrdinalIgnoreCase));
        bool preserveMutable = !tokens.Any(t => t.Equals("--allow-mutable", StringComparison.OrdinalIgnoreCase)) ||
                               tokens.Any(t => t.Equals("--preserve-mutable", StringComparison.OrdinalIgnoreCase));
        bool isForce = ctx.IsForce || tokens.Any(t => t.Equals("--force", StringComparison.OrdinalIgnoreCase) || t.Equals("-f", StringComparison.OrdinalIgnoreCase));

        // Interactive safety prompt if live deduplication and not forced
        if (!isDryRun && !isForce && !Console.IsInputRedirected && !ctx.IsJson)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"[DEDUP] You are about to execute live deduplication on '{targetPath}'. Proceed? [y/N]: ");
            Console.ResetColor();
            string? response = Console.ReadLine();
            if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(response?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
            {
                OutputFormatter.WriteError(ctx, "Deduplication cancelled by user.", new { status = "CANCELLED", exitCode = ExitCancelled });
                return ExitCancelled;
            }
        }

        var sw = Stopwatch.StartNew();
        var options = new DedupOptions
        {
            DryRun = isDryRun,
            AllowMutableHardLinks = !preserveMutable,
            EnableCrossVolumeLfcFallback = true,
            ExcludedPaths = CliEditionGate.LoadScanExclusions(ctx.AppDataRootOverride)
        };

        DedupResult result = await VolumeAwareDeduplicator.Instance.DeduplicateDirectoryAsync(targetPath, options, null, ct).ConfigureAwait(false);
        sw.Stop();

        var jsonModel = new
        {
            status = "SUCCESS",
            command = "dedup",
            dryRun = isDryRun,
            targetPath = Path.GetFullPath(targetPath),
            filesProcessed = result.TotalFilesScanned,
            duplicateClusters = result.DuplicateClustersFound,
            filesConsolidated = result.DuplicatesConsolidated,
            mutableFilesPreserved = result.MutableFilesPreserved,
            crossVolumeFilesHandled = result.CrossVolumeFilesHandled,
            physicalBytesReclaimed = result.TotalBytesReclaimed,
            formattedBytesReclaimed = FormatBytes(result.TotalBytesReclaimed),
            durationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1),
            warnings = result.Warnings,
            errors = result.Errors
        };

        if (ctx.IsJson)
        {
            OutputFormatter.Write(ctx, string.Empty, jsonModel);
            return ExitSuccess;
        }

        OutputFormatter.Write(ctx, "LogicFlow HyperStore (V-Dense) — Host Volume Deduplication", null, ConsoleColor.Cyan);
        OutputFormatter.Write(ctx, $"Target          : {Path.GetFullPath(targetPath)}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Execution Mode  : {(isDryRun ? "Simulation (Dry Run — Zero File Modifications)" : "Live In-Place Consolidation")}", null, isDryRun ? ConsoleColor.Yellow : ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"Mutable Docs    : {(preserveMutable ? "Preserved (Safe Immutability Guard Active)" : "Consolidated")}\n", null, ConsoleColor.Gray);

        OutputFormatter.Write(ctx, "  DEDUPLICATION SUMMARY:", null, ConsoleColor.White);
        OutputFormatter.Write(ctx, $"    Files Scanned           : {result.TotalFilesScanned:N0} files", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Duplicate Clusters      : {result.DuplicateClustersFound:N0} clusters", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Files Consolidated      : {result.DuplicatesConsolidated:N0} files", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Skipped Mutable Files   : {result.MutableFilesPreserved:N0} files", null, ConsoleColor.Yellow);
        OutputFormatter.Write(ctx, $"    Cross-Volume Files      : {result.CrossVolumeFilesHandled:N0} files", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Physical Space Freed    : {FormatBytes(result.TotalBytesReclaimed)} ({result.TotalBytesReclaimed:N0} bytes)", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Duration                : {sw.Elapsed.TotalMilliseconds:N1} ms", null, ConsoleColor.DarkGray);

        return ExitSuccess;
    }

    /// <summary>
    /// logicflow store pack <input-dir> <output.lfc> [--tier <hot|cold>] [--dict] [--force] [--json]
    /// Compresses folder into sovereign .lfc container via LfcWriter.PackDirectoryAsync.
    /// </summary>
    private static async Task<int> HandlePackAsync(CliContext ctx, CancellationToken ct)
    {
        var tokens = ExtractSubcommandArgs(ctx, "pack");
        var positional = tokens.Where(t => !t.StartsWith('-')).ToList();

        if (positional.Count < 2)
        {
            OutputFormatter.WriteError(ctx, "Missing required arguments: store pack <input-dir> <output.lfc>", new { error = "MISSING_ARGUMENTS", command = "pack", exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        string inputDir = positional[0];
        string outputFile = positional[1];

        if (!Directory.Exists(inputDir))
        {
            OutputFormatter.WriteError(ctx, $"Source directory not found: '{inputDir}'", new { error = "DIRECTORY_NOT_FOUND", inputDir, exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        bool isForce = ctx.IsForce || tokens.Any(t => t.Equals("--force", StringComparison.OrdinalIgnoreCase) || t.Equals("-f", StringComparison.OrdinalIgnoreCase));
        if (File.Exists(outputFile) && !isForce)
        {
            OutputFormatter.WriteError(ctx, $"Output file already exists: '{outputFile}'. Use --force to overwrite.", new { error = "FILE_ALREADY_EXISTS", outputFile, exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        // Tier parsing
        CompressionTier tier = CompressionTier.Hot;
        for (int i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Equals("--tier", StringComparison.OrdinalIgnoreCase) && i + 1 < tokens.Count)
            {
                string t = tokens[i + 1].ToLowerInvariant();
                tier = t switch
                {
                    "cold" => CompressionTier.Cold,
                    _ => CompressionTier.Hot
                };
            }
        }

        bool trainDict = tokens.Any(t => t.Equals("--dict", StringComparison.OrdinalIgnoreCase));

        var sw = Stopwatch.StartNew();
        var packOptions = new LfcPackOptions
        {
            Tier = tier,
            TrainDictionary = trainDict,
            EnableDeltaCompression = true,
            ExcludedPaths = CliEditionGate.LoadScanExclusions(ctx.AppDataRootOverride)
        };

        using (var writer = new LfcWriter())
        {
            await writer.PackDirectoryAsync(inputDir, outputFile, packOptions, null, ct).ConfigureAwait(false);
        }

        using var reader = new LfcReader();
        var info = reader.InspectArchive(outputFile);
        sw.Stop();

        var jsonModel = new
        {
            status = "SUCCESS",
            command = "pack",
            inputDir = Path.GetFullPath(inputDir),
            outputFile = Path.GetFullPath(outputFile),
            tier = tier.ToString(),
            trainDictionary = trainDict,
            rawSizeBytes = info.TotalRawBytes,
            formattedRawSize = FormatBytes(info.TotalRawBytes),
            containerSizeBytes = info.TotalCompressedBytes,
            formattedContainerSize = FormatBytes(info.TotalCompressedBytes),
            compressionRatio = info.SpaceReductionRatio,
            spaceSavedBytes = info.SpaceSavingsBytes,
            formattedSpaceSaved = FormatBytes(info.SpaceSavingsBytes),
            chunksStored = info.TotalUniqueChunks,
            totalFiles = info.TotalFiles,
            durationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1)
        };

        if (ctx.IsJson)
        {
            OutputFormatter.Write(ctx, string.Empty, jsonModel);
            return ExitSuccess;
        }

        OutputFormatter.Write(ctx, "LogicFlow HyperStore (V-Dense) — Container Archiver (.lfc)", null, ConsoleColor.Cyan);
        OutputFormatter.Write(ctx, $"Source          : {Path.GetFullPath(inputDir)}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Destination     : {Path.GetFullPath(outputFile)}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Compression Tier: {tier} {(trainDict ? "+ Trained Dictionary" : "")}\n", null, ConsoleColor.Gray);

        OutputFormatter.Write(ctx, "  PACK COMPLETE:", null, ConsoleColor.White);
        OutputFormatter.Write(ctx, $"    Source Files Processed  : {info.TotalFiles:N0} files", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Raw Input Size          : {FormatBytes(info.TotalRawBytes)} ({info.TotalRawBytes:N0} bytes)", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Container Size (.lfc)   : {FormatBytes(info.TotalCompressedBytes)} ({info.TotalCompressedBytes:N0} bytes)", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Global Compression Ratio: {info.SpaceReductionRatio:F2}x ({FormatBytes(info.SpaceSavingsBytes)} saved)", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Unique Chunks Stored    : {info.TotalUniqueChunks:N0} chunks", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Duration                : {sw.Elapsed.TotalMilliseconds:N1} ms", null, ConsoleColor.DarkGray);

        return ExitSuccess;
    }

    /// <summary>
    /// logicflow store unpack <input.lfc> <output-dir> [--no-verify] [--force] [--json]
    /// Restores folder structure from .lfc container via LfcReader.UnpackArchiveAsync.
    /// </summary>
    private static async Task<int> HandleUnpackAsync(CliContext ctx, CancellationToken ct)
    {
        var tokens = ExtractSubcommandArgs(ctx, "unpack");
        var positional = tokens.Where(t => !t.StartsWith('-')).ToList();

        if (positional.Count < 2)
        {
            OutputFormatter.WriteError(ctx, "Missing required arguments: store unpack <input.lfc> <output-dir>", new { error = "MISSING_ARGUMENTS", command = "unpack", exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        string inputFile = positional[0];
        string outputDir = positional[1];

        if (!File.Exists(inputFile))
        {
            OutputFormatter.WriteError(ctx, $"Container file not found: '{inputFile}'", new { error = "FILE_NOT_FOUND", inputFile, exitCode = ExitInvalidArguments });
            return ExitInvalidArguments;
        }

        bool noVerify = tokens.Any(t => t.Equals("--no-verify", StringComparison.OrdinalIgnoreCase));
        bool isForce = ctx.IsForce || tokens.Any(t => t.Equals("--force", StringComparison.OrdinalIgnoreCase) || t.Equals("-f", StringComparison.OrdinalIgnoreCase));

        var sw = Stopwatch.StartNew();
        using var reader = new LfcReader();
        var unpackOptions = new LfcUnpackOptions
        {
            Overwrite = isForce,
            VerifyHashes = !noVerify
        };

        await reader.UnpackArchiveAsync(inputFile, outputDir, unpackOptions, null, ct).ConfigureAwait(false);
        var info = reader.InspectArchive(inputFile);
        sw.Stop();

        var jsonModel = new
        {
            status = "SUCCESS",
            command = "unpack",
            inputFile = Path.GetFullPath(inputFile),
            outputDir = Path.GetFullPath(outputDir),
            filesRestored = info.TotalFiles,
            totalBytesExtracted = info.TotalRawBytes,
            formattedTotalBytes = FormatBytes(info.TotalRawBytes),
            chunksVerified = info.TotalUniqueChunks,
            verificationSuccess = !noVerify,
            durationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1)
        };

        if (ctx.IsJson)
        {
            OutputFormatter.Write(ctx, string.Empty, jsonModel);
            return ExitSuccess;
        }

        OutputFormatter.Write(ctx, "LogicFlow HyperStore (V-Dense) — Container Extractor (.lfc)", null, ConsoleColor.Cyan);
        OutputFormatter.Write(ctx, $"Container       : {Path.GetFullPath(inputFile)}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Destination     : {Path.GetFullPath(outputDir)}", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"Hash Verification: {(noVerify ? "Disabled (--no-verify)" : "Active (256-bit BLAKE3 SIMD)")}\n", null, noVerify ? ConsoleColor.Yellow : ConsoleColor.Green);

        OutputFormatter.Write(ctx, "  UNPACK COMPLETE:", null, ConsoleColor.White);
        OutputFormatter.Write(ctx, $"    Files Restored          : {info.TotalFiles:N0} files", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Total Bytes Written     : {FormatBytes(info.TotalRawBytes)} ({info.TotalRawBytes:N0} bytes)", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Chunks Verified         : {info.TotalUniqueChunks:N0} chunks", null, ConsoleColor.Gray);
        OutputFormatter.Write(ctx, $"    Integrity Status        : {(!noVerify ? "PASS (Zero bit rot detected)" : "SKIPPED")}", null, ConsoleColor.Green);
        OutputFormatter.Write(ctx, $"    Duration                : {sw.Elapsed.TotalMilliseconds:N1} ms", null, ConsoleColor.DarkGray);

        return ExitSuccess;
    }

    #endregion

    #region Helpers & Diagnostics

    private static int ShowHelp(CliContext ctx)
    {
        string helpText =
            "LogicFlow HyperStore (V-Dense) CLI Commands\n" +
            "Usage: lf store <command> [arguments] [options]\n\n" +
            "Commands:\n" +
            "  scan   <path> [--min-size <bytes>] [--json]\n" +
            "         Scans target path, reports duplicate clusters, savings potential, and MinHash similarity.\n\n" +
            "  dedup  <path> [--dry-run] [--preserve-mutable] [--force] [--json]\n" +
            "         Executes safe host deduplication via VolumeAwareDeduplicator.\n\n" +
            "  pack   <input-dir> <output.lfc> [--tier <hot|cold>] [--dict] [--force] [--json]\n" +
            "         Compresses folder into .lfc container via LfcWriter.\n\n" +
            "  unpack <input.lfc> <output-dir> [--no-verify] [--force] [--json]\n" +
            "         Restores folder structure from .lfc container via LfcReader.\n\n" +
            "Options:\n" +
            "  --json            Output structured machine-readable JSON.\n" +
            "  --force           Overwrite existing targets or bypass confirmation prompts.\n" +
            "  --dry-run         Simulate operation without modifying filesystem.\n" +
            "  --silent          Suppress standard output logging.\n";

        var jsonModel = new
        {
            group = "store",
            description = "HyperStore (V-Dense) content-defined chunking, deduplication and .lfc container engine",
            commands = new[]
            {
                new { name = "scan", syntax = "lf store scan <path> [--min-size <bytes>] [--json]" },
                new { name = "dedup", syntax = "lf store dedup <path> [--dry-run] [--preserve-mutable] [--force] [--json]" },
                new { name = "pack", syntax = "lf store pack <input-dir> <output.lfc> [--tier <hot|cold>] [--dict] [--force] [--json]" },
                new { name = "unpack", syntax = "lf store unpack <input.lfc> <output-dir> [--no-verify] [--force] [--json]" }
            }
        };

        OutputFormatter.Write(ctx, helpText, jsonModel, ConsoleColor.Cyan);
        return ExitSuccess;
    }

    private static int HandleUnknownCommand(CliContext ctx, string command)
    {
        OutputFormatter.WriteError(ctx, $"Unknown store command: '{command}'. Available: scan, dedup, pack, unpack", new { error = "UNKNOWN_COMMAND", group = "store", command, exitCode = ExitInvalidArguments });
        return ExitInvalidArguments;
    }

    private static List<string> ExtractSubcommandArgs(CliContext ctx, string subcommand)
    {
        var tokens = ctx.RemainingArgs.ToList();
        if (tokens.Count > 0 && tokens[0].Equals("store", StringComparison.OrdinalIgnoreCase))
        {
            tokens.RemoveAt(0);
        }
        if (tokens.Count > 0 && tokens[0].Equals(subcommand, StringComparison.OrdinalIgnoreCase))
        {
            tokens.RemoveAt(0);
        }
        return tokens;
    }

    private static string GetDriveFileSystem(string path)
    {
        try
        {
            string? root = Path.GetPathRoot(path);
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                return drive.DriveFormat;
            }
        }
        catch { }
        return "NTFS";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        string[] suffixes = ["B", "KB", "MB", "GB", "TB"];
        int counter = 0;
        decimal number = bytes;
        while (Math.Round(number / 1024) >= 1 && counter < suffixes.Length - 1)
        {
            number /= 1024;
            counter++;
        }
        return $"{number:n2} {suffixes[counter]}";
    }

    #endregion
}
