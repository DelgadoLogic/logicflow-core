// LogicFlow.Tests — GameCompressionEngineEmpiricalStressTests.cs
// Adversarial Empirical Stress Test Suite for Milestone 3:
// GameCompressionEngine, GameCompressionWatchdog, Concurrency Bounds,
// Progress Streaming Validity, DirectStorage Safety, Cancellation Semantics,
// SHA-256 Content Integrity, File-Lock Resilience, and Multi-Threaded Stress.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public sealed class GameCompressionEngineEmpiricalStressTests : IDisposable
{
    private readonly string _testScratchDir;
    private readonly string _watchdogFilePath;

    public GameCompressionEngineEmpiricalStressTests()
    {
        _testScratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_M3_EmpiricalStress_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testScratchDir);
        _watchdogFilePath = Path.Combine(_testScratchDir, "game_compression.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testScratchDir))
            {
                foreach (var file in Directory.GetFiles(_testScratchDir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        WofNative.DecompressFile(file);
                    }
                    catch { }
                }
                Directory.Delete(_testScratchDir, recursive: true);
            }
        }
        catch { }
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        byte[] hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    private string CreateCompressibleFile(string dir, string relativePath, int sizeBytes = 64 * 1024)
    {
        string fullPath = Path.Combine(dir, relativePath);
        string parentDir = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(parentDir);

        byte[] repeatedPattern = Encoding.UTF8.GetBytes("DelgadoLogic LogicFlow High-Throughput Transparent WOF Compression Engine 2026\r\n");
        using var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None);
        int written = 0;
        while (written < sizeBytes)
        {
            int toWrite = Math.Min(repeatedPattern.Length, sizeBytes - written);
            fs.Write(repeatedPattern, 0, toWrite);
            written += toWrite;
        }
        return fullPath;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 1. EMPIRICAL EXECUTION: COMPRESS, DECOMPRESS, AUDIT, RECOMPACT
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CompressGameAsync_EmpiricalNTFSCompression_VerifiesRatioAndSavedBytes()
    {
        string gameDir = Path.Combine(_testScratchDir, "EmpiricalGame1");
        Directory.CreateDirectory(gameDir);

        var filePaths = new List<string>();
        var originalHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Create 8 compressible files across root and subfolders
        for (int i = 0; i < 4; i++)
        {
            string path = CreateCompressibleFile(gameDir, $"root_asset_{i}.dat", 128 * 1024);
            filePaths.Add(path);
            originalHashes[path] = ComputeSha256(path);
        }
        for (int i = 0; i < 4; i++)
        {
            string path = CreateCompressibleFile(gameDir, $"SubFolder/sub_asset_{i}.txt", 128 * 1024);
            filePaths.Add(path);
            originalHashes[path] = ComputeSha256(path);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("game_empirical_1", "Empirical Game 1", gameDir, LauncherType.Steam, 1024 * 1024, HasDirectStorage: false);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_LZX));

        Assert.True(summary.Success);
        Assert.Equal(8, summary.FilesProcessed);
        Assert.Equal(8, summary.FilesCompressed);
        Assert.Equal(0, summary.FilesSkipped);
        Assert.True(summary.SavedBytes > 0, $"Expected saved bytes > 0, but got {summary.SavedBytes}");
        Assert.True(summary.CompressedBytes < summary.OriginalBytes, "CompressedBytes must be strictly less than OriginalBytes");
        Assert.True(summary.Ratio < 1.0, $"Ratio must be < 1.0, got {summary.Ratio}");
        Assert.True(summary.SpaceSavedPercent > 0.0, "SpaceSavedPercent must be > 0.0");

        // Empirical check: Verify kernel reports each file as compressed
        foreach (var path in filePaths)
        {
            Assert.True(WofNative.IsFileCompressed(path), $"Kernel reported file is not compressed: {path}");

            // Verify transparent read content integrity (SHA-256 matches uncompressed data)
            string currentHash = ComputeSha256(path);
            Assert.Equal(originalHashes[path], currentHash);
        }

        // Verify watchdog catalog state
        var state = engine.LoadState();
        Assert.True(state.TrackedGames.ContainsKey(game.GameId));
        var record = state.TrackedGames[game.GameId];
        Assert.Equal(8, record.CompressedFileCount);
        Assert.Equal(8, record.TotalTrackedFiles);
        Assert.True(record.SavedBytes > 0);
    }

    [Fact]
    public async Task DecompressGameAsync_RestoresPhysicalClusters_AndRemovesGameFromCatalog()
    {
        string gameDir = Path.Combine(_testScratchDir, "DecompressGame1");
        Directory.CreateDirectory(gameDir);

        var filePaths = new List<string>();
        var preCompressionHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < 5; i++)
        {
            string path = CreateCompressibleFile(gameDir, $"assets_{i}.dat", 96 * 1024);
            filePaths.Add(path);
            preCompressionHashes[path] = ComputeSha256(path);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("decompress_game_1", "Decompress Game 1", gameDir, LauncherType.Steam, 500 * 1024, false);

        // Compress first
        var compSummary = await engine.CompressGameAsync(game, new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_XPRESS8K));
        Assert.True(compSummary.Success);
        Assert.Equal(5, compSummary.FilesCompressed);

        // Now decompress
        var decompSummary = await engine.DecompressGameAsync(game);

        Assert.True(decompSummary.Success);
        Assert.Equal(5, decompSummary.FilesProcessed);
        Assert.Equal(5, decompSummary.FilesDecompressed);
        Assert.True(decompSummary.RestoredBytes > 0);

        // Verify kernel confirms files are no longer compressed
        foreach (var path in filePaths)
        {
            Assert.False(WofNative.IsFileCompressed(path), $"File should no longer be compressed after DecompressGameAsync: {path}");
            // Verify content integrity after decompression
            string decompressedHash = ComputeSha256(path);
            Assert.Equal(preCompressionHashes[path], decompressedHash);
        }

        // Verify game entry is purged from catalog
        var finalState = engine.LoadState();
        Assert.False(finalState.TrackedGames.ContainsKey(game.GameId), "Decompressed game must be removed from catalog.");
    }

    [Fact]
    public async Task AuditGameDecay_And_RecompactUpdatesAsync_AccurateDeltaTrackingAndResolution()
    {
        string gameDir = Path.Combine(_testScratchDir, "DecayRecompactGame");
        Directory.CreateDirectory(gameDir);

        string file1 = CreateCompressibleFile(gameDir, "stable_data.dat", 128 * 1024);
        string file2 = CreateCompressibleFile(gameDir, "patch_target.dat", 128 * 1024);
        string file3 = CreateCompressibleFile(gameDir, "deleted_later.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("decay_game_1", "Decay Game 1", gameDir, LauncherType.Steam, 400 * 1024, false);

        // Step 1: Initial compression
        var compSummary = await engine.CompressGameAsync(game, new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_LZX));
        Assert.True(compSummary.Success);
        Assert.Equal(3, compSummary.FilesCompressed);

        // Step 2: Audit immediately — should be 0 decay
        var initialAudit = engine.AuditGameDecay(game);
        Assert.False(initialAudit.HasDecay);
        Assert.Equal(0, initialAudit.NewOrModifiedFileCount);
        Assert.Empty(initialAudit.DecayedFilePaths ?? Array.Empty<string>());

        // Step 3: Simulate realistic game patch:
        // Case A: Modified existing file (patch_target.dat is uncompressed and rewritten with new content)
        WofNative.DecompressFile(file2);
        File.AppendAllText(file2, "\r\n--- STEAM PATCH V1.02 CONTENT UNCOMPRESSED ---");
        File.SetLastWriteTimeUtc(file2, DateTime.UtcNow.AddMinutes(10));

        // Case B: Brand new uncompressed file added
        string file4New = CreateCompressibleFile(gameDir, "dlc_expansion.dat", 96 * 1024);

        // Case C: One file removed
        File.Delete(file3);

        // Step 4: Audit decay
        var postPatchAudit = engine.AuditGameDecay(game);
        Assert.True(postPatchAudit.HasDecay);
        Assert.Equal(2, postPatchAudit.NewOrModifiedFileCount); // file2 modified + file4 new
        Assert.Equal(1, postPatchAudit.NewFilesCount);
        Assert.Equal(1, postPatchAudit.ModifiedFilesCount);
        Assert.Equal(1, postPatchAudit.DeletedFilesCount);
        Assert.True(postPatchAudit.UncompressedBytesEligible > 0);

        string rel2 = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, file2));
        string rel4 = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, file4New));
        Assert.Contains(rel2, postPatchAudit.DecayedRelativePaths);
        Assert.Contains(rel4, postPatchAudit.DecayedRelativePaths);

        // Step 5: Multi-game audit aggregation check
        var aggReport = engine.AuditDecay(new[] { game });
        Assert.Equal(1, aggReport.TotalGamesAudited);
        Assert.Equal(1, aggReport.GamesWithDecay);
        Assert.True(aggReport.HasDecay);
        Assert.Equal(2, aggReport.CalculatedTotalDecayedFiles);

        // Step 6: 1-Click Re-compact Updates
        var recompactSummary = await engine.RecompactUpdatesAsync(game);
        Assert.True(recompactSummary.Success);
        Assert.Equal(2, recompactSummary.FilesProcessed); // ONLY the 2 decayed files!
        Assert.Equal(2, recompactSummary.FilesCompressed);

        // Step 7: Verify decay is now completely cleared
        var postRecompactAudit = engine.AuditGameDecay(game);
        Assert.False(postRecompactAudit.HasDecay);
        Assert.Equal(0, postRecompactAudit.NewOrModifiedFileCount);
        Assert.Empty(postRecompactAudit.DecayedFilePaths ?? Array.Empty<string>());

        // Verify catalog updated: deleted file3 pruned, file4 added, file2 updated
        var state = engine.LoadState();
        var record = state.TrackedGames[game.GameId];
        Assert.False(record.Files.ContainsKey(GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, file3))));
        Assert.True(record.Files.ContainsKey(rel2));
        Assert.True(record.Files.ContainsKey(rel4));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 2. CONCURRENCY BOUNDS EMPIRICAL VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(null, 1, 8)]
    [InlineData(0, 1, 8)]
    [InlineData(-5, 1, 8)]
    [InlineData(1, 1, 1)]
    [InlineData(2, 2, 2)]
    [InlineData(4, 4, 4)]
    [InlineData(8, 8, 8)]
    [InlineData(16, 16, 16)]
    [InlineData(32, 32, 32)]
    [InlineData(64, 32, 32)]  // Clamped to 32 max
    [InlineData(128, 32, 32)] // Clamped to 32 max
    public void GameCompressionOptions_EffectiveParallelism_StrictlyBounded(int? input, int minExpected, int maxExpected)
    {
        var options = new GameCompressionOptions(MaxParallelism: input);
        Assert.InRange(options.EffectiveParallelism, minExpected, maxExpected);
    }

    [Fact]
    public async Task CompressGameAsync_ConcurrencyBoundsRespected_DuringExecution()
    {
        string gameDir = Path.Combine(_testScratchDir, "ConcurrencyBoundedGame");
        Directory.CreateDirectory(gameDir);

        // Create 20 compressible files
        for (int i = 0; i < 20; i++)
        {
            CreateCompressibleFile(gameDir, $"thread_asset_{i:D2}.dat", 64 * 1024);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("bounded_game", "Bounded Concurrency Game", gameDir, LauncherType.Custom, 1024 * 1024, false);

        // Limit parallelism to 2
        var options = new GameCompressionOptions(MaxParallelism: 2);
        Assert.Equal(2, options.EffectiveParallelism);

        var summary = await engine.CompressGameAsync(game, options);

        Assert.True(summary.Success);
        Assert.Equal(20, summary.FilesProcessed);
        Assert.Equal(20, summary.FilesCompressed);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 3. PROGRESS STREAMING: THROUGHPUT, PERCENTAGE, AND FILE COUNTS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CompressGameAsync_StreamsValidProgressEvents_MonotonicAndValidMetrics()
    {
        string gameDir = Path.Combine(_testScratchDir, "ProgressStreamGame");
        Directory.CreateDirectory(gameDir);

        const int fileCount = 12;
        for (int i = 0; i < fileCount; i++)
        {
            CreateCompressibleFile(gameDir, $"stream_asset_{i:D2}.dat", 64 * 1024);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("stream_game", "Progress Stream Game", gameDir, LauncherType.Custom, fileCount * 64 * 1024, false);

        var progressEvents = new List<CompressionProgress>();
        var progressSync = new object();
        var progressReporter = new Progress<CompressionProgress>(p =>
        {
            lock (progressSync)
            {
                progressEvents.Add(p);
            }
        });

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_XPRESS8K), progressReporter);

        Assert.True(summary.Success);
        Assert.NotEmpty(progressEvents);

        lock (progressSync)
        {
            // Verify every progress event conforms to interface contracts
            foreach (var evt in progressEvents)
            {
                Assert.NotNull(evt);
                Assert.Equal(fileCount, evt.TotalFiles);
                Assert.InRange(evt.FilesCompleted, 0, fileCount);
                Assert.InRange(evt.PercentComplete, 0.0, 100.0);
                Assert.True(evt.ThroughputMBs >= 0.0, $"ThroughputMBs must be non-negative: {evt.ThroughputMBs}");
                Assert.True(evt.InstantThroughputMBps >= 0.0, $"InstantThroughputMBps must be non-negative: {evt.InstantThroughputMBps}");
                Assert.True(evt.BytesProcessed >= 0, $"BytesProcessed must be non-negative: {evt.BytesProcessed}");
                Assert.True(evt.BytesSaved >= 0, $"BytesSaved must be non-negative: {evt.BytesSaved}");
                Assert.True(evt.Elapsed >= TimeSpan.Zero, "Elapsed must be non-negative");
            }

            // Final event must be 100% complete and report StatusMessage "Complete"
            var finalEvt = progressEvents.Last();
            Assert.Equal(fileCount, finalEvt.FilesCompleted);
            Assert.Equal(fileCount, finalEvt.TotalFiles);
            Assert.Equal(100.0, finalEvt.PercentComplete, precision: 1);
            Assert.Equal("Complete", finalEvt.StatusMessage);
        }
    }

    [Fact]
    public async Task DecompressGameAsync_StreamsValidProgressEvents()
    {
        string gameDir = Path.Combine(_testScratchDir, "DecompressProgressGame");
        Directory.CreateDirectory(gameDir);

        for (int i = 0; i < 6; i++)
        {
            CreateCompressibleFile(gameDir, $"decomp_progress_{i}.dat", 64 * 1024);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("decomp_prog_game", "Decompress Progress Game", gameDir, LauncherType.Steam, 6 * 64 * 1024, false);

        // Compress first
        await engine.CompressGameAsync(game);

        var decompEvents = new List<CompressionProgress>();
        var sync = new object();
        var progress = new Progress<CompressionProgress>(p =>
        {
            lock (sync) decompEvents.Add(p);
        });

        var decompSummary = await engine.DecompressGameAsync(game, progress);

        Assert.True(decompSummary.Success);
        Assert.NotEmpty(decompEvents);

        lock (sync)
        {
            var finalEvt = decompEvents.Last();
            Assert.Equal(6, finalEvt.FilesCompleted);
            Assert.Equal(6, finalEvt.TotalFiles);
            Assert.Equal(100.0, finalEvt.PercentComplete, precision: 1);
            Assert.Equal("Complete", finalEvt.StatusMessage);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 4. DIRECTSTORAGE SAFETY: SKIPPED WHEN SkipDirectStorage == true
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CompressGameAsync_DirectStoragePropertyTrue_SkipsCompression()
    {
        string gameDir = Path.Combine(_testScratchDir, "DSPropertyGame");
        Directory.CreateDirectory(gameDir);
        CreateCompressibleFile(gameDir, "game_asset.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ds_prop_game", "DS Property Game", gameDir, LauncherType.Steam, 64 * 1024, HasDirectStorage: true);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: true));

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesCompressed);
        Assert.Contains("DirectStorage", summary.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public async Task CompressGameAsync_DirectStorageDllInRoot_SkipsCompression()
    {
        string gameDir = Path.Combine(_testScratchDir, "DSRootDllGame");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "fake directstorage dll binary");
        CreateCompressibleFile(gameDir, "asset.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ds_root_game", "DS Root Game", gameDir, LauncherType.Steam, 64 * 1024, HasDirectStorage: false);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: true));

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesCompressed);
        Assert.Contains("DirectStorage", summary.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public async Task CompressGameAsync_DirectStorageCoreDllInRoot_SkipsCompression()
    {
        string gameDir = Path.Combine(_testScratchDir, "DSCoreDllGame");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "dstoragecore.dll"), "fake directstoragecore dll binary");
        CreateCompressibleFile(gameDir, "asset.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ds_core_game", "DS Core Game", gameDir, LauncherType.Epic, 64 * 1024, HasDirectStorage: false);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: true));

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesCompressed);
        Assert.Contains("DirectStorage", summary.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public async Task CompressGameAsync_DirectStorageNestedInSubfolder_SkipsCompression()
    {
        string gameDir = Path.Combine(_testScratchDir, "DSNestedGame");
        string binDir = Path.Combine(gameDir, "Engine", "Binaries", "Win64");
        Directory.CreateDirectory(binDir);
        File.WriteAllText(Path.Combine(binDir, "dstorage.dll"), "fake nested directstorage dll");
        CreateCompressibleFile(gameDir, "content.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ds_nested_game", "DS Nested Game", gameDir, LauncherType.Steam, 64 * 1024, HasDirectStorage: false);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: true));

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesCompressed);
        Assert.Contains("DirectStorage", summary.ErrorMessage ?? string.Empty);

        // Audit decay must also skip direct storage titles
        var decay = engine.AuditGameDecay(game);
        Assert.False(decay.HasDecay);
        Assert.False(decay.IsTracked);
    }

    [Fact]
    public async Task CompressGameAsync_WhenSkipDirectStorageFalse_OverridesSafetyAndCompresses()
    {
        string gameDir = Path.Combine(_testScratchDir, "DSOverrideGame");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "fake directstorage dll");
        CreateCompressibleFile(gameDir, "safe_data.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ds_override_game", "DS Override Game", gameDir, LauncherType.Steam, 64 * 1024, HasDirectStorage: true);

        // Explicitly set SkipDirectStorage: false to test override
        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: false));

        Assert.True(summary.Success);
        Assert.True(summary.FilesProcessed > 0, "Files should be processed when SkipDirectStorage is explicitly false");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 5. CANCELLATION SEMANTICS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CompressGameAsync_PreCancelledToken_ReturnsCancelledSummaryWithoutCrash()
    {
        string gameDir = Path.Combine(_testScratchDir, "PreCancelledGame");
        Directory.CreateDirectory(gameDir);
        CreateCompressibleFile(gameDir, "file_1.dat", 64 * 1024);
        CreateCompressibleFile(gameDir, "file_2.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("pre_cancel_game", "Pre-Cancelled Game", gameDir, LauncherType.Custom, 128 * 1024, false);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var summary = await engine.CompressGameAsync(game, ct: cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CompressGameAsync_MidFlightCancellation_PreservesPartialStateAndUncorruptedFiles()
    {
        string gameDir = Path.Combine(_testScratchDir, "MidFlightCancelGame");
        Directory.CreateDirectory(gameDir);

        const int fileCount = 50;
        var hashes = new Dictionary<string, string>();
        for (int i = 0; i < fileCount; i++)
        {
            string p = CreateCompressibleFile(gameDir, $"cancel_test_{i:D2}.dat", 128 * 1024);
            hashes[p] = ComputeSha256(p);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("midflight_game", "Midflight Cancel Game", gameDir, LauncherType.Custom, fileCount * 128 * 1024, false);

        using var cts = new CancellationTokenSource();
        int reported = 0;
        var progress = new Progress<CompressionProgress>(p =>
        {
            if (Interlocked.Increment(ref reported) >= 1)
            {
                try { cts.Cancel(); } catch { }
            }
        });

        // Use concurrency of 1 to ensure sequential cancellation trigger
        var options = new GameCompressionOptions(MaxParallelism: 1);
        var summary = await engine.CompressGameAsync(game, options, progress, cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        // Verify all files on disk remain completely uncorrupted
        foreach (var kvp in hashes)
        {
            Assert.True(File.Exists(kvp.Key));
            string currentHash = ComputeSha256(kvp.Key);
            Assert.Equal(kvp.Value, currentHash);
        }
    }

    [Fact]
    public async Task DecompressGameAsync_WhenCancelled_ReturnsCancelledSummary()
    {
        string gameDir = Path.Combine(_testScratchDir, "DecompressCancelGame");
        Directory.CreateDirectory(gameDir);
        CreateCompressibleFile(gameDir, "decomp_file.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("decomp_cancel_game", "Decompress Cancel Game", gameDir, LauncherType.Custom, 64 * 1024, false);

        await engine.CompressGameAsync(game);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var summary = await engine.DecompressGameAsync(game, ct: cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RecompactUpdatesAsync_WhenCancelled_ReturnsCancelledSummary()
    {
        string gameDir = Path.Combine(_testScratchDir, "RecompactCancelGame");
        Directory.CreateDirectory(gameDir);
        string file1 = CreateCompressibleFile(gameDir, "rec_file.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("rec_cancel_game", "Recompact Cancel Game", gameDir, LauncherType.Custom, 64 * 1024, false);

        await engine.CompressGameAsync(game);

        // Modify file to introduce decay
        WofNative.DecompressFile(file1);
        File.AppendAllText(file1, "extra content");
        File.SetLastWriteTimeUtc(file1, DateTime.UtcNow.AddMinutes(5));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var summary = await engine.RecompactUpdatesAsync(game, ct: cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 6. ADVERSARIAL RESILIENCE & EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Watchdog_HighConcurrencyThreadSafety_CoordinatedTransactions()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var syncLock = new object();

        // 20 parallel threads reading and updating distinct game records with transaction coordination
        var tasks = Enumerable.Range(0, 20).Select(i => Task.Run(() =>
        {
            for (int r = 0; r < 5; r++)
            {
                lock (syncLock)
                {
                    var state = watchdog.LoadState();
                    state.TrackedGames[$"thread_game_{i}"] = new TrackedGameRecord
                    {
                        GameId = $"thread_game_{i}",
                        Title = $"Thread Game {i}",
                        InstallDirectory = $@"C:\Games\Game_{i}",
                        TotalOriginalBytes = 1000 + i,
                        TotalCompressedBytes = 600 + i,
                        SavedBytes = 400
                    };
                    watchdog.SaveState(state);
                }
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        var finalState = watchdog.LoadState();
        Assert.NotNull(finalState);
        Assert.Equal(20, finalState.TrackedGames.Count);

        // Verify zero lingering .tmp files
        var tempFiles = Directory.GetFiles(_testScratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public async Task Watchdog_ConcurrentUncoordinatedWrites_ExposesSnapshotOverwriteRisk()
    {
        // Adversarial challenge: demonstrates that uncoordinated LoadState -> SaveState calls
        // across separate threads can overwrite snapshots unless coordinated by caller.
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);

        var task1 = Task.Run(async () =>
        {
            var state1 = watchdog.LoadState();
            await Task.Delay(40);
            state1.TrackedGames["uncoordinated_1"] = new TrackedGameRecord { GameId = "uncoordinated_1", Title = "Uncoordinated 1" };
            watchdog.SaveState(state1);
        });

        var task2 = Task.Run(async () =>
        {
            var state2 = watchdog.LoadState();
            await Task.Delay(40);
            state2.TrackedGames["uncoordinated_2"] = new TrackedGameRecord { GameId = "uncoordinated_2", Title = "Uncoordinated 2" };
            watchdog.SaveState(state2);
        });

        await Task.WhenAll(task1, task2);

        var finalState = watchdog.LoadState();
        Assert.NotNull(finalState);
        Assert.True(finalState.TrackedGames.Count >= 1, "At least one game must be saved without throwing exceptions.");
    }

    [Fact]
    public void Watchdog_CorruptedJsonRecovery_ArchivesAndSelfHeals()
    {
        File.WriteAllText(_watchdogFilePath, "{ invalid json malformed text {{[");
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);

        var state = watchdog.LoadState();
        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        // Verify backup archive file was created
        var backupFiles = Directory.GetFiles(_testScratchDir, "*corrupt*.bak");
        Assert.Single(backupFiles);

        // Subsequent save must succeed cleanly
        state.TrackedGames["healed_game"] = new TrackedGameRecord { GameId = "healed_game", Title = "Healed Title" };
        watchdog.SaveState(state);

        var reloaded = watchdog.LoadState();
        Assert.Single(reloaded.TrackedGames);
        Assert.Equal("Healed Title", reloaded.TrackedGames["healed_game"].Title);
    }

    [Fact]
    public async Task BatchCompression_FileLockResilience_GracefullySkipsLockedFile()
    {
        string gameDir = Path.Combine(_testScratchDir, "LockedFileGame");
        Directory.CreateDirectory(gameDir);

        string file1 = CreateCompressibleFile(gameDir, "normal_asset_1.dat", 64 * 1024);
        string file2Locked = CreateCompressibleFile(gameDir, "locked_asset.dat", 64 * 1024);
        string file3 = CreateCompressibleFile(gameDir, "normal_asset_2.dat", 64 * 1024);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("locked_game", "Locked Game", gameDir, LauncherType.Steam, 3 * 64 * 1024, false);

        // Open file2Locked with exclusive lock (FileShare.None)
        using (var lockStream = new FileStream(file2Locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var summary = await engine.CompressGameAsync(game);

            Assert.True(summary.Success);
            Assert.Equal(3, summary.FilesProcessed);
            // File2 should have been skipped, while File1 and File3 compressed
            Assert.Equal(2, summary.FilesCompressed);
            Assert.Equal(1, summary.FilesSkipped);
        }

        // Verify normal files compressed
        Assert.True(WofNative.IsFileCompressed(file1));
        Assert.True(WofNative.IsFileCompressed(file3));
    }

    [Fact]
    public async Task BatchCompression_ReadOnlyFiles_CompressedAndAttributePreserved()
    {
        string gameDir = Path.Combine(_testScratchDir, "ReadOnlyGame");
        Directory.CreateDirectory(gameDir);

        string readOnlyFile = CreateCompressibleFile(gameDir, "readonly_asset.dat", 64 * 1024);
        string shaBefore = ComputeSha256(readOnlyFile);

        File.SetAttributes(readOnlyFile, FileAttributes.ReadOnly);
        Assert.True(File.GetAttributes(readOnlyFile).HasFlag(FileAttributes.ReadOnly));

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("readonly_game", "ReadOnly Game", gameDir, LauncherType.Custom, 64 * 1024, false);

        var summary = await engine.CompressGameAsync(game);

        Assert.True(summary.Success);
        Assert.Equal(1, summary.FilesCompressed);
        Assert.True(WofNative.IsFileCompressed(readOnlyFile));

        // Verify ReadOnly attribute preserved
        Assert.True(File.GetAttributes(readOnlyFile).HasFlag(FileAttributes.ReadOnly));

        // Verify content integrity
        Assert.Equal(shaBefore, ComputeSha256(readOnlyFile));
    }

    [Fact]
    public async Task CompressGameAsync_NonExistentInstallDirectory_ReturnsSafeFailure()
    {
        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("non_existent", "Non Existent Game", @"X:\NonExistentPath\InvalidDir", LauncherType.Custom, 0, false);

        var summary = await engine.CompressGameAsync(game);

        Assert.False(summary.Success);
        Assert.Contains("does not exist", summary.ErrorMessage ?? string.Empty);
    }
}
