// LogicFlow.Tests — GameCompressionEngineTests.cs
// Comprehensive Unit & Integration Test Suite for Milestone 3:
// GameCompressionEngine, GameCompressionWatchdog, Options Presets, Parallel Batch Pipeline,
// Decompression, Decay Auditing, and Incremental Re-compaction.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public sealed class GameCompressionEngineTests : IDisposable
{
    private readonly string _scratchDir;
    private readonly string _customWatchdogPath;

    public GameCompressionEngineTests()
    {
        _scratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_GameCompactTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratchDir);
        _customWatchdogPath = Path.Combine(_scratchDir, "game_compression.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_scratchDir))
            {
                foreach (var file in Directory.GetFiles(_scratchDir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        WofNative.DecompressFile(file);
                    }
                    catch { }
                }
                Directory.Delete(_scratchDir, true);
            }
        }
        catch { }
    }

    // ─── 1. Options & Presets Tests ──────────────────────────────────────────

    [Fact]
    public void GameCompressionOptions_DefaultEffectiveParallelism_BoundedBetweenOneAndEight()
    {
        var options = GameCompressionOptions.Default;

        Assert.Equal(WofNative.ALGORITHM_LZX, options.Algorithm);
        Assert.Null(options.MaxParallelism);
        Assert.True(options.SkipDirectStorage);
        Assert.InRange(options.EffectiveParallelism, 1, 8);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(4, 4)]
    [InlineData(8, 8)]
    [InlineData(16, 16)]
    [InlineData(32, 32)]
    [InlineData(64, 32)] // Clamped to 32
    public void GameCompressionOptions_CustomParallelism_ClampedProperly(int input, int expected)
    {
        var options = new GameCompressionOptions(MaxParallelism: input);
        Assert.Equal(expected, options.EffectiveParallelism);
    }

    [Fact]
    public void GameCompressionOptions_StaticPresets_HaveCorrectAlgorithms()
    {
        Assert.Equal(WofNative.ALGORITHM_LZX, GameCompressionOptions.Maximum.Algorithm);
        Assert.Equal(WofNative.ALGORITHM_XPRESS8K, GameCompressionOptions.Balanced.Algorithm);
        Assert.Equal(WofNative.ALGORITHM_XPRESS16K, GameCompressionOptions.Fast.Algorithm);
    }

    // ─── 2. Summaries & Formatting Tests ─────────────────────────────────────

    [Fact]
    public void GameCompressionSummary_ThroughputAndSavedPercent_CalculatedCorrectly()
    {
        var summary = new GameCompressionSummary(
            GameId: "test_game_1",
            Title: "Test Game",
            Success: true,
            FilesProcessed: 100,
            FilesCompressed: 80,
            FilesSkipped: 20,
            OriginalBytes: 100 * 1024 * 1024L, // 100 MB
            CompressedBytes: 60 * 1024 * 1024L, // 60 MB
            SavedBytes: 40 * 1024 * 1024L,     // 40 MB
            Ratio: 0.60,
            Duration: TimeSpan.FromSeconds(2.0));

        Assert.Equal(40.0, summary.SpaceSavedPercent, 1);
        Assert.Equal(50.0, summary.ThroughputMBs, 1);
        Assert.Contains("MB", summary.FormattedOriginalBytes);
        Assert.Contains("MB", summary.FormattedCompressedBytes);
        Assert.Contains("MB", summary.FormattedSavedBytes);
        Assert.Contains("MB/s", summary.FormattedThroughput);
    }

    [Fact]
    public void GameCompressionSummary_Failed_ConstructsValidFailureRecord()
    {
        var failed = GameCompressionSummary.Failed("fail_id", "Fail Title", "Drive unavailable", TimeSpan.FromSeconds(1));

        Assert.False(failed.Success);
        Assert.Equal("fail_id", failed.GameId);
        Assert.Equal("Drive unavailable", failed.ErrorMessage);
        Assert.Equal(0, failed.FilesCompressed);
    }

    [Fact]
    public void GameDecompressionSummary_Failed_ConstructsValidFailureRecord()
    {
        var failed = GameDecompressionSummary.Failed("fail_id", "Fail Title", "Not enough disk space");

        Assert.False(failed.Success);
        Assert.Equal("fail_id", failed.GameId);
        Assert.Equal("Not enough disk space", failed.ErrorMessage);
    }

    // ─── 3. Watchdog State Persistence & Resilience ─────────────────────────

    [Fact]
    public void Watchdog_LoadState_WhenFileMissing_ReturnsFreshState()
    {
        string missingPath = Path.Combine(_scratchDir, "non_existent.json");
        var watchdog = new GameCompressionWatchdog(missingPath);

        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);
    }

    [Fact]
    public void Watchdog_SaveState_PerformsAtomicReplace_LeavesNoTempFiles()
    {
        var watchdog = new GameCompressionWatchdog(_customWatchdogPath);
        var state = new GameCompressionState();
        state.TrackedGames["game_1"] = new TrackedGameRecord
        {
            GameId = "game_1",
            Title = "Game One",
            InstallDirectory = @"C:\Games\GameOne",
            TotalOriginalBytes = 1000,
            TotalCompressedBytes = 600,
            SavedBytes = 400
        };

        watchdog.SaveState(state);

        Assert.True(File.Exists(_customWatchdogPath));
        var loaded = watchdog.LoadState();
        Assert.Single(loaded.TrackedGames);
        Assert.Equal("Game One", loaded.TrackedGames["game_1"].Title);

        // Verify no orphaned .tmp files remain in the folder
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public void Watchdog_LoadState_WhenCorruptedJson_ArchivesCorruptFileAndReturnsFreshState()
    {
        File.WriteAllText(_customWatchdogPath, "{ corrupt json content !!! not valid");
        var watchdog = new GameCompressionWatchdog(_customWatchdogPath);

        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        // Verify a .corrupt.*.bak archive was produced
        var backupFiles = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(backupFiles);
    }

    // ─── 4. DirectStorage Safety Check ──────────────────────────────────────

    [Fact]
    public async Task CompressGameAsync_WhenDirectStorageDetectedAndSkipEnabled_SkipsCompression()
    {
        string gameDir = Path.Combine(_scratchDir, "DirectStorageGame");
        Directory.CreateDirectory(gameDir);

        // Simulate presence of dstorage.dll
        string dstoragePath = Path.Combine(gameDir, "dstorage.dll");
        File.WriteAllText(dstoragePath, "fake direct storage dll content");

        string assetFile = Path.Combine(gameDir, "data.bin");
        File.WriteAllText(assetFile, "game content data block that should not be touched");

        var engine = new GameCompressionEngine(watchdogFilePath: _customWatchdogPath);
        var game = new DetectedGame("ds_game", "DS Game", gameDir, LauncherType.Steam, 1000, HasDirectStorage: true);

        var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(SkipDirectStorage: true));

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesCompressed);
        Assert.Contains("DirectStorage", summary.ErrorMessage ?? string.Empty);
    }

    [Fact]
    public async Task CompressGameAsync_MissingInstallDirectory_ReturnsFailureSummary()
    {
        var engine = new GameCompressionEngine(watchdogFilePath: _customWatchdogPath);
        var game = new DetectedGame("missing_game", "Missing Title", @"Z:\NonExistentDrive\GamePath", LauncherType.Custom, 0, false);

        var summary = await engine.CompressGameAsync(game);

        Assert.False(summary.Success);
        Assert.Contains("does not exist", summary.ErrorMessage);
    }

    // ─── 5. End-to-End Compression, Decompression & Decay Lifecycle ─────────

    [Fact]
    public async Task GameCompressionEngine_CompleteLifecycle_Compress_Audit_Recompact_Decompress()
    {
        string gameDir = Path.Combine(_scratchDir, "LifecycleGame");
        Directory.CreateDirectory(gameDir);
        string subDir = Path.Combine(gameDir, "SubData");
        Directory.CreateDirectory(subDir);

        // Create synthetic compressible files (text with repeated patterns)
        string file1 = Path.Combine(gameDir, "main_assets.dat");
        string file2 = Path.Combine(subDir, "dialogue.txt");
        string preCompressed = Path.Combine(gameDir, "movie.mp4"); // Should be filtered out

        string repeatedContent = string.Concat(Enumerable.Repeat("LogicFlow High Throughput Transparent WOF Compression DelgadoLogic 2026\r\n", 500));
        File.WriteAllText(file1, repeatedContent);
        File.WriteAllText(file2, repeatedContent);
        File.WriteAllText(preCompressed, "dummy mp4 content");

        var engine = new GameCompressionEngine(watchdogFilePath: _customWatchdogPath);
        var game = new DetectedGame("lifecycle_game_1", "Lifecycle Game", gameDir, LauncherType.Steam, 50000, HasDirectStorage: false);

        var progressList = new List<CompressionProgress>();
        var progressReporter = new Progress<CompressionProgress>(p => progressList.Add(p));

        // 1. Compress Game
        var compressSummary = await engine.CompressGameAsync(
            game,
            new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_LZX),
            progressReporter);

        Assert.True(compressSummary.Success);
        Assert.Equal(2, compressSummary.FilesProcessed); // movie.mp4 excluded by heuristics

        // Verify state is stored in watchdog
        var state = engine.LoadState();
        Assert.True(state.TrackedGames.ContainsKey(game.GameId));
        var record = state.TrackedGames[game.GameId];
        Assert.Equal(2, record.TotalTrackedFiles);

        // 2. Audit Decay (immediately after: no decay should be detected)
        var initialDecay = engine.AuditGameDecay(game);
        Assert.False(initialDecay.HasDecay);
        Assert.Equal(0, initialDecay.NewOrModifiedFileCount);

        // 3. Simulate game update / patch:
        // A: Modify existing file
        File.AppendAllText(file1, "\r\nNEW PATCH UPDATED CONTENT UNCOMPRESSED BY STEAM\r\n");
        // Ensure timestamp is modified beyond 2.0s tolerance
        File.SetLastWriteTimeUtc(file1, DateTime.UtcNow.AddMinutes(5));

        // B: Add new uncompressed DLC file
        string newDlcFile = Path.Combine(subDir, "dlc_expansion.dat");
        File.WriteAllText(newDlcFile, repeatedContent);

        // 4. Audit Decay again (should detect 2 decayed files: 1 modified, 1 new)
        var postUpdateDecay = engine.AuditGameDecay(game);
        Assert.True(postUpdateDecay.HasDecay);
        Assert.Equal(2, postUpdateDecay.NewOrModifiedFileCount);
        Assert.Contains(GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, file1)), postUpdateDecay.DecayedRelativePaths);
        Assert.Contains(GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, newDlcFile)), postUpdateDecay.DecayedRelativePaths);

        // Test multi-game audit aggregator
        var multiAudit = engine.AuditDecay(new[] { game });
        Assert.Equal(1, multiAudit.TotalGamesAudited);
        Assert.Equal(1, multiAudit.GamesWithDecay);
        Assert.True(multiAudit.HasDecay);

        // 5. 1-Click Re-compact Updates
        var recompactSummary = await engine.RecompactUpdatesAsync(game, new GameCompressionOptions());
        Assert.True(recompactSummary.Success);
        Assert.Equal(2, recompactSummary.FilesProcessed); // Only the 2 decayed files!

        // Verify audit is clean after re-compaction
        var postRecompactDecay = engine.AuditGameDecay(game);
        Assert.False(postRecompactDecay.HasDecay);
        Assert.Equal(0, postRecompactDecay.NewOrModifiedFileCount);

        // 6. Decompress Game
        var decompressSummary = await engine.DecompressGameAsync(game);
        Assert.True(decompressSummary.Success);

        // Verify game is removed from watchdog catalog after full decompression
        var finalState = engine.LoadState();
        Assert.False(finalState.TrackedGames.ContainsKey(game.GameId));
    }

    // ─── 6. Cooperative Cancellation ────────────────────────────────────────

    [Fact]
    public async Task CompressGameAsync_WhenCancelled_ReturnsPartialSummarySafely()
    {
        string gameDir = Path.Combine(_scratchDir, "CancelGame");
        Directory.CreateDirectory(gameDir);
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"file_{i}.txt"), "Test compressible content " + i);
        }

        var engine = new GameCompressionEngine(watchdogFilePath: _customWatchdogPath);
        var game = new DetectedGame("cancel_game", "Cancel Game", gameDir, LauncherType.Custom, 1000, false);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancelled

        var summary = await engine.CompressGameAsync(game, options: null, progress: null, ct: cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }
}
