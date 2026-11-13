// LogicFlow.Tests — GameCompressionWatchdogAdversarialTests.cs
// Empirical Challenger 2 Adversarial Stress Suite for Milestone 3:
// 1. Atomic state persistence against power loss/crash scenarios (temp file lifecycle, atomic replace, high-concurrency races).
// 2. Corrupted JSON handling (truncated files, random binary garbage, mismatched schemas, backup generation, self-healing).
// 3. Fast-path decay auditing (2.0s timestamp tolerance boundary, size changes, new DLC files, deleted files, DirectStorage exclusion).
// 4. Locked file resilience (ERROR_SHARING_VIOLATION, FileShare.None, ReadOnly attributes, graceful batch continuation).
// 5. Pre-flight volume free space verification logic & edge cases during decompression.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public sealed class GameCompressionWatchdogAdversarialTests : IDisposable
{
    private readonly string _scratchDir;
    private readonly string _watchdogFilePath;

    public GameCompressionWatchdogAdversarialTests()
    {
        _scratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_AdvWatchdog_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratchDir);
        _watchdogFilePath = Path.Combine(_scratchDir, "game_compression.json");
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

    // ═════════════════════════════════════════════════════════════════════════
    // 1. ATOMIC PERSISTENCE & CRASH/POWER LOSS RESILIENCE
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Watchdog_SaveState_AtomicMoveReplacesTarget_NoTemporaryFilesOrphaned()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        state.TrackedGames["game_alpha"] = new TrackedGameRecord
        {
            GameId = "game_alpha",
            Title = "Game Alpha",
            InstallDirectory = Path.Combine(_scratchDir, "Alpha"),
            TotalOriginalBytes = 5000,
            TotalCompressedBytes = 2500,
            SavedBytes = 2500,
            AlgorithmUsed = WofNative.ALGORITHM_LZX
        };

        watchdog.SaveState(state);

        Assert.True(File.Exists(_watchdogFilePath));
        var loaded = watchdog.LoadState();
        Assert.Single(loaded.TrackedGames);
        Assert.Equal("Game Alpha", loaded.TrackedGames["game_alpha"].Title);

        // Verify that no .tmp files linger anywhere in the directory
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public void Watchdog_SaveState_WhenPreExistingTempFilesExist_LeavesExistingUntouchedAndCleansUpOwn()
    {
        // Simulate a stale .tmp file left by a prior hard power-off crash
        string staleTmp = Path.Combine(_scratchDir, "game_compression.json.deadbeefdeadbeefdeadbeefdeadbeef.tmp");
        File.WriteAllText(staleTmp, "stale content from previous crash");

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        state.TrackedGames["game_beta"] = new TrackedGameRecord
        {
            GameId = "game_beta",
            Title = "Game Beta",
            InstallDirectory = Path.Combine(_scratchDir, "Beta")
        };

        watchdog.SaveState(state);

        Assert.True(File.Exists(_watchdogFilePath));
        Assert.True(File.Exists(staleTmp), "Stale crash temp file should remain untouched by unrelated save operations.");
        Assert.Equal("stale content from previous crash", File.ReadAllText(staleTmp));

        // No new temporary files should have been left behind
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Single(tempFiles);
        Assert.Equal(staleTmp, tempFiles[0]);
    }

    [Fact]
    public void Watchdog_SaveState_WhenTargetFolderDoesNotExist_CreatesDirectoryAndPersistsState()
    {
        string deeplyNestedPath = Path.Combine(_scratchDir, "Nested", "Sub", "Dir", "state.json");
        var watchdog = new GameCompressionWatchdog(deeplyNestedPath);

        var state = new GameCompressionState();
        state.TrackedGames["nested_game"] = new TrackedGameRecord
        {
            GameId = "nested_game",
            Title = "Nested Game"
        };

        watchdog.SaveState(state);

        Assert.True(File.Exists(deeplyNestedPath));
        var loaded = watchdog.LoadState();
        Assert.True(loaded.TrackedGames.ContainsKey("nested_game"));
    }

    [Fact]
    public void Watchdog_SaveState_WhenTargetFileLockedForWriting_ThrowsAndCleansUpTempFile()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        state.TrackedGames["lock_test"] = new TrackedGameRecord { GameId = "lock_test", Title = "Locked Test" };

        // Save initial state so the file exists
        watchdog.SaveState(state);

        // Lock the target file with FileShare.None
        using (var lockStream = new FileStream(_watchdogFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            state.TrackedGames["lock_test"].Title = "Updated Title While Locked";

            // Attempting to overwrite while exclusively locked throws UnauthorizedAccessException or IOException on Windows
            var ex = Assert.ThrowsAny<Exception>(() => watchdog.SaveState(state));
            Assert.True(ex is UnauthorizedAccessException || ex is IOException, $"Expected UnauthorizedAccessException or IOException, but got {ex.GetType().Name}");
        }

        // Even though SaveState threw, the temp file MUST be deleted by the finally block
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public void Watchdog_SaveState_UnderHighConcurrency_MultipleThreadsSavingConcurrently_LeavesValidState()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        int threadCount = 20;
        var exceptions = new ConcurrentBag<Exception>();

        Parallel.For(0, threadCount, i =>
        {
            try
            {
                var state = new GameCompressionState();
                state.TrackedGames[$"game_{i}"] = new TrackedGameRecord
                {
                    GameId = $"game_{i}",
                    Title = $"Concurrent Game {i}",
                    SavedBytes = i * 1000
                };
                watchdog.SaveState(state);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.True(File.Exists(_watchdogFilePath));

        // The final state must be completely valid JSON and deserializable without error
        var finalState = watchdog.LoadState();
        Assert.NotNull(finalState);
        Assert.NotEmpty(finalState.TrackedGames);

        // Verify zero temporary files were leaked
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public async Task Watchdog_SaveAndLoad_HighConcurrencyRace_NeverReadsPartialOrCorruptedState()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);

        // Seed initial state
        var initialState = new GameCompressionState();
        initialState.TrackedGames["seed"] = new TrackedGameRecord { GameId = "seed", Title = "Seed Game" };
        watchdog.SaveState(initialState);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var exceptions = new ConcurrentBag<Exception>();
        long successfulLoads = 0;
        long successfulSaves = 0;

        // Writer task: continuously writes states with varied payload sizes
        var writerTask = Task.Run(() =>
        {
            int counter = 0;
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var state = new GameCompressionState();
                    for (int i = 0; i < (counter % 15) + 1; i++)
                    {
                        state.TrackedGames[$"game_{i}"] = new TrackedGameRecord
                        {
                            GameId = $"game_{i}",
                            Title = $"Game {i} - iteration {counter}",
                            TotalOriginalBytes = 10000 + i,
                            TotalCompressedBytes = 5000 + i
                        };
                    }
                    watchdog.SaveState(state);
                    Interlocked.Increment(ref successfulSaves);
                    counter++;
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        });

        // Reader task: continuously reads and validates state integrity
        var readerTask = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var loaded = watchdog.LoadState();
                    Assert.NotNull(loaded);
                    Assert.NotNull(loaded.TrackedGames);
                    // The loaded state must never be empty because there is always at least one game
                    Assert.NotEmpty(loaded.TrackedGames);
                    Interlocked.Increment(ref successfulLoads);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        });

        await Task.WhenAll(writerTask, readerTask);

        Assert.Empty(exceptions);
        Assert.True(Interlocked.Read(ref successfulSaves) > 10, "Should have performed multiple concurrent saves.");
        Assert.True(Interlocked.Read(ref successfulLoads) > 50, "Should have performed multiple concurrent loads.");

        // No orphaned temp files
        var tempFiles = Directory.GetFiles(_scratchDir, "*.tmp");
        Assert.Empty(tempFiles);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 2. CORRUPTED JSON HANDLING & DISASTER RECOVERY
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Watchdog_LoadState_WhenTruncatedJson_ArchivesCorruptedFileAndReturnsFreshState()
    {
        string truncatedJson = "{\"Version\": 1, \"TrackedGames\": {\"game_1\": {\"GameId\": \"game_1\", \"Title\": \"Incomplete";
        File.WriteAllText(_watchdogFilePath, truncatedJson, Encoding.UTF8);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        // Verify .corrupt.<timestamp>.bak was created
        var backupFiles = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(backupFiles);

        // Verify the backup file contains the exact truncated JSON byte-for-byte
        string backedUpContent = File.ReadAllText(backupFiles[0], Encoding.UTF8);
        Assert.Equal(truncatedJson, backedUpContent);
    }

    [Fact]
    public void Watchdog_LoadState_WhenBinaryGarbage_ArchivesCorruptedFileAndReturnsFreshState()
    {
        byte[] garbage = new byte[] { 0x00, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x80, 0x90 };
        File.WriteAllBytes(_watchdogFilePath, garbage);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        var backupFiles = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(backupFiles);

        byte[] backedUpBytes = File.ReadAllBytes(backupFiles[0]);
        Assert.Equal(garbage, backedUpBytes);
    }

    [Fact]
    public void Watchdog_LoadState_WhenMismatchedSchema_ArchivesCorruptedFileAndReturnsFreshState()
    {
        // Valid JSON syntax, but invalid schema: TrackedGames is an integer instead of dictionary
        string mismatchedJson = "{\"Version\": 1, \"TrackedGames\": 99999}";
        File.WriteAllText(_watchdogFilePath, mismatchedJson, Encoding.UTF8);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        var backupFiles = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(backupFiles);
        Assert.Equal(mismatchedJson, File.ReadAllText(backupFiles[0]));
    }

    [Fact]
    public void Watchdog_LoadState_WhenEmptyOrWhitespace_ReturnsFreshStateWithoutCreatingBackup()
    {
        File.WriteAllText(_watchdogFilePath, "    \r\n\t  \r\n  ");

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = watchdog.LoadState();

        Assert.NotNull(state);
        Assert.Empty(state.TrackedGames);

        // Empty file should not be treated as a corruption requiring backup
        var backupFiles = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Empty(backupFiles);
    }

    [Fact]
    public void Watchdog_SelfHealingLoop_SubsequentSaveAndLoadWorksCleanly()
    {
        // Step 1: Write corrupted JSON
        File.WriteAllText(_watchdogFilePath, "{ corrupted json syntax !@#$%^&*");

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);

        // Step 2: Load triggers corruption recovery and archives to .bak
        var freshState = watchdog.LoadState();
        Assert.Empty(freshState.TrackedGames);

        var initialBackups = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(initialBackups);

        // Step 3: Populate state and save
        freshState.TrackedGames["healed_game"] = new TrackedGameRecord
        {
            GameId = "healed_game",
            Title = "Healed Game Title",
            SavedBytes = 12345
        };
        watchdog.SaveState(freshState);

        // Step 4: Subsequent load should read successfully and NOT create any additional backup files
        var reloadedState = watchdog.LoadState();
        Assert.Single(reloadedState.TrackedGames);
        Assert.Equal("Healed Game Title", reloadedState.TrackedGames["healed_game"].Title);

        var postSaveBackups = Directory.GetFiles(_scratchDir, "*corrupt*.bak");
        Assert.Single(postSaveBackups); // Still just the 1 initial backup
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 3. FAST-PATH DECAY AUDITING EMPIRICAL VERIFICATION
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void AuditGameDecay_WhenTimestampModifiedWithinTwoSecondTolerance_FastPathDoesNotFlagDecay()
    {
        string gameDir = Path.Combine(_scratchDir, "ToleranceGame");
        Directory.CreateDirectory(gameDir);

        string testFile = Path.Combine(gameDir, "asset.bin");
        File.WriteAllText(testFile, "Consistent payload content for fast-path tolerance verification.");

        var fi = new FileInfo(testFile);
        DateTime baselineTime = fi.LastWriteTimeUtc;

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord
        {
            GameId = "tol_game",
            Title = "Tolerance Game",
            InstallDirectory = gameDir,
            LastCompressionTimeUtc = baselineTime,
            TotalOriginalBytes = fi.Length,
            TotalCompressedBytes = fi.Length / 2,
            SavedBytes = fi.Length / 2,
            AlgorithmUsed = WofNative.ALGORITHM_LZX
        };

        string relPath = GameCompressionWatchdog.NormalizeRelativePath("asset.bin");
        record.Files[relPath] = new TrackedFileEntry(
            RelativePath: relPath,
            LastWriteTimeUtc: baselineTime,
            Length: fi.Length,
            IsCompressed: true,
            Algorithm: WofNative.ALGORITHM_LZX);

        state.TrackedGames["tol_game"] = record;
        watchdog.SaveState(state);

        var game = new DetectedGame("tol_game", "Tolerance Game", gameDir, LauncherType.Steam, fi.Length, false);

        // Baseline: No decay
        var baselineDecay = watchdog.AuditGameDecay(game);
        Assert.False(baselineDecay.HasDecay);

        // Alter timestamp by +1.5 seconds (within the 2.0s tolerance window)
        File.SetLastWriteTimeUtc(testFile, baselineTime.AddSeconds(1.5));

        var withinToleranceDecay = watchdog.AuditGameDecay(game);
        Assert.False(withinToleranceDecay.HasDecay, "Timestamp shift <= 2.0s should NOT trigger decay re-compaction.");
        Assert.Equal(0, withinToleranceDecay.NewOrModifiedFileCount);
    }

    [Fact]
    public void AuditGameDecay_WhenTimestampModifiedBeyondTwoSecondTolerance_FlagsModifiedDecay()
    {
        string gameDir = Path.Combine(_scratchDir, "BeyondToleranceGame");
        Directory.CreateDirectory(gameDir);

        string testFile = Path.Combine(gameDir, "asset.bin");
        File.WriteAllText(testFile, "Uncompressed payload content after Steam game update.");

        var fi = new FileInfo(testFile);
        DateTime baselineTime = DateTime.UtcNow.AddHours(-1);
        File.SetLastWriteTimeUtc(testFile, baselineTime);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord
        {
            GameId = "beyond_tol_game",
            Title = "Beyond Tolerance Game",
            InstallDirectory = gameDir,
            LastCompressionTimeUtc = baselineTime
        };

        string relPath = GameCompressionWatchdog.NormalizeRelativePath("asset.bin");
        record.Files[relPath] = new TrackedFileEntry(
            RelativePath: relPath,
            LastWriteTimeUtc: baselineTime,
            Length: fi.Length,
            IsCompressed: true,
            Algorithm: WofNative.ALGORITHM_LZX);

        state.TrackedGames["beyond_tol_game"] = record;
        watchdog.SaveState(state);

        var game = new DetectedGame("beyond_tol_game", "Beyond Tolerance Game", gameDir, LauncherType.Steam, fi.Length, false);

        // Shift timestamp by +5.0 seconds (well beyond the 2.0s threshold)
        File.SetLastWriteTimeUtc(testFile, baselineTime.AddSeconds(5.0));

        var decay = watchdog.AuditGameDecay(game);
        Assert.True(decay.HasDecay, "Timestamp shift > 2.0s must trigger decay re-compaction.");
        Assert.Equal(1, decay.NewOrModifiedFileCount);
        Assert.Equal(1, decay.ModifiedFilesCount);
        Assert.Equal(0, decay.NewFilesCount);
        Assert.Contains(relPath, decay.DecayedRelativePaths);
        Assert.Equal(fi.Length, decay.UncompressedBytesEligible);
    }

    [Fact]
    public void AuditGameDecay_WhenSizeModifiedWithExactSameTimestamp_FlagsModifiedDecay()
    {
        string gameDir = Path.Combine(_scratchDir, "SizeChangeGame");
        Directory.CreateDirectory(gameDir);

        // Note: use .dat, as .pak is intentionally excluded by GameSafetyHeuristics pre-compressed filter
        string testFile = Path.Combine(gameDir, "data.dat");
        File.WriteAllText(testFile, "Initial content");

        var fi = new FileInfo(testFile);
        DateTime originalTime = DateTime.UtcNow.AddMinutes(-30);
        File.SetLastWriteTimeUtc(testFile, originalTime);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord
        {
            GameId = "size_game",
            Title = "Size Change Game",
            InstallDirectory = gameDir
        };

        string relPath = GameCompressionWatchdog.NormalizeRelativePath("data.dat");
        record.Files[relPath] = new TrackedFileEntry(
            RelativePath: relPath,
            LastWriteTimeUtc: originalTime,
            Length: fi.Length,
            IsCompressed: true,
            Algorithm: WofNative.ALGORITHM_LZX);

        state.TrackedGames["size_game"] = record;
        watchdog.SaveState(state);

        var game = new DetectedGame("size_game", "Size Change Game", gameDir, LauncherType.Steam, fi.Length, false);

        // Append content (size changes) but preserve exact original timestamp
        File.AppendAllText(testFile, " + Extra appended update content that increases size.");
        File.SetLastWriteTimeUtc(testFile, originalTime);

        var decay = watchdog.AuditGameDecay(game);
        Assert.True(decay.HasDecay, "Size alteration with identical timestamp must be detected as decay.");
        Assert.Equal(1, decay.ModifiedFilesCount);
        Assert.Contains(relPath, decay.DecayedRelativePaths);
    }

    [Fact]
    public void AuditGameDecay_WhenNewFileAddedInSubdirectory_FlagsNewFileDecay()
    {
        string gameDir = Path.Combine(_scratchDir, "DlcGame");
        Directory.CreateDirectory(gameDir);
        string dlcSubDir = Path.Combine(gameDir, "DLC_01");
        Directory.CreateDirectory(dlcSubDir);

        string baseFile = Path.Combine(gameDir, "base.dat");
        File.WriteAllText(baseFile, "Base game data");

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord
        {
            GameId = "dlc_game",
            Title = "DLC Game",
            InstallDirectory = gameDir
        };

        string baseRel = GameCompressionWatchdog.NormalizeRelativePath("base.dat");
        var baseFi = new FileInfo(baseFile);
        record.Files[baseRel] = new TrackedFileEntry(baseRel, baseFi.LastWriteTimeUtc, baseFi.Length, true, WofNative.ALGORITHM_LZX);

        state.TrackedGames["dlc_game"] = record;
        watchdog.SaveState(state);

        var game = new DetectedGame("dlc_game", "DLC Game", gameDir, LauncherType.Steam, 1000, false);

        // Add brand new DLC file in subfolder
        string dlcFile = Path.Combine(dlcSubDir, "expansion.dat");
        File.WriteAllText(dlcFile, "Brand new uncompressed expansion asset pack.");
        var dlcFi = new FileInfo(dlcFile);

        var decay = watchdog.AuditGameDecay(game);
        Assert.True(decay.HasDecay);
        Assert.Equal(1, decay.NewFilesCount);
        Assert.Equal(0, decay.ModifiedFilesCount);
        Assert.Equal(1, decay.NewOrModifiedFileCount);

        string expectedRel = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(gameDir, dlcFile));
        Assert.Contains(expectedRel, decay.DecayedRelativePaths);
        Assert.Equal(dlcFi.Length, decay.UncompressedBytesEligible);
    }

    [Fact]
    public void AuditGameDecay_WhenFileDeleted_TracksDeletedFilesCountWithoutFlaggingAsNewOrModified()
    {
        string gameDir = Path.Combine(_scratchDir, "DeleteGame");
        Directory.CreateDirectory(gameDir);

        string file1 = Path.Combine(gameDir, "file1.dat");
        File.WriteAllText(file1, "File 1 content");
        var fi1 = new FileInfo(file1);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord
        {
            GameId = "delete_game",
            Title = "Delete Game",
            InstallDirectory = gameDir
        };

        string rel1 = GameCompressionWatchdog.NormalizeRelativePath("file1.dat");
        string rel2 = GameCompressionWatchdog.NormalizeRelativePath("obsolete.dat");

        record.Files[rel1] = new TrackedFileEntry(rel1, fi1.LastWriteTimeUtc, fi1.Length, true, WofNative.ALGORITHM_LZX);
        record.Files[rel2] = new TrackedFileEntry(rel2, DateTime.UtcNow, 2048, true, WofNative.ALGORITHM_LZX);

        state.TrackedGames["delete_game"] = record;
        watchdog.SaveState(state);

        var game = new DetectedGame("delete_game", "Delete Game", gameDir, LauncherType.Steam, 1000, false);

        // obsolete.dat does not exist on disk (deleted by patch)
        var decay = watchdog.AuditGameDecay(game);
        Assert.False(decay.HasDecay, "Deleted files do NOT constitute uncompressed decay requiring re-compaction.");
        Assert.Equal(0, decay.NewOrModifiedFileCount);
        Assert.Equal(1, decay.DeletedFilesCount);
    }

    [Fact]
    public void AuditGameDecay_WhenZeroByteFileAdded_IgnoredFromDecay()
    {
        string gameDir = Path.Combine(_scratchDir, "ZeroByteGame");
        Directory.CreateDirectory(gameDir);

        string baseFile = Path.Combine(gameDir, "base.dat");
        File.WriteAllText(baseFile, "Base data");
        var baseFi = new FileInfo(baseFile);

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var state = new GameCompressionState();
        var record = new TrackedGameRecord { GameId = "zb_game", Title = "Zero Byte Game", InstallDirectory = gameDir };
        string baseRel = GameCompressionWatchdog.NormalizeRelativePath("base.dat");
        record.Files[baseRel] = new TrackedFileEntry(baseRel, baseFi.LastWriteTimeUtc, baseFi.Length, true, WofNative.ALGORITHM_LZX);
        state.TrackedGames["zb_game"] = record;
        watchdog.SaveState(state);

        // Introduce a 0-byte file (e.g. .touch or lock indicator)
        string zeroFile = Path.Combine(gameDir, "marker.zero");
        File.WriteAllBytes(zeroFile, Array.Empty<byte>());

        var game = new DetectedGame("zb_game", "Zero Byte Game", gameDir, LauncherType.Steam, 1000, false);

        var decay = watchdog.AuditGameDecay(game);
        Assert.False(decay.HasDecay, "Zero-byte files cannot be compressed and must not be marked as decay.");
        Assert.Equal(0, decay.NewOrModifiedFileCount);
    }

    [Fact]
    public void AuditGameDecay_WhenDirectStorageDetected_ReturnsNoDecayImmediately()
    {
        string gameDir = Path.Combine(_scratchDir, "DsAuditGame");
        Directory.CreateDirectory(gameDir);

        // Plant DirectStorage runtime
        File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "direct storage marker");

        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var game = new DetectedGame("ds_audit", "DS Audit Game", gameDir, LauncherType.Steam, 1000, HasDirectStorage: true);

        var decay = watchdog.AuditGameDecay(game);
        Assert.False(decay.HasDecay);
        Assert.False(decay.IsTracked);
        Assert.Equal(0, decay.NewOrModifiedFileCount);
    }

    [Fact]
    public void AuditDecay_AggregatesMultipleGamesAccurately()
    {
        var watchdog = new GameCompressionWatchdog(_watchdogFilePath);
        var games = new List<DetectedGame>();

        // Game 1: Clean (no decay)
        string dir1 = Path.Combine(_scratchDir, "MultiClean");
        Directory.CreateDirectory(dir1);
        string f1 = Path.Combine(dir1, "a.dat");
        File.WriteAllText(f1, "clean");
        var fi1 = new FileInfo(f1);

        // Game 2: Decayed (new file)
        string dir2 = Path.Combine(_scratchDir, "MultiDecayed");
        Directory.CreateDirectory(dir2);
        string f2 = Path.Combine(dir2, "b.dat");
        File.WriteAllText(f2, "decayed content block");
        var fi2 = new FileInfo(f2);

        var state = new GameCompressionState();
        var rec1 = new TrackedGameRecord { GameId = "g1", Title = "G1", InstallDirectory = dir1 };
        rec1.Files["a.dat"] = new TrackedFileEntry("a.dat", fi1.LastWriteTimeUtc, fi1.Length, true, 1);
        state.TrackedGames["g1"] = rec1;

        var rec2 = new TrackedGameRecord { GameId = "g2", Title = "G2", InstallDirectory = dir2 };
        // rec2 has no tracked files, so f2 is seen as new file
        state.TrackedGames["g2"] = rec2;

        watchdog.SaveState(state);

        games.Add(new DetectedGame("g1", "G1", dir1, LauncherType.Steam, fi1.Length, false));
        games.Add(new DetectedGame("g2", "G2", dir2, LauncherType.Steam, fi2.Length, false));

        var report = watchdog.AuditDecay(games);
        Assert.Equal(2, report.TotalGamesAudited);
        Assert.Equal(1, report.GamesWithDecay);
        Assert.True(report.HasDecay);
        Assert.Single(report.DecayedGames);
        Assert.Equal("g2", report.DecayedGames[0].GameId);
        Assert.Equal(fi2.Length, report.TotalUncompressedBytesEligible);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 4. LOCKED FILE RESILIENCE (SHARING VIOLATION & ACCESS DENIED)
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CompressGameAsync_WhenFileExclusivelyLocked_SkipsLockedFileAndCompressesRemainingFiles()
    {
        string gameDir = Path.Combine(_scratchDir, "LockedBatchGame");
        Directory.CreateDirectory(gameDir);

        string unlockedFile1 = Path.Combine(gameDir, "unlocked1.txt");
        string lockedFile = Path.Combine(gameDir, "locked.txt");
        string unlockedFile2 = Path.Combine(gameDir, "unlocked2.txt");

        string repetitiveText = string.Concat(Enumerable.Repeat("Compressible repeating data block DelgadoLogic 2026\r\n", 300));
        File.WriteAllText(unlockedFile1, repetitiveText);
        File.WriteAllText(lockedFile, repetitiveText);
        File.WriteAllText(unlockedFile2, repetitiveText);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("locked_batch", "Locked Batch Game", gameDir, LauncherType.Steam, 30000, false);

        // Lock the middle file exclusively with FileShare.None (simulating active game process holding lock)
        using (var lockStream = new FileStream(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var summary = await engine.CompressGameAsync(game, new GameCompressionOptions(Algorithm: WofNative.ALGORITHM_LZX));

            // The batch operation MUST NOT crash or abort
            Assert.True(summary.Success);
            Assert.Equal(3, summary.FilesProcessed);
            Assert.True(summary.FilesSkipped >= 1, "The locked file must be recorded in FilesSkipped.");

            // Verify the unlocked files were processed and stored in watchdog
            var state = engine.LoadState();
            Assert.True(state.TrackedGames.ContainsKey("locked_batch"));
            var record = state.TrackedGames["locked_batch"];
            Assert.Equal(3, record.TotalTrackedFiles);
        }
    }

    [Fact]
    public async Task DecompressGameAsync_WhenFileExclusivelyLocked_ContinuesDecompressingRemainingFilesWithoutCrashing()
    {
        string gameDir = Path.Combine(_scratchDir, "LockedDecompressGame");
        Directory.CreateDirectory(gameDir);

        string file1 = Path.Combine(gameDir, "file1.txt");
        string file2 = Path.Combine(gameDir, "file2.txt");

        string repetitiveText = string.Concat(Enumerable.Repeat("Compressible decompression content DelgadoLogic\r\n", 200));
        File.WriteAllText(file1, repetitiveText);
        File.WriteAllText(file2, repetitiveText);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("locked_decomp", "Locked Decompress Game", gameDir, LauncherType.Steam, 20000, false);

        // First compress both files
        var compSummary = await engine.CompressGameAsync(game);
        Assert.True(compSummary.Success);

        // Exclusively lock file1 with FileShare.None (simulating in-use game process)
        using (var lockStream = new FileStream(file1, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var decompSummary = await engine.DecompressGameAsync(game);

            // Decompression batch must complete gracefully without unhandled exception or crash
            Assert.True(decompSummary.Success);

            // Unlocked file2 is successfully decompressed
            Assert.True(decompSummary.FilesDecompressed >= 1, "Unlocked file2 must be decompressed.");
        }
    }

    [Fact]
    public async Task RecompactUpdatesAsync_WhenDecayedFileLocked_SkipsLockedFileAndCompletes()
    {
        string gameDir = Path.Combine(_scratchDir, "LockedRecompactGame");
        Directory.CreateDirectory(gameDir);

        string normalFile = Path.Combine(gameDir, "normal.txt");
        string lockedUpdateFile = Path.Combine(gameDir, "update_locked.txt");

        string repetitive = string.Concat(Enumerable.Repeat("Recompact delta payload DelgadoLogic 2026\r\n", 200));
        File.WriteAllText(normalFile, repetitive);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("locked_recomp", "Locked Recompact", gameDir, LauncherType.Steam, 10000, false);

        // Initial compress
        await engine.CompressGameAsync(game);

        // Introduce a new uncompressed file that represents an update
        File.WriteAllText(lockedUpdateFile, repetitive);

        // Lock the update file
        using (var lockStream = new FileStream(lockedUpdateFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var summary = await engine.RecompactUpdatesAsync(game);

            Assert.True(summary.Success);
            Assert.Equal(1, summary.FilesProcessed);
            Assert.Equal(1, summary.FilesSkipped);
        }
    }

    [Fact]
    public async Task CompressGameAsync_WhenFileHasReadOnlyAttribute_HandlesGracefully()
    {
        string gameDir = Path.Combine(_scratchDir, "ReadOnlyGame");
        Directory.CreateDirectory(gameDir);

        string roFile = Path.Combine(gameDir, "readonly.txt");
        string repetitive = string.Concat(Enumerable.Repeat("Readonly file compression resilience DelgadoLogic\r\n", 200));
        File.WriteAllText(roFile, repetitive);
        File.SetAttributes(roFile, FileAttributes.ReadOnly);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("ro_game", "ReadOnly Game", gameDir, LauncherType.Steam, 10000, false);

        var summary = await engine.CompressGameAsync(game);

        Assert.True(summary.Success);
        Assert.Equal(1, summary.FilesProcessed);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 5. PRE-FLIGHT VOLUME FREE SPACE VERIFICATION LOGIC
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task DecompressGameAsync_WhenNoExpansionNeeded_SucceedsImmediately()
    {
        string gameDir = Path.Combine(_scratchDir, "NoCompGame");
        Directory.CreateDirectory(gameDir);

        string normalFile = Path.Combine(gameDir, "plain.txt");
        File.WriteAllText(normalFile, "Uncompressed plain text");

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("no_comp", "No Comp Game", gameDir, LauncherType.Steam, 100, false);

        // When no files are compressed, DecompressGameAsync returns immediately
        var summary = await engine.DecompressGameAsync(game);

        Assert.True(summary.Success);
        Assert.Equal(0, summary.FilesProcessed);
        Assert.Equal(0, summary.FilesDecompressed);
        Assert.Equal(0L, summary.RestoredBytes);
    }

    [Fact]
    public async Task DecompressGameAsync_WhenCancelledViaToken_HaltsPromptly()
    {
        string gameDir = Path.Combine(_scratchDir, "CancelDecompGame");
        Directory.CreateDirectory(gameDir);

        string f1 = Path.Combine(gameDir, "f1.txt");
        string repetitive = string.Concat(Enumerable.Repeat("Cancel decompression test DelgadoLogic 2026\r\n", 300));
        File.WriteAllText(f1, repetitive);

        var engine = new GameCompressionEngine(watchdogFilePath: _watchdogFilePath);
        var game = new DetectedGame("cancel_decomp", "Cancel Decomp", gameDir, LauncherType.Steam, 10000, false);

        await engine.CompressGameAsync(game);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancel

        var summary = await engine.DecompressGameAsync(game, progress: null, ct: cts.Token);

        Assert.False(summary.Success);
        Assert.Contains("cancelled", summary.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GameDecompressionSummary_Failed_ContainsFormattedErrorMessageAndMetrics()
    {
        var failed = GameDecompressionSummary.Failed(
            gameId: "test_insufficient_space",
            title: "Space Failure Title",
            errorMessage: "Insufficient disk space to safely decompress game. Required: 52.4 GB, Available: 12.1 GB.",
            duration: TimeSpan.FromMilliseconds(42));

        Assert.False(failed.Success);
        Assert.Equal("test_insufficient_space", failed.GameId);
        Assert.Equal("Space Failure Title", failed.Title);
        Assert.Contains("Insufficient disk space", failed.ErrorMessage);
        Assert.Equal(0, failed.FilesDecompressed);
        Assert.Equal(0L, failed.RestoredBytes);
        Assert.Equal("0 B", failed.FormattedRestoredBytes);
        Assert.Equal("0.0 MB/s", failed.FormattedThroughput);
    }
}
