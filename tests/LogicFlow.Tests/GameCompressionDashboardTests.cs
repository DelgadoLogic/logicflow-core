// LogicFlow.Tests — GameCompressionDashboardTests.cs
// Milestone 5: 25 Headless Automated Tests for Game Vault ViewModels, Controllers,
// Thread Marshaling, DirectStorage Safety, and STA/MTA Apartment Compatibility.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Dashboard.Common;
using LogicFlow.Dashboard.ViewModels;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

/// <summary>
/// Helper to run actions on an isolated Single-Threaded Apartment (STA) thread.
/// </summary>
public static class StaTestRunner
{
    public static void Run(Action testAction)
    {
        Exception? capturedException = null;
        var thread = new Thread(() =>
        {
            try
            {
                testAction();
            }
            catch (Exception ex)
            {
                capturedException = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (capturedException != null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(capturedException).Throw();
        }
    }

    public static async Task RunAsync(Func<Task> testFunc)
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(async () =>
        {
            try
            {
                await testFunc();
                tcs.SetResult(true);
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await tcs.Task;
    }
}

[Collection("WofEmpiricalTests")]
public sealed class GameCompressionDashboardTests : IDisposable
{
    private readonly string _scratchDir;

    public GameCompressionDashboardTests()
    {
        _scratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_DashTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratchDir);
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

    private DetectedGame CreateTestGame(
        string id = "steam_1086940",
        string title = "Baldur's Gate 3",
        LauncherType launcher = LauncherType.Steam,
        long logicalSize = 120L * 1024 * 1024 * 1024,
        long diskSize = 120L * 1024 * 1024 * 1024,
        long savings = 42L * 1024 * 1024 * 1024,
        bool hasDs = false,
        bool isCompressed = false,
        string? customDir = null)
    {
        string dir = customDir ?? Path.Combine(_scratchDir, id);
        try
        {
            Directory.CreateDirectory(dir);
        }
        catch
        {
            // Allow tests specifying non-existent or invalid drives to test error resilience
        }
        return new DetectedGame(
            GameId: id,
            Title: title,
            InstallDirectory: dir,
            Launcher: launcher,
            SizeOnDiskBytes: diskSize,
            HasDirectStorage: hasDs,
            IsCompressed: isCompressed,
            EstimatedSavingsBytes: savings)
        {
            LogicalSizeBytes = logicalSize
        };
    }

    // ─── 1. View Model & Metric Mapping Tests ─────────────────────────────────

    [Fact]
    public void GameVaultItemViewModel_Initialization_MapsAllDetectedGameProperties()
    {
        var game = CreateTestGame();
        var vm = new GameVaultItemViewModel(game);

        Assert.Equal(game.GameId, vm.GameId);
        Assert.Equal(game.Title, vm.Title);
        Assert.Equal(game.InstallDirectory, vm.InstallDirectory);
        Assert.Equal(game.Launcher, vm.Launcher);
        Assert.Equal(game.SizeOnDiskBytes, vm.SizeOnDiskBytes);
        Assert.Equal(game.LogicalSizeBytes, vm.LogicalSizeBytes);
        Assert.Equal(game.EstimatedSavingsBytes, vm.EstimatedSavingsBytes);
        Assert.Equal(game.HasDirectStorage, vm.HasDirectStorage);
        Assert.Equal(game.IsCompressed, vm.IsCompressed);
        Assert.Equal(WofNative.ALGORITHM_LZX, vm.SelectedAlgorithm);
        Assert.True(vm.CanCompact);
        Assert.False(vm.CanDecompress);
    }

    [Fact]
    public void GameVaultItemViewModel_Formatting_OutputsHumanReadableMetrics()
    {
        var game = CreateTestGame(
            logicalSize: 10L * 1024 * 1024 * 1024,
            diskSize: 10L * 1024 * 1024 * 1024,
            savings: 4L * 1024 * 1024 * 1024);
        var vm = new GameVaultItemViewModel(game);

        Assert.Contains("10 GB", vm.FormattedSizeOnDisk);
        Assert.Contains("4 GB", vm.FormattedEstimatedSavings);
        Assert.Contains("4 GB", vm.SavingsBadgeText);
        Assert.Contains("40.0%", vm.SavingsText);
    }

    [Fact]
    public void GameVaultItemViewModel_WhenCompressed_SavingsTextReflectsActualRecovery()
    {
        var game = CreateTestGame(
            logicalSize: 100L * 1024 * 1024 * 1024,
            diskSize: 60L * 1024 * 1024 * 1024,
            isCompressed: true);
        var vm = new GameVaultItemViewModel(game);

        Assert.Equal(40.0, vm.SpaceSavedPercent, 1);
        Assert.Contains("40.0%", vm.SavingsText);
        Assert.Contains("40 GB", vm.SavingsText);
        Assert.DoesNotContain("Est.", vm.SavingsText);
    }

    [Fact]
    public void GameVaultItemViewModel_ZeroByteOrEmptyGame_HandlesGracefullyWithoutDivisionByZero()
    {
        var game = CreateTestGame(logicalSize: 0, diskSize: 0, savings: 0);
        var vm = new GameVaultItemViewModel(game);

        Assert.Equal(0.0, vm.SpaceSavedPercent);
        Assert.Equal(0.0, vm.SavingsPercent);
        Assert.Equal("0 B", vm.FormattedSizeOnDisk);
        Assert.Contains("0 B", vm.SavingsText);
        Assert.Equal("Optimal", vm.SavingsBadgeText);
    }

    [Fact]
    public void GameVaultSummaryViewModel_Aggregation_ComputesAccurateLibraryTotals()
    {
        var g1 = CreateTestGame("g1", "Game 1", logicalSize: 100L * 1024 * 1024 * 1024, diskSize: 100L * 1024 * 1024 * 1024, savings: 30L * 1024 * 1024 * 1024, isCompressed: false);
        var g2 = CreateTestGame("g2", "Game 2", logicalSize: 80L * 1024 * 1024 * 1024, diskSize: 50L * 1024 * 1024 * 1024, savings: 0, isCompressed: true);
        var g3 = CreateTestGame("g3", "Game 3", logicalSize: 20L * 1024 * 1024 * 1024, diskSize: 20L * 1024 * 1024 * 1024, savings: 5L * 1024 * 1024 * 1024, hasDs: true, isCompressed: false);

        var vm1 = new GameVaultItemViewModel(g1);
        var vm2 = new GameVaultItemViewModel(g2);
        var vm3 = new GameVaultItemViewModel(g3);

        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm1);
        summary.Items.Add(vm2);
        summary.Items.Add(vm3);
        summary.Recalculate();

        Assert.Equal(3, summary.TotalGames);
        Assert.Equal(1, summary.CompressedGames);
        Assert.Equal(2, summary.UncompressedGamesCount);
        Assert.Equal(1, summary.DirectStorageProtectedCount);

        long expectedDiskBytes = (100L + 50L + 20L) * 1024 * 1024 * 1024;
        long expectedSavings = (30L + 0L + 5L) * 1024 * 1024 * 1024;
        long expectedReclaimed = (80L - 50L) * 1024 * 1024 * 1024;

        Assert.Equal(expectedDiskBytes, summary.TotalRawSizeBytes);
        Assert.Equal(expectedSavings, summary.TotalEstimatedSavingsBytes);
        Assert.Equal(expectedReclaimed, summary.TotalReclaimedStorageBytes);
        Assert.Contains("3 games installed", summary.SummaryText);
    }

    [Fact]
    public void GameVaultSummaryViewModel_DecayState_UpdatesBannerVisibilityAndCount()
    {
        var summary = new GameVaultSummaryViewModel();
        Assert.False(summary.HasDecay);

        summary.DecayedGamesCount = 2;
        summary.TotalDecayedBytes = 10L * 1024 * 1024 * 1024;

        Assert.True(summary.HasDecay);
        Assert.True(summary.HasDecayedGames);
        Assert.Equal(2, summary.DecayedGamesCount);
        Assert.Contains("2 game(s)", summary.DecayBannerText);
        Assert.Contains("10 GB", summary.DecayBannerText);
    }

    // ─── 2. Algorithm & ComboBox Mapping Tests ─────────────────────────────────

    [Fact]
    public void GameVaultItemViewModel_AlgorithmConversions_MapsAllFourWofAlgorithms()
    {
        var vm = new GameVaultItemViewModel(CreateTestGame());

        vm.SelectedAlgorithm = WofNative.ALGORITHM_LZX;
        Assert.Contains("LZX", vm.SelectedAlgorithmName);
        Assert.Equal(0, vm.SelectedAlgorithmIndex);

        vm.SelectedAlgorithm = WofNative.ALGORITHM_XPRESS8K;
        Assert.Contains("XPRESS8K", vm.SelectedAlgorithmName);
        Assert.Equal(1, vm.SelectedAlgorithmIndex);

        vm.SelectedAlgorithm = WofNative.ALGORITHM_XPRESS16K;
        Assert.Contains("XPRESS16K", vm.SelectedAlgorithmName);
        Assert.Equal(2, vm.SelectedAlgorithmIndex);

        vm.SelectedAlgorithm = WofNative.ALGORITHM_XPRESS4K;
        Assert.Contains("XPRESS4K", vm.SelectedAlgorithmName);
        Assert.Equal(3, vm.SelectedAlgorithmIndex);
    }

    [Fact]
    public void GameVaultItemViewModel_AlgorithmIndex_MapsComboBoxIndicesAccurately()
    {
        var vm = new GameVaultItemViewModel(CreateTestGame());

        vm.SelectedAlgorithmIndex = 0;
        Assert.Equal(WofNative.ALGORITHM_LZX, vm.SelectedAlgorithm);

        vm.SelectedAlgorithmIndex = 1;
        Assert.Equal(WofNative.ALGORITHM_XPRESS8K, vm.SelectedAlgorithm);

        vm.SelectedAlgorithmIndex = 2;
        Assert.Equal(WofNative.ALGORITHM_XPRESS16K, vm.SelectedAlgorithm);

        vm.SelectedAlgorithmIndex = 3;
        Assert.Equal(WofNative.ALGORITHM_XPRESS4K, vm.SelectedAlgorithm);
    }

    [Fact]
    public void GameVaultItemViewModel_InvalidAlgorithm_FallbacksToLzx()
    {
        var vm = new GameVaultItemViewModel(CreateTestGame());
        vm.SelectedAlgorithm = 999;
        Assert.Equal(WofNative.ALGORITHM_LZX, vm.SelectedAlgorithm);
    }

    // ─── 3. Launcher Branding & Badges Tests ──────────────────────────────────

    [Fact]
    public void GameVaultItemViewModel_LauncherBadges_MapsAllLaunchersWithUniqueBranding()
    {
        var steam = new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Steam));
        var epic = new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Epic));
        var gog = new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.GOG));
        var custom = new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Custom));

        Assert.Equal("STEAM", steam.LauncherBadgeText);
        Assert.Equal("EPIC", epic.LauncherBadgeText);
        Assert.Equal("GOG", gog.LauncherBadgeText);
        Assert.Equal("CUSTOM", custom.LauncherBadgeText);

        Assert.StartsWith("#", steam.LauncherBadgeColorHex);
        Assert.StartsWith("#", epic.LauncherBadgeColorHex);
        Assert.StartsWith("#", gog.LauncherBadgeColorHex);
        Assert.StartsWith("#", custom.LauncherBadgeColorHex);

        Assert.NotEqual(steam.LauncherBadgeColorHex, epic.LauncherBadgeColorHex);
        Assert.NotEqual(steam.LauncherBadgeColorHex, gog.LauncherBadgeColorHex);
    }

    [Fact]
    public void GameVaultItemViewModel_LauncherDisplayNames_AreHumanFriendly()
    {
        Assert.Equal("Steam", new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Steam)).LauncherDisplayName);
        Assert.Equal("Epic Games", new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Epic)).LauncherDisplayName);
        Assert.Equal("GOG Galaxy", new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.GOG)).LauncherDisplayName);
        Assert.Equal("Local / Custom", new GameVaultItemViewModel(CreateTestGame(launcher: LauncherType.Custom)).LauncherDisplayName);
    }

    // ─── 4. DirectStorage Safety Heuristics Tests ─────────────────────────────

    [Fact]
    public void GameVaultItemViewModel_DirectStorageBadge_ActiveOnlyWhenDirectStorageDetected()
    {
        var safeGame = new GameVaultItemViewModel(CreateTestGame(hasDs: false));
        var dsGame = new GameVaultItemViewModel(CreateTestGame(hasDs: true));

        Assert.False(safeGame.DirectStorageWarningVisible);
        Assert.True(dsGame.DirectStorageWarningVisible);
        Assert.Equal("DirectStorage Active", dsGame.DirectStorageBadgeText);
        Assert.Contains("dstorage.dll", dsGame.DirectStorageTooltip);
    }

    [Fact]
    public void GameVaultItemViewModel_DirectStorage_CanCompactTogglesWithSkipFlag()
    {
        var dsGame = new GameVaultItemViewModel(CreateTestGame(hasDs: true));

        dsGame.SkipDirectStorage = true;
        Assert.False(dsGame.CanCompact);

        dsGame.SkipDirectStorage = false;
        Assert.True(dsGame.CanCompact);
    }

    // ─── 5. Controller Async Execution & Orchestration Tests ──────────────────

    [Fact]
    public async Task GameVaultController_RefreshAsync_ScansLibrariesAndPopulatesViewModels()
    {
        string gameDir = Path.Combine(_scratchDir, "CustomGame1");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "game.exe"), "executable");
        File.WriteAllText(Path.Combine(gameDir, "data.pak_uncomp"), new string('X', 5000));

        var summary = new GameVaultSummaryViewModel();
        var controller = new GameVaultController(summary);

        await controller.RefreshAsync(new[] { _scratchDir });

        Assert.NotEmpty(summary.Items);
        Assert.Contains(summary.Items, i => i.InstallDirectory.Equals(gameDir, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Scan complete", summary.GlobalProgressText);
    }

    [Fact]
    public async Task GameVaultController_CompactGameAsync_SingleGame_UpdatesProgressAndMarksCompressed()
    {
        string gameDir = Path.Combine(_scratchDir, "CompactSingleTest");
        Directory.CreateDirectory(gameDir);
        string file1 = Path.Combine(gameDir, "assets.dat");
        File.WriteAllText(file1, new string('A', 32 * 1024));

        var game = CreateTestGame("comp_single", "Compact Test Game", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        bool ok = await controller.CompactGameAsync(vm);

        Assert.True(ok);
        Assert.True(vm.IsCompressed);
        Assert.Contains("Compacted", vm.StatusText);
        Assert.False(vm.IsProcessing);
    }

    [Fact]
    public async Task GameVaultController_DecompressGameAsync_SingleGame_RestoresUncompressedState()
    {
        string gameDir = Path.Combine(_scratchDir, "DecompSingleTest");
        Directory.CreateDirectory(gameDir);
        string file1 = Path.Combine(gameDir, "archive.bin");
        File.WriteAllText(file1, new string('D', 32 * 1024));

        var game = CreateTestGame("decomp_single", "Decompress Test Game", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        await controller.CompactGameAsync(vm);
        Assert.True(vm.IsCompressed);

        bool decompressOk = await controller.DecompressGameAsync(vm);

        Assert.True(decompressOk);
        Assert.False(vm.IsCompressed);
        Assert.Equal("Decompressed", vm.StatusText);
        Assert.False(vm.IsProcessing);
    }

    [Fact]
    public async Task GameVaultController_CompactAllAsync_BatchCompression_SkipsDirectStorageAndAggregates()
    {
        string dir1 = Path.Combine(_scratchDir, "BatchGame1");
        string dir2 = Path.Combine(_scratchDir, "BatchGameDs");
        Directory.CreateDirectory(dir1);
        Directory.CreateDirectory(dir2);

        File.WriteAllText(Path.Combine(dir1, "game.dat"), new string('B', 16 * 1024));
        File.WriteAllText(Path.Combine(dir2, "game.dat"), new string('B', 16 * 1024));
        File.WriteAllText(Path.Combine(dir2, "dstorage.dll"), "mock_ds");

        var g1 = CreateTestGame("b1", "Batch 1", hasDs: false, customDir: dir1);
        var g2 = CreateTestGame("b2", "Batch DS", hasDs: true, customDir: dir2);

        var vm1 = new GameVaultItemViewModel(g1);
        var vm2 = new GameVaultItemViewModel(g2);

        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm1);
        summary.Items.Add(vm2);

        var controller = new GameVaultController(summary);
        int compactedCount = await controller.CompactAllAsync();

        Assert.Equal(1, compactedCount);
        Assert.True(vm1.IsCompressed);
        Assert.False(vm2.IsCompressed);
    }

    [Fact]
    public async Task GameVaultController_RecompactUpdatesAsync_DecayRoutine_ProcessesOnlyDecayedGames()
    {
        string gameDir = Path.Combine(_scratchDir, "DecayGameTest");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "initial.dat"), new string('I', 16 * 1024));

        var game = CreateTestGame("decay_test", "Decay Game", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        await controller.CompactGameAsync(vm);
        Assert.True(vm.IsCompressed);

        // Simulate patch write
        File.WriteAllText(Path.Combine(gameDir, "patch_update.dat"), new string('P', 32 * 1024));

        int recompacted = await controller.RecompactUpdatesAsync();

        Assert.True(recompacted >= 0);
        Assert.False(summary.HasDecay);
        Assert.Equal(0, summary.DecayedGamesCount);
    }

    [Fact]
    public async Task GameVaultController_CancelActiveOperation_SignalsCancellationTokenAndHaltsCleanly()
    {
        string gameDir = Path.Combine(_scratchDir, "CancelTest");
        Directory.CreateDirectory(gameDir);
        for (int i = 0; i < 20; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"data_{i}.bin"), new string('C', 16 * 1024));
        }

        var game = CreateTestGame("cancel_test", "Cancel Test", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        using var cts = new CancellationTokenSource();
        var task = controller.CompactGameAsync(vm, cts.Token);
        cts.Cancel();

        bool result = await task;

        Assert.False(result);
        Assert.False(vm.IsProcessing);
        Assert.False(summary.IsGlobalProcessing);
    }

    // ─── 6. Error Boundaries & Thread Safety Tests ────────────────────────────

    [Fact]
    public async Task GameVaultController_LockedFile_DoesNotAbortEntireBatch()
    {
        string gameDir = Path.Combine(_scratchDir, "LockedFileTest");
        Directory.CreateDirectory(gameDir);
        string normalFile = Path.Combine(gameDir, "normal.dat");
        string lockedFile = Path.Combine(gameDir, "locked.dat");

        File.WriteAllText(normalFile, new string('N', 16 * 1024));
        File.WriteAllText(lockedFile, new string('L', 16 * 1024));

        using var lockStream = new FileStream(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var game = CreateTestGame("locked_test", "Locked Test", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        bool ok = await controller.CompactGameAsync(vm);

        Assert.True(ok);
        Assert.True(vm.IsCompressed);
    }

    [Fact]
    public async Task GameVaultController_UnauthorizedAccess_MarksErrorWithoutThrowingUnhandledException()
    {
        var game = CreateTestGame("unauth_test", "Invalid Path Game", customDir: "Z:\\NonExistentPath_InvalidDir_12345");
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        bool result = await controller.CompactGameAsync(vm);

        Assert.False(result);
        Assert.False(vm.IsProcessing);
        Assert.False(summary.IsGlobalProcessing);
    }

    [Fact]
    public async Task GameVaultController_ConcurrentInvocations_GuardsAgainstRaceConditions()
    {
        string gameDir = Path.Combine(_scratchDir, "ConcurrentTest");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "data.bin"), new string('C', 16 * 1024));

        var game = CreateTestGame("concurrent_test", "Concurrent Test", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        var task1 = controller.CompactGameAsync(vm);
        var task2 = controller.CompactGameAsync(vm);

        var results = await Task.WhenAll(task1, task2);

        Assert.Contains(true, results);
        Assert.Contains(false, results);
        Assert.False(vm.IsProcessing);
    }

    [Fact]
    public void GameVaultController_ProgressReporting_MarshalsThreadSafelyWithoutLiveDispatcher()
    {
        var game = CreateTestGame();
        var vm = new GameVaultItemViewModel(game);
        int reportCount = 0;

        for (int i = 0; i < 50; i++)
        {
            var p = new CompressionProgress(
                CurrentFile: $"file_{i}.dat",
                FilesCompleted: i,
                TotalFiles: 50,
                BytesProcessed: i * 1024 * 1024L,
                BytesSaved: i * 512 * 1024L,
                CompressionRatio: 0.5,
                ThroughputMBs: 125.0,
                PercentComplete: (i / 50.0) * 100.0);

            UiDispatcher.Invoke(() =>
            {
                vm.UpdateFromProgress(p);
                reportCount++;
            });
        }

        Assert.Equal(50, reportCount);
        Assert.Equal("file_49.dat", vm.CurrentFile);
        Assert.Equal(125.0, vm.ThroughputMBs);
    }

    // ─── 7. STA / MTA Apartment Compatibility Tests ───────────────────────────

    [Fact]
    public void StaTestRunner_ExecutesActionOnStaThreadSuccessfully()
    {
        ApartmentState? capturedApartment = null;
        StaTestRunner.Run(() =>
        {
            capturedApartment = Thread.CurrentThread.GetApartmentState();
        });

        Assert.Equal(ApartmentState.STA, capturedApartment);
    }

    [Fact]
    public void GameVaultItemViewModel_InstantiatesUnderBothMtaAndStaWithoutCrashing()
    {
        // 1. MTA execution (current test runner thread pool)
        var game = CreateTestGame();
        var mtaVm = new GameVaultItemViewModel(game);
        Assert.NotNull(mtaVm);

        // 2. STA execution
        GameVaultItemViewModel? staVm = null;
        StaTestRunner.Run(() =>
        {
            staVm = new GameVaultItemViewModel(game);
        });

        Assert.NotNull(staVm);
        Assert.Equal(mtaVm.Title, staVm.Title);
    }
}
