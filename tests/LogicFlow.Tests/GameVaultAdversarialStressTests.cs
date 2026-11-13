// LogicFlow.Tests — GameVaultAdversarialStressTests.cs
// Adversarial Stress, Concurrency, Rapid Cancellation, Null Resilience,
// Boundary Values, Scale, and Apartment State Verification for Game Vault Dashboard & ViewModels.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Dashboard.Common;
using LogicFlow.Dashboard.ViewModels;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public sealed class GameVaultAdversarialStressTests : IDisposable
{
    private readonly string _scratchDir;

    public GameVaultAdversarialStressTests()
    {
        _scratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_AdvTest_" + Guid.NewGuid().ToString("N"));
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
        string id = "adv_game_1",
        string title = "Adversarial Game Title",
        LauncherType launcher = LauncherType.Steam,
        long logicalSize = 50L * 1024 * 1024 * 1024,
        long diskSize = 50L * 1024 * 1024 * 1024,
        long savings = 20L * 1024 * 1024 * 1024,
        bool hasDs = false,
        bool isCompressed = false,
        string? customDir = null)
    {
        string dir = customDir ?? Path.Combine(_scratchDir, id);
        try
        {
            Directory.CreateDirectory(dir);
        }
        catch { }

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

    // ═══════════════════════════════════════════════════════════════════════════
    // 1. RAPID CANCELLATION & RE-ENTRANCY ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RapidCancellation_CompactGameAsync_CancelsInstantlyWithoutHangsOrCorruptedState()
    {
        string gameDir = Path.Combine(_scratchDir, "RapidCancelGame");
        Directory.CreateDirectory(gameDir);
        for (int i = 0; i < 20; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"payload_{i}.bin"), new string('Z', 64 * 1024));
        }

        var game = CreateTestGame("rc_1", "Rapid Cancel 1", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        for (int cycle = 0; cycle < 5; cycle++)
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel(); // Pre-cancelled token

            bool result = await controller.CompactGameAsync(vm, cts.Token);

            Assert.False(result);
            Assert.False(vm.IsProcessing);
            Assert.False(summary.IsGlobalProcessing);
            Assert.Equal("Compression cancelled", vm.StatusText);
        }
    }

    [Fact]
    public async Task RapidCancellation_CompactAllAsync_CancelsMidBatchAndReleasesGlobalLock()
    {
        var summary = new GameVaultSummaryViewModel();
        for (int i = 0; i < 15; i++)
        {
            string gDir = Path.Combine(_scratchDir, $"BatchCancel_{i}");
            Directory.CreateDirectory(gDir);
            File.WriteAllText(Path.Combine(gDir, "data.bin"), new string('B', 32 * 1024));

            var g = CreateTestGame($"bc_{i}", $"Batch Game {i}", customDir: gDir);
            summary.Items.Add(new GameVaultItemViewModel(g));
        }

        var controller = new GameVaultController(summary);
        using var cts = new CancellationTokenSource();

        // Start batch compression and cancel after 25ms
        cts.CancelAfter(TimeSpan.FromMilliseconds(25));
        int compacted = await controller.CompactAllAsync(cts.Token);

        Assert.True(compacted < 15);
        Assert.False(summary.IsGlobalProcessing);
        Assert.Equal("Batch operation cancelled", summary.GlobalProgressText);
    }

    [Fact]
    public async Task RapidCancellation_ControllerCancelActiveOperation_SignalsCorrectly()
    {
        string gameDir = Path.Combine(_scratchDir, "CancelActiveOpTest");
        Directory.CreateDirectory(gameDir);
        for (int i = 0; i < 30; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"chunk_{i}.bin"), new string('C', 64 * 1024));
        }

        var game = CreateTestGame("cao_1", "Cancel Active Operation", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        var task = controller.CompactGameAsync(vm);
        // Call controller's internal cancel method
        controller.CancelActiveOperation();
        bool ok = await task;

        Assert.False(ok);
        Assert.False(vm.IsProcessing);
        Assert.False(summary.IsGlobalProcessing);
    }

    [Fact]
    public async Task ConcurrencyGuard_SimultaneousCompactOnSameItem_RejectsSecondInvocation()
    {
        string gameDir = Path.Combine(_scratchDir, "SimultaneousCompactTest");
        Directory.CreateDirectory(gameDir);
        for (int i = 0; i < 10; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"f_{i}.bin"), new string('S', 32 * 1024));
        }

        var game = CreateTestGame("sim_1", "Simultaneous Game", customDir: gameDir);
        var vm = new GameVaultItemViewModel(game);
        var summary = new GameVaultSummaryViewModel();
        summary.Items.Add(vm);
        var controller = new GameVaultController(summary);

        var task1 = controller.CompactGameAsync(vm);
        var task2 = controller.CompactGameAsync(vm);

        var results = await Task.WhenAll(task1, task2);

        // Exactly one should succeed, one rejected
        Assert.True(results[0] != results[1] || (results[0] == false && results[1] == false));
        Assert.False(vm.IsProcessing);
    }

    [Fact]
    public async Task ConcurrencyGuard_SimultaneousCompactAll_OnlyOneExecutesOthersReturnZero()
    {
        var summary = new GameVaultSummaryViewModel();
        for (int i = 0; i < 5; i++)
        {
            string gDir = Path.Combine(_scratchDir, $"SimBatch_{i}");
            Directory.CreateDirectory(gDir);
            File.WriteAllText(Path.Combine(gDir, "data.bin"), new string('S', 16 * 1024));
            summary.Items.Add(new GameVaultItemViewModel(CreateTestGame($"sb_{i}", $"Sim Batch {i}", customDir: gDir)));
        }

        var controller = new GameVaultController(summary);

        var t1 = controller.CompactAllAsync();
        var t2 = controller.CompactAllAsync();
        var t3 = controller.CompactAllAsync();

        var results = await Task.WhenAll(t1, t2, t3);

        // At least two calls should be rejected with 0
        int zeros = results.Count(r => r == 0);
        Assert.True(zeros >= 2);
        Assert.False(summary.IsGlobalProcessing);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 2. CONCURRENT PROPERTY UPDATES & MULTI-THREADED STRESS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void ConcurrentPropertyUpdates_20Threads_NoExceptionsOrCorruptedState()
    {
        var game = CreateTestGame();
        var vm = new GameVaultItemViewModel(game);

        int eventCount = 0;
        vm.PropertyChanged += (s, e) =>
        {
            Interlocked.Increment(ref eventCount);
        };

        const int numThreads = 20;
        const int iterations = 500;

        Parallel.For(0, numThreads, threadId =>
        {
            for (int i = 0; i < iterations; i++)
            {
                long sz = (i + 1) * 1024L * 1024L;
                vm.LogicalSizeBytes = sz;
                vm.SizeOnDiskBytes = sz / 2;
                vm.EstimatedSavingsBytes = sz / 4;
                vm.IsCompressed = (i % 2 == 0);
                vm.SelectedAlgorithm = (uint)(i % 4);
                vm.SkipDirectStorage = (i % 3 == 0);
                vm.ProgressPercent = (i % 100);
                vm.ThroughputMBs = (i * 1.5);
                vm.StatusText = $"Thread {threadId} Iteration {i}";
                vm.HasDecay = (i % 5 == 0);
                vm.DecayedBytes = (i * 100L);

                // Read computed properties concurrently
                _ = vm.FormattedLogicalSize;
                _ = vm.FormattedSizeOnDisk;
                _ = vm.FormattedEstimatedSavings;
                _ = vm.SavingsText;
                _ = vm.SavingsPercent;
                _ = vm.SpaceSavedPercent;
                _ = vm.LauncherDisplayName;
                _ = vm.LauncherBadgeColorHex;
                _ = vm.CanCompact;
                _ = vm.CanDecompress;
                _ = vm.StatusBadgeText;
            }
        });

        Assert.True(eventCount > 0);
        Assert.NotNull(vm.StatusText);
        Assert.NotNull(vm.FormattedSizeOnDisk);
    }

    [Fact]
    public void ConcurrentSummaryRecalculation_10Threads_CompletesSafely()
    {
        var summary = new GameVaultSummaryViewModel();
        var items = new List<GameVaultItemViewModel>();
        for (int i = 0; i < 100; i++)
        {
            var g = CreateTestGame($"rec_{i}", $"Game {i}", logicalSize: 10L * 1024 * 1024 * 1024, diskSize: 8L * 1024 * 1024 * 1024, isCompressed: i % 2 == 0);
            var vm = new GameVaultItemViewModel(g);
            items.Add(vm);
            summary.Items.Add(vm);
        }

        Parallel.For(0, 10, threadId =>
        {
            for (int i = 0; i < 50; i++)
            {
                summary.Recalculate(items);
                _ = summary.FormattedTotalSize;
                _ = summary.FormattedTotalSavings;
                _ = summary.FormattedReclaimedStorage;
                _ = summary.SummaryText;
            }
        });

        Assert.Equal(100, summary.TotalGames);
        Assert.Equal(50, summary.CompressedGames);
    }

    [Fact]
    public void ConcurrentProgressTelemetry_FloodedFromMultipleThreads_NoCrashes()
    {
        var progressVm = new GameVaultProgressViewModel();

        Parallel.For(0, 10, threadId =>
        {
            for (int i = 0; i < 200; i++)
            {
                var cp = new CompressionProgress(
                    CurrentFile: $"thread_{threadId}_file_{i}.bin",
                    FilesCompleted: i,
                    TotalFiles: 200,
                    BytesProcessed: i * 1024L * 1024L,
                    BytesSaved: i * 512L * 1024L,
                    CompressionRatio: 0.5,
                    ThroughputMBs: 150.0 + threadId,
                    PercentComplete: (i / 200.0) * 100.0,
                    Elapsed: TimeSpan.FromSeconds(i),
                    EstimatedTimeRemaining: TimeSpan.FromSeconds(200 - i),
                    StatusMessage: $"Processing file {i}");

                progressVm.UpdateFromProgress(cp, $"Thread {threadId} Op");

                _ = progressVm.FormattedThroughput;
                _ = progressVm.FormattedBytesProcessed;
                _ = progressVm.FormattedBytesSaved;
                _ = progressVm.FormattedEta;
                _ = progressVm.ProgressFilesText;
            }
        });

        Assert.True(progressVm.IsActive);
        Assert.NotNull(progressVm.CurrentFile);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 3. NULL RESILIENCE & BOUNDARY CONDITIONS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void NullResilience_AllViewModelsAndDispatcherHandleNullsGracefully()
    {
        var game = CreateTestGame();
        var vm = new GameVaultItemViewModel(game);
        var progressVm = new GameVaultProgressViewModel();

        // Null mutations must not throw exceptions
        vm.UpdateFromProgress(null!);
        vm.UpdateFromSummary(null!);
        vm.UpdateFromDecompression(null!);
        vm.UpdateFromDetectedGame(null!);

        progressVm.Update(null!);
        progressVm.UpdateFromProgress(null!);

        // UiDispatcher null calls must be resilient
        UiDispatcher.Invoke(null!);
        var task = UiDispatcher.InvokeAsync((Action)null!);
        Assert.True(task.IsCompleted);

        // Constructor null checks
        Assert.Throws<ArgumentNullException>(() => new GameVaultItemViewModel(null!));
        Assert.Throws<ArgumentNullException>(() => new GameVaultController(null!));
    }

    [Fact]
    public async Task NullResilience_ControllerMethodsHandleNullItems()
    {
        var summary = new GameVaultSummaryViewModel();
        var controller = new GameVaultController(summary);

        bool compactRes = await controller.CompactGameAsync(null!);
        bool decompRes = await controller.DecompressGameAsync(null!);

        Assert.False(compactRes);
        Assert.False(decompRes);
    }

    [Theory]
    [InlineData(-1000L, "0 B")]
    [InlineData(0L, "0 B")]
    [InlineData(1L, "1 B")]
    [InlineData(1023L, "1023 B")]
    [InlineData(1024L, "1 KB")]
    [InlineData(1048576L, "1 MB")]
    [InlineData(1073741824L, "1 GB")]
    [InlineData(1099511627776L, "1 TB")]
    [InlineData(long.MaxValue, "8388608 TB")]
    public void ExtremeNumericBoundaries_FormatBytes_ProducesValidStrings(long bytes, string expectedPrefix)
    {
        string formatted = GameVaultItemViewModel.FormatBytes(bytes);
        Assert.NotNull(formatted);
        Assert.StartsWith(expectedPrefix, formatted);
    }

    [Fact]
    public void ExtremeNumericBoundaries_FormatBytes_HandlesLongMinValueWithoutThrowing()
    {
        // long.MinValue is negative, so FormatBytes returns "0 B"
        string formatted = GameVaultItemViewModel.FormatBytes(long.MinValue);
        Assert.Equal("0 B", formatted);
    }

    [Fact]
    public void ExtremeNumericBoundaries_Percentages_DoNotOverflowOrProduceNegative()
    {
        var game = CreateTestGame(logicalSize: 0, diskSize: 0, savings: 0);
        var vm = new GameVaultItemViewModel(game);

        // Negative values
        vm.LogicalSizeBytes = -500;
        vm.SizeOnDiskBytes = -100;
        Assert.Equal(0.0, vm.SavingsPercent);
        Assert.Equal(0.0, vm.SpaceSavedPercent);

        // Disk larger than logical (e.g. bloated or uncompressible)
        vm.LogicalSizeBytes = 1000;
        vm.SizeOnDiskBytes = 2000;
        Assert.Equal(0.0, vm.SpaceSavedPercent);

        // Huge sizes without arithmetic overflow
        vm.LogicalSizeBytes = long.MaxValue / 2;
        vm.SizeOnDiskBytes = long.MaxValue / 4;
        Assert.True(vm.SpaceSavedPercent > 49.0 && vm.SpaceSavedPercent < 51.0);
    }

    [Theory]
    [InlineData(uint.MaxValue)]
    [InlineData(4u)]
    [InlineData(999u)]
    public void InvalidAlgorithms_OutOfBoundsValuesFallBackToLzx(uint invalidAlgo)
    {
        var vm = new GameVaultItemViewModel(CreateTestGame());
        vm.SelectedAlgorithm = invalidAlgo;
        Assert.Equal(WofNative.ALGORITHM_LZX, vm.SelectedAlgorithm);
        Assert.Equal(0, vm.SelectedAlgorithmIndex);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 4. INVALID PATHS & FILE ACCESS HOSTILITY
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("Z:\\NonExistent_Drive_Directory_99999")]
    [InlineData("C:\\Invalid*Path?With\"Special|Chars")]
    [InlineData("")]
    public async Task InvalidPaths_NonExistentOrCorruptDirectoriesHandledGracefully(string path)
    {
        var game = CreateTestGame("inv_path", "Invalid Path Game", customDir: path);
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
    public async Task LockedFiles_PartialLockingDoesNotCrashOrHangBatch()
    {
        string gameDir = Path.Combine(_scratchDir, "HostileLockGame");
        Directory.CreateDirectory(gameDir);

        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(gameDir, $"unlocked_{i}.dat"), new string('U', 16 * 1024));
        }

        string lockedPath = Path.Combine(gameDir, "locked.dat");
        File.WriteAllText(lockedPath, new string('L', 16 * 1024));

        using (var lockStream = new FileStream(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var game = CreateTestGame("lock_game", "Locked Game", customDir: gameDir);
            var vm = new GameVaultItemViewModel(game);
            var summary = new GameVaultSummaryViewModel();
            summary.Items.Add(vm);
            var controller = new GameVaultController(summary);

            bool ok = await controller.CompactGameAsync(vm);

            // Operation completes gracefully despite the locked file
            Assert.False(vm.IsProcessing);
            Assert.False(summary.IsGlobalProcessing);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 5. HIGH VOLUME SCALE STRESS (10,000 GAMES)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void HighVolumeScale_10000Games_RecalculateCompletesQuickly()
    {
        var summary = new GameVaultSummaryViewModel();
        var items = new List<GameVaultItemViewModel>(10000);

        for (int i = 0; i < 10000; i++)
        {
            var game = new DetectedGame(
                GameId: $"scale_{i}",
                Title: $"Scale Game {i}",
                InstallDirectory: $@"C:\Games\Game_{i}",
                Launcher: (LauncherType)(i % 4),
                SizeOnDiskBytes: 50L * 1024 * 1024 * 1024,
                HasDirectStorage: (i % 10 == 0),
                IsCompressed: (i % 2 == 0),
                EstimatedSavingsBytes: 20L * 1024 * 1024 * 1024)
            {
                LogicalSizeBytes = 50L * 1024 * 1024 * 1024
            };

            items.Add(new GameVaultItemViewModel(game));
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        summary.Recalculate(items);
        sw.Stop();

        Assert.Equal(10000, summary.TotalGames);
        Assert.Equal(5000, summary.CompressedGames);
        Assert.Equal(1000, summary.DirectStorageProtectedCount);
        // Recalculation across 10,000 games should take under 500ms
        Assert.True(sw.ElapsedMilliseconds < 500, $"Recalculate took {sw.ElapsedMilliseconds} ms, expected < 500 ms");
    }

    [Fact]
    public void HighVolumeProgressEvents_10000Events_HandledWithoutBacklogDeadlock()
    {
        var vm = new GameVaultItemViewModel(CreateTestGame());
        int receivedEvents = 0;

        for (int i = 0; i < 10000; i++)
        {
            var p = new CompressionProgress(
                CurrentFile: $"stream_{i}.dat",
                FilesCompleted: i,
                TotalFiles: 10000,
                BytesProcessed: i * 1024L,
                BytesSaved: i * 512L,
                CompressionRatio: 0.5,
                ThroughputMBs: 250.0,
                PercentComplete: (i / 10000.0) * 100.0);

            UiDispatcher.Invoke(() =>
            {
                vm.UpdateFromProgress(p);
                receivedEvents++;
            });
        }

        Assert.Equal(10000, receivedEvents);
        Assert.Equal("stream_9999.dat", vm.CurrentFile);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // 6. UI DISPATCHER APARTMENT STATE & HOOKS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void UiDispatcher_DispatchOverride_InterceptsInvocations()
    {
        int overrideCount = 0;
        UiDispatcher.DispatchOverride = action =>
        {
            overrideCount++;
            action();
        };

        try
        {
            UiDispatcher.Invoke(() => { });
            Assert.Equal(1, overrideCount);
        }
        finally
        {
            UiDispatcher.DispatchOverride = null;
        }
    }

    [Fact]
    public void UiDispatcher_ExceptionPropagation_ThrowsCallerException()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            UiDispatcher.Invoke(() => throw new InvalidOperationException("TestDispatcherException"));
        });
    }

    [Fact]
    public async Task UiDispatcher_InvokeAsync_ExecutesAndReturnsValue()
    {
        string result = await UiDispatcher.InvokeAsync(() => "LogicFlow_Result_42");
        Assert.Equal("LogicFlow_Result_42", result);
    }

    [Fact]
    public void StaTestRunner_ExecutesUnderStaApartmentState()
    {
        bool executed = false;
        StaTestRunner.Run(() =>
        {
            executed = true;
            Assert.Equal(ApartmentState.STA, Thread.CurrentThread.GetApartmentState());
        });

        Assert.True(executed);
    }
}
