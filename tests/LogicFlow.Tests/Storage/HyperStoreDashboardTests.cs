// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — HyperStore Telemetry Dashboard Test Suite
// Verification of Requirement R4: Antivirus-Style Telemetry Dashboard (Storage Armor)
// Tests ViewModel initialization, default gauge baselines, telemetry recalculation,
// 500-item FIFO action feed capping, execution mode toggles, async operations,
// and UiDispatcher headless execution via StaTestRunner.
// ─────────────────────────────────────────────────────────────────────────────

#nullable enable

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using LogicFlow.Dashboard.Common;
using LogicFlow.Dashboard.ViewModels;
using LogicFlow.Guardian.Worker;
using LogicFlow.Tests;
using Xunit;

namespace LogicFlow.Tests.Storage;

[Collection("WpfHeadlessExecution")]
public sealed class HyperStoreDashboardTests : IDisposable
{
    private readonly string _testRoot;

    public HyperStoreDashboardTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), $"HyperStoreDashboardTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testRoot);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testRoot))
            {
                Directory.Delete(_testRoot, recursive: true);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }

    #region 1. ViewModel Initialization & Baseline Gauges

    [Fact]
    public void ViewModel_Initialization_SetsExpectedDefaultGaugeBaselines()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();

            // 4 Telemetry Gauges Baseline
            Assert.Equal(0, vm.TotalBytesReclaimed);
            Assert.Equal("0 B", vm.TotalSpaceReclaimedFormatted);
            Assert.Equal(0.0, vm.SpaceReclaimedPercent);
            Assert.Equal("0.0% Net Gain", vm.SpaceReclaimedPercentFormatted);

            Assert.Equal(1.0, vm.GlobalCompressionRatio);
            Assert.Equal("1.00x", vm.GlobalCompressionRatioFormatted);
            Assert.Equal(0.0, vm.SpaceReductionPercent);
            Assert.Equal("0.0% Space Saved", vm.SpaceSavedPercentFormatted);

            Assert.Equal(0, vm.ChunksIndexed);
            Assert.Equal("0", vm.ChunksIndexedFormatted);
            Assert.Equal(0, vm.UniqueChunks);
            Assert.Equal(0, vm.DuplicateChunks);

            Assert.Equal("Protected", vm.ActiveProtectionStatus);
            Assert.Equal("#22C55E", vm.ProtectionStatusBadgeBrush);
            Assert.False(string.IsNullOrWhiteSpace(vm.ProtectionStatusDetail));

            // Live Progress State Baseline
            Assert.False(vm.IsBusy);
            Assert.True(vm.IsNotBusy);
            Assert.Equal(Visibility.Collapsed, vm.ProgressVisibility);
            Assert.Equal(0.0, vm.ProgressPercent);
            Assert.Equal("Idle", vm.ActiveOperation);

            // Autonomous Settings Baseline
            Assert.Equal(WorkerExecutionMode.ContinuousLowPriority, vm.ExecutionMode);
            Assert.True(vm.IsContinuousLowPriority);
            Assert.False(vm.IsScheduledWindow);
            Assert.False(vm.IsManualOnly);
            Assert.True(vm.IsGameGuardEnabled);
            Assert.True(vm.IsAcPowerOnly);
            Assert.True(vm.IsRefsCloningEnabled);

            // Action Feed Initialized with Welcome Shield Entry
            Assert.NotEmpty(vm.ActionFeed);
            Assert.Equal("SHIELD", vm.ActionFeed[0].Category);
        });
    }

    #endregion

    #region 2. Telemetry Gauges Recalculation & Badge States

    [Fact]
    public void ViewModel_UpdateMetrics_RecalculatesTelemetryCorrectly()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();

            long reclaimed = 153_391_689_728L; // ~142.85 GB
            double ratio = 3.82;
            long chunks = 1_489_203L;

            vm.UpdateMetrics(reclaimed, ratio, chunks, "Scanning");

            Assert.Equal(reclaimed, vm.TotalBytesReclaimed);
            Assert.Contains("GB", vm.TotalSpaceReclaimedFormatted);
            Assert.Equal(3.82, vm.GlobalCompressionRatio);
            Assert.Equal("3.82x", vm.GlobalCompressionRatioFormatted);
            Assert.Equal(73.8, vm.SpaceReductionPercent);
            Assert.Equal("73.8% Space Saved", vm.SpaceSavedPercentFormatted);

            Assert.Equal(chunks, vm.ChunksIndexed);
            Assert.Equal("1,489,203", vm.ChunksIndexedFormatted);

            Assert.Equal("Scanning", vm.ActiveProtectionStatus);
            Assert.Equal("#00E5FF", vm.ProtectionStatusBadgeBrush);
        });
    }

    [Theory]
    [InlineData("Protected", "#22C55E")]
    [InlineData("Scanning", "#00E5FF")]
    [InlineData("Suspended", "#F59E0B")]
    [InlineData("Idle", "#94A3B8")]
    public void ViewModel_ActiveProtectionStatus_SwitchesBadgeBrushesCorrectly(string status, string expectedBrush)
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            vm.ActiveProtectionStatus = status;

            Assert.Equal(status, vm.ActiveProtectionStatus);
            Assert.Equal(expectedBrush, vm.ProtectionStatusBadgeBrush);
        });
    }

    [Fact]
    public void ViewModel_SpaceReclaimedPercent_CalculatesAccurately()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel
            {
                TotalScannedBytes = 1_000_000_000L,
                TotalBytesReclaimed = 250_000_000L
            };

            Assert.Equal(25.0, vm.SpaceReclaimedPercent);
            Assert.Equal("25.0% Net Gain", vm.SpaceReclaimedPercentFormatted);
        });
    }

    #endregion

    #region 3. Action Feed Real-Time Logging & 500-Item FIFO Capping

    [Fact]
    public void ActionFeed_AddingUpTo500Entries_MaintainsSequentialOrder()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            vm.ClearActionFeed();

            for (int i = 0; i < 50; i++)
            {
                vm.AddLogEntry("DEDUP", $"Consolidated item #{i}", $@"C:\Data\file_{i}.bin", i * 1024);
            }

            Assert.Equal(50, vm.ActionFeed.Count);
            Assert.Equal("Consolidated item #0", vm.ActionFeed[0].Message);
            Assert.Equal("Consolidated item #49", vm.ActionFeed[49].Message);
        });
    }

    [Fact]
    public void ActionFeed_AddingMoreThan500Entries_StrictlyEnforces500ItemFifoCap()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            vm.ClearActionFeed();

            const int totalEntries = 550;
            for (int i = 0; i < totalEntries; i++)
            {
                vm.AddLogEntry("DEDUP", $"Log message #{i}", $@"C:\Data\file_{i}.dat", 1024);
            }

            // Must be strictly capped at 500
            Assert.Equal(HyperStoreViewModel.MaxActionFeedCapacity, vm.ActionFeed.Count);
            Assert.Equal(500, vm.ActionFeed.Count);

            // FIFO: The first 50 entries (0..49) must have been dropped.
            // Index 0 in feed must be entry #50.
            Assert.Equal("Log message #50", vm.ActionFeed[0].Message);

            // Last index (499) must be entry #549.
            Assert.Equal("Log message #549", vm.ActionFeed[499].Message);
        });
    }

    [Fact]
    public void ActionFeed_ClearActionFeed_RemovesAllEntries()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            vm.AddLogEntry("TEST", "Test entry 1");
            vm.AddLogEntry("TEST", "Test entry 2");
            Assert.NotEmpty(vm.ActionFeed);

            vm.ClearActionFeed();
            Assert.Empty(vm.ActionFeed);
        });
    }

    [Fact]
    public void HyperStoreLogEntryViewModel_FormatsPropertiesAndBadgesCorrectly()
    {
        StaTestRunner.Run(() =>
        {
            var entry = new HyperStoreLogEntryViewModel(
                "DEDUP",
                "Consolidated 4 duplicate files",
                @"D:\Workspace\binary.dll",
                402_653_184L); // 384 MB

            Assert.Equal("DEDUP", entry.Category);
            Assert.Equal("[DEDUP]", entry.CategoryTag);
            Assert.Equal("#00E5FF", entry.CategoryBrush);
            Assert.Equal("binary.dll", entry.FileName);
            Assert.True(entry.HasBytesSaved);
            Assert.Equal(Visibility.Visible, entry.SavedBadgeVisibility);
            Assert.Contains("384.0 MB", entry.FormattedBytesSaved);
            Assert.StartsWith("[", entry.FormattedTimestamp);
            Assert.EndsWith("]", entry.FormattedTimestamp);

            // Entry with zero bytes saved
            var infoEntry = new HyperStoreLogEntryViewModel("INFO", "Scanning initiated", "", 0);
            Assert.False(infoEntry.HasBytesSaved);
            Assert.Equal(Visibility.Collapsed, infoEntry.SavedBadgeVisibility);
            Assert.Equal("0 B", infoEntry.FormattedBytesSaved);
        });
    }

    #endregion

    #region 4. Execution Mode Toggles & Configuration

    [Fact]
    public void ExecutionMode_TogglesCorrectly_AndNotifiesPropertyChanges()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();

            // Default
            Assert.Equal(WorkerExecutionMode.ContinuousLowPriority, vm.ExecutionMode);
            Assert.True(vm.IsContinuousLowPriority);
            Assert.False(vm.IsScheduledWindow);
            Assert.False(vm.IsManualOnly);

            // Switch to Scheduled
            vm.IsScheduledWindow = true;
            Assert.Equal(WorkerExecutionMode.ScheduledWindow, vm.ExecutionMode);
            Assert.False(vm.IsContinuousLowPriority);
            Assert.True(vm.IsScheduledWindow);
            Assert.False(vm.IsManualOnly);

            // Switch to Manual
            vm.IsManualOnly = true;
            Assert.Equal(WorkerExecutionMode.ManualOnly, vm.ExecutionMode);
            Assert.False(vm.IsContinuousLowPriority);
            Assert.False(vm.IsScheduledWindow);
            Assert.True(vm.IsManualOnly);

            // Switch back to Continuous
            vm.IsContinuousLowPriority = true;
            Assert.Equal(WorkerExecutionMode.ContinuousLowPriority, vm.ExecutionMode);
            Assert.True(vm.IsContinuousLowPriority);
            Assert.False(vm.IsScheduledWindow);
            Assert.False(vm.IsManualOnly);
        });
    }

    [Fact]
    public void HardwareSensorSettings_ToggleCorrectly()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();

            Assert.True(vm.IsGameGuardEnabled);
            vm.IsGameGuardEnabled = false;
            Assert.False(vm.IsGameGuardEnabled);

            Assert.True(vm.IsAcPowerOnly);
            vm.IsAcPowerOnly = false;
            Assert.False(vm.IsAcPowerOnly);

            Assert.True(vm.IsRefsCloningEnabled);
            vm.IsRefsCloningEnabled = false;
            Assert.False(vm.IsRefsCloningEnabled);
        });
    }

    #endregion

    #region 5. Interactive Async Non-Blocking Operations

    [Fact]
    public async Task ScanDriveForRedundanciesAsync_ExecutesAndReportsTelemetry_WithoutFreezing()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();

            // Create sample files in temp dir with known duplicate content
            string scanDir = Path.Combine(_testRoot, "ScanTest");
            Directory.CreateDirectory(scanDir);

            byte[] duplicateContent = Encoding.UTF8.GetBytes(new string('X', 65536)); // 64 KB duplicate
            for (int i = 0; i < 4; i++)
            {
                await File.WriteAllBytesAsync(Path.Combine(scanDir, $"dup_{i}.bin"), duplicateContent);
            }

            for (int i = 0; i < 2; i++)
            {
                await File.WriteAllBytesAsync(Path.Combine(scanDir, $"unique_{i}.bin"), Encoding.UTF8.GetBytes($"UniqueContent_{i}_{Guid.NewGuid()}"));
            }

            int scannedFiles = await vm.ScanDriveForRedundanciesAsync(scanDir);

            Assert.Equal(6, scannedFiles);
            Assert.False(vm.IsBusy);
            Assert.True(vm.ChunksIndexed > 0);
            Assert.True(vm.DuplicateChunks > 0);
            Assert.True(vm.TotalScannedBytes > 0);
            Assert.Single(vm.DuplicateFindings);
            Assert.True(vm.DuplicateFindings[0].TotalWastedBytes > 0);
            Assert.Equal(0, vm.TotalBytesReclaimed); // Scan is read-only; no bytes reclaimed until deduplication
            Assert.Equal("Protected", vm.ActiveProtectionStatus);
            Assert.Contains(vm.ActionFeed, e => e.Category == "SCAN");
        });
    }

    [Fact]
    public async Task PackDirectoryToLfcAsync_CreatesArchiveAndUpdatesMetrics_WithoutFreezing()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();

            string packDir = Path.Combine(_testRoot, "PackTest");
            Directory.CreateDirectory(packDir);

            for (int i = 0; i < 5; i++)
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(packDir, $"file_{i}.txt"),
                    Encoding.UTF8.GetBytes($"Compressible text data line {i} repeatable content " + new string('A', 4096)));
            }

            string lfcPath = Path.Combine(_testRoot, "PackTest.lfc");
            string resultPath = await vm.PackDirectoryToLfcAsync(packDir, lfcPath);

            Assert.Equal(lfcPath, resultPath);
            Assert.True(File.Exists(lfcPath));
            Assert.True(new FileInfo(lfcPath).Length > 0);
            Assert.False(vm.IsBusy);
            Assert.True(vm.GlobalCompressionRatio >= 1.0);
            Assert.Contains(vm.ActionFeed, e => e.Category == "PACK");
        });
    }

    [Fact]
    public async Task DeduplicateWorkspaceAsync_RunsDeduplicationInDryRunMode_WithoutFreezing()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();

            string dedupDir = Path.Combine(_testRoot, "DedupTest");
            Directory.CreateDirectory(dedupDir);

            byte[] sharedData = Encoding.UTF8.GetBytes(new string('Z', 32768));
            await File.WriteAllBytesAsync(Path.Combine(dedupDir, "orig.bin"), sharedData);
            await File.WriteAllBytesAsync(Path.Combine(dedupDir, "copy.bin"), sharedData);

            var result = await vm.DeduplicateWorkspaceAsync(dedupDir, dryRun: true);

            Assert.NotNull(result);
            Assert.False(vm.IsBusy);
            Assert.Equal("Protected", vm.ActiveProtectionStatus);
            Assert.Contains(vm.ActionFeed, e => e.Category == "SIMULATE" || e.Category == "DEDUP");
        });
    }

    [Fact]
    public void CancelActiveOperation_CancelsRunningOperationPromptly()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            vm.CancelActiveOperation();
            Assert.False(vm.IsBusy);
        });
    }

    #endregion

    #region 6. UiDispatcher Headless Execution & Override Safety

    [Fact]
    public void UiDispatcher_ExecutesSyncActionHeadlessly_WithoutThrowing()
    {
        bool executed = false;
        UiDispatcher.Invoke(() => executed = true);
        Assert.True(executed);
    }

    [Fact]
    public async Task UiDispatcher_ExecutesAsyncActionHeadlessly_WithoutThrowing()
    {
        bool executed = false;
        await UiDispatcher.InvokeAsync(() => executed = true);
        Assert.True(executed);
    }

    [Fact]
    public async Task UiDispatcher_ExecutesAsyncFuncHeadlessly_ReturnsCorrectResult()
    {
        int result = await UiDispatcher.InvokeAsync(() => 12345);
        Assert.Equal(12345, result);
    }

    [Fact]
    public void UiDispatcher_DispatchOverride_RedirectsInvocationsSuccessfully()
    {
        int overrideCount = 0;
        Action<Action> customHook = act =>
        {
            overrideCount++;
            act();
        };

        UiDispatcher.DispatchOverride = customHook;
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

    #endregion

    #region 7. Background Worker Event Telemetry Streaming

    [Fact]
    public void BackgroundWorker_OptimizationEvent_StreamsDirectlyIntoActionFeed()
    {
        StaTestRunner.Run(() =>
        {
            using var worker = new HyperStoreBackgroundWorker();
            var vm = new HyperStoreViewModel(null, worker);
            vm.ClearActionFeed();

            var evt = new OptimizationEvent(
                @"C:\Data\Asset.dat",
                "ConsolidatedDuplicate",
                52_428_800L, // 50 MB
                "[12:00:00] Consolidated duplicate binary — Saved 50 MB",
                DateTime.UtcNow);

            worker.PublishOptimizationEvent(evt);

            Assert.Single(vm.ActionFeed);
            Assert.Equal("DEDUP", vm.ActionFeed[0].Category);
            Assert.Equal(52_428_800L, vm.ActionFeed[0].BytesSaved);
            Assert.Equal(52_428_800L, vm.TotalBytesReclaimed);
        });
    }

    #endregion

    #region 8. FormatBytes Static Helper Verification

    [Theory]
    [InlineData(0L, "0 B")]
    [InlineData(512L, "512 B")]
    [InlineData(1024L, "1.0 KB")]
    [InlineData(1048576L, "1.0 MB")]
    [InlineData(1073741824L, "1.00 GB")]
    [InlineData(34359738368L, "32.00 GB")]
    public void FormatBytes_FormatsByteQuantitiesAccurately(long bytes, string expected)
    {
        string actual = HyperStoreViewModel.FormatBytes(bytes);
        Assert.Equal(expected, actual);
    }

    #endregion

    #region 9. Duplicate Findings, Category Breakdown, Filtering & Batch Deduplication

    [Theory]
    [InlineData(".exe", "Installers & Binaries", "BIN / EXE", "#00E5FF")]
    [InlineData(".msi", "Installers & Binaries", "BIN / EXE", "#00E5FF")]
    [InlineData(".mp4", "Media", "MEDIA", "#A78BFA")]
    [InlineData(".png", "Media", "MEDIA", "#A78BFA")]
    [InlineData(".zip", "Code & Archives", "CODE / ZIP", "#F59E0B")]
    [InlineData(".cs", "Code & Archives", "CODE / ZIP", "#F59E0B")]
    [InlineData(".pdf", "Documents", "DOCUMENT", "#38BDF8")]
    [InlineData(".docx", "Documents", "DOCUMENT", "#38BDF8")]
    [InlineData(".xyz", "Other", "FILE", "#94A3B8")]
    public void ClassifyExtension_ReturnsCorrectCategoryBadgeAndBrush(string ext, string expectedCat, string expectedBadge, string expectedBrush)
    {
        var (category, badge, brush) = HyperStoreDuplicateFindingViewModel.ClassifyExtension(ext);
        Assert.Equal(expectedCat, category);
        Assert.Equal(expectedBadge, badge);
        Assert.Equal(expectedBrush, brush);
    }

    [Fact]
    public async Task ScanDriveForRedundancies_IdentifiesDuplicateClustersAndPopulatesFindings()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "ScanTest");
            Directory.CreateDirectory(scanDir);

            // Create duplicates for .exe
            byte[] exeData = Encoding.UTF8.GetBytes(new string('E', 8192));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "app1.exe"), exeData);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "app2.exe"), exeData);

            // Create duplicates for .mp4
            byte[] mediaData = Encoding.UTF8.GetBytes(new string('M', 16384));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "video1.mp4"), mediaData);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "video2.mp4"), mediaData);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "video3.mp4"), mediaData);

            // Create unique file (should not be in findings)
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "unique.txt"), Encoding.UTF8.GetBytes("Unique file content"));

            int filesScanned = await vm.ScanDriveForRedundanciesAsync(scanDir);

            Assert.Equal(6, filesScanned);
            Assert.Equal(2, vm.TotalFindingsCount);
            Assert.True(vm.HasDuplicateFindings);
            Assert.Equal(Visibility.Visible, vm.FindingsVisibility);
            Assert.Equal(Visibility.Collapsed, vm.FindingsEmptyVisibility);

            // Check category breakdown counts
            Assert.Equal(1, vm.InstallersCount);
            Assert.Equal(1, vm.MediaCount);
            Assert.Equal(0, vm.DocumentsCount);
            Assert.Equal(0, vm.CodeArchivesCount);

            // Check wasted bytes calculation: (2 - 1) * 8192 + (3 - 1) * 16384 = 8192 + 32768 = 40960
            long expectedWasted = 8192L + 32768L;
            Assert.Equal(expectedWasted, vm.SelectedWastedBytes);
            Assert.Equal(2, vm.SelectedFindingsCount);

            // Verify finding models
            var exeFinding = vm.DuplicateFindings.FirstOrDefault(f => f.Extension == ".exe");
            Assert.NotNull(exeFinding);
            Assert.Equal("Installers & Binaries", exeFinding.Category);
            Assert.Equal("BIN / EXE", exeFinding.FileTypeBadge);
            Assert.Equal(2, exeFinding.DuplicateCopiesCount);
            Assert.Equal(8192L, exeFinding.TotalWastedBytes);
            Assert.Equal("ORIGINAL", exeFinding.Copies[0].CopyTypeBadge);
            Assert.Equal("DUPLICATE", exeFinding.Copies[1].CopyTypeBadge);

            var mediaFinding = vm.DuplicateFindings.FirstOrDefault(f => f.Extension == ".mp4");
            Assert.NotNull(mediaFinding);
            Assert.Equal("Media", mediaFinding.Category);
            Assert.Equal(3, mediaFinding.DuplicateCopiesCount);
            Assert.Equal(32768L, mediaFinding.TotalWastedBytes);
        });
    }

    [Fact]
    public async Task CategoryFiltering_FiltersViewAndUpdatesFilterBooleans()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "FilterTest");
            Directory.CreateDirectory(scanDir);

            byte[] b1 = Encoding.UTF8.GetBytes(new string('1', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "tool.exe"), b1);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "tool_copy.exe"), b1);

            byte[] b2 = Encoding.UTF8.GetBytes(new string('2', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "song.mp3"), b2);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "song_copy.mp3"), b2);

            await vm.ScanDriveForRedundanciesAsync(scanDir);
            Assert.Equal(2, vm.DuplicateFindings.Count);

            // Filter to Media
            vm.SelectedCategoryFilter = "Media";
            Assert.True(vm.IsFilterMedia);
            Assert.False(vm.IsFilterAll);
            Assert.False(vm.IsFilterInstallers);
            Assert.Single(vm.FilteredDuplicateFindings);
            Assert.Equal(".mp3", vm.FilteredDuplicateFindings[0].Extension);

            // Filter to Installers & Binaries
            vm.SelectedCategoryFilter = "Installers & Binaries";
            Assert.True(vm.IsFilterInstallers);
            Assert.Single(vm.FilteredDuplicateFindings);
            Assert.Equal(".exe", vm.FilteredDuplicateFindings[0].Extension);

            // Reset to All
            vm.SelectedCategoryFilter = "All";
            Assert.True(vm.IsFilterAll);
            Assert.Equal(2, vm.FilteredDuplicateFindings.Count);
        });
    }

    [Fact]
    public async Task BatchSelectionAndExclusion_UpdatesMetricsCorrectly()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "BatchTest");
            string subDir = Path.Combine(scanDir, "ExcludedSub");
            Directory.CreateDirectory(scanDir);
            Directory.CreateDirectory(subDir);

            byte[] d1 = Encoding.UTF8.GetBytes(new string('A', 5000));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "f1.pdf"), d1);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "f1_dup.pdf"), d1);

            byte[] d2 = Encoding.UTF8.GetBytes(new string('B', 10000));
            await File.WriteAllBytesAsync(Path.Combine(subDir, "f2.zip"), d2);
            await File.WriteAllBytesAsync(Path.Combine(subDir, "f2_dup.zip"), d2);

            await vm.ScanDriveForRedundanciesAsync(scanDir);
            Assert.Equal(2, vm.DuplicateFindings.Count);

            // Test DeselectAll
            vm.SelectAllFindings(false);
            Assert.Equal(0, vm.SelectedFindingsCount);
            Assert.Equal(0L, vm.SelectedWastedBytes);

            // Test SelectAll
            vm.SelectAllFindings(true);
            Assert.Equal(2, vm.SelectedFindingsCount);
            Assert.Equal(15000L, vm.SelectedWastedBytes);

            // Test SelectSafe (Selects only f2.zip because .pdf is a protected mutable working document)
            vm.SelectSafeFindings();
            Assert.Equal(1, vm.SelectedFindingsCount);
            Assert.Equal(10000L, vm.SelectedWastedBytes);

            // Re-select all before testing folder exclusion
            vm.SelectAllFindings(true);
            Assert.Equal(2, vm.SelectedFindingsCount);

            // Test ExcludeFolder on subDir
            vm.ExcludeFolder(subDir);
            Assert.Single(vm.DuplicateFindings);
            Assert.Equal(".pdf", vm.DuplicateFindings[0].Extension);
            Assert.Equal(5000L, vm.SelectedWastedBytes);
        });
    }

    [Fact]
    public async Task DeduplicateSelected_ConsolidatesSelectedClusters()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "DedupActionTest");
            Directory.CreateDirectory(scanDir);

            byte[] d1 = Encoding.UTF8.GetBytes(new string('X', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "doc.txt"), d1);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "doc_copy.txt"), d1);

            await vm.ScanDriveForRedundanciesAsync(scanDir);
            Assert.Single(vm.DuplicateFindings);

            var finding = vm.DuplicateFindings[0];
            Assert.False(finding.IsDeduplicated);

            long reclaimed = await vm.DeduplicateSelectedAsync();
            Assert.True(reclaimed >= 0);
            Assert.True(finding.IsDeduplicated);
            Assert.Equal("Consolidated", finding.StatusText);
            Assert.Equal(0, vm.SelectedFindingsCount);
            Assert.Contains(vm.ActionFeed, e => e.Category == "DEDUP");
        });
    }

    [Fact]
    public async Task ScanDriveForRedundancies_EmptyDirectory_ReturnsZeroAndClearsFindings()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string emptyDir = Path.Combine(_testRoot, "EmptyDir");
            Directory.CreateDirectory(emptyDir);

            int filesScanned = await vm.ScanDriveForRedundanciesAsync(emptyDir);

            Assert.Equal(0, filesScanned);
            Assert.Empty(vm.DuplicateFindings);
            Assert.Empty(vm.FilteredDuplicateFindings);
            Assert.Equal(0, vm.TotalFindingsCount);
            Assert.Equal(Visibility.Collapsed, vm.FindingsVisibility);
            Assert.Equal(Visibility.Visible, vm.FindingsEmptyVisibility);
        });
    }

    [Fact]
    public async Task ScanDriveForRedundancies_AllUniqueFiles_FindsZeroClusters()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string uniqueDir = Path.Combine(_testRoot, "UniqueDir");
            Directory.CreateDirectory(uniqueDir);

            await File.WriteAllBytesAsync(Path.Combine(uniqueDir, "u1.dat"), Encoding.UTF8.GetBytes("Alpha"));
            await File.WriteAllBytesAsync(Path.Combine(uniqueDir, "u2.dat"), Encoding.UTF8.GetBytes("BetaUniqueBytes"));
            await File.WriteAllBytesAsync(Path.Combine(uniqueDir, "u3.dat"), Encoding.UTF8.GetBytes("GammaUniqueDifferentLength"));

            int filesScanned = await vm.ScanDriveForRedundanciesAsync(uniqueDir);

            Assert.Equal(3, filesScanned);
            Assert.Empty(vm.DuplicateFindings);
            Assert.Empty(vm.FilteredDuplicateFindings);
            Assert.False(vm.HasDuplicateFindings);
        });
    }

    [Fact]
    public async Task ScanDriveForRedundancies_PreCanceledToken_AbortsPromptly()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            int result = await vm.ScanDriveForRedundanciesAsync(_testRoot, cts.Token);
            Assert.Equal(0, result);
            Assert.False(vm.IsBusy);
            Assert.Contains(vm.ActionFeed, e => e.Category == "ALERT");
        });
    }

    [Fact]
    public async Task DeduplicateFinding_AlreadyDeduplicated_ReturnsZeroReclaimed()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            var finding = new HyperStoreDuplicateFindingViewModel(
                Path.Combine(_testRoot, "f.bin"),
                1024,
                new[] { Path.Combine(_testRoot, "f_dup.bin") });

            finding.IsDeduplicated = true;
            long reclaimed = await vm.DeduplicateFindingAsync(finding);
            Assert.Equal(0, reclaimed);
        });
    }

    [Fact]
    public void ExcludeFolder_EmptyOrNull_NoOp()
    {
        StaTestRunner.Run(() =>
        {
            var vm = new HyperStoreViewModel();
            int initialExcluded = vm.ExcludedFolders.Count;

            vm.ExcludeFolder("");
            vm.ExcludeFolder("   ");

            Assert.Equal(initialExcluded, vm.ExcludedFolders.Count);
        });
    }

    [Fact]
    public async Task ScanDriveForRedundancies_DoesNotAlterTotalBytesReclaimed()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "ScanReclaimedIsolationTest");
            Directory.CreateDirectory(scanDir);

            byte[] d1 = Encoding.UTF8.GetBytes(new string('Z', 8192));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "pkg1.msi"), d1);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "pkg2.msi"), d1);

            Assert.Equal(0, vm.TotalBytesReclaimed);

            await vm.ScanDriveForRedundanciesAsync(scanDir);

            // Scan is read-only; TotalBytesReclaimed must remain strictly 0!
            Assert.Single(vm.DuplicateFindings);
            Assert.Equal(8192L, vm.DuplicateFindings[0].TotalWastedBytes);
            Assert.Equal(0, vm.TotalBytesReclaimed);
            Assert.Equal("0 B", vm.TotalSpaceReclaimedFormatted);
        });
    }

    [Fact]
    public async Task SelectSafeFindings_DifferentiatesSafeFromUnsafe()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string scanDir = Path.Combine(_testRoot, "SafeSelectDiscriminationTest");
            Directory.CreateDirectory(scanDir);

            byte[] payload = Encoding.UTF8.GetBytes(new string('S', 4096));

            // Static/Safe: .exe and .mp4
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "app.exe"), payload);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "app_copy.exe"), payload);

            byte[] mediaPayload = Encoding.UTF8.GetBytes(new string('M', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "clip.mp4"), mediaPayload);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "clip_copy.mp4"), mediaPayload);

            // Mutable/Unsafe: .docx and .cs
            byte[] docPayload = Encoding.UTF8.GetBytes(new string('D', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "report.docx"), docPayload);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "report_copy.docx"), docPayload);

            byte[] codePayload = Encoding.UTF8.GetBytes(new string('C', 4096));
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "program.cs"), codePayload);
            await File.WriteAllBytesAsync(Path.Combine(scanDir, "program_copy.cs"), codePayload);

            await vm.ScanDriveForRedundanciesAsync(scanDir);
            Assert.Equal(4, vm.DuplicateFindings.Count);

            var exeFinding = vm.DuplicateFindings.First(f => f.Extension == ".exe");
            var mp4Finding = vm.DuplicateFindings.First(f => f.Extension == ".mp4");
            var docxFinding = vm.DuplicateFindings.First(f => f.Extension == ".docx");
            var csFinding = vm.DuplicateFindings.First(f => f.Extension == ".cs");

            Assert.True(exeFinding.IsSafe);
            Assert.True(mp4Finding.IsSafe);
            Assert.False(docxFinding.IsSafe);
            Assert.False(csFinding.IsSafe);

            // Initially all selected
            Assert.Equal(4, vm.SelectedFindingsCount);

            // Call SelectSafeFindings
            vm.SelectSafeFindings();

            Assert.Equal(2, vm.SelectedFindingsCount);
            Assert.True(exeFinding.IsSelected);
            Assert.True(mp4Finding.IsSelected);
            Assert.False(docxFinding.IsSelected);
            Assert.False(csFinding.IsSelected);
        });
    }

    [Fact]
    public async Task EnumerateFilesSafe_HandlesNestedDirectoriesWithoutFailing()
    {
        await StaTestRunner.RunAsync(async () =>
        {
            var vm = new HyperStoreViewModel();
            string root = Path.Combine(_testRoot, "NestedScanTest");
            string deep = Path.Combine(root, "level1", "level2", "level3");
            Directory.CreateDirectory(deep);

            byte[] data = Encoding.UTF8.GetBytes(new string('N', 2048));
            await File.WriteAllBytesAsync(Path.Combine(root, "top.iso"), data);
            await File.WriteAllBytesAsync(Path.Combine(deep, "deep.iso"), data);

            int count = await vm.ScanDriveForRedundanciesAsync(root);
            Assert.Equal(2, count);
            Assert.Single(vm.DuplicateFindings);
            Assert.Equal(2048L, vm.DuplicateFindings[0].TotalWastedBytes);
        });
    }

    #endregion
}
