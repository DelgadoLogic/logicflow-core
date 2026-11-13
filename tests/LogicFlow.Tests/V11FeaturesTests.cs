using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using LogicFlow.CLI.Commands;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class V11FeaturesTests : IDisposable
{
    private readonly string _tempDir;

    public V11FeaturesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "LogicFlow_V11Tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE 1: Per-Browser SQLite Cookie/Session Whitelist & Vacuum Cleaner
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("https://mail.google.com/mail/u/0/#inbox", "mail.google.com")]
    [InlineData(".github.com", "github.com")]
    [InlineData("  HTTPS://Sub.Example.COM:8443/path?a=1  ", "sub.example.com")]
    [InlineData("", "")]
    public void BrowserPrivacyCleaner_NormalizeDomain_NormalizesUrlsAndHostKeys(string raw, string expected)
    {
        Assert.Equal(expected, BrowserPrivacyCleanerEngine.NormalizeDomain(raw));
    }

    [Fact]
    public void BrowserPrivacyCleaner_IsDomainWhitelisted_MatchesExactAndSubdomainsOnly()
    {
        var whitelist = new[] { "google.com", "github.com", "localhost" };

        Assert.True(BrowserPrivacyCleanerEngine.IsDomainWhitelisted(".google.com", whitelist));
        Assert.True(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("accounts.google.com", whitelist));
        Assert.True(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("api.github.com", whitelist));
        Assert.True(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("localhost", whitelist));

        // Must NOT match partial suffix lookalikes or unrelated trackers
        Assert.False(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("evilgoogle.com", whitelist));
        Assert.False(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("doubleclick.net", whitelist));
        Assert.False(BrowserPrivacyCleanerEngine.IsDomainWhitelisted("", whitelist));
    }

    [Fact]
    public void BrowserPrivacyCleaner_WhitelistPersistence_AddRemoveAndReload()
    {
        string wlPath = Path.Combine(_tempDir, "browser_whitelist.json");
        var engine = new BrowserPrivacyCleanerEngine(whitelistFilePath: wlPath);

        var initial = engine.GetWhitelistedDomains();
        Assert.Contains("google.com", initial);
        Assert.Contains("github.com", initial);

        var afterAdd = engine.AddWhitelistedDomain("https://custom.delgadologic.com/dashboard");
        Assert.Contains("custom.delgadologic.com", afterAdd);

        var reloaded = engine.GetWhitelistedDomains();
        Assert.Contains("custom.delgadologic.com", reloaded);

        var afterRemove = engine.RemoveWhitelistedDomain("custom.delgadologic.com");
        Assert.DoesNotContain("custom.delgadologic.com", afterRemove);
    }

    [Fact]
    public void BrowserPrivacyCleaner_CleanAndVacuumSqliteDatabase_ChromiumAndFirefox_PrunesTrackersAndVacuums()
    {
        string wlPath = Path.Combine(_tempDir, "whitelist.json");
        var engine = new BrowserPrivacyCleanerEngine(whitelistFilePath: wlPath);
        var whitelist = new[] { "google.com", "github.com" };

        // 1. Chromium 'Cookies' SQLite database
        string chromiumDb = Path.Combine(_tempDir, "Cookies");
        BrowserPrivacyCleanerEngine.CreateCookieDatabase(
            chromiumDb,
            isFirefox: false,
            new[]
            {
                (".google.com", "SID", "val1"),
                ("accounts.google.com", "LSID", "val2"),
                (".github.com", "user_session", "val3"),
                (".doubleclick.net", "IDE", "track1"),
                ("ads.tracker.org", "uid", "track2"),
                ("analytics.adnetwork.io", "_ga", "track3")
            });
        Assert.True(File.Exists(chromiumDb));

        // Dry run first: should report 3 removed, 3 preserved without mutating DB
        var dryResult = engine.CleanAndVacuumSqliteDatabase(chromiumDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: true, dryRun: true);
        Assert.Equal(3, dryResult.Removed);
        Assert.Equal(3, dryResult.Preserved);

        // Real clean + VACUUM: should delete 3 trackers and leave only the 3 whitelisted cookies
        var realResult = engine.CleanAndVacuumSqliteDatabase(chromiumDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: true, dryRun: false);
        Assert.True(realResult.Vacuumed);
        Assert.Equal(3, realResult.Removed);
        Assert.Equal(3, realResult.Preserved);

        // Subsequent dry run confirms 0 non-whitelisted cookies remain and 3 whitelisted cookies are intact
        var verifyResult = engine.CleanAndVacuumSqliteDatabase(chromiumDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: true, dryRun: true);
        Assert.Equal(0, verifyResult.Removed);
        Assert.Equal(3, verifyResult.Preserved);

        // 2. Firefox 'cookies.sqlite' database
        string firefoxDb = Path.Combine(_tempDir, "cookies.sqlite");
        BrowserPrivacyCleanerEngine.CreateCookieDatabase(
            firefoxDb,
            isFirefox: true,
            new[]
            {
                (".github.com", "logged_in", "yes"),
                (".criteo.com", "uid", "track1"),
                (".taboola.com", "t_gid", "track2")
            });
        Assert.True(File.Exists(firefoxDb));

        var fxClean = engine.CleanAndVacuumSqliteDatabase(firefoxDb, whitelist, isCookieDb: true, isFirefox: true, vacuum: true, dryRun: false);
        Assert.True(fxClean.Vacuumed);
        Assert.Equal(2, fxClean.Removed);
        Assert.Equal(1, fxClean.Preserved);
    }

    [Fact]
    public void BrowserPrivacyCleaner_IsFileLocked_DetectsExclusiveHandle()
    {
        string lockedFile = Path.Combine(_tempDir, "locked.sqlite");
        File.WriteAllBytes(lockedFile, new byte[] { 1, 2, 3, 4 });

        Assert.False(BrowserPrivacyCleanerEngine.IsFileLocked(lockedFile));

        using (var exclusiveStream = new FileStream(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.True(BrowserPrivacyCleanerEngine.IsFileLocked(lockedFile));
        }

        Assert.False(BrowserPrivacyCleanerEngine.IsFileLocked(lockedFile));
    }

    [Fact]
    public void BrowserPrivacyCleaner_CleanAndVacuumSqliteDatabase_WalModeWithSharedReader_ReclaimsSpaceAndTruncatesWal()
    {
        string wlPath = Path.Combine(_tempDir, "wal_whitelist.json");
        var engine = new BrowserPrivacyCleanerEngine(whitelistFilePath: wlPath);
        var whitelist = new[] { "google.com" };

        string walCookieDb = Path.Combine(_tempDir, "WalCookies");
        var seedCookies = new List<(string HostKey, string Name, string Value)>
        {
            (".google.com", "SID", "keep_session_token")
        };
        string heavyPayload = new('X', 2048);
        for (int i = 0; i < 60; i++)
        {
            seedCookies.Add(($".tracker{i}.example.net", $"trk_{i}", heavyPayload));
        }

        BrowserPrivacyCleanerEngine.CreateCookieDatabase(
            walCookieDb,
            isFirefox: false,
            seedCookies,
            useWalMode: true);

        Assert.True(File.Exists(walCookieDb));
        Assert.True(BrowserPrivacyCleanerEngine.CanOpenForWrite(walCookieDb));

        // Hold a shared read stream (simulating non-exclusive background inspection) while running dryRun and clean+VACUUM
        using (var sharedReader = new FileStream(walCookieDb, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            Assert.True(BrowserPrivacyCleanerEngine.CanOpenForWrite(walCookieDb));

            var dryRes = engine.CleanAndVacuumSqliteDatabase(walCookieDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: true, dryRun: true);
            Assert.Equal(60, dryRes.Removed);
            Assert.Equal(1, dryRes.Preserved);

            var cleanRes = engine.CleanAndVacuumSqliteDatabase(walCookieDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: true, dryRun: false);
            Assert.True(cleanRes.Vacuumed);
            Assert.Equal(60, cleanRes.Removed);
            Assert.Equal(1, cleanRes.Preserved);
            Assert.True(cleanRes.BytesReclaimed > 0, $"Expected positive reclaimed bytes after WAL checkpoint + VACUUM, got {cleanRes.BytesReclaimed}");
        }

        var postVerify = engine.CleanAndVacuumSqliteDatabase(walCookieDb, whitelist, isCookieDb: true, isFirefox: false, vacuum: false, dryRun: true);
        Assert.Equal(0, postVerify.Removed);
        Assert.Equal(1, postVerify.Preserved);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE 2: Interactive Disk Space Treemap UI (Squarified Layout Engine)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void DiskSpaceAnalyzer_ComputeTreemapLayout_SquarifiedBoundsAndAreaConservation()
    {
        var analyzer = new DiskSpaceAnalyzer();
        var root = new DiskSpaceAnalyzer.FolderNode
        {
            Name = "Root",
            FullPath = @"C:\Root",
            SizeBytes = 1000,
            Children = new List<DiskSpaceAnalyzer.FolderNode>
            {
                new() { Name = "Games.zip", FullPath = @"C:\Root\Games.zip", SizeBytes = 500, FileCount = 1, IsFile = true },
                new() { Name = "Capture.mp4", FullPath = @"C:\Root\Capture.mp4", SizeBytes = 300, FileCount = 1, IsFile = true },
                new() { Name = "Source.cs", FullPath = @"C:\Root\Source.cs", SizeBytes = 150, FileCount = 1, IsFile = true },
                new() { Name = "Readme.pdf", FullPath = @"C:\Root\Readme.pdf", SizeBytes = 50, FileCount = 1, IsFile = true }
            }
        };

        double width = 800;
        double height = 400;
        var tiles = analyzer.ComputeTreemapLayout(root, width, height, maxDepth: 1);

        Assert.Equal(4, tiles.Count);

        double totalArea = 0;
        foreach (var tile in tiles)
        {
            Assert.True(tile.X >= -0.001);
            Assert.True(tile.Y >= -0.001);
            Assert.True(tile.Width > 0);
            Assert.True(tile.Height > 0);
            Assert.True(tile.X + tile.Width <= width + 0.01);
            Assert.True(tile.Y + tile.Height <= height + 0.01);
            Assert.StartsWith("#", tile.ColorHex);
            totalArea += tile.Width * tile.Height;
        }

        Assert.Equal(width * height, totalArea, precision: 1);
        Assert.Contains(tiles, t => t.Name == "Games.zip" && t.Category == "Games & Archives");
        Assert.Contains(tiles, t => t.Name == "Capture.mp4" && t.Category == "Media & Video");
        Assert.Contains(tiles, t => t.Name == "Source.cs" && t.Category == "Code & Dev");
        Assert.Contains(tiles, t => t.Name == "Readme.pdf" && t.Category == "Documents");
    }

    [Fact]
    public void DiskSpaceAnalyzer_ComputeTreemapLayout_HierarchicalMaxDepth2_PopulatesSubTilesWithinParentBounds()
    {
        var analyzer = new DiskSpaceAnalyzer();
        var root = new DiskSpaceAnalyzer.FolderNode
        {
            Name = "Root",
            FullPath = @"C:\Root",
            SizeBytes = 1000,
            FileCount = 3,
            Children = new List<DiskSpaceAnalyzer.FolderNode>
            {
                new()
                {
                    Name = "SubFolder",
                    FullPath = @"C:\Root\SubFolder",
                    SizeBytes = 700,
                    FileCount = 2,
                    IsFile = false,
                    Children = new List<DiskSpaceAnalyzer.FolderNode>
                    {
                        new() { Name = "Engine.dll", FullPath = @"C:\Root\SubFolder\Engine.dll", SizeBytes = 500, FileCount = 1, IsFile = true },
                        new() { Name = "Data.pak", FullPath = @"C:\Root\SubFolder\Data.pak", SizeBytes = 200, FileCount = 1, IsFile = true }
                    }
                },
                new() { Name = "Video.mkv", FullPath = @"C:\Root\Video.mkv", SizeBytes = 300, FileCount = 1, IsFile = true }
            }
        };

        var tiles = analyzer.ComputeTreemapLayout(root, 600, 300, maxDepth: 2);
        Assert.Equal(2, tiles.Count);

        var folderTile = tiles.First(t => t.Name == "SubFolder");
        Assert.True(folderTile.IsDirectory);
        Assert.Equal(2, folderTile.SubTiles.Count);

        foreach (var sub in folderTile.SubTiles)
        {
            Assert.Equal(2, sub.Depth);
            Assert.True(sub.X >= folderTile.X - 0.01);
            Assert.True(sub.Y >= folderTile.Y - 0.01);
            Assert.True(sub.X + sub.Width <= folderTile.X + folderTile.Width + 0.01);
            Assert.True(sub.Y + sub.Height <= folderTile.Y + folderTile.Height + 0.01);
        }
    }

    [Fact]
    public void DiskSpaceAnalyzer_ComputeTreemapLayout_HandlesNullAndZeroDimensions()
    {
        var analyzer = new DiskSpaceAnalyzer();
        Assert.Empty(analyzer.ComputeTreemapLayout(null, 800, 400));
        var emptyNode = new DiskSpaceAnalyzer.FolderNode { Name = "Empty", SizeBytes = 0 };
        Assert.Empty(analyzer.ComputeTreemapLayout(emptyNode, 800, 400));
        Assert.Empty(analyzer.ComputeTreemapLayout(emptyNode, 0, 400));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE 3: Boot-Time Critical Path Flamegraph & Diagnostics (Event 100–110)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void BootPerformanceAnalyzer_TryParseEvent100AndDegradationXml_ParsesAccurately()
    {
        string event100Xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>100</EventID>
    <TimeCreated SystemTime='2026-10-15T12:00:00.000Z' />
  </System>
  <EventData>
    <Data Name='BootTime'>18450</Data>
    <Data Name='MainPathBootTime'>11200</Data>
    <Data Name='BootPostBootTime'>7250</Data>
    <Data Name='BootDriverInitTime'>2400</Data>
    <Data Name='BootExplorerInitTime'>1800</Data>
    <Data Name='BootTsVersion'>2</Data>
  </EventData>
</Event>";

        var report = new BootPerformanceAnalyzer.BootAnalysisReport();
        bool ok100 = BootPerformanceAnalyzer.TryParseEvent100Xml(event100Xml, DateTime.UtcNow, report);

        Assert.True(ok100);
        Assert.Equal(18450, report.TotalBootTimeMs);
        Assert.Equal(18.45, report.TotalBootSeconds, precision: 2);
        Assert.Equal(11200, report.MainPathBootTimeMs);
        Assert.Equal(7250, report.PostBootTimeMs);
        Assert.Equal(2400, report.DriverInitTimeMs);
        Assert.Equal(1800, report.ExplorerInitTimeMs);

        string event101Xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>101</EventID>
    <TimeCreated SystemTime='2026-10-15T12:00:05.000Z' />
  </System>
  <EventData>
    <Data Name='Name'>HeavyLauncher.exe</Data>
    <Data Name='FriendlyName'>Heavy Game Launcher</Data>
    <Data Name='TotalTime'>3450</Data>
    <Data Name='DegradationTime'>2650</Data>
  </EventData>
</Event>";

        var degEntry = BootPerformanceAnalyzer.TryParseDegradationEventXml(event101Xml, 101);
        Assert.NotNull(degEntry);
        Assert.Equal(101, degEntry!.EventId);
        Assert.Equal("Startup App", degEntry.Phase);
        Assert.Equal("HeavyLauncher.exe", degEntry.Name);
        Assert.Equal(3450, degEntry.DurationMs);
        Assert.Equal(2650, degEntry.DegradationMs);
        Assert.Equal("3.45 s (3,450 ms)", degEntry.DurationFormatted);
        Assert.Equal("Critical", degEntry.Severity);
        Assert.Equal("#EF4444", degEntry.ColorHex);

        var subSecondEntry = new BootPerformanceAnalyzer.BootCriticalPathEntry { DurationMs = 850 };
        Assert.Equal("850 ms", subSecondEntry.DurationFormatted);

        report.CriticalPathEntries.Add(degEntry);
        BootPerformanceAnalyzer.PopulateFlamegraphMetrics(report, maxBarWidthPx: 420.0);
        Assert.InRange(degEntry.BarWidthPx, 18.0, 420.0);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE 4: VSS Snapshot File Browser & Single-File Restore
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void SystemRestoreEngine_ParseVssAdminOutput_ParsesSnapshotsAndNormalizesVolumeRoot()
    {
        string sampleOutput = @"
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {11111111-2222-3333-4444-555555555555}
   Contained 1 shadow copies at creation time: 10/14/2026 8:30:00 AM
      Shadow Copy ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
         Original Volume: (C:)\\?\Volume{99999999-0000-1111-2222-333333333333}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12
         Originating Machine: WORKSTATION
         Service Machine: WORKSTATION
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessibleWriters
         Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
";

        var parsed = SystemRestoreEngine.ParseVssAdminOutput(sampleOutput);
        Assert.Single(parsed);
        Assert.Equal("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", parsed[0].ShadowId);
        Assert.Equal(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12", parsed[0].DeviceObject);
        Assert.Equal(@"C:\", parsed[0].VolumeName);
        Assert.Equal(@"C:\Users\notes.txt", Path.Combine(parsed[0].VolumeName, @"Users\notes.txt"));
    }

    [Fact]
    public void SystemRestoreEngine_PathSanitizationAndReadOnlyOverwrite_HandlesEdgeCasesCleanly()
    {
        Assert.Equal(@"C:\", SystemRestoreEngine.NormalizeLiveVolumeRoot("C:"));
        Assert.Equal(@"D:\", SystemRestoreEngine.NormalizeLiveVolumeRoot("D:\\"));
        Assert.Equal(@"Users\Documents\report.docx", SystemRestoreEngine.NormalizeRelativeShadowPath(@"C:\Users\Documents\report.docx:Zone.Identifier"));
        Assert.Equal(@"Windows\System32\drivers\etc\hosts", SystemRestoreEngine.NormalizeRelativeShadowPath(@"..\..\Windows\System32\.\drivers\etc\hosts."));

        string simulatedShadowRoot = Path.Combine(_tempDir, "ShadowRO");
        string simulatedLiveRoot = Path.Combine(_tempDir, "LiveRO");
        Directory.CreateDirectory(simulatedShadowRoot);
        Directory.CreateDirectory(simulatedLiveRoot);

        string shadowFile = Path.Combine(simulatedShadowRoot, "readonly.cfg");
        string liveFile = Path.Combine(simulatedLiveRoot, "readonly.cfg");
        File.WriteAllText(shadowFile, "clean_snapshot_config=1");
        File.WriteAllText(liveFile, "corrupted_live_config=0");

        // Mark both snapshot source and live destination as ReadOnly
        File.SetAttributes(shadowFile, FileAttributes.ReadOnly);
        File.SetAttributes(liveFile, FileAttributes.ReadOnly);

        try
        {
            var engine = new SystemRestoreEngine();
            var res = engine.RestoreFileFromShadowCopy(simulatedShadowRoot, "readonly.cfg:Zone.Identifier", liveFile, overwrite: true);
            Assert.True(res.Success, res.Message);
            Assert.Equal("clean_snapshot_config=1", File.ReadAllText(liveFile));
            Assert.Equal((FileAttributes)0, File.GetAttributes(liveFile) & FileAttributes.ReadOnly);
        }
        finally
        {
            File.SetAttributes(shadowFile, FileAttributes.Normal);
            if (File.Exists(liveFile))
                File.SetAttributes(liveFile, FileAttributes.Normal);
        }
    }

    [Fact]
    public void SystemRestoreEngine_VssBrowseAndRestore_DetectsDiffsAndRestoresFilesWithoutReboot()
    {
        string simulatedShadowRoot = Path.Combine(_tempDir, "ShadowRoot");
        string simulatedLiveRoot = Path.Combine(_tempDir, "LiveRoot");
        Directory.CreateDirectory(simulatedShadowRoot);
        Directory.CreateDirectory(simulatedLiveRoot);

        // 1. Deleted file (exists in shadow, missing on live disk)
        string shadowDeleted = Path.Combine(simulatedShadowRoot, "deleted_report.docx");
        File.WriteAllText(shadowDeleted, "Important content from yesterday");

        // 2. Modified file (exists in both, different size/content)
        string shadowModified = Path.Combine(simulatedShadowRoot, "config.json");
        string liveModified = Path.Combine(simulatedLiveRoot, "config.json");
        File.WriteAllText(shadowModified, "{\"version\":1,\"good\":true}");
        File.WriteAllText(liveModified, "{\"version\":2}");

        // 3. Identical file (same size and timestamp)
        string shadowIdentical = Path.Combine(simulatedShadowRoot, "notes.txt");
        string liveIdentical = Path.Combine(simulatedLiveRoot, "notes.txt");
        File.WriteAllText(shadowIdentical, "Unchanged notes");
        File.WriteAllText(liveIdentical, "Unchanged notes");
        DateTime fixedTime = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(shadowIdentical, fixedTime);
        File.SetLastWriteTimeUtc(liveIdentical, fixedTime);

        var engine = new SystemRestoreEngine();
        var entries = engine.BrowseShadowCopyDirectory(simulatedShadowRoot, "", simulatedLiveRoot);

        Assert.Equal(3, entries.Count);

        // Verify DeletedOnLiveDisk is sorted first
        var deletedEntry = entries.First(e => e.Name == "deleted_report.docx");
        Assert.Equal(VssDiffStatus.DeletedOnLiveDisk, deletedEntry.DiffStatus);

        var modifiedEntry = entries.First(e => e.Name == "config.json");
        Assert.Equal(VssDiffStatus.ModifiedSinceSnapshot, modifiedEntry.DiffStatus);

        var identicalEntry = entries.First(e => e.Name == "notes.txt");
        Assert.Equal(VssDiffStatus.Identical, identicalEntry.DiffStatus);

        // Restore the deleted file back to live disk
        string restoreTarget = Path.Combine(simulatedLiveRoot, "deleted_report.docx");
        var restoreRes = engine.RestoreFileFromShadowCopy(simulatedShadowRoot, "deleted_report.docx", restoreTarget, overwrite: false);
        Assert.True(restoreRes.Success, restoreRes.Message);
        Assert.True(File.Exists(restoreTarget));
        Assert.Equal("Important content from yesterday", File.ReadAllText(restoreTarget));

        // Verify overwrite: false refuses to clobber existing file, while overwrite: true succeeds
        var noOverwriteRes = engine.RestoreFileFromShadowCopy(simulatedShadowRoot, "config.json", liveModified, overwrite: false);
        Assert.False(noOverwriteRes.Success);

        var overwriteRes = engine.RestoreFileFromShadowCopy(simulatedShadowRoot, "config.json", liveModified, overwrite: true);
        Assert.True(overwriteRes.Success, overwriteRes.Message);
        Assert.Equal("{\"version\":1,\"good\":true}", File.ReadAllText(liveModified));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE 5: CLI Discovery Schema & Multi-Arch Packaging Script Verification
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void CliDiscoveryAndPackaging_ExposesV11SubcommandsAndMultiArchParameters()
    {
        string schemaJson = JsonSerializer.Serialize(AgenticCommands.GetDiscoverySchema());
        Assert.Contains("boot-analyze", schemaJson);
        Assert.Contains("vss-list", schemaJson);
        Assert.Contains("vss-browse", schemaJson);
        Assert.Contains("vss-restore", schemaJson);
        Assert.Contains("browser-clean", schemaJson);
        Assert.Contains("disk-analyze", schemaJson);

        var lfRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var packageScriptPath = Path.Combine(lfRoot, "package_and_deploy.ps1");
        var buildBatPath = Path.Combine(lfRoot, "Installer", "build.bat");
        var distManifestPath = Path.Combine(lfRoot, "dist", "release-manifest.json");

        Assert.True(File.Exists(packageScriptPath));
        string scriptText = File.ReadAllText(packageScriptPath);
        Assert.Contains("[ValidateSet(\"win-x64\", \"win-arm64\")]", scriptText);
        Assert.DoesNotContain("win-x86", scriptText);
        Assert.Contains("[switch]$AllArchitectures", scriptText);
        Assert.Contains("[string[]]$targetRuntimes", scriptText);
        Assert.Contains("supportedArchitectures", scriptText);

        Assert.True(File.Exists(buildBatPath));
        string buildBatText = File.ReadAllText(buildBatPath);
        Assert.Contains("vcvarsamd64_x86.bat", buildBatText);
        Assert.Contains("vcvarsamd64_arm64.bat", buildBatText);
        Assert.Contains("/MACHINE:%LINK_MACHINE%", buildBatText);

        if (File.Exists(distManifestPath))
        {
            using var manifestDoc = JsonDocument.Parse(File.ReadAllText(distManifestPath));
            var root = manifestDoc.RootElement;
            Assert.Equal("LogicFlow", root.GetProperty("product").GetString());
            Assert.True(root.GetProperty("sizeBytes").GetInt64() > 100_000_000L);
            Assert.Equal(64, root.GetProperty("sha256").GetString()?.Length);
            var archs = root.GetProperty("supportedArchitectures").EnumerateArray().Select(e => e.GetString()).ToList();
            Assert.Contains("win-x64", archs);
            Assert.DoesNotContain("win-x86", archs);
        }
    }
}
