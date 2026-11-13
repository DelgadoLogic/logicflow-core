// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — HyperStore Volume-Aware Deduplication Test Suite
// Verification of Requirement R2: Volume-Aware Host Deduplication
// Tests canonical volume resolution, NTFS hard links, ReFS block cloning contracts,
// immutability safeguards, and cross-volume .lfc container fallback.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Guardian.Deduplication;
using LogicFlow.Native;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;
using Xunit;

namespace LogicFlow.Tests.Storage;

public sealed class HyperStoreVolumeDedupTests : IDisposable
{
    private readonly string _testRoot;

    public HyperStoreVolumeDedupTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), $"HyperStoreDedupTests_{Guid.NewGuid():N}");
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

    #region 1. Canonical Volume Resolution & Reparse Point Traversal Tests

    [Fact]
    public void VolumeResolver_ResolvesValidVolumeGuidForNormalPath()
    {
        string dirPath = Path.Combine(_testRoot, "NormalDir");
        Directory.CreateDirectory(dirPath);

        string volumeGuid = VolumeResolver.GetVolumeGuid(dirPath);

        Assert.NotNull(volumeGuid);
        Assert.StartsWith(@"\\?\Volume{", volumeGuid, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(@"}\", volumeGuid, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("-", volumeGuid);
    }

    [Fact]
    public void VolumeResolver_ResolvesVolumeGuidForExistingFile()
    {
        string filePath = Path.Combine(_testRoot, "probe.dat");
        File.WriteAllText(filePath, "probe data for volume resolver");

        string fileVolGuid = VolumeResolver.GetVolumeGuid(filePath);
        string dirVolGuid = VolumeResolver.GetVolumeGuid(_testRoot);

        Assert.Equal(dirVolGuid, fileVolGuid);
    }

    [Fact]
    public void VolumeResolver_SameVolumeReturnsTrueForSameDrive()
    {
        string dir1 = Path.Combine(_testRoot, "SubA");
        string dir2 = Path.Combine(_testRoot, "SubB");
        Directory.CreateDirectory(dir1);
        Directory.CreateDirectory(dir2);

        bool sameVolume = VolumeResolver.AreOnSameVolume(dir1, dir2);
        Assert.True(sameVolume);
    }

    [Fact]
    public void VolumeResolver_ResolvesJunctionToTargetVolume()
    {
        string targetDir = Path.Combine(_testRoot, "JunctionTarget");
        string junctionDir = Path.Combine(_testRoot, "JunctionMount");
        Directory.CreateDirectory(targetDir);

        // Create directory junction via native mklink /J
        using var process = new Process();
        process.StartInfo.FileName = "cmd.exe";
        process.StartInfo.Arguments = $"/c mklink /J \"{junctionDir}\" \"{targetDir}\"";
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.UseShellExecute = false;
        process.Start();
        process.WaitForExit(5000);

        Assert.True(Directory.Exists(junctionDir));
        Assert.True(VolumeResolver.IsReparsePoint(junctionDir));

        string targetGuid = VolumeResolver.GetVolumeGuid(targetDir);
        string junctionGuid = VolumeResolver.GetVolumeGuid(junctionDir);

        Assert.Equal(targetGuid, junctionGuid);
        Assert.True(VolumeResolver.AreOnSameVolume(junctionDir, targetDir));
    }

    [Fact]
    public void VolumeResolver_GetVolumeInfo_ReturnsValidGeometryAndFlags()
    {
        var info = VolumeResolver.GetVolumeInfo(_testRoot);

        Assert.NotNull(info);
        Assert.NotEmpty(info.FileSystemName);
        Assert.True(info.ClusterSize >= 512, "ClusterSize should be at least 512 bytes");
        Assert.True(info.SectorsPerCluster > 0);
        Assert.True(info.BytesPerSector >= 512);
        Assert.True(info.MaximumComponentLength >= 255);
    }

    [Fact]
    public void VolumeResolver_DetectsCrossVolumeBetweenDistinctDrives()
    {
        // Check if both C:\ and D:\ exist on the system
        if (Directory.Exists(@"C:\") && Directory.Exists(@"D:\"))
        {
            string guidC = VolumeResolver.GetVolumeGuid(@"C:\");
            string guidD = VolumeResolver.GetVolumeGuid(@"D:\");

            Assert.NotEqual(guidC, guidD);
            Assert.False(VolumeResolver.AreOnSameVolume(@"C:\", @"D:\"));
        }
    }

    #endregion

    #region 2. File Immutability Classifier Tests

    [Theory]
    [InlineData("document.docx")]
    [InlineData("spreadsheet.xlsx")]
    [InlineData("presentation.pptx")]
    [InlineData("contract.doc")]
    [InlineData("budget.xls")]
    [InlineData("memo.txt")]
    [InlineData("readme.md")]
    [InlineData("data.csv")]
    [InlineData("program.cs")]
    [InlineData("script.py")]
    [InlineData("app.ts")]
    [InlineData("index.js")]
    [InlineData("settings.json")]
    [InlineData("config.xml")]
    [InlineData("app.config")]
    [InlineData("database.sqlite")]
    [InlineData("store.db")]
    public void FileImmutabilityClassifier_MutableWorkingDocuments_AreIdentifiedAndProtected(string fileName)
    {
        string fullPath = Path.Combine(_testRoot, fileName);

        var category = FileImmutabilityClassifier.Classify(fullPath);
        Assert.Equal(ImmutabilityCategory.MutableWorkingDocument, category);

        Assert.True(FileImmutabilityClassifier.IsMutableWorkingDocument(fullPath));
        Assert.False(FileImmutabilityClassifier.IsStaticAsset(fullPath));

        // Must NEVER be safe for NTFS hard linking!
        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(fullPath));
    }

    [Theory]
    [InlineData("disk.iso")]
    [InlineData("vm.vhd")]
    [InlineData("vm.vhdx")]
    [InlineData("engine.dll")]
    [InlineData("launcher.exe")]
    [InlineData("driver.sys")]
    [InlineData("library.lib")]
    [InlineData("symbols.pdb")]
    [InlineData("addon.node")]
    [InlineData("textures.pak")]
    [InlineData("game.assets")]
    [InlineData("archive.bin")]
    [InlineData("installer.msi")]
    [InlineData("package.nupkg")]
    [InlineData("release.zip")]
    [InlineData("backup.7z")]
    [InlineData("video.mp4")]
    public void FileImmutabilityClassifier_StaticImmutableAssets_AreEligibleForHardLinks(string fileName)
    {
        string fullPath = Path.Combine(_testRoot, fileName);

        var category = FileImmutabilityClassifier.Classify(fullPath);
        Assert.Equal(ImmutabilityCategory.StaticImmutable, category);

        Assert.True(FileImmutabilityClassifier.IsStaticAsset(fullPath));
        Assert.False(FileImmutabilityClassifier.IsMutableWorkingDocument(fullPath));

        Assert.True(FileImmutabilityClassifier.IsSafeForNtfsHardLink(fullPath));
    }

    [Theory]
    [InlineData("file.unknownext")]
    [InlineData("file.random123")]
    [InlineData("noextensionfile")]
    public void FileImmutabilityClassifier_AmbiguousFiles_AreDefensivelyRejected(string fileName)
    {
        string fullPath = Path.Combine(_testRoot, fileName);

        var category = FileImmutabilityClassifier.Classify(fullPath);
        Assert.Equal(ImmutabilityCategory.Ambiguous, category);

        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(fullPath));
    }

    [Fact]
    public void FileImmutabilityClassifier_ProtectedDirectories_AreRejectedEvenWithStaticExtension()
    {
        string gitPath = Path.Combine(_testRoot, ".git", "objects", "pack.bin");
        string vsPath = Path.Combine(_testRoot, ".vs", "config", "cache.dll");
        string nodeModulesPath = Path.Combine(_testRoot, "node_modules", "pkg", "native.node");

        Assert.True(FileImmutabilityClassifier.IsInProtectedPath(gitPath));
        Assert.True(FileImmutabilityClassifier.IsInProtectedPath(vsPath));
        Assert.True(FileImmutabilityClassifier.IsInProtectedPath(nodeModulesPath));

        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(gitPath));
        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(vsPath));
        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(nodeModulesPath));
    }

    [Fact]
    public void FileImmutabilityClassifier_FileAgeGuardrail_RejectsRecentlyModifiedFiles()
    {
        string staticFile = Path.Combine(_testRoot, "test_age.bin");
        File.WriteAllBytes(staticFile, new byte[1024]);

        // File modified right now -> within minAge of 7 days -> rejected
        Assert.False(FileImmutabilityClassifier.IsSafeForNtfsHardLink(staticFile, minAge: TimeSpan.FromDays(7)));

        // Set LastWriteTime to 14 days ago -> older than 7 days -> accepted
        File.SetLastWriteTimeUtc(staticFile, DateTime.UtcNow.AddDays(-14));
        Assert.True(FileImmutabilityClassifier.IsSafeForNtfsHardLink(staticFile, minAge: TimeSpan.FromDays(7)));
    }

    #endregion

    #region 3. Native Storage Primitives & Hard Link Tests

    [Fact]
    public void StorageNative_CreateHardLinkAndGetHardLinkCount_MaintainsRealState()
    {
        string sourceFile = Path.Combine(_testRoot, "source_native.bin");
        string linkFile = Path.Combine(_testRoot, "link_native.bin");

        byte[] payload = new byte[8192];
        Random.Shared.NextBytes(payload);
        File.WriteAllBytes(sourceFile, payload);

        // Initial link count must be 1
        uint initialLinks = StorageNative.GetHardLinkCount(sourceFile);
        Assert.Equal(1u, initialLinks);

        // Create hard link
        StorageNative.CreateHardLink(linkFile, sourceFile);

        // Both directory entries now reference the same MFT record -> link count must be 2
        uint sourceLinks = StorageNative.GetHardLinkCount(sourceFile);
        uint targetLinks = StorageNative.GetHardLinkCount(linkFile);

        Assert.Equal(2u, sourceLinks);
        Assert.Equal(2u, targetLinks);

        // File content must match exactly
        byte[] readBack = File.ReadAllBytes(linkFile);
        Assert.Equal(payload, readBack);

        // Inspect file indices: both files must have identical file index and volume serial number
        var infoSource = StorageNative.GetFileInformation(sourceFile);
        var infoLink = StorageNative.GetFileInformation(linkFile);

        Assert.Equal(infoSource.dwVolumeSerialNumber, infoLink.dwVolumeSerialNumber);
        Assert.Equal(infoSource.FileIndex, infoLink.FileIndex);
    }

    [Fact]
    public void StorageNative_MoveFileEx_AtomicallyReplacesExistingFile()
    {
        string originalFile = Path.Combine(_testRoot, "original.dat");
        string newFile = Path.Combine(_testRoot, "new.dat");

        File.WriteAllText(originalFile, "Original Content 1.0");
        File.WriteAllText(newFile, "New Updated Content 2.0");

        StorageNative.MoveFileEx(
            newFile,
            originalFile,
            StorageNative.MOVEFILE_REPLACE_EXISTING | StorageNative.MOVEFILE_WRITE_THROUGH);

        Assert.False(File.Exists(newFile));
        Assert.True(File.Exists(originalFile));
        Assert.Equal("New Updated Content 2.0", File.ReadAllText(originalFile));
    }

    [Fact]
    public void StorageNative_GetFinalPathName_ReturnsValidGuidFormat()
    {
        string finalPath = StorageNative.GetFinalPathName(
            _testRoot,
            StorageNative.VOLUME_NAME_GUID | StorageNative.FILE_NAME_NORMALIZED);

        Assert.NotNull(finalPath);
        Assert.StartsWith(@"\\?\Volume{", finalPath, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region 4. VolumeAwareDeduplicator (NTFS Hard Link & Safety Protection) Tests

    [Fact]
    public async Task VolumeAwareDeduplicator_ConsolidatesStaticAssetsOnSameVolume()
    {
        string dedupDir = Path.Combine(_testRoot, "DedupStaticDir");
        Directory.CreateDirectory(dedupDir);

        // Create 3 identical binary files of 64 KB each
        byte[] payload = new byte[65536];
        Random.Shared.NextBytes(payload);

        string file1 = Path.Combine(dedupDir, "asset1.bin");
        string file2 = Path.Combine(dedupDir, "asset2.bin");
        string file3 = Path.Combine(dedupDir, "asset3.bin");

        File.WriteAllBytes(file1, payload);
        File.WriteAllBytes(file2, payload);
        File.WriteAllBytes(file3, payload);

        // Pre-dedup link count is 1 for all files
        Assert.Equal(1u, StorageNative.GetHardLinkCount(file1));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(file2));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(file3));

        var deduplicator = VolumeAwareDeduplicator.Instance;
        var progressList = new List<DedupProgress>();
        var progress = new Progress<DedupProgress>(p => progressList.Add(p));

        var result = await deduplicator.DeduplicateDirectoryAsync(
            dedupDir,
            new DedupOptions { MinFileSizeBytes = 1024 },
            progress);

        Assert.Equal(3, result.TotalFilesScanned);
        Assert.Equal(1, result.DuplicateClustersFound);
        Assert.Equal(2, result.DuplicatesConsolidated);
        Assert.Equal(131072L, result.TotalBytesReclaimed); // 2 * 64 KB reclaimed
        Assert.Empty(result.Errors);

        // After consolidation, all 3 files share the same MFT record -> link count must be 3!
        Assert.Equal(3u, StorageNative.GetHardLinkCount(file1));
        Assert.Equal(3u, StorageNative.GetHardLinkCount(file2));
        Assert.Equal(3u, StorageNative.GetHardLinkCount(file3));

        // Content verification: 0 data corruption
        Assert.Equal(payload, File.ReadAllBytes(file1));
        Assert.Equal(payload, File.ReadAllBytes(file2));
        Assert.Equal(payload, File.ReadAllBytes(file3));
    }

    [Fact]
    public async Task VolumeAwareDeduplicator_PreservesMutableWorkingDocumentsFromHardLinking()
    {
        string docDir = Path.Combine(_testRoot, "MutableDocsDir");
        Directory.CreateDirectory(docDir);

        byte[] codePayload = Encoding.UTF8.GetBytes("public class StorageSecurityGuard { public int Token = 42; }");

        string doc1 = Path.Combine(docDir, "source1.cs");
        string doc2 = Path.Combine(docDir, "source2.cs");
        string sheet1 = Path.Combine(docDir, "data1.xlsx");
        string sheet2 = Path.Combine(docDir, "data2.xlsx");

        File.WriteAllBytes(doc1, codePayload);
        File.WriteAllBytes(doc2, codePayload);
        File.WriteAllBytes(sheet1, codePayload);
        File.WriteAllBytes(sheet2, codePayload);

        var deduplicator = VolumeAwareDeduplicator.Instance;
        var result = await deduplicator.DeduplicateDirectoryAsync(
            docDir,
            new DedupOptions { AllowMutableHardLinks = false });

        Assert.Equal(4, result.TotalFilesScanned);
        Assert.Equal(0, result.DuplicatesConsolidated);
        Assert.True(result.MutableFilesPreserved >= 2);
        Assert.Equal(0L, result.TotalBytesReclaimed);

        // Hard link count MUST remain 1 to guarantee multi-file write safety!
        Assert.Equal(1u, StorageNative.GetHardLinkCount(doc1));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(doc2));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(sheet1));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(sheet2));

        Assert.NotEmpty(result.Warnings);
        Assert.Contains(result.Warnings, w => w.Contains("Preserved mutable working document"));
    }

    [Fact]
    public async Task VolumeAwareDeduplicator_SkipsAlreadyConsolidatedHardLinks()
    {
        string dir = Path.Combine(_testRoot, "AlreadyLinkedDir");
        Directory.CreateDirectory(dir);

        string master = Path.Combine(dir, "master.dll");
        string linked = Path.Combine(dir, "linked.dll");

        byte[] data = new byte[4096];
        Random.Shared.NextBytes(data);
        File.WriteAllBytes(master, data);

        // Manually link first
        StorageNative.CreateHardLink(linked, master);
        Assert.Equal(2u, StorageNative.GetHardLinkCount(master));

        var deduplicator = VolumeAwareDeduplicator.Instance;
        var result = await deduplicator.DeduplicateDirectoryAsync(dir);

        Assert.Equal(2, result.TotalFilesScanned);
        Assert.Equal(0, result.DuplicatesConsolidated); // Already linked, no redundant consolidation
        Assert.Equal(0L, result.TotalBytesReclaimed);
        Assert.Contains(result.Items, i => i.Method == DedupMethod.SkippedIdenticalLink);
    }

    [Fact]
    public async Task VolumeAwareDeduplicator_DryRun_ReportsPotentialSavingsWithoutMutatingDisk()
    {
        string dir = Path.Combine(_testRoot, "DryRunDir");
        Directory.CreateDirectory(dir);

        byte[] data = new byte[16384];
        Random.Shared.NextBytes(data);

        string f1 = Path.Combine(dir, "dry1.pak");
        string f2 = Path.Combine(dir, "dry2.pak");
        File.WriteAllBytes(f1, data);
        File.WriteAllBytes(f2, data);

        var deduplicator = VolumeAwareDeduplicator.Instance;
        var result = await deduplicator.DeduplicateDirectoryAsync(
            dir,
            new DedupOptions { DryRun = true });

        Assert.Equal(1, result.DuplicatesConsolidated);
        Assert.Equal(16384L, result.TotalBytesReclaimed);

        // Physical link count MUST remain 1 since it was a dry run!
        Assert.Equal(1u, StorageNative.GetHardLinkCount(f1));
        Assert.Equal(1u, StorageNative.GetHardLinkCount(f2));
    }

    [Fact]
    public async Task VolumeAwareDeduplicator_HonorsCancellationToken()
    {
        string dir = Path.Combine(_testRoot, "CancelDir");
        Directory.CreateDirectory(dir);

        for (int i = 0; i < 10; i++)
        {
            File.WriteAllBytes(Path.Combine(dir, $"file_{i}.bin"), new byte[1024]);
        }

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancel

        var deduplicator = VolumeAwareDeduplicator.Instance;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await deduplicator.DeduplicateDirectoryAsync(dir, ct: cts.Token);
        });
    }

    #endregion

    #region 5. ReFS Block Cloning Capability & IOCTL Contract Tests

    [Fact]
    public void ReFS_CapabilityCheck_AccuratelyEvaluatesBlockRefcountingFlag()
    {
        var volInfo = VolumeResolver.GetVolumeInfo(_testRoot);

        bool expected = (volInfo.FileSystemFlags & StorageNative.FILE_SUPPORTS_BLOCK_REFCOUNTING) != 0;
        Assert.Equal(expected, volInfo.SupportsBlockCloning);

        // On NTFS, SupportsBlockCloning should be false
        if (volInfo.FileSystemName.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
        {
            Assert.False(volInfo.SupportsBlockCloning);
        }
        else if (volInfo.FileSystemName.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
        {
            Assert.True(volInfo.SupportsBlockCloning);
        }
    }

    [Fact]
    public void ReFS_AlignmentCalculations_CorrectlyPartitionExtentsAndTailBuffer()
    {
        uint clusterSize = 4096;
        long totalLength = 100_000;

        long alignedBytes = (totalLength / clusterSize) * clusterSize;
        long tailBytes = totalLength - alignedBytes;

        Assert.Equal(98304L, alignedBytes);
        Assert.Equal(1696L, tailBytes);
        Assert.Equal(totalLength, alignedBytes + tailBytes);
        Assert.Equal(0L, alignedBytes % clusterSize);
    }

    [Fact]
    public void ReFS_TryDuplicateExtents_SafelyFailsOnNonRefsVolumeWithoutCrashing()
    {
        var volInfo = VolumeResolver.GetVolumeInfo(_testRoot);

        string src = Path.Combine(_testRoot, "refs_src.bin");
        string dst = Path.Combine(_testRoot, "refs_dst.bin");
        File.WriteAllBytes(src, new byte[8192]);
        File.WriteAllBytes(dst, new byte[8192]);

        using var srcHandle = StorageNative.OpenHandle(src, StorageNative.GENERIC_READ);
        using var dstHandle = StorageNative.OpenHandle(dst, StorageNative.GENERIC_WRITE);

        bool success = StorageNative.TryDuplicateExtents(srcHandle, dstHandle, 0, 0, 4096, out int errorCode);

        if (!volInfo.SupportsBlockCloning)
        {
            // On NTFS, calling FSCTL_DUPLICATE_EXTENTS_TO_FILE returns false with non-zero error code
            Assert.False(success);
            Assert.True(errorCode != 0);
            // Typically ERROR_INVALID_FUNCTION (1) or ERROR_NOT_SUPPORTED (50)
            Assert.True(errorCode is StorageNative.ERROR_INVALID_FUNCTION or StorageNative.ERROR_NOT_SUPPORTED or StorageNative.ERROR_INVALID_PARAMETER);
        }
        else
        {
            Assert.True(success);
            Assert.Equal(0, errorCode);
        }
    }

    #endregion

    #region 6. Cross-Volume Duplicate Fallback to .lfc Container Tests

    [Fact]
    public async Task VolumeAwareDeduplicator_CrossVolumeDuplicate_FallsBackToLfcContainer()
    {
        // Check if distinct volumes C:\ and D:\ are available on this machine
        string? driveC = Directory.Exists(@"C:\") ? @"C:\" : null;
        string? driveD = Directory.Exists(@"D:\") ? @"D:\" : null;

        if (driveC != null && driveD != null && !VolumeResolver.AreOnSameVolume(driveC, driveD))
        {
            string dirC = Path.Combine(Path.GetTempPath(), $"crossvol_test_c_{Guid.NewGuid():N}");
            string dirD = Path.Combine(@"D:\", $"crossvol_test_d_{Guid.NewGuid():N}");

            try
            {
                Directory.CreateDirectory(dirC);
                Directory.CreateDirectory(dirD);

                // Create identical 32 KB payload
                byte[] payload = new byte[32768];
                Random.Shared.NextBytes(payload);

                string fileOnC = Path.Combine(dirC, "duplicate_payload.dat");
                string fileOnD = Path.Combine(dirD, "duplicate_payload.dat");

                File.WriteAllBytes(fileOnC, payload);
                File.WriteAllBytes(fileOnD, payload);

                // Confirm they are on different volumes
                Assert.False(VolumeResolver.AreOnSameVolume(fileOnC, fileOnD));

                string containerPath = Path.Combine(dirC, "cross_volume_result.lfc");

                var deduplicator = VolumeAwareDeduplicator.Instance;
                var pairResult = await deduplicator.DeduplicatePairAsync(
                    fileOnC,
                    fileOnD,
                    new DedupOptions
                    {
                        EnableCrossVolumeLfcFallback = true,
                        CrossVolumeContainerPath = containerPath
                    });

                Assert.Equal(DedupMethod.CrossVolumeLfc, pairResult.Method);
                Assert.True(pairResult.Success);
                Assert.Equal(32768L, pairResult.BytesReclaimed);

                // Verify the sovereign .lfc container was generated
                Assert.True(File.Exists(containerPath));

                // Inspect the .lfc archive using LfcReader
                using var reader = new LfcReader();
                var archiveInfo = reader.InspectArchive(containerPath);

                Assert.NotNull(archiveInfo);
                Assert.Equal(2, archiveInfo.TotalFiles);
                Assert.True(archiveInfo.TotalRawBytes >= 65536L, "Raw size should account for both duplicate files");

                // In the .lfc container, FastCDC + BLAKE3 deduplicated the identical chunk payloads!
                Assert.True(archiveInfo.SpaceSavingsBytes > 0, "Deduplication must yield space savings in container");
            }
            finally
            {
                try { if (Directory.Exists(dirC)) Directory.Delete(dirC, recursive: true); } catch { }
                try { if (Directory.Exists(dirD)) Directory.Delete(dirD, recursive: true); } catch { }
            }
        }
    }

    #endregion
}
