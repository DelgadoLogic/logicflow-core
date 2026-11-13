// LogicFlow.Tests — WOF Compression Empirical Verification & Stress Test Suite
// Authored by M1 Challenger 1 for LogicFlow Native Win32/WOF Game Compression Engine

using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using LogicFlow.Native;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public class WofCompressionEmpiricalTests : IDisposable
{
    private readonly string _testDir;

    public WofCompressionEmpiricalTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "LogicFlow_Wof_Tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
            {
                // Unset any read-only attributes before deleting
                foreach (var file in Directory.GetFiles(_testDir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        WofNative.DecompressFile(file);
                    }
                    catch { }
                }
                Directory.Delete(_testDir, true);
            }
        }
        catch { }
    }

    private string CreateCompressibleSampleFile(string fileName, int targetSizeBytes)
    {
        string filePath = Path.Combine(_testDir, fileName);
        string textBlock = "LogicFlow Sovereign Game Optimization Engine DirectStorage Safe Transparent NTFS Compression DelgadoLogic 2026\r\n";
        byte[] blockBytes = Encoding.UTF8.GetBytes(textBlock);

        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            int written = 0;
            while (written < targetSizeBytes)
            {
                int toWrite = Math.Min(blockBytes.Length, targetSizeBytes - written);
                fs.Write(blockBytes, 0, toWrite);
                written += toWrite;
            }
        }

        return filePath;
    }

    private string CreateIncompressibleSampleFile(string fileName, int targetSizeBytes)
    {
        string filePath = Path.Combine(_testDir, fileName);
        byte[] randomBytes = new byte[targetSizeBytes];
        RandomNumberGenerator.Fill(randomBytes);
        File.WriteAllBytes(filePath, randomBytes);
        return filePath;
    }

    // ─── 1. STRUCTURE LAYOUT & MARSHALING CHECKS ───────────────────────────────

    [Fact]
    public void WofStructures_MemoryLayoutAndSizes_AreExact()
    {
        Assert.Equal(8, Marshal.SizeOf<WOF_EXTERNAL_INFO>());
        Assert.Equal(8, Marshal.SizeOf<WOF_FILE_COMPRESSION_INFO_V1>());
        Assert.Equal(12, Marshal.SizeOf<FILE_PROVIDER_EXTERNAL_INFO_V1>());
        Assert.Equal(20, Marshal.SizeOf<WOF_FILE_PROVIDER_EXTERNAL_INFO>());
    }

    [Fact]
    public void WofConstants_MatchKernelSpecification()
    {
        Assert.Equal(0u, WofNative.FILE_PROVIDER_COMPRESSION_XPRESS4K);
        Assert.Equal(1u, WofNative.FILE_PROVIDER_COMPRESSION_LZX);
        Assert.Equal(2u, WofNative.FILE_PROVIDER_COMPRESSION_XPRESS8K);
        Assert.Equal(3u, WofNative.FILE_PROVIDER_COMPRESSION_XPRESS16K);

        Assert.Equal(0u, WofNative.ALGORITHM_XPRESS4K);
        Assert.Equal(1u, WofNative.ALGORITHM_LZX);
        Assert.Equal(2u, WofNative.ALGORITHM_XPRESS8K);
        Assert.Equal(3u, WofNative.ALGORITHM_XPRESS16K);

        Assert.Equal(0x0009030Cu, WofNative.FSCTL_SET_EXTERNAL_BACKING);
        Assert.Equal(0x00090310u, WofNative.FSCTL_GET_EXTERNAL_BACKING);
        Assert.Equal(0x00090314u, WofNative.FSCTL_DELETE_EXTERNAL_BACKING);
        Assert.Equal(0x00090318u, WofNative.FSCTL_ENUM_EXTERNAL_BACKING);

        Assert.Equal(2u, WofNative.WOF_PROVIDER_FILE);
        Assert.Equal(1u, WofNative.WOF_CURRENT_VERSION);
    }

    // ─── 2. EMPIRICAL COMPRESSION ACROSS ALL 4 ALGORITHMS ───────────────────────

    [Theory]
    [InlineData(WofNative.ALGORITHM_XPRESS4K, "xpress4k")]
    [InlineData(WofNative.ALGORITHM_LZX, "lzx")]
    [InlineData(WofNative.ALGORITHM_XPRESS8K, "xpress8k")]
    [InlineData(WofNative.ALGORITHM_XPRESS16K, "xpress16k")]
    public void SetFileCompression_AllAlgorithms_SuccessfullyCompressesAndPreservesData(uint algorithm, string tag)
    {
        // 256 KB of repeating text
        int fileSizeBytes = 256 * 1024;
        string filePath = CreateCompressibleSampleFile($"sample_{tag}.dat", fileSizeBytes);
        byte[] originalHash = SHA256.HashData(File.ReadAllBytes(filePath));

        // Verify uncompressed initially
        Assert.False(WofNative.IsFileCompressed(filePath));

        // Compress file
        WofCompressionResult result = WofNative.SetFileCompression(filePath, algorithm);

        Assert.True(result.Success, $"Compression failed for {tag}: {result.ErrorMessage} (Code: {result.ErrorCode})");
        Assert.Equal(WofCompressionStatus.Success, result.Status);
        Assert.Equal(fileSizeBytes, result.OriginalSize);
        Assert.True(result.CompressedSize < result.OriginalSize, $"CompressedSize ({result.CompressedSize}) should be < OriginalSize ({result.OriginalSize})");
        Assert.True(result.SavedBytes > 0, "SavedBytes must be greater than 0");
        Assert.Equal(algorithm, result.Algorithm);
        Assert.False(result.NonBeneficial);

        // Verify IsFileCompressed reports true with exact algorithm and sizes
        bool isCompressed = WofNative.IsFileCompressed(filePath, out uint activeAlgo, out ulong origSize, out ulong compSize);
        Assert.True(isCompressed, "IsFileCompressed must return true");
        Assert.Equal(algorithm, activeAlgo);
        Assert.Equal((ulong)fileSizeBytes, origSize);
        Assert.Equal((ulong)result.CompressedSize, compSize);

        // Verify physical disk allocation via GetPhysicalFileSize
        long physicalSize = WofNative.GetPhysicalFileSize(filePath);
        Assert.Equal((long)compSize, physicalSize);

        // Verify transparent decompression on read (data integrity)
        byte[] readBackBytes = File.ReadAllBytes(filePath);
        Assert.Equal(fileSizeBytes, readBackBytes.Length);
        byte[] readBackHash = SHA256.HashData(readBackBytes);
        Assert.Equal(originalHash, readBackHash);

        // Decompress and verify restoration
        bool decompressResult = WofNative.DecompressFile(filePath);
        Assert.True(decompressResult, "DecompressFile must return true");

        // Verify file is no longer externally backed
        Assert.False(WofNative.IsFileCompressed(filePath), "File should no longer be compressed");
        long physicalAfterDecompress = WofNative.GetPhysicalFileSize(filePath);
        Assert.True(physicalAfterDecompress >= fileSizeBytes, $"Physical size ({physicalAfterDecompress}) after decompression should restore to full size ({fileSizeBytes})");

        // Verify data integrity again after decompression
        byte[] finalBytes = File.ReadAllBytes(filePath);
        Assert.Equal(originalHash, SHA256.HashData(finalBytes));
    }

    // ─── 3. ALGORITHM EFFICIENCY COMPARISON ─────────────────────────────────────

    [Fact]
    public void CompressionAlgorithms_CompareRatiosOnIdenticalData()
    {
        int size = 512 * 1024; // 512 KB
        string file4k = CreateCompressibleSampleFile("comp_4k.dat", size);
        string file8k = CreateCompressibleSampleFile("comp_8k.dat", size);
        string file16k = CreateCompressibleSampleFile("comp_16k.dat", size);
        string fileLzx = CreateCompressibleSampleFile("comp_lzx.dat", size);

        var res4k = WofNative.SetFileCompression(file4k, WofNative.ALGORITHM_XPRESS4K);
        var res8k = WofNative.SetFileCompression(file8k, WofNative.ALGORITHM_XPRESS8K);
        var res16k = WofNative.SetFileCompression(file16k, WofNative.ALGORITHM_XPRESS16K);
        var resLzx = WofNative.SetFileCompression(fileLzx, WofNative.ALGORITHM_LZX);

        Assert.True(res4k.Success);
        Assert.True(res8k.Success);
        Assert.True(res16k.Success);
        Assert.True(resLzx.Success);

        // All should achieve substantial savings (> 70% on repeating text)
        Assert.True(res4k.SpaceSavedPercent > 70.0, $"XPRESS4K savings ({res4k.SpaceSavedPercent}%) should be > 70%");
        Assert.True(res8k.SpaceSavedPercent > 70.0, $"XPRESS8K savings ({res8k.SpaceSavedPercent}%) should be > 70%");
        Assert.True(res16k.SpaceSavedPercent > 70.0, $"XPRESS16K savings ({res16k.SpaceSavedPercent}%) should be > 70%");
        Assert.True(resLzx.SpaceSavedPercent > 70.0, $"LZX savings ({resLzx.SpaceSavedPercent}%) should be > 70%");

        // LZX uses larger 32KB window and dictionary, should be <= XPRESS variants in compressed size
        Assert.True(resLzx.CompressedSize <= res4k.CompressedSize, "LZX should be at least as compact as XPRESS4K");
    }

    // ─── 4. RECOMPRESSION AND ALGORITHM SWITCHING ──────────────────────────────

    [Fact]
    public void SetFileCompression_AlreadyCompressedWithSameAlgo_ReportsAlreadyCompressed()
    {
        string filePath = CreateCompressibleSampleFile("recomp_same.dat", 128 * 1024);
        var first = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(first.Success);
        Assert.False(first.AlreadyCompressed);

        var second = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(second.Success);
        Assert.True(second.AlreadyCompressed);
        Assert.Equal(WofCompressionStatus.SkippedAlreadyCompressed, second.Status);
    }

    [Fact]
    public void SetFileCompression_SwitchAlgorithm_RecompressesSuccessfully()
    {
        string filePath = CreateCompressibleSampleFile("switch_algo.dat", 256 * 1024);
        var first = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_XPRESS4K);
        Assert.True(first.Success);
        Assert.True(WofNative.IsFileCompressed(filePath, out uint algo1, out ulong orig1, out ulong comp1));
        Assert.Equal(WofNative.ALGORITHM_XPRESS4K, algo1);

        // Switch to LZX
        var second = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(second.Success);
        Assert.True(WofNative.IsFileCompressed(filePath, out uint algo2, out ulong orig2, out ulong comp2));
        Assert.Equal(WofNative.ALGORITHM_LZX, algo2);
    }

    // ─── 5. DECOMPRESSION IDEMPOTENCE ──────────────────────────────────────────

    [Fact]
    public void DecompressFile_AlreadyUncompressed_ReturnsTrueIdempotently()
    {
        string filePath = CreateCompressibleSampleFile("already_uncompressed.dat", 64 * 1024);
        Assert.False(WofNative.IsFileCompressed(filePath));

        bool result = WofNative.DecompressFile(filePath);
        Assert.True(result);
        Assert.False(WofNative.IsFileCompressed(filePath));
    }

    [Fact]
    public void DecompressFile_MultipleSuccessiveCalls_RemainsConsistent()
    {
        string filePath = CreateCompressibleSampleFile("multi_decompress.dat", 128 * 1024);
        Assert.True(WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX).Success);
        Assert.True(WofNative.IsFileCompressed(filePath));

        Assert.True(WofNative.DecompressFile(filePath));
        Assert.False(WofNative.IsFileCompressed(filePath));

        Assert.True(WofNative.DecompressFile(filePath));
        Assert.False(WofNative.IsFileCompressed(filePath));
    }

    // ─── 6. NON-BENEFICIAL COMPRESSION & EDGE CASES ─────────────────────────────

    [Fact]
    public void SetFileCompression_ZeroByteFile_HandledGracefullyWithoutFailure()
    {
        string filePath = Path.Combine(_testDir, "zero_byte.dat");
        File.WriteAllBytes(filePath, Array.Empty<byte>());

        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(result.Success);
        Assert.Equal(0, result.OriginalSize);
        Assert.Equal(0, result.CompressedSize);
        Assert.Equal(0, result.SavedBytes);
    }

    [Fact]
    public void SetFileCompression_IncompressibleHighEntropyData_ReturnsNonBeneficialStatus()
    {
        // 64 KB of cryptographically random bytes cannot be compressed
        string filePath = CreateIncompressibleSampleFile("random_data.bin", 64 * 1024);

        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        // Should either detect non-beneficial or complete without throwing
        Assert.True(result.Success);
        Assert.True(result.NonBeneficial || result.SavedBytes <= 0, "High-entropy data should be flagged as non-beneficial or yield no savings");
    }

    [Fact]
    public void SetFileCompression_SmallFileBelowCluster_HandlesGracefully()
    {
        // 32 bytes (resident file in MFT)
        string filePath = Path.Combine(_testDir, "tiny.txt");
        File.WriteAllText(filePath, "Small resident text.");

        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(result.Success);
        // Should report non-beneficial since resident MFT records cannot/need not be WOF backed
        Assert.True(result.NonBeneficial || result.SavedBytes == 0);
    }

    [Fact]
    public void SetFileCompression_ReadOnlyFile_ClearsAttributeAndRestoresAfterCompression()
    {
        string filePath = CreateCompressibleSampleFile("readonly.dat", 128 * 1024);
        File.SetAttributes(filePath, FileAttributes.ReadOnly);

        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Compression should succeed on readonly file: {result.ErrorMessage}");
        Assert.True(WofNative.IsFileCompressed(filePath));

        // ReadOnly attribute must be restored
        var attrsAfterComp = File.GetAttributes(filePath);
        Assert.True((attrsAfterComp & FileAttributes.ReadOnly) != 0, "ReadOnly attribute must be restored after compression");

        // Decompression should also succeed and restore ReadOnly
        bool decompressed = WofNative.DecompressFile(filePath);
        Assert.True(decompressed, "Decompression should succeed on readonly file");
        Assert.False(WofNative.IsFileCompressed(filePath));

        var attrsAfterDecomp = File.GetAttributes(filePath);
        Assert.True((attrsAfterDecomp & FileAttributes.ReadOnly) != 0, "ReadOnly attribute must be restored after decompression");
    }

    // ─── 7. UNICODE PATHS & DIRECTORY HANDLING ─────────────────────────────────

    [Fact]
    public void SetFileCompression_UnicodeAndEmojiPath_CompressesAndPreservesIntegrity()
    {
        string filePath = CreateCompressibleSampleFile("游戏_compression_測試_🎮.dat", 128 * 1024);
        byte[] originalHash = SHA256.HashData(File.ReadAllBytes(filePath));

        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Failed to compress Unicode path: {result.ErrorMessage}");
        Assert.True(WofNative.IsFileCompressed(filePath));

        byte[] readHash = SHA256.HashData(File.ReadAllBytes(filePath));
        Assert.Equal(originalHash, readHash);

        Assert.True(WofNative.DecompressFile(filePath));
        Assert.False(WofNative.IsFileCompressed(filePath));
    }

    [Fact]
    public void SetFileCompression_DirectoryPath_ReturnsFileNotFound()
    {
        var result = WofNative.SetFileCompression(_testDir, WofNative.ALGORITHM_LZX);
        Assert.False(result.Success);
        Assert.Equal(WofCompressionNative.ERROR_FILE_NOT_FOUND, result.ErrorCode);
    }

    // ─── 8. INVALID PARAMETERS & ERROR PATHS ───────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void SetFileCompression_NullOrEmptyPath_ReturnsInvalidParameter(string? invalidPath)
    {
        var result = WofNative.SetFileCompression(invalidPath!, WofNative.ALGORITHM_LZX);
        Assert.False(result.Success);
        Assert.Equal(WofCompressionNative.ERROR_INVALID_PARAMETER, result.ErrorCode);
    }

    [Fact]
    public void SetFileCompression_NonExistentFile_ReturnsFileNotFound()
    {
        string nonExistent = Path.Combine(_testDir, "does_not_exist_" + Guid.NewGuid() + ".dat");
        var result = WofNative.SetFileCompression(nonExistent, WofNative.ALGORITHM_LZX);
        Assert.False(result.Success);
        Assert.Equal(WofCompressionNative.ERROR_FILE_NOT_FOUND, result.ErrorCode);
    }

    [Fact]
    public void SetFileCompression_InvalidAlgorithmId_ReturnsInvalidParameter()
    {
        string filePath = CreateCompressibleSampleFile("invalid_algo.dat", 64 * 1024);
        var result = WofNative.SetFileCompression(filePath, 99u);
        Assert.False(result.Success);
        Assert.Equal(WofCompressionNative.ERROR_INVALID_PARAMETER, result.ErrorCode);
    }

    [Fact]
    public void DecompressFile_NonExistentFile_ReturnsFalse()
    {
        string nonExistent = Path.Combine(_testDir, "missing_" + Guid.NewGuid() + ".dat");
        Assert.False(WofNative.DecompressFile(nonExistent));
    }

    [Fact]
    public void IsFileCompressed_NonExistentFile_ReturnsFalse()
    {
        string nonExistent = Path.Combine(_testDir, "missing_" + Guid.NewGuid() + ".dat");
        Assert.False(WofNative.IsFileCompressed(nonExistent));
    }

    [Fact]
    public void GetPhysicalFileSize_NonExistentFile_ReturnsZero()
    {
        string nonExistent = Path.Combine(_testDir, "missing_" + Guid.NewGuid() + ".dat");
        Assert.Equal(0, WofNative.GetPhysicalFileSize(nonExistent));
    }

    // ─── 9. LOCK RESILIENCE & SHARING VIOLATION ────────────────────────────────

    [Fact]
    public void SetFileCompression_ExclusiveLockedFile_ReturnsSkippedLockedGracefully()
    {
        string filePath = CreateCompressibleSampleFile("locked.dat", 128 * 1024);

        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
            Assert.False(result.Success);
            Assert.Equal(WofCompressionStatus.SkippedLocked, result.Status);
            Assert.Equal(WofCompressionNative.ERROR_SHARING_VIOLATION, result.ErrorCode);
        }
    }

    [Fact]
    public void SetFileCompression_FileSharedWithReadWrite_CompressesSuccessfully()
    {
        string filePath = CreateCompressibleSampleFile("shared_readwrite.dat", 128 * 1024);

        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
            Assert.True(result.Success, $"Compression failed on shared file: {result.ErrorMessage}");
            Assert.True(WofNative.IsFileCompressed(filePath));
        }
    }

    // ─── 10. MULTI-THREADED CONCURRENCY STRESS TEST ─────────────────────────────

    [Fact]
    public void SetFileCompression_MultiThreadedConcurrency_ExecutesWithoutRaceCondition()
    {
        int fileCount = 16;
        var files = new string[fileCount];
        for (int i = 0; i < fileCount; i++)
        {
            files[i] = CreateCompressibleSampleFile($"concur_{i}.dat", 128 * 1024);
        }

        uint[] algos = new[]
        {
            WofNative.ALGORITHM_XPRESS4K,
            WofNative.ALGORITHM_LZX,
            WofNative.ALGORITHM_XPRESS8K,
            WofNative.ALGORITHM_XPRESS16K
        };

        Parallel.For(0, fileCount, i =>
        {
            uint algo = algos[i % algos.Length];
            var result = WofNative.SetFileCompression(files[i], algo);
            Assert.True(result.Success, $"Concurrent compression failed for file {i}: {result.ErrorMessage}");
            Assert.True(WofNative.IsFileCompressed(files[i]));
        });

        // Parallel decompression
        Parallel.For(0, fileCount, i =>
        {
            Assert.True(WofNative.DecompressFile(files[i]));
            Assert.False(WofNative.IsFileCompressed(files[i]));
        });
    }

    // ─── 11. API PARITY (WofNative vs WofCompressionNative) ─────────────────────

    [Fact]
    public void WofNative_ForwardingParity_MatchesWofCompressionNative()
    {
        string filePath = CreateCompressibleSampleFile("parity.dat", 128 * 1024);

        var resNative = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(resNative.Success);

        bool isComp1 = WofCompressionNative.IsFileCompressed(filePath, out uint a1, out ulong o1, out ulong c1);
        bool isComp2 = WofNative.IsFileCompressed(filePath, out uint a2, out ulong o2, out ulong c2);

        Assert.Equal(isComp1, isComp2);
        Assert.Equal(a1, a2);
        Assert.Equal(o1, o2);
        Assert.Equal(c1, c2);

        Assert.True(WofNative.DecompressFile(filePath));
        Assert.False(WofCompressionNative.IsFileCompressed(filePath));
    }
}
