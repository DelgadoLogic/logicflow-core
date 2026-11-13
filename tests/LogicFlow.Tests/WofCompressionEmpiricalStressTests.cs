// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — WofCompressionEmpiricalStressTests.cs
// Empirical Challenger 2 Adversarial Stress Test Suite:
// Edge cases (ReadOnly, Locked, 0-byte, deep paths, Unicode), GetPhysicalFileSize accuracy,
// SHA256 content integrity before/during/after compression, rapid cycles, and algorithm checks.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WofEmpiricalTests")]
public class WofCompressionEmpiricalStressTests : IDisposable
{
    private readonly string _testScratchDir;

    public WofCompressionEmpiricalStressTests()
    {
        _testScratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_WofStress_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testScratchDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testScratchDir))
            {
                // Remove read-only attributes before deleting scratch directory
                foreach (var file in Directory.GetFiles(_testScratchDir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                    }
                    catch { }
                }
                Directory.Delete(_testScratchDir, true);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        byte[] hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    private string CreateSampleFile(string filename, int sizeBytes, string pattern = "LogicFlow Sovereign Game Compact Compression Engine ")
    {
        string filePath = Path.Combine(_testScratchDir, filename);
        byte[] patternBytes = Encoding.UTF8.GetBytes(pattern);
        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            int written = 0;
            while (written < sizeBytes)
            {
                int toWrite = Math.Min(patternBytes.Length, sizeBytes - written);
                fs.Write(patternBytes, 0, toWrite);
                written += toWrite;
            }
        }
        return filePath;
    }

    // ─── 1. Adversarial Edge Case: Read-Only Files ────────────────────────────

    [Fact]
    public void ReadOnlyFile_CompressAndDecompress_PreservesAttributesAndContentIntegrity()
    {
        string filePath = CreateSampleFile("readonly_sample.txt", 128 * 1024);
        string shaBefore = ComputeSha256(filePath);

        // Mark file as ReadOnly
        File.SetAttributes(filePath, FileAttributes.ReadOnly);
        Assert.True(File.GetAttributes(filePath).HasFlag(FileAttributes.ReadOnly));

        // Attempt compression on read-only file
        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Compression failed on read-only file: {result.ErrorMessage}");
        Assert.True(WofCompressionNative.IsFileCompressed(filePath), "File should report compressed after SetFileCompression.");

        // Verify ReadOnly attribute was restored
        var attrsAfterCompress = File.GetAttributes(filePath);
        Assert.True(attrsAfterCompress.HasFlag(FileAttributes.ReadOnly), "ReadOnly attribute must be preserved after compression.");

        // Verify content integrity while compressed
        string shaWhileCompressed = ComputeSha256(filePath);
        Assert.Equal(shaBefore, shaWhileCompressed);

        // Decompress read-only file
        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed, "DecompressFile must succeed on read-only file.");
        Assert.False(WofCompressionNative.IsFileCompressed(filePath), "File should not be compressed after decompress.");

        // Verify ReadOnly attribute was restored after decompression
        var attrsAfterDecompress = File.GetAttributes(filePath);
        Assert.True(attrsAfterDecompress.HasFlag(FileAttributes.ReadOnly), "ReadOnly attribute must be preserved after decompression.");

        // Verify content integrity after decompression
        string shaAfterDecompress = ComputeSha256(filePath);
        Assert.Equal(shaBefore, shaAfterDecompress);
    }

    // ─── 2. Adversarial Edge Case: 0-Byte Files ───────────────────────────────

    [Fact]
    public void ZeroByteFile_CompressionAndDecompression_HandledGracefullyWithoutError()
    {
        string filePath = Path.Combine(_testScratchDir, "empty_file.dat");
        File.WriteAllBytes(filePath, Array.Empty<byte>());
        Assert.Equal(0, new FileInfo(filePath).Length);

        // SetFileCompression on 0-byte file
        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success, "0-byte file compression should return successful/handled status.");
        Assert.Equal(0, result.OriginalSize);
        Assert.Equal(0, result.SavedBytes);

        // DecompressFile on 0-byte file
        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed, "DecompressFile on 0-byte file should return true.");
        Assert.Equal(0, new FileInfo(filePath).Length);
    }

    // ─── 3. Adversarial Edge Case: Locked / In-Use Files ─────────────────────

    [Fact]
    public void LockedFile_ExclusiveLock_HandledSafelyWithoutUnhandledExceptions()
    {
        string filePath = CreateSampleFile("locked_exclusive.dat", 64 * 1024);
        string shaOriginal = ComputeSha256(filePath);

        // Acquire exclusive lock on the file
        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
            Assert.False(result.Success, "Compression should report failure on exclusively locked file.");
            Assert.True(
                result.ErrorCode == WofCompressionNative.ERROR_SHARING_VIOLATION ||
                result.ErrorCode == WofCompressionNative.ERROR_LOCK_VIOLATION ||
                result.Status == WofCompressionStatus.SkippedLocked ||
                result.Status == WofCompressionStatus.Error,
                $"Expected sharing/lock violation, got ErrorCode={result.ErrorCode}, Status={result.Status}");

            // Decompression on locked file should also fail gracefully without throwing
            bool decompressResult = WofCompressionNative.DecompressFile(filePath);
            // Result may be false or true depending on IsFileCompressed check, but MUST NOT throw
            _ = decompressResult;
        }

        // Lock released: file must remain intact with identical content
        string shaAfterLock = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaAfterLock);
    }

    [Fact]
    public void LockedFile_ExclusiveLock_StrictContract_ShouldClassifyStatusAsSkippedLocked()
    {
        string filePath = CreateSampleFile("locked_strict.dat", 64 * 1024);

        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
            Assert.False(result.Success);
            Assert.Equal(WofCompressionNative.ERROR_SHARING_VIOLATION, result.ErrorCode);
            // Empirical challenge: Does WofCompressionNative classify locked file as SkippedLocked?
            // Currently FAILS because CreateFile failure at line 404 returns WofCompressionStatus.Error!
            Assert.Equal(WofCompressionStatus.SkippedLocked, result.Status);
        }
    }

    [Fact]
    public void AlreadyCompressed_SameAlgorithm_StrictContract_ShouldClassifyStatusAsSkippedAlreadyCompressed()
    {
        string filePath = CreateSampleFile("already_comp_strict.dat", 64 * 1024);

        var first = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(first.Success);

        // Re-compress with identical algorithm
        var second = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(second.Success);
        Assert.True(second.AlreadyCompressed);
        // Empirical challenge: Does WofCompressionNative classify already compressed file as SkippedAlreadyCompressed?
        // Currently FAILS because line 350 uses constructor that evaluates Status = Success!
        Assert.Equal(WofCompressionStatus.SkippedAlreadyCompressed, second.Status);
    }

    [Fact]
    public void LockedFile_SharedReadLock_HandledGracefullyWithoutCrashing()
    {
        string filePath = CreateSampleFile("locked_sharedread.dat", 64 * 1024);
        string shaOriginal = ComputeSha256(filePath);

        // File is open for Read with FileShare.Read (disallowing write access needed by CreateFile GENERIC_WRITE)
        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
            // It should either succeed via read fallback or gracefully fail with sharing violation, NEVER crash
            Assert.NotNull(result);
        }

        string shaAfter = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaAfter);
    }

    // ─── 4. Adversarial Edge Case: Non-Existent and Invalid Paths ────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("C:\\NonExistent_Dir_987654321\\fake_file_xyz.bin")]
    public void NonExistentOrInvalidPaths_ReturnFailureGracefully(string invalidPath)
    {
        var compressResult = WofCompressionNative.SetFileCompression(invalidPath);
        Assert.False(compressResult.Success);
        Assert.True(compressResult.ErrorCode != 0 || !string.IsNullOrEmpty(compressResult.ErrorMessage));

        bool isCompressed = WofCompressionNative.IsFileCompressed(invalidPath);
        Assert.False(isCompressed);

        bool decompressResult = WofCompressionNative.DecompressFile(invalidPath);
        Assert.False(decompressResult);

        long physicalSize = WofCompressionNative.GetPhysicalFileSize(invalidPath);
        Assert.Equal(0, physicalSize);
    }

    [Fact]
    public void UnsupportedAlgorithmId_ReturnsInvalidParameter()
    {
        string filePath = CreateSampleFile("unsupported_algo.dat", 32 * 1024);
        var result = WofCompressionNative.SetFileCompression(filePath, 999);
        Assert.False(result.Success);
        Assert.Equal(WofCompressionNative.ERROR_INVALID_PARAMETER, result.ErrorCode);
    }

    // ─── 5. Adversarial Edge Case: Unicode & Special Character Filenames ─────

    [Fact]
    public void UnicodeFilenames_CompressionDecompressionIntegrity_Preserved()
    {
        // Multi-script Unicode filename with spaces, emoji, and CJK characters
        string unicodeName = "测试文件_한국어_тест_café_🎮_game_pack.dat";
        string filePath = CreateSampleFile(unicodeName, 128 * 1024);
        string shaOriginal = ComputeSha256(filePath);

        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Unicode file compression failed: {result.ErrorMessage}");
        Assert.True(WofCompressionNative.IsFileCompressed(filePath));

        // Read while compressed
        string shaCompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaCompressed);

        // Decompress
        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed);
        Assert.False(WofCompressionNative.IsFileCompressed(filePath));

        // Verify final SHA256
        string shaDecompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaDecompressed);
    }

    // ─── 6. Adversarial Edge Case: Deep Directory Paths ───────────────────────

    [Fact]
    public void DeepDirectoryPath_CompressionAndDecompression_OperatesSafely()
    {
        string deepDir = _testScratchDir;
        for (int i = 0; i < 8; i++)
        {
            deepDir = Path.Combine(deepDir, $"subfolder_level_{i}");
        }
        Directory.CreateDirectory(deepDir);

        string filePath = Path.Combine(deepDir, "deep_asset.bin");
        byte[] patternBytes = Encoding.UTF8.GetBytes("Deep path test repetitive pattern 1234567890 ");
        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            for (int i = 0; i < 2000; i++)
                fs.Write(patternBytes, 0, patternBytes.Length);
        }

        string shaOriginal = ComputeSha256(filePath);

        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Deep path compression failed: {result.ErrorMessage}");
        Assert.True(WofCompressionNative.IsFileCompressed(filePath));

        string shaCompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaCompressed);

        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed);
        Assert.False(WofCompressionNative.IsFileCompressed(filePath));

        string shaDecompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaDecompressed);
    }

    // ─── 7. Physical Size Tracking Verification ──────────────────────────────

    [Fact]
    public void GetPhysicalFileSize_AccuratelyTracksUncompressedVsCompressedFootprint()
    {
        int fileSize = 512 * 1024; // 512 KB
        string filePath = CreateSampleFile("size_tracking.dat", fileSize);

        long uncompressedPhysical = WofCompressionNative.GetPhysicalFileSize(filePath);
        Assert.True(uncompressedPhysical >= fileSize,
            $"Uncompressed physical size ({uncompressedPhysical}) should be >= logical size ({fileSize}) due to cluster alignment.");

        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success);

        long compressedPhysical = WofCompressionNative.GetPhysicalFileSize(filePath);
        Assert.True(compressedPhysical < uncompressedPhysical,
            $"Compressed physical size ({compressedPhysical}) must be strictly less than uncompressed ({uncompressedPhysical}).");
        Assert.Equal(compressedPhysical, result.CompressedSize);
        Assert.True(result.SavedBytes > 0, "SavedBytes must be positive.");
        Assert.True(result.SpaceSavedPercent > 70.0, $"Expected > 70% space savings for repeating pattern, got {result.SpaceSavedPercent:F1}%.");

        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed);

        long rehydratedPhysical = WofCompressionNative.GetPhysicalFileSize(filePath);
        Assert.True(rehydratedPhysical >= fileSize,
            $"Rehydrated physical size ({rehydratedPhysical}) must return to full allocation (>= {fileSize}).");
    }

    // ─── 8. SHA256 Integrity: Before, During, and After Compression ───────────

    [Theory]
    [InlineData(64 * 1024, "JSON/Text payload")]
    [InlineData(256 * 1024, "Medium game data payload")]
    [InlineData(1024 * 1024, "1MB large texture data payload")]
    public void Sha256Integrity_StrictlyPreserved_BeforeDuringAndAfterCompression(int size, string label)
    {
        string filePath = CreateSampleFile($"integrity_{size}.dat", size, $"Payload [{label}] - Verified for zero corruption. ");
        string shaBefore = ComputeSha256(filePath);

        // Compress
        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
        Assert.True(result.Success, $"Compression failed: {result.ErrorMessage}");
        Assert.True(WofCompressionNative.IsFileCompressed(filePath));

        // Read while externally backed (tests transparent WOF kernel filter decompression)
        string shaWhileCompressed = ComputeSha256(filePath);
        Assert.Equal(shaBefore, shaWhileCompressed);

        // Decompress (tests FSCTL_DELETE_EXTERNAL_BACKING physical rehydration)
        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed, "DecompressFile failed.");
        Assert.False(WofCompressionNative.IsFileCompressed(filePath));

        // Read after physical rehydration
        string shaAfterDecompress = ComputeSha256(filePath);
        Assert.Equal(shaBefore, shaAfterDecompress);
    }

    // ─── 9. Rapid Repeated Compress / Decompress Stress Cycles ────────────────

    [Fact]
    public void RapidRepeatedCycles_30Iterations_MaintainsIntegrityAndStability()
    {
        string filePath = CreateSampleFile("rapid_cycles.dat", 128 * 1024);
        string shaInitial = ComputeSha256(filePath);

        const int iterations = 30;
        for (int i = 0; i < iterations; i++)
        {
            var compResult = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);
            Assert.True(compResult.Success, $"Iteration {i}: Compression failed ({compResult.ErrorMessage})");
            Assert.True(WofCompressionNative.IsFileCompressed(filePath), $"Iteration {i}: File not reported compressed.");

            bool decompResult = WofCompressionNative.DecompressFile(filePath);
            Assert.True(decompResult, $"Iteration {i}: Decompression failed.");
            Assert.False(WofCompressionNative.IsFileCompressed(filePath), $"Iteration {i}: File still reported compressed.");
        }

        string shaFinal = ComputeSha256(filePath);
        Assert.Equal(shaInitial, shaFinal);
    }

    // ─── 10. Algorithm Comparative Stress & Integrity ────────────────────────

    [Theory]
    [InlineData(WofCompressionNative.ALGORITHM_XPRESS4K, "XPRESS4K")]
    [InlineData(WofCompressionNative.ALGORITHM_LZX, "LZX")]
    [InlineData(WofCompressionNative.ALGORITHM_XPRESS8K, "XPRESS8K")]
    [InlineData(WofCompressionNative.ALGORITHM_XPRESS16K, "XPRESS16K")]
    public void AllSupportedAlgorithms_CompressAndDecompressCleanly(uint algo, string algoName)
    {
        string filePath = CreateSampleFile($"algo_{algoName}.dat", 128 * 1024);
        string shaOriginal = ComputeSha256(filePath);

        var result = WofCompressionNative.SetFileCompression(filePath, algo);
        Assert.True(result.Success, $"Algorithm {algoName} ({algo}) failed: {result.ErrorMessage}");
        Assert.Equal(algo, result.Algorithm);

        bool isComp = WofCompressionNative.IsFileCompressed(filePath, out uint detectedAlgo, out ulong origSize, out ulong compSize);
        Assert.True(isComp);
        Assert.Equal(algo, detectedAlgo);
        Assert.Equal((ulong)128 * 1024, origSize);
        Assert.True(compSize < origSize, "Physical size should be reduced.");

        string shaCompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaCompressed);

        bool decompressed = WofCompressionNative.DecompressFile(filePath);
        Assert.True(decompressed);
        Assert.False(WofCompressionNative.IsFileCompressed(filePath));

        string shaDecompressed = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaDecompressed);
    }

    // ─── 11. High Entropy / Incompressible Data Resilience ───────────────────

    [Fact]
    public void HighEntropyIncompressibleFile_HandledGracefullyWithoutCorruption()
    {
        string filePath = Path.Combine(_testScratchDir, "high_entropy.bin");
        byte[] randomData = new byte[64 * 1024];
        RandomNumberGenerator.Fill(randomData);
        File.WriteAllBytes(filePath, randomData);

        string shaOriginal = ComputeSha256(filePath);

        // Attempting to compress high-entropy random data may return non-beneficial (0x80070158)
        var result = WofCompressionNative.SetFileCompression(filePath, WofCompressionNative.ALGORITHM_LZX);

        // Must complete safely: either marked NonBeneficial or Success, never throw or corrupt
        Assert.NotNull(result);

        string shaAfter = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaAfter);
    }

    // ─── 12. WofNative Contract Equivalence ──────────────────────────────────

    [Fact]
    public void WofNativeAlias_ProvidesIdenticalContractAndBehavior()
    {
        string filePath = CreateSampleFile("wofnative_contract.dat", 128 * 1024);
        string shaOriginal = ComputeSha256(filePath);

        // Use WofNative wrapper
        var result = WofNative.SetFileCompression(filePath, WofNative.ALGORITHM_LZX);
        Assert.True(result.Success);
        Assert.True(WofNative.IsFileCompressed(filePath));

        long physical = WofNative.GetPhysicalFileSize(filePath);
        Assert.True(physical < 128 * 1024);

        bool decompressed = WofNative.DecompressFile(filePath);
        Assert.True(decompressed);
        Assert.False(WofNative.IsFileCompressed(filePath));

        string shaAfter = ComputeSha256(filePath);
        Assert.Equal(shaOriginal, shaAfter);
    }
}
