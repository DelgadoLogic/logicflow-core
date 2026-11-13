// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests.Storage – HyperStoreStressVerificationTests
// Adversarial Empirical Challenge Suite 2 for Milestone 1 (Stress Verifier):
//   1. Verify dual-tier Zstandard and MinHash delta compression achieve >5x space reduction.
//   2. Adversarially challenge .lfc container parsing (corrupt headers, bit-flipped CRC32C,
//      truncated payloads, invalid manifest magic, file lock release, path traversal).
//   3. Verify full round-trip bit-exact file reconstruction on complex directory structures.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Storage.Engine.Chunking;
using LogicFlow.Storage.Engine.Clustering;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;
using Xunit;
using Xunit.Abstractions;

namespace LogicFlow.Tests.Storage;

public sealed class HyperStoreStressVerificationTests
{
    private readonly ITestOutputHelper _output;

    public HyperStoreStressVerificationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region 1. Space Reduction & Compression Ratio Verification (>5x)

    [Fact]
    public async Task DualTier_SpaceReduction_ExceedsFiveTimes_OnStructuredCollections()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_Stress_Comp_" + Guid.NewGuid().ToString("N"));
        string sourceDir = Path.Combine(tempRoot, "Source");
        string lfcFile = Path.Combine(tempRoot, "archive.lfc");

        try
        {
            Directory.CreateDirectory(sourceDir);

            // Generate 20 structured revision files mimicking version-controlled documents / logs
            // with high similarity across revisions (~90-95% common schema/content)
            const int fileCount = 20;
            long totalRawBytes = 0;

            string baseTemplate = @"{{
  ""eventId"": ""EVT-{0}-{1}"",
  ""service"": ""LogicFlow.HyperStore.Telemetry"",
  ""timestamp"": ""2026-09-30T01:30:00.{1:D3}Z"",
  ""severity"": ""Information"",
  ""message"": ""Sovereign storage chunk optimization pass completed successfully."",
  ""payload"": {{
    ""clusterId"": ""US-EAST-WIN11-001"",
    ""chunkCount"": {1},
    ""hashAlgorithm"": ""BLAKE3-256-SIMD"",
    ""dedupRatio"": 4.82,
    ""activePolicy"": ""Standard_HotCold_Balancing"",
    ""metrics"": [
      {{ ""name"": ""cpu_usage_pct"", ""value"": 12.4 }},
      {{ ""name"": ""ram_rss_mb"", ""value"": 84.2 }},
      {{ ""name"": ""io_read_mbs"", ""value"": 2100.5 }}
    ],
    ""metadata"": ""DELGADOLOGIC_PROPRIETARY_V_DENSE_STORAGE_ENGINE_2026""
  }}
}}";

            for (int f = 0; f < fileCount; f++)
            {
                var sb = new StringBuilder();
                for (int r = 0; r < 60; r++)
                {
                    sb.AppendFormat(baseTemplate, f, r);
                    sb.AppendLine(",");
                }

                string filePath = Path.Combine(sourceDir, $"log_revision_{f:D2}.json");
                byte[] bytes = Encoding.UTF8.GetBytes(sb.ToString());
                await File.WriteAllBytesAsync(filePath, bytes);
                totalRawBytes += bytes.Length;
            }

            // Pack directory with delta compression and cold tier
            using var writer = new LfcWriter();
            var packOptions = new LfcPackOptions
            {
                Tier = CompressionTier.Cold,
                EnableDeltaCompression = true,
                TrainDictionary = true
            };

            await writer.PackDirectoryAsync(sourceDir, lfcFile, packOptions, null, CancellationToken.None);

            Assert.True(File.Exists(lfcFile));
            long archiveSize = new FileInfo(lfcFile).Length;

            using var reader = new LfcReader();
            var info = reader.InspectArchive(lfcFile);

            double reductionRatio = (double)totalRawBytes / archiveSize;
            _output.WriteLine($"=== Compression Ratio Stress Test ===");
            _output.WriteLine($"Total Raw Bytes:       {totalRawBytes:N0} bytes ({totalRawBytes / 1024.0:F2} KB)");
            _output.WriteLine($"Archive Size (.lfc):   {archiveSize:N0} bytes ({archiveSize / 1024.0:F2} KB)");
            _output.WriteLine($"Reported Compressed:   {info.TotalCompressedBytes:N0} bytes");
            _output.WriteLine($"Reduction Ratio:       {reductionRatio:F2}x (Requirement: > 5.0x)");

            // Requirement R1 / Acceptance Criteria: Similar file collections achieve >5x space reduction
            Assert.True(reductionRatio >= 5.0,
                $"Achieved reduction ratio was {reductionRatio:F2}x, which is below the required 5.0x threshold!");
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task DualTier_IncompressibleData_DoesNotCatastrophicallyInflate()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_Stress_Incomp_" + Guid.NewGuid().ToString("N"));
        string sourceDir = Path.Combine(tempRoot, "Source");
        string lfcFile = Path.Combine(tempRoot, "archive.lfc");

        try
        {
            Directory.CreateDirectory(sourceDir);

            // Generate 256 KB of pure cryptographic random bytes (incompressible)
            byte[] randomBytes = new byte[256 * 1024];
            Random.Shared.NextBytes(randomBytes);

            await File.WriteAllBytesAsync(Path.Combine(sourceDir, "random.bin"), randomBytes);

            using var writer = new LfcWriter();
            await writer.PackDirectoryAsync(sourceDir, lfcFile, LfcPackOptions.Default, null, CancellationToken.None);

            long archiveSize = new FileInfo(lfcFile).Length;
            _output.WriteLine($"Incompressible Data: Raw={randomBytes.Length} bytes, Archive={archiveSize} bytes");

            // Container overhead (Header, Footer, CDT, Manifest) should not inflate file by more than 10%
            double inflation = (double)archiveSize / randomBytes.Length;
            Assert.True(inflation < 1.10, $"Incompressible archive inflated excessively: {inflation:F2}x");
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    #endregion

    #region 2. Adversarial .lfc Container Parsing Resilience

    [Fact]
    public void Adversarial_InspectArchive_EmptyOrSubMinimumSize_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            using var reader = new LfcReader();

            // 0-byte file
            File.WriteAllBytes(tempFile, []);
            Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));

            // 63-byte file (less than header size)
            File.WriteAllBytes(tempFile, new byte[63]);
            Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));

            // 127-byte file (less than header + footer size = 128 bytes)
            File.WriteAllBytes(tempFile, new byte[127]);
            Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_CorruptedHeaderMagic_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] archive = CreateValidMinimalArchiveBytes();

            // Corrupt header magic (offset 0..3)
            archive[0] = 0xDE;
            archive[1] = 0xAD;
            archive[2] = 0xBE;
            archive[3] = 0xEF;

            File.WriteAllBytes(tempFile, archive);

            using var reader = new LfcReader();
            var ex = Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
            Assert.Contains("Header", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_BitFlippedHeaderCrc32c_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] archive = CreateValidMinimalArchiveBytes();

            // Flip 1 bit in header payload (e.g. at offset 10) without updating CRC
            archive[10] ^= 0x01;

            File.WriteAllBytes(tempFile, archive);

            using var reader = new LfcReader();
            var ex = Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
            Assert.Contains("Header", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_CorruptedFooterMagic_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] archive = CreateValidMinimalArchiveBytes();

            // Footer is located at EOF - 64 bytes
            int footerOffset = archive.Length - 64;
            archive[footerOffset] = 0x00;
            archive[footerOffset + 1] = 0x00;
            archive[footerOffset + 2] = 0x00;
            archive[footerOffset + 3] = 0x00;

            File.WriteAllBytes(tempFile, archive);

            using var reader = new LfcReader();
            var ex = Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
            Assert.Contains("Footer", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_BitFlippedFooterCrc32c_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] archive = CreateValidMinimalArchiveBytes();

            // Flip 1 bit in footer payload
            int footerOffset = archive.Length - 64;
            archive[footerOffset + 8] ^= 0x01;

            File.WriteAllBytes(tempFile, archive);

            using var reader = new LfcReader();
            var ex = Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
            Assert.Contains("Footer", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_CorruptedManifestMagic_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] archive = CreateValidMinimalArchiveBytes();

            // Locate manifest offset from footer
            int footerOffset = archive.Length - 64;
            var footerSpan = archive.AsSpan(footerOffset, 64);
            var footer = MemoryMarshal.Read<LfcFooter>(footerSpan);

            int manifestOffset = (int)footer.ManifestOffset;
            // Corrupt manifest magic ('LCSM' = 0x4D46534C)
            archive[manifestOffset] = 0x00;
            archive[manifestOffset + 1] = 0x00;
            archive[manifestOffset + 2] = 0x00;
            archive[manifestOffset + 3] = 0x00;

            File.WriteAllBytes(tempFile, archive);

            using var reader = new LfcReader();
            var ex = Assert.Throws<InvalidDataException>(() => reader.InspectArchive(tempFile));
            Assert.Contains("manifest", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Adversarial_InspectArchive_NonExistentFile_ThrowsFileNotFoundException()
    {
        using var reader = new LfcReader();
        string nonExistent = Path.Combine(Path.GetTempPath(), "non_existent_" + Guid.NewGuid().ToString("N") + ".lfc");
        Assert.Throws<FileNotFoundException>(() => reader.InspectArchive(nonExistent));
    }

    [Fact]
    public async Task Adversarial_UnpackArchive_TruncatedFile_ThrowsCleanExceptionWithoutHandleLeak()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_TruncTest_" + Guid.NewGuid().ToString("N"));
        string archivePath = Path.Combine(tempRoot, "truncated.lfc");
        string destDir = Path.Combine(tempRoot, "out");

        try
        {
            Directory.CreateDirectory(tempRoot);
            byte[] fullArchive = CreateValidMinimalArchiveBytes();

            // Truncate the archive in the middle (keep 75% of bytes)
            byte[] truncated = new byte[(int)(fullArchive.Length * 0.75)];
            Buffer.BlockCopy(fullArchive, 0, truncated, 0, truncated.Length);
            await File.WriteAllBytesAsync(archivePath, truncated);

            using var reader = new LfcReader();

            // Should throw clean exception (InvalidDataException or EndOfStreamException)
            await Assert.ThrowsAnyAsync<Exception>(() =>
                reader.UnpackArchiveAsync(archivePath, destDir));

            // CRITICAL TEST: Verify no file handle leak!
            // If the reader leaked fileStream, File.Delete or File.Open will throw IOException.
            using (var testStream = new FileStream(archivePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.True(testStream.CanWrite);
            }

            File.Delete(archivePath);
            Assert.False(File.Exists(archivePath));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task Adversarial_UnpackArchive_BitFlippedPayload_ThrowsIntegrityException()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_PayloadTamper_" + Guid.NewGuid().ToString("N"));
        string sourceDir = Path.Combine(tempRoot, "Source");
        string lfcFile = Path.Combine(tempRoot, "tampered.lfc");
        string destDir = Path.Combine(tempRoot, "Dest");

        try
        {
            Directory.CreateDirectory(sourceDir);
            string testFile = Path.Combine(sourceDir, "critical_binary.dat");
            byte[] data = new byte[32768];
            Random.Shared.NextBytes(data);
            await File.WriteAllBytesAsync(testFile, data);

            // Pack
            using var writer = new LfcWriter();
            await writer.PackDirectoryAsync(sourceDir, lfcFile, LfcPackOptions.Default);

            // Read archive bytes
            byte[] archiveBytes = await File.ReadAllBytesAsync(lfcFile);

            using var reader = new LfcReader();
            var info = reader.InspectArchive(lfcFile);
            ulong cdtOffset = info.Footer.ChunkTableOffset;

            // CDT is at cdtOffset. Payload is between Header (offset 64) and cdtOffset.
            // Let's tamper with the compressed payload bytes around offset 80
            Assert.True(cdtOffset > 80);
            archiveBytes[80] ^= 0xAA;

            // Note: Since we only modified the payload region (not header, footer, CDT, or manifest),
            // Header and Footer CRC32C checksums will STILL MATCH!
            await File.WriteAllBytesAsync(lfcFile, archiveBytes);

            // Unpack with VerifyHashes = true
            var unpackOptions = new LfcUnpackOptions
            {
                Overwrite = true,
                VerifyHashes = true
            };

            // Reader MUST detect corruption either via Zstandard decompression error or BLAKE3 Hash256 verification failure
            await Assert.ThrowsAnyAsync<Exception>(() =>
                reader.UnpackArchiveAsync(lfcFile, destDir, unpackOptions));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task Adversarial_PathTraversal_ZipSlipVulnerability_Assessment()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_ZipSlip_" + Guid.NewGuid().ToString("N"));
        string lfcFile = Path.Combine(tempRoot, "traversal.lfc");
        string destDir = Path.Combine(tempRoot, "Destination");
        string outsideEscapedFile = Path.Combine(tempRoot, "escaped_secret.txt");

        try
        {
            Directory.CreateDirectory(tempRoot);
            Directory.CreateDirectory(destDir);

            // Craft an archive with an adversarial relative path: "../escaped_secret.txt"
            byte[] payload = Encoding.UTF8.GetBytes("ESCAPED_DATA_PATH_TRAVERSAL_BREACH");
            CreateAdversarialPathArchive(lfcFile, "../escaped_secret.txt", payload);

            using var reader = new LfcReader();
            // Test unpack
            bool threwException = false;
            try
            {
                await reader.UnpackArchiveAsync(lfcFile, destDir);
            }
            catch (Exception ex)
            {
                threwException = true;
                _output.WriteLine($"[SECURITY] Unpack threw exception on path traversal: {ex.GetType().Name} - {ex.Message}");
            }

            _output.WriteLine($"[SECURITY] Did unpack throw exception? {threwException}");
            bool escapedFileExists = File.Exists(outsideEscapedFile);
            _output.WriteLine($"[SECURITY] Did '../escaped_secret.txt' write outside destDir? {escapedFileExists}");

            // Verify that ZipSlip is prevented: must throw exception and NOT write outside destDir
            Assert.True(threwException, "Expected UnpackArchiveAsync to throw InvalidDataException on path traversal attempt!");
            Assert.False(escapedFileExists, "Vulnerability defect: archive extracted file outside destinationDir!");
            _output.WriteLine("[SECURITY PASS] Path traversal was successfully blocked.");
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    #endregion

    #region 3. Complex Directory Structure Full Round-Trip Fidelity

    [Fact]
    public async Task FullRoundTrip_ComplexHierarchy_ZeroBytesLoss_BitExactVerification()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_DeepComplex_" + Guid.NewGuid().ToString("N"));
        string sourceDir = Path.Combine(tempRoot, "SourceTree");
        string lfcFile = Path.Combine(tempRoot, "complex_archive.lfc");
        string unpackDir = Path.Combine(tempRoot, "RestoredTree");

        try
        {
            Directory.CreateDirectory(sourceDir);

            // Create a 5-level deep directory structure
            string dirLevel1 = Path.Combine(sourceDir, "Level1");
            string dirLevel2 = Path.Combine(dirLevel1, "Level2_Data");
            string dirLevel3 = Path.Combine(dirLevel2, "Level3_SubModule");
            string dirLevel4 = Path.Combine(dirLevel3, "Level4_Internal");
            string dirLevel5 = Path.Combine(dirLevel4, "Level5_Deepest");
            Directory.CreateDirectory(dirLevel5);

            var expectedFiles = new Dictionary<string, byte[]>();

            // 1. Root level files
            await AddFileAsync(sourceDir, "empty_file.dat", []); // 0-byte file edge case
            await AddFileAsync(sourceDir, "small_text.txt", Encoding.UTF8.GetBytes("Small payload below 8 KB chunk threshold"));

            // 2. Medium file spanning exactly ~48 KB (crosses 32 KB nominal target, below 64 KB max)
            byte[] midData = new byte[48 * 1024];
            Random.Shared.NextBytes(midData);
            await AddFileAsync(dirLevel1, "medium_48k.bin", midData);

            // 3. Multi-chunk file (96 KB spanning 2-4 variable chunks, within 256 KB window)
            byte[] largeData = new byte[96 * 1024];
            Random.Shared.NextBytes(largeData);
            await AddFileAsync(dirLevel2, "large_blob.bin", largeData);

            // 4. Exact duplicate of file in Level 4 (tests cross-folder deduplication)
            await AddFileAsync(dirLevel4, "large_blob_duplicate.bin", (byte[])largeData.Clone());

            // 5. Near-duplicate of file in Level 5 (tests cross-folder MinHash delta compression)
            byte[] nearLargeData = (byte[])largeData.Clone();
            for (int i = 20000; i < 20200; i++)
            {
                nearLargeData[i] ^= 0x7E;
            }
            await AddFileAsync(dirLevel5, "large_blob_rev2.bin", nearLargeData);

            // 6. Structured XML and source files with unicode paths
            string xmlContent = @"<?xml version=""1.0"" encoding=""utf-8""?>
<StorageProfile xmlns=""http://delgadologic.com/hyperstore/v1"">
  <Engine name=""V-Dense"" version=""1.0.0"" simd=""AVX2;SSE4.2"" />
  <Thresholds minChunk=""8192"" targetChunk=""32768"" maxChunk=""65536"" />
</StorageProfile>";
            await AddFileAsync(dirLevel3, "config_profile.xml", Encoding.UTF8.GetBytes(xmlContent));

            // Pack directory
            using var writer = new LfcWriter();
            var packOptions = new LfcPackOptions
            {
                Tier = CompressionTier.Cold,
                EnableDeltaCompression = true,
                TrainDictionary = true
            };

            var progressReports = new List<HyperStoreProgressReport>();
            var progress = new Progress<HyperStoreProgressReport>(r => progressReports.Add(r));

            long packStart = Stopwatch.GetTimestamp();
            await writer.PackDirectoryAsync(sourceDir, lfcFile, packOptions, progress);
            long packEnd = Stopwatch.GetTimestamp();

            double packElapsedSec = (double)(packEnd - packStart) / Stopwatch.Frequency;
            _output.WriteLine($"Pack completed in {packElapsedSec * 1000:F2} ms");

            Assert.True(File.Exists(lfcFile));
            long lfcSizeBytes = new FileInfo(lfcFile).Length;
            _output.WriteLine($"Packed .lfc container size: {lfcSizeBytes:N0} bytes");

            // Inspect archive
            using var reader = new LfcReader();
            var info = reader.InspectArchive(lfcFile);

            Assert.Equal(expectedFiles.Count, (int)info.TotalFiles);
            Assert.Equal(expectedFiles.Count, info.Manifest!.Files.Count);
            Assert.True(info.TotalUniqueChunks > 0);

            // Unpack archive
            long unpackStart = Stopwatch.GetTimestamp();
            var unpackOptions = new LfcUnpackOptions
            {
                Overwrite = true,
                VerifyHashes = true
            };
            await reader.UnpackArchiveAsync(lfcFile, unpackDir, unpackOptions);
            long unpackEnd = Stopwatch.GetTimestamp();
            double unpackElapsedSec = (double)(unpackEnd - unpackStart) / Stopwatch.Frequency;
            _output.WriteLine($"Unpack completed in {unpackElapsedSec * 1000:F2} ms");

            // Verify bit-for-bit fidelity for ALL files
            string[] restoredFiles = Directory.GetFiles(unpackDir, "*", SearchOption.AllDirectories);
            Assert.Equal(expectedFiles.Count, restoredFiles.Length);

            foreach (var restoredPath in restoredFiles)
            {
                string relPath = Path.GetRelativePath(unpackDir, restoredPath);
                Assert.True(expectedFiles.TryGetValue(relPath, out byte[]? expectedBytes),
                    $"Unexpected restored file: {relPath}");

                byte[] actualBytes = await File.ReadAllBytesAsync(restoredPath);
                Assert.Equal(expectedBytes.Length, actualBytes.Length);
                Assert.Equal(expectedBytes, actualBytes);

                // Cryptographic validation (SHA-256 and BLAKE3)
                byte[] expectedSha = SHA256.HashData(expectedBytes);
                byte[] actualSha = SHA256.HashData(actualBytes);
                Assert.Equal(expectedSha, actualSha);

                Hash256 expectedB3 = Hash256.Compute(expectedBytes);
                Hash256 actualB3 = Hash256.Compute(actualBytes);
                Assert.Equal(expectedB3, actualB3);
            }

            _output.WriteLine($"Successfully verified {restoredFiles.Length}/{expectedFiles.Count} files with 100% bit-exact SHA-256 and BLAKE3 identity!");

            async Task AddFileAsync(string dir, string fileName, byte[] content)
            {
                string filePath = Path.Combine(dir, fileName);
                await File.WriteAllBytesAsync(filePath, content);
                string rel = Path.GetRelativePath(sourceDir, filePath);
                expectedFiles[rel] = content;
            }
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Theory]
    [InlineData(128 * 1024)] // 128 KB - fits in single sliding window
    [InlineData(300 * 1024)] // 300 KB - triggers sliding window refill without desync
    [InlineData(512 * 1024)] // 512 KB - triggers multiple sliding window refills
    [InlineData(1024 * 1024)] // 1 MB - multiple refills with full roundtrip fidelity
    public async Task LfcWriter_LargeFile_SlidingWindowRefill_BitExactRoundTrip(int fileSizeBytes)
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_DesyncRepro_" + Guid.NewGuid().ToString("N"));
        string sourceDir = Path.Combine(tempRoot, "Src");
        string destDir = Path.Combine(tempRoot, "Dst");
        string lfcFile = Path.Combine(tempRoot, "test.lfc");

        try
        {
            Directory.CreateDirectory(sourceDir);
            byte[] fileBytes = new byte[fileSizeBytes];
            // High-entropy random data to prevent trivial single-chunk runs
            Random.Shared.NextBytes(fileBytes);
            string srcFile = Path.Combine(sourceDir, "testfile.bin");
            await File.WriteAllBytesAsync(srcFile, fileBytes);

            using var writer = new LfcWriter();
            await writer.PackDirectoryAsync(sourceDir, lfcFile, LfcPackOptions.Default);

            using var reader = new LfcReader();
            var unpackOptions = new LfcUnpackOptions { Overwrite = true, VerifyHashes = true };

            await reader.UnpackArchiveAsync(lfcFile, destDir, unpackOptions);
            byte[] restored = await File.ReadAllBytesAsync(Path.Combine(destDir, "testfile.bin"));
            Assert.Equal(fileBytes, restored);

            Hash256 origHash = Hash256.Compute(fileBytes);
            Hash256 restHash = Hash256.Compute(restored);
            Assert.Equal(origHash, restHash);
            _output.WriteLine($"[PASS] Size {fileSizeBytes / 1024} KB roundtripped cleanly with bit-exact hash verification.");
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task Adversarial_DeltaChunk_SelfReferencingCycle_ThrowsInvalidDataException()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_CycleTest_" + Guid.NewGuid().ToString("N"));
        string lfcFile = Path.Combine(tempRoot, "cycle.lfc");
        string destDir = Path.Combine(tempRoot, "Destination");

        try
        {
            Directory.CreateDirectory(tempRoot);
            CreateAdversarialDeltaArchive(lfcFile, baseChunkIndex: 0); // Chunk 0 points to itself (cycle)

            using var reader = new LfcReader();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
                reader.UnpackArchiveAsync(lfcFile, destDir));

            _output.WriteLine($"[SECURITY PASS] Delta cycle threw: {ex.Message}");
            Assert.Contains("cycle", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task Adversarial_DeltaChunk_OutOfBoundsBaseIndex_ThrowsInvalidDataException()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "LF_OobBaseTest_" + Guid.NewGuid().ToString("N"));
        string lfcFile = Path.Combine(tempRoot, "oob_base.lfc");
        string destDir = Path.Combine(tempRoot, "Destination");

        try
        {
            Directory.CreateDirectory(tempRoot);
            CreateAdversarialDeltaArchive(lfcFile, baseChunkIndex: 99999); // Invalid base chunk index

            using var reader = new LfcReader();
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
                reader.UnpackArchiveAsync(lfcFile, destDir));

            _output.WriteLine($"[SECURITY PASS] OOB base chunk threw: {ex.Message}");
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task Adversarial_Header_ExcessiveCDTCount_ThrowsInvalidDataException()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            CreateArchiveWithExcessiveCDTCount(tempFile);

            using var reader = new LfcReader();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                reader.UnpackArchiveAsync(tempFile, Path.GetTempPath()));
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    private static void CreateArchiveWithExcessiveCDTCount(string filePath)
    {
        byte[] archive = CreateValidMinimalArchiveBytes();
        int footerOffset = archive.Length - 64;
        var footerSpan = archive.AsSpan(footerOffset, 64);
        var footer = MemoryMarshal.Read<LfcFooter>(footerSpan);

        // Corrupt footer chunk count to 2,000,000,000
        footer.TotalUniqueChunks = 2_000_000_000;
        footer.FinalizeChecksum();
        MemoryMarshal.Write(footerSpan, in footer);

        File.WriteAllBytes(filePath, archive);
    }

    #endregion

    #region Helper Methods

    private static byte[] CreateValidMinimalArchiveBytes()
    {
        using var ms = new MemoryStream();

        // 1. Header (64 bytes)
        ulong cdtOffset = 64;
        ulong manifestOffset = 64;

        var header = LfcHeader.CreateDefault();
        header.ChunkTableOffset = cdtOffset;
        header.ManifestOffset = manifestOffset;
        header.FinalizeChecksum();

        Span<byte> headerBytes = stackalloc byte[64];
        MemoryMarshal.Write(headerBytes, in header);
        ms.Write(headerBytes);

        // 2. Empty Manifest
        var manifest = new LfcStreamManifest { Files = [] };
        manifest.WriteTo(ms);
        ulong footerOffset = (ulong)ms.Position;

        // 3. Footer (64 bytes)
        var footer = LfcFooter.CreateDefault();
        footer.TotalFiles = 0;
        footer.TotalUniqueChunks = 0;
        footer.ChunkTableOffset = cdtOffset;
        footer.ManifestOffset = manifestOffset;
        footer.FinalizeChecksum();

        Span<byte> footerBytes = stackalloc byte[64];
        MemoryMarshal.Write(footerBytes, in footer);
        ms.Write(footerBytes);

        return ms.ToArray();
    }

    private static void CreateAdversarialPathArchive(string lfcFile, string adversarialPath, byte[] payload)
    {
        Hash256 payloadHash = Hash256.Compute(payload);

        using var fs = new FileStream(lfcFile, FileMode.Create, FileAccess.ReadWrite);

        // 1. Reserve Header (64 bytes)
        fs.Write(new byte[64]);

        // 2. Write 1 raw chunk
        ulong payloadOffset = (ulong)fs.Position;
        fs.Write(payload);

        // 3. Write CDT
        ulong cdtOffset = (ulong)fs.Position;
        var desc = new ChunkDescriptor(
            fingerprint: payloadHash,
            payloadOffset: payloadOffset,
            compressedSize: (uint)payload.Length,
            rawSize: (uint)payload.Length,
            flags: (ushort)ChunkFlags.None,
            baseChunkIndex: 0xFFFFFFFF,
            minHashFeature: 0);

        Span<byte> descSpan = stackalloc byte[ChunkDescriptor.SizeInBytes];
        MemoryMarshal.Write(descSpan, in desc);
        fs.Write(descSpan);

        // 4. Write Manifest with adversarial path
        ulong manifestOffset = (ulong)fs.Position;
        var manifest = new LfcStreamManifest();
        manifest.Files.Add(new LfcFileEntry
        {
            RelativePath = adversarialPath,
            FileAttributes = 0,
            CreationTimeUtc = DateTime.UtcNow.ToFileTimeUtc(),
            LastWriteTimeUtc = DateTime.UtcNow.ToFileTimeUtc(),
            FileRawSizeBytes = (ulong)payload.Length,
            FileHash = payloadHash,
            ChunkIndices = [0]
        });
        manifest.WriteTo(fs);

        // 5. Write Footer
        var footer = LfcFooter.CreateDefault();
        footer.TotalFiles = 1;
        footer.TotalUniqueChunks = 1;
        footer.TotalRawBytes = (ulong)payload.Length;
        footer.TotalCompressedBytes = (ulong)payload.Length;
        footer.ChunkTableOffset = cdtOffset;
        footer.ManifestOffset = manifestOffset;
        footer.FinalizeChecksum();

        Span<byte> footerSpan = stackalloc byte[64];
        MemoryMarshal.Write(footerSpan, in footer);
        fs.Write(footerSpan);

        // 6. Write Header
        fs.Position = 0;
        var header = LfcHeader.CreateDefault();
        header.ChunkTableOffset = cdtOffset;
        header.ChunkTableLength = 64;
        header.ManifestOffset = manifestOffset;
        header.ManifestLength = (uint)(footer.ChunkTableOffset - manifestOffset);
        header.FinalizeChecksum();

        Span<byte> headerSpan = stackalloc byte[64];
        MemoryMarshal.Write(headerSpan, in header);
        fs.Write(headerSpan);
    }

    private static void CreateAdversarialDeltaArchive(string lfcFile, uint baseChunkIndex)
    {
        byte[] payload = Encoding.UTF8.GetBytes("DELTA_RECURSION_TEST");
        Hash256 payloadHash = Hash256.Compute(payload);

        using var fs = new FileStream(lfcFile, FileMode.Create, FileAccess.ReadWrite);

        // 1. Reserve Header
        fs.Write(new byte[64]);

        // 2. Write payload
        ulong payloadOffset = (ulong)fs.Position;
        fs.Write(payload);

        // 3. Write CDT with delta flags pointing to baseChunkIndex
        ulong cdtOffset = (ulong)fs.Position;
        var desc = new ChunkDescriptor(
            fingerprint: payloadHash,
            payloadOffset: payloadOffset,
            compressedSize: (uint)payload.Length,
            rawSize: (uint)payload.Length,
            flags: (ushort)(ChunkFlags.IsCompressed | ChunkFlags.IsDelta),
            baseChunkIndex: baseChunkIndex,
            minHashFeature: 0);

        Span<byte> descSpan = stackalloc byte[ChunkDescriptor.SizeInBytes];
        MemoryMarshal.Write(descSpan, in desc);
        fs.Write(descSpan);

        // 4. Manifest
        ulong manifestOffset = (ulong)fs.Position;
        var manifest = new LfcStreamManifest();
        manifest.Files.Add(new LfcFileEntry
        {
            RelativePath = "cycle_test.bin",
            FileAttributes = 0,
            CreationTimeUtc = DateTime.UtcNow.ToFileTimeUtc(),
            LastWriteTimeUtc = DateTime.UtcNow.ToFileTimeUtc(),
            FileRawSizeBytes = (ulong)payload.Length,
            FileHash = payloadHash,
            ChunkIndices = [0]
        });
        manifest.WriteTo(fs);

        // 5. Footer
        var footer = LfcFooter.CreateDefault();
        footer.TotalFiles = 1;
        footer.TotalUniqueChunks = 1;
        footer.TotalRawBytes = (ulong)payload.Length;
        footer.TotalCompressedBytes = (ulong)payload.Length;
        footer.ChunkTableOffset = cdtOffset;
        footer.ManifestOffset = manifestOffset;
        footer.FinalizeChecksum();

        Span<byte> footerSpan = stackalloc byte[64];
        MemoryMarshal.Write(footerSpan, in footer);
        fs.Write(footerSpan);

        // 6. Header
        fs.Position = 0;
        var header = LfcHeader.CreateDefault();
        header.ChunkTableOffset = cdtOffset;
        header.ChunkTableLength = 64;
        header.ManifestOffset = manifestOffset;
        header.ManifestLength = (uint)(footer.ChunkTableOffset - manifestOffset);
        header.FinalizeChecksum();

        Span<byte> headerSpan = stackalloc byte[64];
        MemoryMarshal.Write(headerSpan, in header);
        fs.Write(headerSpan);
    }

    #endregion
}
