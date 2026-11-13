// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests.Storage – HyperStoreEmpiricalChallengerTests
// Adversarial Empirical Challenge Suite for Milestone 1:
//   1. FastCDC Gear Chunker throughput across random, zero-filled, and mixed payloads.
//   2. Boundary shift resilience and downstream resynchronization (even vs odd phase shift).
//   3. Hash256 BLAKE3 fingerprinting: zero truncation, strict avalanche diffusion,
//      and collision freedom under high iteration stress (250,000 iterations).
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using LogicFlow.Storage.Engine.Chunking;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;
using Xunit;
using Xunit.Abstractions;

namespace LogicFlow.Tests.Storage;

public sealed class HyperStoreEmpiricalChallengerTests
{
    private readonly ITestOutputHelper _output;

    public HyperStoreEmpiricalChallengerTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region 1. FastCDC Throughput Empirical Verification

    [Theory]
    [InlineData(16 * 1024 * 1024)]  // 16 MB
    [InlineData(64 * 1024 * 1024)]  // 64 MB
    [InlineData(128 * 1024 * 1024)] // 128 MB
    public void FastCDC_Throughput_EmpiricalVerification_AcrossBufferSizes(int dataSize)
    {
        var chunker = new FastCdcChunker();

        // 1. Random buffer
        byte[] randomData = new byte[dataSize];
        Random.Shared.NextBytes(randomData);

        // 2. Zero-filled buffer
        byte[] zeroData = new byte[dataSize];

        // 3. Mixed payload buffer
        byte[] mixedData = new byte[dataSize];
        int quarter = dataSize / 4;
        Array.Clear(mixedData, 0, quarter);
        byte[] textSample = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog. LogicFlow sovereign engine 2026.\n");
        for (int i = quarter; i < quarter * 2; i++)
        {
            mixedData[i] = textSample[i % textSample.Length];
        }
        for (int i = quarter * 2; i < quarter * 3; i++)
        {
            mixedData[i] = (i % 2 == 0) ? (byte)0xAA : (byte)0x55;
        }
        Random.Shared.NextBytes(mixedData.AsSpan(quarter * 3, quarter));

        // Warm-up pass
        _ = chunker.ChunkBoundaries(randomData.AsSpan(0, Math.Min(4 * 1024 * 1024, dataSize)));

        const int iterations = 5;
        var randomResults = BenchmarkPayload(chunker, randomData, $"Random-{(dataSize / (1024 * 1024))}MB", iterations);
        var zeroResults = BenchmarkPayload(chunker, zeroData, $"Zero-{(dataSize / (1024 * 1024))}MB", iterations);
        var mixedResults = BenchmarkPayload(chunker, mixedData, $"Mixed-{(dataSize / (1024 * 1024))}MB", iterations);

        _output.WriteLine($"=== Buffer Size: {dataSize / (1024 * 1024)} MB ===");
        _output.WriteLine($"Random:      Avg={randomResults.AvgGbSec:F2} GB/s ({randomResults.AvgGibSec:F2} GiB/s), Min={randomResults.MinGbSec:F2} GB/s, Max={randomResults.MaxGbSec:F2} GB/s, Chunks={randomResults.ChunkCount}, Elapsed={randomResults.AvgElapsedMs:F2}ms");
        _output.WriteLine($"Zero-Filled: Avg={zeroResults.AvgGbSec:F2} GB/s ({zeroResults.AvgGibSec:F2} GiB/s), Min={zeroResults.MinGbSec:F2} GB/s, Max={zeroResults.MaxGbSec:F2} GB/s, Chunks={zeroResults.ChunkCount}, Elapsed={zeroResults.AvgElapsedMs:F2}ms");
        _output.WriteLine($"Mixed:       Avg={mixedResults.AvgGbSec:F2} GB/s ({mixedResults.AvgGibSec:F2} GiB/s), Min={mixedResults.MinGbSec:F2} GB/s, Max={mixedResults.MaxGbSec:F2} GB/s, Chunks={mixedResults.ChunkCount}, Elapsed={mixedResults.AvgElapsedMs:F2}ms");

        // Log whether standard >2.0 GB/s was met
        _output.WriteLine($"Threshold (>2.0 GB/s met?): Random={randomResults.AvgGbSec >= 2.0}, ZeroFilled={zeroResults.AvgGbSec >= 2.0}, Mixed={mixedResults.AvgGbSec >= 2.0}");
    }

    private BenchmarkResult BenchmarkPayload(FastCdcChunker chunker, byte[] data, string label, int iterations)
    {
        double minSec = double.MaxValue;
        double maxSec = 0;
        double totalSec = 0;
        int chunkCount = 0;

        for (int i = 0; i < iterations; i++)
        {
            long start = Stopwatch.GetTimestamp();
            var boundaries = chunker.ChunkBoundaries(data);
            long end = Stopwatch.GetTimestamp();

            double elapsedSec = (double)(end - start) / Stopwatch.Frequency;
            totalSec += elapsedSec;
            if (elapsedSec < minSec) minSec = elapsedSec;
            if (elapsedSec > maxSec) maxSec = elapsedSec;
            chunkCount = boundaries.Count;
        }

        double avgSec = totalSec / iterations;
        double dataGb = data.Length / 1_000_000_000.0;
        double dataGib = data.Length / (1024.0 * 1024.0 * 1024.0);

        return new BenchmarkResult
        {
            Label = label,
            AvgGbSec = dataGb / avgSec,
            AvgGibSec = dataGib / avgSec,
            MinGbSec = dataGb / maxSec,
            MaxGbSec = dataGb / minSec,
            ChunkCount = chunkCount,
            AvgElapsedMs = avgSec * 1000
        };
    }

    public record BenchmarkResult
    {
        public string Label { get; init; } = "";
        public double AvgGbSec { get; init; }
        public double AvgGibSec { get; init; }
        public double MinGbSec { get; init; }
        public double MaxGbSec { get; init; }
        public int ChunkCount { get; init; }
        public double AvgElapsedMs { get; init; }
    }

    #endregion

    #region 2. Boundary Shift Resilience Empirical Verification: Even vs Odd Parity

    [Theory]
    // Odd shift lengths: demonstrate catastrophic desynchronization cascade
    [InlineData(1, 0)]
    [InlineData(1, 100000)]
    [InlineData(3, 100000)]
    [InlineData(7, 250000)]
    [InlineData(15, 250000)]
    // Even shift lengths: demonstrate normal resynchronization
    [InlineData(2, 100000)]
    [InlineData(4, 100000)]
    [InlineData(8, 250000)]
    [InlineData(16, 250000)]
    [InlineData(64, 50000)]
    [InlineData(1024, 750000)]
    [InlineData(32768, 500000)]
    public void FastCDC_BoundaryShiftResilience_ParityAudit(int insertSize, int insertOffset)
    {
        const int baseSize = 2 * 1024 * 1024; // 2 MB
        byte[] baseData = new byte[baseSize];
        new Random(42).NextBytes(baseData);

        var chunker = new FastCdcChunker();
        var baseChunks = new List<ChunkDescriptor>(chunker.ChunkBuffer(baseData));

        // Create mutated buffer with insertion
        byte[] mutatedData = new byte[baseSize + insertSize];
        Buffer.BlockCopy(baseData, 0, mutatedData, 0, insertOffset);
        for (int i = 0; i < insertSize; i++)
        {
            mutatedData[insertOffset + i] = (byte)(0xFF ^ (i & 0x7F));
        }
        Buffer.BlockCopy(baseData, insertOffset, mutatedData, insertOffset + insertSize, baseSize - insertOffset);

        var mutatedChunks = new List<ChunkDescriptor>(chunker.ChunkBuffer(mutatedData));

        var baseHashes = new HashSet<Hash256>();
        foreach (var c in baseChunks) baseHashes.Add(c.Fingerprint);

        int matchingChunks = 0;
        foreach (var c in mutatedChunks)
        {
            if (baseHashes.Contains(c.Fingerprint))
            {
                matchingChunks++;
            }
        }

        double matchPercentage = (double)matchingChunks / baseChunks.Count * 100.0;
        bool isOdd = (insertSize % 2 != 0);

        _output.WriteLine($"[Shift Parity: {(isOdd ? "ODD" : "EVEN")}] Insert {insertSize} bytes at {insertOffset}: BaseChunks={baseChunks.Count}, MutatedChunks={mutatedChunks.Count}, Matching={matchingChunks} ({matchPercentage:F1}%)");

        Assert.True(matchingChunks >= baseChunks.Count - 4,
            $"Insertion ({insertSize} bytes) failed to resynchronize! Matching chunks: {matchingChunks}/{baseChunks.Count}");
    }

    [Theory]
    [InlineData(1, 200000)]  // Odd deletion (1 byte)
    [InlineData(3, 200000)]  // Odd deletion (3 bytes)
    [InlineData(2, 200000)]  // Even deletion (2 bytes)
    [InlineData(128, 200000)]// Even deletion (128 bytes)
    public void FastCDC_BoundaryShiftResilience_DeletionParityAudit(int deleteLength, int deleteOffset)
    {
        const int baseSize = 2 * 1024 * 1024;
        byte[] baseData = new byte[baseSize];
        new Random(42).NextBytes(baseData);

        var chunker = new FastCdcChunker();
        var baseChunks = new List<ChunkDescriptor>(chunker.ChunkBuffer(baseData));

        byte[] deletedData = new byte[baseSize - deleteLength];
        Buffer.BlockCopy(baseData, 0, deletedData, 0, deleteOffset);
        Buffer.BlockCopy(baseData, deleteOffset + deleteLength, deletedData, deleteOffset, baseSize - (deleteOffset + deleteLength));

        var deletedChunks = new List<ChunkDescriptor>(chunker.ChunkBuffer(deletedData));

        var baseHashes = new HashSet<Hash256>();
        foreach (var c in baseChunks) baseHashes.Add(c.Fingerprint);

        int matchingChunks = 0;
        foreach (var c in deletedChunks)
        {
            if (baseHashes.Contains(c.Fingerprint))
            {
                matchingChunks++;
            }
        }

        double matchPercentage = (double)matchingChunks / baseChunks.Count * 100.0;
        bool isOdd = (deleteLength % 2 != 0);

        _output.WriteLine($"[Deletion Parity: {(isOdd ? "ODD" : "EVEN")}] Delete {deleteLength} bytes at {deleteOffset}: BaseChunks={baseChunks.Count}, MutatedChunks={deletedChunks.Count}, Matching={matchingChunks} ({matchPercentage:F1}%)");

        Assert.True(matchingChunks >= baseChunks.Count - 4,
            $"Deletion ({deleteLength} bytes) failed to resynchronize! Matching chunks: {matchingChunks}/{baseChunks.Count}");
    }

    #endregion

    #region 3. Hash256 BLAKE3 Fingerprinting Stress Tests

    [Fact]
    public void Hash256_ZeroTruncation_All32BytesRetainedAndRoundtrip()
    {
        byte[] rawBytes = new byte[32];
        for (int i = 0; i < 32; i++) rawBytes[i] = (byte)(i * 7 + 3);

        Hash256 hash = new Hash256(rawBytes);

        Assert.NotEqual(UInt128.Zero, hash.Part0);
        Assert.NotEqual(UInt128.Zero, hash.Part1);

        byte[] exported = hash.ToByteArray();
        Assert.Equal(32, exported.Length);
        Assert.Equal(rawBytes, exported);

        byte[] written = new byte[32];
        hash.WriteTo(written);
        Assert.Equal(rawBytes, written);

        string hex = hash.ToHexString();
        Assert.Equal(64, hex.Length);
        Assert.Equal(Convert.ToHexString(rawBytes).ToLowerInvariant(), hex);

        Hash256 parsed = Hash256.Parse(hex);
        Assert.Equal(hash, parsed);

        Assert.True(Hash256.TryParse(hex, out Hash256 tryParsed));
        Assert.Equal(hash, tryParsed);

        Assert.True(Hash256.TryParse(hex.ToUpperInvariant(), out Hash256 upperParsed));
        Assert.Equal(hash, upperParsed);
    }

    [Fact]
    public void Hash256_Diffusion_StrictAvalancheCriterion_1000Iterations()
    {
        const int iterations = 1000;
        int minBitsFlipped = int.MaxValue;
        int maxBitsFlipped = 0;
        long totalBitsFlipped = 0;

        byte[] original = new byte[4096];
        byte[] mutated = new byte[4096];

        for (int i = 0; i < iterations; i++)
        {
            Random.Shared.NextBytes(original);
            Buffer.BlockCopy(original, 0, mutated, 0, original.Length);

            int byteIndex = Random.Shared.Next(0, original.Length);
            int bitIndex = Random.Shared.Next(0, 8);
            mutated[byteIndex] ^= (byte)(1 << bitIndex);

            Hash256 h1 = Hash256.Compute(original);
            Hash256 h2 = Hash256.Compute(mutated);

            Assert.NotEqual(h1, h2);

            UInt128 diff0 = h1.Part0 ^ h2.Part0;
            UInt128 diff1 = h1.Part1 ^ h2.Part1;

            int flipped = BitOperations.PopCount((ulong)diff0)
                        + BitOperations.PopCount((ulong)(diff0 >> 64))
                        + BitOperations.PopCount((ulong)diff1)
                        + BitOperations.PopCount((ulong)(diff1 >> 64));

            if (flipped < minBitsFlipped) minBitsFlipped = flipped;
            if (flipped > maxBitsFlipped) maxBitsFlipped = flipped;
            totalBitsFlipped += flipped;

            Assert.True(flipped >= 80, $"Iteration {i}: Avalanche effect failed! Only {flipped}/256 bits changed.");
        }

        double avgBitsFlipped = (double)totalBitsFlipped / iterations;
        double avgPercentage = (avgBitsFlipped / 256.0) * 100.0;

        _output.WriteLine($"=== BLAKE3 Hash256 Diffusion (1,000 Single-Bit Flips) ===");
        _output.WriteLine($"Mean Flipped Bits: {avgBitsFlipped:F2} / 256 ({avgPercentage:F2}%) [Ideal: 128.0 (50.0%)]");
        _output.WriteLine($"Min Flipped: {minBitsFlipped} ({(minBitsFlipped / 256.0) * 100.0:F1}%)");
        _output.WriteLine($"Max Flipped: {maxBitsFlipped} ({(maxBitsFlipped / 256.0) * 100.0:F1}%)");

        Assert.InRange(avgBitsFlipped, 126.0, 130.0);
    }

    [Fact]
    public void Hash256_CollisionFreedom_HighIterationCount_250kHashes()
    {
        const int iterations = 250_000;
        var set = new HashSet<Hash256>(iterations);
        byte[] buffer = new byte[64];

        long start = Stopwatch.GetTimestamp();

        for (int i = 0; i < iterations; i++)
        {
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 8), (long)i);
            BitConverter.TryWriteBytes(buffer.AsSpan(8, 8), (long)(i ^ 0x5555555555555555L));
            BitConverter.TryWriteBytes(buffer.AsSpan(16, 8), (long)(i * 31));
            BitConverter.TryWriteBytes(buffer.AsSpan(24, 8), (long)(i * 6364136223846793005L + 1));

            Hash256 hash = Hash256.Compute(buffer);

            bool added = set.Add(hash);
            Assert.True(added, $"BLAKE3 collision detected at iteration {i}!");
        }

        long end = Stopwatch.GetTimestamp();
        double elapsedSec = (double)(end - start) / Stopwatch.Frequency;
        double hashesPerSec = iterations / elapsedSec;

        _output.WriteLine($"=== BLAKE3 Hash256 Collision Freedom (250,000 Hashes) ===");
        _output.WriteLine($"Total Hashes: {set.Count:N0}");
        _output.WriteLine($"Collisions: 0 (100% collision-free)");
        _output.WriteLine($"Throughput: {hashesPerSec:N0} hashes/sec (Elapsed: {elapsedSec * 1000:F2} ms)");

        Assert.Equal(iterations, set.Count);
    }

    #endregion
}
