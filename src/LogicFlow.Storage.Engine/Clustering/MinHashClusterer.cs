using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Clustering;

/// <summary>
/// Locality-Sensitive Hashing (LSH) MinHash clusterer.
/// Evaluates 32 min-wise permutations grouped into 4 super-features to estimate
/// Jaccard similarity and detect near-duplicate file and chunk clusters.
/// </summary>
public sealed class MinHashClusterer
{
    // 32 deterministic pseudo-random odd multipliers (coprime to 2^64)
    private static readonly ulong[] Multipliers =
    [
        0x2545F4914F6CDD1DUL, 0xBA6F0A9ABAE1F529UL, 0x8C1B79F215AC6A43UL, 0x47B00C379308D2C5UL,
        0x5608FA1A0983A897UL, 0x6E4C4B184B4FBEEBUL, 0x1B07DA78E3DA788DUL, 0x31AB1E9528D08149UL,
        0x4B3FCD4B7B7B49B5UL, 0x76878DA8E1F9A2DFUL, 0x9330D00BC054E391UL, 0x2A109D9455353CE3UL,
        0x5C808E4A0C58A5DBUL, 0xE9811C8A609B5BC7UL, 0x877BD79F39CA5E23UL, 0x60010DB7C50D32E9UL,
        0x10134BD53DDB1B01UL, 0x228B47C56A6CE863UL, 0x3841D44783E00AE7UL, 0x4896DA5225E0359BUL,
        0x51E5B422B694F1F5UL, 0x6FEBE0B99B7F9827UL, 0x7BA72DF7ED7A1B1DUL, 0x85D084661D2258D9UL,
        0x9068DFBBE3B87A83UL, 0xA38EBEE3D83D48AFUL, 0xB668A7C6B7FEAEB5UL, 0xC4FE19CDAD481487UL,
        0xD792D469616238FDUL, 0xE5DFBD78DF9B7829UL, 0xF1AB742F16260B11UL, 0x0546ACD4B892F263UL
    ];

    // 32 deterministic pseudo-random offsets
    private static readonly ulong[] Offsets =
    [
        0x61C8864680B583EBul, 0x9E3779B97F4A7C15ul, 0x3C6EF372FE94F82Bul, 0xC4CEB9FE1A85EC53ul,
        0xA5B357B4A2173F81ul, 0x27D4EB2F165667C5ul, 0x5D3E836A31E56B0Ful, 0xB8E1E5C77C8E2859ul,
        0xE2B34B9C23D4D541ul, 0x47B00C379308D2C5ul, 0x7F4A7C159E3779B9ul, 0x1A85EC53C4CEB9FEul,
        0xA2173F81A5B357B4ul, 0x165667C527D4EB2Ful, 0x31E56B0F5D3E836Aul, 0x7C8E2859B8E1E5C7ul,
        0x23D4D541E2B34B9Cul, 0x80B583EB61C88646ul, 0xFE94F82B3C6EF372ul, 0x9308D2C547B00C37ul,
        0x6A09E667F3BCC908ul, 0xBB67AE8584CAA73Bul, 0x3C6EF372FE94F82Bul, 0xA54FF53A5F1D36F1ul,
        0x510E527FADE682D1ul, 0x9B05688C2B3E6C1Ful, 0x1F83D9ABFB41BD6Bul, 0x5BE0CD19137E2179ul,
        0x28B4D6DF04B144E5ul, 0x82A1B30FE2CF526Ful, 0x39D2F024B4C1CD38ul, 0x7C98DE4532B0F1A7ul
    ];

    public static MinHashClusterer Instance { get; } = new();

    /// <summary>
    /// Computes MinHash signature from a set of chunk descriptors (file-level resemblance).
    /// </summary>
    public MinHashSignature ComputeSignature(IEnumerable<ChunkDescriptor> chunks)
    {
        ArgumentNullException.ThrowIfNull(chunks);

        ulong[] minHashes = new ulong[MinHashSignature.NumHashes];
        Array.Fill(minHashes, ulong.MaxValue);

        bool hasAny = false;
        foreach (var chunk in chunks)
        {
            hasAny = true;
            ulong x = (ulong)chunk.Fingerprint.Part0 ^ (ulong)(chunk.Fingerprint.Part1 >> 64);
            UpdateMinHashes(minHashes, x);
        }

        if (!hasAny)
        {
            return MinHashSignature.Empty;
        }

        return FinalizeSignature(minHashes);
    }

    /// <summary>
    /// Computes MinHash signature from raw byte data using 8-byte rolling shingles (chunk-level resemblance).
    /// </summary>
    public MinHashSignature ComputeSignature(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return MinHashSignature.Empty;
        }

        ulong[] minHashes = new ulong[MinHashSignature.NumHashes];
        Array.Fill(minHashes, ulong.MaxValue);

        if (data.Length < 8)
        {
            ulong x = 0;
            for (int i = 0; i < data.Length; i++)
            {
                x = (x << 8) | data[i];
            }
            UpdateMinHashes(minHashes, x);
        }
        else
        {
            // Shingle data with 4-byte stride for speed and overlap coverage
            int limit = data.Length - 8;
            for (int i = 0; i <= limit; i += 4)
            {
                ulong shingle = MemoryMarshal.Read<ulong>(data.Slice(i, 8));
                UpdateMinHashes(minHashes, shingle);
            }

            if (limit % 4 != 0)
            {
                ulong lastShingle = MemoryMarshal.Read<ulong>(data.Slice(limit, 8));
                UpdateMinHashes(minHashes, lastShingle);
            }
        }

        return FinalizeSignature(minHashes);
    }

    /// <summary>
    /// Computes MinHash signature from an array of 256-bit hashes.
    /// </summary>
    public MinHashSignature ComputeSignature(ReadOnlySpan<Hash256> fingerprints)
    {
        if (fingerprints.IsEmpty)
        {
            return MinHashSignature.Empty;
        }

        ulong[] minHashes = new ulong[MinHashSignature.NumHashes];
        Array.Fill(minHashes, ulong.MaxValue);

        for (int k = 0; k < fingerprints.Length; k++)
        {
            ulong x = (ulong)fingerprints[k].Part0 ^ (ulong)(fingerprints[k].Part1 >> 64);
            UpdateMinHashes(minHashes, x);
        }

        return FinalizeSignature(minHashes);
    }

    /// <summary>
    /// Estimates Jaccard similarity index [0.0, 1.0] between two MinHash signatures.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public double ComputeSimilarity(in MinHashSignature a, in MinHashSignature b)
    {
        ReadOnlySpan<ulong> ma = a.MinHashes;
        ReadOnlySpan<ulong> mb = b.MinHashes;

        if (ma.IsEmpty || mb.IsEmpty)
        {
            return 0.0;
        }

        int matches = 0;
        for (int i = 0; i < MinHashSignature.NumHashes; i++)
        {
            if (ma[i] == mb[i])
            {
                matches++;
            }
        }

        return (double)matches / MinHashSignature.NumHashes;
    }

    /// <summary>
    /// Returns true if two signatures exceed the resemblance threshold or share super-features.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool AreResembling(in MinHashSignature a, in MinHashSignature b, double threshold = 0.5)
    {
        if (a.HasSuperFeatureMatch(b))
        {
            return true;
        }

        return ComputeSimilarity(a, b) >= threshold;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UpdateMinHashes(ulong[] minHashes, ulong x)
    {
        for (int i = 0; i < MinHashSignature.NumHashes; i++)
        {
            ulong h = (Multipliers[i] * x) + Offsets[i];
            // SplitMix64 finalizer mix for high dispersion
            h ^= h >> 30;
            h *= 0xBF58476D1CE4E5B9UL;
            h ^= h >> 27;
            h *= 0x94D049BB133111EBUL;
            h ^= h >> 31;

            if (h < minHashes[i])
            {
                minHashes[i] = h;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static MinHashSignature FinalizeSignature(ulong[] minHashes)
    {
        ulong s0 = CombineSuperFeature(minHashes, 0);
        ulong s1 = CombineSuperFeature(minHashes, 8);
        ulong s2 = CombineSuperFeature(minHashes, 16);
        ulong s3 = CombineSuperFeature(minHashes, 24);

        return new MinHashSignature(minHashes, s0, s1, s2, s3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong CombineSuperFeature(ulong[] minHashes, int start)
    {
        ulong s = 0xcbf29ce484222325UL;
        for (int i = 0; i < MinHashSignature.HashesPerSuperFeature; i++)
        {
            s = (s ^ minHashes[start + i]) * 0x100000001b3UL;
        }
        return s;
    }
}
