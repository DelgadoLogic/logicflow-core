using System;
using System.Runtime.CompilerServices;

namespace LogicFlow.Storage.Engine.Clustering;

/// <summary>
/// Locality-Sensitive Hashing MinHash signature comprising 32 min-hash values
/// and 4 combined super-features for resemblance clustering.
/// </summary>
public readonly struct MinHashSignature : IEquatable<MinHashSignature>
{
    public const int NumHashes = 32;
    public const int SuperFeatureCount = 4;
    public const int HashesPerSuperFeature = 8;

    public readonly ulong S0;
    public readonly ulong S1;
    public readonly ulong S2;
    public readonly ulong S3;

    private readonly ulong[] _minHashes;

    public ReadOnlySpan<ulong> MinHashes => _minHashes ?? [];

    public static readonly MinHashSignature Empty = new(new ulong[NumHashes], 0, 0, 0, 0);

    public MinHashSignature(ulong[] minHashes, ulong s0, ulong s1, ulong s2, ulong s3)
    {
        if (minHashes.Length != NumHashes)
        {
            throw new ArgumentException($"MinHash array must contain exactly {NumHashes} values.", nameof(minHashes));
        }

        _minHashes = minHashes;
        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool HasSuperFeatureMatch(in MinHashSignature other)
    {
        return S0 == other.S0 || S1 == other.S1 || S2 == other.S2 || S3 == other.S3;
    }

    public bool Equals(MinHashSignature other)
    {
        if (S0 != other.S0 || S1 != other.S1 || S2 != other.S2 || S3 != other.S3)
        {
            return false;
        }

        if (_minHashes == null && other._minHashes == null)
        {
            return true;
        }

        if (_minHashes == null || other._minHashes == null)
        {
            return false;
        }

        for (int i = 0; i < NumHashes; i++)
        {
            if (_minHashes[i] != other._minHashes[i])
            {
                return false;
            }
        }

        return true;
    }

    public override bool Equals(object? obj) => obj is MinHashSignature other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(S0, S1, S2, S3);

    public static bool operator ==(MinHashSignature left, MinHashSignature right) => left.Equals(right);
    public static bool operator !=(MinHashSignature left, MinHashSignature right) => !left.Equals(right);
}
