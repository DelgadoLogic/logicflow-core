using System;
using System.Runtime.InteropServices;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Container;

/// <summary>
/// Flags for stored chunk descriptors.
/// </summary>
[Flags]
public enum ChunkFlags : ushort
{
    None = 0,
    IsCompressed = 1 << 0,
    UsesDictionary = 1 << 1,
    IsDelta = 1 << 2
}

/// <summary>
/// Sovereign 64-byte aligned Chunk Descriptor stored in the Chunk Descriptor Table (CDT).
/// Exactly 64 bytes fitting a standard CPU cache line.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct ChunkDescriptor : IEquatable<ChunkDescriptor>
{
    public const int SizeInBytes = 64;

    /// <summary>
    /// 256-bit BLAKE3 cryptographic hash (32 bytes).
    /// </summary>
    public Hash256 Fingerprint;

    /// <summary>
    /// Byte offset in the .lfc container payload pool where chunk data is stored.
    /// </summary>
    public ulong PayloadOffset;

    /// <summary>
    /// Stored size on disk (bytes).
    /// </summary>
    public uint CompressedSize;

    /// <summary>
    /// Uncompressed original size (bytes).
    /// </summary>
    public uint RawSize;

    /// <summary>
    /// Chunk flags (Compressed, Dict, Delta).
    /// </summary>
    public ushort Flags;

    /// <summary>
    /// Reserved for alignment / future extensions.
    /// </summary>
    public ushort Reserved;

    /// <summary>
    /// Index of reference chunk in CDT if delta compressed (0xFFFFFFFF if none).
    /// </summary>
    public uint BaseChunkIndex;

    /// <summary>
    /// Primary 64-bit MinHash super-feature for fast resemblance lookup.
    /// </summary>
    public ulong MinHashFeature;

    public ChunkDescriptor(
        Hash256 fingerprint,
        ulong payloadOffset,
        uint compressedSize,
        uint rawSize,
        ushort flags = 0,
        uint baseChunkIndex = 0xFFFFFFFF,
        ulong minHashFeature = 0)
    {
        Fingerprint = fingerprint;
        PayloadOffset = payloadOffset;
        CompressedSize = compressedSize;
        RawSize = rawSize;
        Flags = flags;
        Reserved = 0;
        BaseChunkIndex = baseChunkIndex;
        MinHashFeature = minHashFeature;
    }

    public bool Equals(ChunkDescriptor other)
    {
        return Fingerprint.Equals(other.Fingerprint) &&
               PayloadOffset == other.PayloadOffset &&
               CompressedSize == other.CompressedSize &&
               RawSize == other.RawSize &&
               Flags == other.Flags &&
               BaseChunkIndex == other.BaseChunkIndex &&
               MinHashFeature == other.MinHashFeature;
    }

    public override bool Equals(object? obj) => obj is ChunkDescriptor other && Equals(other);

    public override int GetHashCode() => Fingerprint.GetHashCode();

    public static bool operator ==(ChunkDescriptor left, ChunkDescriptor right) => left.Equals(right);
    public static bool operator !=(ChunkDescriptor left, ChunkDescriptor right) => !left.Equals(right);
}
