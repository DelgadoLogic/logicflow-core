using System;
using LogicFlow.Storage.Engine.Compression;

namespace LogicFlow.Storage.Engine.Container;

/// <summary>
/// Real-time progress report emitted during packing or unpacking operations.
/// </summary>
public sealed class HyperStoreProgressReport
{
    public int FilesProcessed { get; set; }
    public int TotalFiles { get; set; }
    public long BytesProcessed { get; set; }
    public long TotalBytes { get; set; }
    public string CurrentFile { get; set; } = string.Empty;
    public int UniqueChunks { get; set; }
    public int TotalChunks { get; set; }
    public long DeduplicatedBytes { get; set; }
    public long CompressedBytes { get; set; }
    public double CompressionRatio => TotalBytes > 0 && CompressedBytes > 0
        ? Math.Round((double)TotalBytes / CompressedBytes, 2)
        : 1.0;
}

/// <summary>
/// Options governing .lfc archive creation.
/// </summary>
public sealed class LfcPackOptions
{
    public CompressionTier Tier { get; set; } = CompressionTier.Hot;
    public bool TrainDictionary { get; set; } = false;
    public bool EnableDeltaCompression { get; set; } = true;
    public int MaxDictionarySize { get; set; } = DualTierZstdCompressor.DefaultDictionarySize;
    public System.Collections.Generic.IReadOnlyList<string> ExcludedPaths { get; set; } = Array.Empty<string>();
    public static LfcPackOptions Default { get; } = new();
}

/// <summary>
/// Options governing .lfc archive unpacking.
/// </summary>
public sealed class LfcUnpackOptions
{
    public bool Overwrite { get; set; } = true;
    public bool VerifyHashes { get; set; } = true;
    public static LfcUnpackOptions Default { get; } = new();
}

/// <summary>
/// Summary information and manifest details inspected from an .lfc archive without unpacking.
/// </summary>
public sealed class LfcArchiveInfo
{
    public LfcHeader Header { get; init; }
    public LfcFooter Footer { get; init; }
    public int TotalFiles => (int)Footer.TotalFiles;
    public int TotalUniqueChunks => (int)Footer.TotalUniqueChunks;
    public long TotalRawBytes => (long)Footer.TotalRawBytes;
    public long TotalCompressedBytes => (long)Footer.TotalCompressedBytes;
    public long SpaceSavingsBytes => TotalRawBytes - TotalCompressedBytes;
    public double SpaceReductionRatio => TotalCompressedBytes > 0
        ? Math.Round((double)TotalRawBytes / TotalCompressedBytes, 2)
        : 1.0;
    public bool HasDictionary => (Header.Flags & (uint)LfcHeaderFlags.HasDictionary) != 0;
    public LfcStreamManifest? Manifest { get; init; }
}
