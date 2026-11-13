using System;
using System.Runtime.InteropServices;
using LogicFlow.Storage.Engine.Compression;

namespace LogicFlow.Storage.Engine.Container;

[Flags]
public enum LfcHeaderFlags : uint
{
    None = 0,
    Encrypted = 1 << 0,
    HasDictionary = 1 << 1,
    ColdTierL19 = 1 << 2,
    Finalized = 1 << 3
}

/// <summary>
/// Sovereign 64-byte Header at fixed offset 0 of any .lfc archive.
/// Magic: 'LFC\x01' (0x0143464C).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct LfcHeader
{
    public const uint MagicValue = 0x0143464C; // 'LFC\x01'
    public const int SizeInBytes = 64;

    public uint Magic;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Flags;
    public ushort ChunkerId;
    public ushort HashAlgId;
    public ushort CompAlgId;
    public ushort Reserved0;
    public long CreatedUtc;
    public ulong ChunkTableOffset;
    public uint ChunkTableLength;
    public ulong ManifestOffset;
    public uint ManifestLength;
    public uint DictLength;
    public uint Reserved1;
    public uint HeaderCrc32c;

    public static LfcHeader CreateDefault(uint flags = (uint)LfcHeaderFlags.Finalized)
    {
        return new LfcHeader
        {
            Magic = MagicValue,
            MajorVersion = 1,
            MinorVersion = 0,
            Flags = flags,
            ChunkerId = 1, // FastCDC-32K
            HashAlgId = 1, // BLAKE3-256
            CompAlgId = 1, // Zstandard
            Reserved0 = 0,
            CreatedUtc = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ChunkTableOffset = 0,
            ChunkTableLength = 0,
            ManifestOffset = 0,
            ManifestLength = 0,
            DictLength = 0,
            Reserved1 = 0,
            HeaderCrc32c = 0
        };
    }

    public void FinalizeChecksum()
    {
        Span<byte> span = stackalloc byte[SizeInBytes];
        MemoryMarshal.Write(span, in this);
        HeaderCrc32c = Crc32c.Compute(span[..60]);
    }

    public bool VerifyChecksum()
    {
        if (Magic != MagicValue) return false;
        Span<byte> span = stackalloc byte[SizeInBytes];
        MemoryMarshal.Write(span, in this);
        uint computed = Crc32c.Compute(span[..60]);
        return computed == HeaderCrc32c;
    }
}

/// <summary>
/// Sovereign 64-byte Footer fixed at EOF - 64 bytes of any .lfc archive.
/// Magic: '\x01CFL' (0x4C464301).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct LfcFooter
{
    public const uint MagicValue = 0x4C464301; // '\x01CFL'
    public const int SizeInBytes = 64;

    public uint FooterMagic;
    public uint TotalFiles;
    public uint TotalUniqueChunks;
    public uint Flags;
    public ulong TotalRawBytes;
    public ulong TotalCompressedBytes;
    public ulong ChunkTableOffset;
    public ulong ManifestOffset;
    public ulong DictOffset;
    public uint DictLength;
    public uint FooterCrc32c;

    public static LfcFooter CreateDefault()
    {
        return new LfcFooter
        {
            FooterMagic = MagicValue,
            TotalFiles = 0,
            TotalUniqueChunks = 0,
            Flags = 0,
            TotalRawBytes = 0,
            TotalCompressedBytes = 0,
            ChunkTableOffset = 0,
            ManifestOffset = 0,
            DictOffset = 0,
            DictLength = 0,
            FooterCrc32c = 0
        };
    }

    public void FinalizeChecksum()
    {
        Span<byte> span = stackalloc byte[SizeInBytes];
        MemoryMarshal.Write(span, in this);
        FooterCrc32c = Crc32c.Compute(span[..60]);
    }

    public bool VerifyChecksum()
    {
        if (FooterMagic != MagicValue) return false;
        Span<byte> span = stackalloc byte[SizeInBytes];
        MemoryMarshal.Write(span, in this);
        uint computed = Crc32c.Compute(span[..60]);
        return computed == FooterCrc32c;
    }
}
