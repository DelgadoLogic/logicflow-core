using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Container;

/// <summary>
/// Reconstruction metadata entry for a single file within the .lfc archive.
/// </summary>
public sealed class LfcFileEntry
{
    public string RelativePath { get; set; } = string.Empty;
    public uint FileAttributes { get; set; }
    public long CreationTimeUtc { get; set; }
    public long LastWriteTimeUtc { get; set; }
    public ulong FileRawSizeBytes { get; set; }
    public Hash256 FileHash { get; set; }
    public uint[] ChunkIndices { get; set; } = [];
}

/// <summary>
/// Stream manifest storing directory hierarchy, file metadata, and chunk reconstruction maps.
/// </summary>
public sealed class LfcStreamManifest
{
    public const uint ManifestMagic = 0x4D46534CU; // 'LCSM'

    public List<LfcFileEntry> Files { get; set; } = [];

    public void WriteTo(Stream stream)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(ManifestMagic);
        writer.Write((uint)Files.Count);

        Span<byte> hashBytes = stackalloc byte[32];

        foreach (var file in Files)
        {
            writer.Write(file.RelativePath);
            writer.Write(file.FileAttributes);
            writer.Write(file.CreationTimeUtc);
            writer.Write(file.LastWriteTimeUtc);
            writer.Write(file.FileRawSizeBytes);

            file.FileHash.WriteTo(hashBytes);
            writer.Write(hashBytes);

            writer.Write((uint)file.ChunkIndices.Length);
            for (int i = 0; i < file.ChunkIndices.Length; i++)
            {
                writer.Write(file.ChunkIndices[i]);
            }
        }
    }

    public static LfcStreamManifest ReadFrom(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        uint magic = reader.ReadUInt32();
        if (magic != ManifestMagic)
        {
            throw new InvalidDataException($"Invalid LFC stream manifest magic: 0x{magic:X8}");
        }

        uint count = reader.ReadUInt32();
        if (stream.CanSeek && (ulong)count > (ulong)(stream.Length / 32))
        {
            throw new InvalidDataException($"Manifest file count ({count}) exceeds stream capacity for length ({stream.Length}).");
        }
        var manifest = new LfcStreamManifest { Files = new List<LfcFileEntry>((int)Math.Min(count, 65536)) };

        byte[] hashBuffer = new byte[32];

        for (uint i = 0; i < count; i++)
        {
            string path = reader.ReadString();
            uint attrs = reader.ReadUInt32();
            long createUtc = reader.ReadInt64();
            long writeUtc = reader.ReadInt64();
            ulong rawSize = reader.ReadUInt64();

            int readBytes = reader.Read(hashBuffer, 0, 32);
            if (readBytes != 32)
            {
                throw new EndOfStreamException("Truncated hash in LfcStreamManifest.");
            }
            Hash256 fileHash = new Hash256(hashBuffer);

            uint chunkCount = reader.ReadUInt32();
            if (stream.CanSeek && (ulong)chunkCount > (ulong)(stream.Length / 4))
            {
                throw new InvalidDataException($"File chunk count ({chunkCount}) exceeds stream capacity.");
            }
            uint[] chunkIndices = new uint[chunkCount];
            for (uint j = 0; j < chunkCount; j++)
            {
                chunkIndices[j] = reader.ReadUInt32();
            }

            manifest.Files.Add(new LfcFileEntry
            {
                RelativePath = path,
                FileAttributes = attrs,
                CreationTimeUtc = createUtc,
                LastWriteTimeUtc = writeUtc,
                FileRawSizeBytes = rawSize,
                FileHash = fileHash,
                ChunkIndices = chunkIndices
            });
        }

        return manifest;
    }

    public byte[] ToByteArray()
    {
        using var ms = new MemoryStream();
        WriteTo(ms);
        return ms.ToArray();
    }

    public static LfcStreamManifest FromByteArray(ReadOnlySpan<byte> bytes)
    {
        using var ms = new MemoryStream(bytes.ToArray());
        return ReadFrom(ms);
    }
}
