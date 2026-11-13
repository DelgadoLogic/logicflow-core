using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Container;

/// <summary>
/// Sovereign .lfc v1.0 Container Reader.
/// Implements fast random-access inspection, full-fidelity directory reconstruction,
/// delta chunk resolution, and end-to-end cryptographic hash verification.
/// </summary>
public sealed class LfcReader : IDisposable
{
    private readonly DualTierZstdCompressor _compressor = DualTierZstdCompressor.Instance;

    public void Dispose()
    {
    }

    /// <summary>
    /// Inspects an .lfc archive without unpacking, reading Header, Footer, and Stream Manifest in O(1) time.
    /// </summary>
    public LfcArchiveInfo InspectArchive(string lfcPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(lfcPath);
        if (!File.Exists(lfcPath))
        {
            throw new FileNotFoundException($"Archive not found: {lfcPath}");
        }

        using var fileStream = new FileStream(lfcPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (fileStream.Length < LfcHeader.SizeInBytes + LfcFooter.SizeInBytes)
        {
            throw new InvalidDataException("Archive size is too small to contain valid LFC Header and Footer.");
        }

        // Read and verify Header
        Span<byte> headerBytes = stackalloc byte[LfcHeader.SizeInBytes];
        fileStream.ReadExactly(headerBytes);
        var header = MemoryMarshal.Read<LfcHeader>(headerBytes);
        if (!header.VerifyChecksum())
        {
            throw new InvalidDataException("LFC Header CRC32C verification failed or invalid magic.");
        }

        // Read and verify Footer
        fileStream.Seek(-LfcFooter.SizeInBytes, SeekOrigin.End);
        Span<byte> footerBytes = stackalloc byte[LfcFooter.SizeInBytes];
        fileStream.ReadExactly(footerBytes);
        var footer = MemoryMarshal.Read<LfcFooter>(footerBytes);
        if (!footer.VerifyChecksum())
        {
            throw new InvalidDataException("LFC Footer CRC32C verification failed or invalid magic.");
        }

        if (footer.ManifestOffset >= (ulong)fileStream.Length || footer.ChunkTableOffset >= (ulong)fileStream.Length)
        {
            throw new InvalidDataException("LFC Footer offsets exceed archive size.");
        }

        // Read Stream Manifest
        fileStream.Position = (long)footer.ManifestOffset;
        var manifest = LfcStreamManifest.ReadFrom(fileStream);

        return new LfcArchiveInfo
        {
            Header = header,
            Footer = footer,
            Manifest = manifest
        };
    }

    /// <summary>
    /// Unpacks an entire .lfc archive into the specified destination directory.
    /// </summary>
    public async Task UnpackArchiveAsync(
        string lfcPath,
        string destinationDir,
        LfcUnpackOptions? options = null,
        IProgress<HyperStoreProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(lfcPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationDir);

        if (!File.Exists(lfcPath))
        {
            throw new FileNotFoundException($"Archive not found: {lfcPath}");
        }

        var opt = options ?? LfcUnpackOptions.Default;
        string fullDest = Path.GetFullPath(destinationDir);
        if (!fullDest.EndsWith(Path.DirectorySeparatorChar))
        {
            fullDest += Path.DirectorySeparatorChar;
        }
        Directory.CreateDirectory(fullDest);

        await using var fileStream = new FileStream(
            lfcPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 131072,
            FileOptions.Asynchronous);

        if (fileStream.Length < LfcHeader.SizeInBytes + LfcFooter.SizeInBytes)
        {
            throw new InvalidDataException("Archive is corrupted or too small.");
        }

        // Read Header
        byte[] headerBytes = new byte[LfcHeader.SizeInBytes];
        await fileStream.ReadExactlyAsync(headerBytes, ct).ConfigureAwait(false);
        var header = MemoryMarshal.Read<LfcHeader>(headerBytes);
        if (!header.VerifyChecksum())
        {
            throw new InvalidDataException("LFC Header CRC32C verification failed.");
        }

        // Read Footer
        fileStream.Seek(-LfcFooter.SizeInBytes, SeekOrigin.End);
        byte[] footerBytes = new byte[LfcFooter.SizeInBytes];
        await fileStream.ReadExactlyAsync(footerBytes, ct).ConfigureAwait(false);
        var footer = MemoryMarshal.Read<LfcFooter>(footerBytes);
        if (!footer.VerifyChecksum())
        {
            throw new InvalidDataException("LFC Footer CRC32C verification failed.");
        }

        // Read dictionary if present
        byte[] dictionary = [];
        if (footer.DictLength > 0 && footer.DictOffset > 0)
        {
            if (footer.DictOffset + footer.DictLength > (ulong)fileStream.Length)
            {
                throw new InvalidDataException("Dictionary offset exceeds archive size.");
            }
            fileStream.Position = (long)footer.DictOffset;
            dictionary = new byte[footer.DictLength];
            await fileStream.ReadExactlyAsync(dictionary, ct).ConfigureAwait(false);
        }

        // Read Chunk Descriptor Table (CDT)
        ulong chunkCount = footer.TotalUniqueChunks;
        ulong maxPossibleChunks = (ulong)(fileStream.Length / ChunkDescriptor.SizeInBytes);
        if (chunkCount > maxPossibleChunks || footer.ChunkTableOffset + (chunkCount * (ulong)ChunkDescriptor.SizeInBytes) > (ulong)fileStream.Length)
        {
            throw new InvalidDataException($"Invalid chunk count ({chunkCount}) or chunk table offset ({footer.ChunkTableOffset}) exceeds archive size ({fileStream.Length}).");
        }

        fileStream.Position = (long)footer.ChunkTableOffset;
        byte[] cdtRaw = new byte[chunkCount * (ulong)ChunkDescriptor.SizeInBytes];
        await fileStream.ReadExactlyAsync(cdtRaw, ct).ConfigureAwait(false);

        var cdt = new ChunkDescriptor[chunkCount];
        for (int i = 0; i < (int)chunkCount; i++)
        {
            cdt[i] = MemoryMarshal.Read<ChunkDescriptor>(cdtRaw.AsSpan(i * ChunkDescriptor.SizeInBytes, ChunkDescriptor.SizeInBytes));
        }

        // Read Stream Manifest
        if (footer.ManifestOffset >= (ulong)fileStream.Length)
        {
            throw new InvalidDataException("Manifest offset exceeds archive size.");
        }
        fileStream.Position = (long)footer.ManifestOffset;
        var manifest = LfcStreamManifest.ReadFrom(fileStream);

        // LRU chunk cache to accelerate duplicate and delta chunk resolution
        var chunkCache = new Dictionary<uint, byte[]>((int)Math.Min(chunkCount, 2048));

        long bytesRestored = 0;
        var report = new HyperStoreProgressReport
        {
            TotalFiles = manifest.Files.Count,
            TotalBytes = (long)footer.TotalRawBytes
        };

        for (int fileIdx = 0; fileIdx < manifest.Files.Count; fileIdx++)
        {
            ct.ThrowIfCancellationRequested();
            var entry = manifest.Files[fileIdx];
            string targetPath = Path.GetFullPath(Path.Combine(fullDest, entry.RelativePath));

            if (!targetPath.StartsWith(fullDest, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"Path traversal detected in archive entry: '{entry.RelativePath}'");
            }

            string? dir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            report.CurrentFile = entry.RelativePath;
            report.FilesProcessed = fileIdx;
            report.BytesProcessed = bytesRestored;
            progress?.Report(report);

            if (File.Exists(targetPath) && !opt.Overwrite)
            {
                continue;
            }

            await using (var outStream = new FileStream(
                targetPath,
                FileMode.Create,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 65536,
                FileOptions.Asynchronous))
            {
                for (int ci = 0; ci < entry.ChunkIndices.Length; ci++)
                {
                    ct.ThrowIfCancellationRequested();
                    uint chunkIdx = entry.ChunkIndices[ci];
                    byte[] chunkBytes = await ResolveChunkAsync(
                        fileStream,
                        cdt,
                        chunkIdx,
                        dictionary,
                        chunkCache,
                        depth: 0,
                        visited: null,
                        ct).ConfigureAwait(false);

                    await outStream.WriteAsync(chunkBytes, ct).ConfigureAwait(false);
                    bytesRestored += chunkBytes.Length;
                }

                // Verify file integrity if requested
                if (opt.VerifyHashes)
                {
                    outStream.Position = 0;
                    Hash256 computedHash = Hash256.Compute(outStream);
                    if (computedHash != entry.FileHash)
                    {
                        throw new InvalidDataException(
                            $"File integrity check failed for '{entry.RelativePath}'. " +
                            $"Expected: {entry.FileHash}, Computed: {computedHash}");
                    }
                }
            }

            // Restore timestamps and file attributes
            try
            {
                if (entry.CreationTimeUtc > 0)
                {
                    File.SetCreationTimeUtc(targetPath, DateTime.FromFileTimeUtc(entry.CreationTimeUtc));
                }
                if (entry.LastWriteTimeUtc > 0)
                {
                    File.SetLastWriteTimeUtc(targetPath, DateTime.FromFileTimeUtc(entry.LastWriteTimeUtc));
                }
                if (entry.FileAttributes > 0)
                {
                    File.SetAttributes(targetPath, (FileAttributes)entry.FileAttributes);
                }
            }
            catch
            {
                // Ignore filesystem attribute restoration exceptions
            }

            report.FilesProcessed = fileIdx + 1;
            report.BytesProcessed = bytesRestored;
            progress?.Report(report);
        }

        report.FilesProcessed = manifest.Files.Count;
        report.BytesProcessed = (long)footer.TotalRawBytes;
        progress?.Report(report);
    }

    private async Task<byte[]> ResolveChunkAsync(
        FileStream fileStream,
        ChunkDescriptor[] cdt,
        uint chunkIndex,
        byte[] dictionary,
        Dictionary<uint, byte[]> chunkCache,
        int depth,
        HashSet<uint>? visited,
        CancellationToken ct)
    {
        if (chunkIndex >= (uint)cdt.Length)
        {
            throw new InvalidDataException($"Invalid chunk index {chunkIndex} (CDT size: {cdt.Length})");
        }

        if (depth > 32)
        {
            throw new InvalidDataException("Exceeded maximum delta chunk recursion depth (potential cycle or adversarial container).");
        }

        visited ??= new HashSet<uint>();
        if (!visited.Add(chunkIndex))
        {
            throw new InvalidDataException($"Cycle detected in delta chunk references: chunk index {chunkIndex} already visited.");
        }

        if (chunkCache.TryGetValue(chunkIndex, out var cached))
        {
            return cached;
        }

        var desc = cdt[chunkIndex];
        if (desc.PayloadOffset + desc.CompressedSize > (ulong)fileStream.Length)
        {
            throw new InvalidDataException($"Chunk payload offset {desc.PayloadOffset} + size {desc.CompressedSize} exceeds archive size {fileStream.Length}");
        }

        byte[] payload = new byte[desc.CompressedSize];

        fileStream.Position = (long)desc.PayloadOffset;
        await fileStream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);

        byte[] decompressed;
        bool isCompressed = (desc.Flags & (ushort)ChunkFlags.IsCompressed) != 0;
        bool isDelta = (desc.Flags & (ushort)ChunkFlags.IsDelta) != 0;
        bool usesDict = (desc.Flags & (ushort)ChunkFlags.UsesDictionary) != 0;

        if (isDelta && desc.BaseChunkIndex != 0xFFFFFFFF)
        {
            if (desc.BaseChunkIndex >= (uint)cdt.Length)
            {
                throw new InvalidDataException($"Invalid base chunk index {desc.BaseChunkIndex} (CDT size: {cdt.Length})");
            }

            byte[] baseChunk = await ResolveChunkAsync(
                fileStream,
                cdt,
                desc.BaseChunkIndex,
                dictionary,
                chunkCache,
                depth + 1,
                visited,
                ct).ConfigureAwait(false);

            decompressed = _compressor.DecompressDelta(payload, baseChunk);
        }
        else if (usesDict && dictionary.Length > 0)
        {
            decompressed = _compressor.Decompress(payload, dictionary);
        }
        else if (isCompressed)
        {
            decompressed = _compressor.Decompress(payload);
        }
        else
        {
            decompressed = payload;
        }

        if (chunkCache.Count < 2048)
        {
            chunkCache[chunkIndex] = decompressed;
        }

        return decompressed;
    }
}
