using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Storage.Engine.Chunking;
using LogicFlow.Storage.Engine.Clustering;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Container;

/// <summary>
/// Sovereign .lfc v1.0 Container Writer.
/// Implements high-throughput content-defined chunking, deduplication, MinHash delta clustering,
/// dual-tier Zstandard compression, and crash-resilient header/footer binary archive generation.
/// </summary>
public sealed class LfcWriter : IDisposable
{
    private readonly DualTierZstdCompressor _compressor = DualTierZstdCompressor.Instance;
    private readonly MinHashClusterer _clusterer = MinHashClusterer.Instance;
    private readonly FastCdcChunker _chunker = new();

    public void Dispose()
    {
    }

    /// <summary>
    /// Packs an entire directory into a sovereign .lfc binary archive.
    /// </summary>
    public async Task PackDirectoryAsync(
        string sourceDir,
        string lfcPath,
        LfcPackOptions? options = null,
        IProgress<HyperStoreProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(lfcPath);

        if (!Directory.Exists(sourceDir))
        {
            throw new DirectoryNotFoundException($"Source directory not found: {sourceDir}");
        }

        var opt = options ?? LfcPackOptions.Default;
        string fullSource = Path.GetFullPath(sourceDir);
        if (IsExcludedByPathBoundary(fullSource, opt.ExcludedPaths))
        {
            throw new InvalidOperationException($"Source directory '{fullSource}' is excluded by ScanExclusions.");
        }

        string[] allFiles = Directory.GetFiles(fullSource, "*", SearchOption.AllDirectories);
        if (opt.ExcludedPaths is { Count: > 0 })
        {
            var filtered = new List<string>(allFiles.Length);
            foreach (var f in allFiles)
            {
                if (!IsExcludedByPathBoundary(f, opt.ExcludedPaths))
                {
                    filtered.Add(f);
                }
            }
            allFiles = filtered.ToArray();
        }

        long totalBytes = 0;
        foreach (var file in allFiles)
        {
            totalBytes += new FileInfo(file).Length;
        }

        string? dirName = Path.GetDirectoryName(lfcPath);
        if (!string.IsNullOrEmpty(dirName))
        {
            Directory.CreateDirectory(dirName);
        }

        // Dictionary training phase if requested
        byte[] trainedDict = [];
        if (opt.TrainDictionary && allFiles.Length > 0)
        {
            trainedDict = await CollectAndTrainDictionaryAsync(allFiles, opt.MaxDictionarySize, ct).ConfigureAwait(false);
        }

        await using var fileStream = new FileStream(
            lfcPath,
            FileMode.Create,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 131072,
            FileOptions.Asynchronous);

        // Reserve 64 bytes for LfcHeader
        byte[] blankHeader = new byte[LfcHeader.SizeInBytes];
        await fileStream.WriteAsync(blankHeader, ct).ConfigureAwait(false);

        // Optional embedded dictionary segment directly following header
        ulong dictOffset = 0;
        if (trainedDict.Length > 0)
        {
            dictOffset = (ulong)fileStream.Position;
            await fileStream.WriteAsync(trainedDict, ct).ConfigureAwait(false);
        }

        // Deduplication tables
        var chunkIndexMap = new Dictionary<Hash256, uint>(allFiles.Length * 4);
        var chunkTable = new List<ChunkDescriptor>(allFiles.Length * 4);
        var baseChunks = new Dictionary<ulong, (uint Index, byte[] Data)>();
        var manifest = new LfcStreamManifest { Files = new List<LfcFileEntry>(allFiles.Length) };

        long bytesProcessed = 0;
        long deduplicatedBytes = 0;
        long compressedBytesStored = 0;
        int totalChunksEncountered = 0;

        var report = new HyperStoreProgressReport
        {
            TotalFiles = allFiles.Length,
            TotalBytes = totalBytes
        };

        for (int fileIdx = 0; fileIdx < allFiles.Length; fileIdx++)
        {
            ct.ThrowIfCancellationRequested();
            string filePath = allFiles[fileIdx];
            var fileInfo = new FileInfo(filePath);
            string relativePath = Path.GetRelativePath(fullSource, filePath);

            report.CurrentFile = relativePath;
            report.FilesProcessed = fileIdx;
            report.BytesProcessed = bytesProcessed;
            progress?.Report(report);

            Hash256 fileHash;
            var fileChunkIndices = new List<uint>();

            await using (var srcStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan))
            {
                fileHash = Hash256.Compute(srcStream);
                srcStream.Position = 0;

                // Chunk file content
                foreach (var (chunk, chunkMemory) in _chunker.ChunkStreamWithData(srcStream))
                {
                    ct.ThrowIfCancellationRequested();
                    totalChunksEncountered++;
                    uint rawSize = chunk.RawSize;

                    if (chunkIndexMap.TryGetValue(chunk.Fingerprint, out uint existingIndex))
                    {
                        // Duplicate chunk detected — consolidate with zero storage waste
                        fileChunkIndices.Add(existingIndex);
                        deduplicatedBytes += rawSize;
                        bytesProcessed += rawSize;
                        continue;
                    }

                    // New unique chunk — copy from sliding window memory (no disk seek!)
                    byte[] rawChunk = chunkMemory.ToArray();

                    // Compute MinHash signature for delta-clustering
                    var sig = _clusterer.ComputeSignature(rawChunk);
                    ulong primaryFeature = sig.S0;

                    byte[] finalPayload;
                    ushort flags = 0;
                    uint baseChunkIndex = 0xFFFFFFFF;

                    // Check for near-duplicate base chunk candidate
                    if (opt.EnableDeltaCompression && baseChunks.TryGetValue(primaryFeature, out var baseCandidate))
                    {
                        byte[] deltaPayload = _compressor.CompressDelta(rawChunk, baseCandidate.Data, (int)opt.Tier);
                        if (deltaPayload.Length < rawChunk.Length)
                        {
                            finalPayload = deltaPayload;
                            flags = (ushort)(ChunkFlags.IsCompressed | ChunkFlags.IsDelta);
                            baseChunkIndex = baseCandidate.Index;
                        }
                        else
                        {
                            finalPayload = rawChunk;
                        }
                    }
                    else
                    {
                        // Standard Hot or Cold compression
                        byte[] compPayload;
                        if (trainedDict.Length > 0)
                        {
                            compPayload = _compressor.CompressCold(rawChunk, trainedDict);
                            flags = (ushort)(ChunkFlags.IsCompressed | ChunkFlags.UsesDictionary);
                        }
                        else if (opt.Tier == CompressionTier.Hot)
                        {
                            compPayload = _compressor.CompressHot(rawChunk);
                            flags = (ushort)ChunkFlags.IsCompressed;
                        }
                        else
                        {
                            compPayload = _compressor.CompressCold(rawChunk);
                            flags = (ushort)ChunkFlags.IsCompressed;
                        }

                        if (compPayload.Length < rawChunk.Length)
                        {
                            finalPayload = compPayload;
                        }
                        else
                        {
                            finalPayload = rawChunk;
                            flags = (ushort)ChunkFlags.None;
                        }
                    }

                    ulong payloadOffset = (ulong)fileStream.Position;
                    await fileStream.WriteAsync(finalPayload, ct).ConfigureAwait(false);

                    uint newChunkIndex = (uint)chunkTable.Count;
                    var descriptor = new ChunkDescriptor(
                        fingerprint: chunk.Fingerprint,
                        payloadOffset: payloadOffset,
                        compressedSize: (uint)finalPayload.Length,
                        rawSize: rawSize,
                        flags: flags,
                        baseChunkIndex: baseChunkIndex,
                        minHashFeature: primaryFeature);

                    chunkTable.Add(descriptor);
                    chunkIndexMap[chunk.Fingerprint] = newChunkIndex;
                    fileChunkIndices.Add(newChunkIndex);

                    if (opt.EnableDeltaCompression && !baseChunks.ContainsKey(primaryFeature) && baseChunks.Count < 2048)
                    {
                        baseChunks[primaryFeature] = (newChunkIndex, rawChunk);
                    }

                    compressedBytesStored += finalPayload.Length;
                    bytesProcessed += rawSize;
                }
            }

            manifest.Files.Add(new LfcFileEntry
            {
                RelativePath = relativePath,
                FileAttributes = (uint)fileInfo.Attributes,
                CreationTimeUtc = fileInfo.CreationTimeUtc.ToFileTimeUtc(),
                LastWriteTimeUtc = fileInfo.LastWriteTimeUtc.ToFileTimeUtc(),
                FileRawSizeBytes = (ulong)fileInfo.Length,
                FileHash = fileHash,
                ChunkIndices = fileChunkIndices.ToArray()
            });

            report.FilesProcessed = fileIdx + 1;
            report.BytesProcessed = bytesProcessed;
            report.UniqueChunks = chunkTable.Count;
            report.TotalChunks = totalChunksEncountered;
            report.DeduplicatedBytes = deduplicatedBytes;
            report.CompressedBytes = compressedBytesStored;
            progress?.Report(report);
        }

        // Write Chunk Descriptor Table (CDT)
        ulong chunkTableOffset = (ulong)fileStream.Position;
        byte[] cdtBuffer = new byte[chunkTable.Count * ChunkDescriptor.SizeInBytes];
        for (int i = 0; i < chunkTable.Count; i++)
        {
            var desc = chunkTable[i];
            MemoryMarshal.Write(cdtBuffer.AsSpan(i * ChunkDescriptor.SizeInBytes, ChunkDescriptor.SizeInBytes), in desc);
        }
        await fileStream.WriteAsync(cdtBuffer, ct).ConfigureAwait(false);
        uint chunkTableLength = (uint)cdtBuffer.Length;

        // Write Stream Manifest
        ulong manifestOffset = (ulong)fileStream.Position;
        byte[] manifestBytes = manifest.ToByteArray();
        await fileStream.WriteAsync(manifestBytes, ct).ConfigureAwait(false);
        uint manifestLength = (uint)manifestBytes.Length;

        // Prepare and write LfcFooter (64 bytes)
        var footer = LfcFooter.CreateDefault();
        footer.TotalFiles = (uint)manifest.Files.Count;
        footer.TotalUniqueChunks = (uint)chunkTable.Count;
        footer.TotalRawBytes = (ulong)totalBytes;
        footer.TotalCompressedBytes = (ulong)compressedBytesStored;
        footer.ChunkTableOffset = chunkTableOffset;
        footer.ManifestOffset = manifestOffset;
        footer.DictOffset = dictOffset;
        footer.DictLength = (uint)trainedDict.Length;
        footer.FinalizeChecksum();

        byte[] footerBytes = new byte[LfcFooter.SizeInBytes];
        MemoryMarshal.Write(footerBytes.AsSpan(), in footer);
        await fileStream.WriteAsync(footerBytes, ct).ConfigureAwait(false);

        // Prepare and write LfcHeader at offset 0
        fileStream.Position = 0;
        uint headerFlags = (uint)LfcHeaderFlags.Finalized;
        if (trainedDict.Length > 0) headerFlags |= (uint)LfcHeaderFlags.HasDictionary;
        if (opt.Tier == CompressionTier.Cold) headerFlags |= (uint)LfcHeaderFlags.ColdTierL19;

        var header = LfcHeader.CreateDefault(headerFlags);
        header.ChunkTableOffset = chunkTableOffset;
        header.ChunkTableLength = chunkTableLength;
        header.ManifestOffset = manifestOffset;
        header.ManifestLength = manifestLength;
        header.DictLength = (uint)trainedDict.Length;
        header.FinalizeChecksum();

        byte[] headerBytes = new byte[LfcHeader.SizeInBytes];
        MemoryMarshal.Write(headerBytes.AsSpan(), in header);
        await fileStream.WriteAsync(headerBytes, ct).ConfigureAwait(false);

        await fileStream.FlushAsync(ct).ConfigureAwait(false);

        report.FilesProcessed = allFiles.Length;
        report.BytesProcessed = totalBytes;
        report.UniqueChunks = chunkTable.Count;
        report.TotalChunks = totalChunksEncountered;
        report.DeduplicatedBytes = deduplicatedBytes;
        report.CompressedBytes = compressedBytesStored;
        progress?.Report(report);
    }

    private static async Task<byte[]> CollectAndTrainDictionaryAsync(string[] allFiles, int maxDictSize, CancellationToken ct)
    {
        var sampleChunks = new List<byte[]>();
        long sampleBytes = 0;
        const long maxSampleSize = 2 * 1024 * 1024; // 2 MB sample target

        foreach (var file in allFiles)
        {
            if (sampleBytes >= maxSampleSize) break;
            try
            {
                byte[] data = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false);
                if (data.Length > 0)
                {
                    int take = Math.Min(data.Length, 32768);
                    byte[] sample = new byte[take];
                    Buffer.BlockCopy(data, 0, sample, 0, take);
                    sampleChunks.Add(sample);
                    sampleBytes += take;
                }
            }
            catch
            {
                // Ignore transient file read errors during sample collection
            }
        }

        if (sampleChunks.Count < 5 || sampleBytes < 32768)
        {
            return [];
        }

        return DualTierZstdCompressor.TrainDictionary(sampleChunks, maxDictSize);
    }

    public static bool IsExcludedByPathBoundary(string? candidatePath, IEnumerable<string>? exclusions)
    {
        if (string.IsNullOrWhiteSpace(candidatePath) || exclusions == null)
            return false;

        string normalizedCandidate = candidatePath.Replace('/', '\\').TrimEnd('\\');
        foreach (var raw in exclusions)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            string normalizedEx = raw.Trim().Replace('/', '\\').TrimEnd('\\');
            if (normalizedEx.Length == 0)
                continue;

            if (normalizedCandidate.Equals(normalizedEx, StringComparison.OrdinalIgnoreCase))
                return true;

            if (normalizedCandidate.Length > normalizedEx.Length &&
                normalizedCandidate.StartsWith(normalizedEx, StringComparison.OrdinalIgnoreCase) &&
                normalizedCandidate[normalizedEx.Length] == '\\')
            {
                return true;
            }
        }
        return false;
    }
}
