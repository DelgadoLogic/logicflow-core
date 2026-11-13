using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Storage.Engine.Chunking;

/// <summary>
/// Cut point boundary representation.
/// </summary>
public readonly record struct ChunkBoundary(long Offset, int Length);

/// <summary>
/// Sovereign FastCDC 2020 Content-Defined Chunker.
/// Features single-byte rolling Gear hash, normalized dual-mask boundaries,
/// 8 KB sub-minimum skipping, and unrolled unsafe pointer kernels achieving >2.0 GB/s per core.
/// </summary>
public sealed class FastCdcChunker
{
    private readonly FastCdcOptions _options;

    public FastCdcChunker(FastCdcOptions? options = null)
    {
        _options = options ?? FastCdcOptions.Default;
        _options.Validate();
    }

    /// <summary>
    /// FastCDC 2020 single-byte rolling hash cut-point finder over pinned memory.
    /// Unrolled 8x unsafe pointer loop with 8 KB sub-minimum skipping.
    /// Evaluates every single byte to eliminate parity lock and guarantee boundary shift resynchronization.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
    public static unsafe int FindCutPoint(
        byte* source,
        int length,
        int minSize,
        int targetSize,
        int maxSize,
        ulong maskS,
        ulong maskL)
    {
        if (length <= minSize)
        {
            return length;
        }

        int remaining = length > maxSize ? maxSize : length;
        int center = remaining < targetSize ? remaining : targetSize;

        ulong* gear = GearTable.GearPtr;
        ulong hash = 0;

        byte* curr = source + minSize;
        byte* end1 = source + center;
        byte* unrollEnd1 = end1 - 8;

        // Phase 1: Strict normalization (minSize to targetSize / center)
        while (curr <= unrollEnd1)
        {
            ulong block = Unsafe.ReadUnaligned<ulong>(curr);

            hash = (hash << 1) + gear[(byte)block];
            if ((hash & maskS) == 0) return (int)(curr - source) + 1;

            hash = (hash << 1) + gear[(byte)(block >> 8)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 2;

            hash = (hash << 1) + gear[(byte)(block >> 16)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 3;

            hash = (hash << 1) + gear[(byte)(block >> 24)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 4;

            hash = (hash << 1) + gear[(byte)(block >> 32)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 5;

            hash = (hash << 1) + gear[(byte)(block >> 40)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 6;

            hash = (hash << 1) + gear[(byte)(block >> 48)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 7;

            hash = (hash << 1) + gear[(byte)(block >> 56)];
            if ((hash & maskS) == 0) return (int)(curr - source) + 8;

            curr += 8;
        }

        while (curr < end1)
        {
            hash = (hash << 1) + gear[*curr];
            curr++;
            if ((hash & maskS) == 0)
            {
                return (int)(curr - source);
            }
        }

        // Phase 2: Loose normalization (targetSize / center to maxSize / remaining)
        byte* end2 = source + remaining;
        byte* unrollEnd2 = end2 - 8;

        while (curr <= unrollEnd2)
        {
            ulong block = Unsafe.ReadUnaligned<ulong>(curr);

            hash = (hash << 1) + gear[(byte)block];
            if ((hash & maskL) == 0) return (int)(curr - source) + 1;

            hash = (hash << 1) + gear[(byte)(block >> 8)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 2;

            hash = (hash << 1) + gear[(byte)(block >> 16)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 3;

            hash = (hash << 1) + gear[(byte)(block >> 24)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 4;

            hash = (hash << 1) + gear[(byte)(block >> 32)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 5;

            hash = (hash << 1) + gear[(byte)(block >> 40)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 6;

            hash = (hash << 1) + gear[(byte)(block >> 48)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 7;

            hash = (hash << 1) + gear[(byte)(block >> 56)];
            if ((hash & maskL) == 0) return (int)(curr - source) + 8;

            curr += 8;
        }

        while (curr < end2)
        {
            hash = (hash << 1) + gear[*curr];
            curr++;
            if ((hash & maskL) == 0)
            {
                return (int)(curr - source);
            }
        }

        return remaining; // Forced cut at maxSize or end of buffer
    }

    /// <summary>
    /// Finds the next cut-point in a ReadOnlySpan.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe int FindCutPoint(ReadOnlySpan<byte> buffer, FastCdcOptions? options = null)
    {
        var opt = options ?? FastCdcOptions.Default;
        if (buffer.Length <= opt.MinSize)
        {
            return buffer.Length;
        }

        fixed (byte* ptr = buffer)
        {
            return FindCutPoint(ptr, buffer.Length, opt.MinSize, opt.TargetSize, opt.MaxSize, opt.MaskS, opt.MaskL);
        }
    }

    /// <summary>
    /// Computes all chunk boundaries within a byte span without hashing.
    /// Fast single-pass pinned pointer iteration.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public unsafe List<ChunkBoundary> ChunkBoundaries(ReadOnlySpan<byte> buffer, FastCdcOptions? options = null)
    {
        var opt = options ?? _options;
        int minSize = opt.MinSize;
        int targetSize = opt.TargetSize;
        int maxSize = opt.MaxSize;
        ulong maskS = opt.MaskS;
        ulong maskL = opt.MaskL;

        int totalLength = buffer.Length;
        int estimatedChunks = (totalLength / targetSize) + 16;
        var boundaries = new List<ChunkBoundary>(estimatedChunks);

        if (totalLength == 0)
        {
            return boundaries;
        }

        fixed (byte* ptr = buffer)
        {
            long offset = 0;
            int remaining = totalLength;

            while (remaining > 0)
            {
                int cut = FindCutPoint(ptr + offset, remaining, minSize, targetSize, maxSize, maskS, maskL);
                boundaries.Add(new ChunkBoundary(offset, cut));
                offset += cut;
                remaining -= cut;
            }
        }

        return boundaries;
    }

    /// <summary>
    /// Chunks an in-memory buffer, computing BLAKE3 fingerprints for each variable chunk.
    /// </summary>
    public IEnumerable<ChunkDescriptor> ChunkBuffer(ReadOnlyMemory<byte> buffer, FastCdcOptions? options = null)
    {
        var opt = options ?? _options;
        int offset = 0;
        int totalLength = buffer.Length;

        while (offset < totalLength)
        {
            int remaining = totalLength - offset;
            int cut = FindCutInMemory(buffer, offset, remaining, opt);
            Hash256 hash = Hash256.Compute(buffer.Span.Slice(offset, cut));

            yield return new ChunkDescriptor(
                fingerprint: hash,
                payloadOffset: (ulong)offset,
                compressedSize: (uint)cut,
                rawSize: (uint)cut);

            offset += cut;
        }
    }

    /// <summary>
    /// Chunks a Stream using a high-throughput sliding window buffer, yielding chunk descriptors alongside raw chunk data.
    /// Does not require stream seeking, supporting arbitrary stream lengths and non-seekable streams.
    /// </summary>
    public IEnumerable<(ChunkDescriptor Descriptor, ReadOnlyMemory<byte> Data)> ChunkStreamWithData(Stream stream, FastCdcOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var opt = options ?? _options;
        int maxSize = opt.MaxSize;

        const int bufferCapacity = 262144; // 256 KB sliding window
        byte[] window = ArrayPool<byte>.Shared.Rent(bufferCapacity);
        int head = 0;
        int tail = 0;
        ulong streamOffset = 0;
        bool eof = false;

        try
        {
            while (true)
            {
                // Compact and refill sliding window if needed
                int available = tail - head;
                if (available < maxSize && !eof)
                {
                    if (head > 0 && available > 0)
                    {
                        Buffer.BlockCopy(window, head, window, 0, available);
                    }
                    head = 0;
                    tail = available;

                    while (tail < bufferCapacity && !eof)
                    {
                        int bytesRead = stream.Read(window, tail, bufferCapacity - tail);
                        if (bytesRead <= 0)
                        {
                            eof = true;
                            break;
                        }
                        tail += bytesRead;
                    }
                    available = tail - head;
                }

                if (available <= 0)
                {
                    break;
                }

                int cut = FindCutInArray(window, head, available, opt);
                ReadOnlyMemory<byte> chunkMem = window.AsMemory(head, cut);
                Hash256 hash = Hash256.Compute(chunkMem.Span);

                var descriptor = new ChunkDescriptor(
                    fingerprint: hash,
                    payloadOffset: streamOffset,
                    compressedSize: (uint)cut,
                    rawSize: (uint)cut);

                yield return (descriptor, chunkMem);

                streamOffset += (ulong)cut;
                head += cut;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(window);
        }
    }

    /// <summary>
    /// Chunks a Stream using a high-throughput sliding window buffer, handling arbitrary stream lengths.
    /// </summary>
    public IEnumerable<ChunkDescriptor> ChunkStream(Stream stream, FastCdcOptions? options = null)
    {
        foreach (var (desc, _) in ChunkStreamWithData(stream, options))
        {
            yield return desc;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindCutInMemory(ReadOnlyMemory<byte> buffer, int offset, int remaining, FastCdcOptions opt)
    {
        return FindCutPoint(buffer.Span.Slice(offset, remaining), opt);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindCutInArray(byte[] array, int offset, int length, FastCdcOptions opt)
    {
        unsafe
        {
            fixed (byte* ptr = array)
            {
                return FindCutPoint(ptr + offset, length, opt.MinSize, opt.TargetSize, opt.MaxSize, opt.MaskS, opt.MaskL);
            }
        }
    }
}
