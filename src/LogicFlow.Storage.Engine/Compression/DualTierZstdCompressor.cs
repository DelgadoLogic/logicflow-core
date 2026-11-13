using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace LogicFlow.Storage.Engine.Compression;

public enum CompressionTier
{
    Hot = 3,
    Cold = 19
}

/// <summary>
/// Dual-Tier Zstandard compression subsystem.
/// Implements Hot L3 real-time compression, Cold L19 deep compression with trained dictionaries,
/// and prefix delta-compression for near-duplicate chunks.
/// </summary>
public sealed class DualTierZstdCompressor
{
    public const int DefaultHotLevel = 3;
    public const int DefaultColdLevel = 19;
    public const int DefaultDictionarySize = 112 * 1024; // 112 KB

    public static DualTierZstdCompressor Instance { get; } = new();

    /// <summary>
    /// Trains a custom domain-specific Zstandard dictionary from sample chunks using ZDICT_trainFromBuffer.
    /// </summary>
    public static unsafe byte[] TrainDictionary(IReadOnlyList<byte[]> samples, int maxDictSize = DefaultDictionarySize)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (samples.Count == 0)
        {
            return [];
        }

        // Calculate total sample buffer size
        long totalBytes = 0;
        foreach (var sample in samples)
        {
            totalBytes += sample.Length;
        }

        if (totalBytes < 1024)
        {
            // Insufficient sample entropy to train a robust dictionary
            return [];
        }

        byte[] samplesBuffer = new byte[totalBytes];
        nuint[] sampleSizes = new nuint[samples.Count];
        int writePos = 0;

        for (int i = 0; i < samples.Count; i++)
        {
            byte[] s = samples[i];
            Buffer.BlockCopy(s, 0, samplesBuffer, writePos, s.Length);
            writePos += s.Length;
            sampleSizes[i] = (nuint)s.Length;
        }

        byte[] dictBuffer = new byte[maxDictSize];

        fixed (void* pDict = dictBuffer)
        fixed (void* pSamples = samplesBuffer)
        fixed (nuint* pSizes = sampleSizes)
        {
            nuint dictResult = Methods.ZDICT_trainFromBuffer(
                pDict,
                (nuint)maxDictSize,
                pSamples,
                pSizes,
                (uint)samples.Count);

            if (Methods.ZDICT_isError(dictResult))
            {
                // Return empty if dictionary training failed (e.g. insufficient samples)
                return [];
            }

            int dictSize = (int)dictResult;
            byte[] finalDict = new byte[dictSize];
            Buffer.BlockCopy(dictBuffer, 0, finalDict, 0, dictSize);
            return finalDict;
        }
    }

    /// <summary>
    /// Compresses data using Hot Tier (Level 3 real-time).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] CompressHot(ReadOnlySpan<byte> data)
    {
        using var compressor = new Compressor(DefaultHotLevel);
        return compressor.Wrap(data).ToArray();
    }

    /// <summary>
    /// Compresses data using Cold Tier (Level 19 deep archive) with optional trained dictionary.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] CompressCold(ReadOnlySpan<byte> data, ReadOnlySpan<byte> dictionary = default)
    {
        using var compressor = new Compressor(DefaultColdLevel);
        if (!dictionary.IsEmpty)
        {
            compressor.LoadDictionary(dictionary);
        }
        return compressor.Wrap(data).ToArray();
    }

    /// <summary>
    /// Compresses data using prefix delta-compression against a reference base chunk.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] CompressDelta(ReadOnlySpan<byte> data, ReadOnlySpan<byte> baseChunk, int level = DefaultColdLevel)
    {
        if (baseChunk.IsEmpty)
        {
            return CompressCold(data);
        }

        using var compressor = new Compressor(level);
        compressor.LoadDictionary(baseChunk);
        return compressor.Wrap(data).ToArray();
    }

    /// <summary>
    /// Decompresses data with optional dictionary.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] Decompress(ReadOnlySpan<byte> compressed, ReadOnlySpan<byte> dictionary = default)
    {
        using var decompressor = new Decompressor();
        if (!dictionary.IsEmpty)
        {
            decompressor.LoadDictionary(dictionary);
        }
        return decompressor.Unwrap(compressed).ToArray();
    }

    /// <summary>
    /// Decompresses delta-compressed data using the reference base chunk.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] DecompressDelta(ReadOnlySpan<byte> compressed, ReadOnlySpan<byte> baseChunk)
    {
        if (baseChunk.IsEmpty)
        {
            return Decompress(compressed);
        }

        using var decompressor = new Decompressor();
        decompressor.LoadDictionary(baseChunk);
        return decompressor.Unwrap(compressed).ToArray();
    }

    /// <summary>
    /// Decompresses data into an existing destination span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DecompressTo(ReadOnlySpan<byte> compressed, Span<byte> destination, ReadOnlySpan<byte> dictionary = default)
    {
        using var decompressor = new Decompressor();
        if (!dictionary.IsEmpty)
        {
            decompressor.LoadDictionary(dictionary);
        }
        return decompressor.Unwrap(compressed, destination);
    }
}
