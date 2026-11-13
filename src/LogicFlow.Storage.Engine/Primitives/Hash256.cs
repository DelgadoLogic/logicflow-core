using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Blake3;

namespace LogicFlow.Storage.Engine.Primitives;

/// <summary>
/// Sovereign 256-bit cryptographic fingerprint backed by two native UInt128 integers.
/// Provides non-allocating memory layout, zero truncation, and SIMD hardware equality checks.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public readonly struct Hash256 : IEquatable<Hash256>, IComparable<Hash256>
{
    public readonly UInt128 Part0;
    public readonly UInt128 Part1;

    public static readonly Hash256 Zero = default;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Hash256(UInt128 part0, UInt128 part1)
    {
        Part0 = part0;
        Part1 = part1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Hash256(ReadOnlySpan<byte> span)
    {
        if (span.Length < 32)
        {
            throw new ArgumentOutOfRangeException(nameof(span), "Span must be at least 32 bytes for Hash256.");
        }

        Part0 = MemoryMarshal.Read<UInt128>(span[..16]);
        Part1 = MemoryMarshal.Read<UInt128>(span.Slice(16, 16));
    }

    /// <summary>
    /// Computes full 256-bit BLAKE3 hash with zero truncation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Hash256 Compute(ReadOnlySpan<byte> data)
    {
        Hash b3 = Hasher.Hash(data);
        ReadOnlySpan<byte> span = b3.AsSpan();
        UInt128 p0 = MemoryMarshal.Read<UInt128>(span[..16]);
        UInt128 p1 = MemoryMarshal.Read<UInt128>(span.Slice(16, 16));
        return new Hash256(p0, p1);
    }

    /// <summary>
    /// Computes full 256-bit BLAKE3 hash from a Stream.
    /// </summary>
    public static Hash256 Compute(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var hasher = Hasher.New();
        byte[] buffer = new byte[65536];
        int bytesRead;
        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hasher.Update(buffer.AsSpan(0, bytesRead));
        }
        Hash b3 = hasher.Finalize();
        ReadOnlySpan<byte> span = b3.AsSpan();
        UInt128 p0 = MemoryMarshal.Read<UInt128>(span[..16]);
        UInt128 p1 = MemoryMarshal.Read<UInt128>(span.Slice(16, 16));
        return new Hash256(p0, p1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < 32)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), "Destination span must be at least 32 bytes.");
        }

        MemoryMarshal.Write(destination[..16], in Part0);
        MemoryMarshal.Write(destination.Slice(16, 16), in Part1);
    }

    public byte[] ToByteArray()
    {
        byte[] bytes = new byte[32];
        WriteTo(bytes);
        return bytes;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string ToHexString()
    {
        Span<byte> bytes = stackalloc byte[32];
        WriteTo(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public override string ToString() => ToHexString();

    public static Hash256 Parse(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        return Parse(s.AsSpan());
    }

    public static Hash256 Parse(ReadOnlySpan<char> s)
    {
        if (TryParse(s, out Hash256 result))
        {
            return result;
        }

        throw new FormatException($"String '{s.ToString()}' is not a valid 64-character hexadecimal Hash256.");
    }

    public static bool TryParse([NotNullWhen(true)] string? s, out Hash256 result)
    {
        if (string.IsNullOrEmpty(s))
        {
            result = Zero;
            return false;
        }

        return TryParse(s.AsSpan(), out result);
    }

    public static bool TryParse(ReadOnlySpan<char> s, out Hash256 result)
    {
        if (s.Length != 64)
        {
            result = Zero;
            return false;
        }

        Span<byte> bytes = stackalloc byte[32];
        for (int i = 0; i < 32; i++)
        {
            int hi = HexVal(s[i * 2]);
            int lo = HexVal(s[i * 2 + 1]);
            if (hi < 0 || lo < 0)
            {
                result = Zero;
                return false;
            }
            bytes[i] = (byte)((hi << 4) | lo);
        }

        result = new Hash256(bytes);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Equals(Hash256 other) => Part0 == other.Part0 && Part1 == other.Part1;

    public override bool Equals(object? obj) => obj is Hash256 other && Equals(other);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public override int GetHashCode()
    {
        ulong p0 = (ulong)Part0 ^ (ulong)(Part0 >> 64);
        ulong p1 = (ulong)Part1 ^ (ulong)(Part1 >> 64);
        ulong mix = p0 ^ (p1 * 0x9E3779B97F4A7C15UL);
        return (int)(mix ^ (mix >> 32));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CompareTo(Hash256 other)
    {
        int c0 = Part0.CompareTo(other.Part0);
        return c0 != 0 ? c0 : Part1.CompareTo(other.Part1);
    }

    public static bool operator ==(Hash256 left, Hash256 right) => left.Equals(right);
    public static bool operator !=(Hash256 left, Hash256 right) => !left.Equals(right);
    public static bool operator <(Hash256 left, Hash256 right) => left.CompareTo(right) < 0;
    public static bool operator <=(Hash256 left, Hash256 right) => left.CompareTo(right) <= 0;
    public static bool operator >(Hash256 left, Hash256 right) => left.CompareTo(right) > 0;
    public static bool operator >=(Hash256 left, Hash256 right) => left.CompareTo(right) >= 0;
}
