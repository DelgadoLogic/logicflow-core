using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace LogicFlow.Storage.Engine.Compression;

/// <summary>
/// Fast Castagnoli CRC32C (polynomial 0x82F63B78) implementation with hardware SSE4.2 acceleration fallback to table lookup.
/// </summary>
public static class Crc32c
{
    private const uint Poly = 0x82F63B78;
    private static readonly uint[] Table = new uint[256];

    static Crc32c()
    {
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ Poly : crc >> 1;
            }
            Table[i] = crc;
        }
    }

    /// <summary>
    /// Computes CRC32C checksum of a byte span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;

        if (Sse42.X64.IsSupported && data.Length >= 8)
        {
            int i = 0;
            int limit = data.Length - 8;
            while (i <= limit)
            {
                ulong val = BitConverter.ToUInt64(data.Slice(i, 8));
                crc = (uint)Sse42.X64.Crc32(crc, val);
                i += 8;
            }

            while (i < data.Length)
            {
                crc = Sse42.Crc32(crc, data[i]);
                i++;
            }

            return ~crc;
        }

        if (Sse42.IsSupported && data.Length >= 4)
        {
            int i = 0;
            int limit = data.Length - 4;
            while (i <= limit)
            {
                uint val = BitConverter.ToUInt32(data.Slice(i, 4));
                crc = Sse42.Crc32(crc, val);
                i += 4;
            }

            while (i < data.Length)
            {
                crc = Sse42.Crc32(crc, data[i]);
                i++;
            }

            return ~crc;
        }

        for (int i = 0; i < data.Length; i++)
        {
            crc = Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }

        return ~crc;
    }
}
