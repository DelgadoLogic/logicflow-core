using System;

namespace LogicFlow.Storage.Engine.Chunking;

/// <summary>
/// Configuration options for FastCDC variable chunking.
/// Default settings align with FastCDC 2020 normalized 32 KB chunking (8 KB min, 64 KB max).
/// </summary>
public sealed class FastCdcOptions
{
    public int MinSize { get; set; } = 8192;
    public int TargetSize { get; set; } = 32768;
    public int MaxSize { get; set; } = 65536;

    /// <summary>
    /// Strict mask applied between MinSize and TargetSize (16-bit strict mask).
    /// </summary>
    public ulong MaskS { get; set; } = 0x0000d90303537000UL;

    /// <summary>
    /// Loose mask applied between TargetSize and MaxSize (14-bit loose mask).
    /// </summary>
    public ulong MaskL { get; set; } = 0x0000d90313530000UL;

    public static FastCdcOptions Default { get; } = new();

    public void Validate()
    {
        if (MinSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(MinSize), "MinSize must be positive.");
        if (TargetSize <= MinSize)
            throw new ArgumentOutOfRangeException(nameof(TargetSize), "TargetSize must be greater than MinSize.");
        if (MaxSize <= TargetSize)
            throw new ArgumentOutOfRangeException(nameof(MaxSize), "MaxSize must be greater than TargetSize.");
    }
}
