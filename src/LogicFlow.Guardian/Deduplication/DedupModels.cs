// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Host Deduplication Data Models & Options
// Proprietary implementation by DelgadoLogic.Tech
// Contracts and telemetry representations for Volume-Aware Host Deduplication
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;

namespace LogicFlow.Guardian.Deduplication;

/// <summary>
/// Execution options for host deduplication operations.
/// </summary>
public sealed class DedupOptions
{
    /// <summary>
    /// If true, simulate deduplication and report actions without making physical modifications.
    /// </summary>
    public bool DryRun { get; set; } = false;

    /// <summary>
    /// If true, allows hard linking mutable working documents on NTFS (default: false for data safety).
    /// </summary>
    public bool AllowMutableHardLinks { get; set; } = false;

    /// <summary>
    /// If true, routes cross-volume duplicate clusters to .lfc container deduplication (default: true).
    /// </summary>
    public bool EnableCrossVolumeLfcFallback { get; set; } = true;

    /// <summary>
    /// Custom output path for cross-volume .lfc archive. If null, placed inside target folder or temp.
    /// </summary>
    public string? CrossVolumeContainerPath { get; set; }

    /// <summary>
    /// Minimum age required before a file is eligible for NTFS hard linking (default: null).
    /// </summary>
    public TimeSpan? MinFileAge { get; set; }

    /// <summary>
    /// Minimum file size in bytes to consider for deduplication (default: 1 byte, skips empty files).
    /// </summary>
    public long MinFileSizeBytes { get; set; } = 1;

    /// <summary>
    /// If true, sets the ReadOnly attribute on consolidated NTFS hard links (default: false).
    /// </summary>
    public bool SetReadOnlyOnHardLink { get; set; } = false;

    /// <summary>
    /// Optional directory/file paths excluded from deduplication (matched on strict path boundaries).
    /// </summary>
    public IReadOnlyList<string>? ExcludedPaths { get; set; }

    public static DedupOptions Default => new();
}

/// <summary>
/// Deduplication method applied to a duplicate pair.
/// </summary>
public enum DedupMethod
{
    None,
    RefsBlockClone,
    NtfsHardLink,
    CrossVolumeLfc,
    PreservedMutable,
    SkippedIdenticalLink
}

/// <summary>
/// Telemetry record for an individual duplicate consolidation operation.
/// </summary>
public sealed record DedupItemResult(
    string SourcePath,
    string TargetPath,
    long BytesReclaimed,
    DedupMethod Method,
    bool Success,
    string? ErrorMessage = null
);

/// <summary>
/// Real-time progress report emitted during deduplication passes.
/// </summary>
public sealed class DedupProgress
{
    public int FilesScanned { get; set; }
    public int TotalFiles { get; set; }
    public int DuplicateClustersFound { get; set; }
    public int DuplicatesProcessed { get; set; }
    public long BytesReclaimed { get; set; }
    public string CurrentOperation { get; set; } = string.Empty;
    public string CurrentFile { get; set; } = string.Empty;
}

/// <summary>
/// Final result summary of a deduplication run.
/// </summary>
public sealed class DedupResult
{
    public int TotalFilesScanned { get; set; }
    public int DuplicateClustersFound { get; set; }
    public int DuplicatesConsolidated { get; set; }
    public int MutableFilesPreserved { get; set; }
    public int CrossVolumeFilesHandled { get; set; }
    public long TotalBytesReclaimed { get; set; }
    public List<DedupItemResult> Items { get; } = new();
    public List<string> Warnings { get; } = new();
    public List<string> Errors { get; } = new();
    public string? CrossVolumeLfcPath { get; set; }
}
