// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Background Storage Worker Models & Contracts
// Proprietary implementation by DelgadoLogic.Tech
// Enums, settings, and antivirus-style telemetry events for HyperStore Background Worker
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using LogicFlow.Guardian.Deduplication;

namespace LogicFlow.Guardian.Worker;

/// <summary>
/// Operational modes for the autonomous background storage worker.
/// </summary>
public enum WorkerExecutionMode
{
    /// <summary>
    /// Executes continuously at low thread and disk I/O priority whenever the system is idle and on AC power.
    /// </summary>
    ContinuousLowPriority,

    /// <summary>
    /// Executes exclusively within a designated daily time window (e.g., 02:00 AM - 06:00 AM).
    /// </summary>
    ScheduledWindow,

    /// <summary>
    /// Background autonomous triggers are disabled; optimization runs only upon explicit user trigger.
    /// </summary>
    ManualOnly
}

/// <summary>
/// Current state of the autonomous background storage worker state machine.
/// </summary>
public enum WorkerState
{
    /// <summary>
    /// Worker is stopped and inactive.
    /// </summary>
    Stopped,

    /// <summary>
    /// Worker is active and waiting for system idle conditions (>5 min, AC power).
    /// </summary>
    WaitingForIdle,

    /// <summary>
    /// Worker is actively scanning and optimizing storage.
    /// </summary>
    Optimizing,

    /// <summary>
    /// Storage operations are suspended because a full-screen game or high GPU workload is active.
    /// </summary>
    SuspendedByGameGuard,

    /// <summary>
    /// Storage operations are suspended because the machine is running on battery power.
    /// </summary>
    SuspendedByBattery,

    /// <summary>
    /// Worker is paused by explicit user action.
    /// </summary>
    PausedByUser
}

/// <summary>
/// Telemetry event emitted when background storage optimization actions occur.
/// Renders antivirus-style notifications and activity feed logs.
/// </summary>
public sealed class OptimizationEvent : EventArgs
{
    /// <summary>
    /// Exact UTC timestamp when the optimization occurred.
    /// </summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Path of the file or directory that was optimized.
    /// </summary>
    public string FilePath { get; init; } = string.Empty;

    /// <summary>
    /// Action description (e.g., "ConsolidatedDuplicate", "ReFSBlockCloned", "NtfsHardLinked", "LfcContainerPacked").
    /// </summary>
    public string Action { get; init; } = string.Empty;

    /// <summary>
    /// Exact physical storage bytes reclaimed by this action.
    /// </summary>
    public long BytesSaved { get; init; }

    /// <summary>
    /// Human-readable log entry for the action feed.
    /// </summary>
    public string Message { get; init; } = string.Empty;

    public OptimizationEvent() { }

    public OptimizationEvent(string filePath, string action, long bytesSaved, string? message = null, DateTime? timestamp = null)
    {
        FilePath = filePath;
        Action = action;
        BytesSaved = bytesSaved;
        Timestamp = timestamp ?? DateTime.UtcNow;
        Message = message ?? FormatDefaultMessage(filePath, action, bytesSaved, Timestamp.ToLocalTime());
    }

    public static string FormatDefaultMessage(string filePath, string action, long bytesSaved, DateTime localTime)
    {
        string savedStr = bytesSaved >= 1024L * 1024 * 1024
            ? $"{bytesSaved / (1024.0 * 1024.0 * 1024.0):F2} GB"
            : bytesSaved >= 1024L * 1024
                ? $"{bytesSaved / (1024.0 * 1024.0):F1} MB"
                : bytesSaved >= 1024L
                    ? $"{bytesSaved / 1024.0:F1} KB"
                    : $"{bytesSaved} B";

        string fileName = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = filePath;
        }

        return $"[{localTime:HH:mm:ss}] {action}: {fileName} — Saved {savedStr}";
    }

    public override string ToString() => Message;
}

/// <summary>
/// Configuration parameters for HyperStoreBackgroundWorker.
/// </summary>
public sealed class WorkerSettings
{
    /// <summary>
    /// Execution mode: ContinuousLowPriority, ScheduledWindow, or ManualOnly.
    /// </summary>
    public WorkerExecutionMode Mode { get; set; } = WorkerExecutionMode.ContinuousLowPriority;

    /// <summary>
    /// Minimum required user inactivity duration before worker initiates background pass (default: 5 minutes = 300,000 ms).
    /// </summary>
    public TimeSpan IdleThreshold { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// If true, requires AC wall power and suspends when operating on battery (default: true).
    /// </summary>
    public bool RequireAcPower { get; set; } = true;

    /// <summary>
    /// Daily scheduled window start time (default: 02:00 AM).
    /// </summary>
    public TimeSpan ScheduledWindowStart { get; set; } = new TimeSpan(2, 0, 0);

    /// <summary>
    /// Daily scheduled window end time (default: 06:00 AM).
    /// </summary>
    public TimeSpan ScheduledWindowEnd { get; set; } = new TimeSpan(6, 0, 0);

    /// <summary>
    /// List of target directory paths monitored and scheduled for deduplication sweeps.
    /// </summary>
    public List<string> TargetDirectories { get; set; } = new();

    /// <summary>
    /// Interval between background optimization sweeps when idle conditions are met (default: 15 minutes).
    /// </summary>
    public TimeSpan SweepInterval { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// DedupOptions applied to duplicate consolidation runs.
    /// </summary>
    public DedupOptions DedupOptions { get; set; } = new();

    /// <summary>
    /// If true, lowers process and thread I/O priority during background optimization (default: true).
    /// </summary>
    public bool EnableBackgroundPriority { get; set; } = true;

    /// <summary>
    /// GPU 3D engine utilization percentage above which the Game Guard triggers immediate pause (default: 35.0%).
    /// </summary>
    public double GpuUtilizationThreshold { get; set; } = 35.0;

    /// <summary>
    /// Checks whether the specified time of day falls within the configured scheduled window.
    /// Handles both same-day windows and overnight spans crossing midnight.
    /// </summary>
    public bool IsInScheduledWindow(TimeSpan timeOfDay)
    {
        if (ScheduledWindowStart <= ScheduledWindowEnd)
        {
            return timeOfDay >= ScheduledWindowStart && timeOfDay <= ScheduledWindowEnd;
        }
        else
        {
            return timeOfDay >= ScheduledWindowStart || timeOfDay <= ScheduledWindowEnd;
        }
    }
}
