// LogicFlow.Guardian — Game & Application Compression Engine & Decay Watchdog
// Proprietary implementation by DelgadoLogic.Tech
// Transparent Win32/WOF CompactOS compression pipeline with multi-launcher discovery,
// DirectStorage safety, tail-latency pre-sorting, lock-free telemetry, and atomic persistence.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Native;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

// ═══════════════════════════════════════════════════════════════════════════════
// 1. PUBLIC OPTIONS, SUMMARIES & TELEMETRY RECORDS
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Configuration options governing game compression operations.
/// </summary>
/// <param name="Algorithm">CompactOS compression algorithm ID (0=XPRESS4K, 1=LZX, 2=XPRESS8K, 3=XPRESS16K). Default: LZX.</param>
/// <param name="MaxParallelism">Maximum concurrent worker tasks. If null or &lt;= 0, clamps to Math.Min(ProcessorCount, 8).</param>
/// <param name="SkipDirectStorage">When true, detects and skips games utilizing DirectStorage/BypassIO (dstorage.dll). Default: true.</param>
public sealed record GameCompressionOptions(
    uint Algorithm = WofNative.ALGORITHM_LZX,
    int? MaxParallelism = null,
    bool SkipDirectStorage = true)
{
    /// <summary>
    /// Computes the effective worker concurrency bounded between 1 and 8.
    /// </summary>
    public int EffectiveParallelism =>
        MaxParallelism.HasValue && MaxParallelism.Value > 0
            ? Math.Clamp(MaxParallelism.Value, 1, 32)
            : Math.Clamp(Environment.ProcessorCount, 1, 8);

    public static GameCompressionOptions Default => new();
    public static GameCompressionOptions Maximum => new(WofNative.ALGORITHM_LZX);
    public static GameCompressionOptions Balanced => new(WofNative.ALGORITHM_XPRESS8K);
    public static GameCompressionOptions Fast => new(WofNative.ALGORITHM_XPRESS16K);
}

/// <summary>
/// Comprehensive execution telemetry and space recovery metrics resulting from a game compression operation.
/// </summary>
public sealed record GameCompressionSummary(
    string GameId,
    string Title,
    bool Success,
    int FilesProcessed,
    int FilesCompressed,
    int FilesSkipped,
    long OriginalBytes,
    long CompressedBytes,
    long SavedBytes,
    double Ratio,
    TimeSpan Duration,
    string? ErrorMessage = null)
{
    public double SpaceSavedPercent =>
        OriginalBytes > 0 ? Math.Max(0.0, (1.0 - ((double)CompressedBytes / OriginalBytes)) * 100.0) : 0.0;

    public double ThroughputMBs =>
        Duration.TotalSeconds > 0 ? (OriginalBytes / (1024.0 * 1024.0)) / Duration.TotalSeconds : 0.0;

    public string FormattedOriginalBytes => FormatBytes(OriginalBytes);
    public string FormattedCompressedBytes => FormatBytes(CompressedBytes);
    public string FormattedSavedBytes => FormatBytes(SavedBytes);
    public string FormattedThroughput => $"{ThroughputMBs:0.0} MB/s";

    public static GameCompressionSummary Failed(string gameId, string title, string errorMessage, TimeSpan duration = default) =>
        new(gameId, title, false, 0, 0, 0, 0, 0, 0, 1.0, duration, errorMessage);

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}

/// <summary>
/// Summary telemetry resulting from a game decompression operation.
/// </summary>
public sealed record GameDecompressionSummary(
    string GameId,
    string Title,
    bool Success,
    int FilesProcessed,
    int FilesDecompressed,
    long RestoredBytes,
    TimeSpan Duration,
    string? ErrorMessage = null)
{
    public double ThroughputMBs =>
        Duration.TotalSeconds > 0 ? (RestoredBytes / (1024.0 * 1024.0)) / Duration.TotalSeconds : 0.0;

    public string FormattedRestoredBytes => FormatBytes(RestoredBytes);
    public string FormattedThroughput => $"{ThroughputMBs:0.0} MB/s";

    public static GameDecompressionSummary Failed(string gameId, string title, string errorMessage, TimeSpan duration = default) =>
        new(gameId, title, false, 0, 0, 0L, duration, errorMessage);

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}

/// <summary>
/// Detailed decay information for an individual game title.
/// </summary>
public sealed record GameDecayInfo(
    string GameId,
    string Title,
    string InstallDirectory,
    int NewOrModifiedFileCount,
    long UncompressedBytesEligible,
    DateTime? LastCompressedUtc = null,
    IReadOnlyList<string>? DecayedFilePaths = null,
    LauncherType Launcher = LauncherType.Custom,
    bool IsTracked = true,
    int NewFilesCount = 0,
    int ModifiedFilesCount = 0,
    int DeletedFilesCount = 0,
    uint PreviousAlgorithm = 0)
{
    public bool HasDecay => NewOrModifiedFileCount > 0;
    public int DecayedFileCount => NewOrModifiedFileCount;
    public long DecayedBytes => UncompressedBytesEligible;
    public DateTime? LastCompressionTimeUtc => LastCompressedUtc;
    public IReadOnlyList<string> DecayedRelativePaths => DecayedFilePaths ?? Array.Empty<string>();

    public string FormattedUncompressedBytes => FormatBytes(UncompressedBytesEligible);
    public string FormattedDecayedBytes => FormattedUncompressedBytes;

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}

/// <summary>
/// Aggregated report of all audited games indicating compression decay status.
/// </summary>
public sealed record DecayAuditReport(
    int TotalGamesAudited,
    int GamesWithDecay,
    List<GameDecayInfo> DecayedGames,
    long TotalDecayedBytes = 0,
    int TotalDecayedFiles = 0)
{
    public bool HasDecay => GamesWithDecay > 0;
    public long TotalUncompressedBytesEligible =>
        TotalDecayedBytes > 0 ? TotalDecayedBytes : DecayedGames.Sum(g => g.UncompressedBytesEligible);
    public int CalculatedTotalDecayedFiles =>
        TotalDecayedFiles > 0 ? TotalDecayedFiles : DecayedGames.Sum(g => g.NewOrModifiedFileCount);

    public string FormattedTotalUncompressedBytes => FormatBytes(TotalUncompressedBytesEligible);
    public string FormattedTotalDecayedBytes => FormattedTotalUncompressedBytes;

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}

/// <summary>
/// Real-time streaming telemetry event payload delivered to UI and CLI progress reporters.
/// </summary>
public sealed record CompressionProgress(
    string CurrentFile,
    int FilesCompleted,
    int TotalFiles,
    long BytesProcessed,
    long BytesSaved,
    double CompressionRatio,
    double ThroughputMBs,
    double PercentComplete,
    long CompressedBytes = 0,
    long TotalBytes = 0,
    double InstantThroughputMBps = 0,
    TimeSpan Elapsed = default,
    TimeSpan? EstimatedTimeRemaining = null,
    string? StatusMessage = null)
{
    public string CurrentFilePath => CurrentFile;
    public double SpaceSavedPercent => BytesProcessed > 0 && CompressedBytes > 0
        ? Math.Max(0.0, (1.0 - ((double)CompressedBytes / BytesProcessed)) * 100.0)
        : (BytesProcessed > 0 ? Math.Max(0.0, ((double)BytesSaved / BytesProcessed) * 100.0) : 0.0);

    public string FormattedBytesProcessed => FormatBytes(BytesProcessed);
    public string FormattedBytesSaved => FormatBytes(BytesSaved);
    public string FormattedThroughput => $"{ThroughputMBs:0.0} MB/s";

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. STATE PERSISTENCE & CATALOG SCHEMA
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Root persistent catalog document holding all tracked game compression entries.
/// </summary>
public sealed class GameCompressionState
{
    public int Version { get; set; } = 1;
    public DateTime LastUpdatedUtc { get; set; } = DateTime.UtcNow;
    public Dictionary<string, TrackedGameRecord> TrackedGames { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Backward-compatibility alias for callers accessing Games property.
    /// </summary>
    [JsonIgnore]
    public Dictionary<string, TrackedGameRecord> Games => TrackedGames;
}

/// <summary>
/// Authoritative metadata catalog entry for a single compressed game installation.
/// </summary>
public sealed class TrackedGameRecord
{
    public string GameId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string InstallDirectory { get; set; } = string.Empty;
    public LauncherType Launcher { get; set; } = LauncherType.Custom;
    public DateTime LastCompressionTimeUtc { get; set; }
    public uint AlgorithmUsed { get; set; }
    public long TotalOriginalBytes { get; set; }
    public long TotalCompressedBytes { get; set; }
    public long SavedBytes { get; set; }
    public int CompressedFileCount { get; set; }
    public int TotalTrackedFiles { get; set; }
    public Dictionary<string, TrackedFileEntry> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public double CompressionRatio => TotalOriginalBytes > 0 ? (double)TotalCompressedBytes / TotalOriginalBytes : 1.0;
    public double SpaceSavedPercent => TotalOriginalBytes > 0 ? Math.Max(0.0, (1.0 - ((double)TotalCompressedBytes / TotalOriginalBytes)) * 100.0) : 0.0;
}

/// <summary>
/// Immutable record capturing an individual file's tracked compression state.
/// </summary>
public sealed record TrackedFileEntry(
    string RelativePath,
    DateTime LastWriteTimeUtc,
    long Length,
    bool IsCompressed,
    uint Algorithm = 0);

/// <summary>
/// State management and delta auditing engine for game compression catalogs.
/// Implements atomic replacement protocol and corruption self-healing.
/// </summary>
public sealed class GameCompressionWatchdog
{
    private readonly string _stateFilePath;
    private readonly ILogger? _logger;
    private readonly object _stateLock = new();

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string StateFilePath => _stateFilePath;

    public static string DefaultStateFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "DelgadoLogic",
            "LogicFlow",
            "game_compression.json");

    public GameCompressionWatchdog(string? stateFilePath = null, ILogger? logger = null)
    {
        _stateFilePath = stateFilePath ?? DefaultStateFilePath;
        _logger = logger;
    }

    // ─── Atomic State Persistence ───────────────────────────────────────────

    public GameCompressionState LoadState()
    {
        lock (_stateLock)
        {
            if (!File.Exists(_stateFilePath))
            {
                return new GameCompressionState();
            }

            try
            {
                using var fs = new FileStream(_stateFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var reader = new StreamReader(fs, Encoding.UTF8);
                string json = reader.ReadToEnd();

                if (string.IsNullOrWhiteSpace(json))
                {
                    return new GameCompressionState();
                }

                var state = JsonSerializer.Deserialize<GameCompressionState>(json, SerializerOptions);
                return state ?? new GameCompressionState();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed reading game compression state from '{Path}'. Archiving corrupted file and creating fresh state.", _stateFilePath);
                try
                {
                    string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                    string backupPath = $"{_stateFilePath}.corrupt.{timestamp}.bak";
                    File.Copy(_stateFilePath, backupPath, overwrite: true);
                }
                catch { }

                return new GameCompressionState();
            }
        }
    }

    public void SaveState(GameCompressionState state)
    {
        if (state == null) throw new ArgumentNullException(nameof(state));

        lock (_stateLock)
        {
            state.LastUpdatedUtc = DateTime.UtcNow;
            string dir = Path.GetDirectoryName(_stateFilePath) ?? AppContext.BaseDirectory;
            Directory.CreateDirectory(dir);

            string tempFilePath = Path.Combine(dir, $"{Path.GetFileName(_stateFilePath)}.{Guid.NewGuid():N}.tmp");

            try
            {
                string json = JsonSerializer.Serialize(state, SerializerOptions);

                using (var fs = new FileStream(tempFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                using (var writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.Write(json);
                    writer.Flush();
                }

                File.Move(tempFilePath, _stateFilePath, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed saving game compression state to '{Path}'", _stateFilePath);
                throw;
            }
            finally
            {
                try
                {
                    if (File.Exists(tempFilePath))
                    {
                        File.Delete(tempFilePath);
                    }
                }
                catch { }
            }
        }
    }

    // ─── Decay Auditing ─────────────────────────────────────────────────────

    public GameDecayInfo AuditGameDecay(DetectedGame game)
    {
        if (game == null) throw new ArgumentNullException(nameof(game));

        if (string.IsNullOrWhiteSpace(game.InstallDirectory) || !Directory.Exists(game.InstallDirectory))
        {
            return new GameDecayInfo(
                game.GameId, game.Title, game.InstallDirectory,
                NewOrModifiedFileCount: 0, UncompressedBytesEligible: 0,
                LastCompressedUtc: null, DecayedFilePaths: Array.Empty<string>(),
                Launcher: game.Launcher, IsTracked: false);
        }

        // DirectStorage protected games are not audited for compression decay
        if (GameSafetyHeuristics.HasDirectStorage(game.InstallDirectory))
        {
            return new GameDecayInfo(
                game.GameId, game.Title, game.InstallDirectory,
                NewOrModifiedFileCount: 0, UncompressedBytesEligible: 0,
                LastCompressedUtc: null, DecayedFilePaths: Array.Empty<string>(),
                Launcher: game.Launcher, IsTracked: false);
        }

        var state = LoadState();
        if (!state.TrackedGames.TryGetValue(game.GameId, out var trackedRecord))
        {
            return new GameDecayInfo(
                game.GameId, game.Title, game.InstallDirectory,
                NewOrModifiedFileCount: 0, UncompressedBytesEligible: 0,
                LastCompressedUtc: null, DecayedFilePaths: Array.Empty<string>(),
                Launcher: game.Launcher, IsTracked: false);
        }

        var candidateFiles = GameSafetyHeuristics.EnumerateCompressibleFiles(game.InstallDirectory, skipDirectStorage: true).ToList();
        var currentRelPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var newFiles = new List<string>();
        var modifiedFiles = new List<string>();
        var decayedPaths = new List<string>();
        long decayedBytes = 0;

        foreach (var fullPath in candidateFiles)
        {
            string relPath = NormalizeRelativePath(Path.GetRelativePath(game.InstallDirectory, fullPath));
            currentRelPaths.Add(relPath);

            FileInfo fi;
            try { fi = new FileInfo(fullPath); } catch { continue; }
            if (fi.Length == 0) continue;

            if (!trackedRecord.Files.TryGetValue(relPath, out var trackedFile))
            {
                // New file introduced after initial compression
                if (!WofNative.IsFileCompressed(fullPath))
                {
                    newFiles.Add(relPath);
                    decayedPaths.Add(relPath);
                    decayedBytes += fi.Length;
                }
            }
            else
            {
                // Known file — check if modified via fast path (size and 2.0s timestamp tolerance)
                bool sizeChanged = fi.Length != trackedFile.Length;
                bool timeChanged = Math.Abs((fi.LastWriteTimeUtc - trackedFile.LastWriteTimeUtc).TotalSeconds) > 2.0;

                if (sizeChanged || timeChanged)
                {
                    if (!WofNative.IsFileCompressed(fullPath))
                    {
                        modifiedFiles.Add(relPath);
                        decayedPaths.Add(relPath);
                        decayedBytes += fi.Length;
                    }
                }
            }
        }

        int deletedCount = trackedRecord.Files.Keys.Count(k => !currentRelPaths.Contains(k));

        return new GameDecayInfo(
            game.GameId,
            game.Title,
            game.InstallDirectory,
            NewOrModifiedFileCount: decayedPaths.Count,
            UncompressedBytesEligible: decayedBytes,
            LastCompressedUtc: trackedRecord.LastCompressionTimeUtc,
            DecayedFilePaths: decayedPaths,
            Launcher: game.Launcher,
            IsTracked: true,
            NewFilesCount: newFiles.Count,
            ModifiedFilesCount: modifiedFiles.Count,
            DeletedFilesCount: deletedCount,
            PreviousAlgorithm: trackedRecord.AlgorithmUsed);
    }

    public DecayAuditReport AuditDecay(IEnumerable<DetectedGame> games)
    {
        if (games == null) throw new ArgumentNullException(nameof(games));

        int totalAudited = 0;
        var decayedGames = new List<GameDecayInfo>();
        long totalDecayedBytes = 0;
        int totalDecayedFiles = 0;

        foreach (var game in games)
        {
            totalAudited++;
            var info = AuditGameDecay(game);
            if (info.HasDecay)
            {
                decayedGames.Add(info);
                totalDecayedBytes += info.UncompressedBytesEligible;
                totalDecayedFiles += info.NewOrModifiedFileCount;
            }
        }

        return new DecayAuditReport(
            TotalGamesAudited: totalAudited,
            GamesWithDecay: decayedGames.Count,
            DecayedGames: decayedGames,
            TotalDecayedBytes: totalDecayedBytes,
            TotalDecayedFiles: totalDecayedFiles);
    }

    public static string NormalizeRelativePath(string relPath) =>
        relPath.Replace('\\', '/').TrimStart('/');
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. CORE GAME COMPRESSION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Sovereign high-throughput transparent game and application compression coordinator.
/// Orchestrates parallel WOF CompactOS compression, safe physical decompression,
/// compression decay auditing, and incremental re-compaction across PC game libraries.
/// </summary>
public sealed class GameCompressionEngine
{
    private readonly ILogger? _logger;
    private readonly GameCompressionWatchdog _watchdog;

    /// <summary>
    /// Shared global singleton instance for non-DI environments (CLI, quick scripts).
    /// </summary>
    public static GameCompressionEngine Instance { get; } = new();

    /// <summary>
    /// The persistent decay watchdog instance used for catalog synchronization.
    /// </summary>
    public GameCompressionWatchdog Watchdog => _watchdog;

    /// <summary>
    /// Initializes a new instance of GameCompressionEngine with optional logging and custom state path.
    /// </summary>
    public GameCompressionEngine(ILogger? logger = null, string? watchdogFilePath = null)
    {
        _logger = logger;
        _watchdog = new GameCompressionWatchdog(watchdogFilePath, logger);
    }

    // ─── 1. Batch Parallel Compression ──────────────────────────────────────

    /// <summary>
    /// Executes high-throughput parallel transparent compression across all compressible files of an installed game.
    /// </summary>
    public async Task<GameCompressionSummary> CompressGameAsync(
        DetectedGame game,
        GameCompressionOptions? options = null,
        IProgress<CompressionProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (game == null) throw new ArgumentNullException(nameof(game));
        options ??= GameCompressionOptions.Default;

        var sw = Stopwatch.StartNew();

        // DirectStorage safety check
        if (options.SkipDirectStorage && (game.HasDirectStorage || GameSafetyHeuristics.HasDirectStorage(game.InstallDirectory)))
        {
            return new GameCompressionSummary(
                game.GameId,
                game.Title,
                Success: true,
                FilesProcessed: 0,
                FilesCompressed: 0,
                FilesSkipped: 0,
                OriginalBytes: 0,
                CompressedBytes: 0,
                SavedBytes: 0,
                Ratio: 1.0,
                Duration: sw.Elapsed,
                ErrorMessage: "Skipped DirectStorage game to protect GPU decompression pipeline.");
        }

        if (string.IsNullOrWhiteSpace(game.InstallDirectory) || !Directory.Exists(game.InstallDirectory))
        {
            return GameCompressionSummary.Failed(
                game.GameId,
                game.Title,
                $"Install directory does not exist: {game.InstallDirectory}",
                sw.Elapsed);
        }

        // Candidate enumeration via safety heuristics
        var candidatePaths = GameSafetyHeuristics.EnumerateCompressibleFiles(game.InstallDirectory, options.SkipDirectStorage).ToList();

        if (candidatePaths.Count == 0)
        {
            return new GameCompressionSummary(
                game.GameId,
                game.Title,
                Success: true,
                FilesProcessed: 0,
                FilesCompressed: 0,
                FilesSkipped: 0,
                OriginalBytes: 0,
                CompressedBytes: 0,
                SavedBytes: 0,
                Ratio: 1.0,
                Duration: sw.Elapsed,
                ErrorMessage: null);
        }

        // Pre-sort candidate files descending by length to eliminate tail latency
        long totalBytes = 0;
        var sizedFiles = candidatePaths.Select(path =>
        {
            long len = 0;
            try { len = new FileInfo(path).Length; } catch { }
            Interlocked.Add(ref totalBytes, len);
            return (Path: path, Length: len);
        })
        .OrderByDescending(f => f.Length)
        .ToList();

        // Concurrency bounded to EffectiveParallelism (clamped to min(procCount, 8))
        int parallelism = options.EffectiveParallelism;

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = parallelism,
            CancellationToken = ct
        };

        // Lock-free atomic metric counters
        int filesCompleted = 0;
        int filesCompressed = 0;
        int filesSkipped = 0;
        long bytesProcessed = 0;
        long compressedBytes = 0;
        long savedBytes = 0;

        var trackedFiles = new ConcurrentDictionary<string, TrackedFileEntry>(StringComparer.OrdinalIgnoreCase);

        long lastReportTicks = 0;
        long lastReportBytes = 0;
        double smoothedThroughput = 0;
        string currentFileName = string.Empty;
        bool cancelled = false;

        void ReportProgress(bool force = false)
        {
            if (progress == null) return;

            long nowTicks = Stopwatch.GetTimestamp();
            long lastTicks = Volatile.Read(ref lastReportTicks);
            double deltaSec = (double)(nowTicks - lastTicks) / Stopwatch.Frequency;

            if (!force && deltaSec < 0.080) // 80ms rate limiting (~12.5 Hz)
                return;

            if (!force && Interlocked.CompareExchange(ref lastReportTicks, nowTicks, lastTicks) != lastTicks)
                return;

            if (force)
                Volatile.Write(ref lastReportTicks, nowTicks);

            long currentProcessed = Interlocked.Read(ref bytesProcessed);
            long lastBytes = Interlocked.Exchange(ref lastReportBytes, currentProcessed);
            long deltaBytes = Math.Max(0, currentProcessed - lastBytes);

            double instantMBs = deltaSec > 0.001 ? (deltaBytes / (1024.0 * 1024.0)) / deltaSec : 0.0;
            double overallMBs = sw.Elapsed.TotalSeconds > 0.001 ? (currentProcessed / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds : 0.0;

            // Smoothed throughput
            smoothedThroughput = smoothedThroughput > 0
                ? 0.3 * instantMBs + 0.7 * smoothedThroughput
                : instantMBs;

            double effectiveThroughput = smoothedThroughput > 0 ? smoothedThroughput : overallMBs;

            int completed = Volatile.Read(ref filesCompleted);
            long saved = Interlocked.Read(ref savedBytes);
            long currentCompBytes = Interlocked.Read(ref compressedBytes);
            double percent = sizedFiles.Count > 0 ? Math.Clamp((double)completed / sizedFiles.Count * 100.0, 0.0, 100.0) : 0.0;
            double ratio = currentProcessed > 0 ? (double)currentCompBytes / currentProcessed : 1.0;

            TimeSpan? eta = null;
            if (effectiveThroughput > 0.01 && totalBytes > currentProcessed)
            {
                double remainingMB = (totalBytes - currentProcessed) / (1024.0 * 1024.0);
                double remainingSec = remainingMB / effectiveThroughput;
                if (remainingSec >= 0 && remainingSec < 86400 * 7)
                    eta = TimeSpan.FromSeconds(remainingSec);
            }

            progress.Report(new CompressionProgress(
                CurrentFile: Volatile.Read(ref currentFileName),
                FilesCompleted: completed,
                TotalFiles: sizedFiles.Count,
                BytesProcessed: currentProcessed,
                BytesSaved: saved,
                CompressionRatio: ratio,
                ThroughputMBs: effectiveThroughput,
                PercentComplete: percent,
                CompressedBytes: currentCompBytes,
                TotalBytes: totalBytes,
                InstantThroughputMBps: instantMBs,
                Elapsed: sw.Elapsed,
                EstimatedTimeRemaining: eta,
                StatusMessage: completed == sizedFiles.Count ? "Complete" : "Compressing"));
        }

        try
        {
            await Parallel.ForEachAsync(sizedFiles, parallelOptions, (item, token) =>
            {
                token.ThrowIfCancellationRequested();
                Volatile.Write(ref currentFileName, Path.GetFileName(item.Path));

                string relPath = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(game.InstallDirectory, item.Path));

                try
                {
                    var result = WofNative.SetFileCompression(item.Path, options.Algorithm);

                    FileInfo? fi = null;
                    try { fi = new FileInfo(item.Path); } catch { }

                    DateTime writeTime = fi?.LastWriteTimeUtc ?? DateTime.UtcNow;
                    long len = fi?.Length ?? item.Length;

                    if (result.Success && result.SavedBytes > 0)
                    {
                        Interlocked.Increment(ref filesCompleted);
                        Interlocked.Increment(ref filesCompressed);
                        Interlocked.Add(ref bytesProcessed, result.OriginalSize > 0 ? result.OriginalSize : len);
                        Interlocked.Add(ref compressedBytes, result.CompressedSize);
                        Interlocked.Add(ref savedBytes, result.SavedBytes);

                        trackedFiles[relPath] = new TrackedFileEntry(relPath, writeTime, len, IsCompressed: true, options.Algorithm);
                    }
                    else
                    {
                        // Skipped (already compressed, not beneficial, small file, or locked)
                        Interlocked.Increment(ref filesCompleted);
                        Interlocked.Increment(ref filesSkipped);
                        long orig = result.OriginalSize > 0 ? result.OriginalSize : len;
                        Interlocked.Add(ref bytesProcessed, orig);
                        Interlocked.Add(ref compressedBytes, orig);

                        bool isComp = result.Status == WofCompressionStatus.SkippedAlreadyCompressed;
                        trackedFiles[relPath] = new TrackedFileEntry(relPath, writeTime, len, IsCompressed: isComp, options.Algorithm);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to compress file '{Path}'", item.Path);
                    Interlocked.Increment(ref filesCompleted);
                    Interlocked.Increment(ref filesSkipped);
                    Interlocked.Add(ref bytesProcessed, item.Length);
                    Interlocked.Add(ref compressedBytes, item.Length);
                }

                ReportProgress(force: false);
                return ValueTask.CompletedTask;
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        sw.Stop();
        ReportProgress(force: true);

        // Atomic commit to watchdog state
        try
        {
            var state = _watchdog.LoadState();
            if (!state.TrackedGames.TryGetValue(game.GameId, out var record))
            {
                record = new TrackedGameRecord
                {
                    GameId = game.GameId,
                    Title = game.Title,
                    InstallDirectory = game.InstallDirectory,
                    Launcher = game.Launcher
                };
                state.TrackedGames[game.GameId] = record;
            }

            record.Title = game.Title;
            record.InstallDirectory = game.InstallDirectory;
            record.Launcher = game.Launcher;
            record.LastCompressionTimeUtc = DateTime.UtcNow;
            record.AlgorithmUsed = options.Algorithm;

            foreach (var kvp in trackedFiles)
            {
                record.Files[kvp.Key] = kvp.Value;
            }

            record.TotalOriginalBytes = record.Files.Values.Sum(f => f.Length);
            record.TotalCompressedBytes = record.Files.Values.Sum(f => f.IsCompressed ? WofNative.GetPhysicalFileSize(Path.Combine(record.InstallDirectory, f.RelativePath)) : f.Length);
            record.SavedBytes = Math.Max(0L, record.TotalOriginalBytes - record.TotalCompressedBytes);
            record.CompressedFileCount = record.Files.Values.Count(f => f.IsCompressed);
            record.TotalTrackedFiles = record.Files.Count;

            _watchdog.SaveState(state);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to update watchdog state for game '{GameId}'", game.GameId);
        }

        long finalProcessed = Interlocked.Read(ref bytesProcessed);
        long finalCompressed = Interlocked.Read(ref compressedBytes);
        long finalSaved = Interlocked.Read(ref savedBytes);
        double finalRatio = finalProcessed > 0 ? (double)finalCompressed / finalProcessed : 1.0;

        return new GameCompressionSummary(
            game.GameId,
            game.Title,
            Success: !cancelled,
            FilesProcessed: Volatile.Read(ref filesCompleted),
            FilesCompressed: Volatile.Read(ref filesCompressed),
            FilesSkipped: Volatile.Read(ref filesSkipped),
            OriginalBytes: finalProcessed,
            CompressedBytes: finalCompressed,
            SavedBytes: finalSaved,
            Ratio: finalRatio,
            Duration: sw.Elapsed,
            ErrorMessage: cancelled ? "Compression cancelled by user." : null);
    }

    // ─── 2. Safe Parallel Decompression ─────────────────────────────────────

    /// <summary>
    /// Safely reverts all compressed files of an installed game back to standard uncompressed NTFS clusters.
    /// Performs pre-flight volume free space checks to prevent out-of-disk crashes.
    /// </summary>
    public async Task<GameDecompressionSummary> DecompressGameAsync(
        DetectedGame game,
        IProgress<CompressionProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (game == null) throw new ArgumentNullException(nameof(game));

        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(game.InstallDirectory) || !Directory.Exists(game.InstallDirectory))
        {
            return GameDecompressionSummary.Failed(
                game.GameId,
                game.Title,
                $"Install directory does not exist: {game.InstallDirectory}",
                sw.Elapsed);
        }

        var allFiles = GameSafetyHeuristics.SafeEnumerateFiles(game.InstallDirectory, skipReparsePoints: true).ToList();

        var compressedFiles = new List<(string Path, long LogicalSize, long PhysicalSize)>();
        long estimatedExpansionBytes = 0;

        foreach (var file in allFiles)
        {
            if (WofNative.IsFileCompressed(file, out _, out long orig, out long comp))
            {
                if (orig > comp)
                {
                    long diff = orig - comp;
                    estimatedExpansionBytes += diff;
                    compressedFiles.Add((file, orig, comp));
                }
                else
                {
                    compressedFiles.Add((file, orig, comp));
                }
            }
        }

        if (compressedFiles.Count == 0)
        {
            try
            {
                var state = _watchdog.LoadState();
                if (state.TrackedGames.Remove(game.GameId))
                {
                    _watchdog.SaveState(state);
                }
            }
            catch { }

            return new GameDecompressionSummary(
                game.GameId,
                game.Title,
                Success: true,
                FilesProcessed: 0,
                FilesDecompressed: 0,
                RestoredBytes: 0,
                Duration: sw.Elapsed);
        }

        // Pre-flight volume free space verification
        try
        {
            string? root = Path.GetPathRoot(game.InstallDirectory);
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                long safetyMargin = Math.Clamp(estimatedExpansionBytes * 2, 16L * 1024 * 1024, 512L * 1024 * 1024);
                if (drive.AvailableFreeSpace < (estimatedExpansionBytes + safetyMargin))
                {
                    return GameDecompressionSummary.Failed(
                        game.GameId,
                        game.Title,
                        $"Insufficient disk space to safely decompress game. Required: {FormatBytes(estimatedExpansionBytes + safetyMargin)}, Available: {FormatBytes(drive.AvailableFreeSpace)}.",
                        sw.Elapsed);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogDebug(ex, "Could not verify drive free space for '{Dir}'", game.InstallDirectory);
        }

        int filesProcessed = 0;
        int filesDecompressed = 0;
        long restoredBytes = 0;
        string currentFileName = string.Empty;
        long lastReportTicks = 0;
        bool cancelled = false;

        void ReportProgress(bool force = false)
        {
            if (progress == null) return;

            long nowTicks = Stopwatch.GetTimestamp();
            long lastTicks = Volatile.Read(ref lastReportTicks);
            double deltaSec = (double)(nowTicks - lastTicks) / Stopwatch.Frequency;

            if (!force && deltaSec < 0.080)
                return;

            if (!force && Interlocked.CompareExchange(ref lastReportTicks, nowTicks, lastTicks) != lastTicks)
                return;

            if (force)
                Volatile.Write(ref lastReportTicks, nowTicks);

            int completed = Volatile.Read(ref filesProcessed);
            long restored = Interlocked.Read(ref restoredBytes);
            double throughputMBs = sw.Elapsed.TotalSeconds > 0.001
                ? (restored / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds
                : 0.0;
            double percent = compressedFiles.Count > 0
                ? Math.Clamp((double)completed / compressedFiles.Count * 100.0, 0.0, 100.0)
                : 0.0;

            progress.Report(new CompressionProgress(
                CurrentFile: Volatile.Read(ref currentFileName),
                FilesCompleted: completed,
                TotalFiles: compressedFiles.Count,
                BytesProcessed: restored,
                BytesSaved: 0,
                CompressionRatio: 1.0,
                ThroughputMBs: throughputMBs,
                PercentComplete: percent,
                Elapsed: sw.Elapsed,
                StatusMessage: completed == compressedFiles.Count ? "Complete" : "Decompressing"));
        }

        int maxParallelism = Math.Clamp(Environment.ProcessorCount, 1, 8);
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = maxParallelism,
            CancellationToken = ct
        };

        try
        {
            await Parallel.ForEachAsync(compressedFiles, parallelOptions, (item, token) =>
            {
                token.ThrowIfCancellationRequested();
                Volatile.Write(ref currentFileName, Path.GetFileName(item.Path));

                try
                {
                    bool decompressed = WofNative.DecompressFile(item.Path);
                    Interlocked.Increment(ref filesProcessed);

                    if (decompressed)
                    {
                        Interlocked.Increment(ref filesDecompressed);
                        long restored = Math.Max(0L, item.LogicalSize - item.PhysicalSize);
                        Interlocked.Add(ref restoredBytes, restored > 0 ? restored : item.LogicalSize);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to decompress file '{Path}'", item.Path);
                    Interlocked.Increment(ref filesProcessed);
                }

                ReportProgress(force: false);
                return ValueTask.CompletedTask;
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        sw.Stop();
        if (progress != null)
        {
            await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
            ReportProgress(force: true);
            await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
        }

        // Update/Remove from Watchdog State
        try
        {
            var state = _watchdog.LoadState();
            if (state.TrackedGames.TryGetValue(game.GameId, out var record))
            {
                if (filesDecompressed >= compressedFiles.Count && !cancelled)
                {
                    state.TrackedGames.Remove(game.GameId);
                }
                else
                {
                    foreach (var item in compressedFiles)
                    {
                        string relPath = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(game.InstallDirectory, item.Path));
                        if (record.Files.TryGetValue(relPath, out var entry))
                        {
                            bool isStillComp = WofNative.IsFileCompressed(item.Path);
                            record.Files[relPath] = entry with { IsCompressed = isStillComp };
                        }
                    }
                    record.TotalCompressedBytes = record.Files.Values.Sum(f => f.IsCompressed ? WofNative.GetPhysicalFileSize(Path.Combine(record.InstallDirectory, f.RelativePath)) : f.Length);
                    record.SavedBytes = Math.Max(0L, record.TotalOriginalBytes - record.TotalCompressedBytes);
                    record.CompressedFileCount = record.Files.Values.Count(f => f.IsCompressed);
                }
                _watchdog.SaveState(state);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to update watchdog state after decompressing '{GameId}'", game.GameId);
        }

        return new GameDecompressionSummary(
            game.GameId,
            game.Title,
            Success: !cancelled,
            FilesProcessed: Volatile.Read(ref filesProcessed),
            FilesDecompressed: Volatile.Read(ref filesDecompressed),
            RestoredBytes: Interlocked.Read(ref restoredBytes),
            Duration: sw.Elapsed,
            ErrorMessage: cancelled ? "Decompression cancelled by user." : null);
    }

    // ─── 3. Decay Auditing ──────────────────────────────────────────────────

    /// <summary>
    /// Audits an installed game for compression decay caused by game updates, patches, or DLC.
    /// </summary>
    public GameDecayInfo AuditGameDecay(DetectedGame game) => _watchdog.AuditGameDecay(game);

    /// <summary>
    /// Audits a collection of detected games and aggregates a comprehensive decay report.
    /// </summary>
    public DecayAuditReport AuditDecay(IEnumerable<DetectedGame> games) => _watchdog.AuditDecay(games);

    // ─── 4. 1-Click Re-compact Updates ──────────────────────────────────────

    /// <summary>
    /// Targeted delta-compression routine that recompresses solely newly added or modified uncompressed files.
    /// </summary>
    public async Task<GameCompressionSummary> RecompactUpdatesAsync(
        DetectedGame game,
        GameCompressionOptions? options = null,
        IProgress<CompressionProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (game == null) throw new ArgumentNullException(nameof(game));
        options ??= GameCompressionOptions.Default;

        var decayInfo = AuditGameDecay(game);
        if (!decayInfo.HasDecay || decayInfo.DecayedRelativePaths.Count == 0)
        {
            return new GameCompressionSummary(
                game.GameId,
                game.Title,
                Success: true,
                FilesProcessed: 0,
                FilesCompressed: 0,
                FilesSkipped: 0,
                OriginalBytes: 0,
                CompressedBytes: 0,
                SavedBytes: 0,
                Ratio: 1.0,
                Duration: TimeSpan.Zero,
                ErrorMessage: null);
        }

        // Determine algorithm: inherit previously used algorithm if default LZX was passed without customization
        uint algo = options.Algorithm;
        if (algo == WofNative.ALGORITHM_LZX && decayInfo.PreviousAlgorithm > 0)
        {
            algo = decayInfo.PreviousAlgorithm;
        }
        var effectiveOptions = options with { Algorithm = algo };

        var sw = Stopwatch.StartNew();

        var decayedFullPaths = decayInfo.DecayedRelativePaths
            .Select(r => Path.Combine(game.InstallDirectory, r.Replace('/', Path.DirectorySeparatorChar)))
            .Where(File.Exists)
            .ToList();

        if (decayedFullPaths.Count == 0)
        {
            return new GameCompressionSummary(
                game.GameId,
                game.Title,
                Success: true,
                FilesProcessed: 0,
                FilesCompressed: 0,
                FilesSkipped: 0,
                OriginalBytes: 0,
                CompressedBytes: 0,
                SavedBytes: 0,
                Ratio: 1.0,
                Duration: sw.Elapsed,
                ErrorMessage: null);
        }

        // Pre-sort files descending by size
        long totalBytes = 0;
        var sizedFiles = decayedFullPaths.Select(path =>
        {
            long len = 0;
            try { len = new FileInfo(path).Length; } catch { }
            Interlocked.Add(ref totalBytes, len);
            return (Path: path, Length: len);
        })
        .OrderByDescending(f => f.Length)
        .ToList();

        int parallelism = effectiveOptions.EffectiveParallelism;
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = parallelism,
            CancellationToken = ct
        };

        int filesCompleted = 0;
        int filesCompressed = 0;
        int filesSkipped = 0;
        long bytesProcessed = 0;
        long compressedBytes = 0;
        long savedBytes = 0;

        var updatedEntries = new ConcurrentDictionary<string, TrackedFileEntry>(StringComparer.OrdinalIgnoreCase);
        string currentFileName = string.Empty;
        long lastReportTicks = 0;
        bool cancelled = false;

        void ReportProgress(bool force = false)
        {
            if (progress == null) return;

            long nowTicks = Stopwatch.GetTimestamp();
            long lastTicks = Volatile.Read(ref lastReportTicks);
            double deltaSec = (double)(nowTicks - lastTicks) / Stopwatch.Frequency;

            if (!force && deltaSec < 0.080)
                return;

            if (!force && Interlocked.CompareExchange(ref lastReportTicks, nowTicks, lastTicks) != lastTicks)
                return;

            if (force)
                Volatile.Write(ref lastReportTicks, nowTicks);

            int completed = Volatile.Read(ref filesCompleted);
            long processed = Interlocked.Read(ref bytesProcessed);
            long saved = Interlocked.Read(ref savedBytes);
            long compBytes = Interlocked.Read(ref compressedBytes);
            double throughputMBs = sw.Elapsed.TotalSeconds > 0.001
                ? (processed / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds
                : 0.0;
            double percent = sizedFiles.Count > 0
                ? Math.Clamp((double)completed / sizedFiles.Count * 100.0, 0.0, 100.0)
                : 0.0;
            double ratio = processed > 0 ? (double)compBytes / processed : 1.0;

            progress.Report(new CompressionProgress(
                CurrentFile: Volatile.Read(ref currentFileName),
                FilesCompleted: completed,
                TotalFiles: sizedFiles.Count,
                BytesProcessed: processed,
                BytesSaved: saved,
                CompressionRatio: ratio,
                ThroughputMBs: throughputMBs,
                PercentComplete: percent,
                CompressedBytes: compBytes,
                TotalBytes: totalBytes,
                Elapsed: sw.Elapsed,
                StatusMessage: completed == sizedFiles.Count ? "Complete" : "Re-compacting"));
        }

        try
        {
            await Parallel.ForEachAsync(sizedFiles, parallelOptions, (item, token) =>
            {
                token.ThrowIfCancellationRequested();
                Volatile.Write(ref currentFileName, Path.GetFileName(item.Path));

                string relPath = GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(game.InstallDirectory, item.Path));

                try
                {
                    var result = WofNative.SetFileCompression(item.Path, effectiveOptions.Algorithm);

                    FileInfo? fi = null;
                    try { fi = new FileInfo(item.Path); } catch { }

                    DateTime writeTime = fi?.LastWriteTimeUtc ?? DateTime.UtcNow;
                    long len = fi?.Length ?? item.Length;

                    if (result.Success && result.SavedBytes > 0)
                    {
                        Interlocked.Increment(ref filesCompleted);
                        Interlocked.Increment(ref filesCompressed);
                        Interlocked.Add(ref bytesProcessed, result.OriginalSize > 0 ? result.OriginalSize : len);
                        Interlocked.Add(ref compressedBytes, result.CompressedSize);
                        Interlocked.Add(ref savedBytes, result.SavedBytes);

                        updatedEntries[relPath] = new TrackedFileEntry(relPath, writeTime, len, IsCompressed: true, effectiveOptions.Algorithm);
                    }
                    else
                    {
                        Interlocked.Increment(ref filesCompleted);
                        Interlocked.Increment(ref filesSkipped);
                        long orig = result.OriginalSize > 0 ? result.OriginalSize : len;
                        Interlocked.Add(ref bytesProcessed, orig);
                        Interlocked.Add(ref compressedBytes, orig);

                        bool isComp = result.Status == WofCompressionStatus.SkippedAlreadyCompressed;
                        updatedEntries[relPath] = new TrackedFileEntry(relPath, writeTime, len, IsCompressed: isComp, effectiveOptions.Algorithm);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to recompact file '{Path}'", item.Path);
                    Interlocked.Increment(ref filesCompleted);
                    Interlocked.Increment(ref filesSkipped);
                    Interlocked.Add(ref bytesProcessed, item.Length);
                    Interlocked.Add(ref compressedBytes, item.Length);
                }

                ReportProgress(force: false);
                return ValueTask.CompletedTask;
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        sw.Stop();
        ReportProgress(force: true);

        // Synchronize and persist updated state
        try
        {
            var state = _watchdog.LoadState();
            if (state.TrackedGames.TryGetValue(game.GameId, out var record))
            {
                foreach (var kvp in updatedEntries)
                {
                    record.Files[kvp.Key] = kvp.Value;
                }

                var currentDiskRelPaths = new HashSet<string>(
                    GameSafetyHeuristics.SafeEnumerateFiles(game.InstallDirectory)
                        .Select(p => GameCompressionWatchdog.NormalizeRelativePath(Path.GetRelativePath(game.InstallDirectory, p))),
                    StringComparer.OrdinalIgnoreCase);

                var deletedKeys = record.Files.Keys.Where(k => !currentDiskRelPaths.Contains(k)).ToList();
                foreach (var k in deletedKeys)
                {
                    record.Files.Remove(k);
                }

                record.TotalOriginalBytes = record.Files.Values.Sum(f => f.Length);
                record.TotalCompressedBytes = record.Files.Values.Sum(f => f.IsCompressed ? WofNative.GetPhysicalFileSize(Path.Combine(record.InstallDirectory, f.RelativePath)) : f.Length);
                record.SavedBytes = Math.Max(0L, record.TotalOriginalBytes - record.TotalCompressedBytes);
                record.CompressedFileCount = record.Files.Values.Count(f => f.IsCompressed);
                record.TotalTrackedFiles = record.Files.Count;
                record.LastCompressionTimeUtc = DateTime.UtcNow;

                _watchdog.SaveState(state);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to persist state after recompacting game '{GameId}'", game.GameId);
        }

        long finalProcessed = Interlocked.Read(ref bytesProcessed);
        long finalCompressed = Interlocked.Read(ref compressedBytes);
        long finalSaved = Interlocked.Read(ref savedBytes);
        double finalRatio = finalProcessed > 0 ? (double)finalCompressed / finalProcessed : 1.0;

        return new GameCompressionSummary(
            game.GameId,
            game.Title,
            Success: !cancelled,
            FilesProcessed: Volatile.Read(ref filesCompleted),
            FilesCompressed: Volatile.Read(ref filesCompressed),
            FilesSkipped: Volatile.Read(ref filesSkipped),
            OriginalBytes: finalProcessed,
            CompressedBytes: finalCompressed,
            SavedBytes: finalSaved,
            Ratio: finalRatio,
            Duration: sw.Elapsed,
            ErrorMessage: cancelled ? "Re-compacting cancelled by user." : null);
    }

    // ─── State Persistence Delegation ───────────────────────────────────────

    public GameCompressionState LoadState() => _watchdog.LoadState();
    public void SaveState(GameCompressionState state) => _watchdog.SaveState(state);

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024.0 && i < units.Length - 1)
        {
            d /= 1024.0;
            i++;
        }
        return $"{d:0.##} {units[i]}";
    }
}
