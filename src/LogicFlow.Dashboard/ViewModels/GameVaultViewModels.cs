// LogicFlow.Dashboard.ViewModels — Game Vault Presentation ViewModels & Headless Controller
// Proprietary implementation by DelgadoLogic.Tech
// Enterprise WOF/CompactOS presentation layer with pure BCL decoupling, zero STA crashes, and full testability.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Dashboard.Common;
using LogicFlow.Guardian;
using LogicFlow.Native;

namespace LogicFlow.Dashboard.ViewModels;

// ═══════════════════════════════════════════════════════════════════════════════
// 1. GAME VAULT ITEM VIEW MODEL
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Presentation ViewModel representing an individual detected game title in the Game Vault.
/// Implements INotifyPropertyChanged to support live UI updates during compression and decompression.
/// Fully apartment-state independent (MTA and STA safe).
/// </summary>
public sealed class GameVaultItemViewModel : INotifyPropertyChanged
{
    private DetectedGame _game;
    private long _sizeOnDiskBytes;
    private long _logicalSizeBytes;
    private long _compressedSizeBytes;
    private long _estimatedSavingsBytes;
    private bool _isCompressed;
    private uint _selectedAlgorithm = WofNative.ALGORITHM_LZX; // Default: LZX (Maximum ratio)
    private bool _skipDirectStorage = true;
    private bool _isProcessing;
    private double _progressPercent;
    private string _currentFile = string.Empty;
    private double _throughputMBs;
    private string _statusText = "Ready to Compact";
    private bool _hasDecay;
    private long _decayedBytes;

    public event PropertyChangedEventHandler? PropertyChanged;

    public GameVaultItemViewModel(DetectedGame game)
    {
        _game = game ?? throw new ArgumentNullException(nameof(game));
        _sizeOnDiskBytes = game.SizeOnDiskBytes;
        _logicalSizeBytes = game.LogicalSizeBytes > 0 ? game.LogicalSizeBytes : game.SizeOnDiskBytes;
        _estimatedSavingsBytes = game.EstimatedSavingsBytes;
        _isCompressed = game.IsCompressed;
        _compressedSizeBytes = game.IsCompressed ? game.SizeOnDiskBytes : 0L;
        _statusText = game.IsCompressed ? "Compressed" : (game.HasDirectStorage ? "DirectStorage Active" : "Ready to Compact");
    }

    // ─── Underlying Model ───
    public DetectedGame Game => _game;
    public DetectedGame Model => _game;
    public string GameId => _game.GameId;
    public string Title => _game.Title;
    public string InstallDirectory => _game.InstallDirectory;
    public LauncherType Launcher => _game.Launcher;
    public bool HasDirectStorage => _game.HasDirectStorage;

    // ─── Size & Metric Properties ───
    public long RawSizeBytes => _logicalSizeBytes;

    public long LogicalSizeBytes
    {
        get => _logicalSizeBytes;
        set
        {
            if (_logicalSizeBytes != value)
            {
                _logicalSizeBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(RawSizeBytes));
                OnPropertyChanged(nameof(FormattedLogicalSize));
                OnPropertyChanged(nameof(DiskFootprintText));
                OnPropertyChanged(nameof(SavingsText));
                OnPropertyChanged(nameof(SavingsPercent));
                OnPropertyChanged(nameof(SpaceSavedPercent));
            }
        }
    }

    public long SizeOnDiskBytes
    {
        get => _sizeOnDiskBytes;
        set
        {
            if (_sizeOnDiskBytes != value)
            {
                _sizeOnDiskBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedSizeOnDisk));
                OnPropertyChanged(nameof(DiskFootprintText));
                OnPropertyChanged(nameof(SavingsText));
                OnPropertyChanged(nameof(SavingsPercent));
                OnPropertyChanged(nameof(SpaceSavedPercent));
            }
        }
    }

    public long CompressedSizeBytes
    {
        get => _compressedSizeBytes;
        set
        {
            if (_compressedSizeBytes != value)
            {
                _compressedSizeBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedCompressedSize));
            }
        }
    }

    public long EstimatedSavingsBytes
    {
        get => _estimatedSavingsBytes;
        set
        {
            if (_estimatedSavingsBytes != value)
            {
                _estimatedSavingsBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedEstimatedSavings));
                OnPropertyChanged(nameof(SavingsBadgeText));
                OnPropertyChanged(nameof(SavingsText));
            }
        }
    }

    public bool IsCompressed
    {
        get => _isCompressed;
        set
        {
            if (_isCompressed != value)
            {
                _isCompressed = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusBadgeText));
                OnPropertyChanged(nameof(StatusBadgeBrushKey));
                OnPropertyChanged(nameof(StatusBadgeForegroundHex));
                OnPropertyChanged(nameof(CanDecompress));
                OnPropertyChanged(nameof(CanCompact));
                OnPropertyChanged(nameof(SavingsText));
            }
        }
    }

    // ─── Algorithm Mapping ───
    public uint SelectedAlgorithm
    {
        get => _selectedAlgorithm;
        set
        {
            uint valid = value switch
            {
                WofNative.ALGORITHM_XPRESS4K => WofNative.ALGORITHM_XPRESS4K,
                WofNative.ALGORITHM_LZX => WofNative.ALGORITHM_LZX,
                WofNative.ALGORITHM_XPRESS8K => WofNative.ALGORITHM_XPRESS8K,
                WofNative.ALGORITHM_XPRESS16K => WofNative.ALGORITHM_XPRESS16K,
                _ => WofNative.ALGORITHM_LZX
            };

            if (_selectedAlgorithm != valid)
            {
                _selectedAlgorithm = valid;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SelectedAlgorithmName));
                OnPropertyChanged(nameof(AlgorithmName));
                OnPropertyChanged(nameof(SelectedAlgorithmIndex));
                OnPropertyChanged(nameof(AlgorithmIndex));
            }
        }
    }

    public int SelectedAlgorithmIndex
    {
        get => _selectedAlgorithm switch
        {
            WofNative.ALGORITHM_LZX => 0,
            WofNative.ALGORITHM_XPRESS8K => 1,
            WofNative.ALGORITHM_XPRESS16K => 2,
            WofNative.ALGORITHM_XPRESS4K => 3,
            _ => 0
        };
        set
        {
            SelectedAlgorithm = value switch
            {
                0 => WofNative.ALGORITHM_LZX,
                1 => WofNative.ALGORITHM_XPRESS8K,
                2 => WofNative.ALGORITHM_XPRESS16K,
                3 => WofNative.ALGORITHM_XPRESS4K,
                _ => WofNative.ALGORITHM_LZX
            };
        }
    }

    public int AlgorithmIndex
    {
        get => SelectedAlgorithmIndex;
        set => SelectedAlgorithmIndex = value;
    }

    public string SelectedAlgorithmName => _selectedAlgorithm switch
    {
        WofNative.ALGORITHM_LZX => "LZX (Maximum Ratio)",
        WofNative.ALGORITHM_XPRESS8K => "XPRESS8K (Balanced Fast)",
        WofNative.ALGORITHM_XPRESS16K => "XPRESS16K (High Throughput)",
        WofNative.ALGORITHM_XPRESS4K => "XPRESS4K (Lightweight)",
        _ => "LZX (Maximum Ratio)"
    };

    public string AlgorithmName => SelectedAlgorithmName;

    // ─── Safety & Execution State ───
    public bool SkipDirectStorage
    {
        get => _skipDirectStorage;
        set
        {
            if (_skipDirectStorage != value)
            {
                _skipDirectStorage = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanCompact));
            }
        }
    }

    public bool IsProcessing
    {
        get => _isProcessing;
        set
        {
            if (_isProcessing != value)
            {
                _isProcessing = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanExecuteAction));
                OnPropertyChanged(nameof(CanCompact));
                OnPropertyChanged(nameof(CanDecompress));
            }
        }
    }

    public bool CanExecuteAction => !_isProcessing;
    public bool CanCompact => !_isProcessing && (!HasDirectStorage || !_skipDirectStorage);
    public bool CanDecompress => !_isProcessing && _isCompressed;

    public double ProgressPercent
    {
        get => _progressPercent;
        set
        {
            if (Math.Abs(_progressPercent - value) > 0.01)
            {
                _progressPercent = value;
                OnPropertyChanged();
            }
        }
    }

    public string CurrentFile
    {
        get => _currentFile;
        set
        {
            if (_currentFile != value)
            {
                _currentFile = value;
                OnPropertyChanged();
            }
        }
    }

    public double ThroughputMBs
    {
        get => _throughputMBs;
        set
        {
            if (Math.Abs(_throughputMBs - value) > 0.01)
            {
                _throughputMBs = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedThroughput));
                OnPropertyChanged(nameof(ThroughputText));
            }
        }
    }

    public string ThroughputText => FormattedThroughput;
    public string FormattedThroughput => $"{_throughputMBs:0.0} MB/s";

    public string StatusText
    {
        get => _statusText;
        set
        {
            if (_statusText != value)
            {
                _statusText = value;
                OnPropertyChanged();
            }
        }
    }

    // ─── Decay Tracking ───
    public bool HasDecay
    {
        get => _hasDecay;
        set
        {
            if (_hasDecay != value)
            {
                _hasDecay = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusBadgeText));
                OnPropertyChanged(nameof(StatusBadgeBrushKey));
                OnPropertyChanged(nameof(StatusBadgeForegroundHex));
            }
        }
    }

    public long DecayedBytes
    {
        get => _decayedBytes;
        set
        {
            if (_decayedBytes != value)
            {
                _decayedBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedDecayedBytes));
            }
        }
    }

    public string FormattedDecayedBytes => FormatBytes(_decayedBytes);

    // ─── Launcher Badges & Branding ───
    public string LauncherDisplayName => Launcher switch
    {
        LauncherType.Steam => "Steam",
        LauncherType.Epic => "Epic Games",
        LauncherType.GOG => "GOG Galaxy",
        LauncherType.Custom => "Local / Custom",
        _ => "Custom"
    };

    public string LauncherBadgeText => Launcher switch
    {
        LauncherType.Steam => "STEAM",
        LauncherType.Epic => "EPIC",
        LauncherType.GOG => "GOG",
        _ => "CUSTOM"
    };

    public string LauncherBadgeColor => Launcher switch
    {
        LauncherType.Steam => "#1B2838",
        LauncherType.Epic => "#252525",
        LauncherType.GOG => "#3B1C54",
        _ => "#064E3B"
    };

    public string LauncherBadgeColorHex => LauncherBadgeColor;

    public string LauncherBadgeBorderColor => Launcher switch
    {
        LauncherType.Steam => "#2A475E",
        LauncherType.Epic => "#3B3B3B",
        LauncherType.GOG => "#6B3299",
        _ => "#047857"
    };

    public string LauncherBadgeBorderColorHex => Launcher switch
    {
        LauncherType.Steam => "#66C0F4",
        LauncherType.Epic => "#9CA3AF",
        LauncherType.GOG => "#D8B4FE",
        LauncherType.Custom => "#34D399",
        _ => "#64748B"
    };

    public string LauncherBadgeForeground => Launcher switch
    {
        LauncherType.Steam => "#66C0F4",
        LauncherType.Epic => "#E6E6E6",
        LauncherType.GOG => "#D4A5FF",
        _ => "#34D399"
    };

    public string LauncherBadgeForegroundHex => LauncherBadgeForeground;

    // ─── DirectStorage Properties ───
    public bool DirectStorageWarningVisible => HasDirectStorage;
    public string DirectStorageBadgeText => "DirectStorage Active";
    public string DirectStorageTooltip => "DirectStorage / BypassIO detected (dstorage.dll). Skipped by default to protect GPU decompression pipelines.";

    // ─── Status Badges ───
    public string StatusBadgeText => IsCompressed
        ? "COMPRESSED"
        : (HasDecay ? "UPDATE DECAY" : "UNCOMPRESSED");

    public string StatusBadgeBrushKey => IsCompressed
        ? "SuccessGreenBrush"
        : (HasDecay ? "WarningAmberBrush" : "TextSecondaryBrush");

    public string StatusBadgeForegroundHex => IsCompressed
        ? "#22C55E"
        : (HasDecay ? "#F59E0B" : "#94A3B8");

    // ─── Formatting & Calculations ───
    public string FormattedSizeOnDisk => FormatBytes(SizeOnDiskBytes);
    public string FormattedLogicalSize => FormatBytes(LogicalSizeBytes);
    public string FormattedCompressedSize => FormatBytes(CompressedSizeBytes);
    public string FormattedEstimatedSavings => FormatBytes(EstimatedSavingsBytes);

    public double SavingsPercent => LogicalSizeBytes > 0 && SizeOnDiskBytes < LogicalSizeBytes
        ? Math.Max(0.0, (1.0 - ((double)SizeOnDiskBytes / LogicalSizeBytes)) * 100.0)
        : (LogicalSizeBytes > 0 && EstimatedSavingsBytes > 0
            ? Math.Min(100.0, ((double)EstimatedSavingsBytes / LogicalSizeBytes) * 100.0)
            : 0.0);

    public double SpaceSavedPercent => LogicalSizeBytes > 0 && SizeOnDiskBytes < LogicalSizeBytes
        ? Math.Max(0.0, (1.0 - ((double)SizeOnDiskBytes / LogicalSizeBytes)) * 100.0)
        : 0.0;

    public string SavingsBadgeText => EstimatedSavingsBytes > 0
        ? $"-{FormatBytes(EstimatedSavingsBytes)}"
        : (IsCompressed ? $"-{FormatBytes(Math.Max(0, LogicalSizeBytes - SizeOnDiskBytes))}" : "Optimal");

    public string DiskFootprintText => LogicalSizeBytes > 0 && SizeOnDiskBytes < LogicalSizeBytes
        ? $"{FormatBytes(SizeOnDiskBytes)} (was {FormatBytes(LogicalSizeBytes)})"
        : FormatBytes(SizeOnDiskBytes);

    public string SavingsText
    {
        get
        {
            if (LogicalSizeBytes <= 0) return "0 B (0.0%)";
            if (IsCompressed)
            {
                long saved = Math.Max(0, LogicalSizeBytes - SizeOnDiskBytes);
                return $"-{FormatBytes(saved)} ({SpaceSavedPercent:0.0}%)";
            }
            return $"Est. -{FormattedEstimatedSavings} ({(LogicalSizeBytes > 0 ? (double)EstimatedSavingsBytes / LogicalSizeBytes * 100.0 : 0.0):0.0}%)";
        }
    }

    // ─── Mutation & Upstream Sync Handlers ───
    public void UpdateFromProgress(CompressionProgress progress)
    {
        if (progress == null) return;
        ProgressPercent = progress.PercentComplete;
        CurrentFile = Path.GetFileName(progress.CurrentFile);
        ThroughputMBs = progress.ThroughputMBs;
        StatusText = $"{progress.PercentComplete:0.0}% ({progress.FormattedThroughput})";
    }

    public void UpdateFromSummary(GameCompressionSummary summary)
    {
        if (summary == null) return;
        if (summary.Success)
        {
            IsCompressed = true;
            SizeOnDiskBytes = summary.CompressedBytes;
            CompressedSizeBytes = summary.CompressedBytes;
            EstimatedSavingsBytes = Math.Max(0L, summary.OriginalBytes - summary.CompressedBytes);
            StatusText = $"Compacted (-{summary.FormattedSavedBytes})";
            HasDecay = false;
            DecayedBytes = 0;
        }
        else
        {
            StatusText = $"Failed: {summary.ErrorMessage}";
        }
    }

    public void UpdateFromDecompression(GameDecompressionSummary summary)
    {
        if (summary == null) return;
        if (summary.Success)
        {
            IsCompressed = false;
            SizeOnDiskBytes = LogicalSizeBytes > 0 ? LogicalSizeBytes : SizeOnDiskBytes;
            CompressedSizeBytes = 0;
            EstimatedSavingsBytes = 0;
            StatusText = "Decompressed";
            HasDecay = false;
            DecayedBytes = 0;
        }
        else
        {
            StatusText = $"Decompress failed: {summary.ErrorMessage}";
        }
    }

    public void UpdateFromDetectedGame(DetectedGame updated)
    {
        if (updated == null) return;
        _game = updated;
        SizeOnDiskBytes = updated.SizeOnDiskBytes;
        LogicalSizeBytes = updated.LogicalSizeBytes > 0 ? updated.LogicalSizeBytes : updated.SizeOnDiskBytes;
        EstimatedSavingsBytes = updated.EstimatedSavingsBytes;
        IsCompressed = updated.IsCompressed;
        CompressedSizeBytes = updated.IsCompressed ? updated.SizeOnDiskBytes : 0L;
    }

    public static string FormatBytes(long bytes)
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

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. GAME VAULT SUMMARY VIEW MODEL
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Aggregates vault-wide library statistics, driving summary metrics and decay banners.
/// Fully apartment-state independent (MTA and STA safe).
/// </summary>
public sealed class GameVaultSummaryViewModel : INotifyPropertyChanged
{
    private int _totalGames;
    private int _compressedGames;
    private int _directStorageGames;
    private long _totalRawSizeBytes;
    private long _totalCompressedSizeBytes;
    private long _totalEstimatedSavingsBytes;
    private long _totalReclaimedStorageBytes;
    private int _decayedGamesCount;
    private long _totalDecayedBytes;
    private int _totalDecayedFiles;
    private bool _isGlobalProcessing;
    private double _globalProgressPercent;
    private string _globalProgressText = "Idle";
    private string _globalThroughputText = "0.0 MB/s";

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<GameVaultItemViewModel> Items { get; } = new();

    public int TotalGames
    {
        get => _totalGames;
        set
        {
            if (_totalGames != value)
            {
                _totalGames = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TotalGamesCount));
                OnPropertyChanged(nameof(UncompressedGamesCount));
                OnPropertyChanged(nameof(SummaryText));
            }
        }
    }

    public int TotalGamesCount => TotalGames;

    public int CompressedGames
    {
        get => _compressedGames;
        set
        {
            if (_compressedGames != value)
            {
                _compressedGames = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CompressedGamesCount));
                OnPropertyChanged(nameof(UncompressedGamesCount));
                OnPropertyChanged(nameof(SummaryText));
            }
        }
    }

    public int CompressedGamesCount => CompressedGames;
    public int UncompressedGamesCount => Math.Max(0, TotalGames - CompressedGames);

    public int DirectStorageProtectedCount
    {
        get => _directStorageGames;
        set
        {
            if (_directStorageGames != value)
            {
                _directStorageGames = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DirectStorageGamesCount));
            }
        }
    }

    public int DirectStorageGamesCount => DirectStorageProtectedCount;

    public long TotalRawSizeBytes
    {
        get => _totalRawSizeBytes;
        set
        {
            if (_totalRawSizeBytes != value)
            {
                _totalRawSizeBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TotalDiskUsedBytes));
                OnPropertyChanged(nameof(FormattedTotalSize));
                OnPropertyChanged(nameof(FormattedTotalDiskUsed));
            }
        }
    }

    public long TotalDiskUsedBytes => TotalRawSizeBytes;

    public long TotalCompressedSizeBytes
    {
        get => _totalCompressedSizeBytes;
        set
        {
            if (_totalCompressedSizeBytes != value)
            {
                _totalCompressedSizeBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedTotalCompressedSize));
            }
        }
    }

    public long TotalEstimatedSavingsBytes
    {
        get => _totalEstimatedSavingsBytes;
        set
        {
            if (_totalEstimatedSavingsBytes != value)
            {
                _totalEstimatedSavingsBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TotalPotentialSavingsBytes));
                OnPropertyChanged(nameof(FormattedTotalSavings));
                OnPropertyChanged(nameof(FormattedTotalPotentialSavings));
            }
        }
    }

    public long TotalPotentialSavingsBytes => TotalEstimatedSavingsBytes;

    public long TotalReclaimedStorageBytes
    {
        get => _totalReclaimedStorageBytes;
        set
        {
            if (_totalReclaimedStorageBytes != value)
            {
                _totalReclaimedStorageBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TotalReclaimedBytes));
                OnPropertyChanged(nameof(FormattedReclaimedStorage));
                OnPropertyChanged(nameof(FormattedTotalReclaimed));
                OnPropertyChanged(nameof(SummaryText));
            }
        }
    }

    public long TotalReclaimedBytes => TotalReclaimedStorageBytes;

    public int DecayedGamesCount
    {
        get => _decayedGamesCount;
        set
        {
            if (_decayedGamesCount != value)
            {
                _decayedGamesCount = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(HasDecay));
                OnPropertyChanged(nameof(HasDecayedGames));
                OnPropertyChanged(nameof(DecayBannerText));
                OnPropertyChanged(nameof(DecayAlertBannerText));
            }
        }
    }

    public bool HasDecay => _decayedGamesCount > 0;
    public bool HasDecayedGames => HasDecay;

    public long TotalDecayedBytes
    {
        get => _totalDecayedBytes;
        set
        {
            if (_totalDecayedBytes != value)
            {
                _totalDecayedBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedDecayedBytes));
                OnPropertyChanged(nameof(FormattedTotalDecayedBytes));
                OnPropertyChanged(nameof(DecayBannerText));
                OnPropertyChanged(nameof(DecayAlertBannerText));
            }
        }
    }

    public int TotalDecayedFiles
    {
        get => _totalDecayedFiles;
        set
        {
            if (_totalDecayedFiles != value)
            {
                _totalDecayedFiles = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsGlobalProcessing
    {
        get => _isGlobalProcessing;
        set
        {
            if (_isGlobalProcessing != value)
            {
                _isGlobalProcessing = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanCancel));
            }
        }
    }

    public bool CanCancel => _isGlobalProcessing;

    public double GlobalProgressPercent
    {
        get => _globalProgressPercent;
        set
        {
            if (Math.Abs(_globalProgressPercent - value) > 0.01)
            {
                _globalProgressPercent = value;
                OnPropertyChanged();
            }
        }
    }

    public string GlobalProgressText
    {
        get => _globalProgressText;
        set
        {
            if (_globalProgressText != value)
            {
                _globalProgressText = value;
                OnPropertyChanged();
            }
        }
    }

    public string GlobalThroughputText
    {
        get => _globalThroughputText;
        set
        {
            if (_globalThroughputText != value)
            {
                _globalThroughputText = value;
                OnPropertyChanged();
            }
        }
    }

    // ─── Formatted Display Strings ───
    public string FormattedTotalSize => GameVaultItemViewModel.FormatBytes(TotalRawSizeBytes);
    public string FormattedTotalDiskUsed => FormattedTotalSize;
    public string FormattedTotalCompressedSize => GameVaultItemViewModel.FormatBytes(TotalCompressedSizeBytes);
    public string FormattedTotalSavings => GameVaultItemViewModel.FormatBytes(TotalEstimatedSavingsBytes);
    public string FormattedTotalPotentialSavings => FormattedTotalSavings;
    public string FormattedReclaimedStorage => GameVaultItemViewModel.FormatBytes(TotalReclaimedStorageBytes);
    public string FormattedTotalReclaimed => FormattedReclaimedStorage;
    public string FormattedDecayedBytes => GameVaultItemViewModel.FormatBytes(TotalDecayedBytes);
    public string FormattedTotalDecayedBytes => FormattedDecayedBytes;

    public string SummaryText => $"{TotalGames} games installed | {CompressedGames} compressed | {FormattedReclaimedStorage} reclaimed";
    public string DecayBannerText => $"{DecayedGamesCount} game(s) have uncompressed updates ({FormattedTotalDecayedBytes} recoverable)";
    public string DecayAlertBannerText => $"{DecayedGamesCount} game(s) updated by launcher since last compaction. Re-compact updates to reclaim storage.";

    public void Recalculate(IEnumerable<GameVaultItemViewModel>? items = null, DecayAuditReport? decayReport = null)
    {
        var list = (items ?? Items).ToList();
        TotalGames = list.Count;
        CompressedGames = list.Count(i => i.IsCompressed);
        DirectStorageProtectedCount = list.Count(i => i.HasDirectStorage);
        TotalRawSizeBytes = list.Sum(i => i.SizeOnDiskBytes);
        TotalCompressedSizeBytes = list.Where(i => i.IsCompressed).Sum(i => i.CompressedSizeBytes > 0 ? i.CompressedSizeBytes : i.SizeOnDiskBytes);
        TotalEstimatedSavingsBytes = list.Sum(i => i.EstimatedSavingsBytes);

        TotalReclaimedStorageBytes = list
            .Where(i => i.IsCompressed && i.LogicalSizeBytes > i.SizeOnDiskBytes)
            .Sum(i => i.LogicalSizeBytes - i.SizeOnDiskBytes);

        if (decayReport != null)
        {
            DecayedGamesCount = decayReport.GamesWithDecay;
            TotalDecayedBytes = decayReport.TotalUncompressedBytesEligible;
            TotalDecayedFiles = decayReport.CalculatedTotalDecayedFiles;
        }
        else
        {
            DecayedGamesCount = list.Count(i => i.HasDecay);
            TotalDecayedBytes = list.Where(i => i.HasDecay).Sum(i => i.DecayedBytes);
            TotalDecayedFiles = DecayedGamesCount;
        }

        NotifyCollectionChanged();
    }

    public void NotifyCollectionChanged()
    {
        OnPropertyChanged(nameof(TotalGames));
        OnPropertyChanged(nameof(TotalGamesCount));
        OnPropertyChanged(nameof(CompressedGames));
        OnPropertyChanged(nameof(CompressedGamesCount));
        OnPropertyChanged(nameof(UncompressedGamesCount));
        OnPropertyChanged(nameof(DirectStorageProtectedCount));
        OnPropertyChanged(nameof(DirectStorageGamesCount));
        OnPropertyChanged(nameof(TotalRawSizeBytes));
        OnPropertyChanged(nameof(TotalDiskUsedBytes));
        OnPropertyChanged(nameof(TotalCompressedSizeBytes));
        OnPropertyChanged(nameof(TotalEstimatedSavingsBytes));
        OnPropertyChanged(nameof(TotalPotentialSavingsBytes));
        OnPropertyChanged(nameof(TotalReclaimedStorageBytes));
        OnPropertyChanged(nameof(TotalReclaimedBytes));
        OnPropertyChanged(nameof(HasDecay));
        OnPropertyChanged(nameof(HasDecayedGames));
        OnPropertyChanged(nameof(DecayedGamesCount));
        OnPropertyChanged(nameof(TotalDecayedBytes));
        OnPropertyChanged(nameof(FormattedTotalSize));
        OnPropertyChanged(nameof(FormattedTotalDiskUsed));
        OnPropertyChanged(nameof(FormattedTotalCompressedSize));
        OnPropertyChanged(nameof(FormattedTotalSavings));
        OnPropertyChanged(nameof(FormattedTotalPotentialSavings));
        OnPropertyChanged(nameof(FormattedReclaimedStorage));
        OnPropertyChanged(nameof(FormattedTotalReclaimed));
        OnPropertyChanged(nameof(FormattedDecayedBytes));
        OnPropertyChanged(nameof(FormattedTotalDecayedBytes));
        OnPropertyChanged(nameof(SummaryText));
        OnPropertyChanged(nameof(DecayBannerText));
        OnPropertyChanged(nameof(DecayAlertBannerText));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. GAME VAULT PROGRESS VIEW MODEL
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Telemetry ViewModel for the real-time progress bar, throughput counter, ETA, and cancellation state.
/// </summary>
public sealed class GameVaultProgressViewModel : INotifyPropertyChanged
{
    private bool _isActive;
    private string _operationTitle = string.Empty;
    private string _currentFileName = string.Empty;
    private int _filesCompleted;
    private int _totalFiles;
    private double _percentComplete;
    private double _throughputMBs;
    private long _bytesProcessed;
    private long _bytesSaved;
    private TimeSpan _elapsed;
    private TimeSpan? _eta;
    private string _statusMessage = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (_isActive != value)
            {
                _isActive = value;
                OnPropertyChanged();
            }
        }
    }

    public string OperationTitle
    {
        get => _operationTitle;
        set
        {
            if (_operationTitle != value)
            {
                _operationTitle = value;
                OnPropertyChanged();
            }
        }
    }

    public string CurrentFile
    {
        get => _currentFileName;
        set
        {
            if (_currentFileName != value)
            {
                _currentFileName = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CurrentFileName));
            }
        }
    }

    public string CurrentFileName
    {
        get => _currentFileName;
        set => CurrentFile = value;
    }

    public int FilesCompleted
    {
        get => _filesCompleted;
        set
        {
            if (_filesCompleted != value)
            {
                _filesCompleted = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProgressFilesText));
            }
        }
    }

    public int TotalFiles
    {
        get => _totalFiles;
        set
        {
            if (_totalFiles != value)
            {
                _totalFiles = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProgressFilesText));
            }
        }
    }

    public double PercentComplete
    {
        get => _percentComplete;
        set
        {
            if (Math.Abs(_percentComplete - value) > 0.01)
            {
                _percentComplete = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(PercentCompleteText));
            }
        }
    }

    public double ThroughputMBs
    {
        get => _throughputMBs;
        set
        {
            if (Math.Abs(_throughputMBs - value) > 0.01)
            {
                _throughputMBs = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedThroughput));
            }
        }
    }

    public long BytesProcessed
    {
        get => _bytesProcessed;
        set
        {
            if (_bytesProcessed != value)
            {
                _bytesProcessed = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedBytesProcessed));
            }
        }
    }

    public long BytesSaved
    {
        get => _bytesSaved;
        set
        {
            if (_bytesSaved != value)
            {
                _bytesSaved = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedBytesSaved));
            }
        }
    }

    public TimeSpan Elapsed
    {
        get => _elapsed;
        set
        {
            if (_elapsed != value)
            {
                _elapsed = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedElapsed));
            }
        }
    }

    public TimeSpan? Eta
    {
        get => _eta;
        set
        {
            if (_eta != value)
            {
                _eta = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedEta));
                OnPropertyChanged(nameof(EtaText));
            }
        }
    }

    public string EtaText => FormattedEta;

    public string StatusMessage
    {
        get => _statusMessage;
        set
        {
            if (_statusMessage != value)
            {
                _statusMessage = value;
                OnPropertyChanged();
            }
        }
    }

    public string FormattedThroughput => $"{_throughputMBs:0.0} MB/s";
    public string FormattedBytesProcessed => GameVaultItemViewModel.FormatBytes(_bytesProcessed);
    public string FormattedBytesSaved => GameVaultItemViewModel.FormatBytes(_bytesSaved);
    public string PercentCompleteText => $"{_percentComplete:0.0}%";
    public string ProgressFilesText => $"{_filesCompleted:N0} / {_totalFiles:N0} files";
    public string FormattedElapsed => $"Elapsed: {_elapsed:mm\\:ss}";
    public string FormattedEta => _eta.HasValue ? $"ETA: {_eta.Value:mm\\:ss}" : "ETA: --:--";

    public void Update(CompressionProgress progress, string? opTitle = null) => UpdateFromProgress(progress, opTitle);

    public void UpdateFromProgress(CompressionProgress progress, string? opTitle = null)
    {
        if (progress == null) return;
        IsActive = true;
        if (!string.IsNullOrEmpty(opTitle)) OperationTitle = opTitle;
        CurrentFile = Path.GetFileName(progress.CurrentFile);
        FilesCompleted = progress.FilesCompleted;
        TotalFiles = progress.TotalFiles;
        PercentComplete = progress.PercentComplete;
        ThroughputMBs = progress.ThroughputMBs;
        BytesProcessed = progress.BytesProcessed;
        BytesSaved = progress.BytesSaved;
        Elapsed = progress.Elapsed;
        Eta = progress.EstimatedTimeRemaining;
        StatusMessage = progress.StatusMessage ?? string.Empty;
    }

    public void Reset()
    {
        IsActive = false;
        OperationTitle = string.Empty;
        CurrentFile = string.Empty;
        FilesCompleted = 0;
        TotalFiles = 0;
        PercentComplete = 0;
        ThroughputMBs = 0;
        BytesProcessed = 0;
        BytesSaved = 0;
        Elapsed = TimeSpan.Zero;
        Eta = null;
        StatusMessage = string.Empty;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GAME VAULT CONTROLLER (HEADLESS ENGINE WRAPPER)
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Headless controller coordinating library discovery, single and batch compaction,
/// decompression, decay updates, and cancellation logic across SteamLibraryDetector
/// and GameCompressionEngine.
/// Designed for 100% thread-safety and headless unit testing without STA dependencies.
/// </summary>
public sealed class GameVaultController
{
    private readonly GameVaultSummaryViewModel _summary;
    private readonly SteamLibraryDetector _detector;
    private readonly GameCompressionEngine _engine;
    private CancellationTokenSource? _activeCts;
    private readonly object _syncLock = new();

    public GameVaultController(
        GameVaultSummaryViewModel summary,
        SteamLibraryDetector? detector = null,
        GameCompressionEngine? engine = null)
    {
        _summary = summary ?? throw new ArgumentNullException(nameof(summary));
        _detector = detector ?? SteamLibraryDetector.Instance;
        _engine = engine ?? GameCompressionEngine.Instance;
    }

    public GameVaultSummaryViewModel Summary => _summary;

    public Task RefreshGamesAsync(IEnumerable<string>? customPaths = null, CancellationToken ct = default) =>
        RefreshAsync(customPaths, ct);

    public async Task RefreshAsync(IEnumerable<string>? customPaths = null, CancellationToken ct = default)
    {
        _summary.IsGlobalProcessing = true;
        _summary.GlobalProgressText = "Scanning game libraries...";

        try
        {
            var detectedGames = await Task.Run(() => _detector.DetectAllGames(customPaths).ToList(), ct);
            var decayReport = await Task.Run(() => _engine.AuditDecay(detectedGames), ct);

            UiDispatcher.Invoke(() =>
            {
                _summary.Items.Clear();
                var decayMap = decayReport.DecayedGames.ToDictionary(d => d.GameId, d => d);

                foreach (var game in detectedGames)
                {
                    var vm = new GameVaultItemViewModel(game);
                    if (decayMap.TryGetValue(game.GameId, out var decayInfo) && decayInfo.HasDecay)
                    {
                        vm.HasDecay = true;
                        vm.DecayedBytes = decayInfo.DecayedBytes;
                    }
                    _summary.Items.Add(vm);
                }

                _summary.Recalculate(_summary.Items, decayReport);
                _summary.GlobalProgressText = $"Scan complete ({_summary.Items.Count} games found)";
            });
        }
        catch (OperationCanceledException)
        {
            _summary.GlobalProgressText = "Scan cancelled";
        }
        catch (Exception ex)
        {
            _summary.GlobalProgressText = $"Scan error: {ex.Message}";
        }
        finally
        {
            _summary.IsGlobalProcessing = false;
        }
    }

    public async Task<bool> CompactGameAsync(GameVaultItemViewModel item, CancellationToken ct = default)
    {
        if (item == null) return false;

        // Concurrency guard: reject re-entrance if already processing
        lock (_syncLock)
        {
            if (item.IsProcessing) return false;
            item.IsProcessing = true;
        }

        item.StatusText = "Compressing...";
        _summary.IsGlobalProcessing = true;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, GetOrCreateActiveCts().Token);
        var progress = new Progress<CompressionProgress>(p =>
        {
            UiDispatcher.Invoke(() =>
            {
                item.ProgressPercent = p.PercentComplete;
                item.CurrentFile = Path.GetFileName(p.CurrentFile);
                item.ThroughputMBs = p.ThroughputMBs;
                item.StatusText = $"Compressing {p.PercentComplete:0.0}% ({p.FormattedThroughput})";
            });
        });

        try
        {
            var options = new GameCompressionOptions(
                Algorithm: item.SelectedAlgorithm,
                SkipDirectStorage: item.SkipDirectStorage);

            var summary = await Task.Run(() => _engine.CompressGameAsync(item.Model, options, progress, linkedCts.Token), linkedCts.Token);

            UiDispatcher.Invoke(() =>
            {
                if (summary.Success)
                {
                    item.UpdateFromSummary(summary);
                    _summary.Recalculate();
                }
                else
                {
                    item.StatusText = $"Failed: {summary.ErrorMessage}";
                }
            });

            return summary.Success;
        }
        catch (OperationCanceledException)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = "Compression cancelled";
            });
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = "Access Denied (Admin required)";
            });
            return false;
        }
        catch (Exception ex)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = $"Error: {ex.Message}";
            });
            return false;
        }
        finally
        {
            lock (_syncLock)
            {
                item.IsProcessing = false;
                item.ProgressPercent = 0;
            }
            _summary.IsGlobalProcessing = false;
        }
    }

    public async Task<bool> DecompressGameAsync(GameVaultItemViewModel item, CancellationToken ct = default)
    {
        if (item == null || !item.IsCompressed) return false;

        lock (_syncLock)
        {
            if (item.IsProcessing) return false;
            item.IsProcessing = true;
        }

        item.StatusText = "Decompressing...";
        _summary.IsGlobalProcessing = true;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, GetOrCreateActiveCts().Token);
        var progress = new Progress<CompressionProgress>(p =>
        {
            UiDispatcher.Invoke(() =>
            {
                item.ProgressPercent = p.PercentComplete;
                item.CurrentFile = Path.GetFileName(p.CurrentFile);
                item.ThroughputMBs = p.ThroughputMBs;
                item.StatusText = $"Decompressing {p.PercentComplete:0.0}% ({p.FormattedThroughput})";
            });
        });

        try
        {
            var summary = await Task.Run(() => _engine.DecompressGameAsync(item.Model, progress, linkedCts.Token), linkedCts.Token);

            UiDispatcher.Invoke(() =>
            {
                if (summary.Success)
                {
                    item.UpdateFromDecompression(summary);
                    _summary.Recalculate();
                }
                else
                {
                    item.StatusText = $"Decompress Failed: {summary.ErrorMessage}";
                }
            });

            return summary.Success;
        }
        catch (OperationCanceledException)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = "Decompression cancelled";
            });
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = "Access Denied (Admin required)";
            });
            return false;
        }
        catch (Exception ex)
        {
            UiDispatcher.Invoke(() =>
            {
                item.StatusText = $"Error: {ex.Message}";
            });
            return false;
        }
        finally
        {
            lock (_syncLock)
            {
                item.IsProcessing = false;
                item.ProgressPercent = 0;
            }
            _summary.IsGlobalProcessing = false;
        }
    }

    public async Task<int> CompactAllAsync(CancellationToken ct = default)
    {
        if (_summary.IsGlobalProcessing) return 0;

        _summary.IsGlobalProcessing = true;
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, GetOrCreateActiveCts().Token);
        int compactedCount = 0;

        try
        {
            var eligible = _summary.Items
                .Where(i => !i.IsCompressed && (!i.HasDirectStorage || !i.SkipDirectStorage))
                .ToList();

            for (int i = 0; i < eligible.Count; i++)
            {
                linkedCts.Token.ThrowIfCancellationRequested();
                var item = eligible[i];
                _summary.GlobalProgressPercent = (double)i / eligible.Count * 100.0;
                _summary.GlobalProgressText = $"Compressing {item.Title} ({i + 1}/{eligible.Count})...";

                bool ok = await CompactGameAsync(item, linkedCts.Token);
                if (ok) compactedCount++;
            }

            _summary.GlobalProgressPercent = 100.0;
            _summary.GlobalProgressText = $"Batch complete ({compactedCount} games compacted)";
        }
        catch (OperationCanceledException)
        {
            _summary.GlobalProgressText = "Batch operation cancelled";
        }
        finally
        {
            _summary.IsGlobalProcessing = false;
            ResetActiveCts();
        }

        return compactedCount;
    }

    public async Task<int> RecompactUpdatesAsync(CancellationToken ct = default)
    {
        if (_summary.IsGlobalProcessing) return 0;

        _summary.IsGlobalProcessing = true;
        _summary.GlobalProgressText = "Auditing and re-compacting game updates...";
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, GetOrCreateActiveCts().Token);
        int recompactedCount = 0;

        try
        {
            var detectedGames = _summary.Items.Select(i => i.Model).ToList();
            var report = await Task.Run(() => _engine.AuditDecay(detectedGames), linkedCts.Token);

            foreach (var decayed in report.DecayedGames)
            {
                linkedCts.Token.ThrowIfCancellationRequested();
                var item = _summary.Items.FirstOrDefault(i => i.GameId == decayed.GameId);
                if (item == null) continue;

                var options = new GameCompressionOptions(Algorithm: item.SelectedAlgorithm, SkipDirectStorage: item.SkipDirectStorage);
                var summary = await Task.Run(() => _engine.RecompactUpdatesAsync(item.Model, options, ct: linkedCts.Token), linkedCts.Token);

                if (summary.Success)
                {
                    UiDispatcher.Invoke(() =>
                    {
                        item.UpdateFromSummary(summary);
                        item.HasDecay = false;
                        item.DecayedBytes = 0;
                        item.StatusText = "Updated & Compacted";
                    });
                    recompactedCount++;
                }
            }

            UiDispatcher.Invoke(() =>
            {
                _summary.DecayedGamesCount = 0;
                _summary.TotalDecayedBytes = 0;
                _summary.Recalculate();
                _summary.GlobalProgressText = $"Re-compaction complete ({recompactedCount} games updated)";
            });
        }
        catch (OperationCanceledException)
        {
            _summary.GlobalProgressText = "Re-compaction cancelled";
        }
        finally
        {
            _summary.IsGlobalProcessing = false;
            ResetActiveCts();
        }

        return recompactedCount;
    }

    public void CancelActiveOperation()
    {
        lock (_syncLock)
        {
            _activeCts?.Cancel();
        }
    }

    private CancellationTokenSource GetOrCreateActiveCts()
    {
        lock (_syncLock)
        {
            _activeCts ??= new CancellationTokenSource();
            return _activeCts;
        }
    }

    private void ResetActiveCts()
    {
        lock (_syncLock)
        {
            _activeCts?.Dispose();
            _activeCts = null;
        }
    }
}
