// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Dashboard.ViewModels — HyperStore Storage Armor ViewModels
// Proprietary implementation by DelgadoLogic.Tech
// Antivirus-style telemetry dashboard, live gauges, 500-item FIFO action feed,
// and 100% async non-blocking execution via UiDispatcher.
// ─────────────────────────────────────────────────────────────────────────────

#nullable enable

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using LogicFlow.Dashboard.Common;
using LogicFlow.Guardian.Deduplication;
using LogicFlow.Guardian.Worker;
using LogicFlow.Storage.Engine.Chunking;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Dashboard.ViewModels;

// ═══════════════════════════════════════════════════════════════════════════════
// 1. RELAY COMMAND HELPER
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Lightweight ICommand implementation for MVVM data binding.
/// </summary>
public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Predicate<object?>? _canExecute;

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public RelayCommand(Action<object?> execute, Predicate<object?>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
        : this(_ => execute(), canExecute != null ? _ => canExecute() : null)
    {
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. REAL-TIME ACTION FEED LOG ENTRY VIEW MODEL
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Presentation ViewModel representing an individual antivirus-style event in the action feed.
/// Features formatted timestamps, category badges, target paths, and exact bytes saved tags.
/// </summary>
public sealed class HyperStoreLogEntryViewModel : INotifyPropertyChanged
{
    private DateTime _timestamp = DateTime.UtcNow;
    private string _category = "INFO";
    private string _filePath = string.Empty;
    private string _message = string.Empty;
    private long _bytesSaved;

    public event PropertyChangedEventHandler? PropertyChanged;

    public DateTime Timestamp
    {
        get => _timestamp;
        set
        {
            if (_timestamp != value)
            {
                _timestamp = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FormattedTimestamp));
            }
        }
    }

    public string FormattedTimestamp => $"[{_timestamp.ToLocalTime():HH:mm:ss}]";

    public string Category
    {
        get => _category;
        set
        {
            if (_category != value)
            {
                _category = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CategoryTag));
                OnPropertyChanged(nameof(CategoryBrush));
            }
        }
    }

    public string CategoryTag => $"[{_category.ToUpperInvariant()}]";

    public string CategoryBrush => _category.ToUpperInvariant() switch
    {
        "DEDUP" => "#00E5FF",      // Brand Cyan
        "CLONE" => "#22C55E",      // Success Green
        "PACK" => "#7C4DFF",       // Brand Purple
        "UNPACK" => "#A78BFA",     // Light Violet
        "SCAN" => "#38BDF8",       // Sky Blue
        "GUARD" => "#F59E0B",      // Warning Amber
        "ALERT" => "#EF4444",      // Danger Red
        "ERROR" => "#EF4444",      // Danger Red
        "SHIELD" => "#22C55E",     // Success Green
        "CONFIG" => "#94A3B8",     // Slate Muted
        _ => "#94A3B8"
    };

    public string FilePath
    {
        get => _filePath;
        set
        {
            if (_filePath != value)
            {
                _filePath = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FileName));
            }
        }
    }

    public string FileName
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_filePath)) return string.Empty;
            try
            {
                return Path.GetFileName(_filePath);
            }
            catch
            {
                return _filePath;
            }
        }
    }

    public string Message
    {
        get => _message;
        set
        {
            if (_message != value)
            {
                _message = value;
                OnPropertyChanged();
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
                OnPropertyChanged(nameof(HasBytesSaved));
            }
        }
    }

    public string FormattedBytesSaved => _bytesSaved > 0
        ? $"+{HyperStoreViewModel.FormatBytes(_bytesSaved)}"
        : "0 B";

    public bool HasBytesSaved => _bytesSaved > 0;

    public System.Windows.Visibility SavedBadgeVisibility => _bytesSaved > 0
        ? System.Windows.Visibility.Visible
        : System.Windows.Visibility.Collapsed;

    public HyperStoreLogEntryViewModel()
    {
    }

    public HyperStoreLogEntryViewModel(
        string category,
        string message,
        string filePath = "",
        long bytesSaved = 0,
        DateTime? timestamp = null)
    {
        _category = category;
        _message = message;
        _filePath = filePath;
        _bytesSaved = bytesSaved;
        _timestamp = timestamp ?? DateTime.UtcNow;
    }

    public HyperStoreLogEntryViewModel(OptimizationEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        _timestamp = evt.Timestamp;
        _category = MapActionToCategory(evt.Action);
        _filePath = evt.FilePath;
        _message = evt.Message;
        _bytesSaved = evt.BytesSaved;
    }

    private static string MapActionToCategory(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return "INFO";
        if (action.Contains("Dedup", StringComparison.OrdinalIgnoreCase) ||
            action.Contains("Consolidat", StringComparison.OrdinalIgnoreCase))
            return "DEDUP";
        if (action.Contains("Clone", StringComparison.OrdinalIgnoreCase)) return "CLONE";
        if (action.Contains("Pack", StringComparison.OrdinalIgnoreCase)) return "PACK";
        if (action.Contains("Unpack", StringComparison.OrdinalIgnoreCase)) return "UNPACK";
        if (action.Contains("Guard", StringComparison.OrdinalIgnoreCase) ||
            action.Contains("Game", StringComparison.OrdinalIgnoreCase))
            return "GUARD";
        if (action.Contains("Scan", StringComparison.OrdinalIgnoreCase)) return "SCAN";
        return "INFO";
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2.5 DUPLICATE FINDINGS & CLUSTER VIEW MODELS
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Represents an individual file copy within a duplicate cluster.
/// </summary>
public sealed class HyperStoreDuplicateCopyViewModel
{
    public string Path { get; }
    public string FilePath => Path;
    public string DirectoryPath { get; }
    public long FileSizeBytes { get; }
    public string FileSizeFormatted => HyperStoreViewModel.FormatBytes(FileSizeBytes);
    public DateTime LastModified { get; }
    public bool IsPrimary { get; }
    public string CopyTypeBadge => IsPrimary ? "ORIGINAL" : "DUPLICATE";
    public string CopyTypeBadgeBrush => IsPrimary ? "#00E5FF" : "#94A3B8";
    public string CopyTypeBadgeBg => IsPrimary ? "#1500E5FF" : "#141A29";

    public HyperStoreDuplicateCopyViewModel(string path, long fileSizeBytes, DateTime lastModified, bool isPrimary = false)
    {
        Path = path ?? string.Empty;
        DirectoryPath = System.IO.Path.GetDirectoryName(path) ?? string.Empty;
        FileSizeBytes = fileSizeBytes;
        LastModified = lastModified;
        IsPrimary = isPrimary;
    }
}

/// <summary>
/// Represents a cluster of duplicate files identified during a redundancy scan.
/// Features primary file name, path, duplicate count, wasted size, category breakdown badge,
/// individual selection, and per-cluster deduplication actions.
/// </summary>
public sealed class HyperStoreDuplicateFindingViewModel : INotifyPropertyChanged
{
    private bool _isSelected = true;
    private bool _isDeduplicated = false;
    private bool _isExpanded = false;
    private string _statusText = "Ready to Deduplicate";

    public event PropertyChangedEventHandler? PropertyChanged;

    public string ClusterId { get; }
    public string PrimaryFileName { get; }
    public string PrimaryFilePath { get; }
    public string DirectoryPath { get; }
    public int DuplicateCopiesCount => Copies.Count;
    public long FileSizeBytes { get; }
    public string FileSizeFormatted => HyperStoreViewModel.FormatBytes(FileSizeBytes);
    public long TotalWastedBytes => Math.Max(0, (Copies.Count - 1) * FileSizeBytes);
    public string WastedSizeFormatted => HyperStoreViewModel.FormatBytes(TotalWastedBytes);
    public string Extension { get; }
    public string Category { get; } // "Installers & Binaries", "Media", "Code & Archives", "Documents", "Other"
    public string FileTypeBadge { get; }
    public string FileTypeBadgeBrush { get; }
    public bool IsSafe { get; }

    public ObservableCollection<HyperStoreDuplicateCopyViewModel> Copies { get; } = new();
    public List<string> DuplicateFilePaths => Copies.Where(c => !c.IsPrimary).Select(c => c.Path).ToList();

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsDeduplicated
    {
        get => _isDeduplicated;
        set
        {
            if (_isDeduplicated != value)
            {
                _isDeduplicated = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsNotDeduplicated));
                OnPropertyChanged(nameof(DeduplicatedBadgeVisibility));
                OnPropertyChanged(nameof(ActionButtonsVisibility));
            }
        }
    }

    public bool IsNotDeduplicated => !_isDeduplicated;

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded != value)
            {
                _isExpanded = value;
                OnPropertyChanged();
            }
        }
    }

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

    public System.Windows.Visibility DeduplicatedBadgeVisibility => _isDeduplicated ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
    public System.Windows.Visibility ActionButtonsVisibility => _isDeduplicated ? System.Windows.Visibility.Collapsed : System.Windows.Visibility.Visible;

    public HyperStoreDuplicateFindingViewModel(
        string primaryFilePath,
        long fileSizeBytes,
        IEnumerable<string> duplicatePaths,
        bool isSafe = true)
    {
        PrimaryFilePath = primaryFilePath ?? string.Empty;
        PrimaryFileName = !string.IsNullOrEmpty(primaryFilePath)
            ? (System.IO.Path.GetFileName(primaryFilePath) ?? primaryFilePath)
            : "Unknown";
        DirectoryPath = !string.IsNullOrEmpty(primaryFilePath)
            ? (System.IO.Path.GetDirectoryName(primaryFilePath) ?? string.Empty)
            : string.Empty;
        FileSizeBytes = fileSizeBytes;
        Extension = !string.IsNullOrEmpty(primaryFilePath)
            ? (System.IO.Path.GetExtension(primaryFilePath) ?? string.Empty).ToLowerInvariant()
            : string.Empty;
        ClusterId = Guid.NewGuid().ToString("N");
        IsSafe = isSafe;

        (Category, FileTypeBadge, FileTypeBadgeBrush) = ClassifyExtension(Extension);

        DateTime primaryModified = DateTime.UtcNow;
        try
        {
            if (File.Exists(primaryFilePath))
            {
                primaryModified = new FileInfo(primaryFilePath).LastWriteTime;
            }
        }
        catch { }

        Copies.Add(new HyperStoreDuplicateCopyViewModel(PrimaryFilePath, fileSizeBytes, primaryModified, isPrimary: true));

        foreach (var dupPath in duplicatePaths)
        {
            if (string.IsNullOrWhiteSpace(dupPath) || string.Equals(dupPath, primaryFilePath, StringComparison.OrdinalIgnoreCase)) continue;
            DateTime dupModified = DateTime.UtcNow;
            try
            {
                if (File.Exists(dupPath))
                {
                    dupModified = new FileInfo(dupPath).LastWriteTime;
                }
            }
            catch { }
            Copies.Add(new HyperStoreDuplicateCopyViewModel(dupPath, fileSizeBytes, dupModified, isPrimary: false));
        }
    }

    public static (string Category, string Badge, string Brush) ClassifyExtension(string ext)
    {
        return ext switch
        {
            ".exe" or ".msi" or ".dll" or ".sys" or ".bin" or ".iso" or ".node" or ".appx" or ".msix" =>
                ("Installers & Binaries", "BIN / EXE", "#00E5FF"),

            ".mp4" or ".mkv" or ".avi" or ".mov" or ".wmv" or ".mp3" or ".wav" or ".flac" or
            ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp" or ".svg" or ".ico" or ".bmp" or ".tiff" =>
                ("Media", "MEDIA", "#A78BFA"),

            ".zip" or ".rar" or ".7z" or ".tar" or ".gz" or ".lfc" or ".bz2" or ".xz" or
            ".cs" or ".cpp" or ".h" or ".js" or ".ts" or ".json" or ".xml" or ".py" or ".rs" or ".go" or ".java" =>
                ("Code & Archives", "CODE / ZIP", "#F59E0B"),

            ".pdf" or ".docx" or ".doc" or ".xlsx" or ".xls" or ".pptx" or ".ppt" or
            ".txt" or ".md" or ".rtf" or ".csv" or ".log" or ".epub" =>
                ("Documents", "DOCUMENT", "#38BDF8"),

            _ => ("Other", "FILE", "#94A3B8")
        };
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. MAIN HYPERSTORE VIEW MODEL
// ═══════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Primary ViewModel for Requirement R4: Antivirus-Style Telemetry Dashboard (Storage Armor).
/// Coordinates 4 telemetry gauges, 500-item FIFO action feed, live progress reporting,
/// autonomous execution mode settings, and 100% async non-blocking operations.
/// </summary>
public sealed class HyperStoreViewModel : INotifyPropertyChanged
{
    public const int MaxActionFeedCapacity = 500;

    private readonly VolumeAwareDeduplicator _deduplicator;
    private readonly HyperStoreBackgroundWorker? _backgroundWorker;
    private readonly LfcWriter _lfcWriter;
    private readonly LfcReader _lfcReader = new();
    private readonly FastCdcChunker _chunker;

    private readonly object _actionFeedLock = new();
    private CancellationTokenSource? _activeOperationCts;

    // ─── 4 Telemetry Gauges State ───
    private long _totalBytesReclaimed;
    private long _totalScannedBytes;
    private double _spaceReclaimedPercent;
    private double _globalCompressionRatio = 1.0;
    private double _spaceReductionPercent;
    private long _chunksIndexed;
    private long _uniqueChunks;
    private long _duplicateChunks;
    private string _activeProtectionStatus = "Protected"; // "Protected", "Scanning", "Idle", "Suspended"

    // ─── Live Progress State ───
    private bool _isBusy;
    private double _progressPercent;
    private string _statusText = "Storage Armor Active — Standing by";
    private string _activeOperation = "Idle";
    private string _currentFile = string.Empty;
    private double _throughputMBs;
    private string _etaFormatted = "--:--";

    // ─── Execution Mode Settings ───
    private WorkerExecutionMode _executionMode = WorkerExecutionMode.ContinuousLowPriority;
    private bool _isGameGuardEnabled = true;
    private bool _isAcPowerOnly = true;
    private bool _isRefsCloningEnabled = true;

    // ─── Duplicate Redundancy Findings State ───
    public ObservableCollection<HyperStoreDuplicateFindingViewModel> DuplicateFindings { get; } = new();
    public ObservableCollection<HyperStoreDuplicateFindingViewModel> FilteredDuplicateFindings { get; } = new();
    public HashSet<string> ExcludedFolders { get; } = new(StringComparer.OrdinalIgnoreCase);

    private string _selectedCategoryFilter = "All";
    public string SelectedCategoryFilter
    {
        get => _selectedCategoryFilter;
        set
        {
            if (_selectedCategoryFilter != value)
            {
                _selectedCategoryFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsFilterAll));
                OnPropertyChanged(nameof(IsFilterInstallers));
                OnPropertyChanged(nameof(IsFilterMedia));
                OnPropertyChanged(nameof(IsFilterCodeArchives));
                OnPropertyChanged(nameof(IsFilterDocuments));
                ApplyCategoryFilter(value);
            }
        }
    }

    public bool IsFilterAll => _selectedCategoryFilter == "All";
    public bool IsFilterInstallers => _selectedCategoryFilter == "Installers & Binaries";
    public bool IsFilterMedia => _selectedCategoryFilter == "Media";
    public bool IsFilterCodeArchives => _selectedCategoryFilter == "Code & Archives";
    public bool IsFilterDocuments => _selectedCategoryFilter == "Documents";

    public int TotalFindingsCount => DuplicateFindings.Count;
    public int InstallersCount => DuplicateFindings.Count(f => f.Category == "Installers & Binaries");
    public int MediaCount => DuplicateFindings.Count(f => f.Category == "Media");
    public int CodeArchivesCount => DuplicateFindings.Count(f => f.Category == "Code & Archives");
    public int DocumentsCount => DuplicateFindings.Count(f => f.Category == "Documents");

    public int SelectedFindingsCount => DuplicateFindings.Count(f => f.IsSelected && !f.IsDeduplicated);
    public long SelectedWastedBytes => DuplicateFindings.Where(f => f.IsSelected && !f.IsDeduplicated).Sum(f => f.TotalWastedBytes);
    public string SelectedWastedSizeFormatted => FormatBytes(SelectedWastedBytes);

    public bool HasDuplicateFindings => DuplicateFindings.Count > 0;
    public System.Windows.Visibility FindingsVisibility => HasDuplicateFindings ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
    public System.Windows.Visibility FindingsEmptyVisibility => HasDuplicateFindings ? System.Windows.Visibility.Collapsed : System.Windows.Visibility.Visible;

    public string FindingsSummaryText => DuplicateFindings.Count > 0
        ? $"{DuplicateFindings.Count} clusters ({FormatBytes(DuplicateFindings.Sum(f => f.TotalWastedBytes))} recoverable) • {SelectedFindingsCount} selected"
        : "No duplicate clusters detected";

    // ─── Observable Action Feed ───
    public ObservableCollection<HyperStoreLogEntryViewModel> ActionFeed { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    // ─── Commands ───
    public ICommand ScanCommand { get; }
    public ICommand PackCommand { get; }
    public ICommand DedupCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ClearLogCommand { get; }
    public ICommand DeduplicateSelectedCommand { get; }
    public ICommand SelectAllSafeCommand { get; }
    public ICommand SelectAllCommand { get; }
    public ICommand DeselectAllCommand { get; }
    public ICommand FilterCategoryCommand { get; }
    public ICommand ExcludeFolderCommand { get; }
    public ICommand DeduplicateFindingCommand { get; }

    #region Gauge 1: Total Space Reclaimed

    /// <summary>
    /// Cumulative physical storage bytes reclaimed by deduplication and compression.
    /// </summary>
    public long TotalBytesReclaimed
    {
        get => _totalBytesReclaimed;
        set
        {
            if (_totalBytesReclaimed != value)
            {
                _totalBytesReclaimed = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TotalSpaceReclaimedFormatted));
                RecalculatePercentages();
            }
        }
    }

    /// <summary>
    /// Formatted total reclaimed space string (e.g. "142.80 GB").
    /// </summary>
    public string TotalSpaceReclaimedFormatted => FormatBytes(_totalBytesReclaimed);

    /// <summary>
    /// Cumulative raw logical bytes analyzed or scanned across all operations.
    /// </summary>
    public long TotalScannedBytes
    {
        get => _totalScannedBytes;
        set
        {
            if (_totalScannedBytes != value)
            {
                _totalScannedBytes = value;
                OnPropertyChanged();
                RecalculatePercentages();
            }
        }
    }

    /// <summary>
    /// Percentage of storage space reclaimed relative to total scanned bytes.
    /// </summary>
    public double SpaceReclaimedPercent
    {
        get => _spaceReclaimedPercent;
        private set
        {
            if (Math.Abs(_spaceReclaimedPercent - value) > 0.01)
            {
                _spaceReclaimedPercent = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SpaceReclaimedPercentFormatted));
            }
        }
    }

    public string SpaceReclaimedPercentFormatted => $"{_spaceReclaimedPercent:F1}% Net Gain";

    #endregion

    #region Gauge 2: Global Compression Ratio

    /// <summary>
    /// Global compression ratio across all indexed and packed containers (e.g. 3.82).
    /// </summary>
    public double GlobalCompressionRatio
    {
        get => _globalCompressionRatio;
        set
        {
            double safeValue = value < 1.0 ? 1.0 : Math.Round(value, 2);
            if (Math.Abs(_globalCompressionRatio - safeValue) > 0.001)
            {
                _globalCompressionRatio = safeValue;
                OnPropertyChanged();
                OnPropertyChanged(nameof(GlobalCompressionRatioFormatted));
                SpaceReductionPercent = _globalCompressionRatio > 1.0
                    ? Math.Round((1.0 - (1.0 / _globalCompressionRatio)) * 100.0, 1)
                    : 0.0;
            }
        }
    }

    public string GlobalCompressionRatioFormatted => $"{_globalCompressionRatio:F2}x";

    /// <summary>
    /// Percentage of physical space saved by compression (e.g. 73.8%).
    /// </summary>
    public double SpaceReductionPercent
    {
        get => _spaceReductionPercent;
        private set
        {
            if (Math.Abs(_spaceReductionPercent - value) > 0.01)
            {
                _spaceReductionPercent = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SpaceSavedPercentFormatted));
            }
        }
    }

    public string SpaceSavedPercentFormatted => $"{_spaceReductionPercent:F1}% Space Saved";

    #endregion

    #region Gauge 3: Chunks Indexed

    /// <summary>
    /// Total FastCDC chunks identified and fingerprinted across repositories.
    /// </summary>
    public long ChunksIndexed
    {
        get => _chunksIndexed;
        set
        {
            if (_chunksIndexed != value)
            {
                _chunksIndexed = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ChunksIndexedFormatted));
            }
        }
    }

    public string ChunksIndexedFormatted => _chunksIndexed.ToString("N0");

    public long UniqueChunks
    {
        get => _uniqueChunks;
        set
        {
            if (_uniqueChunks != value)
            {
                _uniqueChunks = value;
                OnPropertyChanged();
            }
        }
    }

    public long DuplicateChunks
    {
        get => _duplicateChunks;
        set
        {
            if (_duplicateChunks != value)
            {
                _duplicateChunks = value;
                OnPropertyChanged();
            }
        }
    }

    #endregion

    #region Gauge 4: Active Protection Status Badge

    /// <summary>
    /// Protection status badge state: "Protected", "Scanning", "Idle", "Suspended".
    /// </summary>
    public string ActiveProtectionStatus
    {
        get => _activeProtectionStatus;
        set
        {
            string normalized = NormalizeProtectionStatus(value);
            if (_activeProtectionStatus != normalized)
            {
                _activeProtectionStatus = normalized;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProtectionStatusBadgeBrush));
                OnPropertyChanged(nameof(ProtectionStatusDetail));
            }
        }
    }

    public string ProtectionStatusBadgeBrush => _activeProtectionStatus switch
    {
        "Protected" => "#22C55E", // Green
        "Scanning" => "#00E5FF",  // Cyan
        "Suspended" => "#F59E0B", // Amber
        "Idle" => "#94A3B8",      // Slate Gray
        _ => "#94A3B8"
    };

    public string ProtectionStatusDetail => _activeProtectionStatus switch
    {
        "Protected" => "FastCDC & Volume-Aware Armor",
        "Scanning" => "Active Storage Optimization in Progress...",
        "Suspended" => "Suspended by Game Guard / Power Sensor (<500ms SLA)",
        "Idle" => "Protection Standing By — Waiting for System Idle",
        _ => "HyperStore Ready"
    };

    private static string NormalizeProtectionStatus(string status)
    {
        if (string.IsNullOrWhiteSpace(status)) return "Idle";
        if (status.StartsWith("Prot", StringComparison.OrdinalIgnoreCase)) return "Protected";
        if (status.StartsWith("Scan", StringComparison.OrdinalIgnoreCase) ||
            status.StartsWith("Opt", StringComparison.OrdinalIgnoreCase)) return "Scanning";
        if (status.StartsWith("Susp", StringComparison.OrdinalIgnoreCase) ||
            status.StartsWith("Pause", StringComparison.OrdinalIgnoreCase)) return "Suspended";
        if (status.StartsWith("Idle", StringComparison.OrdinalIgnoreCase) ||
            status.StartsWith("Stop", StringComparison.OrdinalIgnoreCase)) return "Idle";
        return status;
    }

    #endregion

    #region Live Progress State

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (_isBusy != value)
            {
                _isBusy = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsNotBusy));
                OnPropertyChanged(nameof(ProgressVisibility));
            }
        }
    }

    public bool IsNotBusy => !_isBusy;

    public System.Windows.Visibility ProgressVisibility => _isBusy
        ? System.Windows.Visibility.Visible
        : System.Windows.Visibility.Collapsed;

    public double ProgressPercent
    {
        get => _progressPercent;
        set
        {
            double clamped = Math.Clamp(value, 0.0, 100.0);
            if (Math.Abs(_progressPercent - clamped) > 0.01)
            {
                _progressPercent = clamped;
                OnPropertyChanged();
            }
        }
    }

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

    public string ActiveOperation
    {
        get => _activeOperation;
        set
        {
            if (_activeOperation != value)
            {
                _activeOperation = value;
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
            if (Math.Abs(_throughputMBs - value) > 0.1)
            {
                _throughputMBs = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ThroughputFormatted));
            }
        }
    }

    public string ThroughputFormatted => $"{_throughputMBs:F1} MB/s";

    public string EtaFormatted
    {
        get => _etaFormatted;
        set
        {
            if (_etaFormatted != value)
            {
                _etaFormatted = value;
                OnPropertyChanged();
            }
        }
    }

    #endregion

    #region Execution Mode Settings

    public WorkerExecutionMode ExecutionMode
    {
        get => _executionMode;
        set
        {
            if (value != WorkerExecutionMode.ManualOnly
                && Common.UiDispatcher.IsMessageLoopRunning
                && !EditionService.Instance.Allows(OmniLicense.Capability.HyperStoreAutonomousWorker))
            {
                // Autonomous worker is Pro-only: keep the current mode, re-sync the radio buttons, show the upgrade prompt.
                System.Windows.Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
                {
                    OnPropertyChanged(nameof(IsContinuousLowPriority));
                    OnPropertyChanged(nameof(IsScheduledWindow));
                    OnPropertyChanged(nameof(IsManualOnly));
                    Gate.Require(OmniLicense.Capability.HyperStoreAutonomousWorker);
                }));
                return;
            }

            if (_executionMode != value)
            {
                _executionMode = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsContinuousLowPriority));
                OnPropertyChanged(nameof(IsScheduledWindow));
                OnPropertyChanged(nameof(IsManualOnly));

                if (_backgroundWorker != null)
                {
                    _backgroundWorker.Settings.Mode = value;
                }

                AddLogEntry("CONFIG", $"Storage Armor Trigger Mode set to {value}.");
            }
        }
    }

    public bool IsContinuousLowPriority
    {
        get => _executionMode == WorkerExecutionMode.ContinuousLowPriority;
        set
        {
            if (value && _executionMode != WorkerExecutionMode.ContinuousLowPriority)
            {
                ExecutionMode = WorkerExecutionMode.ContinuousLowPriority;
            }
        }
    }

    public bool IsScheduledWindow
    {
        get => _executionMode == WorkerExecutionMode.ScheduledWindow;
        set
        {
            if (value && _executionMode != WorkerExecutionMode.ScheduledWindow)
            {
                ExecutionMode = WorkerExecutionMode.ScheduledWindow;
            }
        }
    }

    public bool IsManualOnly
    {
        get => _executionMode == WorkerExecutionMode.ManualOnly;
        set
        {
            if (value && _executionMode != WorkerExecutionMode.ManualOnly)
            {
                ExecutionMode = WorkerExecutionMode.ManualOnly;
            }
        }
    }

    public bool IsGameGuardEnabled
    {
        get => _isGameGuardEnabled;
        set
        {
            if (_isGameGuardEnabled != value)
            {
                _isGameGuardEnabled = value;
                OnPropertyChanged();
                AddLogEntry("GUARD", $"Full-Screen Game Guard {(_isGameGuardEnabled ? "Enabled (<500ms suspend)" : "Disabled")}.");
            }
        }
    }

    public bool IsAcPowerOnly
    {
        get => _isAcPowerOnly;
        set
        {
            if (_isAcPowerOnly != value)
            {
                _isAcPowerOnly = value;
                OnPropertyChanged();
                if (_backgroundWorker != null)
                {
                    _backgroundWorker.Settings.RequireAcPower = value;
                }
            }
        }
    }

    public bool IsRefsCloningEnabled
    {
        get => _isRefsCloningEnabled;
        set
        {
            if (_isRefsCloningEnabled != value)
            {
                _isRefsCloningEnabled = value;
                OnPropertyChanged();
            }
        }
    }

    #endregion

    #region Constructor & Dependency Wiring

    public HyperStoreViewModel() : this(null, null, null, null)
    {
    }

    public HyperStoreViewModel(
        VolumeAwareDeduplicator? deduplicator = null,
        HyperStoreBackgroundWorker? backgroundWorker = null,
        LfcWriter? lfcWriter = null,
        FastCdcChunker? chunker = null)
    {
        _deduplicator = deduplicator ?? VolumeAwareDeduplicator.Instance;
        _backgroundWorker = backgroundWorker;
        _lfcWriter = lfcWriter ?? new LfcWriter();
        _chunker = chunker ?? new FastCdcChunker();

        try
        {
            var persistedExclusions = SettingsManager.Load().ScanExclusions;
            if (persistedExclusions is { Count: > 0 })
            {
                foreach (var ex in persistedExclusions)
                {
                    if (!string.IsNullOrWhiteSpace(ex))
                        ExcludedFolders.Add(ex);
                }
            }
        }
        catch { }

        // Initialize Commands
        ScanCommand = new RelayCommand(async () => await ScanDriveForRedundanciesAsync());
        PackCommand = new RelayCommand(async () =>
        {
            string defaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
            if (Directory.Exists(defaultDir))
            {
                await PackDirectoryToLfcAsync(defaultDir);
            }
        });
        DedupCommand = new RelayCommand(async () => await DeduplicateWorkspaceAsync());
        CancelCommand = new RelayCommand(CancelActiveOperation);
        ClearLogCommand = new RelayCommand(ClearActionFeed);
        DeduplicateSelectedCommand = new RelayCommand(async () => await DeduplicateSelectedAsync());
        SelectAllSafeCommand = new RelayCommand(SelectSafeFindings);
        SelectAllCommand = new RelayCommand(() => SelectAllFindings(true));
        DeselectAllCommand = new RelayCommand(() => SelectAllFindings(false));
        FilterCategoryCommand = new RelayCommand(cat => ApplyCategoryFilter(cat?.ToString() ?? "All"));
        ExcludeFolderCommand = new RelayCommand(folder => ExcludeFolder(folder?.ToString() ?? string.Empty));
        DeduplicateFindingCommand = new RelayCommand(async obj =>
        {
            if (obj is HyperStoreDuplicateFindingViewModel finding)
            {
                await DeduplicateFindingAsync(finding);
            }
        });

        // Wire background worker events if provided
        if (_backgroundWorker != null)
        {
            _backgroundWorker.OnOptimizationEvent += (_, evt) =>
            {
                UiDispatcher.Invoke(() =>
                {
                    TotalBytesReclaimed += evt.BytesSaved;
                    AddLogEntry(new HyperStoreLogEntryViewModel(evt));
                });
            };

            _backgroundWorker.OnStateChanged += (_, state) =>
            {
                UiDispatcher.Invoke(() =>
                {
                    ActiveProtectionStatus = state switch
                    {
                        WorkerState.Optimizing => "Scanning",
                        WorkerState.SuspendedByGameGuard => "Suspended",
                        WorkerState.SuspendedByBattery => "Suspended",
                        WorkerState.WaitingForIdle => "Protected",
                        WorkerState.PausedByUser => "Idle",
                        WorkerState.Stopped => "Idle",
                        _ => "Idle"
                    };
                });
            };
        }

        // Add initial welcome status entry
        AddLogEntry(new HyperStoreLogEntryViewModel(
            "SHIELD",
            "Storage Armor online — 32 KB FastCDC, 256-bit BLAKE3 SIMD & Zstd ready.",
            "",
            0));
    }

    #endregion

    #region Real-Time Action Feed FIFO Capping (500-Item Cap)

    /// <summary>
    /// Appends a log entry to the real-time action feed, strictly enforcing the 500-item FIFO cap.
    /// Thread-safe via UiDispatcher.
    /// </summary>
    public void AddLogEntry(HyperStoreLogEntryViewModel entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        UiDispatcher.Invoke(() =>
        {
            lock (_actionFeedLock)
            {
                while (ActionFeed.Count >= MaxActionFeedCapacity)
                {
                    ActionFeed.RemoveAt(0);
                }
                ActionFeed.Add(entry);
            }
        });
    }

    /// <summary>
    /// Convenience helper to create and append a log entry with specified metadata.
    /// </summary>
    public void AddLogEntry(string category, string message, string filePath = "", long bytesSaved = 0)
    {
        AddLogEntry(new HyperStoreLogEntryViewModel(category, message, filePath, bytesSaved));
    }

    /// <summary>
    /// Clears the real-time action feed.
    /// </summary>
    public void ClearActionFeed()
    {
        UiDispatcher.Invoke(() =>
        {
            lock (_actionFeedLock)
            {
                ActionFeed.Clear();
            }
        });
    }

    #endregion

    #region Duplicate Findings Management & Actions

    /// <summary>
    /// Refreshes computed totals, category counts, and summaries for duplicate findings.
    /// Thread-safe via UiDispatcher.
    /// </summary>
    public void RefreshFindingsSummaries()
    {
        UiDispatcher.Invoke(() =>
        {
            OnPropertyChanged(nameof(TotalFindingsCount));
            OnPropertyChanged(nameof(InstallersCount));
            OnPropertyChanged(nameof(MediaCount));
            OnPropertyChanged(nameof(CodeArchivesCount));
            OnPropertyChanged(nameof(DocumentsCount));
            OnPropertyChanged(nameof(SelectedFindingsCount));
            OnPropertyChanged(nameof(SelectedWastedBytes));
            OnPropertyChanged(nameof(SelectedWastedSizeFormatted));
            OnPropertyChanged(nameof(HasDuplicateFindings));
            OnPropertyChanged(nameof(FindingsVisibility));
            OnPropertyChanged(nameof(FindingsEmptyVisibility));
            OnPropertyChanged(nameof(FindingsSummaryText));
        });
    }

    /// <summary>
    /// Applies a category breakdown filter ("All", "Installers & Binaries", "Media", "Code & Archives", "Documents").
    /// </summary>
    public void ApplyCategoryFilter(string category)
    {
        _selectedCategoryFilter = string.IsNullOrWhiteSpace(category) ? "All" : category;
        UiDispatcher.Invoke(() =>
        {
            FilteredDuplicateFindings.Clear();
            var matches = _selectedCategoryFilter == "All"
                ? DuplicateFindings
                : DuplicateFindings.Where(f => string.Equals(f.Category, _selectedCategoryFilter, StringComparison.OrdinalIgnoreCase));

            foreach (var item in matches)
            {
                FilteredDuplicateFindings.Add(item);
            }

            OnPropertyChanged(nameof(SelectedCategoryFilter));
            OnPropertyChanged(nameof(IsFilterAll));
            OnPropertyChanged(nameof(IsFilterInstallers));
            OnPropertyChanged(nameof(IsFilterMedia));
            OnPropertyChanged(nameof(IsFilterCodeArchives));
            OnPropertyChanged(nameof(IsFilterDocuments));
            RefreshFindingsSummaries();
        });
    }

    /// <summary>
    /// Selects or deselects all duplicate clusters.
    /// </summary>
    public void SelectAllFindings(bool select)
    {
        UiDispatcher.Invoke(() =>
        {
            foreach (var finding in DuplicateFindings)
            {
                if (!finding.IsDeduplicated)
                {
                    finding.IsSelected = select;
                }
            }
            RefreshFindingsSummaries();
        });
    }

    /// <summary>
    /// Selects only safe duplicate findings (non-critical user folders, media, archives, installers).
    /// </summary>
    public void SelectSafeFindings()
    {
        UiDispatcher.Invoke(() =>
        {
            foreach (var finding in DuplicateFindings)
            {
                if (!finding.IsDeduplicated)
                {
                    finding.IsSelected = finding.IsSafe;
                }
            }
            RefreshFindingsSummaries();
        });
    }

    /// <summary>
    /// Excludes a folder from current findings and future deduplication passes.
    /// </summary>
    public void ExcludeFolder(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath)) return;
        string fullFolder;
        try
        {
            fullFolder = Path.GetFullPath(folderPath.Trim());
        }
        catch
        {
            fullFolder = folderPath.Trim();
        }

        if (fullFolder.Length > 3)
        {
            fullFolder = fullFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        ExcludedFolders.Add(fullFolder);

        // Persist to global ScanExclusions in SettingsManager so restarts & CLI/JunkCleaner honor it
        try
        {
            var settings = SettingsManager.Load();
            if (!settings.ScanExclusions.Any(x => string.Equals(x, fullFolder, StringComparison.OrdinalIgnoreCase)))
            {
                settings.ScanExclusions.Add(fullFolder);
                SettingsManager.Normalize(settings);
                SettingsManager.Save();
            }
        }
        catch { }

        string[] boundarySet = [fullFolder];
        UiDispatcher.Invoke(() =>
        {
            var toRemove = DuplicateFindings
                .Where(f => f.Copies.Any(c =>
                    VolumeAwareDeduplicator.IsExcludedByPathBoundary(c.DirectoryPath, boundarySet) ||
                    VolumeAwareDeduplicator.IsExcludedByPathBoundary(c.FilePath, boundarySet)))
                .ToList();

            foreach (var item in toRemove)
            {
                DuplicateFindings.Remove(item);
                FilteredDuplicateFindings.Remove(item);
            }

            RefreshFindingsSummaries();
        });

        AddLogEntry("CONFIG", $"Excluded folder '{fullFolder}' from Storage Armor deduplication.", fullFolder, 0);
    }

    /// <summary>
    /// Deduplicates a single duplicate cluster using volume-aware ReFS block cloning or NTFS hard linking.
    /// </summary>
    public async Task<long> DeduplicateFindingAsync(HyperStoreDuplicateFindingViewModel finding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (finding.IsDeduplicated) return 0;

        long reclaimedInCluster = 0;
        string primary = finding.PrimaryFilePath;
        var dedupOptions = new DedupOptions
        {
            AllowMutableHardLinks = true,
            EnableCrossVolumeLfcFallback = true
        };

        int successfulCopies = 0;
        int preservedCopies = 0;
        int failedCopies = 0;

        foreach (var copy in finding.Copies.Where(c => !c.IsPrimary))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var itemResult = await _deduplicator.DeduplicatePairAsync(primary, copy.Path, dedupOptions, ct: ct).ConfigureAwait(false);
                if (itemResult.Success && itemResult.BytesReclaimed > 0)
                {
                    reclaimedInCluster += itemResult.BytesReclaimed;
                    successfulCopies++;
                }
                else if (itemResult.Success && itemResult.Method == DedupMethod.SkippedIdenticalLink)
                {
                    successfulCopies++;
                }
                else if (itemResult.Method == DedupMethod.PreservedMutable)
                {
                    preservedCopies++;
                }
                else
                {
                    failedCopies++;
                }
            }
            catch (Exception ex)
            {
                failedCopies++;
                AddLogEntry("ERROR", $"Deduplication failed for '{copy.Path}': {ex.Message}", copy.Path, 0);
            }
        }

        if (reclaimedInCluster > 0 || successfulCopies > 0)
        {
            UiDispatcher.Invoke(() =>
            {
                finding.IsDeduplicated = true;
                finding.StatusText = "Consolidated";
                TotalBytesReclaimed += reclaimedInCluster;
                DuplicateChunks += successfulCopies;
                RefreshFindingsSummaries();
            });

            AddLogEntry(
                "DEDUP",
                $"Consolidated duplicate '{finding.PrimaryFileName}' ({successfulCopies} copies) — Reclaimed {FormatBytes(reclaimedInCluster)}",
                finding.PrimaryFilePath,
                reclaimedInCluster);

            return reclaimedInCluster;
        }
        else if (preservedCopies > 0)
        {
            UiDispatcher.Invoke(() =>
            {
                finding.StatusText = "Preserved (Safety Guard)";
                RefreshFindingsSummaries();
            });

            AddLogEntry(
                "GUARD",
                $"Preserved '{finding.PrimaryFileName}' — mutable document protected from hard linking",
                finding.PrimaryFilePath,
                0);

            return 0;
        }
        else
        {
            UiDispatcher.Invoke(() =>
            {
                finding.StatusText = failedCopies > 0 ? "Failed" : "Preserved";
                RefreshFindingsSummaries();
            });

            return 0;
        }
    }

    /// <summary>
    /// Consolidates all selected duplicate clusters in batch.
    /// </summary>
    public async Task<long> DeduplicateSelectedAsync(CancellationToken ct = default)
    {
        if (IsBusy) return 0;

        var selected = DuplicateFindings.Where(f => f.IsSelected && !f.IsDeduplicated).ToList();
        if (selected.Count == 0) return 0;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeOperationCts = cts;

        UiDispatcher.Invoke(() =>
        {
            IsBusy = true;
            ActiveOperation = "Deduplicating Selected";
            ActiveProtectionStatus = "Scanning";
            StatusText = $"Deduplicating {selected.Count} selected clusters...";
            ProgressPercent = 0.0;
        });

        AddLogEntry("DEDUP", $"Starting batch deduplication of {selected.Count} duplicate clusters...", "", 0);

        long totalReclaimed = 0;
        int processed = 0;

        try
        {
            foreach (var finding in selected)
            {
                cts.Token.ThrowIfCancellationRequested();

                long reclaimed = await DeduplicateFindingAsync(finding, cts.Token).ConfigureAwait(false);
                totalReclaimed += reclaimed;

                processed++;
                double percent = Math.Min(100.0, (double)processed / selected.Count * 100.0);

                UiDispatcher.Invoke(() =>
                {
                    ProgressPercent = percent;
                    StatusText = $"Consolidating {processed}/{selected.Count} clusters ({percent:F0}%)...";
                    CurrentFile = finding.PrimaryFileName;
                });
            }

            AddLogEntry(
                "DEDUP",
                $"Batch deduplication complete: {processed} clusters consolidated — Reclaimed {FormatBytes(totalReclaimed)}.",
                "",
                totalReclaimed);

            return totalReclaimed;
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("ALERT", "Batch deduplication canceled by user.", "", 0);
            return totalReclaimed;
        }
        finally
        {
            _activeOperationCts = null;
            UiDispatcher.Invoke(() =>
            {
                IsBusy = false;
                ActiveOperation = "Idle";
                ActiveProtectionStatus = "Protected";
                StatusText = "Deduplication Complete — Storage Armor Active";
                CurrentFile = string.Empty;
                RefreshFindingsSummaries();
            });
        }
    }

    #endregion

    #region Interactive Actions (100% Async Non-Blocking)

    /// <summary>
    /// Scans a target path or user profile for redundancies using FastCDC chunking and 256-bit BLAKE3 hashing.
    /// Populates actionable itemized duplicate clusters with category breakdown and live non-blocking telemetry.
    /// 100% async non-blocking execution via Task.Run with zero UI freezes.
    /// </summary>
    public async Task<int> ScanDriveForRedundanciesAsync(string? targetPath = null, CancellationToken ct = default)
    {
        if (IsBusy) return 0;

        string target = string.IsNullOrWhiteSpace(targetPath)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            : targetPath;

        if (!Directory.Exists(target))
        {
            target = Path.GetTempPath();
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeOperationCts = cts;

        UiDispatcher.Invoke(() =>
        {
            IsBusy = true;
            ActiveOperation = "Scanning Drive";
            ActiveProtectionStatus = "Scanning";
            StatusText = $"Discovering files in '{target}'...";
            ProgressPercent = 0.0;
        });

        AddLogEntry("SCAN", $"Initiating redundancy scan across '{target}'...", target, 0);

        try
        {
            return await Task.Run(() =>
            {
                // 1. Enumerate files safely with live UI telemetry updates
                var allFiles = new List<string>();
                var visitedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var dirQueue = new Queue<string>();

                dirQueue.Enqueue(target);
                try { visitedDirs.Add(Path.GetFullPath(target)); } catch { visitedDirs.Add(target); }

                while (dirQueue.Count > 0)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    string currentDir = dirQueue.Dequeue();

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(currentDir))
                        {
                            cts.Token.ThrowIfCancellationRequested();
                            allFiles.Add(file);
                            if (allFiles.Count % 25 == 0)
                            {
                                int count = allFiles.Count;
                                string fn = Path.GetFileName(file);
                                UiDispatcher.Invoke(() =>
                                {
                                    StatusText = $"Discovering files in '{Path.GetFileName(target)}'... ({count:N0} found)";
                                    CurrentFile = fn;
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (DirectoryNotFoundException) { }
                    catch (IOException) { }
                    catch (System.Security.SecurityException) { }

                    try
                    {
                        foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                        {
                            cts.Token.ThrowIfCancellationRequested();
                            try
                            {
                                var dirInfo = new DirectoryInfo(subDir);
                                if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                                    continue;

                                string normalized = Path.GetFullPath(subDir);
                                if (visitedDirs.Add(normalized))
                                {
                                    dirQueue.Enqueue(subDir);
                                }
                            }
                            catch { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (DirectoryNotFoundException) { }
                    catch (IOException) { }
                    catch (System.Security.SecurityException) { }
                }

                int totalFiles = allFiles.Count;
                if (totalFiles == 0)
                {
                    UiDispatcher.Invoke(() =>
                    {
                        StatusText = "Scan completed: zero files found in target.";
                        ProgressPercent = 100.0;
                        DuplicateFindings.Clear();
                        FilteredDuplicateFindings.Clear();
                        RefreshFindingsSummaries();
                    });
                    return 0;
                }

                // Filter out excluded folders (both HyperStore-local and global Settings exclusions)
                var globalExclusions = new List<string>();
                try
                {
                    var us = SettingsManager.Load().ScanExclusions;
                    if (us != null) globalExclusions.AddRange(us);
                }
                catch { }

                var eligibleFiles = allFiles
                    .Where(f => !VolumeAwareDeduplicator.IsExcludedByPathBoundary(f, ExcludedFolders) &&
                                !VolumeAwareDeduplicator.IsExcludedByPathBoundary(f, globalExclusions))
                    .ToList();

                // 2. Pre-filter: Group by exact file size
                var sizeGroups = new Dictionary<long, List<string>>();
                long totalLogicalBytes = 0;

                foreach (var file in eligibleFiles)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists || info.Length == 0) continue;
                        totalLogicalBytes += info.Length;

                        if (!sizeGroups.TryGetValue(info.Length, out var list))
                        {
                            list = new List<string>();
                            sizeGroups[info.Length] = list;
                        }
                        list.Add(file);
                    }
                    catch { }
                }

                var candidateGroups = sizeGroups.Where(kv => kv.Value.Count > 1).ToList();
                int totalCandidates = candidateGroups.Sum(kv => kv.Value.Count);
                int candidatesHashed = 0;
                long bytesHashed = 0;
                var startTime = DateTime.UtcNow;

                // 3. Compute 256-bit BLAKE3 hashes for candidate files with matching sizes
                var duplicateClusters = new List<List<string>>();

                foreach (var group in candidateGroups)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    var hashGroups = new Dictionary<Hash256, List<string>>();

                    foreach (var file in group.Value)
                    {
                        cts.Token.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
                            Hash256 hash = Hash256.Compute(fs);

                            if (!hashGroups.TryGetValue(hash, out var cluster))
                            {
                                cluster = new List<string>();
                                hashGroups[hash] = cluster;
                            }
                            cluster.Add(file);
                            bytesHashed += group.Key;
                        }
                        catch { }

                        candidatesHashed++;
                        double percent = totalCandidates > 0 ? Math.Min(90.0, (double)candidatesHashed / totalCandidates * 90.0) : 0;
                        double elapsedSec = Math.Max(0.001, (DateTime.UtcNow - startTime).TotalSeconds);
                        double throughput = (bytesHashed / (1024.0 * 1024.0)) / elapsedSec;

                        if (candidatesHashed % 5 == 0 || candidatesHashed == totalCandidates)
                        {
                            int ch = candidatesHashed;
                            string fn = Path.GetFileName(file);
                            UiDispatcher.Invoke(() =>
                            {
                                ProgressPercent = percent;
                                StatusText = $"Fingerprinting candidates: {ch}/{totalCandidates} ({percent:F0}%)...";
                                CurrentFile = fn;
                                ThroughputMBs = throughput;
                            });
                        }
                    }

                    foreach (var kvp in hashGroups)
                    {
                        if (kvp.Value.Count > 1)
                        {
                            duplicateClusters.Add(kvp.Value);
                        }
                    }
                }

                // 4. Create Duplicate Findings Models
                var newFindings = new List<HyperStoreDuplicateFindingViewModel>();
                long totalWastedBytes = 0;

                foreach (var cluster in duplicateClusters.OrderByDescending(c =>
                {
                    try { return new FileInfo(c[0]).Length * (c.Count - 1); } catch { return 0L; }
                }))
                {
                    try
                    {
                        long fileLen = new FileInfo(cluster[0]).Length;
                        bool isSafe = FileImmutabilityClassifier.IsSafeForNtfsHardLink(cluster[0]) &&
                                      cluster.All(p => !FileImmutabilityClassifier.IsInProtectedPath(p));
                        var finding = new HyperStoreDuplicateFindingViewModel(cluster[0], fileLen, cluster.Skip(1), isSafe: isSafe);
                        totalWastedBytes += finding.TotalWastedBytes;
                        newFindings.Add(finding);
                    }
                    catch { }
                }

                // 5. FastCDC chunk indexing analysis across non-empty files
                var chunkMap = new Dictionary<Hash256, int>();
                long redundantChunkBytes = 0;
                long totalChunks = 0;
                long dupChunks = 0;

                var sampleFiles = eligibleFiles.Count > 200 ? eligibleFiles.Take(200).ToList() : eligibleFiles;
                foreach (var file in sampleFiles)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    try
                    {
                        var fi = new FileInfo(file);
                        if (!fi.Exists || fi.Length == 0) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
                        var chunks = _chunker.ChunkStreamWithData(fs);
                        foreach (var chunk in chunks)
                        {
                            totalChunks++;
                            Hash256 chHash = Hash256.Compute(chunk.Data.Span);
                            if (chunkMap.TryGetValue(chHash, out int cnt))
                            {
                                chunkMap[chHash] = cnt + 1;
                                dupChunks++;
                                redundantChunkBytes += chunk.Descriptor.RawSize;
                            }
                            else
                            {
                                chunkMap[chHash] = 1;
                            }
                        }
                    }
                    catch { }
                }

                if (totalWastedBytes > 0 && redundantChunkBytes == 0)
                {
                    redundantChunkBytes = totalWastedBytes;
                    dupChunks = Math.Max(1, newFindings.Sum(f => f.DuplicateCopiesCount - 1));
                }

                long uniqueChunks = chunkMap.Count;
                long finalReclaimableBytes = Math.Max(redundantChunkBytes, totalWastedBytes);
                double savingsRatio = totalLogicalBytes > 0 && (totalLogicalBytes - finalReclaimableBytes) > 0
                    ? Math.Round((double)totalLogicalBytes / Math.Max(1, totalLogicalBytes - finalReclaimableBytes), 2)
                    : 1.0;

                // 6. Update UI with real measured findings and telemetry (never fabricated)
                UiDispatcher.Invoke(() =>
                {
                    DuplicateFindings.Clear();
                    FilteredDuplicateFindings.Clear();

                    foreach (var finding in newFindings)
                    {
                        DuplicateFindings.Add(finding);
                    }

                    ApplyCategoryFilter(_selectedCategoryFilter);

                    ChunksIndexed = totalChunks;
                    UniqueChunks = uniqueChunks;
                    DuplicateChunks = dupChunks;
                    TotalScannedBytes = totalLogicalBytes;
                    GlobalCompressionRatio = savingsRatio;

                    ProgressPercent = 100.0;
                    StatusText = $"Scan finished: {eligibleFiles.Count} files scanned. Found {newFindings.Count} duplicate clusters ({FormatBytes(totalWastedBytes)} recoverable).";
                    CurrentFile = string.Empty;
                    RefreshFindingsSummaries();
                });

                AddLogEntry(
                    "SCAN",
                    $"Scan finished: {eligibleFiles.Count} files scanned ({FormatBytes(totalLogicalBytes)}). Found {newFindings.Count} duplicate clusters ({FormatBytes(totalWastedBytes)} recoverable) with {dupChunks} redundant chunks.",
                    target,
                    finalReclaimableBytes);

                return eligibleFiles.Count;
            }, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("ALERT", "Redundancy scan aborted by user.", target, 0);
            return 0;
        }
        catch (Exception ex)
        {
            AddLogEntry("ERROR", $"Redundancy scan failed: {ex.Message}", target, 0);
            return 0;
        }
        finally
        {
            _activeOperationCts = null;
            UiDispatcher.Invoke(() =>
            {
                IsBusy = false;
                ActiveOperation = "Idle";
                ActiveProtectionStatus = "Protected";
                StatusText = "Scan Complete — Storage Armor Active";
                CurrentFile = string.Empty;
                ThroughputMBs = 0.0;
                RefreshFindingsSummaries();
            });
        }
    }

    /// <summary>
    /// Packs a directory into a sovereign .lfc binary archive using dual-tier Zstandard compression.
    /// 100% async non-blocking execution with live IProgress updates.
    /// </summary>
    public async Task<string> PackDirectoryToLfcAsync(string sourceDir, string? destinationLfc = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDir);

        if (IsBusy) return string.Empty;

        if (!Directory.Exists(sourceDir))
        {
            AddLogEntry("ERROR", $"Source directory does not exist: {sourceDir}", sourceDir, 0);
            return string.Empty;
        }

        var mergedExclusions = new List<string>(ExcludedFolders);
        try
        {
            var globalExclusions = SettingsManager.Load().ScanExclusions;
            if (globalExclusions is { Count: > 0 })
                mergedExclusions.AddRange(globalExclusions);
        }
        catch { }

        if (VolumeAwareDeduplicator.IsExcludedByPathBoundary(sourceDir, mergedExclusions))
        {
            AddLogEntry("ALERT", $"Skipped packing '{sourceDir}' — folder is excluded in ScanExclusions.", sourceDir, 0);
            return string.Empty;
        }

        string dest = destinationLfc ?? Path.Combine(
            Path.GetDirectoryName(sourceDir) ?? sourceDir,
            $"{Path.GetFileName(sourceDir.TrimEnd('\\', '/'))}.lfc");

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeOperationCts = cts;

        UiDispatcher.Invoke(() =>
        {
            IsBusy = true;
            ActiveOperation = "Packing Directory";
            ActiveProtectionStatus = "Scanning";
            StatusText = $"Packing '{Path.GetFileName(sourceDir)}' into .lfc...";
            ProgressPercent = 0.0;
        });

        AddLogEntry("PACK", $"Packing directory '{sourceDir}' to '{Path.GetFileName(dest)}'...", dest, 0);

        var progress = new Progress<HyperStoreProgressReport>(report =>
        {
            UiDispatcher.Invoke(() =>
            {
                if (report.TotalFiles > 0)
                {
                    ProgressPercent = Math.Min(100.0, (double)report.FilesProcessed / report.TotalFiles * 100.0);
                }
                StatusText = $"Packed {report.FilesProcessed}/{report.TotalFiles} files ({ProgressPercent:F0}%)...";
                CurrentFile = report.CurrentFile;
            });
        });

        try
        {
            var packOpts = new LfcPackOptions
            {
                Tier = LfcPackOptions.Default.Tier,
                TrainDictionary = LfcPackOptions.Default.TrainDictionary,
                EnableDeltaCompression = LfcPackOptions.Default.EnableDeltaCompression,
                MaxDictionarySize = LfcPackOptions.Default.MaxDictionarySize,
                ExcludedPaths = mergedExclusions
            };

            await Task.Run(async () =>
            {
                await _lfcWriter.PackDirectoryAsync(sourceDir, dest, packOpts, progress, cts.Token).ConfigureAwait(false);
            }, cts.Token).ConfigureAwait(false);

            var info = new FileInfo(dest);
            long rawSize = 0;
            try
            {
                rawSize = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories)
                    .Where(f => !VolumeAwareDeduplicator.IsExcludedByPathBoundary(f, mergedExclusions))
                    .Sum(f => new FileInfo(f).Length);
            }
            catch { }

            long saved = Math.Max(0, rawSize - info.Length);
            double ratio = info.Length > 0 ? (double)rawSize / info.Length : 1.0;

            UiDispatcher.Invoke(() =>
            {
                TotalBytesReclaimed += saved;
                if (ratio > GlobalCompressionRatio)
                {
                    GlobalCompressionRatio = ratio;
                }
                TotalScannedBytes += rawSize;
            });

            AddLogEntry(
                "PACK",
                $"Successfully packed '{Path.GetFileName(sourceDir)}' into .lfc — Saved {FormatBytes(saved)} ({ratio:F2}x compression).",
                dest,
                saved);

            return dest;
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("ALERT", "Container packing operation canceled by user.", dest, 0);
            return string.Empty;
        }
        catch (Exception ex)
        {
            AddLogEntry("ERROR", $"Container pack error: {ex.Message}", dest, 0);
            return string.Empty;
        }
        finally
        {
            _activeOperationCts = null;
            UiDispatcher.Invoke(() =>
            {
                IsBusy = false;
                ActiveOperation = "Idle";
                ActiveProtectionStatus = "Protected";
                StatusText = "Packing Complete — Storage Armor Active";
                CurrentFile = string.Empty;
            });
        }
    }

    /// <summary>
    /// Unpacks a sovereign .lfc binary archive into a destination directory using LfcReader.
    /// 100% async non-blocking execution with live IProgress updates and CRC32C/BLAKE3 verification.
    /// </summary>
    public async Task<string> UnpackLfcArchiveAsync(string lfcPath, string? destinationDir = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(lfcPath);

        if (IsBusy) return string.Empty;

        if (!File.Exists(lfcPath))
        {
            AddLogEntry("ERROR", $"Archive file does not exist: {lfcPath}", lfcPath, 0);
            return string.Empty;
        }

        string dest = string.IsNullOrWhiteSpace(destinationDir)
            ? Path.Combine(
                Path.GetDirectoryName(lfcPath) ?? Path.GetTempPath(),
                $"{Path.GetFileNameWithoutExtension(lfcPath)}_Unpacked")
            : destinationDir;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeOperationCts = cts;

        UiDispatcher.Invoke(() =>
        {
            IsBusy = true;
            ActiveOperation = "Unpacking Archive";
            ActiveProtectionStatus = "Scanning";
            StatusText = $"Unpacking '{Path.GetFileName(lfcPath)}'...";
            ProgressPercent = 0.0;
        });

        AddLogEntry("UNPACK", $"Unpacking archive '{Path.GetFileName(lfcPath)}' to '{dest}'...", lfcPath, 0);

        var progress = new Progress<HyperStoreProgressReport>(report =>
        {
            UiDispatcher.Invoke(() =>
            {
                if (report.TotalFiles > 0)
                {
                    ProgressPercent = Math.Min(100.0, (double)report.FilesProcessed / report.TotalFiles * 100.0);
                }
                StatusText = $"Unpacked {report.FilesProcessed}/{report.TotalFiles} files ({ProgressPercent:F0}%)...";
                CurrentFile = report.CurrentFile;
            });
        });

        try
        {
            var info = _lfcReader.InspectArchive(lfcPath);
            await Task.Run(async () =>
            {
                await _lfcReader.UnpackArchiveAsync(lfcPath, dest, LfcUnpackOptions.Default, progress, cts.Token).ConfigureAwait(false);
            }, cts.Token).ConfigureAwait(false);

            int extractedCount = info.Manifest?.Files.Count ?? 0;
            AddLogEntry(
                "UNPACK",
                $"Successfully unpacked {extractedCount} file(s) from '{Path.GetFileName(lfcPath)}' to '{dest}'.",
                dest,
                0);

            return dest;
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("ALERT", "Archive unpacking canceled by user.", lfcPath, 0);
            return string.Empty;
        }
        catch (Exception ex)
        {
            AddLogEntry("ERROR", $"Archive unpack error: {ex.Message}", lfcPath, 0);
            return string.Empty;
        }
        finally
        {
            _activeOperationCts = null;
            UiDispatcher.Invoke(() =>
            {
                IsBusy = false;
                ActiveOperation = "Idle";
                ActiveProtectionStatus = "Protected";
                StatusText = "Unpacking Complete — Storage Armor Active";
                CurrentFile = string.Empty;
            });
        }
    }

    /// <summary>
    /// Executes volume-aware host deduplication across a directory workspace.
    /// Utilizes native ReFS Block Extent Cloning or atomic NTFS Hard Links with immutability whitelisting.
    /// </summary>
    public async Task<DedupResult> DeduplicateWorkspaceAsync(string? targetPath = null, bool dryRun = false, CancellationToken ct = default)
    {
        if (IsBusy) return new DedupResult();

        string target = string.IsNullOrWhiteSpace(targetPath)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop")
            : targetPath;

        if (!Directory.Exists(target))
        {
            target = Path.GetTempPath();
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeOperationCts = cts;

        UiDispatcher.Invoke(() =>
        {
            IsBusy = true;
            ActiveOperation = dryRun ? "Simulating Deduplication" : "Deduplicating Workspace";
            ActiveProtectionStatus = "Scanning";
            StatusText = $"Deduplicating workspace '{target}'...";
            ProgressPercent = 0.0;
        });

        AddLogEntry("DEDUP", $"{(dryRun ? "Simulating" : "Starting")} workspace deduplication in '{target}'...", target, 0);

        var progress = new Progress<DedupProgress>(p =>
        {
            UiDispatcher.Invoke(() =>
            {
                if (p.TotalFiles > 0)
                {
                    ProgressPercent = Math.Min(100.0, (double)p.FilesScanned / p.TotalFiles * 100.0);
                }
                StatusText = $"Processed {p.FilesScanned}/{p.TotalFiles} files ({ProgressPercent:F0}%)...";
                CurrentFile = p.CurrentFile;
            });
        });

        try
        {
            var combinedExclusions = new List<string>(ExcludedFolders);
            try
            {
                var us = SettingsManager.Load().ScanExclusions;
                if (us != null) combinedExclusions.AddRange(us);
            }
            catch { }

            var options = new DedupOptions
            {
                DryRun = dryRun,
                AllowMutableHardLinks = false,
                EnableCrossVolumeLfcFallback = true,
                ExcludedPaths = combinedExclusions
            };

            var result = await Task.Run(async () =>
            {
                return await _deduplicator.DeduplicateDirectoryAsync(target, options, progress, cts.Token).ConfigureAwait(false);
            }, cts.Token).ConfigureAwait(false);

            UiDispatcher.Invoke(() =>
            {
                TotalBytesReclaimed += result.TotalBytesReclaimed;
                DuplicateChunks += result.DuplicatesConsolidated;
                TotalScannedBytes += result.TotalBytesReclaimed * 2; // Estimation of processed footprint
            });

            foreach (var item in result.Items.Where(i => i.Success && i.BytesReclaimed > 0).Take(50))
            {
                AddLogEntry(
                    item.Method == DedupMethod.RefsBlockClone ? "CLONE" : "DEDUP",
                    $"Consolidated duplicate {Path.GetFileName(item.TargetPath)} ({item.Method}) — Reclaimed {FormatBytes(item.BytesReclaimed)}",
                    item.TargetPath,
                    item.BytesReclaimed);
            }

            AddLogEntry(
                dryRun ? "SIMULATE" : "DEDUP",
                $"Deduplication pass complete: {result.DuplicatesConsolidated} duplicates consolidated, {result.MutableFilesPreserved} mutable files protected — Reclaimed {FormatBytes(result.TotalBytesReclaimed)}.",
                target,
                result.TotalBytesReclaimed);

            return result;
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("ALERT", "Workspace deduplication canceled by user.", target, 0);
            return new DedupResult();
        }
        catch (Exception ex)
        {
            AddLogEntry("ERROR", $"Deduplication failed: {ex.Message}", target, 0);
            return new DedupResult();
        }
        finally
        {
            _activeOperationCts = null;
            UiDispatcher.Invoke(() =>
            {
                IsBusy = false;
                ActiveOperation = "Idle";
                ActiveProtectionStatus = "Protected";
                StatusText = "Deduplication Complete — Storage Armor Active";
                CurrentFile = string.Empty;
            });
        }
    }

    /// <summary>
    /// Sets the autonomous background worker execution mode.
    /// </summary>
    public void SetExecutionMode(WorkerExecutionMode mode)
    {
        ExecutionMode = mode;
    }

    /// <summary>
    /// Cancels any active scan, pack, or deduplication operation.
    /// </summary>
    public void CancelActiveOperation()
    {
        if (_activeOperationCts != null && !_activeOperationCts.IsCancellationRequested)
        {
            _activeOperationCts.Cancel();
            UiDispatcher.Invoke(() =>
            {
                StatusText = "Cancelling active storage operation...";
            });
        }
    }

    /// <summary>
    /// Manually updates telemetry gauge values (useful in testing and integration).
    /// </summary>
    public void UpdateMetrics(long bytesReclaimed, double ratio, long chunksIndexed, string? protectionStatus = null)
    {
        UiDispatcher.Invoke(() =>
        {
            TotalBytesReclaimed = bytesReclaimed;
            GlobalCompressionRatio = ratio;
            ChunksIndexed = chunksIndexed;
            if (!string.IsNullOrWhiteSpace(protectionStatus))
            {
                ActiveProtectionStatus = protectionStatus;
            }
        });
    }

    #endregion

    #region Internal Calculations & String Formatting

    private void RecalculatePercentages()
    {
        if (_totalScannedBytes > 0 && _totalBytesReclaimed > 0)
        {
            SpaceReclaimedPercent = Math.Round((double)_totalBytesReclaimed / _totalScannedBytes * 100.0, 1);
        }
        else
        {
            SpaceReclaimedPercent = 0.0;
        }
    }

    /// <summary>
    /// Formats raw byte counts into human-readable strings (B, KB, MB, GB).
    /// </summary>
    public static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024)
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        if (bytes >= 1024L * 1024)
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        if (bytes >= 1024L)
            return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    #endregion
}
