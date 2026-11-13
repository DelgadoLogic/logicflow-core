// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – JunkCleanerEngine
// Smart junk file cleaner: temp files, browser caches, logs, WU cache, etc.
// Classic feature from TuneUp Utilities (2003), CCleaner, and Glary Utilities
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Scans and cleans junk files across multiple categories.
/// Each category can be independently toggled and previewed before cleaning.
/// </summary>
public sealed class JunkCleanerEngine
{
    private readonly ILogger<JunkCleanerEngine>? _logger;

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    private const uint SHERB_NOCONFIRMATION = 0x00000001;
    private const uint SHERB_NOPROGRESSUI   = 0x00000002;
    private const uint SHERB_NOSOUND        = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SHQUERYRBINFO
    {
        public int cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    public BrowserPrivacyCleanerEngine BrowserPrivacyCleaner { get; }

    public JunkCleanerEngine(ILogger<JunkCleanerEngine>? logger = null, BrowserPrivacyCleanerEngine? browserPrivacyCleaner = null)
    {
        _logger = logger;
        BrowserPrivacyCleaner = browserPrivacyCleaner ?? new BrowserPrivacyCleanerEngine();
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public enum JunkCategory
    {
        WindowsTemp,
        UserTemp,
        BrowserCache,
        WindowsLogs,
        WindowsUpdateCache,
        RecycleBin,
        Thumbnails,
        Prefetch,
        CrashDumps,
        InstallerCache,
        GpuShaderCache,
        DriverStoreCache,
        DeliveryOptimizationCache
    }

    public sealed class JunkScanResult : INotifyPropertyChanged
    {
        public JunkCategory Category { get; init; }
        public string DisplayName { get; init; } = "";
        public string Description { get; init; } = "";
        public string TargetPathSummary { get; set; } = "";
        public bool IsSafeCategory { get; set; } = true;
        public List<JunkFile> Files { get; init; } = new();
        public long TotalBytes => Files.Sum(f => f.SizeBytes);
        public string TotalFormatted => FormatBytes(TotalBytes);
        public int FileCount => Files.Count;

        private bool _isSelected = true;
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

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public sealed class JunkFile
    {
        public string Path { get; init; } = "";
        public long SizeBytes { get; init; }
        public DateTime LastModified { get; init; }
    }

    public sealed class CleanResult
    {
        public long BytesCleaned { get; init; }
        public int FilesDeleted { get; init; }
        public int FilesFailed { get; init; }
        public bool WasCancelled { get; init; }
        public List<string> Errors { get; init; } = new();
        public string BytesCleanedFormatted => FormatBytes(BytesCleaned);
    }

    /// <summary>
    /// User-configured folder or file paths excluded from junk scanning and deletion.
    /// </summary>
    public IReadOnlyList<string> ExcludedPaths { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Checks whether a candidate file or directory path matches any configured exclusion prefix or exact path.
    /// </summary>
    public bool IsExcludedPath(string? candidatePath, IEnumerable<string>? additionalExclusions = null)
    {
        if (string.IsNullOrWhiteSpace(candidatePath)) return false;

        string normalizedCandidate;
        try
        {
            normalizedCandidate = Path.GetFullPath(candidatePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            normalizedCandidate = candidatePath.Trim().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        IEnumerable<string> allExclusions = ExcludedPaths ?? Array.Empty<string>();
        if (additionalExclusions != null)
        {
            allExclusions = allExclusions.Concat(additionalExclusions);
        }

        foreach (var rawEx in allExclusions)
        {
            if (string.IsNullOrWhiteSpace(rawEx)) continue;
            string normEx;
            try
            {
                normEx = Path.GetFullPath(rawEx.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            catch
            {
                normEx = rawEx.Trim().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }

            if (normEx.Length == 0) continue;

            if (string.Equals(normalizedCandidate, normEx, StringComparison.OrdinalIgnoreCase) ||
                normalizedCandidate.StartsWith(normEx + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // ─── Scan (Preview mode — no files deleted) ─────────────────────────

    public List<JunkScanResult> Scan() => Scan(additionalExclusions: null, ct: default);

    public List<JunkScanResult> Scan(IEnumerable<string>? additionalExclusions, CancellationToken ct = default)
    {
        _logger?.LogInformation("Starting parallel junk file scan...");
        var tasks = new List<Task<JunkScanResult>>
        {
            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsTemp, "Windows Temp Files",
                "System temporary files that can be safely removed",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                null, isSafe: true), ct),

            Task.Run(() => ScanDirectory(
                JunkCategory.UserTemp, "User Temp Files",
                "Your temporary files from apps and installations",
                Path.GetTempPath(),
                null, isSafe: true), ct),

            Task.Run(ScanBrowserCaches, ct),

            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsLogs, "Windows Log Files",
                "System log files (.log, .etl) that accumulate over time",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                new[] { "*.log", "*.etl", "*.evtx" }, isSafe: true), ct),

            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsUpdateCache, "Windows Update Cache",
                "Downloaded update files — safe to remove after updates install",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"),
                null, isSafe: false), ct),

            Task.Run(ScanThumbnailCache, ct),

            Task.Run(() => ScanDirectory(
                JunkCategory.Prefetch, "Prefetch Data",
                "App launch prefetch data — Windows rebuilds this automatically",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"),
                new[] { "*.pf" }, isSafe: false), ct),

            Task.Run(ScanCrashDumps, ct),

            Task.Run(() => ScanDirectory(
                JunkCategory.InstallerCache, "Installer Temp Files",
                "Leftover files from software installations",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer", "$PatchCache$"),
                null, isSafe: true), ct),

            Task.Run(ScanShaderCaches, ct),

            Task.Run(ScanDriverStoreCache, ct),

            Task.Run(ScanDeliveryOptimizationCache, ct),

            Task.Run(ScanRecycleBin, ct)
        };

        var resultsArray = Task.WhenAll(tasks).GetAwaiter().GetResult();
        var results = new List<JunkScanResult>(resultsArray);

        // Apply user-configured path exclusions to scanned file lists and recompute totals
        bool hasExclusions = (ExcludedPaths is { Count: > 0 }) || (additionalExclusions != null && additionalExclusions.Any());
        if (hasExclusions)
        {
            foreach (var r in results)
            {
                if (r.Files.Count == 0) continue;
                r.Files.RemoveAll(f => IsExcludedPath(f.Path, additionalExclusions));
            }
        }

        var totalBytes = results.Sum(r => r.TotalBytes);
        var totalFiles = results.Sum(r => r.FileCount);
        _logger?.LogInformation("Scan complete. Found {Files} junk files ({Size})",
            totalFiles, FormatBytes(totalBytes));

        return results;
    }

    // ─── Clean (Deletes selected categories) ────────────────────────────

    /// <summary>
    /// Deletes junk files from selected categories.
    /// Pass the scan results with IsSelected set for categories to clean.
    /// </summary>
    public CleanResult Clean(List<JunkScanResult> scanResults)
        => Clean(scanResults, ct: default, additionalExclusions: null);

    public CleanResult Clean(
        List<JunkScanResult> scanResults,
        CancellationToken ct,
        IEnumerable<string>? additionalExclusions = null)
    {
        long bytesCleaned = 0;
        int filesDeleted = 0;
        int filesFailed = 0;
        bool wasCancelled = false;
        var errors = new List<string>();
        var errorsLock = new object();

        var selectedCategories = scanResults.Where(r => r.IsSelected).ToList();

        foreach (var category in selectedCategories)
        {
            if (ct.IsCancellationRequested)
            {
                wasCancelled = true;
                break;
            }

            _logger?.LogInformation("Cleaning {Category}...", category.DisplayName);

            if (category.Category == JunkCategory.RecycleBin)
            {
                try
                {
                    int hr = SHEmptyRecycleBin(IntPtr.Zero, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
                    if (hr == 0 || hr == 1) // S_OK or S_FALSE (already empty)
                    {
                        Interlocked.Add(ref bytesCleaned, category.TotalBytes);
                        int countToDelete = category.FileCount > 0 ? category.FileCount : (category.TotalBytes > 0 ? 1 : 0);
                        Interlocked.Add(ref filesDeleted, countToDelete);
                    }
                    else
                    {
                        lock (errorsLock) { errors.Add($"Recycle Bin: SHEmptyRecycleBin returned 0x{hr:X8}"); }
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref filesFailed);
                    lock (errorsLock) { errors.Add($"Recycle Bin: {ex.Message}"); }
                }
                continue;
            }

            try
            {
                Parallel.ForEach(
                    category.Files,
                    new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
                    file =>
                    {
                        if (ct.IsCancellationRequested || IsExcludedPath(file.Path, additionalExclusions))
                            return;

                        try
                        {
                            if (File.Exists(file.Path))
                            {
                                var size = file.SizeBytes; // Reuse cached size from scan phase
                                File.Delete(file.Path);
                                Interlocked.Add(ref bytesCleaned, size);
                                Interlocked.Increment(ref filesDeleted);
                            }
                            else if (Directory.Exists(file.Path))
                            {
                                var dirSize = file.SizeBytes; // Reuse cached size from scan phase
                                Directory.Delete(file.Path, true);
                                Interlocked.Add(ref bytesCleaned, dirSize);
                                Interlocked.Increment(ref filesDeleted);
                            }
                        }
                        catch (Exception ex)
                        {
                            Interlocked.Increment(ref filesFailed);
                            lock (errorsLock)
                            {
                                // Only log first few errors to avoid spam
                                if (errors.Count < 10)
                                    errors.Add($"{Path.GetFileName(file.Path)}: {ex.Message}");
                            }
                        }
                    });
            }
            catch (OperationCanceledException)
            {
                wasCancelled = true;
                break;
            }
        }

        _logger?.LogInformation("Cleaned {Files} files, freed {Size}. {Failed} files locked/skipped.",
            filesDeleted, FormatBytes(bytesCleaned), filesFailed);

        return new CleanResult
        {
            BytesCleaned = bytesCleaned,
            FilesDeleted = filesDeleted,
            FilesFailed = filesFailed,
            WasCancelled = wasCancelled,
            Errors = errors
        };
    }

    /// <summary>
    /// Quick clean — scan and delete all safe categories in one call.
    /// </summary>
    public CleanResult QuickClean()
    {
        var scan = Scan();
        // Auto-select safe categories only; never silently wipe Recycle Bin, Prefetch, or WU cache
        foreach (var r in scan)
        {
            r.IsSelected = r.IsSafeCategory &&
                           r.Category is not (JunkCategory.Prefetch or JunkCategory.WindowsUpdateCache or JunkCategory.RecycleBin);
        }
        return Clean(scan);
    }

    /// <summary>
    /// Prunes non-whitelisted browser tracking cookies and compacts closed browser SQLite databases.
    /// </summary>
    public BrowserPrivacyCleanerEngine.BrowserPrivacyCleanReport CleanBrowserPrivacy(
        bool vacuumDatabases = true,
        bool dryRun = false,
        IEnumerable<string>? overrideWhitelist = null,
        bool clearHistory = false)
    {
        return BrowserPrivacyCleaner.CleanProfiles(vacuumDatabases, dryRun, overrideWhitelist, clearHistory: clearHistory);
    }

    // ─── Private Scanners ────────────────────────────────────────────────

    private JunkScanResult ScanDirectory(JunkCategory category, string name, string description,
        string path, string[]? patterns = null, bool isSafe = true)
    {
        var result = new JunkScanResult
        {
            Category = category,
            DisplayName = name,
            Description = description,
            TargetPathSummary = path,
            IsSafeCategory = isSafe,
            IsSelected = isSafe
        };

        if (!Directory.Exists(path)) return result;

        try
        {
            patterns ??= new[] { "*" };
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.System | FileAttributes.ReparsePoint
            };
            foreach (var pattern in patterns)
            {
                foreach (var file in Directory.EnumerateFiles(path, pattern, options))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists) continue;
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                    catch { /* Skip files we can't access */ }
                }
            }
        }
        catch { /* Skip directories we can't access */ }

        return result;
    }

    private JunkScanResult ScanBrowserCaches()
    {
        var result = new JunkScanResult
        {
            Category = JunkCategory.BrowserCache,
            DisplayName = "Browser Cache Files",
            Description = "Cached web pages, images, and scripts from browsers",
            TargetPathSummary = "Chrome, Edge, Firefox, Brave, and Opera cache folders",
            IsSafeCategory = true,
            IsSelected = true
        };

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var browserCachePaths = new[]
        {
            // Chrome
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cache"),
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Code Cache"),
            // Edge
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cache"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Code Cache"),
            // Firefox — profiles directory structure
            Path.Combine(localAppData, "Mozilla", "Firefox", "Profiles"),
            // Brave
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"),
            // Opera
            Path.Combine(localAppData, "Opera Software", "Opera Stable", "Cache"),
        };

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true
        };

        foreach (var cachePath in browserCachePaths)
        {
            if (!Directory.Exists(cachePath)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cachePath, "*", options))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists) continue;
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }

        return result;
    }

    private JunkScanResult ScanThumbnailCache()
    {
        var explorerPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Windows", "Explorer");

        var result = new JunkScanResult
        {
            Category = JunkCategory.Thumbnails,
            DisplayName = "Thumbnail Cache",
            Description = "Windows Explorer thumbnail preview database files",
            TargetPathSummary = explorerPath,
            IsSafeCategory = true,
            IsSelected = true
        };

        if (!Directory.Exists(explorerPath)) return result;

        try
        {
            foreach (var file in Directory.EnumerateFiles(explorerPath, "thumbcache_*.db"))
            {
                try
                {
                    var info = new FileInfo(file);
                    result.Files.Add(new JunkFile
                    {
                        Path = file,
                        SizeBytes = info.Length,
                        LastModified = info.LastWriteTime
                    });
                }
                catch { }
            }
        }
        catch { }

        return result;
    }

    private JunkScanResult ScanCrashDumps()
    {
        var result = new JunkScanResult
        {
            Category = JunkCategory.CrashDumps,
            DisplayName = "Crash Dump Files",
            Description = "Memory dump files from crashes and BSODs",
            TargetPathSummary = "%SystemRoot%\\Minidump, %SystemRoot%\\MEMORY.DMP, %LocalAppData%\\CrashDumps",
            IsSafeCategory = false,
            IsSelected = false
        };

        var dumpPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "MEMORY.DMP"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps"),
        };

        foreach (var path in dumpPaths)
        {
            if (File.Exists(path))
            {
                try
                {
                    var info = new FileInfo(path);
                    result.Files.Add(new JunkFile
                    {
                        Path = path,
                        SizeBytes = info.Length,
                        LastModified = info.LastWriteTime
                    });
                }
                catch { }
            }
            else if (Directory.Exists(path))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(path, "*.dmp", SearchOption.TopDirectoryOnly))
                    {
                        var info = new FileInfo(file);
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                }
                catch { }
            }
        }

        return result;
    }

    private static JunkScanResult ScanShaderCaches()
    {
        var result = new JunkScanResult
        {
            Category = JunkCategory.GpuShaderCache,
            DisplayName = "GPU & DirectX Shader Caches",
            Description = "DirectX, NVIDIA, AMD, and Intel compiled GPU shader caches",
            TargetPathSummary = "DirectX, NVIDIA, AMD, and Intel GPU shader cache folders",
            IsSafeCategory = true,
            IsSelected = true
        };

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var shaderDirs = new[]
        {
            Path.Combine(localAppData, "D3DSCache"),
            Path.Combine(localAppData, "Microsoft", "DirectX Shader Cache"),
            Path.Combine(localAppData, "NVIDIA", "DXCache"),
            Path.Combine(localAppData, "NVIDIA", "GLCache"),
            Path.Combine(appData, "NVIDIA", "ComputeCache"),
            Path.Combine(localAppData, "AMD", "DxCache"),
            Path.Combine(localAppData, "AMD", "GLCache"),
            Path.Combine(localAppData, "Intel", "ShaderCache"),
            Path.Combine(localAppData, "Intel", "IGC")
        };

        foreach (var dir in shaderDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", options))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }

        return result;
    }

    private static JunkScanResult ScanDriverStoreCache()
    {
        var driverStoreTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "DriverStore", "Temp");
        var result = new JunkScanResult
        {
            Category = JunkCategory.DriverStoreCache,
            DisplayName = "DriverStore Temp & Backup Cache",
            Description = "Temporary driver staging and installation cache files",
            TargetPathSummary = driverStoreTemp,
            IsSafeCategory = false,
            IsSelected = false
        };

        if (Directory.Exists(driverStoreTemp))
        {
            try
            {
                var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
                foreach (var file in Directory.EnumerateFiles(driverStoreTemp, "*.*", options))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }

        return result;
    }

    private static JunkScanResult ScanDeliveryOptimizationCache()
    {
        var result = new JunkScanResult
        {
            Category = JunkCategory.DeliveryOptimizationCache,
            DisplayName = "Delivery Optimization Files",
            Description = "Downloaded peer-to-peer Windows update cache files",
            TargetPathSummary = "%SystemRoot%\\SoftwareDistribution\\DeliveryOptimization, %LocalAppData%\\Microsoft\\Windows\\DeliveryOptimization",
            IsSafeCategory = true,
            IsSelected = true
        };

        var doDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "DeliveryOptimization"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "DeliveryOptimization")
        };

        foreach (var dir in doDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", options))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        result.Files.Add(new JunkFile
                        {
                            Path = file,
                            SizeBytes = info.Length,
                            LastModified = info.LastWriteTime
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }

        return result;
    }

    private static JunkScanResult ScanRecycleBin()
    {
        var result = new JunkScanResult
        {
            Category = JunkCategory.RecycleBin,
            DisplayName = "Recycle Bin",
            Description = "Deleted files residing in the Windows Recycle Bin",
            TargetPathSummary = "Recycle Bin",
            IsSafeCategory = false,
            IsSelected = false
        };

        try
        {
            var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };
            int hr = SHQueryRecycleBin(null, ref info);
            if (hr == 0 && info.i64NumItems > 0)
            {
                bool foundFiles = false;
                try
                {
                    foreach (var drive in DriveInfo.GetDrives())
                    {
                        if (!drive.IsReady || drive.DriveType != DriveType.Fixed) continue;
                        var binPath = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                        if (!Directory.Exists(binPath)) continue;

                        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
                        foreach (var file in Directory.EnumerateFiles(binPath, "*.*", options))
                        {
                            try
                            {
                                var fi = new FileInfo(file);
                                result.Files.Add(new JunkFile
                                {
                                    Path = file,
                                    SizeBytes = fi.Length,
                                    LastModified = fi.LastWriteTime
                                });
                                foundFiles = true;
                            }
                            catch { }
                        }
                    }
                }
                catch { }

                if (!foundFiles)
                {
                    result.Files.Add(new JunkFile
                    {
                        Path = $"Recycle Bin ({info.i64NumItems} items)",
                        SizeBytes = Math.Max(0, info.i64Size),
                        LastModified = DateTime.Now
                    });
                }
                else
                {
                    long enumeratedSize = result.Files.Sum(f => f.SizeBytes);
                    long uncountedBytes = Math.Max(0, info.i64Size - enumeratedSize);
                    int uncountedItems = (int)Math.Max(0, info.i64NumItems - result.Files.Count);
                    if (uncountedBytes > 0 || uncountedItems > 0)
                    {
                        result.Files.Add(new JunkFile
                        {
                            Path = $"Recycle Bin System & Other Users ({uncountedItems} items)",
                            SizeBytes = uncountedBytes,
                            LastModified = DateTime.Now
                        });
                    }
                }
            }
        }
        catch { }

        return result;
    }

    /// <summary>
    /// Creates or removes the weekly scheduled junk clean task (LogicFlow_WeeklyJunkClean)
    /// executing "logicflow.exe clean --all --yes" via ScheduledMaintenanceEngine / schtasks.exe.
    /// </summary>
    public ScheduleResult ScheduleWeeklyClean(bool enable = true)
    {
        var scheduler = new ScheduledMaintenanceEngine(
            taskName: ScheduledMaintenanceEngine.WeeklyJunkCleanTaskName,
            commandArgs: "clean --all --yes");

        if (!enable)
        {
            return scheduler.DeleteSchedule();
        }

        return scheduler.CreateSchedule(new MaintenanceSchedule
        {
            Frequency = ScheduleFrequency.Weekly,
            DayOfWeek = DayOfWeek.Sunday,
            Time = new TimeOnly(3, 0)
        });
    }

    /// <summary>
    /// Toggles the weekly scheduled junk clean task on or off depending on its current status.
    /// </summary>
    public (bool IsEnabled, ScheduleResult Result) ToggleWeeklySchedule()
    {
        var scheduler = new ScheduledMaintenanceEngine(
            taskName: ScheduledMaintenanceEngine.WeeklyJunkCleanTaskName,
            commandArgs: "clean --all --yes");

        var status = scheduler.GetStatus();
        if (status.IsConfigured)
        {
            var delResult = scheduler.DeleteSchedule();
            return (false, delResult);
        }

        var createResult = ScheduleWeeklyClean(enable: true);
        return (createResult.Success, createResult);
    }

    // ─── Utilities ───────────────────────────────────────────────────────

    private static long GetDirectorySize(string path)
    {
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true
            };
            return Directory.EnumerateFiles(path, "*", options)
                .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0; } });
        }
        catch { return 0; }
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
