// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – JunkCleanerEngine
// Smart junk file cleaner: temp files, browser caches, logs, WU cache, etc.
// Classic feature from TuneUp Utilities (2003), CCleaner, and Glary Utilities
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
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

    public JunkCleanerEngine(ILogger<JunkCleanerEngine>? logger = null)
    {
        _logger = logger;
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
        InstallerCache
    }

    public sealed class JunkScanResult
    {
        public JunkCategory Category { get; init; }
        public string DisplayName { get; init; } = "";
        public string Description { get; init; } = "";
        public List<JunkFile> Files { get; init; } = new();
        public long TotalBytes => Files.Sum(f => f.SizeBytes);
        public string TotalFormatted => FormatBytes(TotalBytes);
        public int FileCount => Files.Count;
        public bool IsSelected { get; set; } = true;
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
        public List<string> Errors { get; init; } = new();
        public string BytesCleanedFormatted => FormatBytes(BytesCleaned);
    }

    // ─── Scan (Preview mode — no files deleted) ─────────────────────────

    public List<JunkScanResult> Scan()
    {
        _logger?.LogInformation("Starting parallel junk file scan...");
        var tasks = new List<Task<JunkScanResult>>
        {
            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsTemp, "Windows Temp Files",
                "System temporary files that can be safely removed",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"))),

            Task.Run(() => ScanDirectory(
                JunkCategory.UserTemp, "User Temp Files",
                "Your temporary files from apps and installations",
                Path.GetTempPath())),

            Task.Run(ScanBrowserCaches),

            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsLogs, "Windows Log Files",
                "System log files (.log, .etl) that accumulate over time",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                new[] { "*.log", "*.etl", "*.evtx" })),

            Task.Run(() => ScanDirectory(
                JunkCategory.WindowsUpdateCache, "Windows Update Cache",
                "Downloaded update files — safe to remove after updates install",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"))),

            Task.Run(ScanThumbnailCache),

            Task.Run(() => ScanDirectory(
                JunkCategory.Prefetch, "Prefetch Data",
                "App launch prefetch data — Windows rebuilds this automatically",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"),
                new[] { "*.pf" })),

            Task.Run(ScanCrashDumps),

            Task.Run(() => ScanDirectory(
                JunkCategory.InstallerCache, "Installer Temp Files",
                "Leftover files from software installations",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer", "$PatchCache$")))
        };

        var resultsArray = Task.WhenAll(tasks).GetAwaiter().GetResult();
        var results = new List<JunkScanResult>(resultsArray);

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
    {
        long bytesCleaned = 0;
        int filesDeleted = 0;
        int filesFailed = 0;
        var errors = new List<string>();
        var errorsLock = new object();

        var selectedCategories = scanResults.Where(r => r.IsSelected).ToList();

        foreach (var category in selectedCategories)
        {
            _logger?.LogInformation("Cleaning {Category}...", category.DisplayName);

            Parallel.ForEach(category.Files, new ParallelOptions { MaxDegreeOfParallelism = 8 }, file =>
            {
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

        _logger?.LogInformation("Cleaned {Files} files, freed {Size}. {Failed} files locked/skipped.",
            filesDeleted, FormatBytes(bytesCleaned), filesFailed);

        return new CleanResult
        {
            BytesCleaned = bytesCleaned,
            FilesDeleted = filesDeleted,
            FilesFailed = filesFailed,
            Errors = errors
        };
    }

    /// <summary>
    /// Quick clean — scan and delete all safe categories in one call.
    /// </summary>
    public CleanResult QuickClean()
    {
        var scan = Scan();
        // Auto-select safe categories, skip prefetch and WU cache by default
        foreach (var r in scan)
        {
            r.IsSelected = r.Category is not (JunkCategory.Prefetch or JunkCategory.WindowsUpdateCache);
        }
        return Clean(scan);
    }

    // ─── Private Scanners ────────────────────────────────────────────────

    private JunkScanResult ScanDirectory(JunkCategory category, string name, string description,
        string path, string[]? patterns = null)
    {
        var result = new JunkScanResult
        {
            Category = category,
            DisplayName = name,
            Description = description
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
            Description = "Cached web pages, images, and scripts from browsers"
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
        var result = new JunkScanResult
        {
            Category = JunkCategory.Thumbnails,
            DisplayName = "Thumbnail Cache",
            Description = "Windows Explorer thumbnail preview database files"
        };

        var explorerPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Windows", "Explorer");

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
            Description = "Memory dump files from crashes and BSODs"
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
