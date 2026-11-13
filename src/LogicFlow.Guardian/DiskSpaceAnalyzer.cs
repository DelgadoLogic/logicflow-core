// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – DiskSpaceAnalyzer
// Visual disk space analysis — find what's eating your storage.
// Classic feature from TuneUp Disk Space Explorer (2007)
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Analyzes disk space usage by folder/file, producing data for
/// treemap or sunburst visualizations in the dashboard.
/// </summary>
public sealed class DiskSpaceAnalyzer
{
    private readonly ILogger<DiskSpaceAnalyzer>? _logger;

    /// <summary>
    /// User-configured folder or file paths excluded from disk space analysis (strict path-boundary matched).
    /// </summary>
    public IReadOnlyList<string> ExcludedPaths { get; set; } = Array.Empty<string>();

    public DiskSpaceAnalyzer(ILogger<DiskSpaceAnalyzer>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public sealed class FolderNode
    {
        public string Name { get; init; } = "";
        public string FullPath { get; init; } = "";
        public long SizeBytes { get; set; }
        public int FileCount { get; set; }
        public int FolderCount { get; set; }
        public double Percentage { get; set; }
        public bool IsFile { get; init; }
        public List<FolderNode> Children { get; init; } = new();
        public string SizeFormatted => FormatBytes(SizeBytes);
    }

    public sealed class LargeFile
    {
        public string Path { get; init; } = "";
        public string Name { get; init; } = "";
        public string Extension { get; init; } = "";
        public long SizeBytes { get; init; }
        public DateTime LastModified { get; init; }
        public string SizeFormatted => FormatBytes(SizeBytes);
    }

    public sealed class SpaceReport
    {
        public string DrivePath { get; init; } = "";
        public long TotalBytes { get; init; }
        public long UsedBytes { get; init; }
        public long FreeBytes { get; init; }
        public FolderNode RootNode { get; init; } = new();
        public List<LargeFile> LargestFiles { get; init; } = new();
        public Dictionary<string, long> ByExtension { get; init; } = new();
        public int TotalFilesScanned { get; set; }
        public int TotalFoldersScanned { get; set; }
        public TimeSpan ScanDuration { get; set; }
    }

    // ─── Analyze a Drive ─────────────────────────────────────────────────

    /// <summary>
    /// Analyzes disk space usage for a given drive root (e.g. "C:\").
    /// Returns a tree structure suitable for treemap visualization.
    /// </summary>
    /// <param name="drivePath">Drive root path, e.g. "C:\"</param>
    /// <param name="maxDepth">How many folder levels deep to scan (default 4)</param>
    /// <param name="topFilesCount">Number of largest files to track (default 50)</param>
    public SpaceReport Analyze(string drivePath, int maxDepth = 4, int topFilesCount = 50)
        => Analyze(drivePath, maxDepth, topFilesCount, additionalExclusions: null);

    public SpaceReport Analyze(string drivePath, int maxDepth, int topFilesCount, IEnumerable<string>? additionalExclusions)
    {
        _logger?.LogInformation("Analyzing disk space for {Drive}...", drivePath);
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var rootDriveLetter = Path.GetPathRoot(Path.GetFullPath(drivePath)) ?? drivePath;
        DriveInfo? driveInfo = null;
        try { driveInfo = new DriveInfo(rootDriveLetter.TrimEnd('\\')); } catch { }
        var largestFiles = new SortedList<long, LargeFile>(new DescendingComparer());
        var extensionMap = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        int totalFiles = 0, totalFolders = 0;

        List<string>? effectiveExclusions = null;
        if ((ExcludedPaths is { Count: > 0 }) || additionalExclusions != null)
        {
            effectiveExclusions = new List<string>();
            if (ExcludedPaths is { Count: > 0 }) effectiveExclusions.AddRange(ExcludedPaths);
            if (additionalExclusions != null) effectiveExclusions.AddRange(additionalExclusions);
        }

        var rootNode = ScanFolder(drivePath, 0, maxDepth, largestFiles, topFilesCount,
            extensionMap, effectiveExclusions, ref totalFiles, ref totalFolders);

        // Calculate percentages
        if (rootNode.SizeBytes > 0)
            CalculatePercentages(rootNode, rootNode.SizeBytes);

        sw.Stop();

        long totalDriveBytes = driveInfo is { IsReady: true } ? driveInfo.TotalSize : rootNode.SizeBytes;
        long freeDriveBytes = driveInfo is { IsReady: true } ? driveInfo.TotalFreeSpace : 0;

        var report = new SpaceReport
        {
            DrivePath = drivePath,
            TotalBytes = totalDriveBytes,
            UsedBytes = Math.Max(0, totalDriveBytes - freeDriveBytes),
            FreeBytes = freeDriveBytes,
            RootNode = rootNode,
            LargestFiles = largestFiles.Values.Take(topFilesCount).ToList(),
            ByExtension = extensionMap.OrderByDescending(kv => kv.Value)
                .Take(20)
                .ToDictionary(kv => kv.Key, kv => kv.Value),
            TotalFilesScanned = totalFiles,
            TotalFoldersScanned = totalFolders,
            ScanDuration = sw.Elapsed
        };

        _logger?.LogInformation("Disk analysis complete. {Files} files, {Folders} folders in {Time:0.0}s",
            totalFiles, totalFolders, sw.Elapsed.TotalSeconds);

        return report;
    }

    // ─── Recursive Scanner ───────────────────────────────────────────────

    private FolderNode ScanFolder(string path, int depth, int maxDepth,
        SortedList<long, LargeFile> largestFiles, int maxLargest,
        Dictionary<string, long> extensionMap, IReadOnlyList<string>? effectiveExclusions,
        ref int totalFiles, ref int totalFolders)
    {
        var folderName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var node = new FolderNode
        {
            Name = string.IsNullOrEmpty(folderName) ? path : folderName,
            FullPath = path,
            IsFile = false
        };

        if (Deduplication.VolumeAwareDeduplicator.IsExcludedByPathBoundary(path, effectiveExclusions))
        {
            return node;
        }

        totalFolders++;
        var directFileNodes = new List<FolderNode>();

        // Scan files in this directory
        try
        {
            foreach (var file in Directory.EnumerateFiles(path))
            {
                try
                {
                    if (Deduplication.VolumeAwareDeduplicator.IsExcludedByPathBoundary(file, effectiveExclusions))
                        continue;

                    var info = new FileInfo(file);
                    if (!info.Exists) continue;

                    var size = info.Length;
                    node.SizeBytes += size;
                    node.FileCount++;
                    totalFiles++;

                    if (size > 0)
                    {
                        directFileNodes.Add(new FolderNode
                        {
                            Name = info.Name,
                            FullPath = file,
                            SizeBytes = size,
                            FileCount = 1,
                            FolderCount = 0,
                            IsFile = true
                        });
                    }

                    // Track extension sizes
                    var ext = info.Extension.ToLowerInvariant();
                    if (string.IsNullOrEmpty(ext)) ext = "(no extension)";
                    extensionMap[ext] = extensionMap.GetValueOrDefault(ext) + size;

                    // Track largest files
                    if (largestFiles.Count < maxLargest || size > largestFiles.Keys.Last())
                    {
                        // Use a unique key to avoid collisions
                        var key = size * 1000 + (totalFiles % 1000);
                        largestFiles[key] = new LargeFile
                        {
                            Path = file,
                            Name = info.Name,
                            Extension = ext,
                            SizeBytes = size,
                            LastModified = info.LastWriteTime
                        };
                        if (largestFiles.Count > maxLargest)
                            largestFiles.RemoveAt(largestFiles.Count - 1);
                    }
                }
                catch { /* Skip inaccessible files */ }
            }
        }
        catch { /* Skip inaccessible directories */ }

        if (directFileNodes.Count > 0)
        {
            directFileNodes.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));
            const int maxDirectIndividual = 12;
            foreach (var df in directFileNodes.Take(maxDirectIndividual))
                node.Children.Add(df);

            if (directFileNodes.Count > maxDirectIndividual)
            {
                var rest = directFileNodes.Skip(maxDirectIndividual).ToList();
                node.Children.Add(new FolderNode
                {
                    Name = $"[{rest.Count} Other Files]",
                    FullPath = path,
                    SizeBytes = rest.Sum(f => f.SizeBytes),
                    FileCount = rest.Count,
                    FolderCount = 0,
                    IsFile = true
                });
            }
        }

        // Recurse into subdirectories
        if (depth < maxDepth)
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(path))
                {
                    try
                    {
                        if (Deduplication.VolumeAwareDeduplicator.IsExcludedByPathBoundary(dir, effectiveExclusions))
                            continue;

                        // Skip system junctions and reparse points
                        var dirInfo = new DirectoryInfo(dir);
                        if (dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;

                        var child = ScanFolder(dir, depth + 1, maxDepth,
                            largestFiles, maxLargest, extensionMap, effectiveExclusions, ref totalFiles, ref totalFolders);

                        node.SizeBytes += child.SizeBytes;
                        node.FileCount += child.FileCount;
                        node.FolderCount += child.FolderCount + 1;
                        node.Children.Add(child);
                    }
                    catch { /* Skip inaccessible subdirectories */ }
                }
            }
            catch { }
        }

        // Sort children by size descending
        node.Children.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

        return node;
    }

    private static void CalculatePercentages(FolderNode node, long totalBytes)
    {
        node.Percentage = totalBytes > 0 ? Math.Round((double)node.SizeBytes / totalBytes * 100, 2) : 0;
        foreach (var child in node.Children)
            CalculatePercentages(child, totalBytes);
    }

    // ─── Squarified Treemap Layout Algorithm ─────────────────────────────

    public sealed class TreemapTile
    {
        public string Name { get; init; } = "";
        public string FullPath { get; init; } = "";
        public long SizeBytes { get; init; }
        public string FormattedSize => FormatBytes(SizeBytes);
        public int FileCount { get; init; }
        public bool IsDirectory { get; init; }
        public int Depth { get; init; }
        public double X { get; init; }
        public double Y { get; init; }
        public double Width { get; init; }
        public double Height { get; init; }
        public double PercentOfParent { get; init; }
        public double PercentOfRoot { get; init; }
        public string Category { get; init; } = "";
        public string ColorHex { get; init; } = "#00E5FF";
        public FolderNode? Node { get; init; }
        public List<TreemapTile> SubTiles { get; init; } = new();
    }

    /// <summary>
    /// Computes a deterministic Squarified Treemap layout (Bruls, Huizing, van Wijk)
    /// for a FolderNode hierarchy within the specified bounding box (width x height).
    /// </summary>
    public List<TreemapTile> ComputeTreemapLayout(FolderNode? root, double width, double height, int maxDepth = 2)
    {
        if (root is null || width <= 0 || height <= 0)
            return new List<TreemapTile>();

        long rootTotalBytes = Math.Max(root.SizeBytes, root.Children.Sum(c => c.SizeBytes));
        if (rootTotalBytes <= 0)
            return new List<TreemapTile>();

        var validChildren = root.Children
            .Where(c => c.SizeBytes > 0)
            .OrderByDescending(c => c.SizeBytes)
            .ToList();

        if (validChildren.Count == 0)
        {
            var cat = ClassifyNodeCategory(root);
            return new List<TreemapTile>
            {
                new TreemapTile
                {
                    Name = string.IsNullOrWhiteSpace(root.Name) ? root.FullPath : root.Name,
                    FullPath = root.FullPath,
                    SizeBytes = root.SizeBytes,
                    FileCount = Math.Max(1, root.FileCount),
                    IsDirectory = !root.IsFile,
                    Depth = 1,
                    X = 0,
                    Y = 0,
                    Width = width,
                    Height = height,
                    PercentOfParent = 100.0,
                    PercentOfRoot = 100.0,
                    Category = cat,
                    ColorHex = GetCategoryColorHex(cat),
                    Node = root
                }
            };
        }

        return LayoutChildrenSquarified(validChildren, 0, 0, width, height, 1, Math.Max(1, maxDepth), rootTotalBytes);
    }

    private static List<TreemapTile> LayoutChildrenSquarified(
        List<FolderNode> children,
        double rx,
        double ry,
        double rw,
        double rh,
        int currentDepth,
        int maxDepth,
        long rootTotalBytes)
    {
        var tiles = new List<TreemapTile>();
        if (children.Count == 0 || rw <= 0 || rh <= 0)
            return tiles;

        double parentBytes = children.Sum(c => (double)Math.Max(0, c.SizeBytes));
        if (parentBytes <= 0)
            return tiles;

        double totalArea = rw * rh;
        var scaledItems = children
            .Select(c => (Node: c, Area: (c.SizeBytes / parentBytes) * totalArea))
            .Where(x => x.Area > 0)
            .ToList();

        int idx = 0;
        double curX = rx, curY = ry, curW = rw, curH = rh;

        while (idx < scaledItems.Count && curW > 1e-9 && curH > 1e-9)
        {
            var row = new List<(FolderNode Node, double Area)> { scaledItems[idx] };
            idx++;

            double shortSide = Math.Min(curW, curH);
            double currentWorst = WorstAspectRatio(row, shortSide);

            while (idx < scaledItems.Count)
            {
                var candidate = scaledItems[idx];
                var testRow = new List<(FolderNode Node, double Area)>(row) { candidate };
                double nextWorst = WorstAspectRatio(testRow, shortSide);

                if (nextWorst <= currentWorst)
                {
                    row.Add(candidate);
                    currentWorst = nextWorst;
                    idx++;
                }
                else
                {
                    break;
                }
            }

            double rowArea = row.Sum(r => r.Area);
            bool splitHorizontally = curW >= curH;

            if (splitHorizontally)
            {
                double colWidth = curH > 0 ? Math.Min(curW, rowArea / curH) : curW;
                double itemY = curY;

                for (int i = 0; i < row.Count; i++)
                {
                    var item = row[i];
                    double itemH = (i == row.Count - 1)
                        ? Math.Max(0, (curY + curH) - itemY)
                        : (colWidth > 0 ? Math.Min(curH, item.Area / colWidth) : 0);

                    tiles.Add(CreateTile(item.Node, curX, itemY, colWidth, itemH, parentBytes, rootTotalBytes, currentDepth, maxDepth));
                    itemY += itemH;
                }

                curX += colWidth;
                curW = Math.Max(0, curW - colWidth);
            }
            else
            {
                double rowHeight = curW > 0 ? Math.Min(curH, rowArea / curW) : curH;
                double itemX = curX;

                for (int i = 0; i < row.Count; i++)
                {
                    var item = row[i];
                    double itemW = (i == row.Count - 1)
                        ? Math.Max(0, (curX + curW) - itemX)
                        : (rowHeight > 0 ? Math.Min(curW, item.Area / rowHeight) : 0);

                    tiles.Add(CreateTile(item.Node, itemX, curY, itemW, rowHeight, parentBytes, rootTotalBytes, currentDepth, maxDepth));
                    itemX += itemW;
                }

                curY += rowHeight;
                curH = Math.Max(0, curH - rowHeight);
            }
        }

        return tiles;
    }

    private static TreemapTile CreateTile(
        FolderNode node,
        double x,
        double y,
        double w,
        double h,
        double parentBytes,
        long rootTotalBytes,
        int currentDepth,
        int maxDepth)
    {
        double clampedX = Math.Max(0, x);
        double clampedY = Math.Max(0, y);
        double clampedW = Math.Max(0, w);
        double clampedH = Math.Max(0, h);
        string category = ClassifyNodeCategory(node);
        string colorHex = GetCategoryColorHex(category);

        var subTiles = new List<TreemapTile>();
        if (currentDepth < maxDepth && !node.IsFile && node.Children.Count > 0 && clampedW >= 4 && clampedH >= 4)
        {
            var validChildren = node.Children
                .Where(c => c.SizeBytes > 0)
                .OrderByDescending(c => c.SizeBytes)
                .ToList();
            if (validChildren.Count > 0)
            {
                subTiles = LayoutChildrenSquarified(validChildren, clampedX, clampedY, clampedW, clampedH, currentDepth + 1, maxDepth, rootTotalBytes);
            }
        }

        return new TreemapTile
        {
            Name = string.IsNullOrWhiteSpace(node.Name) ? node.FullPath : node.Name,
            FullPath = node.FullPath,
            SizeBytes = node.SizeBytes,
            FileCount = node.FileCount,
            IsDirectory = !node.IsFile,
            Depth = currentDepth,
            X = clampedX,
            Y = clampedY,
            Width = clampedW,
            Height = clampedH,
            PercentOfParent = parentBytes > 0 ? Math.Round(node.SizeBytes / parentBytes * 100.0, 2) : 0,
            PercentOfRoot = rootTotalBytes > 0 ? Math.Round((double)node.SizeBytes / rootTotalBytes * 100.0, 2) : 0,
            Category = category,
            ColorHex = colorHex,
            Node = node,
            SubTiles = subTiles
        };
    }

    private static double WorstAspectRatio(List<(FolderNode Node, double Area)> row, double shortSide)
    {
        if (row.Count == 0 || shortSide <= 0)
            return double.MaxValue;

        double sumArea = 0;
        double maxArea = 0;
        double minArea = double.MaxValue;

        foreach (var (_, area) in row)
        {
            sumArea += area;
            if (area > maxArea) maxArea = area;
            if (area < minArea) minArea = area;
        }

        if (sumArea <= 0 || minArea <= 0)
            return double.MaxValue;

        double s2 = sumArea * sumArea;
        double w2 = shortSide * shortSide;
        return Math.Max((w2 * maxArea) / s2, s2 / (w2 * minArea));
    }

    public static string ClassifyNodeCategory(FolderNode node)
    {
        string name = (node.Name ?? "").ToLowerInvariant();
        string path = (node.FullPath ?? "").ToLowerInvariant();
        string ext = Path.GetExtension(name).ToLowerInvariant();

        if (ext is ".mp4" or ".mkv" or ".avi" or ".mov" or ".mp3" or ".wav" or ".flac" or ".png" or ".jpg" or ".jpeg" or ".webp" or ".gif" ||
            name is "videos" or "music" or "pictures" or "media" or "recordings")
            return "Media & Video";

        if (ext is ".pak" or ".vpk" or ".wad" or ".unity3d" or ".iso" or ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".lfc" ||
            path.Contains("steamapps") || path.Contains("epic games") || name is "games" or "archives" or "backups")
            return "Games & Archives";

        if (ext is ".cs" or ".cpp" or ".h" or ".py" or ".js" or ".ts" or ".tsx" or ".json" or ".sln" or ".csproj" or ".pdb" ||
            name is "node_modules" or ".git" or "src" or "repos" or "source" or "packages" or ".nuget" or "bin" or "obj")
            return "Code & Dev";

        if (ext is ".pdf" or ".docx" or ".doc" or ".xlsx" or ".xls" or ".pptx" or ".txt" or ".md" or ".csv" ||
            name is "documents" or "desktop" or "onedrive")
            return "Documents";

        if (ext is ".exe" or ".dll" or ".msi" or ".sys" ||
            name is "program files" or "program files (x86)" or "appdata" or "local" or "roaming" or "programs")
            return "Binaries & Apps";

        return "System & Other";
    }

    public static string GetCategoryColorHex(string category) => category switch
    {
        "Binaries & Apps" => "#00E5FF",
        "Games & Archives" => "#8B5CF6",
        "Media & Video" => "#EC4899",
        "Code & Dev" => "#10B981",
        "Documents" => "#F59E0B",
        _ => "#3B82F6"
    };

    // ─── Quick Summary (Lighter) ─────────────────────────────────────────

    /// <summary>
    /// Gets a quick summary of all drives without deep folder scanning.
    /// </summary>
    public List<DriveSummary> GetDriveSummaries()
    {
        var summaries = new List<DriveSummary>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady) continue;
            summaries.Add(new DriveSummary
            {
                Name = drive.Name,
                Label = drive.VolumeLabel,
                FileSystem = drive.DriveFormat,
                Type = drive.DriveType.ToString(),
                TotalBytes = drive.TotalSize,
                FreeBytes = drive.TotalFreeSpace,
                UsedBytes = drive.TotalSize - drive.TotalFreeSpace,
                UsagePercent = Math.Round((1.0 - (double)drive.TotalFreeSpace / drive.TotalSize) * 100, 1)
            });
        }
        return summaries;
    }

    public sealed class DriveSummary
    {
        public string Name { get; init; } = "";
        public string Label { get; init; } = "";
        public string FileSystem { get; init; } = "";
        public string Type { get; init; } = "";
        public long TotalBytes { get; init; }
        public long FreeBytes { get; init; }
        public long UsedBytes { get; init; }
        public double UsagePercent { get; init; }
        public string TotalFormatted => FormatBytes(TotalBytes);
        public string FreeFormatted => FormatBytes(FreeBytes);
        public string UsedFormatted => FormatBytes(UsedBytes);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private class DescendingComparer : IComparer<long>
    {
        public int Compare(long x, long y) => y.CompareTo(x);
    }

    public static string FormatBytes(long bytes)
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
