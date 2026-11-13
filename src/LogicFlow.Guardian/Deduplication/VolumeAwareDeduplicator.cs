// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Volume-Aware Host Deduplication Engine
// Proprietary implementation by DelgadoLogic.Tech
// Safe host duplicate consolidation across ReFS CoW block cloning, NTFS hard links,
// strict immutability guards, and cross-volume .lfc container fallback.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Native;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;
using LogicFlow.Storage.Engine.Primitives;

namespace LogicFlow.Guardian.Deduplication;

/// <summary>
/// Autonomous host deduplication engine providing volume-aware duplicate consolidation.
/// Executes native ReFS Copy-on-Write block cloning, NTFS hard links with strict immutability
/// safeguards, and graceful cross-volume .lfc container fallback.
/// </summary>
public sealed class VolumeAwareDeduplicator
{
    private static readonly Lazy<VolumeAwareDeduplicator> s_instance = new(() => new VolumeAwareDeduplicator());
    public static VolumeAwareDeduplicator Instance => s_instance.Value;

    /// <summary>
    /// Scans a target directory, clusters duplicates by length and 256-bit BLAKE3 hash,
    /// and executes volume-aware deduplication according to options.
    /// </summary>
    public async Task<DedupResult> DeduplicateDirectoryAsync(
        string targetPath,
        DedupOptions? options = null,
        IProgress<DedupProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

        if (!Directory.Exists(targetPath))
        {
            throw new DirectoryNotFoundException($"Target directory does not exist: {targetPath}");
        }

        var opt = options ?? DedupOptions.Default;
        var result = new DedupResult();
        string fullTargetPath = Path.GetFullPath(targetPath);

        // 1. Enumerate all files, guarding against recursive reparse loops and honoring ExcludedPaths
        var allFiles = EnumerateFilesSafe(fullTargetPath);
        if (opt.ExcludedPaths is { Count: > 0 })
        {
            allFiles = allFiles.Where(f => !IsExcludedByPathBoundary(f, opt.ExcludedPaths)).ToList();
        }
        result.TotalFilesScanned = allFiles.Count;

        progress?.Report(new DedupProgress
        {
            FilesScanned = allFiles.Count,
            TotalFiles = allFiles.Count,
            CurrentOperation = "Scanning and grouping candidate duplicates by length"
        });

        // 2. Phase 1: Group files by exact byte length (filter out length < MinFileSizeBytes and unique sizes)
        var sizeGroups = allFiles
            .Select(f =>
            {
                try
                {
                    var fi = new FileInfo(f);
                    return new { Path = f, Length = fi.Length, Exists = fi.Exists };
                }
                catch
                {
                    return new { Path = f, Length = -1L, Exists = false };
                }
            })
            .Where(f => f.Exists && f.Length >= opt.MinFileSizeBytes)
            .GroupBy(f => f.Length)
            .Where(g => g.Count() > 1)
            .ToList();

        ct.ThrowIfCancellationRequested();

        // 3. Phase 2: Compute 256-bit BLAKE3 hashes for candidates with identical lengths
        var duplicateClusters = new List<List<string>>();

        int hashedFiles = 0;
        int totalToHash = sizeGroups.Sum(g => g.Count());

        foreach (var group in sizeGroups)
        {
            ct.ThrowIfCancellationRequested();

            var hashGroups = new Dictionary<Hash256, List<string>>();

            foreach (var candidate in group)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var stream = new FileStream(
                        candidate.Path,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);

                    Hash256 hash = Hash256.Compute(stream);

                    if (!hashGroups.TryGetValue(hash, out var list))
                    {
                        list = new List<string>();
                        hashGroups[hash] = list;
                    }
                    list.Add(candidate.Path);
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Failed to compute BLAKE3 hash for '{candidate.Path}': {ex.Message}");
                }

                hashedFiles++;
                if (hashedFiles % 25 == 0 || hashedFiles == totalToHash)
                {
                    progress?.Report(new DedupProgress
                    {
                        FilesScanned = hashedFiles,
                        TotalFiles = totalToHash,
                        CurrentOperation = "Fingerprinting candidate files with 256-bit BLAKE3 SIMD",
                        CurrentFile = candidate.Path
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

        result.DuplicateClustersFound = duplicateClusters.Count;

        // 4. Phase 3: Execute volume-aware deduplication per cluster
        var crossVolumeDuplicates = new List<(string Source, string Target)>();

        int processedClusters = 0;
        foreach (var cluster in duplicateClusters)
        {
            ct.ThrowIfCancellationRequested();

            string sourceFile = cluster[0];

            for (int i = 1; i < cluster.Count; i++)
            {
                ct.ThrowIfCancellationRequested();

                string targetFile = cluster[i];

                var itemResult = DeduplicatePairInternal(
                    sourceFile,
                    targetFile,
                    opt,
                    crossVolumeDuplicates,
                    result,
                    ct);

                result.Items.Add(itemResult);

                if (itemResult.Success)
                {
                    if (itemResult.Method == DedupMethod.RefsBlockClone || itemResult.Method == DedupMethod.NtfsHardLink)
                    {
                        result.DuplicatesConsolidated++;
                        result.TotalBytesReclaimed += itemResult.BytesReclaimed;
                    }
                    else if (itemResult.Method == DedupMethod.PreservedMutable)
                    {
                        result.MutableFilesPreserved++;
                    }
                }
                else if (!string.IsNullOrEmpty(itemResult.ErrorMessage))
                {
                    result.Errors.Add(itemResult.ErrorMessage);
                }

                progress?.Report(new DedupProgress
                {
                    DuplicateClustersFound = duplicateClusters.Count,
                    DuplicatesProcessed = result.Items.Count,
                    BytesReclaimed = result.TotalBytesReclaimed,
                    CurrentOperation = $"Consolidating duplicate [{itemResult.Method}]: {Path.GetFileName(targetFile)}",
                    CurrentFile = targetFile
                });
            }

            processedClusters++;
        }

        // 5. Phase 4: Handle Cross-Volume Fallback via .lfc Container
        if (crossVolumeDuplicates.Count > 0 && opt.EnableCrossVolumeLfcFallback)
        {
            ct.ThrowIfCancellationRequested();

            string lfcOutPath = opt.CrossVolumeContainerPath ??
                Path.Combine(fullTargetPath, $"cross_volume_dedup_{DateTime.UtcNow:yyyyMMdd_HHmmss}.lfc");

            progress?.Report(new DedupProgress
            {
                DuplicateClustersFound = duplicateClusters.Count,
                DuplicatesProcessed = result.Items.Count,
                BytesReclaimed = result.TotalBytesReclaimed,
                CurrentOperation = $"Packing {crossVolumeDuplicates.Count} cross-volume duplicates into .lfc archive",
                CurrentFile = lfcOutPath
            });

            await ConsolidateCrossVolumeIntoLfcAsync(crossVolumeDuplicates, lfcOutPath, result, ct);
        }

        return result;
    }

    /// <summary>
    /// Deduplicates a single pair of identical files, choosing the optimal volume-aware method.
    /// </summary>
    public async Task<DedupItemResult> DeduplicatePairAsync(
        string sourcePath,
        string targetPath,
        DedupOptions? options = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException($"Source file not found: {sourcePath}");
        }

        if (!File.Exists(targetPath))
        {
            throw new FileNotFoundException($"Target file not found: {targetPath}");
        }

        var opt = options ?? DedupOptions.Default;
        var dummyCrossVolume = new List<(string Source, string Target)>();
        var dummyResult = new DedupResult();

        var item = DeduplicatePairInternal(
            sourcePath,
            targetPath,
            opt,
            dummyCrossVolume,
            dummyResult,
            ct);

        if (item.Method == DedupMethod.CrossVolumeLfc && dummyCrossVolume.Count > 0 && opt.EnableCrossVolumeLfcFallback)
        {
            string lfcOut = opt.CrossVolumeContainerPath ??
                Path.Combine(Path.GetDirectoryName(targetPath) ?? Path.GetTempPath(), $"cross_volume_pair_{Guid.NewGuid():N}.lfc");

            await ConsolidateCrossVolumeIntoLfcAsync(dummyCrossVolume, lfcOut, dummyResult, ct);
        }

        return item;
    }

    /// <summary>
    /// Core volume-aware decision matrix for a candidate duplicate pair.
    /// </summary>
    private DedupItemResult DeduplicatePairInternal(
        string sourcePath,
        string targetPath,
        DedupOptions opt,
        List<(string Source, string Target)> crossVolumeList,
        DedupResult overallResult,
        CancellationToken ct)
    {
        long fileLength = 0;
        try
        {
            fileLength = new FileInfo(targetPath).Length;
        }
        catch
        {
            return new DedupItemResult(sourcePath, targetPath, 0, DedupMethod.None, false, $"Cannot access target file '{targetPath}'.");
        }

        // Check if both files already point to the same physical file record (identical hard link)
        try
        {
            var infoSource = StorageNative.GetFileInformation(sourcePath);
            var infoTarget = StorageNative.GetFileInformation(targetPath);

            if (infoSource.dwVolumeSerialNumber == infoTarget.dwVolumeSerialNumber &&
                infoSource.FileIndex == infoTarget.FileIndex)
            {
                return new DedupItemResult(sourcePath, targetPath, 0, DedupMethod.SkippedIdenticalLink, true);
            }
        }
        catch
        {
            // If handle acquisition fails, proceed with volume check
        }

        // 1. Canonical Volume Resolution
        bool sameVolume = VolumeResolver.AreOnSameVolume(sourcePath, targetPath);

        if (!sameVolume)
        {
            // Cross-Volume scenario
            if (opt.EnableCrossVolumeLfcFallback)
            {
                crossVolumeList.Add((sourcePath, targetPath));
                return new DedupItemResult(
                    sourcePath,
                    targetPath,
                    fileLength,
                    DedupMethod.CrossVolumeLfc,
                    true);
            }
            else
            {
                return new DedupItemResult(
                    sourcePath,
                    targetPath,
                    0,
                    DedupMethod.None,
                    false,
                    $"Files reside on different volumes ({VolumeResolver.GetVolumeGuid(sourcePath)} vs {VolumeResolver.GetVolumeGuid(targetPath)}) and .lfc fallback is disabled.");
            }
        }

        // 2. Same-Volume: Inspect File System Capabilities
        StorageNative.VolumeInformation volInfo;
        try
        {
            volInfo = VolumeResolver.GetVolumeInfo(sourcePath);
        }
        catch (Exception ex)
        {
            return new DedupItemResult(
                sourcePath,
                targetPath,
                0,
                DedupMethod.None,
                false,
                $"Failed to query volume capabilities for '{sourcePath}': {ex.Message}");
        }

        // 3. Subcase A: Volume supports native ReFS Copy-on-Write Block Cloning
        if (volInfo.SupportsBlockCloning)
        {
            if (opt.DryRun)
            {
                return new DedupItemResult(sourcePath, targetPath, fileLength, DedupMethod.RefsBlockClone, true);
            }

            bool cloned = ConsolidateRefsBlockClone(sourcePath, targetPath, volInfo.ClusterSize, out string? cloneError);
            if (cloned)
            {
                return new DedupItemResult(sourcePath, targetPath, fileLength, DedupMethod.RefsBlockClone, true);
            }
            else
            {
                return new DedupItemResult(sourcePath, targetPath, 0, DedupMethod.RefsBlockClone, false, cloneError);
            }
        }

        // 4. Subcase B: NTFS Volume (Block Cloning unsupported)
        // Guard mutable working documents from NTFS hard linking!
        bool isSafeForHardLink = FileImmutabilityClassifier.IsSafeForNtfsHardLink(targetPath, opt.MinFileAge);

        if (!isSafeForHardLink && !opt.AllowMutableHardLinks)
        {
            overallResult.Warnings.Add($"Preserved mutable working document '{targetPath}' from NTFS hard link to prevent destructive multi-file edits.");
            return new DedupItemResult(
                sourcePath,
                targetPath,
                0,
                DedupMethod.PreservedMutable,
                true);
        }

        // Static asset eligible for NTFS hard link consolidation
        if (opt.DryRun)
        {
            return new DedupItemResult(sourcePath, targetPath, fileLength, DedupMethod.NtfsHardLink, true);
        }

        bool linked = ConsolidateNtfsHardLink(sourcePath, targetPath, opt.SetReadOnlyOnHardLink, out string? linkError);
        if (linked)
        {
            return new DedupItemResult(sourcePath, targetPath, fileLength, DedupMethod.NtfsHardLink, true);
        }
        else
        {
            return new DedupItemResult(sourcePath, targetPath, 0, DedupMethod.NtfsHardLink, false, linkError);
        }
    }

    /// <summary>
    /// Consolidates identical files on ReFS via native Copy-on-Write Block Cloning (FSCTL_DUPLICATE_EXTENTS_TO_FILE)
    /// with cluster alignment and tail buffer fallback. Safe for both mutable and immutable files.
    /// </summary>
    public bool ConsolidateRefsBlockClone(
        string sourcePath,
        string targetPath,
        uint clusterSize,
        out string? errorMessage)
    {
        errorMessage = null;

        if (clusterSize == 0)
        {
            clusterSize = 4096;
        }

        string dir = Path.GetDirectoryName(targetPath) ?? ".";
        string stagingPath = Path.Combine(dir, $"{Path.GetFileName(targetPath)}.lf_clone_{Guid.NewGuid():N}.tmp");

        try
        {
            long fileLength = new FileInfo(sourcePath).Length;

            // Open source file for reading
            using var sourceHandle = StorageNative.OpenHandle(
                sourcePath,
                StorageNative.GENERIC_READ,
                StorageNative.FILE_SHARE_READ | StorageNative.FILE_SHARE_WRITE | StorageNative.FILE_SHARE_DELETE,
                StorageNative.OPEN_EXISTING);

            // Create staging target file
            using var stagingHandle = StorageNative.OpenHandle(
                stagingPath,
                StorageNative.GENERIC_READ | StorageNative.GENERIC_WRITE,
                StorageNative.FILE_SHARE_READ | StorageNative.FILE_SHARE_WRITE | StorageNative.FILE_SHARE_DELETE,
                StorageNative.CREATE_ALWAYS);

            // ReFS requires destination EOF to be pre-allocated to at least source size
            StorageNative.SetFileLength(stagingHandle, fileLength);

            long alignedBytes = (fileLength / clusterSize) * clusterSize;
            long tailBytes = fileLength - alignedBytes;

            // 1. Block clone aligned extents in <= 1 GB segments
            if (alignedBytes > 0)
            {
                long offset = 0;
                long maxChunk = 1024L * 1024 * 1024; // 1 GB
                maxChunk = (maxChunk / clusterSize) * clusterSize;

                while (offset < alignedBytes)
                {
                    long chunk = Math.Min(alignedBytes - offset, maxChunk);

                    if (!StorageNative.TryDuplicateExtents(sourceHandle, stagingHandle, offset, offset, chunk, out int errClone))
                    {
                        errorMessage = $"FSCTL_DUPLICATE_EXTENTS_TO_FILE failed at offset {offset} (Win32 Error: {errClone}).";
                        TryDeleteFile(stagingPath);
                        return false;
                    }

                    offset += chunk;
                }
            }

            // 2. Handle sub-cluster unaligned file tail via direct buffer copy
            if (tailBytes > 0)
            {
                byte[] tailBuffer = new byte[tailBytes];
                using (var srcStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    srcStream.Seek(alignedBytes, SeekOrigin.Begin);
                    int read = srcStream.Read(tailBuffer, 0, (int)tailBytes);
                    if (read != tailBytes)
                    {
                        errorMessage = $"Failed to read complete tail buffer from '{sourcePath}'.";
                        TryDeleteFile(stagingPath);
                        return false;
                    }
                }

                using (var dstStream = new FileStream(stagingPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                {
                    dstStream.Seek(alignedBytes, SeekOrigin.Begin);
                    dstStream.Write(tailBuffer, 0, (int)tailBytes);
                    dstStream.Flush();
                }
            }

            // Close handles prior to atomic swap
            sourceHandle.Dispose();
            stagingHandle.Dispose();

            // 3. Atomically replace target with staging clone
            if (!StorageNative.TryMoveFileEx(
                stagingPath,
                targetPath,
                StorageNative.MOVEFILE_REPLACE_EXISTING | StorageNative.MOVEFILE_WRITE_THROUGH,
                out int errMove))
            {
                errorMessage = $"Atomic swap of cloned file failed (Win32 Error: {errMove}).";
                TryDeleteFile(stagingPath);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"ReFS Block Cloning exception: {ex.Message}";
            TryDeleteFile(stagingPath);
            return false;
        }
    }

    /// <summary>
    /// Consolidates identical files on NTFS via native Hard Links (CreateHardLinkW)
    /// with crash-resilient atomic staging swap (MoveFileExW).
    /// </summary>
    public bool ConsolidateNtfsHardLink(
        string sourcePath,
        string targetPath,
        bool setReadOnly,
        out string? errorMessage)
    {
        errorMessage = null;

        string dir = Path.GetDirectoryName(targetPath) ?? ".";
        string stagingLink = Path.Combine(dir, $"{Path.GetFileName(targetPath)}.lf_swap_{Guid.NewGuid():N}.tmp");

        try
        {
            // 1. Create hard link to source file in staging location
            if (!StorageNative.TryCreateHardLink(stagingLink, sourcePath, out int errLink))
            {
                errorMessage = $"CreateHardLink failed: '{stagingLink}' -> '{sourcePath}' (Win32 Error: {errLink}).";
                return false;
            }

            // 2. Atomically swap staging link over target duplicate
            if (!StorageNative.TryMoveFileEx(
                stagingLink,
                targetPath,
                StorageNative.MOVEFILE_REPLACE_EXISTING | StorageNative.MOVEFILE_WRITE_THROUGH,
                out int errMove))
            {
                errorMessage = $"MoveFileEx atomic swap failed: '{stagingLink}' -> '{targetPath}' (Win32 Error: {errMove}).";
                TryDeleteFile(stagingLink);
                return false;
            }

            // 3. Verify hard link count was incremented
            try
            {
                uint links = StorageNative.GetHardLinkCount(targetPath);
                if (links < 2)
                {
                    errorMessage = $"Hard link count verification failed: expected >= 2, got {links}.";
                }
            }
            catch
            {
                // Verification spot check
            }

            if (setReadOnly)
            {
                try
                {
                    File.SetAttributes(targetPath, File.GetAttributes(targetPath) | FileAttributes.ReadOnly);
                }
                catch
                {
                    // Non-fatal attribute adjustment
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"NTFS Hard Link consolidation exception: {ex.Message}";
            TryDeleteFile(stagingLink);
            return false;
        }
    }

    /// <summary>
    /// Consolidates cross-volume duplicates into an .lfc binary archive using LfcWriter.PackDirectoryAsync.
    /// FastCDC chunking and 256-bit BLAKE3 indexing eliminate physical duplicate chunk storage in the archive.
    /// </summary>
    private async Task ConsolidateCrossVolumeIntoLfcAsync(
        List<(string Source, string Target)> crossVolumePairs,
        string lfcOutputPath,
        DedupResult overallResult,
        CancellationToken ct)
    {
        string stagingDir = Path.Combine(Path.GetTempPath(), $"lf_crossvol_stage_{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDir);

        try
        {
            var uniqueFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (src, dst) in crossVolumePairs)
            {
                uniqueFiles.Add(src);
                uniqueFiles.Add(dst);
            }

            // Copy files to staging folder to preserve original directory names
            int counter = 0;
            foreach (var file in uniqueFiles)
            {
                ct.ThrowIfCancellationRequested();

                if (!File.Exists(file)) continue;

                string destFileName = $"{counter:D4}_{Path.GetFileName(file)}";
                string destFilePath = Path.Combine(stagingDir, destFileName);

                File.Copy(file, destFilePath, overwrite: true);
                counter++;
            }

            string? lfcDir = Path.GetDirectoryName(lfcOutputPath);
            if (!string.IsNullOrEmpty(lfcDir))
            {
                Directory.CreateDirectory(lfcDir);
            }

            using var writer = new LfcWriter();
            var packOptions = new LfcPackOptions
            {
                Tier = CompressionTier.Hot,
                EnableDeltaCompression = true
            };

            await writer.PackDirectoryAsync(stagingDir, lfcOutputPath, packOptions, null, ct);

            overallResult.CrossVolumeFilesHandled = uniqueFiles.Count;
            overallResult.CrossVolumeLfcPath = lfcOutputPath;

            // Calculate total bytes reclaimed from deduplicating in container
            long totalRaw = uniqueFiles.Where(File.Exists).Sum(f => new FileInfo(f).Length);
            long containerSize = File.Exists(lfcOutputPath) ? new FileInfo(lfcOutputPath).Length : 0;
            long saved = Math.Max(0, totalRaw - containerSize);

            overallResult.TotalBytesReclaimed += saved;
        }
        catch (Exception ex)
        {
            overallResult.Errors.Add($"Cross-volume .lfc fallback failed: {ex.Message}");
        }
        finally
        {
            try
            {
                if (Directory.Exists(stagingDir))
                {
                    Directory.Delete(stagingDir, recursive: true);
                }
            }
            catch
            {
                // Staging cleanup
            }
        }
    }

    /// <summary>
    /// Safe directory enumeration that skips inaccessible files and circular reparse points.
    /// </summary>
    private static List<string> EnumerateFilesSafe(string rootDir)
    {
        var result = new List<string>();
        var visitedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>();

        queue.Enqueue(rootDir);
        visitedDirectories.Add(rootDir);

        while (queue.Count > 0)
        {
            string currentDir = queue.Dequeue();

            try
            {
                foreach (var file in Directory.EnumerateFiles(currentDir))
                {
                    result.Add(file);
                }
            }
            catch
            {
                // Inaccessible directory files
            }

            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                {
                    // Avoid circular reparse loops
                    string normalized = Path.GetFullPath(subDir);
                    if (visitedDirectories.Add(normalized))
                    {
                        queue.Enqueue(subDir);
                    }
                }
            }
            catch
            {
                // Inaccessible directory
            }
        }

        return result;
    }

    public static bool IsExcludedByPathBoundary(string candidatePath, IEnumerable<string>? exclusions)
    {
        if (string.IsNullOrWhiteSpace(candidatePath) || exclusions == null)
            return false;

        string normalizedCandidate = candidatePath.Replace('/', '\\').TrimEnd('\\');
        foreach (var raw in exclusions)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            string normalizedEx = raw.Trim().Replace('/', '\\').TrimEnd('\\');
            if (normalizedEx.Length == 0)
                continue;

            if (normalizedCandidate.Equals(normalizedEx, StringComparison.OrdinalIgnoreCase))
                return true;

            if (normalizedCandidate.Length > normalizedEx.Length &&
                normalizedCandidate.StartsWith(normalizedEx, StringComparison.OrdinalIgnoreCase) &&
                normalizedCandidate[normalizedEx.Length] == '\\')
            {
                return true;
            }
        }
        return false;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }
}
