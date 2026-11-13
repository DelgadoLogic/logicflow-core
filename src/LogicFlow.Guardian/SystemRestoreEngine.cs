// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — System Restore Engine
// Creates, lists, and restores Windows System Restore points.
// Auto-creates snapshots before risky operations (driver updates, tweaks).
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Manages Windows System Restore points.
/// Creates snapshots, lists existing restore points, and triggers restore.
/// </summary>
public sealed class SystemRestoreEngine
{
    private readonly ILogger<SystemRestoreEngine>? _logger;

    public SystemRestoreEngine(ILogger<SystemRestoreEngine>? logger = null) => _logger = logger;

    /// <summary>
    /// Creates a new system restore point with the given description.
    /// Returns true if successful.
    /// </summary>
    public async Task<RestorePointResult> CreateRestorePointAsync(string description = "LogicFlow Checkpoint",
        CancellationToken ct = default)
    {
        _logger?.LogInformation("Creating restore point: {Description}", description);

        try
        {
            // Use PowerShell Checkpoint-Computer which is more reliable than WMI
            var script = $"Checkpoint-Computer -Description '{description.Replace("'", "''")}' -RestorePointType 'APPLICATION_INSTALL' -ErrorAction Stop";

            var output = await RunPowerShell(script, ct);

            _logger?.LogInformation("Restore point created: {Description}", description);
            return new RestorePointResult
            {
                Success = true,
                Description = description,
                CreatedAt = DateTimeOffset.UtcNow,
                Message = "Restore point created successfully"
            };
        }
        catch (Exception ex)
        {
            // Common error: too many restore points in 24 hours
            var message = ex.Message.Contains("frequency", StringComparison.OrdinalIgnoreCase)
                ? "Windows limits restore point creation to once per 24 hours"
                : ex.Message;

            _logger?.LogWarning(ex, "Failed to create restore point");
            return new RestorePointResult
            {
                Success = false,
                Description = description,
                Message = message
            };
        }
    }

    /// <summary>
    /// Lists all available system restore points.
    /// </summary>
    public List<RestorePointInfo> ListRestorePoints()
    {
        _logger?.LogInformation("Listing system restore points...");
        var points = new List<RestorePointInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\default",
                "SELECT * FROM SystemRestore ORDER BY CreationTime DESC");

            foreach (var obj in searcher.Get())
            {
                points.Add(new RestorePointInfo
                {
                    SequenceNumber = Convert.ToInt32(obj["SequenceNumber"]),
                    Description = obj["Description"]?.ToString() ?? "",
                    CreationTime = ManagementDateTimeConverter.ToDateTime(
                        obj["CreationTime"]?.ToString() ?? ""),
                    RestorePointType = ParseRestoreType(
                        Convert.ToInt32(obj["RestorePointType"])),
                    EventType = ParseEventType(
                        Convert.ToInt32(obj["EventType"]))
                });
            }

            _logger?.LogInformation("Found {Count} restore points", points.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to list restore points");
        }

        return points;
    }

    /// <summary>
    /// Initiates a system restore to the specified restore point.
    /// WARNING: This will restart the computer.
    /// </summary>
    public async Task<RestorePointResult> RestoreToPointAsync(int sequenceNumber,
        CancellationToken ct = default)
    {
        _logger?.LogWarning("Initiating system restore to point #{Seq}", sequenceNumber);

        try
        {
            var script = $"Restore-Computer -RestorePoint {sequenceNumber} -Confirm:$false";
            await RunPowerShell(script, ct);

            return new RestorePointResult
            {
                Success = true,
                Message = $"System restore to point #{sequenceNumber} initiated. The computer will restart."
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "System restore failed");
            return new RestorePointResult
            {
                Success = false,
                Message = $"Restore failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Checks if System Restore is enabled on the system drive.
    /// </summary>
    public bool IsSystemRestoreEnabled()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\default",
                "SELECT * FROM SystemRestoreConfig");

            foreach (var obj in searcher.Get())
            {
                var rpSessionInterval = Convert.ToInt32(obj["RPSessionInterval"]);
                return rpSessionInterval > 0;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Could not check System Restore status");
        }

        return false;
    }

    /// <summary>
    /// Deletes a system restore point by its sequence number.
    /// </summary>
    public async Task<RestorePointResult> DeleteRestorePointAsync(int sequenceNumber, CancellationToken ct = default)
    {
        _logger?.LogInformation("Deleting restore point #{Seq}...", sequenceNumber);
        try
        {
            var script = $"Get-WmiObject -Namespace root\\default -Class SystemRestore | Where-Object {{ $_.SequenceNumber -eq {sequenceNumber} }} | ForEach-Object {{ $_.Delete() }}";
            await RunPowerShell(script, ct);
            return new RestorePointResult
            {
                Success = true,
                Message = $"Restore point #{sequenceNumber} deleted successfully."
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to delete restore point #{Seq}", sequenceNumber);
            return new RestorePointResult
            {
                Success = false,
                Message = $"Delete failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Exports checkpoint details into a structured JSON file.
    /// </summary>
    public string ExportRestorePoint(RestorePointInfo info, string? targetDirectory = null)
    {
        var dir = targetDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow", "Backups");
        Directory.CreateDirectory(dir);
        var filename = $"Checkpoint_{info.SequenceNumber}_{info.CreationTime:yyyyMMdd_HHmmss}.json";
        var filePath = Path.Combine(dir, filename);
        var json = System.Text.Json.JsonSerializer.Serialize(info, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(filePath, json);
        return filePath;
    }

    /// <summary>
    /// Enables System Restore on the system drive.
    /// </summary>
    public async Task<bool> EnableSystemRestore(CancellationToken ct = default)
    {
        try
        {
            var script = "Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop";
            await RunPowerShell(script, ct);
            _logger?.LogInformation("System Restore enabled on system drive");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enable System Restore");
            return false;
        }
    }

    // ─── Volume Shadow Copy (VSS) Snapshot Browser & Single-File Restore ──

    /// <summary>
    /// Lists Volume Shadow Copies (Win32_ShadowCopy WMI with vssadmin fallback).
    /// </summary>
    public List<VssShadowCopyInfo> ListShadowCopies()
    {
        var shadows = new List<VssShadowCopyInfo>();

        try
        {
            var volumeGuidToDriveMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var volSearcher = new ManagementObjectSearcher(
                    @"\\.\root\cimv2",
                    "SELECT DeviceID, DriveLetter FROM Win32_Volume WHERE DriveLetter IS NOT NULL");
                foreach (var vObj in volSearcher.Get())
                {
                    var devId = vObj["DeviceID"]?.ToString()?.Trim();
                    var letter = vObj["DriveLetter"]?.ToString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(devId) && !string.IsNullOrWhiteSpace(letter))
                    {
                        volumeGuidToDriveMap[devId.TrimEnd('\\')] = NormalizeLiveVolumeRoot(letter);
                    }
                }
            }
            catch { }

            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\cimv2",
                "SELECT ID, DeviceObject, VolumeName, InstallDate, ClientAccessible FROM Win32_ShadowCopy");

            foreach (var obj in searcher.Get())
            {
                var deviceObj = obj["DeviceObject"]?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(deviceObj))
                    continue;

                DateTime installDate = DateTime.Now;
                var rawDate = obj["InstallDate"]?.ToString();
                if (!string.IsNullOrWhiteSpace(rawDate))
                {
                    try { installDate = ManagementDateTimeConverter.ToDateTime(rawDate); } catch { }
                }

                var rawVol = obj["VolumeName"]?.ToString()?.Trim() ?? "";
                string resolvedVol = (Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\");
                if (!string.IsNullOrWhiteSpace(rawVol))
                {
                    if (volumeGuidToDriveMap.TryGetValue(rawVol.TrimEnd('\\'), out var mappedDrive))
                        resolvedVol = mappedDrive;
                    else
                        resolvedVol = NormalizeLiveVolumeRoot(rawVol);
                }

                shadows.Add(new VssShadowCopyInfo
                {
                    ShadowId = obj["ID"]?.ToString() ?? "",
                    DeviceObject = deviceObj.TrimEnd('\\'),
                    VolumeName = resolvedVol,
                    InstallDate = installDate
                });
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Win32_ShadowCopy WMI query failed; trying vssadmin fallback.");
        }

        if (shadows.Count == 0)
        {
            try
            {
                var psi = new ProcessStartInfo("vssadmin.exe", "list shadows")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    var output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(5000);
                    shadows.AddRange(ParseVssAdminOutput(output));
                }
            }
            catch { }
        }

        var ordered = shadows.OrderByDescending(s => s.InstallDate).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            ordered[i].Index = i + 1;
            ordered[i].Description = $"VSS Snapshot #{i + 1} ({ordered[i].InstallDate:yyyy-MM-dd HH:mm})";
        }
        return ordered;
    }

    public static List<VssShadowCopyInfo> ParseVssAdminOutput(string? vssOutput)
    {
        var list = new List<VssShadowCopyInfo>();
        if (string.IsNullOrWhiteSpace(vssOutput))
            return list;

        string currentId = "";
        string currentDevice = "";
        string currentVolume = @"C:\";
        DateTime currentDate = DateTime.Now;
        int idx = 1;

        foreach (var rawLine in vssOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("Contents of shadow copy set", StringComparison.OrdinalIgnoreCase))
            {
                var atIdx = line.IndexOf("creation time:", StringComparison.OrdinalIgnoreCase);
                if (atIdx >= 0)
                {
                    var datePart = line[(atIdx + "creation time:".Length)..].Trim();
                    if (DateTime.TryParse(datePart, out var dt))
                        currentDate = dt;
                }
            }
            else if (line.StartsWith("Shadow Copy ID:", StringComparison.OrdinalIgnoreCase))
            {
                currentId = line["Shadow Copy ID:".Length..].Trim();
            }
            else if (line.StartsWith("Original Volume:", StringComparison.OrdinalIgnoreCase))
            {
                var volPart = line["Original Volume:".Length..].Trim();
                int parenEnd = volPart.IndexOf(')');
                if (parenEnd > 0 && volPart.StartsWith('('))
                    currentVolume = NormalizeLiveVolumeRoot(volPart[1..parenEnd]);
            }
            else if (line.StartsWith("Shadow Copy Volume:", StringComparison.OrdinalIgnoreCase))
            {
                currentDevice = line["Shadow Copy Volume:".Length..].Trim().TrimEnd('\\');
                if (!string.IsNullOrWhiteSpace(currentDevice))
                {
                    list.Add(new VssShadowCopyInfo
                    {
                        Index = idx++,
                        ShadowId = currentId,
                        DeviceObject = currentDevice,
                        VolumeName = currentVolume,
                        InstallDate = currentDate,
                        Description = $"VSS Snapshot #{idx - 1} ({currentDate:yyyy-MM-dd HH:mm})"
                    });
                }
            }
        }

        return list;
    }

    /// <summary>
    /// Ensures a volume root (such as "C:" or a directory path) has a trailing backslash
    /// when it represents a drive specification so Path.Combine never produces a CWD-relative path ("C:Users").
    /// </summary>
    public static string NormalizeLiveVolumeRoot(string? volumeOrPath)
    {
        if (string.IsNullOrWhiteSpace(volumeOrPath))
            return Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

        string trimmed = volumeOrPath.Trim().Replace('/', '\\');
        if (trimmed.Length == 2 && char.IsLetter(trimmed[0]) && trimmed[1] == ':')
            return trimmed + @"\";

        if (trimmed.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
            return Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

        return trimmed;
    }

    /// <summary>
    /// Normalizes a VSS DeviceObject (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1)
    /// and a relative path into a valid Win32 path with the required trailing backslash on the root.
    /// </summary>
    public static string BuildShadowCopyPath(string deviceObject, string? relativeSubPath = null)
    {
        if (string.IsNullOrWhiteSpace(deviceObject))
            throw new ArgumentException("DeviceObject cannot be empty.", nameof(deviceObject));

        string root = deviceObject.Trim().TrimEnd('\\', '/');
        string rel = NormalizeRelativeShadowPath(relativeSubPath);

        if (string.IsNullOrEmpty(rel))
            return root + @"\";

        return root + @"\" + rel;
    }

    public static string NormalizeRelativeShadowPath(string? relativeSubPath)
    {
        if (string.IsNullOrWhiteSpace(relativeSubPath))
            return string.Empty;

        string p = relativeSubPath.Trim().Replace('/', '\\');
        // Strip leading drive letter like "C:\" if user pasted a full path
        if (p.Length >= 2 && char.IsLetter(p[0]) && p[1] == ':')
        {
            p = p[2..];
        }

        // Strip any NTFS Alternate Data Stream suffix (e.g. "file.txt:Zone.Identifier")
        int colonIdx = p.IndexOf(':');
        if (colonIdx >= 0)
        {
            p = p[..colonIdx];
        }

        var cleanSegments = new List<string>();
        foreach (var rawSeg in p.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            string seg = rawSeg.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(seg) || seg == "." || seg == "..")
                continue;
            cleanSegments.Add(seg);
        }

        return string.Join(@"\", cleanSegments);
    }

    /// <summary>
    /// Browses a directory inside a Volume Shadow Copy snapshot and compares each file
    /// against the live volume to report Deleted, Modified, or Identical status.
    /// </summary>
    public List<VssFileEntry> BrowseShadowCopyDirectory(
        string deviceObject,
        string? relativeSubPath = null,
        string? liveVolumeRootOverride = null)
    {
        var entries = new List<VssFileEntry>();
        string shadowDirPath = BuildShadowCopyPath(deviceObject, relativeSubPath);
        string normalizedRel = NormalizeRelativeShadowPath(relativeSubPath);
        string liveRoot = NormalizeLiveVolumeRoot(liveVolumeRootOverride);

        if (!Directory.Exists(shadowDirPath))
            return entries;

        // 1. Enumerate directories
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(shadowDirPath))
            {
                try
                {
                    var di = new DirectoryInfo(dir);
                    string childRel = string.IsNullOrEmpty(normalizedRel) ? di.Name : $@"{normalizedRel}\{di.Name}";
                    string liveDirPath = Path.Combine(liveRoot, childRel);
                    bool existsOnLive = Directory.Exists(liveDirPath);

                    entries.Add(new VssFileEntry
                    {
                        Name = di.Name,
                        RelativePath = childRel,
                        ShadowFullPath = dir,
                        LiveFullPath = liveDirPath,
                        IsDirectory = true,
                        SizeBytes = 0,
                        SnapshotLastModifiedUtc = di.LastWriteTimeUtc,
                        DiffStatus = existsOnLive ? VssDiffStatus.Identical : VssDiffStatus.DeletedOnLiveDisk
                    });
                }
                catch { }
            }
        }
        catch { }

        // 2. Enumerate files
        try
        {
            foreach (var file in Directory.EnumerateFiles(shadowDirPath))
            {
                try
                {
                    var fi = new FileInfo(file);
                    string childRel = string.IsNullOrEmpty(normalizedRel) ? fi.Name : $@"{normalizedRel}\{fi.Name}";
                    string liveFilePath = Path.Combine(liveRoot, childRel);
                    var diff = ComputeLiveFileDiff(fi, liveFilePath);

                    entries.Add(new VssFileEntry
                    {
                        Name = fi.Name,
                        RelativePath = childRel,
                        ShadowFullPath = file,
                        LiveFullPath = liveFilePath,
                        IsDirectory = false,
                        SizeBytes = fi.Length,
                        SnapshotLastModifiedUtc = fi.LastWriteTimeUtc,
                        DiffStatus = diff
                    });
                }
                catch { }
            }
        }
        catch { }

        return entries
            .OrderByDescending(e => e.IsDirectory)
            .ThenBy(e => e.DiffStatus switch
            {
                VssDiffStatus.DeletedOnLiveDisk => 0,
                VssDiffStatus.ModifiedSinceSnapshot => 1,
                _ => 2
            })
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static VssDiffStatus ComputeLiveFileDiff(FileInfo snapshotFile, string liveFilePath)
    {
        if (!File.Exists(liveFilePath))
            return VssDiffStatus.DeletedOnLiveDisk;

        var liveInfo = new FileInfo(liveFilePath);
        if (liveInfo.Length != snapshotFile.Length)
            return VssDiffStatus.ModifiedSinceSnapshot;

        if (Math.Abs((liveInfo.LastWriteTimeUtc - snapshotFile.LastWriteTimeUtc).TotalSeconds) > 2.0)
            return VssDiffStatus.ModifiedSinceSnapshot;

        return VssDiffStatus.Identical;
    }

    /// <summary>
    /// Restores an individual file or directory directly from a Volume Shadow Copy snapshot
    /// to the specified destination path without requiring a full system rollback or reboot.
    /// </summary>
    public VssFileRestoreResult RestoreFileFromShadowCopy(
        string deviceObject,
        string relativeFilePath,
        string destinationPath,
        bool overwrite = false)
    {
        if (string.IsNullOrWhiteSpace(deviceObject))
        {
            return new VssFileRestoreResult
            {
                Success = false,
                Message = "Shadow Copy DeviceObject is required."
            };
        }

        if (string.IsNullOrWhiteSpace(relativeFilePath))
        {
            return new VssFileRestoreResult
            {
                Success = false,
                Message = "Relative file path inside the snapshot is required."
            };
        }

        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            return new VssFileRestoreResult
            {
                Success = false,
                Message = "Destination path is required."
            };
        }

        string sourcePath = BuildShadowCopyPath(deviceObject, relativeFilePath);

        try
        {
            if (File.Exists(sourcePath))
            {
                string finalDest = destinationPath;
                if (Directory.Exists(destinationPath) || destinationPath.EndsWith('\\') || destinationPath.EndsWith('/'))
                {
                    Directory.CreateDirectory(destinationPath);
                    finalDest = Path.Combine(destinationPath, Path.GetFileName(sourcePath));
                }
                else
                {
                    var parentDir = Path.GetDirectoryName(finalDest);
                    if (!string.IsNullOrEmpty(parentDir))
                        Directory.CreateDirectory(parentDir);
                }

                if (!overwrite && File.Exists(finalDest))
                {
                    return new VssFileRestoreResult
                    {
                        Success = false,
                        SourceShadowPath = sourcePath,
                        DestinationPath = finalDest,
                        Message = $"Destination file '{finalDest}' already exists. Enable overwrite to replace it."
                    };
                }

                if (overwrite && File.Exists(finalDest))
                {
                    ClearReadOnlyAttributes(finalDest);
                }

                File.Copy(sourcePath, finalDest, overwrite: overwrite);
                ClearReadOnlyAttributes(finalDest);
                var restoredInfo = new FileInfo(finalDest);

                return new VssFileRestoreResult
                {
                    Success = true,
                    SourceShadowPath = sourcePath,
                    DestinationPath = finalDest,
                    FilesRestored = 1,
                    BytesRestored = restoredInfo.Exists ? restoredInfo.Length : 0,
                    Message = $"Restored '{Path.GetFileName(finalDest)}' ({FormatBytes(restoredInfo.Length)}) from VSS snapshot."
                };
            }

            if (Directory.Exists(sourcePath))
            {
                Directory.CreateDirectory(destinationPath);
                int filesCopied = 0;
                int skippedExisting = 0;
                long bytesCopied = 0;

                foreach (var srcFile in Directory.EnumerateFiles(sourcePath, "*", SearchOption.AllDirectories))
                {
                    string relInsideDir = srcFile[sourcePath.Length..].TrimStart('\\', '/');
                    string targetFile = Path.Combine(destinationPath, relInsideDir);
                    var targetParent = Path.GetDirectoryName(targetFile);
                    if (!string.IsNullOrEmpty(targetParent))
                        Directory.CreateDirectory(targetParent);

                    if (!overwrite && File.Exists(targetFile))
                    {
                        skippedExisting++;
                        continue;
                    }

                    if (overwrite && File.Exists(targetFile))
                    {
                        ClearReadOnlyAttributes(targetFile);
                    }

                    File.Copy(srcFile, targetFile, overwrite: overwrite);
                    ClearReadOnlyAttributes(targetFile);
                    filesCopied++;
                    bytesCopied += new FileInfo(targetFile).Length;
                }

                if (filesCopied == 0 && skippedExisting > 0)
                {
                    return new VssFileRestoreResult
                    {
                        Success = false,
                        SourceShadowPath = sourcePath,
                        DestinationPath = destinationPath,
                        FilesRestored = 0,
                        BytesRestored = 0,
                        Message = $"All {skippedExisting} file(s) in '{destinationPath}' already exist. Enable overwrite to replace them."
                    };
                }

                return new VssFileRestoreResult
                {
                    Success = true,
                    SourceShadowPath = sourcePath,
                    DestinationPath = destinationPath,
                    FilesRestored = filesCopied,
                    BytesRestored = bytesCopied,
                    Message = $"Restored {filesCopied} file(s) ({FormatBytes(bytesCopied)}) from VSS snapshot directory."
                };
            }

            return new VssFileRestoreResult
            {
                Success = false,
                SourceShadowPath = sourcePath,
                DestinationPath = destinationPath,
                Message = $"Source path '{sourcePath}' was not found inside the VSS snapshot."
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to restore {Source} from VSS snapshot to {Dest}", sourcePath, destinationPath);
            return new VssFileRestoreResult
            {
                Success = false,
                SourceShadowPath = sourcePath,
                DestinationPath = destinationPath,
                Message = $"VSS restore failed: {ex.Message}"
            };
        }
    }

    private static void ClearReadOnlyAttributes(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return;

            var attrs = File.GetAttributes(filePath);
            if ((attrs & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System)) != 0)
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
            }
        }
        catch { }
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = Math.Max(0, bytes);
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    // ─── Internal ────────────────────────────────────────────────────────

    private async Task<string> RunPowerShell(string script, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell", $"-NoProfile -Command \"{script}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start PowerShell");

        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        var error = await proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
            throw new InvalidOperationException(error.Trim());

        return output;
    }

    private static string ParseRestoreType(int type) => type switch
    {
        0 => "Application Install",
        1 => "Application Uninstall",
        6 => "Restore",
        7 => "Checkpoint",
        10 => "Device Driver Install",
        11 => "First Run",
        12 => "Modify Settings",
        13 => "Cancelled Operation",
        _ => $"Other ({type})"
    };

    private static string ParseEventType(int type) => type switch
    {
        100 => "Begin System Change",
        101 => "End System Change",
        102 => "Begin Nested System Change",
        103 => "End Nested System Change",
        _ => $"Other ({type})"
    };
}

// ─── Data Models ────────────────────────────────────────────────────────

public sealed class RestorePointResult
{
    public bool Success { get; set; }
    public string Description { get; set; } = "";
    public string Message { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class RestorePointInfo
{
    public int SequenceNumber { get; set; }
    public string Description { get; set; } = "";
    public DateTime CreationTime { get; set; }
    public string RestorePointType { get; set; } = "";
    public string EventType { get; set; } = "";
}

public enum VssDiffStatus
{
    Identical,
    ModifiedSinceSnapshot,
    DeletedOnLiveDisk
}

public sealed class VssShadowCopyInfo
{
    public int Index { get; set; }
    public string ShadowId { get; set; } = "";
    public string DeviceObject { get; set; } = "";
    public string VolumeName { get; set; } = @"C:\";
    public DateTime InstallDate { get; set; }
    public string Description { get; set; } = "";
    public string DisplayLabel => $"#{Index} — {InstallDate:yyyy-MM-dd HH:mm:ss} ({VolumeName}) [{DeviceObject}]";
}

public sealed class VssFileEntry
{
    public string Name { get; set; } = "";
    public string RelativePath { get; set; } = "";
    public string ShadowFullPath { get; set; } = "";
    public string LiveFullPath { get; set; } = "";
    public bool IsDirectory { get; set; }
    public long SizeBytes { get; set; }
    public DateTime SnapshotLastModifiedUtc { get; set; }
    public VssDiffStatus DiffStatus { get; set; }
    public string StatusBadge => DiffStatus switch
    {
        VssDiffStatus.DeletedOnLiveDisk => "Deleted on Live Disk",
        VssDiffStatus.ModifiedSinceSnapshot => "Modified Since Snapshot",
        _ => "Unchanged"
    };
    public string SizeFormatted => IsDirectory ? "<DIR>" : DiskSpaceAnalyzer.FormatBytes(SizeBytes);
}

public sealed class VssFileRestoreResult
{
    public bool Success { get; set; }
    public string SourceShadowPath { get; set; } = "";
    public string DestinationPath { get; set; } = "";
    public int FilesRestored { get; set; }
    public long BytesRestored { get; set; }
    public string Message { get; set; } = "";
}
