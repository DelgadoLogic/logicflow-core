// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Volume-Aware Storage Subsystem
// Proprietary implementation by DelgadoLogic.Tech
// Canonical volume GUID resolution and boundary detection across junctions/symlinks
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.ComponentModel;
using System.IO;
using LogicFlow.Native;

namespace LogicFlow.Guardian.Deduplication;

/// <summary>
/// Resolves paths, directory junctions, symbolic links, and volume mount points to their
/// canonical physical volume GUIDs. Enables deterministic volume boundary detection to prevent
/// ERROR_NOT_SAME_DEVICE failures during hard linking or block cloning.
/// </summary>
public static class VolumeResolver
{
    private const string VolumePrefix = @"\\?\Volume{";

    /// <summary>
    /// Automatically resolves any file, directory, junction, or mount point to the underlying
    /// canonical volume GUID prefix: \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\.
    /// </summary>
    public static string GetVolumeGuid(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string trimmed = path.Trim();

        // If the path is already a canonical volume GUID or starts with one, extract directly
        if (trimmed.StartsWith(VolumePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return ExtractVolumeGuidPrefix(trimmed);
        }

        string fullPath = Path.GetFullPath(trimmed);

        // If the path exists directly as file or directory, resolve via kernel handle
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            string finalPath = StorageNative.GetFinalPathName(
                fullPath,
                StorageNative.VOLUME_NAME_GUID | StorageNative.FILE_NAME_NORMALIZED);

            return ExtractVolumeGuidPrefix(finalPath);
        }

        // If the path does not exist yet (e.g. prospective staging or link target),
        // walk up to the nearest existing ancestor directory
        string? current = fullPath;
        while (!string.IsNullOrEmpty(current) && !File.Exists(current) && !Directory.Exists(current))
        {
            current = Path.GetDirectoryName(current);
        }

        if (!string.IsNullOrEmpty(current) && (File.Exists(current) || Directory.Exists(current)))
        {
            string finalPath = StorageNative.GetFinalPathName(
                current,
                StorageNative.VOLUME_NAME_GUID | StorageNative.FILE_NAME_NORMALIZED);

            return ExtractVolumeGuidPrefix(finalPath);
        }

        // Fallback: extract root path (e.g. "C:\") and query kernel handle
        string? root = Path.GetPathRoot(fullPath);
        if (!string.IsNullOrEmpty(root))
        {
            if (StorageNative.TryGetFinalPathName(
                root,
                out string? finalRoot,
                StorageNative.VOLUME_NAME_GUID | StorageNative.FILE_NAME_NORMALIZED) &&
                !string.IsNullOrEmpty(finalRoot))
            {
                return ExtractVolumeGuidPrefix(finalRoot);
            }
        }

        throw new DirectoryNotFoundException($"Could not resolve volume GUID for path '{path}': ancestor directory does not exist.");
    }

    /// <summary>
    /// Safely attempts to resolve the canonical volume GUID without throwing.
    /// </summary>
    public static bool TryGetVolumeGuid(string path, out string? volumeGuid)
    {
        volumeGuid = null;
        try
        {
            volumeGuid = GetVolumeGuid(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Detects whether two paths reside on the exact same physical volume device,
    /// regardless of drive letters, junctions, SUBST drives, or symbolic links.
    /// </summary>
    public static bool AreOnSameVolume(string path1, string path2)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path1);
        ArgumentException.ThrowIfNullOrWhiteSpace(path2);

        string guid1 = GetVolumeGuid(path1);
        string guid2 = GetVolumeGuid(path2);

        return string.Equals(guid1, guid2, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Retrieves file system information, feature flags (including ReFS block cloning),
    /// and cluster geometry for the volume underlying the specified path.
    /// </summary>
    public static StorageNative.VolumeInformation GetVolumeInfo(string path)
    {
        string volumeGuid = GetVolumeGuid(path);
        return StorageNative.GetVolumeInformation(volumeGuid);
    }

    /// <summary>
    /// Safely attempts to retrieve volume information without throwing.
    /// </summary>
    public static bool TryGetVolumeInfo(string path, out StorageNative.VolumeInformation? info)
    {
        info = null;
        try
        {
            info = GetVolumeInfo(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the normalized canonical DOS path (e.g. \\?\C:\Directory\File.ext)
    /// resolving all junctions, relative dot elements, and 8.3 short names.
    /// </summary>
    public static string GetCanonicalNormalizedPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);

        if (StorageNative.TryGetFinalPathName(
            fullPath,
            out string? normalized,
            StorageNative.VOLUME_NAME_DOS | StorageNative.FILE_NAME_NORMALIZED) &&
            !string.IsNullOrEmpty(normalized))
        {
            // Strip the extended length prefix if caller expects standard DOS path
            if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) && normalized.Length > 6 && normalized[5] == ':')
            {
                return normalized[4..];
            }
            return normalized;
        }

        return fullPath;
    }

    /// <summary>
    /// Checks whether the specified path represents an NTFS reparse point (junction or symlink).
    /// </summary>
    public static bool IsReparsePoint(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return false;
        }

        try
        {
            var attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Helper to extract the volume GUID prefix (e.g. \\?\Volume{...}\) from a resolved path.
    /// </summary>
    private static string ExtractVolumeGuidPrefix(string volumePath)
    {
        int prefixStart = volumePath.IndexOf(VolumePrefix, StringComparison.OrdinalIgnoreCase);
        if (prefixStart >= 0)
        {
            int braceClose = volumePath.IndexOf('}', prefixStart);
            if (braceClose > prefixStart)
            {
                return volumePath.Substring(prefixStart, braceClose - prefixStart + 1) + "\\";
            }
        }

        if (volumePath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) && volumePath.Length >= 7 && volumePath[5] == ':')
        {
            return volumePath.Substring(0, 7); // \\?\C:\
        }

        string? root = Path.GetPathRoot(volumePath);
        if (!string.IsNullOrEmpty(root))
        {
            return root.EndsWith('\\') ? root : root + "\\";
        }

        return volumePath;
    }
}
