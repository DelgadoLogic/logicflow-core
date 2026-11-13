// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — File Immutability & Safety Classification
// Proprietary implementation by DelgadoLogic.Tech
// Isolates mutable working documents from static assets to prevent NTFS multi-file corruption
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using LogicFlow.Native;

namespace LogicFlow.Guardian.Deduplication;

/// <summary>
/// Categorization of file immutability and mutation risk.
/// </summary>
public enum ImmutabilityCategory
{
    /// <summary>
    /// Static or read-only binary assets safe for NTFS hard linking (e.g. .iso, .vhd, .dll, .exe, .pak, .bin).
    /// </summary>
    StaticImmutable,

    /// <summary>
    /// Working documents, source code, and configuration files that must NEVER be hard-linked on NTFS
    /// because in-place writes would silently corrupt all duplicate references simultaneously.
    /// </summary>
    MutableWorkingDocument,

    /// <summary>
    /// Ambiguous or unrecognized extensions; treated defensively as mutable on NTFS.
    /// </summary>
    Ambiguous
}

/// <summary>
/// Classifies file paths based on extension, directory context, file age, and link counts
/// to enforce strict NTFS hard link safety guardrails.
/// </summary>
public static class FileImmutabilityClassifier
{
    private static readonly HashSet<string> MutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Productivity Documents
        ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt", ".ods", ".rtf", ".pdf",
        ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv",

        // Source Code & Scripts
        ".cs", ".py", ".js", ".ts", ".jsx", ".tsx", ".cpp", ".c", ".h", ".hpp",
        ".rs", ".go", ".java", ".rb", ".php", ".ps1", ".bat", ".cmd", ".sh",

        // Configuration & Project Files
        ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".config", ".env",
        ".sln", ".csproj", ".vcxproj", ".fsproj", ".props", ".targets",

        // Databases & Keystores
        ".sqlite", ".sqlite3", ".db", ".db3", ".mdf", ".ldf", ".kdbx", ".accde", ".accdb"
    };

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Disk Images & Virtualization
        ".iso", ".vhd", ".vhdx", ".img", ".qcow2", ".vmdk",

        // Binaries & Native Libraries
        ".dll", ".exe", ".sys", ".lib", ".pdb", ".node", ".so", ".dylib",

        // Game & Application Data Archives
        ".pak", ".bundle", ".assets", ".vpk", ".wad", ".dat", ".bin", ".cas",

        // Installers & Package Feeds
        ".msi", ".cab", ".msix", ".appx", ".nupkg",

        // Compressed Static Archives
        ".zip", ".7z", ".tar", ".gz", ".xz", ".bz2",

        // Static Media Containers
        ".mp4", ".mkv", ".avi", ".flac", ".wav", ".mp3",
        ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".ico"
    };

    private static readonly string[] ProtectedDirectoryKeywords =
    {
        @"\.git\",
        @"/.git/",
        @"\.vs\",
        @"/.vs/",
        @"\.idea\",
        @"/.idea/",
        @"\node_modules\",
        @"/node_modules/"
    };

    /// <summary>
    /// Classifies a file into StaticImmutable, MutableWorkingDocument, or Ambiguous.
    /// </summary>
    public static ImmutabilityCategory Classify(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (IsInProtectedPath(filePath))
        {
            return ImmutabilityCategory.MutableWorkingDocument;
        }

        string ext = Path.GetExtension(filePath);
        if (string.IsNullOrEmpty(ext))
        {
            return ImmutabilityCategory.Ambiguous;
        }

        if (MutableExtensions.Contains(ext))
        {
            return ImmutabilityCategory.MutableWorkingDocument;
        }

        if (StaticExtensions.Contains(ext))
        {
            return ImmutabilityCategory.StaticImmutable;
        }

        return ImmutabilityCategory.Ambiguous;
    }

    /// <summary>
    /// Returns true if the file is a mutable working document (.docx, .xlsx, .cs, .py, .json, .sqlite, etc.).
    /// </summary>
    public static bool IsMutableWorkingDocument(string filePath)
    {
        return Classify(filePath) == ImmutabilityCategory.MutableWorkingDocument;
    }

    /// <summary>
    /// Returns true if the file is a verified static/immutable asset (.iso, .dll, .exe, .pak, .bin, etc.).
    /// </summary>
    public static bool IsStaticAsset(string filePath)
    {
        return Classify(filePath) == ImmutabilityCategory.StaticImmutable;
    }

    /// <summary>
    /// Evaluates whether a file is completely safe to consolidate via native NTFS hard links.
    /// Requires verified static immutability, non-protected directory, optional minimum age,
    /// and current MFT link count strictly below the architectural limit (1024).
    /// </summary>
    public static bool IsSafeForNtfsHardLink(
        string filePath,
        TimeSpan? minAge = null,
        int maxExistingLinks = 1020)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        // 1. Must be strictly classified as StaticImmutable
        if (Classify(filePath) != ImmutabilityCategory.StaticImmutable)
        {
            return false;
        }

        // 2. Cannot reside within protected directories (.git, .vs, node_modules)
        if (IsInProtectedPath(filePath))
        {
            return false;
        }

        // 3. Inspect live filesystem attributes if file exists
        if (File.Exists(filePath))
        {
            try
            {
                var fileInfo = new FileInfo(filePath);

                // Age verification
                if (minAge.HasValue && minAge.Value > TimeSpan.Zero)
                {
                    var age = DateTime.UtcNow - fileInfo.LastWriteTimeUtc;
                    if (age < minAge.Value)
                    {
                        return false;
                    }
                }

                // Query MFT link count via kernel handle
                uint linkCount = StorageNative.GetHardLinkCount(filePath);
                if (linkCount >= maxExistingLinks)
                {
                    return false;
                }
            }
            catch
            {
                // If inspection fails (e.g. sharing violation), err on the side of safety
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Checks whether the path resides within a version control or IDE internal folder (.git, .vs, .idea).
    /// </summary>
    public static bool IsInProtectedPath(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        string normalized = filePath.Replace('/', '\\');
        foreach (var keyword in ProtectedDirectoryKeywords)
        {
            string searchKw = keyword.Replace('/', '\\');
            if (normalized.Contains(searchKw, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
