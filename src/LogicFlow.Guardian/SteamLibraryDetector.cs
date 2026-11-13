// LogicFlow.Guardian — Steam Library & Multi-Launcher Game Discovery Engine
// Proprietary implementation by DelgadoLogic.Tech
// Enterprise Safety Heuristics: DirectStorage, Anti-Cheat/Driver exclusions, Pre-compressed filtering.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian;

/// <summary>
/// Origin launcher classification for detected gaming titles.
/// </summary>
public enum LauncherType
{
    Steam,
    Epic,
    GOG,
    Custom
}

/// <summary>
/// Alias enum for backward and cross-milestone compatibility.
/// </summary>
public enum GameLauncherType
{
    Steam = LauncherType.Steam,
    Epic = LauncherType.Epic,
    GOG = LauncherType.GOG,
    Custom = LauncherType.Custom
}

/// <summary>
/// Canonical immutable representation of an installed game across all PC gaming platforms.
/// </summary>
public record DetectedGame(
    string GameId,
    string Title,
    string InstallDirectory,
    LauncherType Launcher,
    long SizeOnDiskBytes,
    bool HasDirectStorage,
    bool IsCompressed = false,
    long EstimatedSavingsBytes = 0,
    int StateFlags = 4)
{
    public DetectedGame() : this(string.Empty, string.Empty, string.Empty, LauncherType.Custom, 0L, false, false, 0L, 4) { }

    public LauncherType LauncherType => Launcher;
    public bool IsRunning { get; init; }
    public string? PrimaryExecutablePath { get; init; }
    public string? AppVersion { get; init; }
    public long LogicalSizeBytes { get; init; }
    public int TotalFileCount { get; init; }
    public int CandidateFileCount { get; init; }
    public int CompressedFileCount { get; init; }
    public DateTime? LastCompressedUtc { get; init; }

    public double CompressionRatio => LogicalSizeBytes > 0 ? (double)SizeOnDiskBytes / LogicalSizeBytes : 1.0;
    public double SpaceSavedPercent => LogicalSizeBytes > 0 ? Math.Max(0.0, (1.0 - ((double)SizeOnDiskBytes / LogicalSizeBytes)) * 100.0) : 0.0;
    public string FormattedSizeOnDisk => FormatBytes(SizeOnDiskBytes);
    public string FormattedEstimatedSavings => FormatBytes(EstimatedSavingsBytes);

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
/// In-memory node representing a KeyValues (VDF / ACF) tree element.
/// </summary>
public sealed class VdfNode
{
    public string Key { get; set; } = string.Empty;
    public string? Value { get; set; }
    public List<VdfNode>? Children { get; set; }

    public bool IsObject => Children != null;

    public string? this[string key]
    {
        get
        {
            if (Children == null) return null;
            return Children.FirstOrDefault(c => string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase))?.Value;
        }
    }

    public VdfNode? GetChild(string key)
    {
        if (Children == null) return null;
        return Children.FirstOrDefault(c => string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase));
    }

    public IEnumerable<VdfNode> GetChildren(string key)
    {
        if (Children == null) return Enumerable.Empty<VdfNode>();
        return Children.Where(c => string.Equals(c.Key, key, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// High-performance KeyValues (VDF/ACF) parser for Steam manifests.
/// </summary>
public static class VdfParser
{
    public static VdfNode Parse(string text)
    {
        var root = new VdfNode { Key = "root", Children = new List<VdfNode>() };
        var stack = new Stack<VdfNode>();
        stack.Push(root);

        int pos = 0;
        int len = text.Length;

        while (pos < len)
        {
            SkipWhitespaceAndComments(text, ref pos);
            if (pos >= len) break;

            char c = text[pos];

            if (c == '{')
            {
                pos++;
                continue;
            }

            if (c == '}')
            {
                pos++;
                if (stack.Count > 1)
                {
                    stack.Pop();
                }
                continue;
            }

            string key = ReadToken(text, ref pos);
            if (string.IsNullOrEmpty(key)) continue;

            SkipWhitespaceAndComments(text, ref pos);
            if (pos >= len)
            {
                stack.Peek().Children!.Add(new VdfNode { Key = key, Value = string.Empty });
                break;
            }

            if (text[pos] == '{')
            {
                pos++;
                var objNode = new VdfNode { Key = key, Children = new List<VdfNode>() };
                stack.Peek().Children!.Add(objNode);
                stack.Push(objNode);
            }
            else
            {
                string value = ReadToken(text, ref pos);
                stack.Peek().Children!.Add(new VdfNode { Key = key, Value = value });
            }
        }

        return root;
    }

    private static void SkipWhitespaceAndComments(string text, ref int pos)
    {
        while (pos < text.Length)
        {
            char c = text[pos];
            if (char.IsWhiteSpace(c))
            {
                pos++;
            }
            else if (c == '/' && pos + 1 < text.Length && text[pos + 1] == '/')
            {
                pos += 2;
                while (pos < text.Length && text[pos] != '\r' && text[pos] != '\n')
                {
                    pos++;
                }
            }
            else
            {
                break;
            }
        }
    }

    private static string ReadToken(string text, ref int pos)
    {
        if (pos >= text.Length) return string.Empty;

        if (text[pos] == '"')
        {
            pos++; // Skip opening quote
            var sb = new StringBuilder();
            while (pos < text.Length)
            {
                char c = text[pos++];
                if (c == '\\' && pos < text.Length)
                {
                    char next = text[pos++];
                    switch (next)
                    {
                        case '\\': sb.Append('\\'); break;
                        case '"': sb.Append('"'); break;
                        case 'n': sb.Append('\n'); break;
                        case 't': sb.Append('\t'); break;
                        case 'r': sb.Append('\r'); break;
                        default: sb.Append('\\').Append(next); break;
                    }
                }
                else if (c == '"')
                {
                    break;
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
        else
        {
            int start = pos;
            while (pos < text.Length && !char.IsWhiteSpace(text[pos]) && text[pos] != '{' && text[pos] != '}' && text[pos] != '"')
            {
                pos++;
            }
            return text[start..pos];
        }
    }
}

/// <summary>
/// Enterprise safety heuristics governing DirectStorage, anti-cheat, pre-compressed files, and lock resilience.
/// </summary>
public static class GameSafetyHeuristics
{
    private static readonly HashSet<string> PreCompressedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4",
        ".bik",
        ".bk2",
        ".webm",
        ".zip",
        ".7z",
        ".rar",
        ".ogg",
        ".flac",
        ".png",
        ".jpg",
        ".jpeg",
        ".pak"
    };

    private static readonly string[] AntiCheatDirectoryKeywords =
    {
        "easyanticheat",
        "battleye",
        "vanguard",
        "anticheat",
        "beclient",
        "ricochet",
        "denuvo",
        "punkbuster",
        "blackcipher",
        "gameguard",
        "nprotect",
        "xigncode"
    };

    private static readonly string[] AntiCheatFilePrefixes =
    {
        "easyanticheat",
        "eac_",
        "battleye",
        "beclient",
        "beservice",
        "bedaisy",
        "vanguard",
        "vgk",
        "vgtray",
        "vgc",
        "ricochet",
        "randgrid",
        "denuvo",
        "pnkbstr",
        "anticheat",
        "blackcipher",
        "nprotect",
        "gameguard",
        "xigncode",
        "ace-safe",
        "ace-base"
    };

    private static readonly HashSet<string> AntiCheatExactFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "battleye.exe",
        "beclient.dll",
        "beclient_x64.dll",
        "beservice.exe",
        "beservice_x64.exe",
        "vanguard.exe",
        "vgk.sys",
        "vgtray.exe",
        "vgc.exe",
        "easyanticheat.exe",
        "easyanticheat_setup.exe",
        "easyanticheat_eos.exe",
        "easyanticheat_eos_setup.exe",
        "easyanticheat_x64.dll",
        "easyanticheat_x86.dll",
        "eac_server.dll",
        "eac_server64.dll",
        "ricochet.dll",
        "randgrid.dll",
        "denuvo.sys",
        "denuvo64.dll",
        "denuvo32.dll",
        "dbdata.dll",
        "pbsvc.exe",
        "pnkbstra.exe",
        "pnkbstrb.exe"
    };

    private static readonly string[] DirectStorageBinaries =
    {
        "dstorage.dll",
        "dstoragecore.dll"
    };

    public static IReadOnlySet<string> GetPreCompressedExtensions() => PreCompressedExtensions;

    public static bool IsPreCompressed(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;
        string ext = Path.GetExtension(filePath);
        return !string.IsNullOrEmpty(ext) && PreCompressedExtensions.Contains(ext);
    }

    public static bool IsAntiCheatOrDriver(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        string ext = Path.GetExtension(filePath);
        if (string.Equals(ext, ".sys", StringComparison.OrdinalIgnoreCase))
            return true;

        string fileName = Path.GetFileName(filePath);
        if (AntiCheatExactFiles.Contains(fileName))
            return true;

        foreach (var prefix in AntiCheatFilePrefixes)
        {
            if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        string? dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
        {
            foreach (var kw in AntiCheatDirectoryKeywords)
            {
                if (dir.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    public static bool IsExcludedFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;
        if (IsAntiCheatOrDriver(filePath)) return true;
        if (IsPreCompressed(filePath)) return true;
        return false;
    }

    public static bool HasDirectStorage(string gameDirectory, int maxDepth = 3)
    {
        if (string.IsNullOrWhiteSpace(gameDirectory) || !Directory.Exists(gameDirectory))
            return false;

        var queue = new Queue<(string DirectoryPath, int Depth)>();
        queue.Enqueue((gameDirectory, 0));

        while (queue.Count > 0)
        {
            var (currentDir, depth) = queue.Dequeue();

            foreach (var binary in DirectStorageBinaries)
            {
                try
                {
                    string candidate = Path.Combine(currentDir, binary);
                    if (File.Exists(candidate))
                        return true;
                }
                catch { }
            }

            if (depth >= maxDepth) continue;

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(currentDir);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or DirectoryNotFoundException
                                     or PathTooLongException
                                     or IOException
                                     or SecurityException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                try
                {
                    var di = new DirectoryInfo(subDir);
                    if ((di.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    queue.Enqueue((subDir, depth + 1));
                }
                catch { }
            }
        }

        return false;
    }

    public static IEnumerable<string> SafeEnumerateFiles(string rootPath, string searchPattern = "*", bool skipReparsePoints = true)
    {
        if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
            yield break;

        var queue = new Queue<string>();
        queue.Enqueue(rootPath);

        while (queue.Count > 0)
        {
            string currentDir = queue.Dequeue();

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(currentDir);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or DirectoryNotFoundException
                                     or PathTooLongException
                                     or IOException
                                     or SecurityException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                try
                {
                    if (skipReparsePoints)
                    {
                        var di = new DirectoryInfo(subDir);
                        if ((di.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    queue.Enqueue(subDir);
                }
                catch { }
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(currentDir, searchPattern);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or DirectoryNotFoundException
                                     or PathTooLongException
                                     or IOException
                                     or SecurityException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }
        }
    }

    public static IEnumerable<string> EnumerateCompressibleFiles(string gameDirectory, bool skipDirectStorage = true)
    {
        if (string.IsNullOrWhiteSpace(gameDirectory) || !Directory.Exists(gameDirectory))
            yield break;

        if (skipDirectStorage && HasDirectStorage(gameDirectory))
            yield break;

        foreach (var file in SafeEnumerateFiles(gameDirectory))
        {
            if (!IsExcludedFile(file))
            {
                yield return file;
            }
        }
    }
}

/// <summary>
/// Multi-launcher game discovery engine and safety heuristics coordinator.
/// Detects Steam, Epic Games, GOG Galaxy, and Custom PC game libraries.
/// </summary>
public sealed class SteamLibraryDetector
{
    private readonly ILogger? _logger;

    public static SteamLibraryDetector Instance { get; } = new();

    public SteamLibraryDetector(ILogger? logger = null)
    {
        _logger = logger;
    }

    // ─── Static Heuristics Delegates ─────────────────────────────────────────

    public static bool HasDirectStorage(string gameDirectory, int maxDepth = 3) =>
        GameSafetyHeuristics.HasDirectStorage(gameDirectory, maxDepth);

    public static bool IsExcludedFile(string filePath) =>
        GameSafetyHeuristics.IsExcludedFile(filePath);

    public static IEnumerable<string> EnumerateCompressibleFiles(string gameDirectory, bool skipDirectStorage = true) =>
        GameSafetyHeuristics.EnumerateCompressibleFiles(gameDirectory, skipDirectStorage);

    public static IReadOnlyList<DetectedGame> DetectAll(IEnumerable<string>? customPaths = null) =>
        Instance.DetectAllGames(customPaths);

    // ─── Steam Discovery Engine ──────────────────────────────────────────────

    public string? DetectSteamInstallPath()
    {
        // 1. Check HKCU
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            if (hkcu?.GetValue("SteamPath") is string steamPath && !string.IsNullOrWhiteSpace(steamPath))
            {
                string norm = NormalizePath(steamPath);
                if (IsValidSteamDirectory(norm)) return norm;
            }

            if (hkcu?.GetValue("SteamExe") is string steamExe && !string.IsNullOrWhiteSpace(steamExe))
            {
                string norm = NormalizePath(Path.GetDirectoryName(steamExe) ?? string.Empty);
                if (IsValidSteamDirectory(norm)) return norm;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed reading Steam from HKCU");
        }

        // 2. Check HKLM 32-bit view (WOW6432Node)
        try
        {
            using var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            using var subKey = hklm32.OpenSubKey(@"SOFTWARE\Valve\Steam");
            if (subKey?.GetValue("InstallPath") is string installPath && !string.IsNullOrWhiteSpace(installPath))
            {
                string norm = NormalizePath(installPath);
                if (IsValidSteamDirectory(norm)) return norm;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed reading Steam from HKLM 32-bit");
        }

        // 3. Check HKLM 64-bit view
        try
        {
            using var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var subKey = hklm64.OpenSubKey(@"SOFTWARE\Valve\Steam");
            if (subKey?.GetValue("InstallPath") is string installPath && !string.IsNullOrWhiteSpace(installPath))
            {
                string norm = NormalizePath(installPath);
                if (IsValidSteamDirectory(norm)) return norm;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed reading Steam from HKLM 64-bit");
        }

        // 4. Default directory heuristics
        string[] candidates =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Steam"),
            @"C:\Steam",
            @"D:\Steam",
            @"D:\SteamLibrary"
        };

        foreach (var candidate in candidates)
        {
            if (IsValidSteamDirectory(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    public IReadOnlyList<string> DetectLibraryFolders(string? steamInstallPath = null)
    {
        steamInstallPath ??= DetectSteamInstallPath();
        if (string.IsNullOrEmpty(steamInstallPath) || !Directory.Exists(steamInstallPath))
        {
            return Array.Empty<string>();
        }

        var libraries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Primary library candidate is the Steam install path itself
        if (Directory.Exists(Path.Combine(steamInstallPath, "steamapps")))
        {
            libraries.Add(Path.GetFullPath(steamInstallPath));
        }

        string vdfPath = Path.Combine(steamInstallPath, "steamapps", "libraryfolders.vdf");
        if (File.Exists(vdfPath))
        {
            try
            {
                string vdfText = ReadFileWithRetry(vdfPath);
                var root = VdfParser.Parse(vdfText);
                var libFoldersNode = root.GetChild("libraryfolders") ?? root.GetChild("LibraryFolders") ?? root;

                if (libFoldersNode.Children != null)
                {
                    foreach (var child in libFoldersNode.Children)
                    {
                        // Check v1 format: scalar pair e.g. "1" "D:\\SteamLibrary"
                        if (!string.IsNullOrWhiteSpace(child.Value))
                        {
                            AddValidLibrary(libraries, child.Value);
                        }
                        // Check v2 format: object block e.g. "1" { "path" "D:\\SteamLibrary" ... }
                        else if (child.IsObject)
                        {
                            string? path = child["path"];
                            if (!string.IsNullOrWhiteSpace(path))
                            {
                                AddValidLibrary(libraries, path);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed parsing libraryfolders.vdf at '{Path}'", vdfPath);
            }
        }

        return libraries.ToList();
    }

    public IReadOnlyList<DetectedGame> DetectSteamGames(string? steamInstallPath = null)
    {
        var libraryFolders = DetectLibraryFolders(steamInstallPath);
        return DetectInstalledGames(libraryFolders);
    }

    public IReadOnlyList<DetectedGame> DetectInstalledGames(IEnumerable<string>? libraryFolders = null)
    {
        libraryFolders ??= DetectLibraryFolders();
        var games = new List<DetectedGame>();

        string? runningAppId = null;
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            var runningVal = hkcu?.GetValue("RunningAppId");
            if (runningVal != null)
            {
                runningAppId = runningVal.ToString();
            }
        }
        catch { }

        foreach (var library in libraryFolders)
        {
            string steamAppsDir = Path.Combine(library, "steamapps");
            if (!Directory.Exists(steamAppsDir)) continue;

            string[] manifests;
            try
            {
                manifests = Directory.GetFiles(steamAppsDir, "appmanifest_*.acf", SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed enumerating manifests in '{Dir}'", steamAppsDir);
                continue;
            }

            foreach (var manifestPath in manifests)
            {
                try
                {
                    if (new FileInfo(manifestPath).Length == 0) continue;

                    string acfText = ReadFileWithRetry(manifestPath);
                    var root = VdfParser.Parse(acfText);
                    var appState = root.GetChild("AppState") ?? root.GetChild("appstate") ?? root;

                    string? appId = appState["appid"];
                    string? title = appState["name"];
                    string? installDir = appState["installdir"];
                    string? stateFlagsRaw = appState["StateFlags"];
                    string? sizeOnDiskRaw = appState["SizeOnDisk"];
                    string? bytesToDownloadRaw = appState["BytesToDownload"];
                    string? bytesDownloadedRaw = appState["BytesDownloaded"];

                    if (string.IsNullOrWhiteSpace(appId) || string.IsNullOrWhiteSpace(installDir))
                        continue;

                    // Skip known common redistributables
                    if (appId == "228980") continue;

                    uint stateFlags = uint.TryParse(stateFlagsRaw, out var sf) ? sf : 4;
                    long sizeOnDisk = long.TryParse(sizeOnDiskRaw, out var sz) ? sz : 0;
                    long bytesToDownload = long.TryParse(bytesToDownloadRaw, out var btd) ? btd : 0;
                    long bytesDownloaded = long.TryParse(bytesDownloadedRaw, out var bd) ? bd : 0;

                    // Filter: must be fully installed (StateFullyInstalled = 4) and not uninstalled (StateUninstalled = 1)
                    if ((stateFlags & 4) == 0 || (stateFlags & 1) != 0) continue;
                    if (bytesToDownload > 0 && bytesToDownload > bytesDownloaded) continue;

                    string fullInstallPath = Path.Combine(steamAppsDir, "common", installDir);
                    if (!Directory.Exists(fullInstallPath)) continue;

                    bool isRunning = (stateFlags & 64) != 0 || string.Equals(runningAppId, appId, StringComparison.OrdinalIgnoreCase);
                    bool hasDirectStorage = GameSafetyHeuristics.HasDirectStorage(fullInstallPath);

                    if (sizeOnDisk <= 0)
                    {
                        sizeOnDisk = CalculateDirectorySize(fullInstallPath);
                    }

                    long estimatedSavings = (!hasDirectStorage) ? (long)(sizeOnDisk * 0.35) : 0L;

                    games.Add(new DetectedGame(
                        GameId: $"steam_{appId}",
                        Title: string.IsNullOrWhiteSpace(title) ? installDir : CleanTitle(title),
                        InstallDirectory: Path.GetFullPath(fullInstallPath),
                        Launcher: LauncherType.Steam,
                        SizeOnDiskBytes: sizeOnDisk,
                        HasDirectStorage: hasDirectStorage,
                        IsCompressed: false,
                        EstimatedSavingsBytes: estimatedSavings,
                        StateFlags: (int)stateFlags)
                    {
                        IsRunning = isRunning
                    });
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Error parsing Steam manifest '{Manifest}'", manifestPath);
                }
            }
        }

        return games;
    }

    // ─── Epic Games Discovery Engine ─────────────────────────────────────────

    public IReadOnlyList<DetectedGame> DetectEpicGames(string? manifestsPath = null)
    {
        manifestsPath ??= ResolveEpicManifestDirectory();
        if (string.IsNullOrWhiteSpace(manifestsPath) || !Directory.Exists(manifestsPath))
            return Array.Empty<DetectedGame>();

        var games = new List<DetectedGame>();
        string[] files;
        try
        {
            files = Directory.GetFiles(manifestsPath, "*.item", SearchOption.TopDirectoryOnly);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed enumerating Epic manifest files in '{Dir}'", manifestsPath);
            return Array.Empty<DetectedGame>();
        }

        foreach (var file in files)
        {
            try
            {
                if (new FileInfo(file).Length == 0) continue;

                string json = ReadFileWithRetry(file);
                if (string.IsNullOrWhiteSpace(json)) continue;

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string? appName = GetStringProperty(root, "AppName");
                string? displayName = GetStringProperty(root, "DisplayName");
                string? installLocation = GetStringProperty(root, "InstallLocation");
                string? catalogNamespace = GetStringProperty(root, "CatalogNamespace");
                string? launchExecutable = GetStringProperty(root, "LaunchExecutable");
                string? appVersion = GetStringProperty(root, "AppVersionString");
                string? technicalType = GetStringProperty(root, "TechnicalType");

                bool bIsIncompleteInstall = GetBooleanProperty(root, "bIsIncompleteInstall", defaultValue: false);
                long installSize = ParseEpicInstallSize(root);

                var appCategories = GetStringListProperty(root, "AppCategories");
                var compatibleApps = GetStringListProperty(root, "CompatibleApps");

                if (string.IsNullOrWhiteSpace(installLocation) || bIsIncompleteInstall)
                    continue;

                string fullInstallPath = NormalizePath(installLocation);
                if (!Directory.Exists(fullInstallPath))
                    continue;

                // Filter out non-games (Unreal Engine editors, plugins, prerequisites)
                if (!IsPlayableEpicGame(appName, displayName, catalogNamespace, technicalType, appCategories, compatibleApps))
                    continue;

                string title = !string.IsNullOrWhiteSpace(displayName)
                    ? CleanTitle(displayName)
                    : new DirectoryInfo(fullInstallPath).Name;

                if (installSize <= 0)
                {
                    installSize = CalculateDirectorySize(fullInstallPath);
                }

                bool hasDirectStorage = GameSafetyHeuristics.HasDirectStorage(fullInstallPath);
                long estimatedSavings = (!hasDirectStorage) ? (long)(installSize * 0.35) : 0L;

                string? primaryExe = !string.IsNullOrWhiteSpace(launchExecutable)
                    ? Path.Combine(fullInstallPath, launchExecutable)
                    : null;

                games.Add(new DetectedGame(
                    GameId: $"epic_{appName ?? Path.GetFileNameWithoutExtension(file)}",
                    Title: title,
                    InstallDirectory: fullInstallPath,
                    Launcher: LauncherType.Epic,
                    SizeOnDiskBytes: installSize,
                    HasDirectStorage: hasDirectStorage,
                    IsCompressed: false,
                    EstimatedSavingsBytes: estimatedSavings,
                    StateFlags: 4)
                {
                    PrimaryExecutablePath = (primaryExe != null && File.Exists(primaryExe)) ? primaryExe : null,
                    AppVersion = appVersion
                });
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Failed parsing Epic manifest '{File}'", file);
            }
        }

        return games;
    }

    private static string? ResolveEpicManifestDirectory()
    {
        string defaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Epic\EpicGamesLauncher\Data\Manifests");

        if (Directory.Exists(defaultPath)) return defaultPath;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            using var subKey = baseKey.OpenSubKey(@"SOFTWARE\Epic Games\EpicGamesLauncher");
            if (subKey?.GetValue("AppDataPath") is string appDataPath && !string.IsNullOrWhiteSpace(appDataPath))
            {
                string candidate = Path.Combine(appDataPath, "Manifests");
                if (Directory.Exists(candidate)) return candidate;
            }
        }
        catch { }

        return null;
    }

    private static bool IsPlayableEpicGame(
        string? appName,
        string? displayName,
        string? catalogNamespace,
        string? technicalType,
        List<string> appCategories,
        List<string> compatibleApps)
    {
        // 1. Exclude Unreal Engine Editors
        if (string.Equals(catalogNamespace, "ue", StringComparison.OrdinalIgnoreCase)) return false;
        if (appName?.StartsWith("UE_", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (appName?.Contains("UnrealEngine", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (displayName?.StartsWith("Unreal Engine", StringComparison.OrdinalIgnoreCase) == true) return false;

        // 2. Exclude Plugins, Engine Extensions & Asset Packs
        if (appCategories.Any(c => c.Equals("plugins", StringComparison.OrdinalIgnoreCase) ||
                                   c.Equals("plugins/engine", StringComparison.OrdinalIgnoreCase)))
            return false;

        if (compatibleApps.Any(c => c.StartsWith("UE_", StringComparison.OrdinalIgnoreCase)))
            return false;

        if (technicalType?.Contains("plugins/engine", StringComparison.OrdinalIgnoreCase) == true ||
            technicalType?.Equals("plugin", StringComparison.OrdinalIgnoreCase) == true)
            return false;

        // 3. Exclude Prerequisites & Redistributables
        if (displayName?.Contains("Prerequisites", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (appName?.Contains("Prereq", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (displayName?.Contains("DirectX", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (appName?.Contains("DirectXRedist", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (displayName?.Contains("Visual C++", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (string.Equals(appName, "EpicOnlineServices", StringComparison.OrdinalIgnoreCase)) return false;

        // 4. Exclude Non-Launchable Addons & Digital Extras
        if (appCategories.Contains("addons") && !appCategories.Contains("addons/launchable"))
            return false;

        if (appCategories.Contains("digitalextras"))
            return false;

        return true;
    }

    private static long ParseEpicInstallSize(JsonElement root)
    {
        if (root.TryGetProperty("InstallSize", out var sizeElem))
        {
            if (sizeElem.ValueKind == JsonValueKind.Number && sizeElem.TryGetInt64(out var num))
                return num;
            if (sizeElem.ValueKind == JsonValueKind.String && long.TryParse(sizeElem.GetString(), out var strNum))
                return strNum;
        }
        return 0L;
    }

    // ─── GOG Galaxy Discovery Engine ─────────────────────────────────────────

    public IReadOnlyList<DetectedGame> DetectGogGames()
    {
        var games = new List<DetectedGame>();
        var seenDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        const string gogSubKeyPath = @"SOFTWARE\GOG.com\Games";

        // 1. Probe 32-bit registry view (WOW6432Node on 64-bit Windows)
        try
        {
            using var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            using var subKey32 = hklm32.OpenSubKey(gogSubKeyPath);
            EnumerateGogSubKeys(subKey32, games, seenDirectories, seenIds);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed reading GOG games from 32-bit registry");
        }

        // 2. Probe 64-bit native registry view
        try
        {
            using var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var subKey64 = hklm64.OpenSubKey(gogSubKeyPath);
            EnumerateGogSubKeys(subKey64, games, seenDirectories, seenIds);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed reading GOG games from 64-bit registry");
        }

        return games;
    }

    private void EnumerateGogSubKeys(
        RegistryKey? parentKey,
        List<DetectedGame> games,
        HashSet<string> seenDirectories,
        HashSet<string> seenIds)
    {
        if (parentKey == null) return;

        foreach (var subKeyName in parentKey.GetSubKeyNames())
        {
            try
            {
                using var gameKey = parentKey.OpenSubKey(subKeyName);
                if (gameKey == null) continue;

                string? path = gameKey.GetValue("path") as string;
                if (string.IsNullOrWhiteSpace(path)) continue;

                string fullPath = NormalizePath(path);
                if (!Directory.Exists(fullPath)) continue;

                string gameId = gameKey.GetValue("gameID")?.ToString() ?? subKeyName;
                if (seenIds.Contains(gameId) || seenDirectories.Contains(fullPath))
                    continue;

                // Check goggame-<id>.info to avoid duplicate DLC registering parent game folder
                string infoPath = Path.Combine(fullPath, $"goggame-{gameId}.info");
                if (File.Exists(infoPath))
                {
                    try
                    {
                        string infoJson = ReadFileWithRetry(infoPath);
                        using var doc = JsonDocument.Parse(infoJson);
                        if (doc.RootElement.TryGetProperty("rootGameId", out var rootElem))
                        {
                            string? rootId = rootElem.GetString();
                            if (!string.IsNullOrEmpty(rootId) && !rootId.Equals(gameId, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }
                        }
                    }
                    catch { }
                }

                string? rawName = gameKey.GetValue("gameName") as string;
                string title = !string.IsNullOrWhiteSpace(rawName)
                    ? CleanTitle(rawName)
                    : new DirectoryInfo(fullPath).Name;

                string? exe = gameKey.GetValue("exe") as string;
                string? exePath = null;
                if (!string.IsNullOrWhiteSpace(exe))
                {
                    exePath = Path.IsPathRooted(exe) ? exe : Path.Combine(fullPath, exe);
                }

                long sizeOnDisk = CalculateDirectorySize(fullPath);
                bool hasDirectStorage = GameSafetyHeuristics.HasDirectStorage(fullPath);
                long estimatedSavings = (!hasDirectStorage) ? (long)(sizeOnDisk * 0.35) : 0L;

                seenDirectories.Add(fullPath);
                seenIds.Add(gameId);

                games.Add(new DetectedGame(
                    GameId: $"gog_{gameId}",
                    Title: title,
                    InstallDirectory: fullPath,
                    Launcher: LauncherType.GOG,
                    SizeOnDiskBytes: sizeOnDisk,
                    HasDirectStorage: hasDirectStorage,
                    IsCompressed: false,
                    EstimatedSavingsBytes: estimatedSavings,
                    StateFlags: 4)
                {
                    PrimaryExecutablePath = (exePath != null && File.Exists(exePath)) ? exePath : null,
                    AppVersion = gameKey.GetValue("ver") as string ?? gameKey.GetValue("buildId") as string
                });
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Failed inspecting GOG registry subkey '{SubKey}'", subKeyName);
            }
        }
    }

    // ─── Custom Paths Scanner ────────────────────────────────────────────────

    public IReadOnlyList<DetectedGame> DetectCustomGames(IEnumerable<string>? customPaths)
    {
        if (customPaths == null) return Array.Empty<DetectedGame>();

        var games = new List<DetectedGame>();
        var seenDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawPath in customPaths)
        {
            if (string.IsNullOrWhiteSpace(rawPath)) continue;

            string fullPath;
            try
            {
                fullPath = NormalizePath(rawPath);
            }
            catch { continue; }

            if (!Directory.Exists(fullPath) || seenDirectories.Contains(fullPath))
                continue;

            if (IsSingleGameDirectory(fullPath))
            {
                seenDirectories.Add(fullPath);
                games.Add(CreateCustomGame(fullPath));
            }
            else
            {
                // Multi-game library directory: inspect immediate subdirectories
                string[] subDirs;
                try
                {
                    subDirs = Directory.GetDirectories(fullPath);
                }
                catch { continue; }

                foreach (var subDir in subDirs)
                {
                    string normSub = NormalizePath(subDir);
                    if (seenDirectories.Contains(normSub) || !Directory.Exists(normSub))
                        continue;

                    if (IsSingleGameDirectory(normSub) || DirectoryContainsAnyFiles(normSub))
                    {
                        seenDirectories.Add(normSub);
                        games.Add(CreateCustomGame(normSub));
                    }
                }
            }
        }

        return games;
    }

    public static bool IsSingleGameDirectory(string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
            return false;

        try
        {
            if (Directory.EnumerateFiles(directoryPath, "*.exe", SearchOption.TopDirectoryOnly).Any())
                return true;

            string[] binaryFolders = { "bin", "binaries", "x64", "win64", "game" };
            foreach (var sub in binaryFolders)
            {
                string candidate = Path.Combine(directoryPath, sub);
                if (Directory.Exists(candidate) &&
                    Directory.EnumerateFiles(candidate, "*.exe", SearchOption.AllDirectories).Take(1).Any())
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    private static bool DirectoryContainsAnyFiles(string directoryPath)
    {
        try
        {
            return Directory.EnumerateFiles(directoryPath, "*", SearchOption.TopDirectoryOnly).Any();
        }
        catch
        {
            return false;
        }
    }

    private static DetectedGame CreateCustomGame(string installDir)
    {
        var di = new DirectoryInfo(installDir);
        string title = !string.IsNullOrEmpty(di.Name) ? di.Name : "Custom Game";
        long sizeOnDisk = CalculateDirectorySize(installDir);
        bool hasDirectStorage = GameSafetyHeuristics.HasDirectStorage(installDir);
        long estimatedSavings = (!hasDirectStorage) ? (long)(sizeOnDisk * 0.35) : 0L;

        string idSlug = SanitizeSlug(title);
        int pathHash = Math.Abs(installDir.GetHashCode());

        return new DetectedGame(
            GameId: $"custom_{idSlug}_{pathHash:x8}",
            Title: title,
            InstallDirectory: installDir,
            Launcher: LauncherType.Custom,
            SizeOnDiskBytes: sizeOnDisk,
            HasDirectStorage: hasDirectStorage,
            IsCompressed: false,
            EstimatedSavingsBytes: estimatedSavings,
            StateFlags: 4);
    }

    // ─── Unified Detection Pipeline ──────────────────────────────────────────

    public IReadOnlyList<DetectedGame> DetectAllGames(IEnumerable<string>? customPaths = null)
    {
        var allGames = new List<DetectedGame>();
        var seenDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddGames(IEnumerable<DetectedGame> games)
        {
            foreach (var game in games)
            {
                if (seenDirectories.Add(game.InstallDirectory))
                {
                    allGames.Add(game);
                }
            }
        }

        // 1. Steam
        try
        {
            AddGames(DetectSteamGames());
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Steam detection error");
        }

        // 2. Epic Games
        try
        {
            AddGames(DetectEpicGames());
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Epic Games detection error");
        }

        // 3. GOG Galaxy
        try
        {
            AddGames(DetectGogGames());
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "GOG Galaxy detection error");
        }

        // 4. Custom Paths
        if (customPaths != null)
        {
            try
            {
                AddGames(DetectCustomGames(customPaths));
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Custom paths detection error");
            }
        }

        return allGames;
    }

    // ─── Utility Helpers ─────────────────────────────────────────────────────

    private static string NormalizePath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        return Path.GetFullPath(raw.Replace('/', Path.DirectorySeparatorChar).TrimEnd(Path.DirectorySeparatorChar));
    }

    private static bool IsValidSteamDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return false;
        return File.Exists(Path.Combine(path, "steam.exe")) || Directory.Exists(Path.Combine(path, "steamapps"));
    }

    private static void AddValidLibrary(HashSet<string> set, string rawPath)
    {
        try
        {
            string norm = NormalizePath(rawPath);
            if (string.IsNullOrWhiteSpace(norm)) return;

            string? root = Path.GetPathRoot(norm);
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                if (!drive.IsReady) return;
            }

            if (Directory.Exists(norm) && Directory.Exists(Path.Combine(norm, "steamapps")))
            {
                set.Add(norm);
            }
        }
        catch { }
    }

    private static string ReadFileWithRetry(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string CleanTitle(string title) =>
        title.Replace("®", "").Replace("™", "").Replace("©", "").Trim();

    private static string SanitizeSlug(string input)
    {
        var sb = new StringBuilder();
        foreach (char c in input)
        {
            if (char.IsLetterOrDigit(c))
                sb.Append(c);
            else if (c == ' ' || c == '_' || c == '-')
                sb.Append('_');
        }
        string result = sb.ToString().Trim('_');
        return string.IsNullOrEmpty(result) ? "game" : result;
    }

    private static long CalculateDirectorySize(string directoryPath)
    {
        long total = 0;
        try
        {
            foreach (var file in GameSafetyHeuristics.SafeEnumerateFiles(directoryPath))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch { }
            }
        }
        catch { }
        return total;
    }

    private static string? GetStringProperty(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String)
        {
            return prop.GetString();
        }
        return null;
    }

    private static List<string> GetStringListProperty(JsonElement element, string propertyName)
    {
        var list = new List<string>();
        if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in prop.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    string? s = item.GetString();
                    if (!string.IsNullOrEmpty(s)) list.Add(s);
                }
            }
        }
        return list;
    }

    private static bool GetBooleanProperty(JsonElement element, string propertyName, bool defaultValue = false)
    {
        if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty(propertyName, out var prop))
        {
            return ParseBoolean(prop, defaultValue);
        }
        return defaultValue;
    }

    private static bool ParseBoolean(JsonElement element, bool defaultValue = false)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.True:
                return true;

            case JsonValueKind.False:
                return false;

            case JsonValueKind.String:
                string? str = element.GetString()?.Trim();
                if (string.IsNullOrEmpty(str))
                    return defaultValue;

                if (bool.TryParse(str, out var boolResult))
                    return boolResult;

                if (long.TryParse(str, out var numResult))
                    return numResult != 0;

                if (string.Equals(str, "yes", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(str, "y", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(str, "on", StringComparison.OrdinalIgnoreCase))
                    return true;

                if (string.Equals(str, "no", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(str, "n", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(str, "off", StringComparison.OrdinalIgnoreCase))
                    return false;

                return defaultValue;

            case JsonValueKind.Number:
                if (element.TryGetInt64(out var longVal))
                    return longVal != 0;

                if (element.TryGetDouble(out var doubleVal))
                    return Math.Abs(doubleVal) > double.Epsilon;

                return defaultValue;

            default:
                return defaultValue;
        }
    }
}

/// <summary>
/// Extension methods for SteamLibraryDetector providing instance call parity for static heuristics.
/// </summary>
public static class SteamLibraryDetectorExtensions
{
    public static bool HasDirectStorage(this SteamLibraryDetector _, string gameDirectory, int maxDepth = 3) =>
        GameSafetyHeuristics.HasDirectStorage(gameDirectory, maxDepth);

    public static bool IsExcludedFile(this SteamLibraryDetector _, string filePath) =>
        GameSafetyHeuristics.IsExcludedFile(filePath);

    public static IEnumerable<string> EnumerateCompressibleFiles(this SteamLibraryDetector _, string gameDirectory, bool skipDirectStorage = true) =>
        GameSafetyHeuristics.EnumerateCompressibleFiles(gameDirectory, skipDirectStorage);
}
