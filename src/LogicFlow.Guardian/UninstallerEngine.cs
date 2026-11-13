// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – UninstallerEngine
// Audits installed software, handles quiet/interactive uninstalls, and
// scans/cleans residual leftover files and registry keys after removal.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using EnumerationOptions = System.IO.EnumerationOptions;

namespace LogicFlow.Guardian;

/// <summary>
/// Audits installed applications, executes uninstallers, and sweeps residual file/registry artifacts.
/// </summary>
public sealed class UninstallerEngine
{
    private readonly ILogger<UninstallerEngine>? _logger;

    public UninstallerEngine(ILogger<UninstallerEngine>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public sealed class InstalledApp
    {
        public string Id { get; init; } = "";
        public string DisplayName { get; init; } = "";
        public string DisplayVersion { get; init; } = "";
        public string Publisher { get; init; } = "";
        public string InstallDate { get; init; } = "";
        public string UninstallString { get; init; } = "";
        public string QuietUninstallString { get; init; } = "";
        public string InstallLocation { get; init; } = "";
        public string DisplayIcon { get; init; } = "";
        public long EstimatedSizeKB { get; init; }
        public string SizeFormatted => FormatSize(EstimatedSizeKB * 1024);
        public bool IsSystemComponent { get; init; }
        public string RegistryPath { get; init; } = "";
    }

    public sealed class ResidualItem
    {
        public enum ItemKind { File, Directory, RegistryKey }
        public ItemKind Kind { get; init; }
        public string PathOrKey { get; init; } = "";
        public long SizeBytes { get; init; }
        public string Description { get; init; } = "";
    }

    public sealed class ResidualScanResult
    {
        public InstalledApp TargetApp { get; init; } = new();
        public List<ResidualItem> Items { get; init; } = new();
        public long TotalBytes => Items.Where(i => i.Kind != ResidualItem.ItemKind.RegistryKey).Sum(i => i.SizeBytes);
        public string TotalFormatted => FormatSize(TotalBytes);
        public int FileCount => Items.Count(i => i.Kind == ResidualItem.ItemKind.File);
        public int DirectoryCount => Items.Count(i => i.Kind == ResidualItem.ItemKind.Directory);
        public int RegistryKeyCount => Items.Count(i => i.Kind == ResidualItem.ItemKind.RegistryKey);
    }

    public sealed class UninstallResult
    {
        public bool Success { get; init; }
        public int ExitCode { get; init; }
        public string ErrorMessage { get; init; } = "";
        public ResidualScanResult? Residuals { get; init; }
    }

    // ─── Core Methods ────────────────────────────────────────────────────

    /// <summary>
    /// Audits all installed applications across 32-bit, 64-bit, and User registry locations.
    /// </summary>
    public List<InstalledApp> GetInstalledApplications()
    {
        _logger?.LogInformation("Auditing installed applications...");
        var apps = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);

        var registryTargets = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Registry64),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Registry32),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Default),
            (RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", RegistryView.Default)
        };

        foreach (var (hive, subKeyPath, view) in registryTargets)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uninstallKey = baseKey.OpenSubKey(subKeyPath);
                if (uninstallKey == null) continue;

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName);
                        if (appKey == null) continue;

                        var displayName = appKey.GetValue("DisplayName")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(displayName)) continue;

                        // Filter out Windows Updates or hidden system updates
                        var parentKeyName = appKey.GetValue("ParentKeyName")?.ToString();
                        var releaseType = appKey.GetValue("ReleaseType")?.ToString();
                        var systemComponent = Convert.ToInt32(appKey.GetValue("SystemComponent") ?? 0) == 1;

                        if (!string.IsNullOrEmpty(parentKeyName) || string.Equals(releaseType, "Security Update", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var uninstallString = appKey.GetValue("UninstallString")?.ToString() ?? "";
                        var quietUninstallString = appKey.GetValue("QuietUninstallString")?.ToString() ?? "";
                        var publisher = appKey.GetValue("Publisher")?.ToString()?.Trim() ?? "";
                        var version = appKey.GetValue("DisplayVersion")?.ToString()?.Trim() ?? "";
                        var installDate = appKey.GetValue("InstallDate")?.ToString()?.Trim() ?? "";
                        var installLocation = appKey.GetValue("InstallLocation")?.ToString()?.Trim() ?? "";
                        var displayIcon = appKey.GetValue("DisplayIcon")?.ToString()?.Trim() ?? "";
                        var estimatedSize = Convert.ToInt64(appKey.GetValue("EstimatedSize") ?? 0);

                        var app = new InstalledApp
                        {
                            Id = subKeyName,
                            DisplayName = displayName,
                            DisplayVersion = version,
                            Publisher = publisher,
                            InstallDate = installDate,
                            UninstallString = uninstallString,
                            QuietUninstallString = quietUninstallString,
                            InstallLocation = installLocation,
                            DisplayIcon = displayIcon,
                            EstimatedSizeKB = estimatedSize,
                            IsSystemComponent = systemComponent,
                            RegistryPath = $@"{hive}\{subKeyPath}\{subKeyName}"
                        };

                        if (!apps.ContainsKey(displayName))
                        {
                            apps[displayName] = app;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug("Failed reading registry subkey {SubKey}: {Msg}", subKeyName, ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning("Failed accessing registry target {Hive}\\{Path}: {Msg}", hive, subKeyPath, ex.Message);
            }
        }

        var resultList = apps.Values.OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        _logger?.LogInformation("Audit complete. Found {Count} installed applications.", resultList.Count);
        return resultList;
    }

    /// <summary>
    /// Scans for residual leftover files, folders, and registry keys associated with an application.
    /// </summary>
    public ResidualScanResult ScanResiduals(InstalledApp app)
    {
        _logger?.LogInformation("Scanning residuals for application: {Name}", app.DisplayName);
        var result = new ResidualScanResult { TargetApp = app };
        var cleanName = CleanSearchTerm(app.DisplayName);
        var publisherName = CleanSearchTerm(app.Publisher);

        if (string.IsNullOrWhiteSpace(cleanName) || cleanName.Length < 3)
            return result;

        // 1. Scan filesystem directories (AppData Local/Roaming, ProgramData, LocalAppDataLow)
        var searchFolders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow")
        };

        var enumOptions = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            IgnoreInaccessible = true
        };

        foreach (var folder in searchFolders)
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(folder, "*", enumOptions))
                {
                    var dirName = Path.GetFileName(dir);
                    if (IsMatch(dirName, cleanName, publisherName))
                    {
                        var dirSize = GetDirectorySizeSafe(dir);
                        result.Items.Add(new ResidualItem
                        {
                            Kind = ResidualItem.ItemKind.Directory,
                            PathOrKey = dir,
                            SizeBytes = dirSize,
                            Description = $"Leftover folder in {Path.GetFileName(folder)}"
                        });
                    }
                }
            }
            catch { }
        }

        // 2. Scan Registry HKLM\Software and HKCU\Software
        var regTargets = new[]
        {
            (RegistryHive.CurrentUser, @"SOFTWARE"),
            (RegistryHive.LocalMachine, @"SOFTWARE"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node")
        };

        foreach (var (hive, path) in regTargets)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var softwareKey = baseKey.OpenSubKey(path);
                if (softwareKey == null) continue;

                foreach (var keyName in softwareKey.GetSubKeyNames())
                {
                    if (IsMatch(keyName, cleanName, publisherName))
                    {
                        result.Items.Add(new ResidualItem
                        {
                            Kind = ResidualItem.ItemKind.RegistryKey,
                            PathOrKey = $@"{hive}\{path}\{keyName}",
                            SizeBytes = 0,
                            Description = "Leftover registry software key"
                        });
                    }
                }
            }
            catch { }
        }

        _logger?.LogInformation("Residual scan complete for {Name}. Found {Count} items ({Size}).",
            app.DisplayName, result.Items.Count, result.TotalFormatted);

        return result;
    }

    /// <summary>
    /// Executes the application uninstaller.
    /// </summary>
    public async Task<UninstallResult> UninstallAppAsync(InstalledApp app, bool quiet = false, CancellationToken ct = default)
    {
        var cmd = quiet && !string.IsNullOrWhiteSpace(app.QuietUninstallString)
            ? app.QuietUninstallString
            : app.UninstallString;

        if (string.IsNullOrWhiteSpace(cmd))
        {
            return new UninstallResult { Success = false, ErrorMessage = "No valid uninstall string found." };
        }

        _logger?.LogInformation("Executing uninstaller for {Name}: {Cmd}", app.DisplayName, cmd);

        try
        {
            ParseCommand(cmd, out var fileName, out var args);
            if (quiet && string.Equals(Path.GetExtension(fileName), ".msi", StringComparison.OrdinalIgnoreCase))
            {
                if (!args.Contains("/q", StringComparison.OrdinalIgnoreCase))
                    args += " /qn /norestart";
            }

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = true,
                Verb = "runas"
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                return new UninstallResult { Success = false, ErrorMessage = "Failed to launch uninstaller process." };
            }

            await process.WaitForExitAsync(ct).ConfigureAwait(false);

            var residuals = ScanResiduals(app);
            return new UninstallResult
            {
                Success = process.ExitCode == 0 || process.ExitCode == 3010, // 3010 = reboot required
                ExitCode = process.ExitCode,
                Residuals = residuals
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Uninstaller execution failed for {Name}", app.DisplayName);
            return new UninstallResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    /// <summary>
    /// Cleans residual files and registry keys returned from a ResidualScanResult.
    /// </summary>
    public int CleanResiduals(ResidualScanResult scanResult)
    {
        int cleanedCount = 0;
        foreach (var item in scanResult.Items)
        {
            try
            {
                if (item.Kind == ResidualItem.ItemKind.Directory && Directory.Exists(item.PathOrKey))
                {
                    Directory.Delete(item.PathOrKey, true);
                    cleanedCount++;
                }
                else if (item.Kind == ResidualItem.ItemKind.File && File.Exists(item.PathOrKey))
                {
                    File.Delete(item.PathOrKey);
                    cleanedCount++;
                }
                else if (item.Kind == ResidualItem.ItemKind.RegistryKey)
                {
                    if (DeleteRegistryKeyPath(item.PathOrKey))
                        cleanedCount++;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning("Failed cleaning residual {Path}: {Msg}", item.PathOrKey, ex.Message);
            }
        }
        return cleanedCount;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static bool IsMatch(string candidate, string appName, string publisher)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        if (string.Equals(candidate, appName, StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrWhiteSpace(publisher) && string.Equals(candidate, publisher, StringComparison.OrdinalIgnoreCase)) return true;
        return candidate.Contains(appName, StringComparison.OrdinalIgnoreCase) && appName.Length >= 4;
    }

    private static string CleanSearchTerm(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        // Remove version numbers, trailing suffixes like (x64), v1.0, etc.
        var cleaned = Regex.Replace(name, @"\b(v?\d+(\.\d+)+|x64|x86|64-bit|32-bit)\b", "", RegexOptions.IgnoreCase);
        return cleaned.Trim();
    }

    private static void ParseCommand(string commandLine, out string fileName, out string arguments)
    {
        commandLine = commandLine.Trim();
        if (commandLine.StartsWith("\""))
        {
            var nextQuote = commandLine.IndexOf('"', 1);
            if (nextQuote > 0)
            {
                fileName = commandLine[1..nextQuote];
                arguments = commandLine[(nextQuote + 1)..].Trim();
                return;
            }
        }

        var spaceIndex = commandLine.IndexOf(' ');
        if (spaceIndex > 0)
        {
            fileName = commandLine[..spaceIndex];
            arguments = commandLine[(spaceIndex + 1)..].Trim();
        }
        else
        {
            fileName = commandLine;
            arguments = "";
        }
    }

    private static bool DeleteRegistryKeyPath(string keyPath)
    {
        var parts = keyPath.Split('\\', 2);
        if (parts.Length < 2) return false;

        RegistryHive hive = parts[0] switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => RegistryHive.LocalMachine,
            "HKEY_CURRENT_USER" or "HKCU" => RegistryHive.CurrentUser,
            _ => RegistryHive.CurrentUser
        };

        var lastSlash = parts[1].LastIndexOf('\\');
        if (lastSlash <= 0) return false;

        var parentPath = parts[1][..lastSlash];
        var keyName = parts[1][(lastSlash + 1)..];

        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var parentKey = baseKey.OpenSubKey(parentPath, true);
        if (parentKey == null) return false;

        parentKey.DeleteSubKeyTree(keyName, false);
        return true;
    }

    private static long GetDirectorySizeSafe(string path)
    {
        try
        {
            var opt = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
            return Directory.EnumerateFiles(path, "*", opt).Sum(f => { try { return new FileInfo(f).Length; } catch { return 0; } });
        }
        catch { return 0; }
    }

    private static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < units.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {units[order]}";
    }
}
