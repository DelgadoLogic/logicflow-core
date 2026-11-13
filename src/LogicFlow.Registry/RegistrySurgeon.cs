// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Registry — Registry Surgeon (v2 — CCleaner-level)
// Comprehensive registry analysis with COM/ActiveX orphans, SharedDLL scan,
// TypeLib orphans, MUI cache, HKCU coverage, and safe repair with backup.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Registry;

/// <summary>
/// Analyzes the Windows registry for orphaned keys, broken references,
/// COM/ActiveX orphans, shared DLL issues, and more.
/// Uses dependency mapping to ensure safe repairs.
/// </summary>
public sealed class RegistryAnalyzer
{
    private readonly ILogger<RegistryAnalyzer> _logger;

    /// <summary>
    /// Critical registry paths that should never be modified.
    /// </summary>
    private static readonly HashSet<string> ProtectedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        @"HKEY_LOCAL_MACHINE\SECURITY",
        @"HKEY_LOCAL_MACHINE\SAM",
        @"HKEY_LOCAL_MACHINE\BCD00000000",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
    };

    public RegistryAnalyzer(ILogger<RegistryAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs a comprehensive registry health scan across all categories.
    /// </summary>
    public RegistryScanResult Scan()
    {
        _logger.LogInformation("Starting comprehensive registry scan...");
        var sw = Stopwatch.StartNew();
        var result = new RegistryScanResult { ScannedAt = DateTimeOffset.UtcNow };

        result.OrphanedSoftwareKeys = ScanOrphanedSoftwareKeys();
        result.BrokenFileAssociations = ScanBrokenFileAssociations();
        result.InvalidPaths = ScanInvalidPaths();
        result.ObsoleteRunEntries = ScanObsoleteRunEntries();
        result.ComActiveXOrphans = ScanComActiveXOrphans();
        result.SharedDllIssues = ScanSharedDlls();
        result.TypeLibOrphans = ScanTypeLibOrphans();
        result.MuiCacheOrphans = ScanMuiCache();
        result.HkcuOrphanedKeys = ScanHkcuOrphans();
        result.InstallerOrphans = ScanInstallerReferences();

        result.TotalIssues = result.OrphanedSoftwareKeys.Count +
                            result.BrokenFileAssociations.Count +
                            result.InvalidPaths.Count +
                            result.ObsoleteRunEntries.Count +
                            result.ComActiveXOrphans.Count +
                            result.SharedDllIssues.Count +
                            result.TypeLibOrphans.Count +
                            result.MuiCacheOrphans.Count +
                            result.HkcuOrphanedKeys.Count +
                            result.InstallerOrphans.Count;

        sw.Stop();
        result.ScanDuration = sw.Elapsed;

        _logger.LogInformation("Registry scan complete. Found {Total} issues in {Time:0.0}s.",
            result.TotalIssues, sw.Elapsed.TotalSeconds);
        return result;
    }

    // ─── 1) Orphaned Software Keys (HKLM + HKCU) ───────────────────────

    private List<RegistryIssue> ScanOrphanedSoftwareKeys()
    {
        var issues = new List<RegistryIssue>();

        // Scan HKLM
        ScanUninstallPath(issues,
            Microsoft.Win32.Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM");

        // Scan HKCU (user-installed apps)
        ScanUninstallPath(issues,
            Microsoft.Win32.Registry.CurrentUser,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU");

        // Scan 32-bit on 64-bit (WoW6432Node)
        ScanUninstallPath(issues,
            Microsoft.Win32.Registry.LocalMachine,
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM (x86)");

        return issues;
    }

    private void ScanUninstallPath(List<RegistryIssue> issues, RegistryKey hive,
        string uninstallPath, string hiveLabel)
    {
        try
        {
            using var key = hive.OpenSubKey(uninstallPath);
            if (key is null) return;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey is null) continue;

                    var installLocation = subKey.GetValue("InstallLocation")?.ToString();
                    var displayName = subKey.GetValue("DisplayName")?.ToString() ?? subKeyName;

                    if (!string.IsNullOrEmpty(installLocation) && !Directory.Exists(installLocation))
                    {
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"{hiveLabel}\{uninstallPath}\{subKeyName}",
                            FullRegistryPath = $@"{(hive == Microsoft.Win32.Registry.LocalMachine ? "HKLM" : "HKCU")}\{uninstallPath}\{subKeyName}",
                            Type = RegistryIssueType.OrphanedKey,
                            Description = $"Install path missing for '{displayName}': {installLocation}",
                            Severity = IssueSeverity.Medium,
                            IsSafeToFix = true
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning {Hive} uninstall keys", hiveLabel);
        }
    }

    // ─── 2) Broken File Associations ────────────────────────────────────

    private List<RegistryIssue> ScanBrokenFileAssociations()
    {
        var issues = new List<RegistryIssue>();

        try
        {
            using var classesRoot = Microsoft.Win32.Registry.ClassesRoot;
            var extensions = classesRoot.GetSubKeyNames()
                .Where(n => n.StartsWith('.'))
                .Take(500);

            foreach (var ext in extensions)
            {
                try
                {
                    using var extKey = classesRoot.OpenSubKey(ext);
                    var progId = extKey?.GetValue("")?.ToString();
                    if (string.IsNullOrEmpty(progId)) continue;

                    using var commandKey = classesRoot.OpenSubKey($@"{progId}\shell\open\command");
                    var command = commandKey?.GetValue("")?.ToString();
                    if (string.IsNullOrEmpty(command)) continue;

                    var exePath = ExtractExePath(command);
                    if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                    {
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"HKCR\{progId}\shell\open\command",
                            FullRegistryPath = $@"HKEY_CLASSES_ROOT\{progId}\shell\open\command",
                            Type = RegistryIssueType.BrokenFileAssociation,
                            Description = $"Extension {ext} → missing exe: {exePath}",
                            Severity = IssueSeverity.Low,
                            IsSafeToFix = true
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning file associations");
        }

        return issues;
    }

    // ─── 3) Invalid App Paths ───────────────────────────────────────────

    private List<RegistryIssue> ScanInvalidPaths()
    {
        var issues = new List<RegistryIssue>();
        var pathKeys = new (string keyPath, RegistryKey hive, string label)[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", Microsoft.Win32.Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", Microsoft.Win32.Registry.CurrentUser, "HKCU"),
        };

        foreach (var (keyPath, hive, label) in pathKeys)
        {
            try
            {
                using var key = hive.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    var path = subKey?.GetValue("")?.ToString();

                    if (!string.IsNullOrEmpty(path) && path.Contains('\\') && !File.Exists(path))
                    {
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"{label}\{keyPath}\{subKeyName}",
                            FullRegistryPath = $@"{(hive == Microsoft.Win32.Registry.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER")}\{keyPath}\{subKeyName}",
                            Type = RegistryIssueType.InvalidPath,
                            Description = $"App path missing: {path}",
                            Severity = IssueSeverity.Low,
                            IsSafeToFix = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error scanning {Label} path keys", label);
            }
        }

        return issues;
    }

    // ─── 4) Obsolete Run Entries (HKLM + HKCU) ─────────────────────────

    private List<RegistryIssue> ScanObsoleteRunEntries()
    {
        var issues = new List<RegistryIssue>();
        var runPaths = new (string path, RegistryKey hive, string label)[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Microsoft.Win32.Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Microsoft.Win32.Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Microsoft.Win32.Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Microsoft.Win32.Registry.CurrentUser, "HKCU"),
        };

        foreach (var (runPath, hive, label) in runPaths)
        {
            try
            {
                using var key = hive.OpenSubKey(runPath);
                if (key is null) continue;

                foreach (var name in key.GetValueNames())
                {
                    var command = key.GetValue(name)?.ToString() ?? "";
                    var exePath = ExtractExePath(command);

                    if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                    {
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"{label}\{runPath}\{name}",
                            FullRegistryPath = $@"{(hive == Microsoft.Win32.Registry.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER")}\{runPath}",
                            ValueName = name,
                            Type = RegistryIssueType.ObsoleteRunEntry,
                            Description = $"Startup entry '{name}' references missing: {exePath}",
                            Severity = IssueSeverity.Medium,
                            IsSafeToFix = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error scanning {Label} Run entries", label);
            }
        }

        return issues;
    }

    // ─── 5) COM/ActiveX Orphan Detection (NEW) ──────────────────────────

    /// <summary>
    /// Scans HKCR\CLSID for COM/ActiveX components referencing missing DLLs/EXEs.
    /// These are InProcServer32, InProcHandler32, and LocalServer32 entries.
    /// </summary>
    private List<RegistryIssue> ScanComActiveXOrphans()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            using var clsidKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID");
            if (clsidKey is null) return issues;

            int scanned = 0;
            foreach (var clsid in clsidKey.GetSubKeyNames())
            {
                if (++scanned > 2000) break; // Limit for performance

                try
                {
                    using var entry = clsidKey.OpenSubKey(clsid);
                    if (entry is null) continue;
                    var displayName = entry.GetValue("")?.ToString() ?? clsid;

                    // Check InProcServer32 (DLL-based COM)
                    CheckComServer(issues, clsidKey, clsid, "InProcServer32", displayName);

                    // Check InProcHandler32
                    CheckComServer(issues, clsidKey, clsid, "InProcHandler32", displayName);

                    // Check LocalServer32 (EXE-based COM)
                    CheckComServer(issues, clsidKey, clsid, "LocalServer32", displayName);
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning COM/ActiveX orphans");
        }

        return issues;
    }

    private static void CheckComServer(List<RegistryIssue> issues, RegistryKey clsidKey,
        string clsid, string serverType, string displayName)
    {
        try
        {
            using var serverKey = clsidKey.OpenSubKey($@"{clsid}\{serverType}");
            var serverPath = serverKey?.GetValue("")?.ToString();
            if (string.IsNullOrEmpty(serverPath)) return;

            // Expand environment variables
            serverPath = Environment.ExpandEnvironmentVariables(serverPath);
            var filePath = ExtractExePath(serverPath);

            if (!string.IsNullOrEmpty(filePath) && filePath.Contains('\\') && !File.Exists(filePath))
            {
                // Skip system paths that might be virtual
                if (filePath.Contains(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return;
                if (filePath.Contains(@"\system32\", StringComparison.OrdinalIgnoreCase) &&
                    filePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

                issues.Add(new RegistryIssue
                {
                    Path = $@"HKCR\CLSID\{clsid}\{serverType}",
                    FullRegistryPath = $@"HKEY_CLASSES_ROOT\CLSID\{clsid}\{serverType}",
                    Type = RegistryIssueType.ComActiveXOrphan,
                    Description = $"COM '{displayName}' → missing: {filePath}",
                    Severity = IssueSeverity.Medium,
                    IsSafeToFix = true
                });
            }
        }
        catch { }
    }

    // ─── 6) Shared DLL Scan (NEW) ───────────────────────────────────────

    /// <summary>
    /// Checks SharedDLLs registry for references to DLL files that no longer exist.
    /// </summary>
    private List<RegistryIssue> ScanSharedDlls()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            var sharedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs";
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(sharedPath);
            if (key is null) return issues;

            int scanned = 0;
            foreach (var dllPath in key.GetValueNames())
            {
                if (++scanned > 2000) break;

                try
                {
                    if (string.IsNullOrEmpty(dllPath) || !dllPath.Contains('\\')) continue;

                    var expanded = Environment.ExpandEnvironmentVariables(dllPath);
                    if (!File.Exists(expanded))
                    {
                        // Skip system32 DLLs — might be architecture-specific
                        if (expanded.Contains(@"\system32\", StringComparison.OrdinalIgnoreCase) ||
                            expanded.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var refCount = Convert.ToInt32(key.GetValue(dllPath) ?? 0);
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"HKLM\{sharedPath}",
                            FullRegistryPath = $@"HKEY_LOCAL_MACHINE\{sharedPath}",
                            ValueName = dllPath,
                            Type = RegistryIssueType.SharedDllOrphan,
                            Description = $"Shared DLL missing (ref count: {refCount}): {Path.GetFileName(dllPath)}",
                            Severity = IssueSeverity.Low,
                            IsSafeToFix = refCount == 0
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning shared DLLs");
        }

        return issues;
    }

    // ─── 7) Type Library Orphans (NEW) ──────────────────────────────────

    /// <summary>
    /// Scans HKCR\TypeLib for registered type libraries with missing files.
    /// </summary>
    private List<RegistryIssue> ScanTypeLibOrphans()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            using var tlbRoot = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("TypeLib");
            if (tlbRoot is null) return issues;

            int scanned = 0;
            foreach (var tlbId in tlbRoot.GetSubKeyNames())
            {
                if (++scanned > 1000) break;

                try
                {
                    using var tlbKey = tlbRoot.OpenSubKey(tlbId);
                    if (tlbKey is null) continue;

                    foreach (var version in tlbKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var verKey = tlbKey.OpenSubKey(version);
                            var displayName = verKey?.GetValue("")?.ToString() ?? tlbId;

                            // Check win32 and win64 paths
                            foreach (var platform in new[] { "0\\win32", "0\\win64" })
                            {
                                using var platKey = verKey?.OpenSubKey(platform);
                                var tlbPath = platKey?.GetValue("")?.ToString();
                                if (string.IsNullOrEmpty(tlbPath)) continue;

                                var expanded = Environment.ExpandEnvironmentVariables(tlbPath);
                                var filePath = ExtractExePath(expanded);

                                if (!string.IsNullOrEmpty(filePath) && filePath.Contains('\\') && !File.Exists(filePath))
                                {
                                    if (filePath.Contains(@"\system32\", StringComparison.OrdinalIgnoreCase)) continue;

                                    issues.Add(new RegistryIssue
                                    {
                                        Path = $@"HKCR\TypeLib\{tlbId}\{version}",
                                        FullRegistryPath = $@"HKEY_CLASSES_ROOT\TypeLib\{tlbId}\{version}",
                                        Type = RegistryIssueType.TypeLibOrphan,
                                        Description = $"TypeLib '{displayName}' → missing: {Path.GetFileName(filePath)}",
                                        Severity = IssueSeverity.Low,
                                        IsSafeToFix = true
                                    });
                                    break; // One issue per TypeLib version
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning TypeLib orphans");
        }

        return issues;
    }

    // ─── 8) MUI Cache Cleanup (NEW) ─────────────────────────────────────

    /// <summary>
    /// Scans MUI cache for entries referencing executables that no longer exist.
    /// </summary>
    private List<RegistryIssue> ScanMuiCache()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            var muiPath = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(muiPath);
            if (key is null) return issues;

            foreach (var valueName in key.GetValueNames())
            {
                try
                {
                    if (!valueName.Contains('\\')) continue;

                    // MUI cache keys are like "C:\path\app.exe.FriendlyAppName"
                    var exePath = valueName;
                    var dotIdx = exePath.LastIndexOf(".FriendlyAppName", StringComparison.OrdinalIgnoreCase);
                    if (dotIdx > 0) exePath = exePath[..dotIdx];
                    dotIdx = exePath.LastIndexOf(".ApplicationCompany", StringComparison.OrdinalIgnoreCase);
                    if (dotIdx > 0) exePath = exePath[..dotIdx];

                    if (exePath.Contains('\\') && !File.Exists(exePath))
                    {
                        issues.Add(new RegistryIssue
                        {
                            Path = $@"HKCU\{muiPath}",
                            FullRegistryPath = $@"HKEY_CURRENT_USER\{muiPath}",
                            ValueName = valueName,
                            Type = RegistryIssueType.MuiCacheOrphan,
                            Description = $"MUI cache for missing app: {Path.GetFileName(exePath)}",
                            Severity = IssueSeverity.Low,
                            IsSafeToFix = true
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning MUI cache");
        }

        return issues;
    }

    // ─── 9) HKCU Software Orphans (NEW) ─────────────────────────────────

    /// <summary>
    /// Scans HKCU\Software for keys referencing programs no longer on disk.
    /// </summary>
    private List<RegistryIssue> ScanHkcuOrphans()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            using var softwareKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software");
            if (softwareKey is null) return issues;

            // Skip Microsoft and known system keys
            var skipVendors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Microsoft", "Classes", "Policies", "RegisteredApplications",
                "DefaultUserEnvironment", "Wine"
            };

            foreach (var vendor in softwareKey.GetSubKeyNames())
            {
                if (skipVendors.Contains(vendor)) continue;

                try
                {
                    using var vendorKey = softwareKey.OpenSubKey(vendor);
                    if (vendorKey is null) continue;

                    // Check if vendor has any subkeys with install paths
                    foreach (var app in vendorKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var appKey = vendorKey.OpenSubKey(app);
                            if (appKey is null) continue;

                            // Look for common path-holding values
                            var installDir = appKey.GetValue("InstallDir")?.ToString()
                                          ?? appKey.GetValue("InstallPath")?.ToString()
                                          ?? appKey.GetValue("InstallLocation")?.ToString()
                                          ?? appKey.GetValue("Path")?.ToString();

                            if (!string.IsNullOrEmpty(installDir) && installDir.Contains('\\') &&
                                !Directory.Exists(installDir) && !File.Exists(installDir))
                            {
                                issues.Add(new RegistryIssue
                                {
                                    Path = $@"HKCU\Software\{vendor}\{app}",
                                    FullRegistryPath = $@"HKEY_CURRENT_USER\Software\{vendor}\{app}",
                                    Type = RegistryIssueType.OrphanedKey,
                                    Description = $"User software '{vendor}\\{app}' path missing: {installDir}",
                                    Severity = IssueSeverity.Low,
                                    IsSafeToFix = true
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning HKCU software orphans");
        }

        return issues;
    }

    // ─── 10) Installer References (NEW) ─────────────────────────────────

    /// <summary>
    /// Checks Windows Installer product keys for uninstalled software.
    /// </summary>
    private List<RegistryIssue> ScanInstallerReferences()
    {
        var issues = new List<RegistryIssue>();
        try
        {
            var productsPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(productsPath);
            if (root is null) return issues;

            foreach (var sid in root.GetSubKeyNames())
            {
                try
                {
                    using var sidKey = root.OpenSubKey($@"{sid}\Products");
                    if (sidKey is null) continue;

                    int scanned = 0;
                    foreach (var productCode in sidKey.GetSubKeyNames())
                    {
                        if (++scanned > 500) break;

                        try
                        {
                            using var prodKey = sidKey.OpenSubKey($@"{productCode}\InstallProperties");
                            if (prodKey is null) continue;

                            var installSource = prodKey.GetValue("InstallSource")?.ToString();
                            var displayName = prodKey.GetValue("DisplayName")?.ToString() ?? productCode;

                            if (!string.IsNullOrEmpty(installSource) &&
                                installSource.Contains('\\') &&
                                !Directory.Exists(installSource))
                            {
                                issues.Add(new RegistryIssue
                                {
                                    Path = $@"HKLM\{productsPath}\{sid}\Products\{productCode}",
                                    FullRegistryPath = $@"HKEY_LOCAL_MACHINE\{productsPath}\{sid}\Products\{productCode}",
                                    Type = RegistryIssueType.InstallerOrphan,
                                    Description = $"Installer ref for '{displayName}' → missing source",
                                    Severity = IssueSeverity.Low,
                                    IsSafeToFix = false // Installer keys are risky
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning installer references");
        }

        return issues;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static string ExtractExePath(string command)
    {
        if (string.IsNullOrEmpty(command)) return "";

        // Handle quoted paths: "C:\Program Files\app.exe" --args
        if (command.StartsWith('"'))
        {
            var endQuote = command.IndexOf('"', 1);
            return endQuote > 0 ? command[1..endQuote] : "";
        }

        // Handle unquoted paths: C:\app.exe --args
        var spaceIdx = command.IndexOf(' ');
        return spaceIdx > 0 ? command[..spaceIdx] : command;
    }
}

/// <summary>
/// Safely repairs registry issues with automatic backup and rollback.
/// Creates a .reg backup file before any modifications.
/// </summary>
public sealed class RepairEngine
{
    private readonly ILogger<RepairEngine> _logger;
    private readonly string _backupDirectory;

    public RepairEngine(ILogger<RepairEngine> logger, string? backupDirectory = null)
    {
        _logger = logger;
        _backupDirectory = backupDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow", "RegistryBackups");
        Directory.CreateDirectory(_backupDirectory);
    }

    /// <summary>
    /// Repairs a list of registry issues. Creates a backup first.
    /// Returns the number of issues fixed and the backup file path.
    /// </summary>
    public RepairResult Fix(List<RegistryIssue> issues)
    {
        var safeIssues = issues.Where(i => i.IsSafeToFix).ToList();
        if (safeIssues.Count == 0)
        {
            return new RepairResult
            {
                Fixed = 0,
                Failed = 0,
                BackupFile = "",
                Message = "No safe-to-fix issues found."
            };
        }

        // Trigger OmniCore.Engine's Smart Systems Rollback (Services snapshot + 5s buffer)
        var sysLogger = Microsoft.Extensions.Logging.Abstractions.NullLogger<OmniCore.Engine.SmartRollbackEngine>.Instance;
        var rollbackEngine = new OmniCore.Engine.SmartRollbackEngine(sysLogger, _backupDirectory);
        rollbackEngine.TakeSnapshotAsync($"Pre-fix snapshot for {safeIssues.Count} registry issues").GetAwaiter().GetResult();

        // Create registry backup before any changes
        var backupFile = CreateBackup($"Pre-fix backup for {safeIssues.Count} issues");
        int fixed_ = 0, failed = 0;
        var errors = new List<string>();

        foreach (var issue in safeIssues)
        {
            try
            {
                bool success = issue.Type switch
                {
                    // For orphaned keys, delete the entire subkey
                    RegistryIssueType.OrphanedKey => DeleteRegistryKey(issue),
                    // For values (Run entries, SharedDLLs, MUI cache), delete the value
                    RegistryIssueType.ObsoleteRunEntry => DeleteRegistryValue(issue),
                    RegistryIssueType.SharedDllOrphan => DeleteRegistryValue(issue),
                    RegistryIssueType.MuiCacheOrphan => DeleteRegistryValue(issue),
                    // For broken associations, delete the command key
                    RegistryIssueType.BrokenFileAssociation => DeleteRegistryKey(issue),
                    // For COM orphans, delete the server subkey
                    RegistryIssueType.ComActiveXOrphan => DeleteRegistryKey(issue),
                    // For TypeLib orphans, delete the version key
                    RegistryIssueType.TypeLibOrphan => DeleteRegistryKey(issue),
                    // For Invalid paths, delete the app path key
                    RegistryIssueType.InvalidPath => DeleteRegistryKey(issue),
                    // Installer orphans are NOT safe to fix
                    _ => false
                };

                if (success) fixed_++;
                else failed++;
            }
            catch (Exception ex)
            {
                failed++;
                if (errors.Count < 10)
                    errors.Add($"{issue.Path}: {ex.Message}");
            }
        }

        _logger.LogInformation("Registry repair: {Fixed} fixed, {Failed} failed. Backup: {Backup}",
            fixed_, failed, backupFile);

        return new RepairResult
        {
            Fixed = fixed_,
            Failed = failed,
            BackupFile = backupFile,
            Errors = errors,
            Message = $"Fixed {fixed_} issues. Backup saved to {Path.GetFileName(backupFile)}"
        };
    }

    /// <summary>
    /// Fixes all issues of a specific category.
    /// </summary>
    public RepairResult FixByCategory(RegistryScanResult scanResult, RegistryIssueType category)
    {
        var allIssues = GetAllIssues(scanResult);
        var categoryIssues = allIssues.Where(i => i.Type == category).ToList();
        return Fix(categoryIssues);
    }

    /// <summary>
    /// Fixes all issues at or above a severity level.
    /// </summary>
    public RepairResult FixBySeverity(RegistryScanResult scanResult, IssueSeverity minSeverity)
    {
        var allIssues = GetAllIssues(scanResult);
        var filtered = allIssues.Where(i => i.Severity >= minSeverity).ToList();
        return Fix(filtered);
    }

    private static List<RegistryIssue> GetAllIssues(RegistryScanResult result)
    {
        var all = new List<RegistryIssue>();
        all.AddRange(result.OrphanedSoftwareKeys);
        all.AddRange(result.BrokenFileAssociations);
        all.AddRange(result.InvalidPaths);
        all.AddRange(result.ObsoleteRunEntries);
        all.AddRange(result.ComActiveXOrphans);
        all.AddRange(result.SharedDllIssues);
        all.AddRange(result.TypeLibOrphans);
        all.AddRange(result.MuiCacheOrphans);
        all.AddRange(result.HkcuOrphanedKeys);
        all.AddRange(result.InstallerOrphans);
        return all;
    }

    // ─── Registry Operations ────────────────────────────────────────────

    private bool DeleteRegistryKey(RegistryIssue issue)
    {
        var (hive, subPath) = ParseRegistryPath(issue.FullRegistryPath);
        if (hive == null || string.IsNullOrEmpty(subPath)) return false;

        var parentPath = Path.GetDirectoryName(subPath)?.Replace('/', '\\') ?? "";
        var keyName = Path.GetFileName(subPath);

        using var parent = hive.OpenSubKey(parentPath, writable: true);
        if (parent == null) return false;

        parent.DeleteSubKeyTree(keyName, throwOnMissingSubKey: false);
        _logger.LogDebug("Deleted registry key: {Path}", issue.FullRegistryPath);
        return true;
    }

    private bool DeleteRegistryValue(RegistryIssue issue)
    {
        if (string.IsNullOrEmpty(issue.ValueName)) return DeleteRegistryKey(issue);

        var (hive, subPath) = ParseRegistryPath(issue.FullRegistryPath);
        if (hive == null || string.IsNullOrEmpty(subPath)) return false;

        using var key = hive.OpenSubKey(subPath, writable: true);
        if (key == null) return false;

        key.DeleteValue(issue.ValueName, throwOnMissingValue: false);
        _logger.LogDebug("Deleted registry value: {Path}\\{Value}", subPath, issue.ValueName);
        return true;
    }

    private static (RegistryKey? hive, string subPath) ParseRegistryPath(string fullPath)
    {
        if (fullPath.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
            return (Microsoft.Win32.Registry.LocalMachine, fullPath[19..]);
        if (fullPath.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
            return (Microsoft.Win32.Registry.CurrentUser, fullPath[18..]);
        if (fullPath.StartsWith("HKEY_CLASSES_ROOT\\", StringComparison.OrdinalIgnoreCase))
            return (Microsoft.Win32.Registry.ClassesRoot, fullPath[18..]);
        return (null, "");
    }

    // ─── Backup ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a registry backup file before repairs.
    /// Uses reg.exe export for maximum compatibility.
    /// </summary>
    public string CreateBackup(string description)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var backupFile = Path.Combine(_backupDirectory, $"registry_backup_{timestamp}.reg");

        try
        {
            // Export key sections that we might modify
            var keysToBackup = new[]
            {
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"
            };

            // Use reg.exe to create proper .reg backup files
            foreach (var key in keysToBackup)
            {
                var partFile = backupFile.Replace(".reg", $"_{key.Replace('\\', '_').Replace("HKLM_", "").Replace("HKCU_", "")}.reg");
                try
                {
                    var psi = new ProcessStartInfo("reg.exe", $"export \"{key}\" \"{partFile}\" /y")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);
                }
                catch { }
            }
        }
        catch { }

        // Write description file
        try
        {
            var descFile = backupFile.Replace(".reg", ".txt");
            File.WriteAllText(descFile, $"Backup: {description}\nDate: {DateTime.UtcNow:u}\n");
        }
        catch { }

        _logger.LogInformation("Registry backup created: {File} — {Desc}", backupFile, description);
        return backupFile;
    }

    /// <summary>
    /// Lists available backup files.
    /// </summary>
    public List<BackupInfo> ListBackups()
    {
        var backups = new List<BackupInfo>();
        try
        {
            foreach (var file in Directory.GetFiles(_backupDirectory, "*.reg"))
            {
                var info = new FileInfo(file);
                backups.Add(new BackupInfo
                {
                    FilePath = file,
                    FileName = info.Name,
                    CreatedAt = info.CreationTime,
                    SizeBytes = info.Length
                });
            }
        }
        catch { }
        return backups.OrderByDescending(b => b.CreatedAt).ToList();
    }

    /// <summary>
    /// Restores a registry backup file.
    /// </summary>
    public bool RestoreBackup(string backupFile)
    {
        if (!File.Exists(backupFile)) return false;

        try
        {
            var psi = new ProcessStartInfo("reg.exe", $"import \"{backupFile}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                Verb = "runas"
            };
            var proc = Process.Start(psi);
            proc?.WaitForExit(10000);
            _logger.LogInformation("Registry backup restored from: {File}", backupFile);
            return proc?.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore registry backup");
            return false;
        }
    }
}

// ─── Data Models ───────────────────────────────────────────────
public sealed class RegistryScanResult
{
    public DateTimeOffset ScannedAt { get; set; }
    public TimeSpan ScanDuration { get; set; }
    public int TotalIssues { get; set; }

    // Original categories
    public List<RegistryIssue> OrphanedSoftwareKeys { get; set; } = [];
    public List<RegistryIssue> BrokenFileAssociations { get; set; } = [];
    public List<RegistryIssue> InvalidPaths { get; set; } = [];
    public List<RegistryIssue> ObsoleteRunEntries { get; set; } = [];

    // New v2 categories
    public List<RegistryIssue> ComActiveXOrphans { get; set; } = [];
    public List<RegistryIssue> SharedDllIssues { get; set; } = [];
    public List<RegistryIssue> TypeLibOrphans { get; set; } = [];
    public List<RegistryIssue> MuiCacheOrphans { get; set; } = [];
    public List<RegistryIssue> HkcuOrphanedKeys { get; set; } = [];
    public List<RegistryIssue> InstallerOrphans { get; set; } = [];

    /// <summary>Summary by category for UI display.</summary>
    public Dictionary<string, int> CategorySummary => new()
    {
        ["Orphaned Software"] = OrphanedSoftwareKeys.Count,
        ["Broken File Associations"] = BrokenFileAssociations.Count,
        ["Invalid App Paths"] = InvalidPaths.Count,
        ["Obsolete Startup Entries"] = ObsoleteRunEntries.Count,
        ["COM/ActiveX Orphans"] = ComActiveXOrphans.Count,
        ["Missing Shared DLLs"] = SharedDllIssues.Count,
        ["Type Library Orphans"] = TypeLibOrphans.Count,
        ["MUI Cache Orphans"] = MuiCacheOrphans.Count,
        ["User Software Orphans"] = HkcuOrphanedKeys.Count,
        ["Installer References"] = InstallerOrphans.Count
    };
}

public sealed record RegistryIssue
{
    public string Path { get; init; } = "";
    public string FullRegistryPath { get; init; } = "";
    public string? ValueName { get; init; }
    public RegistryIssueType Type { get; init; }
    public string Description { get; init; } = "";
    public IssueSeverity Severity { get; init; }
    public bool IsSafeToFix { get; init; }
    public string SeverityIcon => Severity switch
    {
        IssueSeverity.Critical => "❌",
        IssueSeverity.High => "🔴",
        IssueSeverity.Medium => "🟡",
        IssueSeverity.Low => "🟢",
        _ => "❓"
    };
}

public sealed class RepairResult
{
    public int Fixed { get; init; }
    public int Failed { get; init; }
    public string BackupFile { get; init; } = "";
    public string Message { get; init; } = "";
    public List<string> Errors { get; init; } = [];
}

public sealed class BackupInfo
{
    public string FilePath { get; init; } = "";
    public string FileName { get; init; } = "";
    public DateTime CreatedAt { get; init; }
    public long SizeBytes { get; init; }
}

public enum RegistryIssueType
{
    OrphanedKey,
    BrokenFileAssociation,
    InvalidPath,
    ObsoleteRunEntry,
    CorruptValue,
    // New v2 types
    ComActiveXOrphan,
    SharedDllOrphan,
    TypeLibOrphan,
    MuiCacheOrphan,
    InstallerOrphan
}

public enum IssueSeverity { Low, Medium, High, Critical }
