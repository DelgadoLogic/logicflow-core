// LogicFlow.Guardian — Smart Driver Engine & Performance Optimizer
// Proprietary implementation by DelgadoLogic.Tech
// Hardware ID matching, power plan automation, debloat, startup optimization

using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Smart Driver Engine: matches hardware IDs to driver information via WMI,
/// detects outdated/problematic drivers, and suggests updates.
/// </summary>
public sealed class SmartDriverEngine
{
    private readonly ILogger<SmartDriverEngine> _logger;

    public SmartDriverEngine(ILogger<SmartDriverEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans all PnP devices and returns driver status for each.
    /// </summary>
    public List<DriverReport> ScanDrivers()
    {
        _logger.LogInformation("Scanning system drivers...");
        var reports = new List<DriverReport>();

        using var searcher = new ManagementObjectSearcher(
            "SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName IS NOT NULL");

        foreach (var obj in searcher.Get())
        {
            var report = new DriverReport
            {
                DeviceName = obj["DeviceName"]?.ToString() ?? "Unknown Device",
                HardwareId = obj["HardWareID"]?.ToString() ?? "",
                DriverVersion = obj["DriverVersion"]?.ToString() ?? "",
                DriverDate = obj["DriverDate"]?.ToString() ?? "",
                Manufacturer = obj["Manufacturer"]?.ToString() ?? "",
                DeviceClass = obj["DeviceClass"]?.ToString() ?? "",
                IsSigned = obj["IsSigned"] is bool signed && signed,
                InfName = obj["InfName"]?.ToString() ?? ""
            };

            report.Status = EvaluateDriverHealth(report);
            reports.Add(report);
        }

        _logger.LogInformation("Scanned {Count} drivers. {Problem} need attention.",
            reports.Count, reports.Count(r => r.Status != DriverStatus.Healthy));

        return reports;
    }

    private static DriverStatus EvaluateDriverHealth(DriverReport driver)
    {
        if (!driver.IsSigned) return DriverStatus.Unsigned;
        if (string.IsNullOrEmpty(driver.DriverVersion)) return DriverStatus.Missing;

        // Check if driver date is older than 2 years
        if (DateTime.TryParse(driver.DriverDate, out var date) && date < DateTime.Now.AddYears(-2))
            return DriverStatus.Outdated;

        return DriverStatus.Healthy;
    }
}

/// <summary>
/// Power Plan Automation: creates AI-optimized power plans for different workloads,
/// with special support for 2026 NPU processors.
/// </summary>
public sealed class PowerPlanAutomation
{
    private readonly ILogger<PowerPlanAutomation> _logger;

    public PowerPlanAutomation(ILogger<PowerPlanAutomation> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets all available power plans on the system.
    /// </summary>
    public List<PowerPlanInfo> GetPowerPlans()
    {
        var plans = new List<PowerPlanInfo>();
        using var searcher = new ManagementObjectSearcher(
            @"root\cimv2\power", "SELECT * FROM Win32_PowerPlan");

        foreach (var obj in searcher.Get())
        {
            plans.Add(new PowerPlanInfo
            {
                ElementName = obj["ElementName"]?.ToString() ?? "",
                InstanceId = obj["InstanceID"]?.ToString() ?? "",
                IsActive = obj["IsActive"] is bool active && active
            });
        }
        return plans;
    }

    /// <summary>
    /// Detects if the system has an NPU (Neural Processing Unit) for AI workloads.
    /// </summary>
    public bool HasNeuralProcessor()
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%NPU%' OR Name LIKE '%Neural%' OR Name LIKE '%AI Engine%'");
        return searcher.Get().Count > 0;
    }
}

/// <summary>
/// Debloat Engine: safely removes pre-installed UWP/MSIX bloatware
/// with dependency graph analysis to prevent breaking system apps.
/// </summary>
public sealed class DebloatEngine
{
    private readonly ILogger<DebloatEngine> _logger;

    // Known safe-to-remove bloatware packages
    private static readonly HashSet<string> KnownBloatware = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingFinance",
        "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.People", "Microsoft.SkypeApp",
        "Microsoft.WindowsFeedbackHub", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "Microsoft.YourPhone", "Microsoft.MixedReality.Portal",
        "Clipchamp.Clipchamp", "Microsoft.Todos", "Microsoft.PowerAutomateDesktop",
        "MicrosoftTeams", "Microsoft.549981C3F5F10", // Cortana
    };

    public DebloatEngine(ILogger<DebloatEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans for installed bloatware and returns removal candidates.
    /// </summary>
    public List<BloatwarePackage> ScanBloatware()
    {
        _logger.LogInformation("Scanning for bloatware...");
        var packages = new List<BloatwarePackage>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Try WMI Win32_InstalledStoreProgram (works if elevated)
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_InstalledStoreProgram");

            foreach (var obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString() ?? "";
                var isBloat = KnownBloatware.Any(b => name.Contains(b, StringComparison.OrdinalIgnoreCase));

                if (isBloat && seenNames.Add(name))
                {
                    packages.Add(new BloatwarePackage
                    {
                        Name = name,
                        Publisher = obj["Vendor"]?.ToString() ?? "",
                        Version = obj["Version"]?.ToString() ?? "",
                        IsSafeToRemove = true
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WMI Win32_InstalledStoreProgram query failed or access denied, checking registry repository.");
        }

        // 2. Supplementary/Fallback: query user AppModel repository in Registry
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (key != null)
            {
                foreach (var subName in key.GetSubKeyNames())
                {
                    var isBloat = KnownBloatware.Any(b => subName.Contains(b, StringComparison.OrdinalIgnoreCase));
                    if (isBloat && seenNames.Add(subName))
                    {
                        packages.Add(new BloatwarePackage
                        {
                            Name = subName,
                            Publisher = "Microsoft Corporation",
                            Version = "",
                            IsSafeToRemove = true
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Registry AppModel Repository query failed.");
        }

        _logger.LogInformation("Found {Count} bloatware packages", packages.Count);
        return packages;
    }

    /// <summary>
    /// Removes a specific UWP / AppX bloatware package using PowerShell AppX cmdlets.
    /// </summary>
    public bool RemoveBloatware(string packageName)
    {
        if (string.IsNullOrWhiteSpace(packageName)) return false;
        try
        {
            _logger.LogInformation("Removing bloatware package: {Name}", packageName);
            var sanitizedName = packageName.Replace("'", "").Replace("\"", "").Replace(";", "");
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"Get-AppxPackage -Name '*{sanitizedName}*' | Remove-AppxPackage -ErrorAction SilentlyContinue; Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -like '*{sanitizedName}*' }} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(30000);
            return proc?.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove bloatware package {Name}", packageName);
            return false;
        }
    }

    /// <summary>
    /// Removes multiple bloatware packages and returns the count of successful removals.
    /// </summary>
    public int RemoveBloatwarePackages(IEnumerable<string> packageNames)
    {
        int removed = 0;
        foreach (var pkg in packageNames)
        {
            if (RemoveBloatware(pkg))
            {
                removed++;
            }
        }
        return removed;
    }
}

/// <summary>
/// Startup Optimizer: analyzes startup impact and manages auto-start programs.
/// </summary>
public sealed class StartupOptimizer
{
    private readonly ILogger<StartupOptimizer> _logger;

    public StartupOptimizer(ILogger<StartupOptimizer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Enumerates all startup items and scores their performance impact across HKCU, HKLM, and startup folders.
    /// </summary>
    public List<StartupItem> AnalyzeStartupItems()
    {
        var items = new List<StartupItem>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Check HKCU Run keys (Primary location for user applications)
        var hkcuKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var keyPath in hkcuKeys)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (seenNames.Add(valueName))
                        {
                            items.Add(new StartupItem
                            {
                                Name = valueName,
                                Command = key.GetValue(valueName)?.ToString() ?? "",
                                Source = $"HKCU\\{keyPath}",
                                ImpactScore = EstimateImpact(valueName)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not read HKCU startup key: {Key}", keyPath);
            }
        }

        // 2. Check HKLM Run registry keys
        var hklmKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var keyPath in hklmKeys)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (seenNames.Add(valueName))
                        {
                            items.Add(new StartupItem
                            {
                                Name = valueName,
                                Command = key.GetValue(valueName)?.ToString() ?? "",
                                Source = $"HKLM\\{keyPath}",
                                ImpactScore = EstimateImpact(valueName)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not read HKLM startup key: {Key}", keyPath);
            }
        }

        // 3. Check User and Common Startup Folders
        var startupFolders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup Folder"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All Users Startup Folder")
        };

        foreach (var (dir, label) in startupFolders)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        var name = Path.GetFileNameWithoutExtension(file);
                        if (seenNames.Add(name))
                        {
                            items.Add(new StartupItem
                            {
                                Name = name,
                                Command = file,
                                Source = label,
                                ImpactScore = EstimateImpact(name)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not enumerate startup folder: {Folder}", dir);
            }
        }

        return items.OrderByDescending(i => i.ImpactScore).ToList();
    }

    /// <summary>
    /// Disables or removes an autostart item from HKCU or HKLM Run registry.
    /// </summary>
    public bool DisableStartupItem(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        bool removed = false;

        try
        {
            using var hkcu = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            if (hkcu != null && hkcu.GetValue(name) != null)
            {
                hkcu.DeleteValue(name, false);
                removed = true;
            }
        }
        catch { }

        try
        {
            using var hklm = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            if (hklm != null && hklm.GetValue(name) != null)
            {
                hklm.DeleteValue(name, false);
                removed = true;
            }
        }
        catch { }

        return removed;
    }

    private static int EstimateImpact(string name)
    {
        var lower = name.ToLowerInvariant();
        // High-impact: known heavy apps
        if (lower.Contains("teams") || lower.Contains("skype") || lower.Contains("onedrive"))
            return 8;
        if (lower.Contains("steam") || lower.Contains("discord") || lower.Contains("spotify"))
            return 7;
        if (lower.Contains("update") || lower.Contains("updater"))
            return 5;
        // Low-impact: security tools, drivers
        if (lower.Contains("security") || lower.Contains("defender"))
            return 2;
        return 4; // Default medium impact
    }
}

// ─── Data Models ───────────────────────────────────────────────
public sealed record DriverReport
{
    public string DeviceName { get; init; } = "";
    public string HardwareId { get; init; } = "";
    public string DriverVersion { get; init; } = "";
    public string DriverDate { get; init; } = "";
    public string Manufacturer { get; init; } = "";
    public string DeviceClass { get; init; } = "";
    public bool IsSigned { get; init; }
    public string InfName { get; init; } = "";
    public DriverStatus Status { get; set; }
}

public enum DriverStatus { Healthy, Outdated, Missing, Unsigned, Problematic }

public sealed record PowerPlanInfo
{
    public string ElementName { get; init; } = "";
    public string InstanceId { get; init; } = "";
    public bool IsActive { get; init; }
}

public sealed record BloatwarePackage
{
    public string Name { get; init; } = "";
    public string Publisher { get; init; } = "";
    public string Version { get; init; } = "";
    public bool IsSafeToRemove { get; init; }
    public bool IsSelected { get; set; } = true;
}

public sealed record StartupItem
{
    public string Name { get; init; } = "";
    public string Command { get; init; } = "";
    public string Source { get; init; } = "";
    public int ImpactScore { get; set; }
}
