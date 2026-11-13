// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — Anonymous System Fingerprint
// Collects hardware/software profile without any personally identifiable info.
// No usernames, no file paths, no IP addresses, no browsing data.
// ─────────────────────────────────────────────────────────────────────────────

using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Generates an anonymous system profile and a stable install ID.
/// The install ID is a one-way hash — cannot be reversed to identify a user.
/// </summary>
public sealed class SystemFingerprint
{
    private readonly ILogger<SystemFingerprint>? _logger;
    private readonly string _installIdPath;

    public SystemFingerprint(ILogger<SystemFingerprint>? logger = null)
    {
        _logger = logger;
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow");
        Directory.CreateDirectory(appData);
        _installIdPath = Path.Combine(appData, ".install_id");
    }

    /// <summary>
    /// Returns a stable, anonymous install ID (persists across sessions).
    /// Generated from a random GUID on first run — NOT tied to hardware.
    /// </summary>
    public string GetInstallId()
    {
        try
        {
            if (File.Exists(_installIdPath))
                return File.ReadAllText(_installIdPath).Trim();

            // Generate new random ID and hash it for extra anonymity
            var rawId = Guid.NewGuid().ToString("N");
            var hashedId = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(rawId)))[..32].ToLowerInvariant();
            File.WriteAllText(_installIdPath, hashedId);
            return hashedId;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to read/create install ID");
            return "unknown";
        }
    }

    /// <summary>
    /// Collects an anonymous system profile. Zero PII.
    /// </summary>
    public SystemProfile Capture()
    {
        _logger?.LogDebug("Capturing anonymous system profile");
        var profile = new SystemProfile();

        try
        {
            // ─── OS Info ───
            profile = profile with
            {
                OsVersion = RuntimeInformation.OSDescription,
                OsBuild = Environment.OSVersion.Version.ToString(),
                DotNetVersion = RuntimeInformation.FrameworkDescription,
                Locale = Thread.CurrentThread.CurrentUICulture.Name
            };

            // ─── CPU ───
            var cpuName = GetWmi("Win32_Processor", "Name");
            var cpuCores = int.TryParse(GetWmi("Win32_Processor", "NumberOfCores"), out var c) ? c : Environment.ProcessorCount;
            var cpuThreads = Environment.ProcessorCount;
            profile = profile with { CpuName = cpuName, CpuCores = cpuCores, CpuThreads = cpuThreads };

            // ─── RAM ───
            var totalRam = long.TryParse(GetWmi("Win32_ComputerSystem", "TotalPhysicalMemory"), out var ram)
                ? ram / (1024 * 1024) : 0;
            profile = profile with { RamTotalMB = totalRam };

            // ─── GPU ───
            var gpuName = GetWmi("Win32_VideoController", "Name");
            var gpuVram = long.TryParse(GetWmi("Win32_VideoController", "AdapterRAM"), out var vram)
                ? vram / (1024 * 1024) : 0;
            profile = profile with { GpuName = gpuName, GpuVramMB = gpuVram };

            // ─── Disk ───
            try
            {
                var sysDrive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\");
                profile = profile with
                {
                    DiskTotalGB = sysDrive.TotalSize / (1024 * 1024 * 1024),
                    DiskFreeGB = sysDrive.TotalFreeSpace / (1024 * 1024 * 1024),
                    DiskType = DetectDiskType()
                };
            }
            catch { /* Disk info unavailable */ }

            // ─── Form Factor ───
            var chassisType = GetWmi("Win32_SystemEnclosure", "ChassisTypes");
            profile = profile with
            {
                IsLaptop = chassisType.Contains("9") || chassisType.Contains("10") ||
                           chassisType.Contains("14") || chassisType.Contains("31"),
                IsServer = Environment.OSVersion.Version.Build < 20000 && // Server builds
                           GetWmi("Win32_OperatingSystem", "ProductType") != "1"
            };

            // ─── Windows Update Status ───
            try
            {
                var lastUpdate = DateTimeOffset.MinValue;
                int pendingCount = 0;
                using var hotfixSearcher = new ManagementObjectSearcher(
                    "SELECT InstalledOn FROM Win32_QuickFixEngineering");
                foreach (var obj in hotfixSearcher.Get())
                {
                    if (obj["InstalledOn"] is string dateStr &&
                        DateTimeOffset.TryParse(dateStr, out var installed) &&
                        installed > lastUpdate)
                    {
                        lastUpdate = installed;
                    }
                }

                // Count pending via COM-free approach: check update session registry
                try
                {
                    using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
                    if (regKey != null) pendingCount = 1; // At least 1 pending reboot-required update
                }
                catch { /* Registry not accessible */ }

                var daysSince = lastUpdate > DateTimeOffset.MinValue
                    ? (int)(DateTimeOffset.UtcNow - lastUpdate).TotalDays : -1;

                profile = profile with
                {
                    PendingUpdateCount = pendingCount,
                    LastUpdateDate = lastUpdate > DateTimeOffset.MinValue ? lastUpdate : null,
                    DaysSinceLastUpdate = daysSince
                };
            }
            catch { /* Windows Update info unavailable */ }

            // ─── Startup Programs Count ───
            try
            {
                int startupCount = 0;
                using var startupSearcher = new ManagementObjectSearcher(
                    "SELECT Name FROM Win32_StartupCommand");
                foreach (var _ in startupSearcher.Get()) startupCount++;
                profile = profile with { StartupProgramCount = startupCount };
            }
            catch { /* Startup count unavailable */ }

            // ─── Power Plan ───
            try
            {
                using var powerSearcher = new ManagementObjectSearcher(
                    @"root\cimv2\power", "SELECT ElementName FROM Win32_PowerPlan WHERE IsActive=TRUE");
                foreach (var obj in powerSearcher.Get())
                {
                    profile = profile with { PowerPlan = obj["ElementName"]?.ToString() ?? "" };
                    break;
                }
            }
            catch { /* Power plan unavailable */ }

            // ─── Secure Boot / TPM ───
            try
            {
                // Secure Boot via registry (most reliable without admin elevation)
                using var sbKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                var secureBoot = sbKey?.GetValue("UEFISecureBootEnabled") is int sb && sb == 1;

                // TPM via WMI
                var tpmPresent = false;
                var tpmVersion = "";
                try
                {
                    using var tpmSearcher = new ManagementObjectSearcher(
                        @"root\cimv2\security\microsofttpm",
                        "SELECT SpecVersion, IsActivated_InitialValue FROM Win32_Tpm");
                    foreach (var obj in tpmSearcher.Get())
                    {
                        tpmPresent = true;
                        var specVer = obj["SpecVersion"]?.ToString() ?? "";
                        tpmVersion = specVer.Contains("2.0") ? "2.0" :
                                     specVer.Contains("1.2") ? "1.2" : specVer;
                        break;
                    }
                }
                catch { /* TPM WMI unavailable — needs admin */ }

                profile = profile with
                {
                    SecureBootEnabled = secureBoot,
                    TpmPresent = tpmPresent,
                    TpmVersion = tpmVersion
                };
            }
            catch { /* Security state unavailable */ }

            // ─── CPU Temperature / Thermal ───
            try
            {
                int cpuTemp = 0;
                bool throttling = false;
                try
                {
                    using var tempSearcher = new ManagementObjectSearcher(
                        @"root\wmi", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                    foreach (var obj in tempSearcher.Get())
                    {
                        if (obj["CurrentTemperature"] is uint tempKelvin)
                        {
                            cpuTemp = (int)(tempKelvin / 10.0 - 273.15);
                            throttling = cpuTemp > 90; // Above 90°C = likely throttling
                        }
                        break;
                    }
                }
                catch { /* Thermal WMI not available without admin */ }

                profile = profile with
                {
                    CpuTempCelsius = cpuTemp,
                    IsThermalThrottling = throttling
                };
            }
            catch { /* Thermal unavailable */ }

            // ─── Display Configuration ───
            try
            {
                int monitorCount = 0;
                string primaryRes = "";
                int refreshRate = 0;

                using var monSearcher = new ManagementObjectSearcher(
                    "SELECT CurrentHorizontalResolution, CurrentVerticalResolution, " +
                    "CurrentRefreshRate FROM Win32_VideoController");
                foreach (var obj in monSearcher.Get())
                {
                    monitorCount++;
                    var hRes = obj["CurrentHorizontalResolution"]?.ToString() ?? "0";
                    var vRes = obj["CurrentVerticalResolution"]?.ToString() ?? "0";
                    var hz = int.TryParse(obj["CurrentRefreshRate"]?.ToString(), out var r) ? r : 0;

                    if (monitorCount == 1) // Primary
                    {
                        primaryRes = $"{hRes}x{vRes}";
                        refreshRate = hz;
                    }
                }

                profile = profile with
                {
                    MonitorCount = monitorCount,
                    PrimaryResolution = primaryRes,
                    RefreshRateHz = refreshRate
                };
            }
            catch { /* Display info unavailable */ }

            // ─── Pagefile / Virtual Memory ───
            try
            {
                using var pfSearcher = new ManagementObjectSearcher(
                    "SELECT AllocatedBaseSize, CurrentUsage FROM Win32_PageFileUsage");
                foreach (var obj in pfSearcher.Get())
                {
                    var allocated = long.TryParse(obj["AllocatedBaseSize"]?.ToString(), out var a) ? a : 0;
                    var used = long.TryParse(obj["CurrentUsage"]?.ToString(), out var u) ? u : 0;
                    profile = profile with
                    {
                        PagefileSizeMB = allocated,
                        PagefileFreeSpaceMB = allocated - used
                    };
                    break;
                }
            }
            catch { /* Pagefile info unavailable */ }

            // ─── Antivirus Product ───
            try
            {
                using var avSearcher = new ManagementObjectSearcher(
                    @"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
                foreach (var obj in avSearcher.Get())
                {
                    var name = obj["displayName"]?.ToString() ?? "";
                    var state = uint.TryParse(obj["productState"]?.ToString(), out var ps) ? ps : 0;
                    var enabled = ((state >> 12) & 0xF) == 1; // Bit 12-15: enabled flag

                    profile = profile with
                    {
                        AntivirusProduct = name,
                        AntivirusEnabled = enabled
                    };
                    break; // First (primary) AV only
                }
            }
            catch { /* SecurityCenter unavailable on servers */ }

            // ─── Boot Type ───
            try
            {
                // Check firmware type via registry
                using var fwKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                var bootType = fwKey != null ? "UEFI" : "Legacy";
                // More reliable check
                var fwType = GetWmi("Win32_ComputerSystem", "BootupState");
                profile = profile with { BootType = bootType };
            }
            catch { profile = profile with { BootType = "Unknown" }; }

            // ─── Network Connection Type ───
            try
            {
                var netType = "Unknown";
                using var netSearcher = new ManagementObjectSearcher(
                    "SELECT NetConnectionID, NetConnectionStatus FROM Win32_NetworkAdapter " +
                    "WHERE NetConnectionStatus=2"); // 2 = Connected
                foreach (var obj in netSearcher.Get())
                {
                    var connId = obj["NetConnectionID"]?.ToString() ?? "";
                    if (connId.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) ||
                        connId.Contains("Wireless", StringComparison.OrdinalIgnoreCase))
                    {
                        netType = "WiFi"; break;
                    }
                    else if (connId.Contains("Ethernet", StringComparison.OrdinalIgnoreCase) ||
                             connId.Contains("Local Area", StringComparison.OrdinalIgnoreCase))
                    {
                        netType = "Ethernet"; break;
                    }
                }
                profile = profile with { NetworkType = netType };
            }
            catch { /* Network type unavailable */ }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "System fingerprint capture partially failed");
        }

        return profile;
    }

    // ─── First-Install System Baseline ────────────────────────────────────

    /// <summary>
    /// Captures a comprehensive system baseline on first install.
    /// This is the "day zero" snapshot — everything we can learn about
    /// the system before LogicFlow starts optimizing it.
    /// </summary>
    public SystemBaseline CaptureBaseline(string appVersion = "1.0.0")
    {
        _logger?.LogInformation("Capturing first-install system baseline");

        var baseline = new SystemBaseline
        {
            InstallId = GetInstallId(),
            AppVersion = appVersion,
            System = Capture(),
            Bios = CaptureBiosInfo(),
            ErrorHistory = CaptureErrorHistory(),
        };

        // Services
        try
        {
            var services = CaptureServices();
            baseline = baseline with
            {
                Services = services,
                TotalServiceCount = services.Count,
                RunningServiceCount = services.Count(s => s.Status == "Running"),
                StoppedServiceCount = services.Count(s => s.Status == "Stopped"),
            };
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Baseline: service capture failed"); }

        // Problem devices
        try { baseline = baseline with { ProblemDevices = CaptureProblemDevices() }; }
        catch (Exception ex) { _logger?.LogDebug(ex, "Baseline: problem device capture failed"); }

        // Hotfixes
        try { baseline = baseline with { Hotfixes = CaptureHotfixes() }; }
        catch (Exception ex) { _logger?.LogDebug(ex, "Baseline: hotfix capture failed"); }

        // Memory slots
        try { baseline = baseline with { MemorySlots = CaptureMemorySlots() }; }
        catch (Exception ex) { _logger?.LogDebug(ex, "Baseline: memory slot capture failed"); }

        // Storage controllers
        try { baseline = baseline with { StorageControllers = CaptureStorageControllers() }; }
        catch (Exception ex) { _logger?.LogDebug(ex, "Baseline: storage controller capture failed"); }

        _logger?.LogInformation(
            "Baseline captured: {Services} services, {Problems} problem devices, {Hotfixes} hotfixes, {Slots} RAM slots",
            baseline.TotalServiceCount, baseline.ProblemDevices.Count,
            baseline.Hotfixes.Count, baseline.MemorySlots.Count);

        return baseline;
    }

    // ─── Baseline Sub-Collectors ─────────────────────────────────────────

    private BiosInfo CaptureBiosInfo()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SMBIOSMajorVersion, SMBIOSMinorVersion FROM Win32_BIOS");
            foreach (var obj in searcher.Get())
            {
                var releaseDate = obj["ReleaseDate"]?.ToString() ?? "";
                // WMI dates: "20241015000000.000000+000" → "10/15/2024"
                if (releaseDate.Length >= 8)
                {
                    try
                    {
                        var dt = ManagementDateTimeConverter.ToDateTime(releaseDate);
                        releaseDate = dt.ToString("yyyy-MM-dd");
                    }
                    catch { /* Keep raw string */ }
                }

                var major = int.TryParse(obj["SMBIOSMajorVersion"]?.ToString(), out var mj) ? mj : 0;
                var minor = int.TryParse(obj["SMBIOSMinorVersion"]?.ToString(), out var mn) ? mn : 0;

                // UEFI detection via registry (more reliable than WMI)
                var isUefi = false;
                try
                {
                    using var fwKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                    isUefi = fwKey != null;
                }
                catch { }

                return new BiosInfo
                {
                    Manufacturer = obj["Manufacturer"]?.ToString()?.Trim() ?? "",
                    Version = obj["SMBIOSBIOSVersion"]?.ToString()?.Trim() ?? "",
                    ReleaseDate = releaseDate,
                    SmbiosVersion = $"{major}.{minor}",
                    IsUefi = isUefi,
                };
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "BIOS info capture failed"); }
        return new BiosInfo();
    }

    private List<ServiceSnapshot> CaptureServices()
    {
        var services = new List<ServiceSnapshot>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, StartMode FROM Win32_Service");
            foreach (var obj in searcher.Get())
            {
                services.Add(new ServiceSnapshot
                {
                    Name = obj["Name"]?.ToString() ?? "",
                    DisplayName = obj["DisplayName"]?.ToString() ?? "",
                    Status = obj["State"]?.ToString() ?? "",
                    StartMode = obj["StartMode"]?.ToString() ?? "",
                });
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Service capture failed"); }
        return services;
    }

    private List<ProblemDevice> CaptureProblemDevices()
    {
        var problems = new List<ProblemDevice>();
        try
        {
            // ConfigManagerErrorCode != 0 means the device has problems
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DeviceID, PNPClass, ConfigManagerErrorCode FROM Win32_PnPEntity " +
                "WHERE ConfigManagerErrorCode != 0");
            foreach (var obj in searcher.Get())
            {
                var errorCode = int.TryParse(obj["ConfigManagerErrorCode"]?.ToString(), out var ec) ? ec : 0;
                problems.Add(new ProblemDevice
                {
                    Name = obj["Name"]?.ToString() ?? "",
                    HardwareId = obj["DeviceID"]?.ToString() ?? "",
                    DeviceClass = obj["PNPClass"]?.ToString() ?? "",
                    ErrorCode = errorCode,
                    ErrorDescription = GetConfigManagerErrorDescription(errorCode),
                });
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Problem device capture failed"); }
        return problems;
    }

    private List<HotfixEntry> CaptureHotfixes()
    {
        var hotfixes = new List<HotfixEntry>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
            foreach (var obj in searcher.Get())
            {
                var installedOn = obj["InstalledOn"] is string dateStr &&
                                  DateTimeOffset.TryParse(dateStr, out var dt)
                    ? dt : (DateTimeOffset?)null;

                hotfixes.Add(new HotfixEntry
                {
                    HotfixId = obj["HotFixID"]?.ToString() ?? "",
                    Description = obj["Description"]?.ToString() ?? "",
                    InstalledOn = installedOn,
                });
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Hotfix capture failed"); }
        return hotfixes;
    }

    private ErrorHistorySummary CaptureErrorHistory()
    {
        int appErrors = 0, appHangs = 0, blueScreens = 0;
        var crashCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-30);

            // Read Windows Reliability records (Win32_ReliabilityRecords)
            using var searcher = new ManagementObjectSearcher(
                "SELECT EventIdentifier, SourceName, ProductName, TimeGenerated " +
                "FROM Win32_ReliabilityRecords");
            foreach (var obj in searcher.Get())
            {
                var timeStr = obj["TimeGenerated"]?.ToString();
                if (timeStr == null) continue;

                try
                {
                    var recordTime = ManagementDateTimeConverter.ToDateTime(timeStr);
                    if (recordTime < cutoff) continue;
                }
                catch { continue; }

                var sourceName = obj["SourceName"]?.ToString() ?? "";
                var productName = obj["ProductName"]?.ToString() ?? "";

                if (sourceName.Contains("Application Error", StringComparison.OrdinalIgnoreCase))
                {
                    appErrors++;
                    // Track by app name (filename only, no path)
                    var appName = Path.GetFileName(productName);
                    if (!string.IsNullOrEmpty(appName))
                    {
                        crashCounts.TryGetValue(appName, out var count);
                        crashCounts[appName] = count + 1;
                    }
                }
                else if (sourceName.Contains("Application Hang", StringComparison.OrdinalIgnoreCase))
                {
                    appHangs++;
                }
                else if (sourceName.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
                         sourceName.Contains("BlueScreen", StringComparison.OrdinalIgnoreCase))
                {
                    blueScreens++;
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Error history capture failed — may need admin");
        }

        var topCrasher = crashCounts.OrderByDescending(kv => kv.Value).FirstOrDefault();

        return new ErrorHistorySummary
        {
            AppErrorsLast30Days = appErrors,
            AppHangsLast30Days = appHangs,
            BlueScreensLast30Days = blueScreens,
            TopCrashingApp = topCrasher.Key ?? "",
            TopCrashingAppCount = topCrasher.Value,
        };
    }

    private List<MemorySlot> CaptureMemorySlots()
    {
        var slots = new List<MemorySlot>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceLocator, Capacity, Speed, MemoryType, SMBIOSMemoryType, Manufacturer " +
                "FROM Win32_PhysicalMemory");
            foreach (var obj in searcher.Get())
            {
                var capacity = long.TryParse(obj["Capacity"]?.ToString(), out var cap) ? cap / (1024 * 1024) : 0;
                var speed = int.TryParse(obj["Speed"]?.ToString(), out var spd) ? spd : 0;
                var smbiosType = int.TryParse(obj["SMBIOSMemoryType"]?.ToString(), out var st) ? st : 0;

                slots.Add(new MemorySlot
                {
                    Slot = obj["DeviceLocator"]?.ToString() ?? "",
                    CapacityMB = capacity,
                    SpeedMHz = speed,
                    MemoryType = MapMemoryType(smbiosType),
                    Manufacturer = obj["Manufacturer"]?.ToString()?.Trim() ?? "",
                });
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Memory slot capture failed"); }
        return slots;
    }

    private List<string> CaptureStorageControllers()
    {
        var controllers = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name FROM Win32_SCSIController");
            foreach (var obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(name)) controllers.Add(name);
            }

            // Also check IDE controllers
            using var ideSearcher = new ManagementObjectSearcher(
                "SELECT Name FROM Win32_IDEController");
            foreach (var obj in ideSearcher.Get())
            {
                var name = obj["Name"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(name)) controllers.Add(name);
            }
        }
        catch (Exception ex) { _logger?.LogDebug(ex, "Storage controller capture failed"); }
        return controllers;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private static string GetConfigManagerErrorDescription(int code) => code switch
    {
        1 => "Device not configured correctly",
        3 => "Driver corrupted",
        10 => "Device cannot start",
        12 => "Not enough resources",
        14 => "Device requires restart",
        16 => "Cannot identify all resources",
        18 => "Reinstall drivers",
        19 => "Registry problem",
        21 => "Windows is removing device",
        22 => "Device disabled",
        24 => "Device not present",
        28 => "Drivers not installed",
        29 => "Device disabled by firmware",
        31 => "Device not working properly",
        32 => "Driver service disabled",
        33 => "Cannot determine resources required",
        34 => "Cannot determine resources required",
        35 => "System firmware insufficient resources",
        36 => "IRQ conflict",
        37 => "Cannot initialize driver",
        38 => "Driver blocked (previously crashed)",
        39 => "Driver corrupted or missing",
        40 => "Registration info in registry bad",
        41 => "System error",
        42 => "Another device using resources",
        43 => "Windows stopped device (reported problems)",
        44 => "Hardware reported problems",
        45 => "Device not connected",
        46 => "OS is shutting down",
        47 => "Eject pending",
        48 => "Firmware blocked start",
        49 => "System hive too large",
        50 => "Cannot apply properties from driver store",
        51 => "Device waiting on another device",
        52 => "Cannot verify digital signature",
        _ => $"Error code {code}"
    };

    private static string MapMemoryType(int smbiosType) => smbiosType switch
    {
        20 => "DDR",
        21 => "DDR2",
        22 => "DDR2 FB-DIMM",
        24 => "DDR3",
        26 => "DDR4",
        30 => "LPDDR4",
        34 => "DDR5",
        35 => "LPDDR5",
        _ => smbiosType > 0 ? $"Type-{smbiosType}" : "Unknown"
    };

    private string GetWmi(string cls, string prop)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
            foreach (var obj in searcher.Get())
            {
                var val = obj[prop];
                if (val is string s) return s.Trim();
                if (val is ushort[] arr) return string.Join(",", arr);
                return val?.ToString()?.Trim() ?? "";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "WMI query {Class}.{Prop} failed", cls, prop);
        }
        return "";
    }

    private string DetectDiskType()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\microsoft\windows\storage");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT MediaType FROM MSFT_PhysicalDisk"));
            foreach (var obj in searcher.Get())
            {
                return obj["MediaType"]?.ToString() switch
                {
                    "3" => "HDD",
                    "4" => "SSD",
                    _ => "Unknown"
                };
            }
        }
        catch
        {
            // Fallback: check if system drive has no seek penalty
            try
            {
                using var searcher2 = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_DiskDrive WHERE Index=0");
                foreach (var obj in searcher2.Get())
                {
                    var mediaType = obj["MediaType"]?.ToString() ?? "";
                    if (mediaType.Contains("SSD", StringComparison.OrdinalIgnoreCase) ||
                        mediaType.Contains("Solid", StringComparison.OrdinalIgnoreCase))
                        return "SSD";
                    return "HDD";
                }
            }
            catch { }
        }
        return "Unknown";
    }
}
