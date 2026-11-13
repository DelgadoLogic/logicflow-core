// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – DriverAuditorEngine
// Audits installed PnP system drivers, detects device hardware errors, and
// checks for unsigned or outdated drivers via WMI/PnP APIs and SetupAPI fallbacks.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian;

/// <summary>
/// Scans system drivers and hardware devices to detect errors, unsigned drivers, and driver diagnostics.
/// </summary>
public sealed class DriverAuditorEngine
{
    private readonly ILogger<DriverAuditorEngine>? _logger;

    public DriverAuditorEngine(ILogger<DriverAuditorEngine>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public sealed class DeviceDriverInfo
    {
        private readonly bool? _isOutdated;

        public string DeviceName { get; init; } = "";
        public string Manufacturer { get; init; } = "";
        public string DriverVersion { get; init; } = "";
        public string DriverDate { get; init; } = "";
        public string HardwareId { get; init; } = "";
        public bool IsSigned { get; init; }
        public string Signer { get; init; } = "";
        public int ConfigManagerErrorCode { get; init; }
        public string DeviceClass { get; init; } = "";
        public string DeviceId { get; init; } = "";
        public string InfName { get; init; } = "";
        public string AvailableVersion { get; init; } = "";
        public string AvailableDate { get; init; } = "";
        public string Category { get; init; } = "";
        public bool IsIgnored { get; set; }
        public bool IsSelected { get; set; } = true;
        public bool IsPhysicalHardware { get; init; } = true;

        public bool HasError => ConfigManagerErrorCode != 0;

        public bool IsOutdated
        {
            get
            {
                if (IsIgnored) return false;
                if (_isOutdated.HasValue) return _isOutdated.Value;
                if (DriverAuditorEngine.IsInboxDriver(Manufacturer, Signer, DriverDate, DeviceClass, DeviceName, HardwareId))
                    return false;
                if (!string.IsNullOrEmpty(AvailableVersion) && !string.IsNullOrEmpty(DriverVersion))
                {
                    if (DriverAuditorEngine.IsNewerVersion(DriverVersion, AvailableVersion))
                        return true;
                }
                return DriverAuditorEngine.IsDateOutdated(DriverDate);
            }
            init => _isOutdated = value;
        }

        public string StatusDescription
        {
            get
            {
                if (HasError) return DriverAuditorEngine.GetErrorCodeDescription(ConfigManagerErrorCode);
                if (IsIgnored) return "Excluded / Frozen";
                if (!IsSigned) return "Unsigned Driver";
                if (IsOutdated) return "Outdated Driver";
                return "OK";
            }
        }
    }

    public sealed class DriverAuditReport
    {
        public List<DeviceDriverInfo> Drivers { get; init; } = new();
        public int TotalDrivers => Drivers.Count;
        public int UpToDateCount => Drivers.Count(d => !d.IsOutdated && !d.HasError && d.IsSigned && !d.IsIgnored);
        public int OutdatedCount => Drivers.Count(d => d.IsOutdated && !d.IsIgnored);
        public int UnsignedCount => Drivers.Count(d => !d.IsSigned && !d.IsIgnored);
        public int ProblemDeviceCount => Drivers.Count(d => d.HasError && !d.IsIgnored);
        public int IgnoredCount => Drivers.Count(d => d.IsIgnored);
        public int HealthScore => DriverAuditorEngine.CalculateHealthScore(TotalDrivers, OutdatedCount, UnsignedCount, ProblemDeviceCount);
    }

    public sealed class DriverStatusSummary
    {
        public int Total { get; init; }
        public int UpToDate { get; init; }
        public int Outdated { get; init; }
        public int Unsigned { get; init; }
        public int ErrorCount { get; init; }
        public int IgnoredCount { get; init; }
        public int HealthScore { get; init; }
    }

    // ─── Core API ────────────────────────────────────────────────────────

    /// <summary>
    /// Audits installed PnP device drivers on the machine using WMI and SetupAPI fallbacks.
    /// By default filters out Windows inbox devices, virtual software devices, and ACPI root containers
    /// to audit physical OEM hardware drivers only (GPU, Chipset, Audio, Wi-Fi, Bluetooth, Network, Storage).
    /// </summary>
    public DriverAuditReport AuditDrivers(bool physicalHardwareOnly = true)
    {
        _logger?.LogInformation("Auditing physical OEM device drivers via WMI...");
        var driverList = new List<DeviceDriverInfo>();

        try
        {
            driverList = QueryWmiDrivers(physicalHardwareOnly);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "WMI Win32_PnPSignedDriver query failed. Falling back to SetupAPI.");
        }

        // If WMI produced no devices or threw, trigger SetupAPI fallback
        if (driverList.Count == 0)
        {
            _logger?.LogInformation("Executing SetupAPI driver fallback scanner...");
            try
            {
                var setupApiDrivers = QuerySetupApiDrivers(physicalHardwareOnly);
                if (setupApiDrivers.Count > 0)
                {
                    driverList = setupApiDrivers;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "SetupAPI driver enumeration failed.");
            }
        }

        _logger?.LogInformation(
            "Driver audit complete. Audited {Count} drivers ({Problem} problem devices, {Outdated} outdated, {Unsigned} unsigned).",
            driverList.Count,
            driverList.Count(d => d.HasError),
            driverList.Count(d => d.IsOutdated),
            driverList.Count(d => !d.IsSigned));

        return new DriverAuditReport
        {
            Drivers = driverList.OrderBy(d => d.DeviceName, StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    /// <summary>
    /// Returns summary metrics (total, upToDate, outdated, unsigned, errorCount, healthScore).
    /// </summary>
    public DriverStatusSummary CheckDriverStatus(DriverAuditReport? report = null)
    {
        report ??= AuditDrivers();
        return new DriverStatusSummary
        {
            Total = report.TotalDrivers,
            UpToDate = report.UpToDateCount,
            Outdated = report.OutdatedCount,
            Unsigned = report.UnsignedCount,
            ErrorCount = report.ProblemDeviceCount,
            IgnoredCount = report.IgnoredCount,
            HealthScore = report.HealthScore
        };
    }

    /// <summary>
    /// Exports driver inventory to JSON or CSV.
    /// </summary>
    public string ExportDriverReport(string filePath, string format = "json", DriverAuditReport? report = null)
    {
        report ??= AuditDrivers();

        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path must not be null or empty.", nameof(filePath));

        var fullPath = Path.GetFullPath(filePath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        bool isCsv = string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase)
            || (!string.Equals(format, "json", StringComparison.OrdinalIgnoreCase) && fullPath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase));

        if (isCsv)
        {
            var sb = new StringBuilder();
            sb.AppendLine("DeviceName,Manufacturer,DriverVersion,DriverDate,HardwareId,IsSigned,Signer,ConfigManagerErrorCode,HasError,IsOutdated,StatusDescription");
            foreach (var d in report.Drivers)
            {
                sb.AppendLine(string.Join(",",
                    EscapeCsv(d.DeviceName),
                    EscapeCsv(d.Manufacturer),
                    EscapeCsv(d.DriverVersion),
                    EscapeCsv(d.DriverDate),
                    EscapeCsv(d.HardwareId),
                    d.IsSigned.ToString().ToLowerInvariant(),
                    EscapeCsv(d.Signer),
                    d.ConfigManagerErrorCode,
                    d.HasError.ToString().ToLowerInvariant(),
                    d.IsOutdated.ToString().ToLowerInvariant(),
                    EscapeCsv(d.StatusDescription)
                ));
            }
            File.WriteAllText(fullPath, sb.ToString(), Encoding.UTF8);
        }
        else
        {
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(fullPath, json, Encoding.UTF8);
        }

        _logger?.LogInformation("Exported driver report with {Count} drivers to {Path} ({Format})",
            report.TotalDrivers, fullPath, isCsv ? "csv" : "json");

        return fullPath;
    }

    // ─── WMI Driver Scanner ──────────────────────────────────────────────

    private List<DeviceDriverInfo> QueryWmiDrivers(bool physicalHardwareOnly = true)
    {
        var driverList = new List<DeviceDriverInfo>();
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ignoredSet = LoadIgnoredDrivers();

        using (var searcher = new ManagementObjectSearcher(
            @"SELECT DeviceName, Manufacturer, DriverVersion, DriverDate, HardWareID, IsSigned, Signer, ConfigManagerErrorCode, DeviceClass, InfName, DeviceID FROM Win32_PnPSignedDriver"))
        using (var results = searcher.Get())
        {
            foreach (ManagementObject obj in results.Cast<ManagementObject>())
            {
                try
                {
                    var name = obj["DeviceName"]?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    var mfr = obj["Manufacturer"]?.ToString() ?? "";
                    var ver = obj["DriverVersion"]?.ToString() ?? "";
                    var rawDate = obj["DriverDate"]?.ToString() ?? "";
                    var hwid = obj["HardWareID"]?.ToString() ?? "";
                    var isSigned = Convert.ToBoolean(obj["IsSigned"] ?? false);
                    var signer = obj["Signer"]?.ToString() ?? "";
                    var errCode = Convert.ToInt32(obj["ConfigManagerErrorCode"] ?? 0);
                    var devClass = obj["DeviceClass"]?.ToString() ?? "";
                    var infName = obj["InfName"]?.ToString() ?? "";
                    var devId = obj["DeviceID"]?.ToString() ?? hwid;

                    if (physicalHardwareOnly && !IsPhysicalOemHardware(name, mfr, devClass, hwid, devId, errCode))
                        continue;

                    var formattedDate = FormatDriverDate(rawDate);
                    var category = DetectCategory(name, devClass);
                    var (targetVer, targetDate) = GetTargetVersion(name, mfr, category, hwid);
                    bool isIgnored = ignoredSet.Contains(hwid) || ignoredSet.Contains(devId) || ignoredSet.Contains(name);

                    bool isOutdated = false;
                    if (!isIgnored)
                    {
                        if (!string.IsNullOrEmpty(targetVer) && !string.IsNullOrEmpty(ver) && IsNewerVersion(ver, targetVer))
                        {
                            isOutdated = true;
                        }
                        else if (!IsInboxDriver(mfr, signer, formattedDate, devClass, name, hwid))
                        {
                            isOutdated = IsDateOutdated(formattedDate);
                        }
                    }

                    var info = new DeviceDriverInfo
                    {
                        DeviceName = name,
                        Manufacturer = mfr,
                        DriverVersion = ver,
                        DriverDate = formattedDate,
                        HardwareId = hwid,
                        IsSigned = isSigned,
                        Signer = signer,
                        ConfigManagerErrorCode = errCode,
                        DeviceClass = devClass,
                        DeviceId = devId,
                        InfName = infName,
                        AvailableVersion = targetVer,
                        AvailableDate = targetDate,
                        Category = category,
                        IsIgnored = isIgnored,
                        IsSelected = !isIgnored && (isOutdated || errCode > 0 || !isSigned),
                        IsOutdated = isOutdated,
                        IsPhysicalHardware = true
                    };

                    driverList.Add(info);
                    if (!string.IsNullOrEmpty(devId)) seenIds.Add(devId);
                    if (!string.IsNullOrEmpty(name)) seenIds.Add(name);
                }
                catch { }
            }
        }

        // Additional check: Detect problem devices from Win32_PnPEntity that might lack installed drivers (e.g. Code 28)
        try
        {
            using var problemSearcher = new ManagementObjectSearcher(
                @"SELECT Name, Manufacturer, DeviceID, ConfigManagerErrorCode, HardwareID, Service FROM Win32_PnPEntity WHERE ConfigManagerErrorCode > 0");
            using var problemResults = problemSearcher.Get();

            foreach (ManagementObject pObj in problemResults.Cast<ManagementObject>())
            {
                try
                {
                    var name = pObj["Name"]?.ToString();
                    var devId = pObj["DeviceID"]?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    if (!seenIds.Contains(devId) && !seenIds.Contains(name))
                    {
                        var mfr = pObj["Manufacturer"]?.ToString() ?? "";
                        var errCode = Convert.ToInt32(pObj["ConfigManagerErrorCode"] ?? 0);
                        var hwids = pObj["HardwareID"] as string[];
                        var hwid = (hwids != null && hwids.Length > 0) ? hwids[0] : "";

                        bool isIgnored = ignoredSet.Contains(hwid) || ignoredSet.Contains(devId) || ignoredSet.Contains(name);

                        driverList.Add(new DeviceDriverInfo
                        {
                            DeviceName = name,
                            Manufacturer = mfr,
                            DriverVersion = "Unknown",
                            DriverDate = "",
                            HardwareId = hwid,
                            IsSigned = false,
                            Signer = "None",
                            ConfigManagerErrorCode = errCode,
                            DeviceId = devId,
                            Category = DetectCategory(name, ""),
                            IsIgnored = isIgnored,
                            IsSelected = !isIgnored,
                            IsOutdated = false,
                            IsPhysicalHardware = true
                        });

                        seenIds.Add(devId);
                        seenIds.Add(name);
                    }
                }
                catch { }
            }
        }
        catch { }

        return driverList;
    }

    // ─── SetupAPI Driver Fallback ────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    private const int DIGCF_PRESENT = 0x00000002;
    private const int DIGCF_ALLCLASSES = 0x00000004;

    private const int SPDRP_DEVICEDESC = 0x00000000;
    private const int SPDRP_HARDWAREID = 0x00000001;
    private const int SPDRP_CLASS = 0x00000007;
    private const int SPDRP_DRIVER = 0x00000009;
    private const int SPDRP_MFG = 0x0000000B;
    private const int SPDRP_FRIENDLYNAME = 0x0000000C;

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr SetupDiGetClassDevs(
        IntPtr classGuid,
        string? enumerator,
        IntPtr hwndParent,
        int flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(
        IntPtr deviceInfoSet,
        int memberIndex,
        ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr deviceInfoSet,
        ref SP_DEVINFO_DATA deviceInfoData,
        int property,
        out int propertyRegDataType,
        byte[] propertyBuffer,
        int propertyBufferSize,
        out int requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("cfgmgr32.dll", SetLastError = true)]
    private static extern int CM_Get_DevNode_Status(
        out int status,
        out int problemNumber,
        int devInst,
        int flags);

    /// <summary>
    /// Enumerates system devices and drivers directly using Windows SetupAPI and CfgMgr32.
    /// Used when WMI is unavailable or returns empty datasets.
    /// </summary>
    public List<DeviceDriverInfo> QuerySetupApiDrivers(bool physicalHardwareOnly = true)
    {
        var list = new List<DeviceDriverInfo>();
        IntPtr hDevInfo = IntPtr.Zero;
        var ignoredSet = LoadIgnoredDrivers();

        try
        {
            hDevInfo = SetupDiGetClassDevs(IntPtr.Zero, null, IntPtr.Zero, DIGCF_ALLCLASSES | DIGCF_PRESENT);
            if (hDevInfo == IntPtr.Zero || hDevInfo == new IntPtr(-1))
            {
                return QueryRegistryFallbackDrivers(physicalHardwareOnly);
            }

            var devInfo = new SP_DEVINFO_DATA();
            devInfo.cbSize = Marshal.SizeOf<SP_DEVINFO_DATA>();

            for (int i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, ref devInfo); i++)
            {
                try
                {
                    string name = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_FRIENDLYNAME);
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        name = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_DEVICEDESC);
                    }
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    string mfr = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_MFG);
                    string hwid = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_HARDWAREID);
                    string devClass = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_CLASS);
                    string driverKey = GetDevicePropertyString(hDevInfo, ref devInfo, SPDRP_DRIVER);

                    int problemCode = 0;
                    if (CM_Get_DevNode_Status(out _, out int prob, devInfo.DevInst, 0) == 0)
                    {
                        problemCode = prob;
                    }

                    if (physicalHardwareOnly && !IsPhysicalOemHardware(name, mfr, devClass, hwid, hwid, problemCode))
                        continue;

                    string version = "";
                    string dateStr = "";
                    string signer = "";
                    bool isSigned = false;

                    if (!string.IsNullOrEmpty(driverKey))
                    {
                        ReadDriverRegistryDetails(driverKey, out version, out dateStr, out signer, out isSigned);
                    }

                    var formattedDate = FormatDriverDate(dateStr);
                    var category = DetectCategory(name, devClass);
                    var (targetVer, targetDate) = GetTargetVersion(name, mfr, category, hwid);
                    bool isIgnored = ignoredSet.Contains(hwid) || ignoredSet.Contains(name);

                    bool isOutdated = false;
                    if (!isIgnored)
                    {
                        if (!string.IsNullOrEmpty(targetVer) && !string.IsNullOrEmpty(version) && IsNewerVersion(version, targetVer))
                        {
                            isOutdated = true;
                        }
                        else if (!IsInboxDriver(mfr, signer, formattedDate, devClass, name, hwid))
                        {
                            isOutdated = IsDateOutdated(formattedDate);
                        }
                    }

                    list.Add(new DeviceDriverInfo
                    {
                        DeviceName = name,
                        Manufacturer = mfr,
                        DriverVersion = version,
                        DriverDate = formattedDate,
                        HardwareId = hwid,
                        IsSigned = isSigned,
                        Signer = signer,
                        ConfigManagerErrorCode = problemCode,
                        DeviceClass = devClass,
                        DeviceId = hwid,
                        AvailableVersion = targetVer,
                        AvailableDate = targetDate,
                        Category = category,
                        IsIgnored = isIgnored,
                        IsSelected = !isIgnored && (isOutdated || problemCode > 0 || !isSigned),
                        IsOutdated = isOutdated,
                        IsPhysicalHardware = true
                    });
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "SetupAPI enumeration threw exception, attempting registry scan");
            return QueryRegistryFallbackDrivers(physicalHardwareOnly);
        }
        finally
        {
            if (hDevInfo != IntPtr.Zero && hDevInfo != new IntPtr(-1))
            {
                SetupDiDestroyDeviceInfoList(hDevInfo);
            }
        }

        return list;
    }

    private static string GetDevicePropertyString(IntPtr hDevInfo, ref SP_DEVINFO_DATA devInfo, int property)
    {
        byte[] buffer = new byte[1024];
        if (SetupDiGetDeviceRegistryProperty(hDevInfo, ref devInfo, property, out _, buffer, buffer.Length, out int requiredSize))
        {
            int len = requiredSize > 0 ? requiredSize : buffer.Length;
            return Encoding.Unicode.GetString(buffer, 0, len).TrimEnd('\0');
        }
        return "";
    }

    private static void ReadDriverRegistryDetails(
        string driverKey,
        out string version,
        out string dateStr,
        out string signer,
        out bool isSigned)
    {
        version = "";
        dateStr = "";
        signer = "";
        isSigned = false;

        try
        {
            string fullSubKey = $@"SYSTEM\CurrentControlSet\Control\Class\{driverKey}";
            using var key = Registry.LocalMachine.OpenSubKey(fullSubKey);
            if (key != null)
            {
                version = key.GetValue("DriverVersion")?.ToString() ?? "";
                dateStr = key.GetValue("DriverDate")?.ToString() ?? "";
                var provider = key.GetValue("ProviderName")?.ToString() ?? "";

                var digitalSigner = key.GetValue("DigitalSigner")?.ToString();
                var signerScore = key.GetValue("SignerScore");

                if (!string.IsNullOrEmpty(digitalSigner))
                {
                    signer = digitalSigner;
                    isSigned = true;
                }
                else if (signerScore != null || !string.IsNullOrWhiteSpace(provider))
                {
                    signer = provider;
                    isSigned = !string.Equals(provider, "Unknown", StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Direct fallback scanning HKLM\SYSTEM\CurrentControlSet\Enum if both WMI and SetupAPI are blocked.
    /// </summary>
    private static List<DeviceDriverInfo> QueryRegistryFallbackDrivers(bool physicalHardwareOnly = true)
    {
        var list = new List<DeviceDriverInfo>();
        var ignoredSet = LoadIgnoredDrivers();

        try
        {
            using var enumKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum");
            if (enumKey == null) return list;

            foreach (var busName in enumKey.GetSubKeyNames().Take(10))
            {
                using var busKey = enumKey.OpenSubKey(busName);
                if (busKey == null) continue;

                foreach (var devName in busKey.GetSubKeyNames().Take(20))
                {
                    using var devKey = busKey.OpenSubKey(devName);
                    if (devKey == null) continue;

                    foreach (var instName in devKey.GetSubKeyNames().Take(5))
                    {
                        using var instKey = devKey.OpenSubKey(instName);
                        if (instKey == null) continue;

                        var desc = instKey.GetValue("DeviceDesc")?.ToString() ?? instKey.GetValue("FriendlyName")?.ToString();
                        if (string.IsNullOrWhiteSpace(desc)) continue;

                        // Clean up INF description syntax like "@oem.inf,%Device%;Device Name"
                        if (desc.Contains(';')) desc = desc[(desc.LastIndexOf(';') + 1)..].Trim();

                        var mfr = instKey.GetValue("Mfg")?.ToString() ?? "";
                        if (mfr.Contains(';')) mfr = mfr[(mfr.LastIndexOf(';') + 1)..].Trim();

                        var driverKey = instKey.GetValue("Driver")?.ToString() ?? "";
                        var hwid = instKey.GetValue("HardwareID") as string[] ?? Array.Empty<string>();
                        string firstHwid = hwid.Length > 0 ? hwid[0] : "";

                        if (physicalHardwareOnly && !IsPhysicalOemHardware(desc, mfr, "", firstHwid, firstHwid, 0))
                            continue;

                        string version = "";
                        string dateStr = "";
                        string signer = "";
                        bool isSigned = false;

                        if (!string.IsNullOrEmpty(driverKey))
                        {
                            ReadDriverRegistryDetails(driverKey, out version, out dateStr, out signer, out isSigned);
                        }

                        var formattedDate = FormatDriverDate(dateStr);
                        var category = DetectCategory(desc, "");
                        var (targetVer, targetDate) = GetTargetVersion(desc, mfr, category, firstHwid);
                        bool isIgnored = ignoredSet.Contains(firstHwid) || ignoredSet.Contains(desc);

                        bool isOutdated = false;
                        if (!isIgnored)
                        {
                            if (!string.IsNullOrEmpty(targetVer) && !string.IsNullOrEmpty(version) && IsNewerVersion(version, targetVer))
                            {
                                isOutdated = true;
                            }
                            else if (!IsInboxDriver(mfr, signer, formattedDate, "", desc, firstHwid))
                            {
                                isOutdated = IsDateOutdated(formattedDate);
                            }
                        }

                        list.Add(new DeviceDriverInfo
                        {
                            DeviceName = desc,
                            Manufacturer = mfr,
                            DriverVersion = version,
                            DriverDate = formattedDate,
                            HardwareId = firstHwid,
                            IsSigned = isSigned,
                            Signer = signer,
                            ConfigManagerErrorCode = 0,
                            AvailableVersion = targetVer,
                            AvailableDate = targetDate,
                            Category = category,
                            IsIgnored = isIgnored,
                            IsSelected = !isIgnored && isOutdated,
                            IsOutdated = isOutdated,
                            IsPhysicalHardware = true
                        });
                    }
                }
            }
        }
        catch { }

        return list;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Determines whether a driver date is older than 2 years or older than reference points.
    /// </summary>
    public static bool IsDateOutdated(string driverDate, DateTime? referenceDate = null)
    {
        if (string.IsNullOrWhiteSpace(driverDate)) return false;

        DateTime now = referenceDate ?? DateTime.Now;
        DateTime cutoff = now.AddYears(-2);

        if (TryParseDriverDate(driverDate, out var date))
        {
            return date < cutoff;
        }

        return false;
    }

    /// <summary>
    /// Robust parsing for WMI CIM_DATETIME or standard date strings.
    /// </summary>
    public static bool TryParseDriverDate(string rawDate, out DateTime parsed)
    {
        parsed = default;
        if (string.IsNullOrWhiteSpace(rawDate)) return false;

        rawDate = rawDate.Trim();

        // 1. WMI CIM_DATETIME (e.g. 20210515000000.000000-000 or 20210515******)
        if (rawDate.Length >= 8 &&
            char.IsDigit(rawDate[0]) && char.IsDigit(rawDate[1]) && char.IsDigit(rawDate[2]) && char.IsDigit(rawDate[3]) &&
            char.IsDigit(rawDate[4]) && char.IsDigit(rawDate[5]) && char.IsDigit(rawDate[6]) && char.IsDigit(rawDate[7]))
        {
            if (int.TryParse(rawDate[..4], out int year) &&
                int.TryParse(rawDate[4..6], out int month) &&
                int.TryParse(rawDate[6..8], out int day))
            {
                try
                {
                    parsed = new DateTime(year, month, day);
                    return true;
                }
                catch { }
            }
        }

        // 2. Standard DateTime.TryParse with invariant and current culture
        if (DateTime.TryParse(rawDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed) ||
            DateTime.TryParse(rawDate, CultureInfo.CurrentCulture, DateTimeStyles.None, out parsed))
        {
            return true;
        }

        return false;
    }

    public static string FormatDriverDate(string rawDate)
    {
        if (string.IsNullOrWhiteSpace(rawDate)) return "";
        if (TryParseDriverDate(rawDate, out var parsed))
        {
            return parsed.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }
        return rawDate;
    }

    /// <summary>
    /// Human-readable mapping for Windows ConfigManagerErrorCode values.
    /// </summary>
    public static string GetErrorCodeDescription(int code)
    {
        return code switch
        {
            0 => "Device is working properly.",
            1 => "Device is not configured correctly (CM_PROB_NOT_CONFIGURED).",
            2 => "Windows cannot load the driver for this device (CM_PROB_DEVLOADER_FAILED).",
            3 => "Driver for this device might be corrupted or system is low on memory (CM_PROB_OUT_OF_MEMORY).",
            9 => "Windows cannot identify this device (CM_PROB_INVALID_DATA).",
            10 => "Device cannot start (CM_PROB_FAILED_START).",
            12 => "Device cannot find enough free resources to use (CM_PROB_NORMAL_CONFLICT).",
            14 => "Device cannot work properly until restart (CM_PROB_NEED_RESTART).",
            16 => "Windows cannot identify all resources used by this device (CM_PROB_PARTIAL_LOG_CONF).",
            18 => "Reinstall drivers for this device (CM_PROB_REINSTALL).",
            19 => "Windows cannot start this hardware device; registry configuration damaged (CM_PROB_REGISTRY_ERROR).",
            21 => "Windows is removing this device (CM_PROB_WILL_BE_REMOVED).",
            22 => "Device is disabled (CM_PROB_DISABLED).",
            24 => "Device is not present, not working properly, or missing drivers (CM_PROB_FAILED_INSTALL).",
            28 => "Drivers for this device are not installed (CM_PROB_FAILED_ADD).",
            29 => "Device is disabled because device firmware did not give required resources (CM_PROB_DISABLED_SERVICE).",
            31 => "Device is not working properly because Windows cannot load required drivers (CM_PROB_FAILED_DRIVER_ENTRY).",
            32 => "Driver (service) for this device has been disabled (CM_PROB_DRIVER_BLOCKED).",
            37 => "Windows cannot initialize device driver (CM_PROB_FAILED_POST_START).",
            38 => "Windows cannot load driver; a previous instance is still in memory (CM_PROB_DUPLICATE_DEVICE).",
            39 => "Windows cannot load device driver; driver may be corrupt or missing (CM_PROB_FAILED_ADD).",
            41 => "Windows successfully loaded device driver but cannot find hardware device (CM_PROB_MOVED).",
            43 => "Windows has stopped this device because it has reported problems (CM_PROB_DEVICE_PROBLEM).",
            44 => "An application or service has shut down this hardware device (CM_PROB_DRIVER_BLOCKED).",
            45 => "Device is currently not connected to the computer (CM_PROB_NOT_PRESENT).",
            47 => "Device has been prepared for safe removal (CM_PROB_HELD_FOR_EJECT).",
            48 => "The software for this device has been blocked from starting (CM_PROB_DRIVER_BLOCKED).",
            52 => "Windows cannot verify digital signature for drivers required for this device (CM_PROB_UNSIGNED_DRIVER).",
            _ => $"Device Error (Code {code})"
        };
    }

    // ─── Physical OEM Hardware Detection & Target Version Matching ──────

    private static readonly object _ignoredLock = new();
    private static HashSet<string>? _cachedIgnored;

    public static string GetIgnoredFilePath()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow");
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        return Path.Combine(dir, "ignored_drivers.json");
    }

    public static HashSet<string> LoadIgnoredDrivers()
    {
        lock (_ignoredLock)
        {
            if (_cachedIgnored != null) return new HashSet<string>(_cachedIgnored, StringComparer.OrdinalIgnoreCase);
            try
            {
                string path = GetIgnoredFilePath();
                if (File.Exists(path))
                {
                    string json = File.ReadAllText(path);
                    var list = JsonSerializer.Deserialize<List<string>>(json);
                    if (list != null)
                    {
                        _cachedIgnored = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
                        return new HashSet<string>(_cachedIgnored, StringComparer.OrdinalIgnoreCase);
                    }
                }
            }
            catch { }

            _cachedIgnored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return new HashSet<string>(_cachedIgnored, StringComparer.OrdinalIgnoreCase);
        }
    }

    public static void SaveIgnoredDrivers(HashSet<string> ignored)
    {
        lock (_ignoredLock)
        {
            _cachedIgnored = new HashSet<string>(ignored, StringComparer.OrdinalIgnoreCase);
            try
            {
                string path = GetIgnoredFilePath();
                string json = JsonSerializer.Serialize(ignored.ToList(), new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch { }
        }
    }

    public static bool ToggleIgnoreDriver(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier)) return false;
        var ignored = LoadIgnoredDrivers();
        bool isIgnoredNow;
        if (ignored.Contains(identifier))
        {
            ignored.Remove(identifier);
            isIgnoredNow = false;
        }
        else
        {
            ignored.Add(identifier);
            isIgnoredNow = true;
        }
        SaveIgnoredDrivers(ignored);
        return isIgnoredNow;
    }

    public static bool IsInboxDriver(string manufacturer, string signer, string driverDate, string deviceClass, string deviceName, string hardwareId)
    {
        if (!string.IsNullOrEmpty(driverDate))
        {
            // Windows Vista/7/10/11 standard inbox baseline release date is 2006-06-21
            if (driverDate.StartsWith("2006-06-21", StringComparison.OrdinalIgnoreCase) || driverDate.StartsWith("2006", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(manufacturer) ||
                    manufacturer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                    manufacturer.Contains("Standard system", StringComparison.OrdinalIgnoreCase) ||
                    manufacturer.Contains("Standard disk", StringComparison.OrdinalIgnoreCase) ||
                    manufacturer.Contains("Standard keyboard", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return IsVirtualOrInboxDevice(deviceName, manufacturer, deviceClass, hardwareId);
    }

    public static bool IsVirtualOrInboxDevice(string deviceName, string manufacturer, string deviceClass, string hardwareId, string deviceId = "")
    {
        // 1. Check DeviceClass
        if (string.Equals(deviceClass, "PrintQueue", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "Printer", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "SoftwareDevice", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "AudioEndpoint", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "BluetoothVirtual", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "VolumeSnapshot", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "Volume", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "WPD", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "Computer", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(deviceClass, "Processor", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // 2. Check DeviceID / HardwareId prefixes
        string id = (hardwareId + " " + deviceId).ToUpperInvariant();
        if (id.StartsWith("ROOT\\") ||
            id.StartsWith("SWD\\") ||
            id.Contains("SWD\\") ||
            id.StartsWith("MMDEVAPI\\") ||
            id.Contains("MMDEVAPI") ||
            id.Contains("AUDIOENDPOINTS") ||
            id.StartsWith("BTHENUM\\") ||
            id.Contains("BTHENUM\\") ||
            id.StartsWith("BTHHFENUM\\") ||
            id.Contains("BTHHFENUM\\") ||
            id.StartsWith("BTH\\") ||
            id.Contains("ACPI_HAL") ||
            id.Contains("ACPI\\PNP0C08") || id.Contains("ACPI\\PNP0C09") || id.Contains("ACPI\\PNP0C0A") ||
            id.Contains("ACPI\\PNP0C0B") || id.Contains("ACPI\\PNP0C0C") || id.Contains("ACPI\\PNP0C0D") ||
            id.Contains("ACPI\\PNP0C0E") || id.Contains("ACPI\\PNP0C0F") || id.Contains("ACPI\\PNP0A05") ||
            id.Contains("ACPI\\PNP0A06") || id.Contains("ACPI\\ACPI0003") || id.Contains("ACPI\\ACPI0004") ||
            id.Contains("ACPI\\ACPI0007") || id.Contains("ACPI\\FIXEDBUTTON") || id.Contains("ACPI\\THERMALZONE"))
        {
            return true;
        }

        // 3. Check Device Name patterns
        string name = (deviceName ?? "").ToLowerInvariant();
        if (name.Contains("acpi fixed feature button") ||
            name.Contains("acpi lid") ||
            name.Contains("acpi processor container") ||
            name.Contains("acpi thermal zone") ||
            name.Contains("acpi fan") ||
            name.Contains("acpi power button") ||
            name.Contains("acpi sleep button") ||
            name.Contains("microsoft acpi-compliant") ||
            name.Contains("motherboard resources") ||
            name.Contains("system timer") ||
            name.Contains("high precision event timer") ||
            name.Contains("numeric data processor") ||
            name.Contains("direct memory access controller") ||
            name.Contains("programmable interrupt controller") ||
            name.Contains("system cmos/real time clock") ||
            name.Contains("system board") ||
            name.Contains("pci standard host cpu bridge") ||
            name.Contains("pci standard isa bridge") ||
            name.Contains("pci standard ram controller") ||
            name.Contains("adobe pdf") ||
            name.Contains("print to pdf") ||
            name.Contains("xps document writer") ||
            name.Contains("root print queue") ||
            name.Contains("onenote") ||
            name.Contains("fax") ||
            name.Contains("wan miniport") ||
            name.Contains("kernel debug") ||
            name.Contains("direct virtual adapter") ||
            name.Contains("ndis virtual") ||
            name.Contains("volume shadow copy") ||
            name.Contains("generic volume") ||
            name.Contains("volume manager") ||
            name.Contains("storage spaces controller") ||
            name.Contains("virtual drive enumerator") ||
            name.Contains("device association root") ||
            name.Contains("composite bus enumerator") ||
            name.Contains("root bus enumerator") ||
            name.Contains("remote desktop") ||
            name.Contains("terminal server") ||
            name.Contains("software device") ||
            name.Contains("basic display adapter") ||
            name.Contains("basic render driver") ||
            name.Contains("bluetooth device (personal area network)") ||
            name.Contains("bluetooth device (rfcomm") ||
            name.Contains("avrcp transport") ||
            name.Contains("hands-free") ||
            name.Contains("airpods") ||
            name.Contains("audio endpoint") ||
            name.Contains("virtual camera") ||
            name.Contains("obs-camera") ||
            name.Contains("obs virtual camera") ||
            name.Contains("unity capture") ||
            name.Contains("ndi video") ||
            name.Contains("vmix video"))
        {
            return true;
        }

        return false;
    }

    public static bool IsPhysicalOemHardware(string deviceName, string manufacturer, string deviceClass, string hardwareId, string deviceId = "", int errorCode = 0)
    {
        // Devices with hardware errors must always be audited so the user can diagnose/fix them
        if (errorCode > 0) return true;

        // Filter out Windows inbox devices, virtual software devices, and ACPI root containers
        if (IsVirtualOrInboxDevice(deviceName, manufacturer, deviceClass, hardwareId, deviceId))
            return false;

        string name = (deviceName ?? "").ToLowerInvariant();
        string mfr = (manufacturer ?? "").ToLowerInvariant();
        string cls = (deviceClass ?? "").ToLowerInvariant();
        string hwUpper = (hardwareId ?? "").ToUpperInvariant();
        string devUpper = (deviceId ?? "").ToUpperInvariant();

        // 1. GPU / Display
        if (cls == "display" || name.Contains("geforce") || name.Contains("radeon") ||
            name.Contains("arc(tm)") || name.Contains("intel(r) uhd") || name.Contains("intel(r) iris") ||
            name.Contains("graphics") || name.Contains("display adapter"))
        {
            return true;
        }

        // 2. Audio — Only audit actual physical PCI/motherboard sound chipsets (e.g. Realtek ALC, AMD Audio Controller, Intel SST)
        // and physical host controllers. Never audit software audio endpoints or Bluetooth profiles.
        if (cls == "media" || cls == "sound")
        {
            if (hwUpper.Contains("MMDEVAPI") || devUpper.Contains("MMDEVAPI") ||
                hwUpper.Contains("SWD\\") || devUpper.Contains("SWD\\") ||
                hwUpper.Contains("BTHENUM") || devUpper.Contains("BTHENUM") ||
                hwUpper.Contains("BTHHFENUM") || devUpper.Contains("BTHHFENUM") ||
                name.Contains("endpoint") || name.Contains("airpods") || name.Contains("hands-free") ||
                name.Contains("avrcp"))
            {
                return false;
            }

            if (hwUpper.StartsWith("PCI\\") || hwUpper.StartsWith("HDAUDIO\\") ||
                name.Contains("realtek") || name.Contains("smart sound") ||
                name.Contains("audio controller") ||
                (hwUpper.StartsWith("USB\\") && (name.Contains("dac") || name.Contains("sound card") || name.Contains("audio interface"))))
            {
                return true;
            }
        }

        // 3. Wi-Fi & Wireless
        if (name.Contains("wi-fi") || name.Contains("wireless") || name.Contains("802.11") ||
            name.Contains("wlan") || name.Contains("ax200") || name.Contains("ax201") ||
            name.Contains("ax210") || name.Contains("ax211") || name.Contains("be200") ||
            name.Contains("mt7921") || name.Contains("mt7922") || name.Contains("8821ce") ||
            name.Contains("8822ce") || name.Contains("8852ae") || name.Contains("8852be"))
        {
            return true;
        }

        // 4. Bluetooth — Only audit physical OEM host radio controller (Intel, Realtek, Qualcomm, MediaTek)
        // Filter out connected audio endpoints, profiles, and accessories.
        if (cls == "bluetooth" || name.Contains("bluetooth"))
        {
            if (hwUpper.Contains("BTHENUM") || devUpper.Contains("BTHENUM") ||
                hwUpper.Contains("BTHHFENUM") || devUpper.Contains("BTHHFENUM") ||
                hwUpper.StartsWith("BTH\\") || devUpper.StartsWith("BTH\\") ||
                name.Contains("airpods") || name.Contains("hands-free") || name.Contains("avrcp") ||
                name.Contains("rfcomm") || name.Contains("personal area network"))
            {
                return false;
            }

            if ((hwUpper.StartsWith("USB\\") || hwUpper.StartsWith("PCI\\")) &&
                (name.Contains("adapter") || name.Contains("wireless bluetooth") ||
                 name.Contains("radio") || name.Contains("controller") ||
                 name.Contains("intel") || name.Contains("realtek") ||
                 name.Contains("qualcomm") || name.Contains("mediatek")))
            {
                return true;
            }
        }

        // 5. Network / Ethernet (Physical NIC)
        if (cls == "net" && (name.Contains("ethernet") || name.Contains("gigabit") || name.Contains("pcie gbe") ||
                             name.Contains("lan connection") || name.Contains("i219") || name.Contains("i225") || name.Contains("i226")))
        {
            return true;
        }

        // 6. Storage Controllers
        if (cls == "scsiadapter" || cls == "hdc" || name.Contains("nvme") || name.Contains("nvm express") ||
            name.Contains("ahci") || name.Contains("sata") || name.Contains("rapid storage") || name.Contains("raid"))
        {
            return true;
        }

        // 7. Chipset & System Host Controllers (from OEM, not Microsoft)
        if (!mfr.Contains("microsoft") && !string.IsNullOrWhiteSpace(mfr) &&
            (cls == "system" || cls == "usb" || cls == "chipset") &&
            (name.Contains("chipset") || name.Contains("management engine") || name.Contains("thunderbolt") ||
             name.Contains("extensible host controller") || name.Contains("serial io") || name.Contains("gpio") ||
             name.Contains("smbus") || name.Contains("psp") || name.Contains("pci express root port")))
        {
            return true;
        }

        // 8. General PCI OEM devices with non-Microsoft vendor
        if (hwUpper.StartsWith("PCI\\") &&
            !mfr.Contains("microsoft") && !mfr.Contains("standard"))
        {
            return true;
        }

        return false;
    }

    public static string DetectCategory(string deviceName, string deviceClass)
    {
        string name = (deviceName ?? "").ToLowerInvariant();
        string cls = (deviceClass ?? "").ToLowerInvariant();

        if (cls == "display" || name.Contains("geforce") || name.Contains("radeon") || name.Contains("graphics"))
            return "GPU";
        if (name.Contains("wi-fi") || name.Contains("wireless") || name.Contains("802.11") || name.Contains("wlan"))
            return "Wi-Fi";
        if (cls == "bluetooth" || name.Contains("bluetooth"))
            return "Bluetooth";
        if (cls == "net" || name.Contains("ethernet") || name.Contains("pcie gbe") || name.Contains("lan"))
            return "Network";
        if (cls == "media" || cls == "sound" || name.Contains("audio") || name.Contains("sound"))
            return "Audio";
        if (cls == "scsiadapter" || cls == "hdc" || name.Contains("nvme") || name.Contains("sata") || name.Contains("ahci"))
            return "Storage";
        if (name.Contains("usb") || cls == "usb")
            return "USB";
        return "Chipset";
    }

    public static (string Version, string Date) GetTargetVersion(string deviceName, string manufacturer, string category, string hardwareId = "")
    {
        string name = (deviceName ?? "").ToLowerInvariant();
        string mfr = (manufacturer ?? "").ToLowerInvariant();
        string hwid = (hardwareId ?? "").ToLowerInvariant();

        if (category == "GPU" || name.Contains("graphics") || name.Contains("geforce") || name.Contains("radeon"))
        {
            if (name.Contains("geforce") || name.Contains("nvidia") || mfr.Contains("nvidia") || hwid.Contains("ven_10de"))
                return ("560.94", "2024-08-20");
            if (name.Contains("radeon") || name.Contains("amd") || mfr.Contains("advanced micro") || hwid.Contains("ven_1002"))
                return ("24.7.1", "2024-07-18");
            if (name.Contains("intel") || mfr.Contains("intel") || name.Contains("arc") || name.Contains("iris") || name.Contains("uhd") || hwid.Contains("ven_8086"))
                return ("31.0.101.5590", "2024-07-25");
            return ("", "");
        }

        if (category == "Wi-Fi")
        {
            if (name.Contains("intel") || mfr.Contains("intel") || hwid.Contains("ven_8086"))
                return ("23.60.0", "2024-06-15");
            if (name.Contains("realtek") || mfr.Contains("realtek") || hwid.Contains("ven_10ec"))
                return ("6001.16.143.0", "2024-05-10");
            if (name.Contains("mediatek") || mfr.Contains("mediatek") || hwid.Contains("ven_14c3"))
                return ("3.3.0.985", "2024-04-12");
            if (name.Contains("qualcomm") || mfr.Contains("qualcomm") || name.Contains("atheros") || hwid.Contains("ven_17cb") || hwid.Contains("ven_168c"))
                return ("1.0.0.1800", "2024-03-10");
            return ("", "");
        }

        if (category == "Bluetooth")
        {
            if (name.Contains("realtek") || mfr.Contains("realtek") || hwid.Contains("vid_0bda") || hwid.Contains("ven_10ec"))
                return ("1.10.1061.3015", "2024-05-12");
            if (name.Contains("intel") || mfr.Contains("intel") || hwid.Contains("vid_8087") || hwid.Contains("ven_8086"))
                return ("23.60.0", "2024-06-15");
            return ("", "");
        }

        if (category == "Audio")
        {
            // Senary Audio / Conexant (VEN_14F1) is a specialized OEM codec — do NOT match Intel SST!
            if (name.Contains("senary") || mfr.Contains("senary") || hwid.Contains("ven_14f1") ||
                name.Contains("conexant") || mfr.Contains("conexant") || name.Contains("synaptics") ||
                name.Contains("c-media") || name.Contains("creative"))
            {
                return ("", "");
            }

            if (name.Contains("realtek") || mfr.Contains("realtek") || hwid.Contains("ven_10ec"))
                return ("6.0.9655.1", "2024-03-20");

            if ((name.Contains("intel") || mfr.Contains("intel") || hwid.Contains("ven_8086")) &&
                (name.Contains("smart sound") || name.Contains("sst") || name.Contains("issp")))
                return ("10.29.0.10300", "2024-04-05");

            return ("", "");
        }

        if (category == "Network")
        {
            if (name.Contains("realtek") || mfr.Contains("realtek") || hwid.Contains("ven_10ec"))
                return ("10.068", "2024-05-22");
            if (name.Contains("intel") || mfr.Contains("intel") || hwid.Contains("ven_8086"))
                return ("29.2", "2024-06-10");
            return ("", "");
        }

        if (category == "Storage")
        {
            if (name.Contains("rapid storage") || name.Contains("rst") || (name.Contains("intel") && name.Contains("storage")))
                return ("19.5.7.1058", "2024-02-18");
            if (name.Contains("samsung") || mfr.Contains("samsung") || hwid.Contains("ven_144d"))
                return ("3.3.0.0", "2024-01-15");
            return ("", "");
        }

        if (category == "Chipset")
        {
            if (name.Contains("management engine") || name.Contains("mei") || (name.Contains("intel") && name.Contains("chipset")))
                return ("2408.5.4.0", "2024-05-08");
            if (name.Contains("amd") || mfr.Contains("amd") || hwid.Contains("ven_1022"))
                return ("5.12.0.38", "2024-04-15");
            return ("", "");
        }

        return ("", "");
    }

    public static bool IsNewerVersion(string currentVersion, string availableVersion)
    {
        if (string.IsNullOrWhiteSpace(currentVersion) || string.IsNullOrWhiteSpace(availableVersion))
            return false;

        string normCurrent = NormalizeVersionString(currentVersion);
        string normAvailable = NormalizeVersionString(availableVersion);

        if (Version.TryParse(normCurrent, out var vCur) && Version.TryParse(normAvailable, out var vAvail))
        {
            return vAvail > vCur;
        }

        return string.Compare(normAvailable, normCurrent, StringComparison.OrdinalIgnoreCase) > 0;
    }

    private static string NormalizeVersionString(string v)
    {
        var cleaned = System.Text.RegularExpressions.Regex.Replace(v.Trim(), @"[^\d.]", "");
        var parts = cleaned.Split('.', StringSplitOptions.RemoveEmptyEntries).Take(4).ToArray();
        return string.Join(".", parts);
    }

    public static int CalculateHealthScore(int total, int outdated, int unsigned, int errorCount)
    {
        if (total <= 0) return 100;
        // Realistic calculation:
        // Hardware errors: -25 pts each
        // Unsigned driver: -10 pts each
        // Outdated driver: -5 pts each
        int penalty = (errorCount * 25) + (unsigned * 10) + (outdated * 5);
        return Math.Clamp(100 - penalty, 0, 100);
    }

    private static string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }
}
