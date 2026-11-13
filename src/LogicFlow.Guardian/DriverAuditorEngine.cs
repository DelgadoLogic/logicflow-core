// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – DriverAuditorEngine
// Audits installed PnP system drivers, detects device hardware errors, and
// checks for unsigned or outdated drivers via WMI/PnP APIs.
// ─────────────────────────────────────────────────────────────────────────────

using System.Management;
using Microsoft.Extensions.Logging;

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
        public string DeviceName { get; init; } = "";
        public string Manufacturer { get; init; } = "";
        public string DriverVersion { get; init; } = "";
        public string DriverDate { get; init; } = "";
        public string HardwareId { get; init; } = "";
        public bool IsSigned { get; init; }
        public string Signer { get; init; } = "";
        public int ConfigManagerErrorCode { get; init; }
        public bool HasError => ConfigManagerErrorCode != 0;
        public string StatusDescription => HasError ? GetErrorCodeDescription(ConfigManagerErrorCode) : "OK";
    }

    public sealed class DriverAuditReport
    {
        public List<DeviceDriverInfo> Drivers { get; init; } = new();
        public int TotalDrivers => Drivers.Count;
        public int UnsignedCount => Drivers.Count(d => !d.IsSigned);
        public int ProblemDeviceCount => Drivers.Count(d => d.HasError);
    }

    // ─── Core API ────────────────────────────────────────────────────────

    /// <summary>
    /// Audits all installed PnP device drivers on the machine.
    /// </summary>
    public DriverAuditReport AuditDrivers()
    {
        _logger?.LogInformation("Auditing PnP signed device drivers...");
        var driverList = new List<DeviceDriverInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(@"SELECT DeviceName, Manufacturer, DriverVersion, DriverDate, HardWareID, IsSigned, Signer, ConfigManagerErrorCode FROM Win32_PnPSignedDriver");
            using var results = searcher.Get();

            foreach (ManagementObject obj in results.Cast<ManagementObject>())
            {
                try
                {
                    var name = obj["DeviceName"]?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    var mfr = obj["Manufacturer"]?.ToString() ?? "";
                    var ver = obj["DriverVersion"]?.ToString() ?? "";
                    var dateStr = obj["DriverDate"]?.ToString() ?? "";
                    var hwid = obj["HardWareID"]?.ToString() ?? "";
                    var isSigned = Convert.ToBoolean(obj["IsSigned"] ?? false);
                    var signer = obj["Signer"]?.ToString() ?? "";
                    var errCode = Convert.ToInt32(obj["ConfigManagerErrorCode"] ?? 0);

                    driverList.Add(new DeviceDriverInfo
                    {
                        DeviceName = name,
                        Manufacturer = mfr,
                        DriverVersion = ver,
                        DriverDate = FormatWmiDate(dateStr),
                        HardwareId = hwid,
                        IsSigned = isSigned,
                        Signer = signer,
                        ConfigManagerErrorCode = errCode
                    });
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning("WMI Win32_PnPSignedDriver query failed: {Msg}", ex.Message);
        }

        _logger?.LogInformation("Driver audit complete. Audited {Count} drivers ({Problem} problem devices).",
            driverList.Count, driverList.Count(d => d.HasError));

        return new DriverAuditReport
        {
            Drivers = driverList.OrderBy(d => d.DeviceName, StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static string FormatWmiDate(string wmiDate)
    {
        if (string.IsNullOrWhiteSpace(wmiDate) || wmiDate.Length < 8) return wmiDate;
        try
        {
            var year = wmiDate[..4];
            var month = wmiDate[4..6];
            var day = wmiDate[6..8];
            return $"{year}-{month}-{day}";
        }
        catch
        {
            return wmiDate;
        }
    }

    private static string GetErrorCodeDescription(int code)
    {
        return code switch
        {
            1 => "Device is not configured correctly.",
            3 => "Driver for this device might be corrupted.",
            10 => "Device cannot start.",
            12 => "Device cannot find enough free resources to use.",
            14 => "Device cannot work properly until restart.",
            18 => "Reinstall drivers for this device.",
            22 => "Device is disabled.",
            28 => "Drivers for this device are not installed.",
            31 => "Device is not working properly.",
            _ => $"Device Error (Code {code})"
        };
    }
}
