#pragma warning disable CA1416
// OmniCore.Engine — System Profiler
// Proprietary implementation by DelgadoLogic.Tech
// Hardware fingerprinting, OS telemetry, and resource monitoring

using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace OmniCore.Engine;

/// <summary>
/// Gathers hardware and OS information for system profiling,
/// HWID generation, and resource monitoring.
/// </summary>
public sealed class SystemProfiler
{
    private readonly ILogger<SystemProfiler> _logger;

    public SystemProfiler(ILogger<SystemProfiler> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Captures a complete system snapshot including CPU, RAM, GPU, OS, and disk info.
    /// </summary>
    public SystemSnapshot CaptureSnapshot()
    {
        _logger.LogInformation("Capturing system snapshot...");

        return new SystemSnapshot
        {
            CapturedAt = DateTimeOffset.UtcNow,
            Cpu = GetCpuInfo(),
            Memory = GetMemoryInfo(),
            Gpu = GetGpuInfo(),
            Os = GetOsInfo(),
            Disks = GetDiskInfo(),
            Motherboard = GetMotherboardInfo()
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    private CpuInfo GetCpuInfo()
    {
        string fastName = "";
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            fastName = key?.GetValue("ProcessorNameString") as string ?? "";
        }
        catch { }

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
            foreach (var obj in searcher.Get())
            {
                var wmiName = obj["Name"]?.ToString();
                return new CpuInfo
                {
                    Name = !string.IsNullOrWhiteSpace(fastName) ? fastName.Trim() : (!string.IsNullOrWhiteSpace(wmiName) ? wmiName.Trim() : "Processor"),
                    Cores = Convert.ToInt32(obj["NumberOfCores"]),
                    LogicalProcessors = Convert.ToInt32(obj["NumberOfLogicalProcessors"]),
                    MaxClockSpeed = Convert.ToInt32(obj["MaxClockSpeed"]),
                    ProcessorId = obj["ProcessorId"]?.ToString() ?? "",
                    Architecture = RuntimeInformation.ProcessArchitecture.ToString()
                };
            }
        }
        catch { }

        return new CpuInfo
        {
            Name = !string.IsNullOrWhiteSpace(fastName) ? fastName.Trim() : "Multi-Core Processor",
            Cores = Environment.ProcessorCount / 2 > 0 ? Environment.ProcessorCount / 2 : Environment.ProcessorCount,
            LogicalProcessors = Environment.ProcessorCount,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString()
        };
    }

    private MemoryInfo GetMemoryInfo()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (GlobalMemoryStatusEx(ref mem))
        {
            return new MemoryInfo
            {
                TotalPhysicalBytes = (long)mem.ullTotalPhys,
                AvailableBytes = (long)mem.ullAvailPhys
            };
        }

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                return new MemoryInfo
                {
                    TotalPhysicalBytes = Convert.ToInt64(obj["TotalPhysicalMemory"]),
                    AvailableBytes = GetAvailableMemory()
                };
            }
        }
        catch { }
        return new MemoryInfo();
    }

    private static long GetAvailableMemory()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (GlobalMemoryStatusEx(ref mem)) return (long)mem.ullAvailPhys;

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                return Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024; // KB to bytes
            }
        }
        catch { }
        return 0;
    }

    private GpuInfo GetGpuInfo()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            foreach (var obj in searcher.Get())
            {
                return new GpuInfo
                {
                    Name = obj["Name"]?.ToString() ?? "Unknown",
                    DriverVersion = obj["DriverVersion"]?.ToString() ?? "",
                    AdapterRam = Convert.ToInt64(obj["AdapterRAM"]),
                    DeviceId = obj["PNPDeviceID"]?.ToString() ?? ""
                };
            }
        }
        catch { }
        return new GpuInfo { Name = "Display Controller" };
    }

    private OsInfo GetOsInfo()
    {
        int build = Environment.OSVersion.Version.Build;
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                DateTime installDate = DateTime.MinValue;
                try
                {
                    var idStr = obj["InstallDate"]?.ToString();
                    if (!string.IsNullOrEmpty(idStr))
                        installDate = ManagementDateTimeConverter.ToDateTime(idStr);
                }
                catch { }

                var caption = obj["Caption"]?.ToString() ?? RuntimeInformation.OSDescription;
                var buildStr = obj["BuildNumber"]?.ToString() ?? "";
                if (int.TryParse(buildStr, out int b) && b > 0) build = b;

                if (build >= 22000 && caption.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
                {
                    caption = System.Text.RegularExpressions.Regex.Replace(caption, @"Windows\s*10", "Windows 11", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                }

                return new OsInfo
                {
                    Caption = caption,
                    Version = obj["Version"]?.ToString() ?? Environment.OSVersion.Version.ToString(),
                    BuildNumber = build.ToString(),
                    Architecture = obj["OSArchitecture"]?.ToString() ?? RuntimeInformation.OSArchitecture.ToString(),
                    InstallDate = installDate
                };
            }
        }
        catch { }

        var fallbackCaption = RuntimeInformation.OSDescription;
        if (build >= 22000 && fallbackCaption.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
        {
            fallbackCaption = System.Text.RegularExpressions.Regex.Replace(fallbackCaption, @"Windows\s*10", "Windows 11", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        return new OsInfo
        {
            Caption = fallbackCaption,
            Version = Environment.OSVersion.Version.ToString(),
            BuildNumber = build.ToString(),
            Architecture = RuntimeInformation.OSArchitecture.ToString()
        };
    }

    private List<DiskInfo> GetDiskInfo()
    {
        var disks = new List<DiskInfo>();
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
        foreach (var obj in searcher.Get())
        {
            disks.Add(new DiskInfo
            {
                Model = obj["Model"]?.ToString() ?? "Unknown",
                SerialNumber = obj["SerialNumber"]?.ToString()?.Trim() ?? "",
                SizeBytes = Convert.ToInt64(obj["Size"]),
                MediaType = obj["MediaType"]?.ToString() ?? "",
                InterfaceType = obj["InterfaceType"]?.ToString() ?? "",
                DeviceId = obj["DeviceID"]?.ToString() ?? ""
            });
        }
        return disks;
    }

    private MotherboardInfo GetMotherboardInfo()
    {
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
        foreach (var obj in searcher.Get())
        {
            return new MotherboardInfo
            {
                Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                Product = obj["Product"]?.ToString() ?? "",
                SerialNumber = obj["SerialNumber"]?.ToString() ?? ""
            };
        }
        return new MotherboardInfo { Manufacturer = "Unknown" };
    }
}

// ─── Data Models ───────────────────────────────────────────────
public sealed record SystemSnapshot
{
    public DateTimeOffset CapturedAt { get; init; }
    public CpuInfo Cpu { get; init; } = new();
    public MemoryInfo Memory { get; init; } = new();
    public GpuInfo Gpu { get; init; } = new();
    public OsInfo Os { get; init; } = new();
    public List<DiskInfo> Disks { get; init; } = [];
    public MotherboardInfo Motherboard { get; init; } = new();
}

public sealed record CpuInfo
{
    public string Name { get; init; } = "";
    public int Cores { get; init; }
    public int LogicalProcessors { get; init; }
    public int MaxClockSpeed { get; init; }
    public string ProcessorId { get; init; } = "";
    public string Architecture { get; init; } = "";
}

public sealed record MemoryInfo
{
    public long TotalPhysicalBytes { get; init; }
    public long AvailableBytes { get; init; }
    public double UsagePercent => TotalPhysicalBytes > 0
        ? (1.0 - (double)AvailableBytes / TotalPhysicalBytes) * 100.0
        : 0;
}

public sealed record GpuInfo
{
    public string Name { get; init; } = "";
    public string DriverVersion { get; init; } = "";
    public long AdapterRam { get; init; }
    public string DeviceId { get; init; } = "";
}

public sealed record OsInfo
{
    public string Caption { get; init; } = "";
    public string Version { get; init; } = "";
    public string BuildNumber { get; init; } = "";
    public string Architecture { get; init; } = "";
    public DateTime InstallDate { get; init; }
}

public sealed record DiskInfo
{
    public string Model { get; init; } = "";
    public string SerialNumber { get; init; } = "";
    public long SizeBytes { get; init; }
    public string MediaType { get; init; } = "";
    public string InterfaceType { get; init; } = "";
    public string DeviceId { get; init; } = "";
}

public sealed record MotherboardInfo
{
    public string Manufacturer { get; init; } = "";
    public string Product { get; init; } = "";
    public string SerialNumber { get; init; } = "";
}
