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

    private CpuInfo GetCpuInfo()
    {
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
        foreach (var obj in searcher.Get())
        {
            return new CpuInfo
            {
                Name = obj["Name"]?.ToString() ?? "Unknown",
                Cores = Convert.ToInt32(obj["NumberOfCores"]),
                LogicalProcessors = Convert.ToInt32(obj["NumberOfLogicalProcessors"]),
                MaxClockSpeed = Convert.ToInt32(obj["MaxClockSpeed"]),
                ProcessorId = obj["ProcessorId"]?.ToString() ?? "",
                Architecture = RuntimeInformation.ProcessArchitecture.ToString()
            };
        }
        return new CpuInfo { Name = "Unknown" };
    }

    private MemoryInfo GetMemoryInfo()
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
        return new MemoryInfo();
    }

    private static long GetAvailableMemory()
    {
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
        foreach (var obj in searcher.Get())
        {
            return Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024; // KB to bytes
        }
        return 0;
    }

    private GpuInfo GetGpuInfo()
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
        return new GpuInfo { Name = "Unknown" };
    }

    private OsInfo GetOsInfo()
    {
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
        foreach (var obj in searcher.Get())
        {
            return new OsInfo
            {
                Caption = obj["Caption"]?.ToString() ?? "Unknown",
                Version = obj["Version"]?.ToString() ?? "",
                BuildNumber = obj["BuildNumber"]?.ToString() ?? "",
                Architecture = obj["OSArchitecture"]?.ToString() ?? "",
                InstallDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"]?.ToString() ?? "")
            };
        }
        return new OsInfo { Caption = "Unknown" };
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
