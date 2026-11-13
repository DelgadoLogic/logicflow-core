using LogicFlow.Dashboard;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class PulseQueryEngineTests
{
    private static SystemInfoEngine.SystemSnapshot CreateTestSnapshot()
    {
        return new SystemInfoEngine.SystemSnapshot
        {
            CpuName = "AMD Ryzen 7 5825U with Radeon Graphics",
            CpuCores = 8,
            CpuThreads = 16,
            CpuSpeedGHz = 2.0,
            CpuUsagePercent = 14.0,
            TotalRamBytes = 64L * 1024 * 1024 * 1024,
            AvailableRamBytes = 28L * 1024 * 1024 * 1024,
            GpuName = "AMD Radeon Graphics",
            GpuDriverVersion = "31.0.12028.2",
            GpuVramBytes = 2L * 1024 * 1024 * 1024,
            OsName = "Windows 11 Pro",
            OsBuild = "22631",
            OsArchitecture = "X64",
            ComputerName = "WORKSTATION",
            UserName = "Manuel",
            Uptime = TimeSpan.FromHours(5),
            ActiveNetworkAdapter = "Wi-Fi 6",
            IpAddress = "192.168.1.150",
            NetworkSpeedMbps = 1200,
            Disks = new List<SystemInfoEngine.DiskInfo>
            {
                new()
                {
                    Name = "C:\\",
                    TotalBytes = 1000L * 1024 * 1024 * 1024,
                    FreeBytes = 400L * 1024 * 1024 * 1024,
                    FileSystem = "NTFS"
                }
            }
        };
    }

    [Theory]
    [InlineData("how my computer speed")]
    [InlineData("how fast is my computer")]
    [InlineData("how fast is my pc")]
    [InlineData("cpu clock")]
    [InlineData("cpu speed")]
    [InlineData("what is my ghz")]
    [InlineData("processor speed")]
    [InlineData("how is my performance")]
    public void ProcessQuery_SpeedQueries_ReturnsFullProcessorDiagnostics(string query)
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery(query, snapshot);

        Assert.Contains("Processor Performance", response);
        Assert.Contains("AMD Ryzen 7 5825U with Radeon Graphics", response);
        Assert.Contains("2.00 GHz", response);
        Assert.Contains("Base Speed", response);
        Assert.Contains("8 Cores / 16 Threads", response);
        Assert.Contains("14%", response);
    }

    [Fact]
    public void ProcessQuery_BatteryQueryWithAbout_RoutesToBatteryNotOverview()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery(
            "tell me about my battery",
            snapshot,
            isPowerStatusAvailable: true,
            acLineStatus: 1,
            batteryFlag: 8,
            batteryLifePercent: 88);

        Assert.Contains("Power & Battery Status", response);
        Assert.Contains("88%", response);
        Assert.DoesNotContain("System Hardware Overview", response);
    }

    [Fact]
    public void ProcessQuery_GpuQueryWithAbout_RoutesToGpuNotOverview()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("tell me about my gpu", snapshot);

        Assert.Contains("Graphics Subsystem", response);
        Assert.Contains("AMD Radeon Graphics", response);
        Assert.DoesNotContain("System Hardware Overview", response);
    }

    [Fact]
    public void ProcessQuery_RamQueryWithAbout_RoutesToRamNotOverview()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("what about my ram", snapshot);

        Assert.Contains("Memory Status", response);
        Assert.Contains("RAM Active", response);
        Assert.DoesNotContain("System Hardware Overview", response);
    }

    [Fact]
    public void ProcessQuery_DiskQuery_ReturnsVolumes()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("check disk space", snapshot);

        Assert.Contains("Storage Volumes", response);
        Assert.Contains("C:\\", response);
    }

    [Fact]
    public void ProcessQuery_SupportQuery_DoesNotTriggerSecurityScan()
    {
        var snapshot = CreateTestSnapshot();
        // Substring 'port' must NOT match 'support' or 'report'
        var response = PulseQueryEngine.ProcessQuery("i need customer support", snapshot);

        Assert.DoesNotContain("Security Profile", response);
    }

    [Fact]
    public void ProcessQuery_FreePricingQuery_DoesNotTriggerDiskStorage()
    {
        var snapshot = CreateTestSnapshot();
        // Word 'free' alone must NOT trigger disk storage unless combined with space/disk/storage
        var response = PulseQueryEngine.ProcessQuery("is logicflow free", snapshot);

        Assert.DoesNotContain("Storage Volumes", response);
    }

    [Fact]
    public void ProcessQuery_SystemHealthQuery_ReturnsHealthStatus()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("how is my system", snapshot, healthScore: "92%");

        Assert.Contains("Overall System Health", response);
        Assert.Contains("92%", response);
    }

    [Fact]
    public void ProcessQuery_SystemHealthQuery_WhenNoScore_ReturnsNotYetCalculated()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("how is my system", snapshot, healthScore: null);

        Assert.Contains("Overall System Health", response);
        Assert.Contains("Not yet calculated", response);
        Assert.DoesNotContain("85%", response);
    }

    [Fact]
    public void ProcessQuery_UnknownQuery_ReturnsFriendlyFallback()
    {
        var snapshot = CreateTestSnapshot();
        var response = PulseQueryEngine.ProcessQuery("xyzzy random gibberish 12345", snapshot);

        Assert.Contains("Pulse (local diagnostics)", response);
        Assert.Contains("how my computer speed", response);
    }

    [Theory]
    [InlineData("Windows 10 Pro", "22631", "Windows 11 Pro")]
    [InlineData("Windows 10 Pro", "22000", "Windows 11 Pro")]
    [InlineData("Windows 10 Home (23H2)", "22631", "Windows 11 Home (23H2)")]
    [InlineData("Windows 10 Pro [22631]", "", "Windows 11 Pro [22631]")]
    [InlineData("Windows 11 Pro", "22631", "Windows 11 Pro")]
    public void ResolveOsName_BuildsAtOrAbove22000_ResolvesToWindows11(string inputName, string build, string expected)
    {
        var resolved = PulseQueryEngine.ResolveOsName(inputName, build);
        Assert.Equal(expected, resolved);
    }

    [Fact]
    public void ProcessQuery_SpecsWithWin10OnWin11Build_OutputsWindows11()
    {
        var snapshot = CreateTestSnapshot();
        snapshot.OsName = "Windows 10 Pro [22631]";
        snapshot.OsBuild = "22631";

        var response = PulseQueryEngine.ProcessQuery("system specs", snapshot);
        Assert.Contains("Windows 11 Pro [22631]", response);
        Assert.DoesNotContain("Windows 10 Pro", response);
    }

    [Fact]
    public void ProcessQuery_GpuFallback_ResolvesActiveAdapter()
    {
        var snapshot = CreateTestSnapshot();
        snapshot.GpuName = "DirectX GPU";

        var response = PulseQueryEngine.ProcessQuery("what is my gpu", snapshot);
        Assert.Contains("Graphics Subsystem", response);
        Assert.DoesNotContain("DirectX GPU", response);
    }

    [Fact]
    public void SystemInfoEngine_CreateFastInitialSnapshot_PopulatesHardwareAndNetwork()
    {
        var snapshot = SystemInfoEngine.CreateFastInitialSnapshot();
        Assert.NotNull(snapshot);
        Assert.False(string.IsNullOrWhiteSpace(snapshot.CpuName));
        Assert.True(snapshot.CpuCores > 0);
        Assert.True(snapshot.CpuThreads > 0);
        Assert.False(string.IsNullOrWhiteSpace(snapshot.GpuName));
        Assert.NotEmpty(snapshot.Disks);
        Assert.False(string.IsNullOrWhiteSpace(snapshot.OsName));
        Assert.False(string.IsNullOrWhiteSpace(snapshot.ActiveNetworkAdapter));
        Assert.False(string.IsNullOrWhiteSpace(snapshot.IpAddress));
    }

    [Fact]
    public void SystemInfoEngine_CollectDiskInfo_ReturnsAtLeastOneValidDisk()
    {
        var disks = SystemInfoEngine.CollectDiskInfo();
        Assert.NotEmpty(disks);
        var primary = disks[0];
        Assert.False(string.IsNullOrWhiteSpace(primary.Name));
        Assert.True(primary.TotalBytes > 0);
        Assert.True(primary.UsagePercent >= 0 && primary.UsagePercent <= 100);
    }

    [Fact]
    public void SystemInfoEngine_GetOsBuildNumber_ReturnsValidBuild()
    {
        var build = SystemInfoEngine.GetOsBuildNumber();
        Assert.False(string.IsNullOrWhiteSpace(build));
        Assert.True(int.TryParse(build.Split('.')[0], out int b) && b > 0);
    }

    [Fact]
    public void SystemInfoEngine_GetFriendlyOsName_ReturnsValidName()
    {
        var os = SystemInfoEngine.GetFriendlyOsName();
        Assert.False(string.IsNullOrWhiteSpace(os));
        Assert.Contains("Windows", os);
    }

    [Theory]
    [InlineData("DirectX GPU")]
    [InlineData("Display Adapter")]
    [InlineData("DirectX Graphics Adapter")]
    [InlineData("Display Controller")]
    [InlineData("Microsoft Basic Display Adapter")]
    [InlineData("Standard VGA Graphics Adapter")]
    public void ResolveGpuName_GenericCandidates_FallbackToHardwareResolution(string genericCandidate)
    {
        var resolved = PulseQueryEngine.ResolveGpuName(genericCandidate);
        Assert.False(string.IsNullOrWhiteSpace(resolved));
        Assert.NotEqual("DirectX GPU", resolved);
        Assert.NotEqual("Display Controller", resolved);
    }

    [Fact]
    public void ResolveGpuName_SpecificHardware_PreservesName()
    {
        var resolved = PulseQueryEngine.ResolveGpuName("NVIDIA GeForce RTX 4070 Laptop GPU");
        Assert.Equal("NVIDIA GeForce RTX 4070 Laptop GPU", resolved);
    }
}
