using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class DriverAuditorEngineTests
{
    [Fact]
    public void AuditDrivers_ReturnsValidReport()
    {
        var engine = new DriverAuditorEngine();
        var report = engine.AuditDrivers();

        Assert.NotNull(report);
        Assert.NotNull(report.Drivers);
        Assert.True(report.TotalDrivers >= 0);
        Assert.True(report.UnsignedCount >= 0);
        Assert.True(report.ProblemDeviceCount >= 0);

        foreach (var driver in report.Drivers)
        {
            Assert.False(string.IsNullOrWhiteSpace(driver.DeviceName));
        }
    }
}
