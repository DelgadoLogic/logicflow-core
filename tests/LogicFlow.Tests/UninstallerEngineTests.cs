using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class UninstallerEngineTests
{
    [Fact]
    public void GetInstalledApplications_ReturnsValidList()
    {
        var engine = new UninstallerEngine();
        var apps = engine.GetInstalledApplications();

        Assert.NotNull(apps);
        // On a Windows test machine, there should be installed applications in registry
        Assert.NotEmpty(apps);

        foreach (var app in apps)
        {
            Assert.False(string.IsNullOrWhiteSpace(app.DisplayName));
        }
    }

    [Fact]
    public void ScanResiduals_WithDummyApp_ReturnsScanResult()
    {
        var engine = new UninstallerEngine();
        var dummyApp = new UninstallerEngine.InstalledApp
        {
            DisplayName = "TestNonExistentApplication12345",
            Publisher = "TestPublisher"
        };

        var result = engine.ScanResiduals(dummyApp);

        Assert.NotNull(result);
        Assert.Equal(dummyApp, result.TargetApp);
        Assert.NotNull(result.Items);
    }
}
