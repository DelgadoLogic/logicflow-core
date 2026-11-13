// LogicFlow.Tests — AiPrivacyGuardTests
// Tests for Windows Recall, Copilot, Edge AI, and NPU privacy guard engine.

using System.Linq;
using System.Threading.Tasks;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class AiPrivacyGuardTests
{
    [Fact]
    public void GetAllFeatures_ReturnsAllExpectedTargets()
    {
        var engine = new AiPrivacyGuardEngine();
        var features = engine.GetAllFeatures();

        Assert.NotNull(features);
        Assert.Equal(6, features.Count);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.WindowsRecall);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.WindowsCopilot);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.EdgeAiSidebar);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.NpuStudioTelemetry);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.BingSearchInStart);
        Assert.Contains(features, f => f.Target == AiPrivacyTarget.WidgetsNewsFeed);
    }

    [Fact]
    public async Task ScanAsync_ReturnsFeatureStatusList()
    {
        var engine = new AiPrivacyGuardEngine();
        var features = await engine.ScanAsync();

        Assert.NotNull(features);
        Assert.NotEmpty(features);
        foreach (var f in features)
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Name));
            Assert.False(string.IsNullOrWhiteSpace(f.Description));
            Assert.False(string.IsNullOrWhiteSpace(f.RegistryImpact));
        }
    }

    [Fact]
    public void IsRecallDisabled_ReturnsBooleanWithoutException()
    {
        var result = AiPrivacyGuardEngine.IsRecallDisabled();
        Assert.True(result == true || result == false);
    }

    [Fact]
    public void IsCopilotDisabled_ReturnsBooleanWithoutException()
    {
        var result = AiPrivacyGuardEngine.IsCopilotDisabled();
        Assert.True(result == true || result == false);
    }
}
