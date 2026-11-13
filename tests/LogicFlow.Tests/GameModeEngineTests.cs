using LogicFlow.Sentinel;
using Xunit;

namespace LogicFlow.Tests;

public class GameModeEngineTests
{
    [Fact]
    public void ActivateAndDeactivateGameMode_TogglesStateCorrectly()
    {
        var engine = new GameModeEngine();
        Assert.False(engine.IsGameModeActive);

        var status = engine.ActivateGameMode();
        Assert.NotNull(status);
        Assert.True(engine.IsGameModeActive);
        Assert.True(status.IsActive);

        var deactivated = engine.DeactivateGameMode();
        Assert.True(deactivated);
        Assert.False(engine.IsGameModeActive);
    }

    [Fact]
    public void PowerSchemeGuids_AreValidAndAccurate()
    {
        // High Performance GUID must be 8c5e7fda-... (not the typo 8c5e7dd5-...)
        Assert.Equal("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", GameModeEngine.HighPerformanceGuid);
        Assert.Equal("e9a42b02-d5df-448d-aa00-03f14749eb61", GameModeEngine.UltimatePerformanceGuid);
        Assert.Equal("381b4222-f694-41f0-9685-ff5bb260df2e", GameModeEngine.BalancedGuid);

        var regex = new System.Text.RegularExpressions.Regex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        Assert.Matches(regex, GameModeEngine.HighPerformanceGuid);
        Assert.Matches(regex, GameModeEngine.UltimatePerformanceGuid);
        Assert.Matches(regex, GameModeEngine.BalancedGuid);
    }
}
