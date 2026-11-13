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
}
