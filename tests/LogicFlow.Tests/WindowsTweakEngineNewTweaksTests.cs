// LogicFlow.Tests — WindowsTweakEngineNewTweaksTests
// Tests for Windows 11 Classic Context Menu and Recall tweaks in WindowsTweakEngine.

using System.Linq;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class WindowsTweakEngineNewTweaksTests
{
    [Fact]
    public void AllTweaks_ContainsClassicContextMenu()
    {
        var engine = new WindowsTweakEngine();
        var tweak = engine.AllTweaks.FirstOrDefault(t => t.Id == "visual.classic_context_menu");

        Assert.NotNull(tweak);
        Assert.Equal(TweakCategory.Visual, tweak.Category);
        Assert.Equal(SafetyLevel.Safe, tweak.Safety);
        Assert.NotNull(tweak.Apply);
        Assert.NotNull(tweak.Revert);
        Assert.NotNull(tweak.QueryState);
    }

    [Fact]
    public void AllTweaks_ContainsWindowsRecallTweak()
    {
        var engine = new WindowsTweakEngine();
        var tweak = engine.AllTweaks.FirstOrDefault(t => t.Id == "privacy.recall");

        Assert.NotNull(tweak);
        Assert.Equal(TweakCategory.Privacy, tweak.Category);
        Assert.Equal(SafetyLevel.Safe, tweak.Safety);
        Assert.NotNull(tweak.Apply);
        Assert.NotNull(tweak.Revert);
        Assert.NotNull(tweak.QueryState);
    }

    [Fact]
    public void RegHelper_Set_ThrowsUnauthorizedAccess_OnRestrictedKey()
    {
        var ex = Assert.Throws<System.UnauthorizedAccessException>(() =>
        {
            RegHelper.Set(@"HKEY_LOCAL_MACHINE\SECURITY\LogicFlowTweakTest", "Val", 1);
        });
        Assert.Contains("Administrator privileges are required", ex.Message);
    }

    [Fact]
    public void WindowsTweakEngine_ApplyTweak_NonExistent_ReturnsFalse()
    {
        var engine = new WindowsTweakEngine();
        var result = engine.ApplyTweak("non_existent_tweak_id");

        Assert.False(result.Success);
        Assert.Equal("Tweak not found", result.Error);
    }
}
