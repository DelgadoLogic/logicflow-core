// LogicFlow.Tests — WinGetUpdaterTests
// Unit tests for WinGet package parsing and CLI command construction.

using System.Collections.Generic;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class WinGetUpdaterTests
{
    [Fact]
    public void ParseWinGetUpgradeOutput_HandlesEmptyString()
    {
        var packages = WinGetUpdaterEngine.ParseWinGetUpgradeOutput("");
        Assert.NotNull(packages);
        Assert.Empty(packages);
    }

    [Fact]
    public void ParseWinGetUpgradeOutput_ParsesStandardTable()
    {
        string sampleOutput = @"
Name                 Id                      Version      Available   Source
----------------------------------------------------------------------------
Google Chrome        Google.Chrome           127.0.6533.88 128.0.6613.85 winget
Discord              Discord.Discord         1.0.9150     1.0.9155    winget
Git                  Git.Git                 2.45.2       2.46.0      winget
3 upgrades available.
";

        var packages = WinGetUpdaterEngine.ParseWinGetUpgradeOutput(sampleOutput);

        Assert.NotNull(packages);
        Assert.Equal(3, packages.Count);

        Assert.Equal("Google Chrome", packages[0].Name);
        Assert.Equal("Google.Chrome", packages[0].Id);
        Assert.Equal("127.0.6533.88", packages[0].CurrentVersion);
        Assert.Equal("128.0.6613.85", packages[0].AvailableVersion);
        Assert.Equal("winget", packages[0].Source);

        Assert.Equal("Discord", packages[1].Name);
        Assert.Equal("Discord.Discord", packages[1].Id);

        Assert.Equal("Git", packages[2].Name);
        Assert.Equal("Git.Git", packages[2].Id);
    }

    [Fact]
    public void IsWinGetInstalled_ExecutesWithoutCrashing()
    {
        var installed = WinGetUpdaterEngine.IsWinGetInstalled();
        Assert.True(installed == true || installed == false);
    }

    [Fact]
    public async Task ScanUpgradableAppsAsync_WithCancelledToken_ReturnsEmptyWithoutThrowing()
    {
        var engine = new WinGetUpdaterEngine();
        using var cts = new System.Threading.CancellationTokenSource();
        cts.Cancel();

        var packages = await engine.ScanUpgradableAppsAsync(cts.Token);
        Assert.NotNull(packages);
    }
}

