using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class TurboModeTests
{
    [Fact]
    public void BuiltInProfiles_HaveConsistentConfiguration()
    {
        var gaming = TurboMode.GamingProfile;
        Assert.NotNull(gaming);
        Assert.True(gaming.SwitchPowerPlan);
        Assert.True(gaming.SetHighPriority);
        Assert.True(gaming.DisableNotifications);
        Assert.Contains("SysMain", gaming.ServicesToStop);
        Assert.Contains("OneDrive", gaming.ProcessesToKill);

        var work = TurboMode.WorkProfile;
        Assert.NotNull(work);
        Assert.True(work.DisableNotifications);
        Assert.False(work.SetHighPriority);

        var battery = TurboMode.BatteryProfile;
        Assert.NotNull(battery);
        Assert.False(battery.SwitchPowerPlan); // Should not switch plan on battery

        var streaming = TurboMode.StreamingProfile;
        Assert.NotNull(streaming);
        Assert.True(streaming.SetHighPriority);

        var server = TurboMode.ServerProfile;
        Assert.NotNull(server);
        Assert.True(server.SwitchPowerPlan);
    }

    [Fact]
    public void ActivateAndDeactivate_ManagesStateAndActionsCleanly()
    {
        var turbo = new TurboMode();
        Assert.False(turbo.IsActive);

        // Test activation with a minimal custom profile to avoid disrupting test runner
        var testProfile = new TurboMode.TurboProfile
        {
            Name = "Test Boost",
            Description = "Safe test profile",
            ServicesToStop = ["NonExistentTestService12345"],
            ProcessesToKill = ["NonExistentTestProcess12345"],
            DisableNotifications = false,
            SetHighPriority = false,
            SwitchPowerPlan = false,
            OptimizeCpuAffinity = false,
            OptimizeNetwork = false,
            DisableVisualEffects = false,
            SetTimerResolution = false,
            BoostGpuPriority = false
        };

        var activateResult = turbo.Activate(testProfile);
        Assert.True(activateResult.Activated);
        Assert.True(turbo.IsActive);
        Assert.NotNull(activateResult.Actions);

        // Re-activating while active must return false
        var reActivateResult = turbo.Activate(testProfile);
        Assert.False(reActivateResult.Activated);
        Assert.Contains("already active", reActivateResult.Actions[0]);

        // Deactivation
        var deactivateResult = turbo.Deactivate();
        Assert.False(deactivateResult.Activated);
        Assert.False(turbo.IsActive);

        // Deactivating again when inactive must return false
        var reDeactivateResult = turbo.Deactivate();
        Assert.False(reDeactivateResult.Activated);
        Assert.Contains("not active", reDeactivateResult.Actions[0]);
    }

    [Fact]
    public void Activate_WhenServicesCannotBeStopped_ReportsHonestly()
    {
        var turbo = new TurboMode();

        // Profile requesting a service that requires admin (e.g. SysMain or WSearch)
        var profile = new TurboMode.TurboProfile
        {
            Name = "Test Unprivileged Boost",
            Description = "Testing elevation honesty",
            ServicesToStop = ["WSearch"],
            ProcessesToKill = [],
            DisableNotifications = false,
            SetHighPriority = false,
            SwitchPowerPlan = false,
            OptimizeCpuAffinity = false,
            OptimizeNetwork = false,
            DisableVisualEffects = false,
            SetTimerResolution = false,
            BoostGpuPriority = false
        };

        var result = turbo.Activate(profile);
        try
        {
            Assert.True(result.Activated);
            // If running un-elevated, servicesDisabled will be 0 and action indicates elevation required
            if (result.ServicesDisabled == 0)
            {
                Assert.Contains(result.Actions, a => a.Contains("Administrator privileges required", System.StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                Assert.Contains(result.Actions, a => a.Contains("Stopped", System.StringComparison.OrdinalIgnoreCase));
            }
        }
        finally
        {
            turbo.Deactivate();
        }
    }
}
