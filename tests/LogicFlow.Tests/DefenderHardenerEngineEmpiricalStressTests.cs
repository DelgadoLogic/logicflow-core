// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — DefenderHardenerEngineEmpiricalStressTests
// Empirical Challenger 2 Stress Test Suite:
// Concurrency, Thread Safety, Error Handling & Missing Binary Scenarios
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Microsoft.Win32;
using Moq;
using Xunit;

namespace LogicFlow.Tests;

public class DefenderHardenerEngineEmpiricalStressTests
{
    private class ThreadSafeMockRegistry : IRegistryService
    {
        public ConcurrentDictionary<string, object> Store { get; } = new(StringComparer.OrdinalIgnoreCase);

        private static string Key(RegistryHive hive, string subKey, string valueName) => $"{hive}\\{subKey}\\{valueName}";

        public int? GetDword(RegistryHive hive, string subKey, string valueName)
        {
            if (Store.TryGetValue(Key(hive, subKey, valueName), out var val))
            {
                if (val is int i) return i;
                if (val is string s && int.TryParse(s, out var parsed)) return parsed;
            }
            return null;
        }

        public string? GetString(RegistryHive hive, string subKey, string valueName)
        {
            if (Store.TryGetValue(Key(hive, subKey, valueName), out var val) && val is string s)
            {
                return s;
            }
            return null;
        }

        public void SetDword(RegistryHive hive, string subKey, string valueName, int value)
        {
            Store[Key(hive, subKey, valueName)] = value;
        }

        public void SetString(RegistryHive hive, string subKey, string valueName, string value)
        {
            Store[Key(hive, subKey, valueName)] = value;
        }

        public void DeleteValue(RegistryHive hive, string subKey, string valueName)
        {
            Store.TryRemove(Key(hive, subKey, valueName), out _);
        }

        public IReadOnlyDictionary<string, object> GetValues(RegistryHive hive, string subKey)
        {
            var prefix = $"{hive}\\{subKey}\\";
            var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in Store)
            {
                if (kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var valName = kvp.Key.Substring(prefix.Length);
                    dict[valName] = kvp.Value;
                }
            }
            return dict;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Concurrency & Race Condition Stress Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StressTest_ConcurrentGetStatusAsync_100ParallelTasks_SucceedsWithoutDeadlockOrCorruption()
    {
        var threadSafeReg = new ThreadSafeMockRegistry();
        threadSafeReg.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 1);
        threadSafeReg.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting", 2);

        var mockRunner = new Mock<IProcessRunner>();
        var engine = new DefenderHardenerEngine(threadSafeReg, mockRunner.Object);

        var tasks = Enumerable.Range(0, 100).Select(async i =>
        {
            await Task.Yield();
            var status = await engine.GetStatusAsync();
            Assert.NotNull(status);
            Assert.True(status.IsPuaProtectionEnabled);
            Assert.True(status.IsCloudProtectionEnabled);
            Assert.Equal(16, status.TotalAsrRulesCount);
            return status;
        });

        var results = await Task.WhenAll(tasks);
        Assert.Equal(100, results.Length);
    }

    [Fact]
    public async Task StressTest_ConcurrentEnableAndRevert_100ParallelTasks_NoUnhandledExceptions()
    {
        var threadSafeReg = new ThreadSafeMockRegistry();
        var mockRunner = new Mock<IProcessRunner>();
        var engine = new DefenderHardenerEngine(threadSafeReg, mockRunner.Object);

        var tasks = Enumerable.Range(0, 100).Select(async i =>
        {
            await Task.Yield();
            if (i % 3 == 0)
            {
                var result = await engine.EnableEnterpriseHardeningAsync();
                Assert.True(result.Success);
            }
            else if (i % 3 == 1)
            {
                var result = await engine.RevertToDefaultsAsync();
                Assert.True(result.Success);
            }
            else
            {
                var status = await engine.GetStatusAsync();
                Assert.NotNull(status);
            }
        });

        await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task StressTest_ConcurrentGranularToggles_50ParallelTasks_ThreadSafeExecution()
    {
        var threadSafeReg = new ThreadSafeMockRegistry();
        var mockRunner = new Mock<IProcessRunner>();
        var engine = new DefenderHardenerEngine(threadSafeReg, mockRunner.Object);

        var rules = DefenderHardenerEngine.KnownAsrRules;

        var tasks = Enumerable.Range(0, 50).Select(async i =>
        {
            var rule = rules[i % rules.Count];
            var state = (AsrRuleState)((i % 4 == 3) ? 6 : (i % 4));
            var result = await engine.SetAsrRuleStateAsync(rule.Guid, state);
            Assert.True(result.Success);

            var toggleResult = await engine.ToggleAsrRuleAsync(rule.Guid);
            Assert.True(toggleResult.Success);
        });

        await Task.WhenAll(tasks);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Registry Exception Resilience (SecurityException & UnauthorizedAccessException)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SecurityException_OnAllMutatingMethods_GracefullyReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()))
            .Throws(new SecurityException("Registry access forbidden by code access security."));
        mockReg.Setup(r => r.DeleteValue(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>()))
            .Throws(new SecurityException("Registry delete forbidden by code access security."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        // 1. EnableEnterpriseHardeningAsync
        var r1 = await engine.EnableEnterpriseHardeningAsync();
        Assert.False(r1.Success);
        Assert.True(r1.RequiresElevation);
        Assert.Contains("elevation required", r1.ErrorMessage, StringComparison.OrdinalIgnoreCase);

        // 2. RevertToDefaultsAsync
        var r2 = await engine.RevertToDefaultsAsync();
        Assert.False(r2.Success);
        Assert.True(r2.RequiresElevation);
        Assert.Contains("elevation required", r2.ErrorMessage, StringComparison.OrdinalIgnoreCase);

        // 3. SetAsrRuleStateAsync
        var r3 = await engine.SetAsrRuleStateAsync("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Block);
        Assert.False(r3.Success);
        Assert.True(r3.RequiresElevation);

        // 4. SetPuaProtectionAsync
        var r4 = await engine.SetPuaProtectionAsync(true);
        Assert.False(r4.Success);
        Assert.True(r4.RequiresElevation);

        // 5. SetCloudProtectionAsync
        var r5 = await engine.SetCloudProtectionAsync(true);
        Assert.False(r5.Success);
        Assert.True(r5.RequiresElevation);

        // 6. SetBlockAtFirstSightAsync
        var r6 = await engine.SetBlockAtFirstSightAsync(true);
        Assert.False(r6.Success);
        Assert.True(r6.RequiresElevation);

        // 7. SetControlledFolderAccessAsync
        var r7 = await engine.SetControlledFolderAccessAsync(true);
        Assert.False(r7.Success);
        Assert.True(r7.RequiresElevation);
    }

    [Fact]
    public async Task UnauthorizedAccessException_OnAllMutatingMethods_GracefullyReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()))
            .Throws(new UnauthorizedAccessException("Access to registry key denied."));
        mockReg.Setup(r => r.DeleteValue(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>()))
            .Throws(new UnauthorizedAccessException("Access to registry key denied."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        // 1. EnableEnterpriseHardeningAsync
        var r1 = await engine.EnableEnterpriseHardeningAsync();
        Assert.False(r1.Success);
        Assert.True(r1.RequiresElevation);

        // 2. RevertToDefaultsAsync
        var r2 = await engine.RevertToDefaultsAsync();
        Assert.False(r2.Success);
        Assert.True(r2.RequiresElevation);

        // 3. SetAsrRuleStateAsync
        var r3 = await engine.SetAsrRuleStateAsync("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Block);
        Assert.False(r3.Success);
        Assert.True(r3.RequiresElevation);

        // 4. SetPuaProtectionAsync
        var r4 = await engine.SetPuaProtectionAsync(true);
        Assert.False(r4.Success);
        Assert.True(r4.RequiresElevation);

        // 5. SetCloudProtectionAsync
        var r5 = await engine.SetCloudProtectionAsync(true);
        Assert.False(r5.Success);
        Assert.True(r5.RequiresElevation);

        // 6. SetBlockAtFirstSightAsync
        var r6 = await engine.SetBlockAtFirstSightAsync(true);
        Assert.False(r6.Success);
        Assert.True(r6.RequiresElevation);

        // 7. SetControlledFolderAccessAsync
        var r7 = await engine.SetControlledFolderAccessAsync(true);
        Assert.False(r7.Success);
        Assert.True(r7.RequiresElevation);
    }

    [Fact]
    public async Task GetStatusAsync_WhenRegistryThrowsUnexpectedException_CapturesErrorMessageGracefully()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.GetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>()))
            .Throws(new InvalidOperationException("Registry hive corrupted or locked."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        Assert.NotNull(status);
        Assert.NotNull(status.ErrorMessage);
        Assert.Contains("Registry hive corrupted", status.ErrorMessage);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. MpCmdRun Missing Binary Behavior & Failure Fallbacks
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TriggerScanAsync_WhenMpCmdRunMissingEverywhere_ReturnsCleanFailureWithExitCodeMinusOne()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockRunner.Setup(r => r.DirectoryExists(It.IsAny<string>())).Returns(false);
        mockRunner.Setup(r => r.FileExists(It.IsAny<string>())).Returns(false);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        var qResult = await engine.TriggerScanAsync(DefenderScanType.Quick);
        Assert.NotNull(qResult);
        Assert.False(qResult.Success);
        Assert.Equal(-1, qResult.ExitCode);
        Assert.Contains("MpCmdRun.exe executable could not be located", qResult.ErrorMessage);

        var fResult = await engine.TriggerScanAsync(DefenderScanType.Full);
        Assert.NotNull(fResult);
        Assert.False(fResult.Success);
        Assert.Equal(-1, fResult.ExitCode);
        Assert.Contains("MpCmdRun.exe executable could not be located", fResult.ErrorMessage);
    }

    [Fact]
    public async Task TriggerScanAsync_WhenMpCmdRunThrowsProcessException_CatchesAndReturnsStructuredFailure()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFiles)).Returns(true);
        mockRunner.Setup(r => r.RunAsync(progFiles, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new System.ComponentModel.Win32Exception(5, "Access is denied launching MpCmdRun.exe"));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("Access is denied", result.ErrorMessage);
    }
}
