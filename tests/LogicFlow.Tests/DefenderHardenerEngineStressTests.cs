// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — DefenderHardenerEngineStressTests
// Adversarial Stress Harness & Empirical Challenge Suite for DefenderHardenerEngine
// ─────────────────────────────────────────────────────────────────────────────

using System;
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

public class DefenderHardenerEngineStressTests
{
    private const string DefenderPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string MpEnginePolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine";
    private const string SpynetPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
    private const string ExploitGuardAsrKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
    private const string AsrRulesKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string ControlledFolderKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 1: Exhaustive GUID & Alias Lookups (Adversarial Variations)
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550")] // lowercase
    [InlineData("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550")] // uppercase
    [InlineData("{BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550}")] // braced
    [InlineData("  BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550  ")] // whitespace padded
    [InlineData("  {be9ba2d9-53ea-4cdc-84e5-9b1eeee46550}  ")] // braced + whitespace
    public void FindRule_AdversarialFormatting_ResolvesCorrectly(string input)
    {
        var rule = DefenderHardenerEngine.FindRule(input);
        Assert.NotNull(rule);
        Assert.Equal("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", rule.Guid, ignoreCase: true);
        Assert.Equal("Block Executables from Email", rule.Name);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    [InlineData("not-a-guid")]
    [InlineData("12345")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("!@#$%^&*()")]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("SELECT * FROM Rules; DROP TABLE Rules;--")]
    public void FindRule_MalformedOrAdversarialInputs_ReturnsNullSafely(string? input)
    {
        var rule = DefenderHardenerEngine.FindRule(input!);
        Assert.Null(rule);
    }

    [Fact]
    public void KnownAsrRules_All16Rules_HaveDistinctNamesAndGuids()
    {
        var rules = DefenderHardenerEngine.KnownAsrRules;
        Assert.Equal(16, rules.Count);

        var guids = rules.Select(r => r.Guid.ToUpperInvariant()).ToHashSet();
        Assert.Equal(16, guids.Count);

        var names = rules.Select(r => r.Name.ToUpperInvariant()).ToHashSet();
        Assert.Equal(16, names.Count);
    }

    [Fact]
    public void KnownAsrRules_VerifyAll5WarnUnsupportedRules_ExplicitlyConfigured()
    {
        var rules = DefenderHardenerEngine.KnownAsrRules;

        // The 5 rules documented by Microsoft as not supporting Warn mode:
        var warnUnsupportedGuids = new[]
        {
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Block Office Process Injection
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Block Win32 API Calls from Macros
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", // Block WMI Persistence
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", // Block LSASS Credential Theft
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C"  // Block PSExec and WMI Process Creation
        };

        foreach (var guid in warnUnsupportedGuids)
        {
            var rule = rules.FirstOrDefault(r => string.Equals(r.Guid, guid, StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(rule);
            Assert.False(rule.SupportsWarn, $"Rule '{rule.Name}' ({guid}) should have SupportsWarn = false");
        }

        // Verify the remaining 11 rules support Warn mode
        var warnSupportedRules = rules.Where(r => !warnUnsupportedGuids.Contains(r.Guid, StringComparer.OrdinalIgnoreCase)).ToList();
        Assert.Equal(11, warnSupportedRules.Count);
        Assert.All(warnSupportedRules, r => Assert.True(r.SupportsWarn, $"Rule '{r.Name}' ({r.Guid}) should have SupportsWarn = true"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 2: Boundary Inputs and Out-of-Range Registry Integer States
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(0, AsrRuleState.Off)]
    [InlineData(1, AsrRuleState.Block)]
    [InlineData(2, AsrRuleState.Audit)]
    [InlineData(5, AsrRuleState.NotConfigured)]
    [InlineData(6, AsrRuleState.Warn)]
    [InlineData(-1, AsrRuleState.Off)]
    [InlineData(3, AsrRuleState.Off)]
    [InlineData(4, AsrRuleState.Off)]
    [InlineData(7, AsrRuleState.Off)]
    [InlineData(999, AsrRuleState.Off)]
    [InlineData(int.MinValue, AsrRuleState.Off)]
    [InlineData(int.MaxValue, AsrRuleState.Off)]
    public async Task GetStatusAsync_VariousIntegerDwordsInRegistry_MapsSafely(int rawValue, AsrRuleState expectedState)
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var testGuid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
        var rulesDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            { testGuid, rawValue }
        };
        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey)).Returns(rulesDict);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        var rule = status.AsrRules.First(r => r.Guid == testGuid);
        Assert.Equal(expectedState, rule.State);
    }

    [Theory]
    [InlineData("0", AsrRuleState.Off)]
    [InlineData("1", AsrRuleState.Block)]
    [InlineData("2", AsrRuleState.Audit)]
    [InlineData("5", AsrRuleState.NotConfigured)]
    [InlineData("6", AsrRuleState.Warn)]
    [InlineData("invalid_string", AsrRuleState.Off)]
    [InlineData("", AsrRuleState.Off)]
    public async Task GetStatusAsync_StringRegistryValues_MapsSafely(string rawString, AsrRuleState expectedState)
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var testGuid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
        var rulesDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            { testGuid, rawString }
        };
        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey)).Returns(rulesDict);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        var rule = status.AsrRules.First(r => r.Guid == testGuid);
        Assert.Equal(expectedState, rule.State);
    }

    [Fact]
    public async Task SetAsrRuleStateAsync_SettingOutOfRangeEnum_WritesCastValue()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var testGuid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        // Cast invalid int 99 as AsrRuleState
        var result = await engine.SetAsrRuleStateAsync(testGuid, (AsrRuleState)99);

        Assert.True(result.Success);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, testGuid, 99), Times.Once);
    }

    [Fact]
    public void SetAsrRuleState_All5WarnUnsupportedRules_EnforceBlockWhenWarnRequested()
    {
        var warnUnsupportedGuids = new[]
        {
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Block Office Process Injection
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Block Win32 API Calls from Macros
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", // Block WMI Persistence
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", // Block LSASS Credential Theft
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C"  // Block PSExec and WMI Process Creation
        };

        foreach (var guid in warnUnsupportedGuids)
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var result = engine.SetAsrRuleState(guid, AsrRuleState.Warn);

            Assert.True(result.Success);
            Assert.Contains("enforced Block mode", result.Output);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, guid, 1), Times.Once);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 3: Cancellation Token Propagation in Scans
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TriggerScanAsync_QuickScan_PropagatesCancellationTokenToRunner()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        using var cts = new CancellationTokenSource();
        var token = cts.Token;

        CancellationToken capturedToken = default;
        mockRunner.Setup(r => r.RunAsync(progFilesPath, "-Scan -ScanType 1", It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((f, a, ct) => capturedToken = ct)
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "OK" });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick, token);

        Assert.True(result.Success);
        Assert.Equal(token, capturedToken);
    }

    [Fact]
    public async Task TriggerScanAsync_OfflineBoot_PropagatesCancellationTokenToRunner()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        using var cts = new CancellationTokenSource();
        var token = cts.Token;

        CancellationToken capturedToken = default;
        mockRunner.Setup(r => r.RunAsync("powershell.exe", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((f, a, ct) => capturedToken = ct)
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "WDO scheduled" });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.OfflineBoot, token);

        Assert.True(result.Success);
        Assert.Equal(token, capturedToken);
    }

    [Fact]
    public async Task TriggerScanAsync_WhenCancelledMidExecution_ReturnsCanceledResult()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        using var cts = new CancellationTokenSource();

        mockRunner.Setup(r => r.RunAsync(progFilesPath, "-Scan -ScanType 2", It.IsAny<CancellationToken>()))
            .Returns<string, string, CancellationToken>(async (f, a, ct) =>
            {
                // Only cancellation can end this fake scan, so a slow/starved test host cannot let it finish first.
                await Task.Delay(Timeout.Infinite, ct);
                return new ProcessExecutionResult { ExitCode = 0 };
            });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        cts.CancelAfter(20);

        var result = await engine.TriggerScanAsync(DefenderScanType.Full, cts.Token);

        Assert.False(result.Success);
        Assert.Contains("canceled", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 4: MpCmdRun Discovery Order and Execution Error Handling
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void LocateMpCmdRun_DiscoversPlatformVersionsInDescendingOrder()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var platformBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        mockRunner.Setup(r => r.DirectoryExists(platformBase)).Returns(true);
        mockRunner.Setup(r => r.GetDirectories(platformBase)).Returns(new[]
        {
            Path.Combine(platformBase, "4.18.23010.1-0"),
            Path.Combine(platformBase, "4.18.24080.9-0"),
            Path.Combine(platformBase, "4.18.23110.4-0"),
            Path.Combine(platformBase, "4.18.24010.7-0")
        });

        var expectedPath = Path.Combine(platformBase, "4.18.24080.9-0", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(expectedPath)).Returns(true);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var binary = engine.LocateMpCmdRun();

        Assert.Equal(expectedPath, binary);
    }

    [Theory]
    [InlineData(1, false)] // MpCmdRun generic error
    [InlineData(-1, false)] // Process error
    [InlineData(1603, false)] // Fatal error
    [InlineData(0, true)] // Clean
    [InlineData(2, true)] // Threats found and cleaned
    public async Task TriggerScanAsync_ExitCodes_HandledCorrectly(int exitCode, bool expectedSuccess)
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        mockRunner.Setup(r => r.RunAsync(progFilesPath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult
            {
                ExitCode = exitCode,
                StandardOutput = "Scan output",
                StandardError = exitCode == 0 || exitCode == 2 ? "" : "Scan error occurred"
            });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick);

        Assert.Equal(expectedSuccess, result.Success);
        Assert.Equal(exitCode, result.ExitCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 5: WMI Provider Error Resilience
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStatusAsync_WhenWmiProviderThrows_FallsBackGracefullyWithoutCrashing()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();
        var mockWmi = new Mock<IWmiDefenderProvider>();

        mockWmi.Setup(w => w.EnrichStatus(It.IsAny<DefenderHardeningStatus>()))
            .Throws(new InvalidOperationException("WMI query failed"));

        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey))
            .Returns(new Dictionary<string, object>());

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object, mockWmi.Object);
        var status = await engine.GetStatusAsync();

        Assert.NotNull(status);
        Assert.Equal(16, status.TotalAsrRulesCount);
        Assert.Equal("WMI query failed", status.ErrorMessage);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 6: Concurrency & Stress Load
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task HighConcurrency_MultiThreadedInvocations_ExecuteWithoutRaceConditions()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey))
            .Returns(new Dictionary<string, object>
            {
                { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", 1 }
            });

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);
        mockRunner.Setup(r => r.RunAsync(progFilesPath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Clean" });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        var tasks = new List<Task>();
        for (int i = 0; i < 50; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                var s = await engine.GetStatusAsync();
                Assert.NotNull(s);
            }));

            tasks.Add(Task.Run(async () =>
            {
                var r = await engine.EnableEnterpriseHardeningAsync();
                Assert.True(r.Success);
            }));

            tasks.Add(Task.Run(async () =>
            {
                var r = await engine.SetAsrRuleStateAsync("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Audit);
                Assert.True(r.Success);
            }));

            tasks.Add(Task.Run(async () =>
            {
                var scan = await engine.TriggerScanAsync(DefenderScanType.Quick);
                Assert.True(scan.Success);
            }));
        }

        await Task.WhenAll(tasks);
    }
}
