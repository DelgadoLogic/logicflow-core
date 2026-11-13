// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — DefenderHardenerEngineTests
// Comprehensive Unit & Integration Test Suite for Windows Defender Enterprise
// Hardening, 16 ASR Rules, PUA Protection, Cloud Defense, CFA, and Scans.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Moq;
using Microsoft.Win32;
using Xunit;

namespace LogicFlow.Tests;

public class DefenderHardenerEngineTests
{
    private const string DefenderPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string MpEnginePolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine";
    private const string SpynetPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
    private const string ExploitGuardAsrKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
    private const string AsrRulesKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string ControlledFolderKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 1: Catalog Integrity, GUID Validation, and Rule Metadata
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void KnownAsrRules_ContainsAll16EnterpriseRules()
    {
        var rules = DefenderHardenerEngine.KnownAsrRules;
        Assert.NotNull(rules);
        Assert.Equal(16, rules.Count);
    }

    [Fact]
    public void KnownAsrRules_AllRulesHaveValidGuidsNamesDescriptionsAndCategories()
    {
        foreach (var rule in DefenderHardenerEngine.KnownAsrRules)
        {
            Assert.True(Guid.TryParse(rule.Guid, out _), $"Rule GUID '{rule.Guid}' is not a valid GUID format.");
            Assert.False(string.IsNullOrWhiteSpace(rule.Name), "Rule Name must not be empty.");
            Assert.False(string.IsNullOrWhiteSpace(rule.Description), $"Rule '{rule.Name}' Description must not be empty.");
            Assert.False(string.IsNullOrWhiteSpace(rule.Category), $"Rule '{rule.Name}' Category must not be empty.");

            if (!string.IsNullOrEmpty(rule.AliasGuid))
            {
                Assert.True(Guid.TryParse(rule.AliasGuid, out _), $"Alias GUID '{rule.AliasGuid}' for rule '{rule.Name}' is not a valid GUID format.");
            }
        }
    }

    [Fact]
    public void KnownAsrRules_AllCanonicalGuidsAreUnique()
    {
        var guids = DefenderHardenerEngine.KnownAsrRules.Select(r => r.Guid.ToUpperInvariant()).ToList();
        var uniqueGuids = guids.Distinct().ToList();
        Assert.Equal(guids.Count, uniqueGuids.Count);
    }

    [Fact]
    public void KnownAsrRules_VerifySpecificCanonicalRulesExist()
    {
        var rules = DefenderHardenerEngine.KnownAsrRules;

        // 1. Email Executables
        Assert.Contains(rules, r => r.Guid.Equals("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", StringComparison.OrdinalIgnoreCase) && r.Category == "Email");

        // 2. Office Child Processes
        Assert.Contains(rules, r => r.Guid.Equals("D4F940AB-401B-4EFC-AADC-AD5F3C50688A", StringComparison.OrdinalIgnoreCase) && r.Category == "Office");

        // 3. Office Executable Creation
        Assert.Contains(rules, r => r.Guid.Equals("3B576869-A4EC-4529-8536-B80A7769E899", StringComparison.OrdinalIgnoreCase) && r.Category == "Office");

        // 4. Office Process Injection
        Assert.Contains(rules, r => r.Guid.Equals("75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", StringComparison.OrdinalIgnoreCase) && !r.SupportsWarn);

        // 5. Macro Win32 API
        Assert.Contains(rules, r => r.Guid.Equals("92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", StringComparison.OrdinalIgnoreCase) && !r.SupportsWarn);

        // 6. Comm App Child Process
        Assert.Contains(rules, r => r.Guid.Equals("26190899-1602-49E8-8B27-EB1D0A1CE869", StringComparison.OrdinalIgnoreCase));

        // 7. Adobe Reader Child Process
        Assert.Contains(rules, r => r.Guid.Equals("7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", StringComparison.OrdinalIgnoreCase));

        // 8. Obfuscated Scripts
        Assert.Contains(rules, r => r.Guid.Equals("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", StringComparison.OrdinalIgnoreCase));

        // 9. JS/VBS Executable Launches
        Assert.Contains(rules, r => r.Guid.Equals("D3E037E1-3EB8-44C8-A917-57927947596D", StringComparison.OrdinalIgnoreCase));

        // 10. WMI Persistence
        Assert.Contains(rules, r => r.Guid.Equals("E6DB77E5-3DF2-4CF1-B95A-636979351E5B", StringComparison.OrdinalIgnoreCase) && !r.SupportsWarn);

        // 11. LSASS Credential Theft
        Assert.Contains(rules, r => r.Guid.Equals("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", StringComparison.OrdinalIgnoreCase) && !r.SupportsWarn);

        // 12. Untrusted USB
        Assert.Contains(rules, r => r.Guid.Equals("B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", StringComparison.OrdinalIgnoreCase));

        // 13. Prevalence Criterion
        Assert.Contains(rules, r => r.Guid.Equals("01443614-CD74-433A-B99E-2ECDC07BFC25", StringComparison.OrdinalIgnoreCase));

        // 14. Advanced Ransomware Protection
        Assert.Contains(rules, r => r.Guid.Equals("C1DB55AB-C21A-4637-BB3F-A12568109D35", StringComparison.OrdinalIgnoreCase));

        // 15. PSExec and WMI Process Creation
        Assert.Contains(rules, r => r.Guid.Equals("D1E49AAC-8F56-4280-B9BA-993A6D77406C", StringComparison.OrdinalIgnoreCase) && !r.SupportsWarn);

        // 16. Vulnerable Signed Drivers
        Assert.Contains(rules, r => r.Guid.Equals("56A863A9-875E-4185-98A7-B882C64B5CE5", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block LSASS Credential Theft")]
    [InlineData("{9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2}", "Block LSASS Credential Theft")]
    [InlineData("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block LSASS Credential Theft")]
    [InlineData("5BEB8E2C-1807-453E-A1E0-8D3AEAB4C88F", "Block Obfuscated Scripts")] // Alias GUID
    [InlineData("5BEB7E2C-829E-4529-A96B-055520E3378E", "Block Obfuscated Scripts")] // Legacy GUID
    [InlineData("E6DB77E5-3DF2-4CF1-B95A-636979351E5B", "Block WMI Persistence")]
    [InlineData("E6DB77E5-3E12-4247-81D7-0E0E5F86BF94", "Block WMI Persistence")] // Legacy GUID
    [InlineData("Untrusted USB", "Block Untrusted USB Executables")]
    [InlineData("Ransomware", "Advanced Ransomware Protection")]
    public void FindRule_ResolvesCanonicalAliasLegacyAndFriendlyNames(string input, string expectedName)
    {
        var rule = DefenderHardenerEngine.FindRule(input);
        Assert.NotNull(rule);
        Assert.Equal(expectedName, rule.Name);
    }

    [Fact]
    public void FindRule_WithNullOrInvalidInput_ReturnsNull()
    {
        Assert.Null(DefenderHardenerEngine.FindRule(""));
        Assert.Null(DefenderHardenerEngine.FindRule("   "));
        Assert.Null(DefenderHardenerEngine.FindRule("00000000-0000-0000-0000-000000000000"));
        Assert.Null(DefenderHardenerEngine.FindRule("NonExistentRuleNamexyz123"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 2: State Modeling, Enums, and Computed Properties
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AsrRuleState_EnumValuesMatchMicrosoftSpec()
    {
        Assert.Equal(0, (int)AsrRuleState.Off);
        Assert.Equal(1, (int)AsrRuleState.Block);
        Assert.Equal(2, (int)AsrRuleState.Audit);
        Assert.Equal(5, (int)AsrRuleState.NotConfigured);
        Assert.Equal(6, (int)AsrRuleState.Warn);
    }

    [Fact]
    public void AsrRuleInfo_IsEnabledProperty_ReflectsBlockState()
    {
        var rule = new AsrRuleInfo { State = AsrRuleState.Off };
        Assert.False(rule.IsEnabled);

        rule.State = AsrRuleState.Block;
        Assert.True(rule.IsEnabled);

        rule.State = AsrRuleState.Audit;
        Assert.False(rule.IsEnabled);

        rule.State = AsrRuleState.Warn;
        Assert.False(rule.IsEnabled);

        // Test setter
        rule.IsEnabled = true;
        Assert.Equal(AsrRuleState.Block, rule.State);

        rule.IsEnabled = false;
        Assert.Equal(AsrRuleState.Off, rule.State);
    }

    [Fact]
    public void DefenderHardeningStatus_CalculatesActiveAndTotalCountsCorrectly()
    {
        var status = new DefenderHardeningStatus
        {
            AsrRules = new List<AsrRuleInfo>
            {
                new() { Guid = "G1", State = AsrRuleState.Block },
                new() { Guid = "G2", State = AsrRuleState.Block },
                new() { Guid = "G3", State = AsrRuleState.Audit },
                new() { Guid = "G4", State = AsrRuleState.Warn },
                new() { Guid = "G5", State = AsrRuleState.Off }
            }
        };

        Assert.Equal(5, status.TotalAsrRulesCount);
        Assert.Equal(2, status.ActiveAsrRulesCount);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 3: Status Querying with Mocked Registry
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStatusAsync_WhenRegistryIsEmpty_ReturnsAllDisabled()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.GetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>())).Returns((int?)null);
        mockReg.Setup(r => r.GetValues(It.IsAny<RegistryHive>(), It.IsAny<string>())).Returns(new Dictionary<string, object>());

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        Assert.NotNull(status);
        Assert.False(status.IsPuaProtectionEnabled);
        Assert.False(status.IsCloudProtectionEnabled);
        Assert.False(status.IsBlockAtFirstSightEnabled);
        Assert.False(status.IsControlledFolderAccessEnabled);
        Assert.Equal(16, status.TotalAsrRulesCount);
        Assert.Equal(0, status.ActiveAsrRulesCount);
        Assert.All(status.AsrRules, r => Assert.Equal(AsrRuleState.Off, r.State));
    }

    [Fact]
    public async Task GetStatusAsync_WhenRegistryPopulated_ReturnsAccurateActiveRulesAndToggles()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        // PUA Protection active
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection")).Returns(1);

        // Spynet Advanced MAPS = 2
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting")).Returns(2);

        // Submit samples = 1, Disable BAFS = 0
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent")).Returns(1);
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight")).Returns(0);

        // Controlled Folder Access = 1
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess")).Returns(1);

        // ASR rules dictionary: 2 in Block mode, 1 in Audit mode, 1 in Warn mode
        var rulesDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", 1 }, // Email Executables -> Block
            { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", 1 }, // LSASS -> Block
            { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", 2 }, // Office Child -> Audit
            { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", 6 }  // Obfuscated Scripts -> Warn
        };
        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey)).Returns(rulesDict);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        Assert.NotNull(status);
        Assert.True(status.IsPuaProtectionEnabled);
        Assert.True(status.IsCloudProtectionEnabled);
        Assert.True(status.IsBlockAtFirstSightEnabled);
        Assert.True(status.IsControlledFolderAccessEnabled);
        Assert.Equal(16, status.TotalAsrRulesCount);
        Assert.Equal(2, status.ActiveAsrRulesCount);

        var emailRule = status.AsrRules.First(r => r.Guid == "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550");
        Assert.Equal(AsrRuleState.Block, emailRule.State);
        Assert.True(emailRule.IsEnabled);

        var officeRule = status.AsrRules.First(r => r.Guid == "D4F940AB-401B-4EFC-AADC-AD5F3C50688A");
        Assert.Equal(AsrRuleState.Audit, officeRule.State);
        Assert.False(officeRule.IsEnabled);

        var scriptRule = status.AsrRules.First(r => r.Guid == "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC");
        Assert.Equal(AsrRuleState.Warn, scriptRule.State);
        Assert.False(scriptRule.IsEnabled);
    }

    [Fact]
    public async Task GetStatusAsync_HandlesStringNumericValuesInRegistry()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var rulesDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "1" }, // String "1" -> Block
            { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "2" }, // String "2" -> Audit
            { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "6" }  // String "6" -> Warn
        };
        mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, AsrRulesKey)).Returns(rulesDict);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var status = await engine.GetStatusAsync();

        Assert.Equal(1, (int)status.AsrRules.First(r => r.Guid == "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550").State);
        Assert.Equal(2, (int)status.AsrRules.First(r => r.Guid == "D4F940AB-401B-4EFC-AADC-AD5F3C50688A").State);
        Assert.Equal(6, (int)status.AsrRules.First(r => r.Guid == "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC").State);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 4: Enterprise Hardening and Revert Operations
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EnableEnterpriseHardeningAsync_WritesAll16RulesAndProtectionDwords()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.EnableEnterpriseHardeningAsync();

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.False(result.RequiresElevation);

        // Verify PUA keys
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 1), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus", 1), Times.Once);

        // Verify Spynet & BAFS keys
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 2), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent", 1), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 0), Times.Once);

        // Verify Controlled Folder Access
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", 1), Times.Once);

        // Verify Master ASR key
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, ExploitGuardAsrKey, "ExploitGuard_ASR_Rules", 1), Times.Once);

        // Verify all 16 ASR rules written in Block mode (1)
        foreach (var rule in DefenderHardenerEngine.KnownAsrRules)
        {
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid, 1), Times.Once);
        }
    }

    [Fact]
    public async Task EnableAllHardeningAsync_AliasMethod_ProducesSameResult()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.EnableAllHardeningAsync();

        Assert.NotNull(result);
        Assert.True(result.Success);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 1), Times.Once);
    }

    [Fact]
    public async Task RevertToDefaultsAsync_DeletesAllPolicyRegistryValues()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.RevertToDefaultsAsync();

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.False(result.RequiresElevation);

        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess"), Times.Once);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, ExploitGuardAsrKey, "ExploitGuard_ASR_Rules"), Times.Once);

        foreach (var rule in DefenderHardenerEngine.KnownAsrRules)
        {
            mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid), Times.Once);
        }
    }

    [Fact]
    public async Task RevertAllAsync_AliasMethod_ProducesSameResult()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.RevertAllAsync();

        Assert.NotNull(result);
        Assert.True(result.Success);
        mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection"), Times.Once);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 5: Granular Rule Management and Component Toggles
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Block, 1)]
    [InlineData("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Audit, 2)]
    [InlineData("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Warn, 6)]
    [InlineData("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Off, 0)]
    public async Task SetAsrRuleStateAsync_ValidRule_WritesCorrectDword(string guid, AsrRuleState state, int expectedVal)
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.SetAsrRuleStateAsync(guid, state);

        Assert.NotNull(result);
        Assert.True(result.Success);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, guid, expectedVal), Times.Once);
    }

    [Fact]
    public async Task SetAsrRuleStateAsync_UnknownRule_ReturnsFailure()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.SetAsrRuleStateAsync("00000000-0000-0000-0000-000000000000", AsrRuleState.Block);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Contains("Unknown ASR rule", result.ErrorMessage);
        mockReg.Verify(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task SetAsrRuleStateAsync_WarnModeOnUnsupportedRule_FallsBackToBlock()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        // LSASS rule does not support Warn mode
        const string lsassGuid = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2";

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.SetAsrRuleStateAsync(lsassGuid, AsrRuleState.Warn);

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.Contains("enforced Block mode", result.Output);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, lsassGuid, (int)AsrRuleState.Block), Times.Once);
    }

    [Fact]
    public async Task ToggleAsrRuleAsync_TogglesBetweenBlockAndOff()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        const string emailGuid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";

        // Current state is Block (1) -> should toggle to Off (0)
        mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, AsrRulesKey, emailGuid)).Returns(1);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.ToggleAsrRuleAsync(emailGuid);

        Assert.True(result.Success);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, AsrRulesKey, emailGuid, 0), Times.Once);
    }

    [Fact]
    public async Task SetPuaProtectionAsync_WritesCorrectDwords()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        // Enable Block mode (1)
        await engine.SetPuaProtectionAsync(true, auditOnly: false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 1), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus", 1), Times.Once);

        // Enable Audit mode (2)
        await engine.SetPuaProtectionAsync(true, auditOnly: true);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 2), Times.Once);

        // Disable (0)
        await engine.SetPuaProtectionAsync(false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 0), Times.Once);
    }

    [Fact]
    public async Task SetCloudProtectionAsync_WritesCorrectDwords()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        await engine.SetCloudProtectionAsync(true);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 2), Times.Once);

        await engine.SetCloudProtectionAsync(false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 0), Times.Once);
    }

    [Fact]
    public async Task SetBlockAtFirstSightAsync_WritesCorrectDwords()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        await engine.SetBlockAtFirstSightAsync(true);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 2), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent", 1), Times.Once);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 0), Times.Once);

        await engine.SetBlockAtFirstSightAsync(false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 1), Times.Once);
    }

    [Fact]
    public async Task SetControlledFolderAccessAsync_WritesCorrectDwords()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

        await engine.SetControlledFolderAccessAsync(true, auditOnly: false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", 1), Times.Once);

        await engine.SetControlledFolderAccessAsync(true, auditOnly: true);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", 2), Times.Once);

        await engine.SetControlledFolderAccessAsync(false);
        mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", 0), Times.Once);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 6: Process Discovery and Scan Invocation
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void LocateMpCmdRun_PrefersLatestPlatformVersionInProgramData()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var platformBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        mockRunner.Setup(r => r.DirectoryExists(platformBase)).Returns(true);
        mockRunner.Setup(r => r.GetDirectories(platformBase)).Returns(new[]
        {
            Path.Combine(platformBase, "4.18.24070.5-0"),
            Path.Combine(platformBase, "4.18.24080.9-0")
        });

        var expectedPath = Path.Combine(platformBase, "4.18.24080.9-0", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(expectedPath)).Returns(true);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var binary = engine.LocateMpCmdRun();

        Assert.Equal(expectedPath, binary);
    }

    [Fact]
    public void LocateMpCmdRun_FallsBackToProgramFilesWhenPlatformMissing()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var platformBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        mockRunner.Setup(r => r.DirectoryExists(platformBase)).Returns(false);

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var binary = engine.LocateMpCmdRun();

        Assert.Equal(progFilesPath, binary);
    }

    [Fact]
    public async Task TriggerScanAsync_QuickScan_PassesCorrectArguments()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        mockRunner.Setup(r => r.RunAsync(progFilesPath, "-Scan -ScanType 1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Scan completed successfully." });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick);

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("Scan completed successfully.", result.ScanOutput);
        mockRunner.Verify(r => r.RunAsync(progFilesPath, "-Scan -ScanType 1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task TriggerScanAsync_FullScan_PassesCorrectArguments()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        mockRunner.Setup(r => r.RunAsync(progFilesPath, "-Scan -ScanType 2", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Full scan complete." });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Full);

        Assert.NotNull(result);
        Assert.True(result.Success);
        mockRunner.Verify(r => r.RunAsync(progFilesPath, "-Scan -ScanType 2", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task TriggerScanAsync_OfflineBoot_InvokesPowerShell()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockRunner.Setup(r => r.RunAsync("powershell.exe", It.Is<string>(a => a.Contains("Start-MpWDOScan")), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "WDO scan scheduled." });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.OfflineBoot);

        Assert.NotNull(result);
        Assert.True(result.Success);
        mockRunner.Verify(r => r.RunAsync("powershell.exe", It.Is<string>(a => a.Contains("Start-MpWDOScan")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task TriggerScanAsync_WhenBinaryNotFound_ReturnsFailure()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        // All paths return false
        mockRunner.Setup(r => r.FileExists(It.IsAny<string>())).Returns(false);
        mockRunner.Setup(r => r.DirectoryExists(It.IsAny<string>())).Returns(false);

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Contains("could not be located", result.ErrorMessage);
    }

    [Fact]
    public async Task TriggerScanAsync_ExitCode2_TreatedAsSuccessWithThreatCleaned()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        // ExitCode 2 means malware was found and successfully cleaned
        mockRunner.Setup(r => r.RunAsync(progFilesPath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessExecutionResult { ExitCode = 2, StandardOutput = "Threat identified and remediated." });

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick);

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public async Task TriggerScanAsync_HonorsCancellationToken()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        var progFilesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        mockRunner.Setup(r => r.FileExists(progFilesPath)).Returns(true);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        mockRunner.Setup(r => r.RunAsync(progFilesPath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.TriggerScanAsync(DefenderScanType.Quick, cts.Token);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Contains("canceled", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 7: Elevation and Error Resilience (Fault Injection)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EnableEnterpriseHardeningAsync_WhenUnauthorizedAccessException_ReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()))
            .Throws(new UnauthorizedAccessException("Access to the registry key is denied."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.EnableEnterpriseHardeningAsync();

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("elevation required", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RevertToDefaultsAsync_WhenUnauthorizedAccessException_ReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.DeleteValue(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>()))
            .Throws(new UnauthorizedAccessException("Access to the registry key is denied."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.RevertToDefaultsAsync();

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
    }

    [Fact]
    public async Task SetAsrRuleStateAsync_WhenUnauthorizedAccessException_ReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()))
            .Throws(new UnauthorizedAccessException("Access is denied."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.SetAsrRuleStateAsync("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", AsrRuleState.Block);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
    }

    [Fact]
    public async Task SetPuaProtectionAsync_WhenSecurityException_ReturnsRequiresElevation()
    {
        var mockReg = new Mock<IRegistryService>();
        var mockRunner = new Mock<IProcessRunner>();

        mockReg.Setup(r => r.SetDword(It.IsAny<RegistryHive>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>()))
            .Throws(new SecurityException("Security violation."));

        var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
        var result = await engine.SetPuaProtectionAsync(true);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 8: Live System Execution Smoke Test
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStatusAsync_LiveSystemExecution_ExecutesWithoutCrashing()
    {
        var engine = new DefenderHardenerEngine();
        var status = await engine.GetStatusAsync();

        Assert.NotNull(status);
        Assert.NotNull(status.AsrRules);
        Assert.Equal(16, status.AsrRules.Count);
        Assert.True(status.ActiveAsrRulesCount >= 0);
        Assert.Equal(16, status.TotalAsrRulesCount);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suite 9: JSON Serialization and Model Roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void DefenderHardeningStatus_JsonSerialization_RoundtripsSuccessfully()
    {
        var original = new DefenderHardeningStatus
        {
            IsPuaProtectionEnabled = true,
            IsCloudProtectionEnabled = true,
            IsBlockAtFirstSightEnabled = true,
            IsControlledFolderAccessEnabled = true,
            AsrRules = new List<AsrRuleInfo>
            {
                new() { Guid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", Name = "Email Rule", State = AsrRuleState.Block, Category = "Email" }
            }
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<DefenderHardeningStatus>(json);

        Assert.NotNull(deserialized);
        Assert.True(deserialized.IsPuaProtectionEnabled);
        Assert.True(deserialized.IsCloudProtectionEnabled);
        Assert.Equal(1, deserialized.ActiveAsrRulesCount);
        Assert.Equal("Email Rule", deserialized.AsrRules[0].Name);
        Assert.Equal(AsrRuleState.Block, deserialized.AsrRules[0].State);
    }

    [Fact]
    public void DefenderOperationResult_JsonSerialization_RoundtripsSuccessfully()
    {
        var original = DefenderOperationResult.Ok("TestOperation", "Operation completed.");
        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<DefenderOperationResult>(json);

        Assert.NotNull(deserialized);
        Assert.Equal("TestOperation", deserialized.Action);
        Assert.True(deserialized.Success);
        Assert.Equal("Operation completed.", deserialized.Output);
    }

    [Fact]
    public void DefenderScanResult_JsonSerialization_RoundtripsSuccessfully()
    {
        var original = new DefenderScanResult
        {
            Action = "TriggerScan_Quick",
            ScanType = DefenderScanType.Quick,
            Success = true,
            ExitCode = 0,
            ScanOutput = "No malware detected.",
            Duration = TimeSpan.FromSeconds(15)
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<DefenderScanResult>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(DefenderScanType.Quick, deserialized.ScanType);
        Assert.Equal(0, deserialized.ExitCode);
        Assert.Equal("No malware detected.", deserialized.ScanOutput);
        Assert.True(deserialized.Success);
    }
}
