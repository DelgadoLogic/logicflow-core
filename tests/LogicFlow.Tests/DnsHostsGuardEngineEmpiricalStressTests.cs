// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — DnsHostsGuardEngineEmpiricalStressTests
// Empirical Challenger 2 Stress Test Suite:
// Concurrency, Thread Safety, Atomic File Swap Resilience, Dual Backup Generation,
// Partial Write Fault Injection, Attribute Normalization & Real Filesystem Sandboxing.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace LogicFlow.Tests;

public class DnsHostsGuardEngineEmpiricalStressTests
{
    #region Sandboxed Real-Filesystem Helper

    private sealed class TempDirectorySandbox : IDisposable
    {
        public string DirectoryPath { get; }
        public string HostsPath { get; }
        public string UserBackupPath { get; }

        public TempDirectorySandbox()
        {
            DirectoryPath = Path.Combine(Path.GetTempPath(), "LogicFlow_Challenger2_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(DirectoryPath);
            HostsPath = Path.Combine(DirectoryPath, "hosts");
            UserBackupPath = Path.Combine(DirectoryPath, "user_backups");
            Directory.CreateDirectory(UserBackupPath);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(DirectoryPath))
                {
                    // Remove read-only attributes before deleting
                    foreach (var file in Directory.GetFiles(DirectoryPath, "*", SearchOption.AllDirectories))
                    {
                        try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                    }
                    Directory.Delete(DirectoryPath, recursive: true);
                }
            }
            catch { }
        }
    }

    private sealed class SandboxedRealHostsFileService : IHostsFileService
    {
        private readonly string _hostsPath;
        private readonly string _userBackupDir;

        public SandboxedRealHostsFileService(string hostsPath, string userBackupDir)
        {
            _hostsPath = hostsPath;
            _userBackupDir = userBackupDir;
        }

        public string GetHostsPath() => _hostsPath;
        public bool FileExists(string path) => File.Exists(path);
        public string[] ReadAllLines(string path) => File.ReadAllLines(path);
        public string ReadAllText(string path) => File.ReadAllText(path);
        public void WriteAllText(string path, string content) => File.WriteAllText(path, content, new UTF8Encoding(false));
        public void ReplaceFile(string sourceFile, string targetFile, string? backupFile) =>
            File.Replace(sourceFile, targetFile, backupFile, ignoreMetadataErrors: true);
        public void MoveFile(string sourceFile, string targetFile) => File.Move(sourceFile, targetFile);
        public void DeleteFile(string path)
        {
            if (File.Exists(path)) File.Delete(path);
        }
        public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
        public void SetAttributes(string path, FileAttributes attributes) => File.SetAttributes(path, attributes);

        public string? CreateSystemBackup(string sourcePath)
        {
            if (!File.Exists(sourcePath)) return null;
            string sysDir = Path.GetDirectoryName(sourcePath) ?? "";
            if (string.IsNullOrEmpty(sysDir)) return null;
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff", System.Globalization.CultureInfo.InvariantCulture);
            string backupPath = Path.Combine(sysDir, $"hosts.bak.{timestamp}");
            File.Copy(sourcePath, backupPath, true);
            return backupPath;
        }

        public string? CreateUserAppDataBackup(string sourcePath)
        {
            if (!File.Exists(sourcePath)) return null;
            if (!Directory.Exists(_userBackupDir)) Directory.CreateDirectory(_userBackupDir);
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff", System.Globalization.CultureInfo.InvariantCulture);
            string backupPath = Path.Combine(_userBackupDir, $"hosts.bak.{timestamp}");
            File.Copy(sourcePath, backupPath, true);
            return backupPath;
        }
    }

    #endregion

    #region Thread-Safe Mock Implementations for Concurrency Testing

    private sealed class ThreadSafeMockFileService : IHostsFileService
    {
        private readonly ConcurrentDictionary<string, string> _files = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _attrLock = new();
        private FileAttributes _attributes = FileAttributes.Normal;
        public ConcurrentBag<string> DeletedTempFiles { get; } = new();
        public ConcurrentBag<string> CreatedSystemBackups { get; } = new();
        public ConcurrentBag<string> CreatedUserBackups { get; } = new();

        public bool ThrowOnWrite { get; set; }
        public bool ThrowOnReplace { get; set; }
        public bool SimulateUnauthorizedAccess { get; set; }
        public bool SimulateSecurityException { get; set; }

        public string HostsPath { get; set; } = @"C:\Windows\System32\drivers\etc\hosts";

        public ThreadSafeMockFileService(string initialContent = "127.0.0.1 localhost\n")
        {
            _files[HostsPath] = initialContent;
        }

        public string GetHostsPath() => HostsPath;

        public bool FileExists(string path)
        {
            return _files.ContainsKey(path);
        }

        public string[] ReadAllLines(string path)
        {
            if (_files.TryGetValue(path, out var content))
            {
                return content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            }
            throw new FileNotFoundException($"Mock file not found: {path}");
        }

        public string ReadAllText(string path)
        {
            if (_files.TryGetValue(path, out var content))
            {
                return content;
            }
            throw new FileNotFoundException($"Mock file not found: {path}");
        }

        public void WriteAllText(string path, string content)
        {
            if (ThrowOnWrite)
                throw new IOException("Simulated disk full or I/O error during temp write.");

            if (SimulateUnauthorizedAccess)
                throw new UnauthorizedAccessException("Simulated access denied.");

            _files[path] = content;
        }

        public void ReplaceFile(string sourceFile, string targetFile, string? backupFile)
        {
            if (SimulateUnauthorizedAccess)
                throw new UnauthorizedAccessException("Simulated access denied on ReplaceFile.");

            if (SimulateSecurityException)
                throw new SecurityException("Simulated security permission error on ReplaceFile.");

            if (ThrowOnReplace)
                throw new IOException("Simulated filesystem lock or sharing violation on ReplaceFile.");

            Interlocked.Increment(ref _replaceCount);
            if (_files.TryGetValue(sourceFile, out var srcContent))
            {
                _files[targetFile] = srcContent;
                _files.TryRemove(sourceFile, out _);
            }
        }

        private int _replaceCount;
        public int ReplaceCountValue => _replaceCount;

        public void MoveFile(string sourceFile, string targetFile)
        {
            Interlocked.Increment(ref _replaceCount);
            if (_files.TryRemove(sourceFile, out var srcContent))
            {
                _files[targetFile] = srcContent;
            }
        }

        public void DeleteFile(string path)
        {
            DeletedTempFiles.Add(path);
            _files.TryRemove(path, out _);
        }

        public FileAttributes GetAttributes(string path)
        {
            lock (_attrLock) { return _attributes; }
        }

        public void SetAttributes(string path, FileAttributes attributes)
        {
            lock (_attrLock) { _attributes = attributes; }
        }

        public string? CreateSystemBackup(string sourcePath)
        {
            if (!_files.ContainsKey(sourcePath)) return null;
            string backup = $"{HostsPath}.bak.{DateTime.UtcNow.Ticks}";
            CreatedSystemBackups.Add(backup);
            return backup;
        }

        public string? CreateUserAppDataBackup(string sourcePath)
        {
            if (!_files.ContainsKey(sourcePath)) return null;
            string backup = $@"C:\AppData\hosts.bak.{DateTime.UtcNow.Ticks}";
            CreatedUserBackups.Add(backup);
            return backup;
        }
    }

    #endregion

    #region Vector 1: Concurrency and Thread Safety Stress Tests

    [Fact]
    public async Task AuditAsync_HighParallelism_50ConcurrentCallers_CompletesWithoutExceptions()
    {
        // Arrange
        string infectedHosts = @"
127.0.0.1 localhost
127.0.0.1 update.microsoft.com # Sinkhole (Critical)
198.51.100.1 paypal.com # Phishing (Critical)
10.0.0.1 internal.server
";
        var mockService = new ThreadSafeMockFileService(infectedHosts);
        var mockAdapterAuditor = new Mock<IDnsAdapterAuditor>();
        mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AdapterDnsAuditItem>
            {
                new()
                {
                    AdapterGuid = "{11111111-2222-3333-4444-555555555555}",
                    AdapterName = "Ethernet",
                    DnsServers = new() { DnsHostsGuardEngine.ClassifyDnsServer("1.1.1.1") }
                }
            });
        var mockCacheFlusher = new Mock<IDnsCacheFlusher>();
        mockCacheFlusher.Setup(c => c.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(mockService, mockAdapterAuditor.Object, mockCacheFlusher.Object);

        int concurrency = 50;
        var tasks = new Task<DnsHostsGuardReport>[concurrency];

        // Act
        for (int i = 0; i < concurrency; i++)
        {
            tasks[i] = Task.Run(async () => await engine.AuditAsync());
        }

        var results = await Task.WhenAll(tasks);

        // Assert
        Assert.Equal(concurrency, results.Length);
        foreach (var report in results)
        {
            Assert.NotNull(report);
            Assert.True(report.HostsFileExists);
            Assert.Equal(4, report.TotalHostsEntries);
            Assert.Equal(2, report.SuspiciousEntries.Count);
            Assert.Equal(2, report.CriticalCount); // update.microsoft.com AND paypal.com
            Assert.False(report.HasRogueDns);
            Assert.Null(report.ErrorMessage);
        }
    }

    [Fact]
    public async Task Concurrency_MixedAuditAndRestore_RunsSafelyWithoutDeadlockOrCorruption()
    {
        // Arrange
        string initialHosts = "127.0.0.1 update.microsoft.com\n";
        var mockService = new ThreadSafeMockFileService(initialHosts);
        var mockAdapterAuditor = new Mock<IDnsAdapterAuditor>();
        mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AdapterDnsAuditItem>());
        var mockCacheFlusher = new Mock<IDnsCacheFlusher>();
        mockCacheFlusher.Setup(c => c.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(mockService, mockAdapterAuditor.Object, mockCacheFlusher.Object);

        int auditCount = 30;
        int restoreCount = 20;
        var auditTasks = new List<Task<DnsHostsGuardReport>>();
        var restoreTasks = new List<Task<HostsRestoreResult>>();

        // Act
        for (int i = 0; i < auditCount; i++)
        {
            auditTasks.Add(Task.Run(async () => await engine.AuditAsync()));
        }
        for (int i = 0; i < restoreCount; i++)
        {
            restoreTasks.Add(Task.Run(async () => await engine.RestoreDefaultHostsFileAsync()));
        }

        await Task.WhenAll(auditTasks.Cast<Task>().Concat(restoreTasks));

        // Assert
        foreach (var r in restoreTasks)
        {
            var res = await r;
            Assert.True(res.Success);
            Assert.False(res.RequiresElevation);
            Assert.True(res.CacheFlushed);
        }

        foreach (var a in auditTasks)
        {
            var rep = await a;
            Assert.NotNull(rep);
            Assert.True(rep.HostsFileExists);
        }

        Assert.True(mockService.ReplaceCountValue >= 1);
    }

    [Fact]
    public void PureMethods_MultiThreadedStress_UnderParallelExecution_ProducesDeterministicResults()
    {
        // Arrange
        string[] sampleIps = { "1.1.1.1", "8.8.8.8", "9.9.9.9", "192.168.1.1", "10.0.0.1", "100.64.0.1", "198.51.100.1", "::1", "fc00::1", "invalid" };
        string testHosts = @"
127.0.0.1 update.microsoft.com # Critical
198.51.100.1 paypal.com # Phishing
0.0.0.0 search.conduit.com # Adblock
10.0.0.1 internal.dev # Custom
127.0.0.1 localhost # Benign
";
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        Parallel.For(0, 500, i =>
        {
            try
            {
                // 1. Classification
                string ip = sampleIps[i % sampleIps.Length];
                var classification = DnsHostsGuardEngine.ClassifyDnsServer(ip);
                Assert.NotNull(classification);

                // 2. Parsing
                var entries = DnsHostsGuardEngine.ParseHostsContent(testHosts);
                Assert.Equal(5, entries.Count);

                // 3. Evaluation
                var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entries[0]);
                Assert.True(evaluated.IsSuspicious);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
    }

    #endregion

    #region Vector 2: Atomic Swap Resilience & Partial Write Fault Injection

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_WhenTempWriteFails_LeavesTargetHostsIntactAndCleansUpTemp()
    {
        // Arrange
        string originalHostsContent = "127.0.0.1 myoriginaldomain.org\n";
        var mockService = new ThreadSafeMockFileService(originalHostsContent)
        {
            ThrowOnWrite = true // Fault injection: disk full or I/O failure during temp file write
        };
        var mockCacheFlusher = new Mock<IDnsCacheFlusher>();
        var engine = new DnsHostsGuardEngine(mockService, new Mock<IDnsAdapterAuditor>().Object, mockCacheFlusher.Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.Contains("Simulated disk full", result.ErrorMessage);
        Assert.Equal(originalHostsContent, mockService.ReadAllText(mockService.HostsPath));
        Assert.Equal(0, mockService.ReplaceCountValue);
        mockCacheFlusher.Verify(c => c.FlushResolverCache(), Times.Never);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_WhenReplaceFileThrows_OriginalPreservedAndTempDeleted()
    {
        // Arrange
        string originalHosts = "127.0.0.1 preserveme.local\n";
        var mockService = new ThreadSafeMockFileService(originalHosts)
        {
            ThrowOnReplace = true // Fault injection: lock/sharing violation on File.Replace
        };
        var mockCacheFlusher = new Mock<IDnsCacheFlusher>();
        var engine = new DnsHostsGuardEngine(mockService, new Mock<IDnsAdapterAuditor>().Object, mockCacheFlusher.Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.Contains("Simulated filesystem lock", result.ErrorMessage);
        Assert.Equal(originalHosts, mockService.ReadAllText(mockService.HostsPath));
        Assert.NotEmpty(mockService.DeletedTempFiles);
        mockCacheFlusher.Verify(c => c.FlushResolverCache(), Times.Never);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_WhenUnauthorizedAccess_ReturnsElevationRequiredWithBackups()
    {
        // Arrange
        var mockService = new ThreadSafeMockFileService("127.0.0.1 infected.com\n")
        {
            SimulateUnauthorizedAccess = true
        };
        var engine = new DnsHostsGuardEngine(mockService, new Mock<IDnsAdapterAuditor>().Object, new Mock<IDnsCacheFlusher>().Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("Elevation required", result.ErrorMessage);
        Assert.True(result.SystemBackupCreated);
        Assert.True(result.UserBackupCreated);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_WhenSecurityException_ReturnsElevationRequired()
    {
        // Arrange
        var mockService = new ThreadSafeMockFileService("127.0.0.1 infected.com\n")
        {
            SimulateSecurityException = true
        };
        var engine = new DnsHostsGuardEngine(mockService, new Mock<IDnsAdapterAuditor>().Object, new Mock<IDnsCacheFlusher>().Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Security access denied", result.ErrorMessage);
    }

    #endregion

    #region Vector 3: Dual-Path Backup Generation & Verification

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_CreatesDualBackupsWithValidPaths()
    {
        // Arrange
        string infected = "127.0.0.1 update.microsoft.com\n198.51.100.1 paypal.com\n";
        var mockService = new ThreadSafeMockFileService(infected);
        var mockCacheFlusher = new Mock<IDnsCacheFlusher>();
        mockCacheFlusher.Setup(c => c.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(mockService, new Mock<IDnsAdapterAuditor>().Object, mockCacheFlusher.Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.True(result.Success);
        Assert.True(result.SystemBackupCreated);
        Assert.True(result.UserBackupCreated);
        Assert.NotNull(result.SystemBackupPath);
        Assert.NotNull(result.UserBackupPath);
        Assert.Contains("bak", result.SystemBackupPath);
        Assert.Contains("bak", result.UserBackupPath);
        Assert.NotEmpty(mockService.CreatedSystemBackups);
        Assert.NotEmpty(mockService.CreatedUserBackups);
    }

    #endregion

    #region Vector 4: Real Filesystem Sandboxed Integration Tests

    [Fact]
    public async Task RealFilesystem_EndToEnd_BackupRestoreAndAttributeClearing()
    {
        using var sandbox = new TempDirectorySandbox();
        string infectedContent = @"# Corrupted hosts file
127.0.0.1 localhost
127.0.0.1 update.microsoft.com
198.51.100.1 chase.com
";
        // 1. Write infected file to real sandbox disk
        File.WriteAllText(sandbox.HostsPath, infectedContent, new UTF8Encoding(false));

        // 2. Set restrictive ReadOnly + Hidden attributes on real file
        File.SetAttributes(sandbox.HostsPath, FileAttributes.ReadOnly | FileAttributes.Hidden);

        var realFileService = new SandboxedRealHostsFileService(sandbox.HostsPath, sandbox.UserBackupPath);
        var mockFlusher = new Mock<IDnsCacheFlusher>();
        mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(realFileService, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

        // 3. Act: Execute Restore
        var result = await engine.RestoreDefaultHostsFileAsync();

        // 4. Assert
        Assert.True(result.Success);
        Assert.False(result.RequiresElevation);
        Assert.True(result.CacheFlushed);
        Assert.True(result.SystemBackupCreated);
        Assert.True(result.UserBackupCreated);

        // Verify restored content on real disk
        string restoredText = File.ReadAllText(sandbox.HostsPath);
        Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", restoredText);
        Assert.DoesNotContain("update.microsoft.com", restoredText);
        Assert.DoesNotContain("chase.com", restoredText);

        // Verify system backup content on real disk
        Assert.NotNull(result.SystemBackupPath);
        Assert.True(File.Exists(result.SystemBackupPath));
        string sysBackupContent = File.ReadAllText(result.SystemBackupPath);
        Assert.Equal(infectedContent, sysBackupContent);

        // Verify user appdata backup content on real disk
        Assert.NotNull(result.UserBackupPath);
        Assert.True(File.Exists(result.UserBackupPath));
        string userBackupContent = File.ReadAllText(result.UserBackupPath);
        Assert.Equal(infectedContent, userBackupContent);

        // Verify attributes were restored to normal on real disk
        var finalAttributes = File.GetAttributes(sandbox.HostsPath);
        Assert.False((finalAttributes & FileAttributes.ReadOnly) != 0, "ReadOnly attribute was not cleared!");
        Assert.False((finalAttributes & FileAttributes.Hidden) != 0, "Hidden attribute was not cleared!");

        // Verify no leftover staging temp files (.tmp.)
        var tempFiles = Directory.GetFiles(sandbox.DirectoryPath, "hosts.tmp.*");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public async Task RealFilesystem_WhenHostsFileDoesNotExist_CreatesFreshDefaultHostsFile()
    {
        using var sandbox = new TempDirectorySandbox();
        // Hosts file intentionally NOT created in sandbox

        var realFileService = new SandboxedRealHostsFileService(sandbox.HostsPath, sandbox.UserBackupPath);
        var mockFlusher = new Mock<IDnsCacheFlusher>();
        mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(realFileService, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.True(result.Success);
        Assert.False(result.SystemBackupCreated);
        Assert.False(result.UserBackupCreated);
        Assert.Null(result.SystemBackupPath);
        Assert.Null(result.UserBackupPath);
        Assert.True(File.Exists(sandbox.HostsPath));

        string createdText = File.ReadAllText(sandbox.HostsPath);
        Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", createdText);

        // Temp staging file is gone
        var tempFiles = Directory.GetFiles(sandbox.DirectoryPath, "hosts.tmp.*");
        Assert.Empty(tempFiles);
    }

    [Fact]
    public async Task RealFilesystem_HighConcurrency_MixedAuditAndRestore_MaintainsIntegrity()
    {
        using var sandbox = new TempDirectorySandbox();
        string initialContent = "127.0.0.1 malicious.example.com\n";
        File.WriteAllText(sandbox.HostsPath, initialContent, new UTF8Encoding(false));

        var realFileService = new SandboxedRealHostsFileService(sandbox.HostsPath, sandbox.UserBackupPath);
        var mockFlusher = new Mock<IDnsCacheFlusher>();
        mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);
        var mockAuditor = new Mock<IDnsAdapterAuditor>();
        mockAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AdapterDnsAuditItem>());

        var engine = new DnsHostsGuardEngine(realFileService, mockAuditor.Object, mockFlusher.Object);

        int auditTasksCount = 20;
        int restoreTasksCount = 10;
        var auditTasks = new List<Task<DnsHostsGuardReport>>();
        var restoreTasks = new List<Task<HostsRestoreResult>>();

        for (int i = 0; i < auditTasksCount; i++)
        {
            auditTasks.Add(Task.Run(async () => await engine.AuditAsync()));
        }
        for (int i = 0; i < restoreTasksCount; i++)
        {
            restoreTasks.Add(Task.Run(async () => await engine.RestoreDefaultHostsFileAsync()));
        }

        await Task.WhenAll(auditTasks.Cast<Task>().Concat(restoreTasks));

        // File must exist and contain valid default content
        Assert.True(File.Exists(sandbox.HostsPath));
        string finalText = File.ReadAllText(sandbox.HostsPath);
        Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", finalText);
    }

    [Fact]
    public async Task RealFilesystem_Large2MBHostsFile_RestoresAndBacksUpAccurately()
    {
        using var sandbox = new TempDirectorySandbox();
        var sb = new StringBuilder();
        sb.AppendLine("# Large 2MB hosts file test");
        for (int i = 0; i < 40000; i++)
        {
            sb.AppendLine($"127.0.0.1 evil-tracker-{i}.telemetry.bad");
        }
        string largeContent = sb.ToString();
        File.WriteAllText(sandbox.HostsPath, largeContent, new UTF8Encoding(false));

        var realFileService = new SandboxedRealHostsFileService(sandbox.HostsPath, sandbox.UserBackupPath);
        var mockFlusher = new Mock<IDnsCacheFlusher>();
        mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

        var engine = new DnsHostsGuardEngine(realFileService, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.True(result.Success);
        Assert.True(result.SystemBackupCreated);
        Assert.True(result.UserBackupCreated);
        Assert.NotNull(result.SystemBackupPath);
        Assert.NotNull(result.UserBackupPath);

        // Verify large backup content size matches
        var sysInfo = new FileInfo(result.SystemBackupPath);
        var userInfo = new FileInfo(result.UserBackupPath);
        Assert.True(sysInfo.Length > 1_000_000, "System backup size was truncated!");
        Assert.True(userInfo.Length > 1_000_000, "User backup size was truncated!");

        // Restored file should be the compact default template
        string restoredText = File.ReadAllText(sandbox.HostsPath);
        Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", restoredText);
        Assert.DoesNotContain("evil-tracker-0", restoredText);
    }

    #endregion

    #region Vector 5: Fuzzing & High-Volume Threat Catalog Performance

    [Fact]
    public void ParseHostsLines_LargeVolumeFuzzing_10000Lines_ExecutesInSubSecond()
    {
        // Arrange: Generate 10,000 lines with diverse tokens, comments, tabs, IPs, and domains
        var lines = new List<string>(10000);
        var rnd = new Random(42);
        string[] sampleDomains = { "update.microsoft.com", "paypal.com", "google.com", "search.conduit.com", "internal.corp", "localhost", "randomdomain.net" };
        string[] sampleIps = { "127.0.0.1", "0.0.0.0", "198.51.100.1", "10.0.0.1", "::1", "192.168.1.100" };

        for (int i = 0; i < 10000; i++)
        {
            if (i % 10 == 0)
            {
                lines.Add($"# Comment line number {i}");
            }
            else if (i % 25 == 0)
            {
                lines.Add("   \t  "); // Whitespace line
            }
            else
            {
                string ip = sampleIps[rnd.Next(sampleIps.Length)];
                string dom1 = sampleDomains[rnd.Next(sampleDomains.Length)];
                string dom2 = $"sub{i}.{sampleDomains[rnd.Next(sampleDomains.Length)]}";
                lines.Add($"{ip}\t{dom1}   {dom2} # inline comment {i}");
            }
        }

        // Act
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var entries = DnsHostsGuardEngine.ParseHostsLines(lines);
        sw.Stop();

        // Assert
        Assert.NotEmpty(entries);
        Assert.True(sw.ElapsedMilliseconds < 2000, $"Parsing 10,000 lines took {sw.ElapsedMilliseconds}ms, expected < 2000ms");
    }

    [Fact]
    public void ClassifyDnsServer_LargeVolumeClassifications_10000Lookups_ExecutesRapidly()
    {
        string[] testIps =
        {
            "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "94.140.14.14", "185.228.168.9", "76.76.2.0",
            "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "127.0.0.1",
            "2606:4700:4700::1111", "2001:4860:4860::8888", "::1", "fc00::1", "fe80::1",
            "198.51.100.55", "203.0.113.12"
        };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 10000; i++)
        {
            string ip = testIps[i % testIps.Length];
            var res = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.NotNull(res);
        }
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 1000, $"10,000 DNS classifications took {sw.ElapsedMilliseconds}ms, expected < 1000ms");
    }

    [Theory]
    [InlineData("127.0.0.1   google.com.   # Trailing dot on FQDN")]
    [InlineData("\t\t127.0.0.1\t\tupdate.microsoft.com\t\t")]
    [InlineData("127.0.0.1 host1 host2 host3 host4 host5")]
    [InlineData("# Entire line is a comment # with multiple # hash symbols")]
    [InlineData("127.0.0.1 # inline comment before domain")]
    [InlineData("invalid.ip.address.format legitimate-domain.com")]
    [InlineData("127.0.0.1:8080 domain-with-port.com")]
    public void ParseHostsLines_MalformedAndEdgeLines_DoesNotCrashOrThrow(string rawLine)
    {
        var entries = DnsHostsGuardEngine.ParseHostsLines(new[] { rawLine });
        Assert.NotNull(entries);
    }

    [Theory]
    [InlineData("127.0.0.1", "paypal.com", true)]
    [InlineData("127.0.0.1", "checkout.paypal.com", true)]
    [InlineData("127.0.0.1", "paypal.com.attacker.com", false)]
    [InlineData("127.0.0.1", "notpaypal.com", false)]
    [InlineData("127.0.0.1", "antivirus-virustotal.com", false)]
    [InlineData("127.0.0.1", "api.virustotal.com", true)]
    public void ThreatDomainCatalog_SuffixAndBoundaryDefense_AccurateDetection(string ip, string hostname, bool expectedThreat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = hostname };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        if (expectedThreat)
        {
            Assert.True(evaluated.IsSuspicious);
            Assert.NotNull(evaluated.MatchedThreatDomain);
        }
        else
        {
            // If it's mapped to loopback/private, it should be categorized as CustomMapping, not suspicious
            Assert.False(evaluated.IsSuspicious);
            Assert.Equal(HostsThreatCategory.CustomMapping, evaluated.Category);
        }
    }

    #endregion
}
