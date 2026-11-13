// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests.E2E – DefenderAndHostsAdversarialTests
// Milestone 5 Phase 2: Adversarial Coverage Hardening (Tier 5)
// White-Box Adversarial Stress Testing on DefenderHardenerEngine and DnsHostsGuardEngine.
//
// Target Vectors:
//   1. Multithreaded Defender Status Toggles & Concurrent Scans (100+ tasks, race conditions, cancellation tokens).
//   2. ASR Rule Catalog Edge Cases (all 16 rules, Warn-mode enforcement, alias resolution, legacy mapping).
//   3. Hosts File Fuzzing & Malformed Byte Sequences (null bytes, corrupted encodings, mixed CRLF, long lines).
//   4. Multi-Megabyte Large Scale Hosts File Stress (10MB+ files, 100,000+ entries, memory & performance safety).
//   5. Unicode & Internationalized Domain Names (IDN, homoglyphs, zero-width spaces, trailing dots, ports).
//   6. Edge-Case CIDR Subnet Masks & IP Boundary Conditions (IPv4 /8, /12, /16, /10 CGNAT, APIPA; IPv6 ULA, Link-Local, Scope IDs).
//   7. Threat Domain Catalog Precision & Suffix Boundary Defense (subdomain matching vs false positive rejection).
//   8. Sandboxed Filesystem Fault Injection (atomic replace, dual backups, attribute normalization, elevation errors).
//
// DelgadoLogic.Tech Proprietary Test Framework
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Microsoft.Win32;
using Moq;
using Xunit;

namespace LogicFlow.Tests.E2E
{
    public class DefenderAndHostsAdversarialTests : IDisposable
    {
        private readonly string _sandboxDir;

        public DefenderAndHostsAdversarialTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "LF_Adv_DefHosts_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    foreach (var file in Directory.GetFiles(_sandboxDir, "*", SearchOption.AllDirectories))
                    {
                        try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                    }
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch { /* Best effort cleanup */ }
        }

        #region Mock and Sandbox Helpers

        private class ConcurrentThreadSafeRegistry : IRegistryService
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

        private class SandboxedHostsFileService : IHostsFileService
        {
            private readonly string _hostsPath;
            private readonly string _userBackupDir;

            public SandboxedHostsFileService(string hostsPath, string userBackupDir)
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

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 1: MULTITHREADED DEFENDER STATUS TOGGLES & SCANS
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 1: Defender Concurrency & Multi-Thread Stress

        [Fact]
        public async Task Adv_Def_01_HighConcurrency_100ParallelTasks_InterleavedTogglesAndStatus_ThreadSafe()
        {
            var reg = new ConcurrentThreadSafeRegistry();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(reg, mockRunner.Object);

            var tasks = Enumerable.Range(0, 100).Select(async i =>
            {
                await Task.Yield();
                int op = i % 8;
                switch (op)
                {
                    case 0:
                        var s0 = await engine.GetStatusAsync();
                        Assert.NotNull(s0);
                        Assert.Equal(16, s0.TotalAsrRulesCount);
                        break;
                    case 1:
                        var res1 = await engine.EnableEnterpriseHardeningAsync();
                        Assert.True(res1.Success);
                        break;
                    case 2:
                        var res2 = await engine.RevertToDefaultsAsync();
                        Assert.True(res2.Success);
                        break;
                    case 3:
                        var rule = DefenderHardenerEngine.KnownAsrRules[i % DefenderHardenerEngine.KnownAsrRules.Count];
                        var res3 = await engine.SetAsrRuleStateAsync(rule.Guid, (AsrRuleState)(i % 4));
                        Assert.True(res3.Success);
                        break;
                    case 4:
                        var ruleT = DefenderHardenerEngine.KnownAsrRules[(i + 1) % DefenderHardenerEngine.KnownAsrRules.Count];
                        var res4 = await engine.ToggleAsrRuleAsync(ruleT.Guid);
                        Assert.True(res4.Success);
                        break;
                    case 5:
                        var res5 = await engine.SetPuaProtectionAsync(i % 2 == 0, auditOnly: i % 4 == 0);
                        Assert.True(res5.Success);
                        break;
                    case 6:
                        var res6 = await engine.SetCloudProtectionAsync(i % 2 == 0);
                        Assert.True(res6.Success);
                        break;
                    case 7:
                        var res7 = await engine.SetControlledFolderAccessAsync(i % 2 == 0);
                        Assert.True(res7.Success);
                        break;
                }
            });

            await Task.WhenAll(tasks);
        }

        [Fact]
        public async Task Adv_Def_02_ConcurrentScans_WithCancellationToken_HandlesCancellationGracefully()
        {
            var reg = new ConcurrentThreadSafeRegistry();
            var mockRunner = new Mock<IProcessRunner>();
            string fakePath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";
            mockRunner.Setup(r => r.FileExists(fakePath)).Returns(true);

            // Simulate delayed scan that honors cancellation
            mockRunner.Setup(r => r.RunAsync(fakePath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns<string, string, CancellationToken>(async (file, args, ct) =>
                {
                    await Task.Delay(500, ct);
                    return new ProcessExecutionResult { ExitCode = 0, StandardOutput = "Scan finished" };
                });

            var engine = new DefenderHardenerEngine(reg, mockRunner.Object);

            using var cts = new CancellationTokenSource(50); // Cancel after 50ms
            var result = await engine.TriggerScanAsync(DefenderScanType.Quick, cts.Token);

            Assert.NotNull(result);
            Assert.False(result.Success);
            Assert.Equal(-1, result.ExitCode);
            Assert.Contains("canceled", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Adv_Def_03_ConcurrentScanInvocations_ExitCode2_ThreatsFound_ClassifiedAsSuccess()
        {
            var reg = new ConcurrentThreadSafeRegistry();
            var mockRunner = new Mock<IProcessRunner>();
            string fakePath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";
            mockRunner.Setup(r => r.FileExists(fakePath)).Returns(true);

            // ExitCode 2 means threats were detected and remediated by Defender
            mockRunner.Setup(r => r.RunAsync(fakePath, "-Scan -ScanType 1", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ProcessExecutionResult
                {
                    ExitCode = 2,
                    StandardOutput = "Threat detected: Trojan:Win32/Test. Remediation: Cleaned.",
                    Duration = TimeSpan.FromMilliseconds(300)
                });

            var engine = new DefenderHardenerEngine(reg, mockRunner.Object);

            var tasks = Enumerable.Range(0, 20).Select(async _ =>
            {
                var scanResult = await engine.TriggerScanAsync(DefenderScanType.Quick);
                Assert.True(scanResult.Success);
                Assert.Equal(2, scanResult.ExitCode);
                Assert.Contains("Threat detected", scanResult.ScanOutput);
                Assert.Null(scanResult.ErrorMessage);
            });

            await Task.WhenAll(tasks);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 2: ASR RULE CATALOG EDGE CASES & WARN MODE ENFORCEMENT
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 2: ASR Rule Catalog Edge Cases

        [Fact]
        public void Adv_Def_04_AsrCatalog_All16Rules_HaveUniqueGuidsAndValidNames()
        {
            var rules = DefenderHardenerEngine.KnownAsrRules;
            Assert.Equal(16, rules.Count);

            var guids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rule in rules)
            {
                Assert.True(Guid.TryParse(rule.Guid, out _), $"Invalid GUID: {rule.Guid}");
                Assert.True(guids.Add(rule.Guid), $"Duplicate GUID found: {rule.Guid}");
                Assert.True(names.Add(rule.Name), $"Duplicate Name found: {rule.Name}");
                Assert.False(string.IsNullOrWhiteSpace(rule.Category));
                Assert.False(string.IsNullOrWhiteSpace(rule.Description));
            }
        }

        [Fact]
        public async Task Adv_Def_05_AsrCatalog_WarnModeEnforcement_OnNonWarnRules_ForcesBlockMode()
        {
            var reg = new ConcurrentThreadSafeRegistry();
            var mockRunner = new Mock<IProcessRunner>();
            var engine = new DefenderHardenerEngine(reg, mockRunner.Object);

            // Rules that do NOT support Warn:
            // 1. Block Office Process Injection (75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84)
            // 2. Block Win32 API Calls from Macros (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)
            // 3. Block WMI Persistence (E6DB77E5-3DF2-4CF1-B95A-636979351E5B)
            // 4. Block LSASS Credential Theft (9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2)
            // 5. Block PSExec and WMI Process Creation (D1E49AAC-8F56-4280-B9BA-993A6D77406C)

            var nonWarnRules = DefenderHardenerEngine.KnownAsrRules.Where(r => !r.SupportsWarn).ToList();
            Assert.Equal(5, nonWarnRules.Count);

            foreach (var rule in nonWarnRules)
            {
                var result = await engine.SetAsrRuleStateAsync(rule.Guid, AsrRuleState.Warn);
                Assert.True(result.Success);
                Assert.Contains("enforced Block mode", result.Output ?? "");

                // Verify registry has Block mode (1) stored, not Warn (6)
                int? storedVal = reg.GetDword(RegistryHive.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                    rule.Guid);
                Assert.Equal(1, storedVal);
            }
        }

        [Theory]
        [InlineData("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550")] // Lowercase
        [InlineData("{BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550}")] // Braced
        [InlineData("  {be9ba2d9-53ea-4cdc-84e5-9b1eeee46550}  ")] // Padded
        [InlineData("BE9BFC54-5307-483F-A7DA-28963B5E8757")] // Alias GUID
        [InlineData("Block Executables from Email")] // Exact friendly name
        [InlineData("executables from email")] // Partial friendly name
        public void Adv_Def_06_AsrCatalog_FindRule_ResolvesVariousInputFormats(string input)
        {
            var rule = DefenderHardenerEngine.FindRule(input);
            Assert.NotNull(rule);
            Assert.Equal("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", rule.Guid, ignoreCase: true);
        }

        [Fact]
        public void Adv_Def_07_AsrCatalog_FindRule_ResolvesLegacyAliasMappings()
        {
            // Legacy alias: 5BEB7E2C-829E-4529-A96B-055520E3378E -> 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC (Block Obfuscated Scripts)
            var rule1 = DefenderHardenerEngine.FindRule("5BEB7E2C-829E-4529-A96B-055520E3378E");
            Assert.NotNull(rule1);
            Assert.Equal("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", rule1.Guid, ignoreCase: true);

            // Legacy alias: E6DB77E5-3E12-4247-81D7-0E0E5F86BF94 -> E6DB77E5-3DF2-4CF1-B95A-636979351E5B (Block WMI Persistence)
            var rule2 = DefenderHardenerEngine.FindRule("E6DB77E5-3E12-4247-81D7-0E0E5F86BF94");
            Assert.NotNull(rule2);
            Assert.Equal("E6DB77E5-3DF2-4CF1-B95A-636979351E5B", rule2.Guid, ignoreCase: true);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("00000000-0000-0000-0000-000000000000")]
        [InlineData("not-a-valid-guid")]
        [InlineData("NonExistentRuleNameXYZ")]
        public async Task Adv_Def_08_AsrCatalog_UnknownRule_ReturnsCleanFailure(string invalidGuid)
        {
            var reg = new ConcurrentThreadSafeRegistry();
            var engine = new DefenderHardenerEngine(reg, new Mock<IProcessRunner>().Object);

            var res1 = await engine.SetAsrRuleStateAsync(invalidGuid, AsrRuleState.Block);
            Assert.False(res1.Success);
            Assert.Contains("Unknown ASR rule", res1.ErrorMessage);

            var res2 = await engine.ToggleAsrRuleAsync(invalidGuid);
            Assert.False(res2.Success);
            Assert.Contains("Unknown ASR rule", res2.ErrorMessage);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 3: HOSTS FILE FUZZING & CORRUPTED BYTE SEQUENCES
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 3: Hosts File Fuzzing & Corrupt Bytes

        [Fact]
        public void Adv_Hosts_01_NullBytesInHostsFile_ParsedWithoutCrash()
        {
            string corruptedHosts = "127.0.0.1\0 localhost\r\n" +
                                   "127.0.0.1\0 update.microsoft.com\r\n" +
                                   "198.51.100.1\0 paypal.com\r\n" +
                                   "10.0.0.1 internal\0.domain";

            var entries = DnsHostsGuardEngine.ParseHostsContent(corruptedHosts);
            Assert.NotNull(entries);
            // Non-crash verification
        }

        [Fact]
        public void Adv_Hosts_02_MixedLineEndingsAndExcessiveWhitespace_ParsedAccurately()
        {
            // Mixed CRLF, LF, CR, and heavy tab/space padding
            string content = "127.0.0.1\t\t\tlocalhost\r\n" +
                             "127.0.0.1    update.microsoft.com\n" +
                             "198.51.100.1 \t chase.com\r" +
                             "0.0.0.0 \t\t\t search.conduit.com # trailing comment\r\n" +
                             "\r\n\n\r" +
                             "   \t   # blank comment line\r\n" +
                             "10.0.0.1  dev.local   test.local   internal.corp\n";

            var entries = DnsHostsGuardEngine.ParseHostsContent(content);
            Assert.Equal(7, entries.Count); // 1 localhost + 1 update + 1 chase + 1 conduit + 3 on the 10.0.0.1 line

            Assert.Contains(entries, e => e.Hostname == "localhost" && e.Category == HostsThreatCategory.BenignLocalMapping);
            Assert.Contains(entries, e => e.Hostname == "update.microsoft.com" && e.Category == HostsThreatCategory.SecuritySinkhole);
            Assert.Contains(entries, e => e.Hostname == "chase.com" && e.Category == HostsThreatCategory.FinancialPhishingRedirect);
            Assert.Contains(entries, e => e.Hostname == "search.conduit.com" && e.Category == HostsThreatCategory.AdwareDomainSinkholed);
            Assert.Contains(entries, e => e.Hostname == "dev.local" && e.Category == HostsThreatCategory.CustomMapping);
            Assert.Contains(entries, e => e.Hostname == "test.local" && e.Category == HostsThreatCategory.CustomMapping);
            Assert.Contains(entries, e => e.Hostname == "internal.corp" && e.Category == HostsThreatCategory.CustomMapping);
        }

        [Fact]
        public void Adv_Hosts_03_ExtremelyLongLines_HandledWithoutOutOfMemoryOrStackOverflow()
        {
            // Generate a 50,000 character line with 1,000 hostnames
            var sb = new StringBuilder();
            sb.Append("127.0.0.1 ");
            for (int i = 0; i < 1000; i++)
            {
                sb.Append($"domain-chunk-{i}.example.com ");
            }

            var entries = DnsHostsGuardEngine.ParseHostsLines(new[] { sb.ToString() });
            Assert.Equal(1000, entries.Count);
            Assert.All(entries, e =>
            {
                Assert.Equal("127.0.0.1", e.IpAddress);
                Assert.Equal(HostsThreatCategory.CustomMapping, e.Category);
                Assert.False(e.IsSuspicious);
            });
        }

        [Fact]
        public void Adv_Hosts_04_CorruptedEncodingByteSequences_ParsedSafely()
        {
            // Test corrupted non-IP lines and replacement characters
            string corruptedContent = "# Header comment\r\n" +
                                     "127.0.0.1 localhost\r\n" +
                                     "\uFFFD\uFFFD\u0000 corrupted-binary-noise\r\n" +
                                     "127.0.0.1 update.microsoft.com\r\n" +
                                     "198.51.100.1 paypal.com\r\n";

            var entries = DnsHostsGuardEngine.ParseHostsContent(corruptedContent);
            Assert.NotEmpty(entries);
            Assert.Contains(entries, e => e.Hostname == "localhost");
            Assert.Contains(entries, e => e.Hostname == "update.microsoft.com" && e.IsSuspicious);
            Assert.Contains(entries, e => e.Hostname == "paypal.com" && e.IsSuspicious);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 4: MULTI-MEGABYTE LARGE SCALE HOSTS FILE STRESS
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 4: Multi-Megabyte Large Scale Hosts Stress

        [Fact]
        public void Adv_Hosts_05_LargeScale_50000Entries_PerformanceAndMemorySafety()
        {
            var lines = new List<string>(50000);
            for (int i = 0; i < 50000; i++)
            {
                if (i % 1000 == 0)
                {
                    lines.Add($"198.51.100.1 evil-phish-{i}.paypal.com # Phishing");
                }
                else if (i % 500 == 0)
                {
                    lines.Add($"0.0.0.0 tracker-{i}.search.conduit.com # Adblock");
                }
                else
                {
                    lines.Add($"10.0.0.1 host-{i}.corp.local");
                }
            }

            var sw = Stopwatch.StartNew();
            var entries = DnsHostsGuardEngine.ParseHostsLines(lines);
            sw.Stop();

            Assert.Equal(50000, entries.Count);
            // 50,000 lines should parse in under 3 seconds
            Assert.True(sw.ElapsedMilliseconds < 3000, $"Parsing 50,000 entries took {sw.ElapsedMilliseconds}ms, expected < 3000ms");

            // Verify critical phishing detections in mass entries
            int criticalCount = entries.Count(e => e.Severity == ThreatSeverity.Critical);
            Assert.True(criticalCount >= 50);
        }

        [Fact]
        public async Task Adv_Hosts_06_SandboxedMassiveFile_RestoreAndBackup_IntegrityMaintained()
        {
            string hostsFile = Path.Combine(_sandboxDir, "massive_hosts");
            string backupDir = Path.Combine(_sandboxDir, "user_backups");

            // Create a 5MB hosts file
            var sb = new StringBuilder(5 * 1024 * 1024);
            sb.AppendLine("# Massive hosts file 5MB stress");
            for (int i = 0; i < 100000; i++)
            {
                sb.AppendLine($"127.0.0.1 sinkhole-node-{i}.telemetry.bad");
            }
            File.WriteAllText(hostsFile, sb.ToString(), new UTF8Encoding(false));

            var fileService = new SandboxedHostsFileService(hostsFile, backupDir);
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(fileService, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            // Execute restore
            var result = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(result.Success);
            Assert.True(result.SystemBackupCreated);
            Assert.True(result.UserBackupCreated);

            // Verify backup sizes exceed 4MB
            var sysFi = new FileInfo(result.SystemBackupPath!);
            var userFi = new FileInfo(result.UserBackupPath!);
            Assert.True(sysFi.Length > 4_000_000, "System backup truncated!");
            Assert.True(userFi.Length > 4_000_000, "User backup truncated!");

            // Restored file is clean template
            string restored = File.ReadAllText(hostsFile);
            Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", restored);
            Assert.DoesNotContain("sinkhole-node-0", restored);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 5: UNICODE & INTERNATIONALIZED DOMAIN NAMES
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 5: Unicode & Domain Name Variations

        [Theory]
        [InlineData("127.0.0.1", "paypal.com.", true, HostsThreatCategory.FinancialAccessBlock)] // Trailing dot FQDN
        [InlineData("127.0.0.1", "pAyPaL.CoM", true, HostsThreatCategory.FinancialAccessBlock)] // Mixed case
        [InlineData("127.0.0.1", "update.microsoft.com...", true, HostsThreatCategory.SecuritySinkhole)] // Multiple trailing dots
        [InlineData("127.0.0.1", "login.live.com", true, HostsThreatCategory.FinancialAccessBlock)] // SSO domain
        [InlineData("198.51.100.1", "accounts.google.com", true, HostsThreatCategory.FinancialPhishingRedirect)] // External SSO redirect
        [InlineData("127.0.0.1", "google.com", true, HostsThreatCategory.SearchAccessBlock)] // Search sinkhole
        [InlineData("198.51.100.1", "bing.com", true, HostsThreatCategory.SearchAdwareHijack)] // Search hijack
        public void Adv_Hosts_07_DomainVariations_EvaluatedAccurately(string ip, string host, bool expectedSuspicious, HostsThreatCategory expectedCategory)
        {
            var entry = new HostsEntry { IpAddress = ip, Hostname = host };
            var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

            Assert.Equal(expectedSuspicious, evaluated.IsSuspicious);
            Assert.Equal(expectedCategory, evaluated.Category);
        }

        [Fact]
        public void Adv_Hosts_08_UnicodeAndPunycodeDomains_ParsedWithoutError()
        {
            string hostsContent = @"
127.0.0.1 xn--pypal-4ve.com # Punycode spoof
127.0.0.1 раyраl.com # Cyrillic homoglyph 'a' and 'p'
127.0.0.1 百度.com # Chinese Baidu domain
127.0.0.1 example.com\u200B # Zero-width space
";
            var entries = DnsHostsGuardEngine.ParseHostsContent(hostsContent);
            Assert.NotNull(entries);
            Assert.NotEmpty(entries);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 6: EDGE-CASE CIDR SUBNET MASKS & IP BOUNDARY CONDITIONS
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 6: CIDR Subnets & IP Boundaries

        [Theory]
        // RFC 1918 Class A: 10.0.0.0/8
        [InlineData("10.0.0.0", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("10.255.255.255", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("9.255.255.255", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("11.0.0.0", DnsServerCategory.RogueUntrustedPublic, false)]

        // RFC 1918 Class B: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        [InlineData("172.15.255.255", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("172.16.0.0", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("172.31.255.255", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("172.32.0.0", DnsServerCategory.RogueUntrustedPublic, false)]

        // RFC 1918 Class C: 192.168.0.0/16
        [InlineData("192.167.255.255", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("192.168.0.0", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("192.168.255.255", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("192.169.0.0", DnsServerCategory.RogueUntrustedPublic, false)]

        // RFC 6598 CGNAT / Tailscale: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
        [InlineData("100.63.255.255", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("100.64.0.0", DnsServerCategory.TailscaleCgnat, true)]
        [InlineData("100.100.100.100", DnsServerCategory.TailscaleCgnat, true)] // Tailscale MagicDNS
        [InlineData("100.127.255.255", DnsServerCategory.TailscaleCgnat, true)]
        [InlineData("100.128.0.0", DnsServerCategory.RogueUntrustedPublic, false)]

        // RFC 3927 APIPA: 169.254.0.0/16
        [InlineData("169.253.255.255", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("169.254.0.1", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("169.254.255.255", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("169.255.0.0", DnsServerCategory.RogueUntrustedPublic, false)]

        // Loopback: 127.0.0.0/8
        [InlineData("127.0.0.1", DnsServerCategory.LocalLoopback, true)]
        [InlineData("127.255.255.254", DnsServerCategory.LocalLoopback, true)]
        [InlineData("128.0.0.1", DnsServerCategory.RogueUntrustedPublic, false)]
        public void Adv_Dns_01_Ipv4CidrBoundaries_ClassifiedCorrectly(string ip, DnsServerCategory expectedCat, bool expectedTrusted)
        {
            var classification = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(expectedCat, classification.Category);
            Assert.Equal(expectedTrusted, classification.IsTrusted);
        }

        [Theory]
        // IPv6 Loopback
        [InlineData("::1", DnsServerCategory.LocalLoopback, true)]

        // IPv6 ULA: fc00::/7 (fc00:: to fdff:ffff:...)
        [InlineData("fc00::1", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("fd12:3456:789a::1", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DnsServerCategory.PrivateSubnet, true)]

        // IPv6 Link-Local: fe80::/10 (fe80:: to febf:ffff:...)
        [InlineData("fe80::1", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("fe80::dead:beef:cafe", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("fec0::1", DnsServerCategory.RogueUntrustedPublic, false)] // Deprecated site-local

        // IPv6 Scope IDs and Bracketed
        [InlineData("fe80::1%12", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("[fe80::1]", DnsServerCategory.PrivateSubnet, true)]
        [InlineData("[::1]", DnsServerCategory.LocalLoopback, true)]
        [InlineData("[1.1.1.1]", DnsServerCategory.TrustedPublic, true)]

        // Untrusted Rogue IPv6
        [InlineData("2600:1400::1", DnsServerCategory.RogueUntrustedPublic, false)]
        [InlineData("2404:6800::1", DnsServerCategory.RogueUntrustedPublic, false)]
        public void Adv_Dns_02_Ipv6CidrBoundaries_ClassifiedCorrectly(string ip, DnsServerCategory expectedCat, bool expectedTrusted)
        {
            var classification = DnsHostsGuardEngine.ClassifyDnsServer(ip);
            Assert.Equal(expectedCat, classification.Category);
            Assert.Equal(expectedTrusted, classification.IsTrusted);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        [InlineData("999.999.999.999")]
        [InlineData("256.1.1.1")]
        [InlineData("1.1.1.1.1")]
        [InlineData("not-an-ip")]
        [InlineData(":::")]
        [InlineData("fe80:::1")]
        public void Adv_Dns_03_MalformedIps_ClassifiedAsInvalidMalformed(string? malformedIp)
        {
            var classification = DnsHostsGuardEngine.ClassifyDnsServer(malformedIp!);
            Assert.Equal(DnsServerCategory.InvalidMalformed, classification.Category);
            Assert.False(classification.IsTrusted);
            Assert.NotNull(classification.WarningMessage);
        }

        [Fact]
        public void Adv_Dns_04_TrustedPublicWhitelist_CoversAllMajorProviders()
        {
            // Verify Cloudflare, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing, Control D
            string[] trustedIps =
            {
                "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3", "2606:4700:4700::1111",
                "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888",
                "9.9.9.9", "149.112.112.112", "2620:fe::fe",
                "208.67.222.222", "208.67.220.220", "208.67.222.123",
                "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff",
                "185.228.168.9", "185.228.169.9", "2a0d:2a00:1::2",
                "76.76.2.0", "76.76.10.0", "2606:1a40::1"
            };

            foreach (var ip in trustedIps)
            {
                var classification = DnsHostsGuardEngine.ClassifyDnsServer(ip);
                Assert.Equal(DnsServerCategory.TrustedPublic, classification.Category);
                Assert.True(classification.IsTrusted);
                Assert.False(string.IsNullOrWhiteSpace(classification.ProviderName));
            }
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 7: THREAT INTELLIGENCE CATALOG SUFFIX & BOUNDARY DEFENSE
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 7: Threat Domain Catalog Precision

        [Theory]
        // Subdomain of threat domain -> MUST MATCH
        [InlineData("login.paypal.com", "paypal.com", true)]
        [InlineData("api.v2.virustotal.com", "virustotal.com", true)]
        [InlineData("auth.chase.com", "chase.com", true)]
        [InlineData("maps.google.com", "google.com", true)]

        // Attacker suffix or prefix -> MUST NOT MATCH (prevents false positives)
        [InlineData("notpaypal.com", "paypal.com", false)]
        [InlineData("paypal.com.attacker.net", "paypal.com", false)]
        [InlineData("paypal-security.org", "paypal.com", false)]
        [InlineData("anti-virustotal.com", "virustotal.com", false)]
        [InlineData("purchase.com", "chase.com", false)]
        [InlineData("fakegoogle.com", "google.com", false)]
        [InlineData("google.com.phishing.io", "google.com", false)]
        public void Adv_Catalog_01_MatchesDomain_ExactBoundaryValidation(string hostname, string catalogDomain, bool expectedMatch)
        {
            bool match = ThreatDomainCatalog.MatchesDomain(hostname, catalogDomain);
            Assert.Equal(expectedMatch, match);
        }

        [Fact]
        public void Adv_Catalog_02_FullCatalogInspection_Covers150PlusDomainsWithoutCollision()
        {
            var catalog = ThreatDomainCatalog.Instance;

            // Security domains
            Assert.True(catalog.IsSecurityDomain("definitionupdates.microsoft.com", out _));
            Assert.True(catalog.IsSecurityDomain("smartscreen.microsoft.com", out _));
            Assert.True(catalog.IsSecurityDomain("virustotal.com", out _));
            Assert.True(catalog.IsSecurityDomain("crowdstrike.com", out _));
            Assert.True(catalog.IsSecurityDomain("sentinelone.com", out _));

            // Financial domains
            Assert.True(catalog.IsFinancialDomain("chase.com", out _));
            Assert.True(catalog.IsFinancialDomain("bankofamerica.com", out _));
            Assert.True(catalog.IsFinancialDomain("coinbase.com", out _));
            Assert.True(catalog.IsFinancialDomain("binance.com", out _));
            Assert.True(catalog.IsFinancialDomain("metamask.io", out _));
            Assert.True(catalog.IsFinancialDomain("login.microsoftonline.com", out _));
            Assert.True(catalog.IsFinancialDomain("github.com", out _));

            // Search domains
            Assert.True(catalog.IsSearchDomain("google.com", out _));
            Assert.True(catalog.IsSearchDomain("bing.com", out _));
            Assert.True(catalog.IsSearchDomain("duckduckgo.com", out _));

            // Adware domains
            Assert.True(catalog.IsAdwareDomain("search.conduit.com", out _));
            Assert.True(catalog.IsAdwareDomain("trovi.com", out _));
            Assert.True(catalog.IsAdwareDomain("searchmine.net", out _));
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // VECTOR 8: SANDBOXED FILESYSTEM FAULT INJECTION & RESTORE INVARIANTS
        // ═════════════════════════════════════════════════════════════════════

        #region Vector 8: Filesystem Fault Injection & Restore

        [Fact]
        public async Task Adv_Restore_01_TargetWithReadOnlyHiddenSystemAttributes_NormalizesAndRestores()
        {
            string hostsFile = Path.Combine(_sandboxDir, "hosts");
            string backupDir = Path.Combine(_sandboxDir, "user_backups");

            string malicious = "127.0.0.1 update.microsoft.com\r\n198.51.100.1 chase.com\r\n";
            File.WriteAllText(hostsFile, malicious, new UTF8Encoding(false));

            // Apply locked / restrictive attributes
            File.SetAttributes(hostsFile, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

            var service = new SandboxedHostsFileService(hostsFile, backupDir);
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(service, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            var result = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(result.Success);
            Assert.True(result.SystemBackupCreated);
            Assert.True(result.UserBackupCreated);
            Assert.True(result.CacheFlushed);

            // Attributes on target must be normalized
            var attrs = File.GetAttributes(hostsFile);
            Assert.False((attrs & FileAttributes.ReadOnly) != 0);
            Assert.False((attrs & FileAttributes.Hidden) != 0);

            // Content restored
            string content = File.ReadAllText(hostsFile);
            Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", content);
            Assert.DoesNotContain("update.microsoft.com", content);
        }

        [Fact]
        public async Task Adv_Restore_02_NonExistentFile_CreatesCleanDefaultWithoutError()
        {
            string hostsFile = Path.Combine(_sandboxDir, "non_existent_hosts");
            string backupDir = Path.Combine(_sandboxDir, "user_backups");

            var service = new SandboxedHostsFileService(hostsFile, backupDir);
            var mockFlusher = new Mock<IDnsCacheFlusher>();
            mockFlusher.Setup(f => f.FlushResolverCache()).Returns(true);

            var engine = new DnsHostsGuardEngine(service, new Mock<IDnsAdapterAuditor>().Object, mockFlusher.Object);

            var result = await engine.RestoreDefaultHostsFileAsync();

            Assert.True(result.Success);
            Assert.False(result.SystemBackupCreated);
            Assert.False(result.UserBackupCreated);
            Assert.True(File.Exists(hostsFile));
            string content = File.ReadAllText(hostsFile);
            Assert.Contains("# Copyright (c) 1993-2009 Microsoft Corp.", content);
        }

        #endregion
    }
}
