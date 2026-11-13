// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – HyperStoreCliTests
// Comprehensive test suite for Requirement R5: HyperStore CLI Primitives.
// Tests store scan, dedup, pack, unpack, JSON envelopes, ANSI output,
// exit codes, error handling, and end-to-end roundtrip containerization.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace LogicFlow.Tests.Storage;

[Collection("CliConsoleExecution")]
public sealed class HyperStoreCliTests : IDisposable
{
    private static readonly Assembly CliAssembly = LoadCliAssembly();
    private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
    private static readonly Type StoreCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.StoreCommands")!;
    private static readonly Type ProgramType = CliAssembly.GetType("LogicFlow.CLI.Program")!;

    private readonly string _sandboxDir;
    private static readonly object ConsoleSyncLock = new();

    public HyperStoreCliTests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), "LF_HyperStoreCliTest_" + Guid.NewGuid().ToString("N"));
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

    #region Reflection Invocation Helpers

    private static Assembly LoadCliAssembly()
    {
        try
        {
            return Assembly.Load("lf");
        }
        catch
        {
            string localLf = Path.Combine(AppContext.BaseDirectory, "lf.dll");
            if (File.Exists(localLf)) return Assembly.LoadFrom(localLf);

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

    private static (int ExitCode, string StdOut, string StdErr) RunStoreCommand(object ctx, string command)
    {
        lock (ConsoleSyncLock)
        {
            var runMethod = StoreCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
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

    private static (int ExitCode, string StdOut, string StdErr) RunProgramMain(params string[] args)
    {
        lock (ConsoleSyncLock)
        {
            var mainMethod = ProgramType.GetMethod("Main", BindingFlags.NonPublic | BindingFlags.Static)!;
            var originalOut = Console.Out;
            var originalErr = Console.Error;
            using var swOut = new StringWriter();
            using var swErr = new StringWriter();

            try
            {
                Console.SetOut(swOut);
                Console.SetError(swErr);
                int exitCode = (int)mainMethod.Invoke(null, new object[] { args })!;
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

    #region Sample Data Generators

    private string CreateDuplicateFilesFixture(int copyCount = 3, int distinctCount = 2, int fileSize = 16384)
    {
        string fixtureDir = Path.Combine(_sandboxDir, "SampleData_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixtureDir);

        byte[] dupBytes = new byte[fileSize];
        for (int i = 0; i < dupBytes.Length; i++)
        {
            dupBytes[i] = (byte)((i * 37) ^ 0x5A);
        }

        for (int i = 0; i < copyCount; i++)
        {
            string path = Path.Combine(fixtureDir, $"duplicate_file_{i}.bin");
            File.WriteAllBytes(path, dupBytes);
        }

        for (int i = 0; i < distinctCount; i++)
        {
            byte[] distinctBytes = new byte[fileSize];
            for (int k = 0; k < distinctBytes.Length; k++)
            {
                distinctBytes[k] = (byte)((k * (i + 13)) ^ 0xA5);
            }
            string path = Path.Combine(fixtureDir, $"distinct_file_{i}.bin");
            File.WriteAllBytes(path, distinctBytes);
        }

        return fixtureDir;
    }

    private string CreateComplexDirectoryTreeFixture()
    {
        string rootDir = Path.Combine(_sandboxDir, "ComplexTree_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);

        // Subdirectories
        string sub1 = Path.Combine(rootDir, "docs");
        string sub2 = Path.Combine(rootDir, "data", "binaries");
        Directory.CreateDirectory(sub1);
        Directory.CreateDirectory(sub2);

        // Content
        File.WriteAllText(Path.Combine(rootDir, "readme.txt"), "LogicFlow HyperStore V-Dense Test Container");
        File.WriteAllText(Path.Combine(sub1, "spec.json"), "{ \"version\": \"1.0.0\", \"engine\": \"FastCDC\" }");

        byte[] testData = new byte[65536];
        new Random(42).NextBytes(testData);
        File.WriteAllBytes(Path.Combine(sub2, "payload.dat"), testData);

        return rootDir;
    }

    #endregion

    // ═════════════════════════════════════════════════════════════════════
    // 1. STORE SCAN TESTS
    // ═════════════════════════════════════════════════════════════════════

    [Fact]
    public void StoreScan_ValidDirectoryWithDuplicates_ReportsDuplicatesAndPotentialSavings()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 3, distinctCount: 1, fileSize: 16384);
        var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "store", "scan", sampleDir);

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "scan");

        Assert.Equal(0, exitCode);
        Assert.Contains("LogicFlow HyperStore (V-Dense) — Redundancy & Chunk Scanner", stdOut);
        Assert.Contains("Exact Duplicate Files", stdOut);
        Assert.Contains("Total Potential Savings", stdOut);
        Assert.Contains("FastCDC Chunks Indexed", stdOut);
    }

    [Fact]
    public void StoreScan_JsonEnvelope_ReturnsValidContract()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 2, fileSize: 16384);
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "scan", sampleDir, "--json");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "scan");

        Assert.Equal(0, exitCode);
        string trimmed = stdOut.Trim();
        Assert.StartsWith("{", trimmed);
        Assert.EndsWith("}", trimmed);

        using var doc = JsonDocument.Parse(trimmed);
        var root = doc.RootElement;
        Assert.Equal("SUCCESS", root.GetProperty("status").GetString());
        Assert.Equal("scan", root.GetProperty("command").GetString());
        Assert.Equal(4, root.GetProperty("scannedFiles").GetInt32());
        Assert.True(root.GetProperty("chunksIndexed").GetInt32() > 0);
        Assert.True(root.GetProperty("exactDuplicateFiles").GetInt32() >= 1);
        Assert.True(root.GetProperty("potentialSavingsBytes").GetInt64() > 0);
        Assert.True(root.TryGetProperty("minHashSimilarity", out _));
        Assert.True(root.TryGetProperty("durationMs", out _));
    }

    [Fact]
    public void StoreScan_CustomMinSize_FiltersSmallerFiles()
    {
        string fixtureDir = Path.Combine(_sandboxDir, "FilterTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixtureDir);

        File.WriteAllBytes(Path.Combine(fixtureDir, "small.dat"), new byte[1024]);
        File.WriteAllBytes(Path.Combine(fixtureDir, "large.dat"), new byte[32768]);

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "scan", fixtureDir, "--min-size", "16384", "--json");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "scan");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.Equal(1, doc.RootElement.GetProperty("scannedFiles").GetInt32());
    }

    [Fact]
    public void StoreScan_NonExistentDirectory_ReturnsExitCode2()
    {
        string fakeDir = Path.Combine(_sandboxDir, "NonExistent_" + Guid.NewGuid().ToString("N"));
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "scan", fakeDir);

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "scan");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StoreScan_MissingPathArgument_ReturnsExitCode2()
    {
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "scan");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "scan");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("Missing required argument", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 2. STORE DEDUP TESTS
    // ═════════════════════════════════════════════════════════════════════

    [Fact]
    public void StoreDedup_DryRun_ReportsSavingsWithoutModifyingFiles()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 1, fileSize: 16384);
        var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "store", "dedup", sampleDir, "--dry-run");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(0, exitCode);
        Assert.Contains("Dry Run", stdOut);
        Assert.Contains("DEDUPLICATION SUMMARY", stdOut);
        Assert.Contains("Physical Space Freed", stdOut);

        // Verify all 3 files still exist independently
        Assert.Equal(3, Directory.GetFiles(sampleDir).Length);
    }

    [Fact]
    public void StoreDedup_DryRun_JsonEnvelope_ReturnsValidContract()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 1, fileSize: 16384);
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "dedup", sampleDir, "--dry-run", "--json");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        var root = doc.RootElement;
        Assert.Equal("SUCCESS", root.GetProperty("status").GetString());
        Assert.Equal("dedup", root.GetProperty("command").GetString());
        Assert.True(root.GetProperty("dryRun").GetBoolean());
        Assert.Equal(3, root.GetProperty("filesProcessed").GetInt32());
        Assert.True(root.GetProperty("duplicateClusters").GetInt32() >= 1);
        Assert.True(root.GetProperty("physicalBytesReclaimed").GetInt64() > 0);
    }

    [Fact]
    public void StoreDedup_LiveExecution_WithForce_ExecutesSuccessfully()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 1, fileSize: 16384);
        var ctx = CreateCliContext(isJson: false, isForce: true, isSilent: false, "store", "dedup", sampleDir, "--force");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(0, exitCode);
        Assert.Contains("Live In-Place Consolidation", stdOut);
        Assert.Contains("Files Consolidated", stdOut);
    }

    [Fact]
    public void StoreDedup_LiveExecution_JsonEnvelope_ReturnsValidContract()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 0, fileSize: 16384);
        var ctx = CreateCliContext(isJson: true, isForce: true, isSilent: false, "store", "dedup", sampleDir, "--force", "--json");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        var root = doc.RootElement;
        Assert.Equal("SUCCESS", root.GetProperty("status").GetString());
        Assert.False(root.GetProperty("dryRun").GetBoolean());
        Assert.True(root.GetProperty("filesConsolidated").GetInt32() >= 1);
    }

    [Fact]
    public void StoreDedup_NonExistentDirectory_ReturnsExitCode2()
    {
        string fakeDir = Path.Combine(_sandboxDir, "FakeDedup_" + Guid.NewGuid().ToString("N"));
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "dedup", fakeDir, "--dry-run");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StoreDedup_MissingPathArgument_ReturnsExitCode2()
    {
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "dedup");

        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "dedup");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("Missing required argument", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 3. STORE PACK & UNPACK ROUNDTRIP TESTS
    // ═════════════════════════════════════════════════════════════════════

    [Fact]
    public void StorePack_DirectoryToLfc_CreatesValidContainer()
    {
        string inputDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "archive.lfc");

        var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "store", "pack", inputDir, lfcFile, "--tier", "hot");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(lfcFile));
        Assert.True(new FileInfo(lfcFile).Length > 64);
        Assert.Contains("PACK COMPLETE", stdOut);
        Assert.Contains("Global Compression Ratio", stdOut);
    }

    [Fact]
    public void StorePack_JsonEnvelope_ReturnsValidContract()
    {
        string inputDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "archive_json.lfc");

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "pack", inputDir, lfcFile, "--json");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        var root = doc.RootElement;
        Assert.Equal("SUCCESS", root.GetProperty("status").GetString());
        Assert.Equal("pack", root.GetProperty("command").GetString());
        Assert.Equal("Hot", root.GetProperty("tier").GetString());
        Assert.True(root.GetProperty("rawSizeBytes").GetInt64() > 0);
        Assert.True(root.GetProperty("containerSizeBytes").GetInt64() > 0);
        Assert.True(root.GetProperty("compressionRatio").GetDouble() >= 1.0);
    }

    [Fact]
    public void StorePack_ColdTier_WithDict_ExecutesSuccessfully()
    {
        string inputDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "archive_cold.lfc");

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "pack", inputDir, lfcFile, "--tier", "cold", "--dict", "--json");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        var root = doc.RootElement;
        Assert.Equal("Cold", root.GetProperty("tier").GetString());
        Assert.True(root.GetProperty("trainDictionary").GetBoolean());
    }

    [Fact]
    public void StorePack_OutputAlreadyExistsWithoutForce_ReturnsExitCode2()
    {
        string inputDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "existing.lfc");
        File.WriteAllText(lfcFile, "dummy");

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "pack", inputDir, lfcFile);
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("already exists", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StorePack_NonExistentSourceDir_ReturnsExitCode2()
    {
        string fakeDir = Path.Combine(_sandboxDir, "NonExistentPack_" + Guid.NewGuid().ToString("N"));
        string lfcFile = Path.Combine(_sandboxDir, "out.lfc");

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "pack", fakeDir, lfcFile);
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StorePack_MissingArguments_ReturnsExitCode2()
    {
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "pack", "only_one_arg");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "pack");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("Missing required arguments", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StoreUnpack_RestoresContainerAndVerifiesIntegrity()
    {
        string sourceDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "roundtrip.lfc");
        string unpackDir = Path.Combine(_sandboxDir, "Restored_" + Guid.NewGuid().ToString("N"));

        // 1. Pack
        var packCtx = CreateCliContext(isJson: false, isForce: true, isSilent: true, "store", "pack", sourceDir, lfcFile);
        var (packCode, _, _) = RunStoreCommand(packCtx, "pack");
        Assert.Equal(0, packCode);

        // 2. Unpack
        var unpackCtx = CreateCliContext(isJson: false, isForce: true, isSilent: false, "store", "unpack", lfcFile, unpackDir);
        var (unpackCode, unpackOut, _) = RunStoreCommand(unpackCtx, "unpack");

        Assert.Equal(0, unpackCode);
        Assert.Contains("UNPACK COMPLETE", unpackOut);
        Assert.Contains("Integrity Status        : PASS", unpackOut);

        // 3. Verify files match source
        var originalFiles = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
        var restoredFiles = Directory.GetFiles(unpackDir, "*", SearchOption.AllDirectories);
        Assert.Equal(originalFiles.Length, restoredFiles.Length);

        foreach (var orig in originalFiles)
        {
            string rel = Path.GetRelativePath(sourceDir, orig);
            string restored = Path.Combine(unpackDir, rel);
            Assert.True(File.Exists(restored), $"Restored file missing: {rel}");

            byte[] b1 = File.ReadAllBytes(orig);
            byte[] b2 = File.ReadAllBytes(restored);
            Assert.Equal(b1, b2);
        }
    }

    [Fact]
    public void StoreUnpack_JsonEnvelope_ReturnsValidContract()
    {
        string sourceDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "unpack_json.lfc");
        string unpackDir = Path.Combine(_sandboxDir, "RestoredJson_" + Guid.NewGuid().ToString("N"));

        // Pack first
        var packCtx = CreateCliContext(isJson: true, isForce: true, isSilent: true, "store", "pack", sourceDir, lfcFile);
        RunStoreCommand(packCtx, "pack");

        // Unpack with --json
        var unpackCtx = CreateCliContext(isJson: true, isForce: true, isSilent: false, "store", "unpack", lfcFile, unpackDir, "--json");
        var (exitCode, stdOut, _) = RunStoreCommand(unpackCtx, "unpack");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        var root = doc.RootElement;
        Assert.Equal("SUCCESS", root.GetProperty("status").GetString());
        Assert.Equal("unpack", root.GetProperty("command").GetString());
        Assert.True(root.GetProperty("verificationSuccess").GetBoolean());
        Assert.True(root.GetProperty("filesRestored").GetInt32() > 0);
        Assert.True(root.GetProperty("totalBytesExtracted").GetInt64() > 0);
    }

    [Fact]
    public void StoreUnpack_NoVerifyFlag_SkipsHashVerification()
    {
        string sourceDir = CreateComplexDirectoryTreeFixture();
        string lfcFile = Path.Combine(_sandboxDir, "noverify.lfc");
        string unpackDir = Path.Combine(_sandboxDir, "RestoredNoVerify_" + Guid.NewGuid().ToString("N"));

        var packCtx = CreateCliContext(isJson: true, isForce: true, isSilent: true, "store", "pack", sourceDir, lfcFile);
        RunStoreCommand(packCtx, "pack");

        var unpackCtx = CreateCliContext(isJson: true, isForce: true, isSilent: false, "store", "unpack", lfcFile, unpackDir, "--no-verify", "--json");
        var (exitCode, stdOut, _) = RunStoreCommand(unpackCtx, "unpack");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.False(doc.RootElement.GetProperty("verificationSuccess").GetBoolean());
    }

    [Fact]
    public void StoreUnpack_NonExistentLfcFile_ReturnsExitCode2()
    {
        string fakeLfc = Path.Combine(_sandboxDir, "NoSuchContainer.lfc");
        string outDir = Path.Combine(_sandboxDir, "Target");

        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "unpack", fakeLfc, outDir);
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "unpack");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StoreUnpack_MissingArguments_ReturnsExitCode2()
    {
        var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "store", "unpack");
        var (exitCode, stdOut, _) = RunStoreCommand(ctx, "unpack");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("Missing required arguments", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 4. PROGRAM.MAIN ROUTING & HELP TESTS
    // ═════════════════════════════════════════════════════════════════════

    [Fact]
    public void ProgramMain_StoreHelp_DisplaysAvailableCommands()
    {
        var (exitCode, stdOut, _) = RunProgramMain("store", "help");

        Assert.Equal(0, exitCode);
        Assert.Contains("LogicFlow HyperStore (V-Dense) CLI Commands", stdOut);
        Assert.Contains("scan", stdOut);
        Assert.Contains("dedup", stdOut);
        Assert.Contains("pack", stdOut);
        Assert.Contains("unpack", stdOut);
    }

    [Fact]
    public void ProgramMain_RootHelp_ListsStoreGroup()
    {
        var (exitCode, stdOut, _) = RunProgramMain("help");

        Assert.Equal(0, exitCode);
        Assert.Contains("store", stdOut);
    }

    [Fact]
    public void ProgramMain_StoreScanJson_ExecutesViaMain()
    {
        string sampleDir = CreateDuplicateFilesFixture(copyCount: 2, distinctCount: 1, fileSize: 16384);
        var (exitCode, stdOut, _) = RunProgramMain("store", "scan", sampleDir, "--json");

        Assert.Equal(0, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.Equal("SUCCESS", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal("scan", doc.RootElement.GetProperty("command").GetString());
    }

    [Fact]
    public void ProgramMain_StoreUnknownSubcommand_ReturnsExitCode2()
    {
        var (exitCode, stdOut, _) = RunProgramMain("store", "unknown-command-xyz", "--json");

        Assert.Equal(2, exitCode);
        using var doc = JsonDocument.Parse(stdOut.Trim());
        Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
        Assert.Contains("Unknown store command", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
    }
}
