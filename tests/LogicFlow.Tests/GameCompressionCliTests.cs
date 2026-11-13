// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – GameCompressionCliTests
// Unit & Integration test suite for CLI Game Compact commands, Toolbox aliasing,
// argument parsing, options processing, stdout/stderr capture, and JSON contracts.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using LogicFlow.Guardian;
using LogicFlow.Native;
using Xunit;

namespace LogicFlow.Tests
{
    [Collection("CliConsoleExecution")]
    public sealed class GameCompressionCliTests : IDisposable
    {
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type AppCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.AppCommands")!;
        private static readonly Type ToolboxCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.ToolboxCommands")!;
        private static readonly Type ProgramType = CliAssembly.GetType("LogicFlow.CLI.Program")!;

        private readonly string _sandboxDir;
        private static readonly object ConsoleSyncLock = new();

        public GameCompressionCliTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "LF_CliCompactTest_" + Guid.NewGuid().ToString("N"));
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
                        try
                        {
                            File.SetAttributes(file, FileAttributes.Normal);
                            WofNative.DecompressFile(file);
                        }
                        catch { }
                    }
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch { /* Best effort cleanup */ }
        }

        #region CLI Invocation Helpers

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

                throw new InvalidOperationException($"Could not find lf.dll assembly. BaseDirectory: {AppContext.BaseDirectory}");
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

        private static (int ExitCode, string StdOut, string StdErr) RunAppCommand(object ctx, string command)
        {
            lock (ConsoleSyncLock)
            {
                var runMethod = AppCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
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

        private static (int ExitCode, string StdOut, string StdErr) RunToolboxCommand(object ctx, string command)
        {
            lock (ConsoleSyncLock)
            {
                var runMethod = ToolboxCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
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

        // ═════════════════════════════════════════════════════════════════════
        // 1. TOOLBOX ALIASING & ROUTING TESTS
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public void ToolboxCommands_GameCompact_List_RoutesSeamlesslyToAppCommands()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "toolbox", "game-compact", "list");
            var (exitCode, stdOut, _) = RunToolboxCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            string trimmed = stdOut.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);

            using var doc = JsonDocument.Parse(trimmed);
            Assert.NotNull(doc);
            Assert.True(doc.RootElement.TryGetProperty("status", out var statusProp));
            Assert.Equal("SUCCESS", statusProp.GetString());
        }

        [Fact]
        public void ToolboxCommands_GameCompact_ParityWithAppCommands()
        {
            var ctxApp = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "list");
            var (exitCodeApp, stdOutApp, _) = RunAppCommand(ctxApp, "game-compact");

            var ctxToolbox = CreateCliContext(isJson: true, isForce: false, isSilent: false, "toolbox", "game-compact", "list");
            var (exitCodeToolbox, stdOutToolbox, _) = RunToolboxCommand(ctxToolbox, "game-compact");

            Assert.Equal(exitCodeApp, exitCodeToolbox);
            Assert.Equal(0, exitCodeToolbox);

            using var docApp = JsonDocument.Parse(stdOutApp.Trim());
            using var docToolbox = JsonDocument.Parse(stdOutToolbox.Trim());

            Assert.Equal(docApp.RootElement.GetProperty("status").GetString(), docToolbox.RootElement.GetProperty("status").GetString());
            Assert.Equal(docApp.RootElement.TryGetProperty("count", out _), docToolbox.RootElement.TryGetProperty("count", out _));
            Assert.Equal(docApp.RootElement.TryGetProperty("games", out _), docToolbox.RootElement.TryGetProperty("games", out _));
        }

        [Fact]
        public void ToolboxCommands_UnknownCommand_ListsGameCompactInAvailable()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "toolbox", "unknown-command-xyz");
            var (exitCode, stdOut, _) = RunToolboxCommand(ctx, "unknown-command-xyz");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("error", out var errProp));
            Assert.Contains("game-compact", errProp.GetString());
        }

        [Fact]
        public void ProgramMain_AppGameCompact_List_ExecutesSuccessfully()
        {
            var (exitCode, stdOut, _) = RunProgramMain("app", "game-compact", "list", "--json");

            Assert.Equal(0, exitCode);
            string trimmed = stdOut.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);
            using var doc = JsonDocument.Parse(trimmed);
            Assert.True(doc.RootElement.TryGetProperty("status", out var statusProp));
            Assert.Equal("SUCCESS", statusProp.GetString());
        }

        [Fact]
        public void ProgramMain_ToolboxGameCompact_List_ExecutesSuccessfully()
        {
            var (exitCode, stdOut, _) = RunProgramMain("toolbox", "game-compact", "list", "--json");

            Assert.Equal(0, exitCode);
            string trimmed = stdOut.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);
            using var doc = JsonDocument.Parse(trimmed);
            Assert.True(doc.RootElement.TryGetProperty("status", out var statusProp));
            Assert.Equal("SUCCESS", statusProp.GetString());
        }

        // ═════════════════════════════════════════════════════════════════════
        // 2. SUBCOMMAND ROUTING & OPTION PARSING
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public void GameCompact_List_TextMode_OutputsHumanReadableTable()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "app", "game-compact", "list");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            Assert.False(string.IsNullOrWhiteSpace(stdOut));
            Assert.Contains("[GAME-COMPACT]", stdOut);
        }

        [Fact]
        public void GameCompact_List_JsonMode_ValidContract()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "list");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out var statusProp));
            Assert.Equal("SUCCESS", statusProp.GetString());
            Assert.True(root.TryGetProperty("games", out var gamesProp));
            Assert.Equal(JsonValueKind.Array, gamesProp.ValueKind);
            Assert.True(root.TryGetProperty("totalSizeBytes", out _));
            Assert.True(root.TryGetProperty("totalEstimatedSavingsBytes", out _));
        }

        [Fact]
        public void GameCompact_Compress_MissingTarget_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("Missing target", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GameCompact_Compress_NonExistentGame_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress", "NonExistentGame_XYZ_999");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("lzx")]
        [InlineData("xpress8k")]
        [InlineData("xpress16k")]
        [InlineData("xpress4k")]
        public void GameCompact_Compress_AlgorithmFlags_RecognizedGracefully(string algo)
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress", "NonExistentGame", "--algo", algo);
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            // Fails due to GAME_NOT_FOUND, not INVALID_ALGORITHM
            Assert.True(root.TryGetProperty("details", out var detailsProp));
            Assert.True(detailsProp.TryGetProperty("status", out var statusProp));
            Assert.Equal("GAME_NOT_FOUND", statusProp.GetString());
        }

        [Fact]
        public void GameCompact_Compress_InvalidAlgorithm_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress", "SomeGame", "--algo", "bogus_algo");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("details", out var detailsProp));
            Assert.True(detailsProp.TryGetProperty("error", out var errProp));
            Assert.Equal("INVALID_ALGORITHM", errProp.GetString());
        }

        [Fact]
        public void GameCompact_Decompress_MissingTarget_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "decompress");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("Missing target", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GameCompact_Decompress_NonExistentGame_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "decompress", "NonExistentGame_XYZ_999");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GameCompact_DecayAudit_TextMode_OutputsReport()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "app", "game-compact", "decay-audit");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            Assert.Contains("[DECAY-AUDIT]", stdOut);
        }

        [Fact]
        public void GameCompact_DecayAudit_JsonMode_ValidContract()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "decay-audit");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            string trimmed = stdOut.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);

            using var doc = JsonDocument.Parse(trimmed);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("totalGamesAudited", out _));
            Assert.True(root.TryGetProperty("gamesWithDecay", out _));
            Assert.True(root.TryGetProperty("decayedGames", out _));
        }

        [Fact]
        public void GameCompact_Recompact_MissingTarget_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "recompact");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("Missing target", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GameCompact_Recompact_NonExistentGame_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "recompact", "NonExistentGame_XYZ_999");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.True(doc.RootElement.TryGetProperty("error", out var errProp));
            Assert.Contains("not found", errProp.GetString(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GameCompact_UnknownSubcommand_ReturnsExitCode1_AndJsonEnvelope()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "bogus-subcommand");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("error", out var errorProp));
            Assert.Contains("Unknown game-compact subcommand", errorProp.GetString());
        }

        [Fact]
        public void GameCompact_Help_ReturnsExitCode0()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "help");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("command", out var cmdProp));
            Assert.Equal("game-compact", cmdProp.GetString());
        }

        // ═════════════════════════════════════════════════════════════════════
        // 3. CONFORMANCE, SILENT & ADVERSARIAL CASES
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public void GameCompact_SilentMode_SuppressesAllOutput()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: true, "app", "game-compact", "list");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

            Assert.Equal(0, exitCode);
            Assert.Equal(string.Empty, stdOut.Trim());
        }

        [Fact]
        public void GameCompact_CaseInsensitiveRouting_ExecutesCleanly()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "APP", "GAME-COMPACT", "LIST");
            var (exitCode, stdOut, _) = RunAppCommand(ctx, "GAME-COMPACT");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut.Trim());
            Assert.NotNull(doc);
        }

        [Fact]
        public void GameCompact_AllCommands_JsonMode_ZeroTrailingNoise()
        {
            string[] subcommands = { "list", "decay-audit" };
            foreach (var sub in subcommands)
            {
                var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", sub);
                var (exitCode, stdOut, _) = RunAppCommand(ctx, "game-compact");

                Assert.Equal(0, exitCode);
                string trimmed = stdOut.Trim();
                Assert.StartsWith("{", trimmed);
                Assert.EndsWith("}", trimmed);
                using var doc = JsonDocument.Parse(trimmed);
                Assert.NotNull(doc);
            }
        }

        [Fact]
        public void GameCompact_DirectStorageSkip_FlagParsedProperly()
        {
            // Verify --skip-directstorage and --no-skip-directstorage do not crash and handle flags
            var ctxSkip = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress", "FakeGame", "--skip-directstorage");
            var (exitCodeSkip, stdOutSkip, _) = RunAppCommand(ctxSkip, "game-compact");
            Assert.Equal(1, exitCodeSkip);

            var ctxNoSkip = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "compress", "FakeGame", "--no-skip-directstorage");
            var (exitCodeNoSkip, stdOutNoSkip, _) = RunAppCommand(ctxNoSkip, "game-compact");
            Assert.Equal(1, exitCodeNoSkip);
        }

        [Fact]
        public async Task GameCompact_E2E_SyntheticGame_EngineDirect_Cycle()
        {
            // Create a synthetic game install directory with compressible payload
            string gameDir = Path.Combine(_sandboxDir, "TestGame_E2E");
            Directory.CreateDirectory(gameDir);

            // Generate repetitive, highly compressible data
            for (int i = 0; i < 5; i++)
            {
                string filePath = Path.Combine(gameDir, $"data_{i}.dat");
                byte[] buffer = new byte[64 * 1024];
                for (int j = 0; j < buffer.Length; j++)
                {
                    buffer[j] = (byte)(j % 16);
                }
                File.WriteAllBytes(filePath, buffer);
            }

            var game = new DetectedGame(
                GameId: "custom_test_game_1",
                Title: "Synthetic Test Game",
                InstallDirectory: gameDir,
                Launcher: LauncherType.Custom,
                SizeOnDiskBytes: 5 * 64 * 1024,
                HasDirectStorage: false);

            var engine = GameCompressionEngine.Instance;
            var compressSummary = await engine.CompressGameAsync(game, GameCompressionOptions.Default);

            Assert.True(compressSummary.Success);
            Assert.Equal(5, compressSummary.FilesProcessed);

            // Verify decompression
            var decompressSummary = await engine.DecompressGameAsync(game);
            Assert.True(decompressSummary.Success);
            Assert.Equal(5, decompressSummary.FilesProcessed);
        }
    }
}
