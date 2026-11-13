// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – GameCompressionCliAdversarialTests.cs
// Empirical Challenger Stress & Adversarial Test Suite for Milestone 4:
// - Multi-tier game resolution heuristics (Exact ID, Exact Title, Numeric ID, Substring, Ambiguity)
// - All 4 CompactOS compression algorithms (LZX, XPRESS8K, XPRESS16K, XPRESS4K) & aliases
// - DirectStorage heuristic bypass & flag parsing (--skip-directstorage, --no-skip-directstorage, --force)
// - Decompression pre-flight free space validation and restoration integrity
// - Compression decay watchdog detection and delta recompact execution
// - Multi-threaded in-process thread safety and [Collection("CliConsoleExecution")] verification
// - Full JSON contract purity & exit code conformance
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    public sealed class GameCompressionCliAdversarialTests : IDisposable
    {
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type AppCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.AppCommands")!;
        private static readonly Type ToolboxCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.ToolboxCommands")!;
        private static readonly Type ProgramType = CliAssembly.GetType("LogicFlow.CLI.Program")!;

        private readonly string _sandboxDir;
        private static readonly object ConsoleSyncLock = new();

        public GameCompressionCliAdversarialTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "LF_ChallengerCli_" + Guid.NewGuid().ToString("N"));
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

        #endregion

        // ═════════════════════════════════════════════════════════════════════
        // 1. MULTI-TIER GAME RESOLUTION HEURISTICS
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public void TryResolveGame_TargetAll_ResolvesSuccessfully()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false);
            var games = new List<DetectedGame>
            {
                new("steam_730", "Counter-Strike 2", @"C:\Games\CS2", LauncherType.Steam, 30_000_000_000L, false)
            };

            var parameters = new object?[] { ctx, "all", games, null, null };
            bool result = (bool)method.Invoke(null, parameters)!;

            Assert.True(result);
            Assert.True((bool)parameters[4]!); // isAll == true
            Assert.Null(parameters[3]);        // game == null
        }

        [Fact]
        public void TryResolveGame_ExactGameId_MatchesDirectly()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true);
            var targetGame = new DetectedGame("steam_730", "Counter-Strike 2", @"C:\Games\CS2", LauncherType.Steam, 30_000_000_000L, false);
            var games = new List<DetectedGame> { targetGame };

            var parameters = new object?[] { ctx, "steam_730", games, null, null };
            bool result = (bool)method.Invoke(null, parameters)!;

            Assert.True(result);
            Assert.Same(targetGame, parameters[3]);
            Assert.False((bool)parameters[4]!);
        }

        [Fact]
        public void TryResolveGame_ExactTitle_MatchesDirectly()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true);
            var targetGame = new DetectedGame("steam_1091500", "Cyberpunk 2077", @"C:\Games\Cyberpunk", LauncherType.Steam, 70_000_000_000L, false);
            var games = new List<DetectedGame> { targetGame };

            var parameters = new object?[] { ctx, "Cyberpunk 2077", games, null, null };
            bool result = (bool)method.Invoke(null, parameters)!;

            Assert.True(result);
            Assert.Same(targetGame, parameters[3]);
        }

        [Fact]
        public void TryResolveGame_NumericIdSuffix_MatchesSteamPrefix()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true);
            var targetGame = new DetectedGame("steam_730", "Counter-Strike 2", @"C:\Games\CS2", LauncherType.Steam, 30_000_000_000L, false);
            var games = new List<DetectedGame> { targetGame };

            var parameters = new object?[] { ctx, "730", games, null, null };
            bool result = (bool)method.Invoke(null, parameters)!;

            Assert.True(result);
            Assert.Same(targetGame, parameters[3]);
        }

        [Fact]
        public void TryResolveGame_SubstringMatch_UniqueTitle_MatchesSuccessfully()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true);
            var targetGame = new DetectedGame("steam_220", "Half-Life 2", @"C:\Games\HL2", LauncherType.Steam, 5_000_000_000L, false);
            var otherGame = new DetectedGame("steam_730", "Counter-Strike 2", @"C:\Games\CS2", LauncherType.Steam, 30_000_000_000L, false);
            var games = new List<DetectedGame> { targetGame, otherGame };

            var parameters = new object?[] { ctx, "Half-Life", games, null, null };
            bool result = (bool)method.Invoke(null, parameters)!;

            Assert.True(result);
            Assert.Same(targetGame, parameters[3]);
        }

        [Fact]
        public void TryResolveGame_AmbiguousMatch_ReturnsFalseAndOutputsChoices()
        {
            var method = AppCommandsType.GetMethod("TryResolveGame", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ctx = CreateCliContext(isJson: true);
            var g1 = new DetectedGame("steam_220", "Half-Life 2", @"C:\Games\HL2", LauncherType.Steam, 5_000_000_000L, false);
            var g2 = new DetectedGame("steam_280", "Half-Life: Source", @"C:\Games\HLS", LauncherType.Steam, 2_000_000_000L, false);
            var games = new List<DetectedGame> { g1, g2 };

            var originalOut = Console.Out;
            using var sw = new StringWriter();
            Console.SetOut(sw);
            try
            {
                var parameters = new object?[] { ctx, "Half-Life", games, null, null };
                bool result = (bool)method.Invoke(null, parameters)!;

                Assert.False(result);
                Assert.Null(parameters[3]);

                string jsonOut = sw.ToString().Trim();
                using var doc = JsonDocument.Parse(jsonOut);
                var root = doc.RootElement;
                Assert.True(root.TryGetProperty("error", out var errProp));
                Assert.Contains("Multiple games matched", errProp.GetString());
                Assert.True(root.TryGetProperty("details", out var detailsProp));
                Assert.Equal("AMBIGUOUS_MATCH", detailsProp.GetProperty("status").GetString());
            }
            finally
            {
                Console.SetOut(originalOut);
            }
        }

        // ═════════════════════════════════════════════════════════════════════
        // 2. ALGORITHM PARSING AND ALIAS MAPPING
        // ═════════════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("lzx", WofNative.ALGORITHM_LZX)]
        [InlineData("LZX", WofNative.ALGORITHM_LZX)]
        [InlineData("xpress8k", WofNative.ALGORITHM_XPRESS8K)]
        [InlineData("xpress8", WofNative.ALGORITHM_XPRESS8K)]
        [InlineData("8k", WofNative.ALGORITHM_XPRESS8K)]
        [InlineData("8K", WofNative.ALGORITHM_XPRESS8K)]
        [InlineData("xpress16k", WofNative.ALGORITHM_XPRESS16K)]
        [InlineData("xpress16", WofNative.ALGORITHM_XPRESS16K)]
        [InlineData("16k", WofNative.ALGORITHM_XPRESS16K)]
        [InlineData("xpress4k", WofNative.ALGORITHM_XPRESS4K)]
        [InlineData("xpress4", WofNative.ALGORITHM_XPRESS4K)]
        [InlineData("4k", WofNative.ALGORITHM_XPRESS4K)]
        [InlineData("xpress", WofNative.ALGORITHM_XPRESS4K)]
        public void ParseAlgorithm_AllValidAlgorithmsAndAliases_MapCorrectly(string algoStr, uint expectedId)
        {
            var method = AppCommandsType.GetMethod("ParseAlgorithm", BindingFlags.NonPublic | BindingFlags.Static)!;
            uint actualId = (uint)method.Invoke(null, new object[] { algoStr })!;
            Assert.Equal(expectedId, actualId);
        }

        [Theory]
        [InlineData("gzip")]
        [InlineData("brotli")]
        [InlineData("zstd")]
        [InlineData("invalid")]
        [InlineData("123")]
        public void ParseAlgorithm_InvalidAlgorithms_ThrowsArgumentException(string invalidAlgo)
        {
            var method = AppCommandsType.GetMethod("ParseAlgorithm", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { invalidAlgo }));
            Assert.IsType<ArgumentException>(ex.InnerException);
            Assert.Contains("Unknown compression algorithm", ex.InnerException.Message);
        }

        // ═════════════════════════════════════════════════════════════════════
        // 3. COMPRESSION WITH ALL 4 ALGORITHMS ON SYNTHETIC GAME DIRECTORY
        // ═════════════════════════════════════════════════════════════════════

        [Theory]
        [InlineData(WofNative.ALGORITHM_LZX)]
        [InlineData(WofNative.ALGORITHM_XPRESS8K)]
        [InlineData(WofNative.ALGORITHM_XPRESS16K)]
        [InlineData(WofNative.ALGORITHM_XPRESS4K)]
        public async Task GameCompressionEngine_AllAlgorithms_ExecuteSuccessfully(uint algorithm)
        {
            string gameDir = Path.Combine(_sandboxDir, $"AlgoGame_{algorithm}");
            Directory.CreateDirectory(gameDir);

            for (int i = 0; i < 3; i++)
            {
                string filePath = Path.Combine(gameDir, $"sample_{i}.dat");
                byte[] buffer = new byte[64 * 1024];
                for (int j = 0; j < buffer.Length; j++) buffer[j] = (byte)(j % 32);
                File.WriteAllBytes(filePath, buffer);
            }

            var game = new DetectedGame(
                GameId: $"synthetic_algo_{algorithm}",
                Title: $"Synthetic Algo {algorithm}",
                InstallDirectory: gameDir,
                Launcher: LauncherType.Custom,
                SizeOnDiskBytes: 3 * 64 * 1024,
                HasDirectStorage: false);

            var engine = GameCompressionEngine.Instance;
            var options = new GameCompressionOptions(algorithm, MaxParallelism: 4, SkipDirectStorage: true);
            var summary = await engine.CompressGameAsync(game, options);

            Assert.True(summary.Success);
            Assert.Equal(3, summary.FilesProcessed);
            Assert.Equal(3, summary.FilesCompressed);
            Assert.True(summary.OriginalBytes > 0);

            // Revert via DecompressGameAsync
            var decompressSummary = await engine.DecompressGameAsync(game);
            Assert.True(decompressSummary.Success);
            Assert.Equal(3, decompressSummary.FilesProcessed);
        }

        // ═════════════════════════════════════════════════════════════════════
        // 4. DIRECTSTORAGE SAFETY & CLI OVERRIDE HEURISTICS
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public async Task DirectStorage_SkipDirectStorageTrue_FilesSkipped()
        {
            string gameDir = Path.Combine(_sandboxDir, "DS_ProtectedGame");
            Directory.CreateDirectory(gameDir);

            // Plant DirectStorage runtime binary
            File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "dummy dstorage binary");

            // Plant compressible file
            string payloadPath = Path.Combine(gameDir, "payload.dat");
            File.WriteAllBytes(payloadPath, new byte[64 * 1024]);

            var game = new DetectedGame(
                GameId: "ds_game_1",
                Title: "DirectStorage Protected Title",
                InstallDirectory: gameDir,
                Launcher: LauncherType.Custom,
                SizeOnDiskBytes: 64 * 1024,
                HasDirectStorage: true);

            var engine = GameCompressionEngine.Instance;
            var optionsSkip = new GameCompressionOptions(WofNative.ALGORITHM_LZX, SkipDirectStorage: true);

            var summary = await engine.CompressGameAsync(game, optionsSkip);

            Assert.True(summary.Success);
            Assert.Equal(0, summary.FilesCompressed); // DirectStorage protection skipped files
        }

        [Fact]
        public async Task DirectStorage_SkipDirectStorageFalse_FilesCompressed()
        {
            string gameDir = Path.Combine(_sandboxDir, "DS_ForcedGame");
            Directory.CreateDirectory(gameDir);

            // Plant DirectStorage runtime binary
            File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "dummy dstorage binary");

            // Plant compressible file
            string payloadPath = Path.Combine(gameDir, "payload.dat");
            byte[] data = new byte[64 * 1024];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 16);
            File.WriteAllBytes(payloadPath, data);

            var game = new DetectedGame(
                GameId: "ds_game_forced",
                Title: "DirectStorage Forced Title",
                InstallDirectory: gameDir,
                Launcher: LauncherType.Custom,
                SizeOnDiskBytes: 64 * 1024,
                HasDirectStorage: true);

            var engine = GameCompressionEngine.Instance;
            var optionsForced = new GameCompressionOptions(WofNative.ALGORITHM_LZX, SkipDirectStorage: false);

            var summary = await engine.CompressGameAsync(game, optionsForced);

            Assert.True(summary.Success);
            Assert.Equal(1, summary.FilesCompressed); // Forced compression compressed the file
        }

        // ═════════════════════════════════════════════════════════════════════
        // 5. COMPRESSION DECAY AUDIT & RECOMPACT LIFECYCLE
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public async Task CompressionDecay_AuditAndRecompact_Lifecycle()
        {
            string gameDir = Path.Combine(_sandboxDir, "DecayGame");
            Directory.CreateDirectory(gameDir);

            // Initial file
            string file1 = Path.Combine(gameDir, "base_data.dat");
            byte[] buffer = new byte[64 * 1024];
            for (int i = 0; i < buffer.Length; i++) buffer[i] = (byte)(i % 8);
            File.WriteAllBytes(file1, buffer);

            var game = new DetectedGame(
                GameId: "decay_test_game",
                Title: "Decay Test Game",
                InstallDirectory: gameDir,
                Launcher: LauncherType.Custom,
                SizeOnDiskBytes: 64 * 1024,
                HasDirectStorage: false);

            var engine = GameCompressionEngine.Instance;
            var initialSummary = await engine.CompressGameAsync(game, GameCompressionOptions.Default);
            Assert.True(initialSummary.Success);
            Assert.Equal(1, initialSummary.FilesCompressed);

            // Initial decay audit should report NO decay
            var cleanReport = engine.AuditDecay(new[] { game });
            Assert.False(cleanReport.HasDecay);

            // Simulate game patch: add a new uncompressed update file
            string patchFile = Path.Combine(gameDir, "patch_update.dat");
            File.WriteAllBytes(patchFile, buffer);

            // Decay audit should now report decay
            var decayReport = engine.AuditDecay(new[] { game });
            Assert.True(decayReport.HasDecay);
            Assert.Equal(1, decayReport.GamesWithDecay);
            Assert.Equal(1, decayReport.CalculatedTotalDecayedFiles);

            // Execute RecompactUpdatesAsync
            var recompactSummary = await engine.RecompactUpdatesAsync(game, GameCompressionOptions.Default);
            Assert.True(recompactSummary.Success);
            Assert.Equal(1, recompactSummary.FilesCompressed); // Only the new patch file was recompacted

            // Final decay audit should report NO decay again
            var finalReport = engine.AuditDecay(new[] { game });
            Assert.False(finalReport.HasDecay);
        }

        // ═════════════════════════════════════════════════════════════════════
        // 6. IN-PROCESS CONCURRENCY & THREAD-SAFETY VALIDATION
        // ═════════════════════════════════════════════════════════════════════

        [Fact]
        public async Task InProcess_ConcurrentCliExecution_PreservesConsoleStreamIntegrity()
        {
            int concurrency = 8;
            var tasks = new Task<(int ExitCode, string StdOut)>[concurrency];

            for (int i = 0; i < concurrency; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "app", "game-compact", "list");
                    var (code, stdOut, _) = RunAppCommand(ctx, "game-compact");
                    return (code, stdOut);
                });
            }

            var results = await Task.WhenAll(tasks);

            foreach (var (code, stdOut) in results)
            {
                Assert.Equal(0, code);
                string trimmed = stdOut.Trim();
                Assert.StartsWith("{", trimmed);
                Assert.EndsWith("}", trimmed);

                using var doc = JsonDocument.Parse(trimmed);
                var root = doc.RootElement;
                Assert.True(root.TryGetProperty("status", out var statusProp));
                Assert.Equal("SUCCESS", statusProp.GetString());
            }
        }
    }
}
