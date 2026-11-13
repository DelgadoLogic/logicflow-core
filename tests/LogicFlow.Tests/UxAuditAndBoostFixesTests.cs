#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DelgadoLogic.Core;
using LogicFlow.Dashboard;
using LogicFlow.Dashboard.ViewModels;
using LogicFlow.Guardian;
using LogicFlow.Guardian.Deduplication;
using LogicFlow.Guardian.Worker;
using LogicFlow.Native;
using LogicFlow.VoiceAgent;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using OmniCore.Engine;
using OmniLicense;
using Xunit;

namespace LogicFlow.Tests;

[Collection("WpfHeadlessExecution")]
public sealed class UxAuditAndBoostFixesTests : IDisposable
{
    private readonly string _tempRoot;

    public UxAuditAndBoostFixesTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"LogicFlow_UxAuditTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        SettingsManager.OverrideSettingsPath = null;
        SettingsManager.ClearCache();
        DelgadoLogicIdentity.OverrideSharedRootForTesting = null;
        DelgadoLogicIdentity.ResetCacheForTesting();

        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch
        {
            // Best-effort temp directory cleanup
        }
    }

    [Fact]
    public void SettingsManager_BooleanFalseToggles_PersistAcrossSaveClearAndReload()
    {
        string settingsFile = Path.Combine(_tempRoot, "settings_bool_test.json");
        SettingsManager.OverrideSettingsPath = settingsFile;
        SettingsManager.ClearCache();

        try
        {
            var settings = SettingsManager.Load();
            settings.MinimizeToTray = false;
            settings.ScanSmartOnStartup = false;
            settings.EnableAnimations = false;
            settings.ShowNotifications = false;
            settings.CheckForUpdatesAutomatically = false;
            settings.AgentEnabled = false;
            settings.StopAgentOnExit = true;
            settings.HideAiAssistant = true;
            settings.AllowCloudAiFallback = false;
            settings.Theme = ThemeMode.Light;
            settings.Accent = AccentColor.Emerald;
            settings.UiScale = 1.25;
            settings.ScanExclusions = [@"C:\ProtectedProjects"];

            SettingsManager.Save();
            SettingsManager.ClearCache();

            var reloaded = SettingsManager.Load();
            Assert.False(reloaded.MinimizeToTray);
            Assert.False(reloaded.ScanSmartOnStartup);
            Assert.False(reloaded.EnableAnimations);
            Assert.False(reloaded.ShowNotifications);
            Assert.False(reloaded.CheckForUpdatesAutomatically);
            Assert.False(reloaded.AgentEnabled);
            Assert.True(reloaded.StopAgentOnExit);
            Assert.True(reloaded.HideAiAssistant);
            Assert.False(reloaded.AllowCloudAiFallback);
            Assert.Equal(ThemeMode.Light, reloaded.Theme);
            Assert.Equal(AccentColor.Emerald, reloaded.Accent);
            Assert.Equal(1.25, reloaded.UiScale, 2);
            Assert.Single(reloaded.ScanExclusions);
            Assert.Equal(@"C:\ProtectedProjects", reloaded.ScanExclusions[0]);
        }
        finally
        {
            SettingsManager.OverrideSettingsPath = null;
            SettingsManager.ClearCache();
        }
    }

    [Fact]
    public void SettingsManager_ExportAndImport_ScrubsSecretsClampsScaleAndRejectsInvalidJson()
    {
        string settingsFile = Path.Combine(_tempRoot, "settings_export_import.json");
        string exportFile = Path.Combine(_tempRoot, "exported_settings.json");
        SettingsManager.OverrideSettingsPath = settingsFile;
        SettingsManager.ClearCache();

        try
        {
            var initial = SettingsManager.Load();
            initial.AiCloudApiKey = "sk-secret-key-do-not-export";
            initial.UiScale = 1.15;
            initial.MinimizeToTray = false;
            SettingsManager.Save();

            SettingsManager.ExportToFile(exportFile, includeSecrets: false);
            string exportedJson = File.ReadAllText(exportFile);
            Assert.DoesNotContain("sk-secret-key-do-not-export", exportedJson);

            // Modify exported file to contain out-of-range UiScale and duplicate exclusions
            string clampedImportFile = Path.Combine(_tempRoot, "clamped_import.json");
            File.WriteAllText(clampedImportFile, """
                {
                  "UiScale": 9.75,
                  "MinimizeToTray": false,
                  "AiCloudApiKey": "",
                  "ScanExclusions": ["C:\\FolderA\\", "c:\\foldera", "  ", "D:\\Keep"]
                }
                """);

            Assert.True(SettingsManager.TryImportFromFile(clampedImportFile, out string? err));
            Assert.Null(err);

            var afterImport = SettingsManager.Load();
            Assert.Equal(1.5, afterImport.UiScale, 2); // Clamped to max 1.5
            Assert.False(afterImport.MinimizeToTray);
            // Existing secret key preserved when imported JSON had scrubbed ""
            Assert.Equal("sk-secret-key-do-not-export", afterImport.AiCloudApiKey);
            Assert.Equal(2, afterImport.ScanExclusions.Count);

            // Edge cases: missing file, JSON array, malformed JSON
            Assert.False(SettingsManager.TryImportFromFile(Path.Combine(_tempRoot, "missing.json"), out string? missingErr));
            Assert.False(string.IsNullOrWhiteSpace(missingErr));

            string arrayJson = Path.Combine(_tempRoot, "array.json");
            File.WriteAllText(arrayJson, "[1, 2, 3]");
            Assert.False(SettingsManager.TryImportFromFile(arrayJson, out string? arrayErr));
            Assert.Contains("JSON object", arrayErr, StringComparison.OrdinalIgnoreCase);

            string brokenJson = Path.Combine(_tempRoot, "broken.json");
            File.WriteAllText(brokenJson, "{ broken json");
            Assert.False(SettingsManager.TryImportFromFile(brokenJson, out string? brokenErr));
            Assert.False(string.IsNullOrWhiteSpace(brokenErr));

            // Lower-bound clamp test
            var lowScale = new UserSettings { UiScale = -2.0, MaxConcurrentScans = 99 };
            SettingsManager.Normalize(lowScale);
            Assert.Equal(1.0, lowScale.UiScale, 2);
            Assert.Equal(8, lowScale.MaxConcurrentScans);
        }
        finally
        {
            SettingsManager.OverrideSettingsPath = null;
            SettingsManager.ClearCache();
        }
    }

    [Theory]
    [InlineData(1, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT)]
    [InlineData(2, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_BUSY)]
    [InlineData(3, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_RUNNING_D3D_FULL_SCREEN)]
    [InlineData(4, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_PRESENTATION_MODE)]
    [InlineData(5, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_ACCEPTS_NOTIFICATIONS)]
    [InlineData(6, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_QUIET_TIME)]
    [InlineData(7, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_APP)]
    [InlineData(0, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT)]
    [InlineData(99, SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT)]
    public void SensorsNative_MapNativeNotificationState_MatchesOfficialOneBasedShellApiValues(
        int rawCode,
        SensorsNative.QUERY_USER_NOTIFICATION_STATE expected)
    {
        Assert.Equal(expected, SensorsNative.MapNativeNotificationState(rawCode));
    }

    [Fact]
    public void FullScreenGameGuard_RawCodeOneNotPresent_DoesNotTriggerFalsePositiveGameDetection()
    {
        using var guard = new FullScreenGameGuard
        {
            UserNotificationStateProvider = () => SensorsNative.MapNativeNotificationState(1), // 1 = QUNS_NOT_PRESENT (idle/locked)
            FullScreenWindowProvider = () => false,
            GpuUtilizationProvider = () => 3.0
        };

        Assert.False(guard.CheckNotificationStateSensor(out _));
        Assert.False(guard.CheckIsGameRunning());

        // Raw code 3 = QUNS_RUNNING_D3D_FULL_SCREEN must trigger game detection
        guard.UserNotificationStateProvider = () => SensorsNative.MapNativeNotificationState(3);
        Assert.True(guard.CheckNotificationStateSensor(out string reason));
        Assert.Contains("D3D Full-Screen", reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(guard.CheckIsGameRunning());
    }

    [Fact]
    public void DelgadoLogicIdentity_FreeTierEphemeralMode_WritesZeroFilesAndPurgeDeletesPersistedRecord()
    {
        string isolatedShared = Path.Combine(_tempRoot, "DelgadoShared");
        DelgadoLogicIdentity.OverrideSharedRootForTesting = isolatedShared;
        DelgadoLogicIdentity.ResetCacheForTesting();

        try
        {
            // Free tier: allowDiskPersistence = false -> zero files or directories created
            var ephemeral = DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false);
            Assert.NotNull(ephemeral);
            Assert.False(string.IsNullOrWhiteSpace(ephemeral.DeviceId));
            Assert.False(ephemeral.IsPersisted);
            Assert.False(Directory.Exists(isolatedShared));

            // Upgrade to Community/Pro: allowDiskPersistence = true -> writes device_identity.json
            var persisted = DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: true);
            Assert.True(persisted.IsPersisted);
            string identityFile = Path.Combine(isolatedShared, "device_identity.json");
            Assert.True(File.Exists(identityFile));

            // Switch back to Free / purge privacy data -> deletes device_identity.json and empty dir
            Assert.True(DelgadoLogicIdentity.PurgePersistedIdentity());
            Assert.False(File.Exists(identityFile));
            Assert.False(Directory.Exists(isolatedShared));
        }
        finally
        {
            DelgadoLogicIdentity.OverrideSharedRootForTesting = null;
            DelgadoLogicIdentity.ResetCacheForTesting();
        }
    }

    [Fact]
    public async Task GemmaAiEngine_HybridAuto_BlocksCloudFallbackUnlessExplicitlyOptedIn()
    {
        int cloudCalls = 0;
        using var handler = new StubHttpMessageHandler((req, _) =>
        {
            Interlocked.Increment(ref cloudCalls);
            string json = """
                {
                  "choices": [
                    { "message": { "role": "assistant", "content": "Cloud opt-in reply" } }
                  ]
                }
                """;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
        });

        using var httpClient = new HttpClient(handler);
        string isolatedAiDir = Path.Combine(_tempRoot, "GemmaCloudOptInTest");
        Directory.CreateDirectory(isolatedAiDir);

        using var engine = new GemmaAiEngine(httpClient, isolatedAiDir)
        {
            Mode = GemmaExecutionMode.HybridAuto,
            CloudEndpointUrl = "https://mock.delgadologic.test/v1/chat/completions"
        };

        // Default must be false (privacy-safe: never transmit prompts off-device by default)
        Assert.False(engine.AllowHybridCloudFallback);

        var blockedResp = await engine.ChatAsync(new GemmaChatRequest { UserPrompt = "Why is my PC slow?" });
        Assert.False(blockedResp.Success);
        Assert.Equal(0, cloudCalls);

        // Explicit opt-in enables HybridAuto cloud fallback
        engine.AllowHybridCloudFallback = true;
        var allowedResp = await engine.ChatAsync(new GemmaChatRequest { UserPrompt = "Why is my PC slow?" });
        Assert.True(allowedResp.Success);
        Assert.Equal(1, cloudCalls);
        Assert.Equal("Cloud opt-in reply", allowedResp.Text);
    }

    [Fact]
    public async Task GemmaAiEngine_DownloadLocalModelWithSidecar_DownloadsAndVerifiesBothSha256Hashes()
    {
        byte[] fakeSidecarBytes = Encoding.UTF8.GetBytes("MZ-FAKE-LLAMA-SERVER-BINARY-PAYLOAD");
        byte[] fakeModelBytes = Encoding.UTF8.GetBytes("GGUF-FAKE-GEMMA4-QUANTIZED-WEIGHTS");
        string expectedSidecarHex = Convert.ToHexString(SHA256.HashData(fakeSidecarBytes));
        string expectedModelHex = Convert.ToHexString(SHA256.HashData(fakeModelBytes));

        using var handler = new StubHttpMessageHandler((req, _) =>
        {
            string url = req.RequestUri?.ToString() ?? "";
            byte[] payload = url.Contains("llama-server.exe", StringComparison.OrdinalIgnoreCase)
                ? fakeSidecarBytes
                : fakeModelBytes;
            var content = new ByteArrayContent(payload);
            content.Headers.ContentLength = payload.Length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        });

        using var httpClient = new HttpClient(handler);
        string isolatedAiDir = Path.Combine(_tempRoot, "GemmaFullAssetsTest");

        using var engine = new GemmaAiEngine(httpClient, isolatedAiDir)
        {
            SidecarDownloadUrl = "https://mock.delgadologic.test/llama-server.exe",
            ModelDownloadUrl = "https://mock.delgadologic.test/gemma-4-E2B-it-Q4_K_M.gguf",
            ExpectedSidecarSha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            ExpectedModelSha256 = expectedModelHex
        };

        // 1. Mismatched sidecar SHA-256 must fail closed and delete partial file
        await Assert.ThrowsAsync<InvalidDataException>(() => engine.DownloadLocalModelAsync());
        Assert.False(File.Exists(engine.LocalSidecarFilePath));
        Assert.False(engine.IsLocalModelInstalled());

        // 2. Matching SHA-256 hashes succeed and populate both sidecar + GGUF model
        engine.ExpectedSidecarSha256 = expectedSidecarHex;
        bool ok = await engine.DownloadLocalModelAsync();
        Assert.True(ok);
        Assert.True(File.Exists(engine.LocalSidecarFilePath));
        Assert.True(engine.IsLocalModelInstalled());
        Assert.Equal(expectedSidecarHex, engine.LastSidecarSha256);
        Assert.Equal(expectedModelHex, engine.LastModelSha256);
    }

    [Fact]
    public async Task LogicFlowFunctionDispatcher_MutatingTools_EnforceFeatureGateAndUserConfirmation()
    {
        Assert.True(LogicFlowFunctionDispatcher.IsMutatingTool("junk_clean"));
        Assert.True(LogicFlowFunctionDispatcher.IsMutatingTool("network_optimize"));
        Assert.True(LogicFlowFunctionDispatcher.IsMutatingTool("game_mode_toggle"));
        Assert.False(LogicFlowFunctionDispatcher.IsMutatingTool("junk_scan"));
        Assert.False(LogicFlowFunctionDispatcher.IsMutatingTool("system_overview"));
        Assert.False(LogicFlowFunctionDispatcher.IsMutatingTool("logicflow_version"));

        int cleanExecutions = 0;
        var dispatcher = new LogicFlowFunctionDispatcher(
            NullLogger<LogicFlowFunctionDispatcher>.Instance,
            new JunkCleanerEngine(),
            new SystemInfoEngine())
        {
            ActiveEditionName = "Free",
            CustomCleanHandler = _ =>
            {
                Interlocked.Increment(ref cleanExecutions);
                return new JunkCleanerEngine.CleanResult { BytesCleaned = 4096, FilesDeleted = 2 };
            }
        };

        using var argsDoc = JsonDocument.Parse("""{"scope":"temp_only"}""");
        var cleanCall = new FunctionCall { Id = "c1", Name = "junk_clean", Args = argsDoc.RootElement.Clone() };

        // 1. Blocked by edition gate
        dispatcher.FeatureGateValidator = (_, _) => (false, "Requires Community ($0) or Pro.");
        var gatedResult = await dispatcher.DispatchAsync(cleanCall);
        Assert.Equal(0, cleanExecutions);
        Assert.Contains("Requires Community", JsonSerializer.Serialize(gatedResult), StringComparison.OrdinalIgnoreCase);

        // 2. Allowed by gate, declined by user confirmation
        dispatcher.FeatureGateValidator = (_, _) => (true, null);
        dispatcher.ConfirmMutatingToolAsync = (_, _) => Task.FromResult(false);
        var cancelledResult = await dispatcher.DispatchAsync(cleanCall);
        Assert.Equal(0, cleanExecutions);
        Assert.Contains("cancelled", JsonSerializer.Serialize(cancelledResult), StringComparison.OrdinalIgnoreCase);

        // 3. Allowed by gate AND confirmed by user -> executes
        dispatcher.ConfirmMutatingToolAsync = (_, _) => Task.FromResult(true);
        var executedResult = await dispatcher.DispatchAsync(cleanCall);
        Assert.Equal(1, cleanExecutions);
        Assert.Contains("4096", JsonSerializer.Serialize(executedResult), StringComparison.OrdinalIgnoreCase);

        // 4. logicflow_version reports dynamic ActiveEditionName
        using var emptyDoc = JsonDocument.Parse("{}");
        var versionResult = await dispatcher.DispatchAsync(new FunctionCall
        {
            Id = "v1",
            Name = "logicflow_version",
            Args = emptyDoc.RootElement.Clone()
        });
        Assert.Contains("Free", JsonSerializer.Serialize(versionResult), StringComparison.Ordinal);
    }

    [Fact]
    public void TurboMode_ProcessWhitelistAndToastRegistrySnapshot_RoundTripsExactPriorState()
    {
        string stateFile = Path.Combine(_tempRoot, "turbo_state_isolated.json");
        string regSubKey = $@"Software\DelgadoLogic_Tests\TurboToast_{Guid.NewGuid():N}";

        try
        {
            var turbo = new TurboMode
            {
                StateFilePathOverride = stateFile,
                OverrideNotificationsRegistrySubKey = regSubKey,
                ForegroundAppPidProvider = () => -1
            };

            Assert.Contains("explorer", turbo.ProcessWhitelist);
            Assert.Contains("LogicFlow", turbo.ProcessWhitelist);
            Assert.Contains("lf", turbo.ProcessWhitelist);
            Assert.Contains("powershell", turbo.ProcessWhitelist);
            Assert.Contains("pwsh", turbo.ProcessWhitelist);
            Assert.Contains("WindowsTerminal", turbo.ProcessWhitelist);

            var whitelistAttemptProfile = new TurboMode.TurboProfile
            {
                Name = "Whitelist Safety Check",
                ServicesToStop = [],
                ProcessesToKill = ["explorer", "LogicFlow", "powershell", "pwsh"],
                DisableNotifications = true,
                SetHighPriority = false,
                SwitchPowerPlan = false,
                OptimizeCpuAffinity = false,
                OptimizeNetwork = false,
                DisableVisualEffects = false,
                SetTimerResolution = false,
                BoostGpuPriority = false
            };

            Assert.Empty(turbo.PreviewTargetProcesses(whitelistAttemptProfile));

            // Case A: Registry value did NOT exist beforehand -> Activate sets 0, Deactivate deletes value
            var actA = turbo.Activate(whitelistAttemptProfile);
            Assert.True(actA.Activated);
            Assert.True(File.Exists(stateFile));

            using (var checkKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false))
            {
                Assert.NotNull(checkKey);
                Assert.Equal(0, checkKey!.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED"));
            }

            turbo.Deactivate();
            Assert.False(File.Exists(stateFile));
            using (var checkAfterA = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false))
            {
                Assert.Null(checkAfterA?.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED"));
            }

            // Case B: User ALREADY had notifications disabled (0) beforehand -> cross-process Deactivate keeps 0!
            using (var presetKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regSubKey, writable: true))
            {
                presetKey.SetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }

            Assert.True(turbo.Activate(whitelistAttemptProfile).Activated);

            // Simulate separate CLI process (`lf boost off` / `LogicFlow.exe /boost off`) reading persisted turbo_state.json
            var cliDeactivator = new TurboMode
            {
                StateFilePathOverride = stateFile,
                OverrideNotificationsRegistrySubKey = regSubKey
            };
            Assert.True(cliDeactivator.IsActive);
            cliDeactivator.Deactivate();
            Assert.False(cliDeactivator.IsActive);

            using (var checkAfterB = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false))
            {
                Assert.Equal(0, checkAfterB?.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED"));
            }
        }
        finally
        {
            try
            {
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\DelgadoLogic_Tests", throwOnMissingSubKey: false);
            }
            catch { }
        }
    }

    [Fact]
    public void App_CommandLineFlags_ParseBoostBoostOffAndAutoMaintenanceAccurately()
    {
        Assert.True(App.HasBoostFlag(["/boost"]));
        Assert.True(App.HasBoostFlag(["--boost"]));
        Assert.True(App.HasBoostFlag(["-boost"]));
        Assert.False(App.HasBoostFlag(["/boost", "off"]));
        Assert.False(App.HasBoostFlag(["--boost-off"]));
        Assert.False(App.HasBoostFlag([]));
        Assert.False(App.HasBoostFlag(null));

        Assert.True(App.HasBoostOffFlag(["/boost", "off"]));
        Assert.True(App.HasBoostOffFlag(["--boost", "disable"]));
        Assert.True(App.HasBoostOffFlag(["/boost-off"]));
        Assert.True(App.HasBoostOffFlag(["--boost-off"]));
        Assert.False(App.HasBoostOffFlag(["/boost"]));
        Assert.False(App.HasBoostOffFlag(null));

        Assert.True(App.HasAutoMaintenanceFlag(["--auto-maintenance"]));
        Assert.True(App.HasAutoMaintenanceFlag(["/auto-maintenance"]));
        Assert.False(App.HasAutoMaintenanceFlag(["--tray"]));
    }

    [Fact]
    public async Task HyperStoreViewModel_HonestChunkCountsAndGlobalScanExclusions()
    {
        string settingsFile = Path.Combine(_tempRoot, "hyperstore_settings.json");
        SettingsManager.OverrideSettingsPath = settingsFile;
        SettingsManager.ClearCache();

        try
        {
            await StaTestRunner.RunAsync(async () =>
            {
                var vm = new HyperStoreViewModel();

                // 1. Empty directory -> strictly 0 chunks
                string emptyDir = Path.Combine(_tempRoot, "EmptyHyperDir");
                Directory.CreateDirectory(emptyDir);
                Assert.Equal(0, await vm.ScanDriveForRedundanciesAsync(emptyDir));
                Assert.Equal(0, vm.ChunksIndexed);

                // 2. Directory with 2 small 8 KB duplicates + an excluded directory with 2 larger duplicates
                string scanRoot = Path.Combine(_tempRoot, "HyperScanWithExclusions");
                string excludedSub = Path.Combine(scanRoot, "SkipThisFolder");
                Directory.CreateDirectory(scanRoot);
                Directory.CreateDirectory(excludedSub);

                SettingsManager.Load().ScanExclusions = [excludedSub];
                SettingsManager.Save();

                byte[] includedPayload = Encoding.UTF8.GetBytes(new string('I', 8192));
                await File.WriteAllBytesAsync(Path.Combine(scanRoot, "inc1.bin"), includedPayload);
                await File.WriteAllBytesAsync(Path.Combine(scanRoot, "inc2.bin"), includedPayload);

                byte[] excludedPayload = Encoding.UTF8.GetBytes(new string('E', 16384));
                await File.WriteAllBytesAsync(Path.Combine(excludedSub, "exc1.iso"), excludedPayload);
                await File.WriteAllBytesAsync(Path.Combine(excludedSub, "exc2.iso"), excludedPayload);

                int count1 = await vm.ScanDriveForRedundanciesAsync(scanRoot);
                Assert.Equal(2, count1);
                Assert.Single(vm.DuplicateFindings);
                Assert.Equal(".bin", vm.DuplicateFindings[0].Extension);

                // Two 8 KB files = 2 chunks (never fabricated as eligibleFiles.Count * 8 = 16)
                Assert.Equal(2, vm.ChunksIndexed);

                // Re-scanning must produce the exact same ChunksIndexed (never += accumulating to 4)
                int count2 = await vm.ScanDriveForRedundanciesAsync(scanRoot);
                Assert.Equal(2, count2);
                Assert.Equal(2, vm.ChunksIndexed);
            });
        }
        finally
        {
            SettingsManager.OverrideSettingsPath = null;
            SettingsManager.ClearCache();
        }
    }

    [Fact]
    public void UninstallerResidualsAndJunkCleanerExclusionsAndCancellation_RespectSelectionsAndTokens()
    {
        // 1. UninstallerEngine.CleanResiduals respects ResidualItem.IsSelected
        string residualDir = Path.Combine(_tempRoot, "Residuals");
        Directory.CreateDirectory(residualDir);
        string deleteMe = Path.Combine(residualDir, "delete_me.log");
        string keepMe = Path.Combine(residualDir, "keep_me.cfg");
        File.WriteAllText(deleteMe, "stale log");
        File.WriteAllText(keepMe, "important user config");

        var scan = new UninstallerEngine.ResidualScanResult
        {
            Items =
            [
                new UninstallerEngine.ResidualItem
                {
                    Kind = UninstallerEngine.ResidualItem.ItemKind.File,
                    PathOrKey = deleteMe,
                    SizeBytes = 9,
                    IsSelected = true
                },
                new UninstallerEngine.ResidualItem
                {
                    Kind = UninstallerEngine.ResidualItem.ItemKind.File,
                    PathOrKey = keepMe,
                    SizeBytes = 21,
                    IsSelected = false
                }
            ]
        };

        var uninstaller = new UninstallerEngine();
        int cleaned = uninstaller.CleanResiduals(scan);
        Assert.Equal(1, cleaned);
        Assert.False(File.Exists(deleteMe));
        Assert.True(File.Exists(keepMe));

        // 2. JunkCleanerEngine.IsExcludedPath boundary accuracy & Clean cancellation
        string keepFolder = Path.Combine(_tempRoot, "Keep");
        string siblingPrefixFolder = Path.Combine(_tempRoot, "KeepOther");
        var cleaner = new JunkCleanerEngine
        {
            ExcludedPaths = [keepFolder]
        };

        Assert.True(cleaner.IsExcludedPath(Path.Combine(keepFolder, "sub", "temp.tmp")));
        Assert.False(cleaner.IsExcludedPath(Path.Combine(siblingPrefixFolder, "temp.tmp")));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() => cleaner.Scan(additionalExclusions: null, ct: cts.Token));

        string untouchedTemp = Path.Combine(_tempRoot, "untouched.tmp");
        File.WriteAllText(untouchedTemp, "temp payload");
        var cancelCleanResult = cleaner.Clean(
            [
                new JunkCleanerEngine.JunkScanResult
                {
                    Category = JunkCleanerEngine.JunkCategory.UserTemp,
                    DisplayName = "User Temp",
                    IsSelected = true,
                    Files = [new JunkCleanerEngine.JunkFile { Path = untouchedTemp, SizeBytes = 12 }]
                }
            ],
            cts.Token);

        Assert.True(cancelCleanResult.WasCancelled);
        Assert.True(File.Exists(untouchedTemp));
    }

    [Fact]
    public void TrayIconTooltipAndOfflineBundledLegalDocs_MeetWin32LimitAndResolveOffline()
    {
        Assert.Equal("LogicFlow", TrayIconManager.FormatSafeTooltip(null));
        Assert.Equal("LogicFlow", TrayIconManager.FormatSafeTooltip("   "));
        Assert.Equal("LogicFlow — Ready", TrayIconManager.FormatSafeTooltip("LogicFlow — Ready"));

        string veryLong = new string('W', 140);
        string truncated = TrayIconManager.FormatSafeTooltip(veryLong);
        Assert.True(truncated.Length <= TrayIconManager.MaxNotifyIconTooltipLength);
        Assert.EndsWith("…", truncated, StringComparison.Ordinal);

        foreach (string slug in new[] { "eula", "privacy", "terms", "refund", "third-party", "security" })
        {
            string? text = Dialogs.ResolveBundledLegalText(slug);
            Assert.False(string.IsNullOrWhiteSpace(text), $"Expected offline bundled legal doc for '{slug}'.");
        }
    }

    [Fact]
    public async Task GemmaAiEngine_DownloadLocalModelAsync_DownloadsDefaultSidecarZip_AndRequiresSidecarForReadyStatus()
    {
        string aiDir = Path.Combine(_tempRoot, "LocalAiDefaultSidecar");
        Directory.CreateDirectory(aiDir);

        byte[] fakeGgufBytes = Encoding.UTF8.GetBytes("GGUF-FAKE-MODEL-WEIGHTS");
        byte[] fakeSidecarExeBytes = Encoding.UTF8.GetBytes("MZ-FAKE-LLAMA-SERVER-EXE");

        byte[] sidecarZipBytes;
        using (var zipMs = new MemoryStream())
        {
            using (var archive = new ZipArchive(zipMs, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = archive.CreateEntry("build/bin/llama-server.exe");
                await using var entryStream = entry.Open();
                await entryStream.WriteAsync(fakeSidecarExeBytes);
            }
            sidecarZipBytes = zipMs.ToArray();
        }

        var requestedUrls = new List<string>();
        using var handler = new StubHttpMessageHandler((req, _) =>
        {
            string url = req.RequestUri?.ToString() ?? string.Empty;
            requestedUrls.Add(url);

            if (url.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var zipResp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(sidecarZipBytes)
                };
                zipResp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
                return Task.FromResult(zipResp);
            }

            var modelResp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(fakeGgufBytes)
            };
            modelResp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            return Task.FromResult(modelResp);
        });

        using var http = new HttpClient(handler);
        using var engine = new GemmaAiEngine(http, aiDir)
        {
            Mode = GemmaExecutionMode.LocalSidecar,
            // Leave SidecarDownloadUrl null (the out-of-the-box default!) while supplying expected hashes for synthetic bytes
            SidecarDownloadUrl = null,
            ExpectedModelSha256 = Convert.ToHexString(SHA256.HashData(fakeGgufBytes)),
            ExpectedSidecarSha256 = Convert.ToHexString(SHA256.HashData(sidecarZipBytes))
        };

        // 1. Model-only state must NOT claim Ready when llama-server.exe is missing
        await File.WriteAllBytesAsync(engine.LocalModelFilePath, fakeGgufBytes);
        Assert.True(engine.IsLocalModelInstalled());
        Assert.False(engine.IsSidecarBinaryInstalled());
        Assert.Contains("Sidecar Runtime Missing", engine.GetStatusSummary(), StringComparison.OrdinalIgnoreCase);

        File.Delete(engine.LocalModelFilePath);

        // 2. DownloadLocalModelAsync with SidecarDownloadUrl == null must fetch BOTH .gguf and DefaultSidecarDownloadUrl ZIP
        bool downloaded = await engine.DownloadLocalModelAsync();
        Assert.True(downloaded);
        Assert.True(engine.IsLocalModelInstalled());
        Assert.True(engine.IsSidecarBinaryInstalled());
        Assert.Contains(requestedUrls, u => u.Equals(GemmaAiEngine.DefaultSidecarDownloadUrl, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Ready", engine.GetStatusSummary(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CloudLicenseBridge_ActivateAsync_FailedActivationInFreeTier_WritesZeroIdentityFiles()
    {
        string isolatedShared = Path.Combine(_tempRoot, "FreeFailedActivationShared");
        string isolatedAppData = Path.Combine(_tempRoot, "FreeFailedActivationAppData");
        Directory.CreateDirectory(isolatedAppData);

        DelgadoLogicIdentity.OverrideSharedRootForTesting = isolatedShared;
        DelgadoLogicIdentity.ResetCacheForTesting();

        try
        {
            using var handler = new StubHttpMessageHandler((_, _) =>
            {
                var errResp = new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("{\"error\":\"Invalid order ID\"}", Encoding.UTF8, "application/json")
                };
                return Task.FromResult(errResp);
            });
            using var http = new HttpClient(handler);
            var bridge = new CloudLicenseBridge(NullLogger.Instance, isolatedAppData, http);

            var result = await bridge.ActivateAsync("INVALID-ORDER-0000", "nobody@example.com");
            Assert.False(result.Success);
            Assert.Equal("Invalid order ID", result.Message);

            // Free-tier failed activation must NEVER create device_identity.json on disk
            Assert.False(Directory.Exists(isolatedShared));
        }
        finally
        {
            DelgadoLogicIdentity.OverrideSharedRootForTesting = null;
            DelgadoLogicIdentity.ResetCacheForTesting();
        }
    }

    [Fact]
    public void TurboMode_CrossProcessPersistenceAndPidStartTimeGuard()
    {
        string statePath = Path.Combine(_tempRoot, "turbo_cross_process_state.json");
        var noopProfile = new TurboMode.TurboProfile
        {
            Name = "NoOpTestProfile",
            ServicesToStop = [],
            ProcessesToKill = [],
            DisableNotifications = false,
            SetHighPriority = false,
            SwitchPowerPlan = false,
            OptimizeCpuAffinity = false,
            OptimizeNetwork = false,
            DisableVisualEffects = false,
            SetTimerResolution = false,
            BoostGpuPriority = false
        };

        var cliInstance1 = new TurboMode { StateFilePathOverride = statePath };
        var act1 = cliInstance1.Activate(noopProfile);
        Assert.True(act1.Activated);
        Assert.True(File.Exists(statePath));

        // Second separate CLI process instance must detect persisted Active == true and refuse to clobber baseline state
        var cliInstance2 = new TurboMode { StateFilePathOverride = statePath };
        Assert.True(cliInstance2.IsActive);
        var act2 = cliInstance2.Activate(noopProfile);
        Assert.False(act2.Activated);
        Assert.Contains(act2.Actions, a => a.Contains("already active", StringComparison.OrdinalIgnoreCase));

        // Simulate recycled PID on an isolated child process so parallel tests sharing testhost.exe never race on Process.GetCurrentProcess()
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
            Arguments = "-n 30 127.0.0.1",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true
        };
        using var child = Process.Start(psi)!;
        try
        {
            child.PriorityClass = ProcessPriorityClass.AboveNormal;
            string bogusPriorityTarget = nameof(ProcessPriorityClass.Idle);

            string recycledStateJson = JsonSerializer.Serialize(new
            {
                Active = true,
                ProfileName = "RecycledPidTest",
                OriginalPowerPlan = "",
                StoppedServices = Array.Empty<string>(),
                NotificationsDisabled = false,
                PriorToastValueExisted = false,
                PriorToastValue = 1,
                BoostedProcessId = child.Id,
                BoostedProcessStartTicksUtc = 12345L, // Deliberate mismatch with child.StartTime
                BoostedOriginalPriority = bogusPriorityTarget
            });
            File.WriteAllText(statePath, recycledStateJson);

            var deactivator = new TurboMode { StateFilePathOverride = statePath };
            var deact = deactivator.Deactivate();
            Assert.False(deactivator.IsActive);
            Assert.False(File.Exists(statePath));

            // Because StartTime ticks did not match, child process priority must NOT have been mutated to Idle
            child.Refresh();
            Assert.Equal(ProcessPriorityClass.AboveNormal, child.PriorityClass);
        }
        finally
        {
            try { if (!child.HasExited) child.Kill(entireProcessTree: true); } catch { }
        }
    }

    [Fact]
    public async Task Gate_ToggleButton_BlocksGatedCheckWithoutFiringChecked_AllowsUncheckInFreeTier_AndAddsButtonLockCue()
    {
        await StaTestRunner.RunAsync(() =>
        {
            Gate.Install();
            var promptedCaps = new List<Capability>();
            bool allowCap = false;

            Gate.CapabilityAllowanceOverrideForTesting = _ => allowCap;
            Gate.UpgradePromptInterceptForTesting = (_, cap) => promptedCaps.Add(cap);

            try
            {
                // 1. Gated CheckBox starting unchecked: Free-tier click must NOT fire Checked handler
                int checkedCount = 0;
                int uncheckedCount = 0;
                var checkBox = new System.Windows.Controls.CheckBox { Content = "Block Windows Telemetry", IsChecked = false };
                checkBox.Checked += (_, _) => checkedCount++;
                checkBox.Unchecked += (_, _) => uncheckedCount++;
                Gate.SetRequires(checkBox, Capability.Core);

                var mouseDownArgs = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left)
                {
                    RoutedEvent = UIElement.PreviewMouseLeftButtonDownEvent,
                    Source = checkBox
                };
                checkBox.RaiseEvent(mouseDownArgs);

                Assert.True(mouseDownArgs.Handled);
                Assert.Equal(false, checkBox.IsChecked);
                Assert.Equal(0, checkedCount);
                Assert.Single(promptedCaps);

                // 2. Pre-checked gated CheckBox (e.g., downgraded from Trial -> Free): Free user MUST be allowed to uncheck!
                var activeToggle = new System.Windows.Controls.CheckBox { Content = "Active Setting", IsChecked = true };
                activeToggle.Unchecked += (_, _) => uncheckedCount++;
                Gate.SetRequires(activeToggle, Capability.Core);

                var uncheckMouseArgs = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left)
                {
                    RoutedEvent = UIElement.PreviewMouseLeftButtonDownEvent,
                    Source = activeToggle
                };
                activeToggle.RaiseEvent(uncheckMouseArgs);
                Assert.False(uncheckMouseArgs.Handled);

                // Simulate ToggleButton completing its uncheck + Click
                activeToggle.IsChecked = false;
                activeToggle.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent, activeToggle));
                Assert.Equal(false, activeToggle.IsChecked);
                Assert.Equal(1, uncheckedCount);
                Assert.Single(promptedCaps); // No upgrade nag when disabling!

                // 3. Standard Button plain-string Content gets "🔒 " prefix when locked and strips it when unlocked
                var btn = new System.Windows.Controls.Button { Content = "Clean Selected" };
                Gate.SetRequires(btn, Capability.Core);
                Assert.Equal("🔒 Clean Selected", btn.Content);

                allowCap = true;
                Gate.UpdateElementCue(btn);
                Assert.Equal("Clean Selected", btn.Content);
            }
            finally
            {
                Gate.CapabilityAllowanceOverrideForTesting = null;
                Gate.UpgradePromptInterceptForTesting = null;
            }

            return Task.CompletedTask;
        });
    }

    [Fact]
    public async Task VolumeAwareDeduplicator_IsExcludedByPathBoundary_DoesNotFalseMatchSiblingPrefix()
    {
        string keepDir = Path.Combine(_tempRoot, "Keep");
        string siblingDir = Path.Combine(_tempRoot, "KeepOther");
        Directory.CreateDirectory(keepDir);
        Directory.CreateDirectory(siblingDir);

        Assert.True(VolumeAwareDeduplicator.IsExcludedByPathBoundary(keepDir, [keepDir]));
        Assert.True(VolumeAwareDeduplicator.IsExcludedByPathBoundary(Path.Combine(keepDir, "nested", "a.bin"), [keepDir]));
        Assert.False(VolumeAwareDeduplicator.IsExcludedByPathBoundary(Path.Combine(siblingDir, "a.bin"), [keepDir]));

        byte[] dupBytes = Encoding.UTF8.GetBytes(new string('D', 8192));
        await File.WriteAllBytesAsync(Path.Combine(keepDir, "protected1.bin"), dupBytes);
        await File.WriteAllBytesAsync(Path.Combine(keepDir, "protected2.bin"), dupBytes);
        await File.WriteAllBytesAsync(Path.Combine(siblingDir, "eligible1.bin"), dupBytes);
        await File.WriteAllBytesAsync(Path.Combine(siblingDir, "eligible2.bin"), dupBytes);

        var dedup = new VolumeAwareDeduplicator();
        var res = await dedup.DeduplicateDirectoryAsync(_tempRoot, new DedupOptions
        {
            DryRun = true,
            MinFileSizeBytes = 4096,
            ExcludedPaths = [keepDir]
        });

        // Only the 2 files in KeepOther should be scanned (the 2 files in Keep are excluded)
        Assert.Equal(2, res.TotalFilesScanned);
        Assert.Equal(1, res.DuplicateClustersFound);
    }

    [Fact]
    public async Task MainWindow_ApplyPaletteToResources_LightThemeUpdatesBrandDarkBrushAndAccents_AndPipeQueueDrains()
    {
        await StaTestRunner.RunAsync(() =>
        {
            var res = new ResourceDictionary();
            var lightSettings = new UserSettings
            {
                Theme = ThemeMode.Light,
                Accent = AccentColor.Cyan
            };

            bool isLight = MainWindow.ApplyPaletteToResources(res, lightSettings);
            Assert.True(isLight);

            var brandBg = Assert.IsType<SolidColorBrush>(res["BrandDarkBrush"]);
            var brandGlass = Assert.IsType<SolidColorBrush>(res["BrandGlassBrush"]);
            var bgCard = Assert.IsType<SolidColorBrush>(res["BrushBgCard"]);
            var textMain = Assert.IsType<SolidColorBrush>(res["BrushTextMain"]);
            var cyanBrush = Assert.IsType<SolidColorBrush>(res["BrandCyanBrush"]);
            Assert.IsType<LinearGradientBrush>(res["GradientAccent"]);

            // Light mode must set light window/card surfaces (#F8FAFC / #FFFFFF) and dark slate text (#0F172A), never black-on-black
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xF8, 0xFA, 0xFC), brandBg.Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xFF, 0xFF, 0xFF), brandGlass.Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xFF, 0xFF, 0xFF), bgCard.Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x0F, 0x17, 0x2A), textMain.Color);
            // Light mode Cyan uses darkened #0284C7 for WCAG contrast against white cards
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x02, 0x84, 0xC7), cyanBrush.Color);

            // Cold-start pipe command queuing when MainWindow is not yet created
            while (App.PendingPipeCommands.TryDequeue(out _)) { }
            App.DispatchOrEnqueuePipeCommand("BOOST");
            Assert.True(App.PendingPipeCommands.TryDequeue(out string? queued));
            Assert.Equal("BOOST", queued);

            return Task.CompletedTask;
        });
    }

    [Fact]
    public async Task VisualVerificationRegressions_TemplatesCheckboxesAndStatusPalette_AreDefectFree()
    {
        await StaTestRunner.RunAsync(() =>
        {
            if (System.Windows.Application.Current == null)
            {
                var app = new LogicFlow.Dashboard.App();
                app.InitializeComponent();
            }

            var appRes = System.Windows.Application.Current!.Resources;

            // 1. RadarPulseDot must not throw InvalidOperationException when Loaded fires inside a Collapsed container
            var radarStyle = Assert.IsType<Style>(appRes["RadarPulseDot"]);
            var collapsedHost = new Grid { Visibility = Visibility.Collapsed };
            var radarDot = new System.Windows.Controls.Control { Style = radarStyle, Visibility = Visibility.Collapsed };
            collapsedHost.Children.Add(radarDot);
            collapsedHost.Measure(new System.Windows.Size(200, 50));
            collapsedHost.Arrange(new Rect(0, 0, 200, 50));
            radarDot.ApplyTemplate();
            var ex = Record.Exception(() => radarDot.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent)));
            Assert.Null(ex);

            // 2. NavButtonActive resting template state must show ActiveBg and ActivePill at Opacity 1.0
            var navActiveStyle = Assert.IsType<Style>(appRes["NavButtonActive"]);
            var navBtn = new System.Windows.Controls.Button { Style = navActiveStyle, Content = "Dashboard" };
            navBtn.Measure(new System.Windows.Size(240, 44));
            navBtn.Arrange(new Rect(0, 0, 240, 44));
            navBtn.ApplyTemplate();
            var activeBg = Assert.IsType<Border>(navBtn.Template.FindName("ActiveBg", navBtn));
            var activePill = Assert.IsType<Border>(navBtn.Template.FindName("ActivePill", navBtn));
            Assert.Equal(1.0, activeBg.Opacity);
            Assert.Equal(1.0, activePill.Opacity);

            // 3. BaseButtonStyle / DangerButtonStyle must propagate Padding to template Border and keep White foreground
            var dangerStyle = Assert.IsType<Style>(appRes["DangerButtonStyle"]);
            var dangerBtn = new System.Windows.Controls.Button
            {
                Style = dangerStyle,
                Content = "Reset",
                Padding = new Thickness(18, 9, 18, 9)
            };
            dangerBtn.Measure(new System.Windows.Size(200, 44));
            dangerBtn.Arrange(new Rect(0, 0, 200, 44));
            dangerBtn.ApplyTemplate();
            var dangerBorder = Assert.IsType<Border>(dangerBtn.Template.FindName("border", dangerBtn));
            Assert.Equal(new Thickness(18, 9, 18, 9), dangerBorder.Padding);
            var dangerFg = Assert.IsType<SolidColorBrush>(dangerBtn.Foreground);
            Assert.Equal(Colors.White, dangerFg.Color);

            // 4. ConsentWindow CmbRegion height (32px) and Step 2 & Step 3 checkbox wrapping
            var consentDir = Path.Combine(_tempRoot, "consent_wrap_verify");
            var consentStore = new OmniPulse.ConsentStore(consentDir, (_, _) => null);
            var consentWin = new ConsentWindow(consentStore, isFirstRunMode: true);
            try
            {
                var cmbRegion = Assert.IsType<System.Windows.Controls.ComboBox>(consentWin.FindName("CmbRegion"));
                Assert.Equal(32.0, cmbRegion.Height);

                string[] wrappedCheckboxes =
                {
                    "ChkStandard",
                    "ChkExtended",
                    "ChkPrefStartWithWindows",
                    "ChkPrefMinimizeToTray",
                    "ChkPrefCheckUpdates",
                    "ChkPrefScanSmart",
                    "ChkPrefTelemetryBlocking"
                };

                foreach (var chkName in wrappedCheckboxes)
                {
                    var chk = Assert.IsType<System.Windows.Controls.CheckBox>(consentWin.FindName(chkName));
                    var tb = Assert.IsType<TextBlock>(chk.Content);
                    Assert.Equal(TextWrapping.Wrap, tb.TextWrapping);
                }
            }
            finally
            {
                consentWin.Close();
            }

            // 5. Light vs Dark WCAG status brushes, BrushTextInverse contrast, and GradientAccent WCAG AA stop
            var isolatedRes = new ResourceDictionary();
            MainWindow.ApplyPaletteToResources(isolatedRes, new UserSettings { Theme = ThemeMode.Light, Accent = AccentColor.Cyan });
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x05, 0x96, 0x69), Assert.IsType<SolidColorBrush>(isolatedRes["SuccessGreenBrush"]).Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xD9, 0x77, 0x06), Assert.IsType<SolidColorBrush>(isolatedRes["WarningAmberBrush"]).Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xDC, 0x26, 0x26), Assert.IsType<SolidColorBrush>(isolatedRes["DangerRedBrush"]).Color);
            Assert.Equal(Colors.White, Assert.IsType<SolidColorBrush>(isolatedRes["BrushTextInverse"]).Color);

            MainWindow.ApplyPaletteToResources(isolatedRes, new UserSettings { Theme = ThemeMode.Light, Accent = AccentColor.Purple });
            Assert.Equal(Colors.White, Assert.IsType<SolidColorBrush>(isolatedRes["BrushTextInverse"]).Color);

            MainWindow.ApplyPaletteToResources(isolatedRes, new UserSettings { Theme = ThemeMode.Dark, Accent = AccentColor.Purple });
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x0E, 0x12, 0x1B), Assert.IsType<SolidColorBrush>(isolatedRes["BrushTextInverse"]).Color);

            MainWindow.ApplyPaletteToResources(isolatedRes, new UserSettings { Theme = ThemeMode.Dark, Accent = AccentColor.Cyan });
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x00, 0xE6, 0x76), Assert.IsType<SolidColorBrush>(isolatedRes["SuccessGreenBrush"]).Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xFF, 0xB3, 0x00), Assert.IsType<SolidColorBrush>(isolatedRes["WarningAmberBrush"]).Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0xFF, 0x52, 0x52), Assert.IsType<SolidColorBrush>(isolatedRes["DangerRedBrush"]).Color);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x0E, 0x12, 0x1B), Assert.IsType<SolidColorBrush>(isolatedRes["BrushTextInverse"]).Color);
            var gradAccent = Assert.IsType<LinearGradientBrush>(isolatedRes["GradientAccent"]);
            Assert.Equal(System.Windows.Media.Color.FromRgb(0x00, 0x77, 0xB6), gradAccent.GradientStops[0].Color);

            // 6. Card & terminal styles must not attach UIElement.Effect (which bitmap-rasterizes ClearType text at 125%/150% scale)
            foreach (var styleKey in new[] { "GlassPanel", "ScoreCardPanel", "GlassCardStyle", "TerminalBoxStyle" })
            {
                var cardStyle = Assert.IsType<Style>(System.Windows.Application.Current.TryFindResource(styleKey));
                Assert.DoesNotContain(cardStyle.Setters.OfType<Setter>(), s => s.Property == UIElement.EffectProperty);
            }

            return Task.CompletedTask;
        });
    }

    [Fact]
    public void PriceSheetAndUiScaleFormatting_MatchSidebarAndComboTags()
    {
        Assert.Equal("Upgrade to Pro ($19.99)", PriceSheet.UpgradeLabel);
        string upgradeMsg = TierPolicy.UpgradeMessage(Edition.Community, Capability.AdvancedRecovery);
        Assert.Contains("$19.99 launch ($29.99 regular)", upgradeMsg, StringComparison.Ordinal);

        Assert.Equal("1.0", 1.0.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("1.15", 1.15.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("1.25", 1.25.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("1.5", 1.5.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task DialogsAndCarvedBadgeLightTheme_HeadlessLayoutAndPalette_DoNotClipOrUseLowContrast()
    {
        string settingsFile = Path.Combine(_tempRoot, "dialogs_carved_theme.json");
        SettingsManager.OverrideSettingsPath = settingsFile;
        SettingsManager.ClearCache();

        try
        {
            await StaTestRunner.RunAsync(() =>
            {
                if (System.Windows.Application.Current == null)
                {
                    var app = new LogicFlow.Dashboard.App();
                    app.InitializeComponent();
                }

                var appRes = System.Windows.Application.Current!.Resources;
                var settings = SettingsManager.Load();

                try
                {
                    // 1. Light mode @ 150% UI scale: Dialogs.ShowUpgradePrompt & Dialogs.ShowAbout must size to content cleanly without clipping
                    settings.Theme = ThemeMode.Light;
                    settings.Accent = AccentColor.Cyan;
                    settings.UiScale = 1.5;
                    SettingsManager.Save();
                    MainWindow.ApplyPaletteToResources(appRes, settings);

                    var capturedSizes = new List<(double DesiredH, double MaxH)>();
                    Dialogs.WindowHostOverrideForTesting = win =>
                    {
                        var content = Assert.IsAssignableFrom<FrameworkElement>(win.Content);
                        double w = double.IsFinite(win.Width) && win.Width > 0 ? win.Width : 680.0;
                        double maxH = double.IsFinite(win.MaxHeight) && win.MaxHeight > 0 ? win.MaxHeight : 2400.0;
                        content.Measure(new System.Windows.Size(w, maxH));
                        capturedSizes.Add((content.DesiredSize.Height, maxH));
                        return false;
                    };

                    Dialogs.ShowUpgradePrompt(null, Capability.AdvancedRecovery);
                    Dialogs.ShowAbout(null);
                    Assert.Equal(2, capturedSizes.Count);
                    Assert.All(capturedSizes, s =>
                    {
                        Assert.True(s.DesiredH > 150.0);
                        Assert.True(s.DesiredH <= s.MaxH);
                    });

                    // 2. CarvedFileItem.IsLightPaletteActive & forensic badges switch between WCAG Light (#0284C7) and Dark (#00E5FF)
                    Assert.True(CarvedFileItem.IsLightPaletteActive());
                    var carved = new CarvedFileItem
                    {
                        DriveSource = @"\\.\C:",
                        Header = new LogicFlow.Lazarus.CarvedFileHeader
                        {
                            FileName = "diagram.png",
                            Extension = "png",
                            FileType = "PNG Image",
                            RecoveryMethod = "NTFS MFT Resident/Runlist",
                            Confidence = "High"
                        }
                    };
                    Assert.Equal(
                        System.Windows.Media.Color.FromRgb(0x02, 0x84, 0xC7),
                        Assert.IsType<SolidColorBrush>(carved.RecoveryMethodBadgeBrush).Color);
                    Assert.Equal(
                        System.Windows.Media.Color.FromRgb(0x02, 0x84, 0xC7),
                        Assert.IsType<SolidColorBrush>(carved.TypeBadgeBrush).Color);

                    settings.Theme = ThemeMode.Dark;
                    settings.UiScale = 1.0;
                    SettingsManager.Save();
                    MainWindow.ApplyPaletteToResources(appRes, settings);

                    int changedProps = 0;
                    carved.PropertyChanged += (_, _) => changedProps++;
                    carved.RefreshThemeBrushes();
                    Assert.Equal(3, changedProps);
                    Assert.False(CarvedFileItem.IsLightPaletteActive());
                    Assert.Equal(
                        System.Windows.Media.Color.FromRgb(0x00, 0xE5, 0xFF),
                        Assert.IsType<SolidColorBrush>(carved.RecoveryMethodBadgeBrush).Color);
                }
                finally
                {
                    Dialogs.WindowHostOverrideForTesting = null;
                    settings.Theme = ThemeMode.Dark;
                    settings.Accent = AccentColor.Cyan;
                    settings.UiScale = 1.0;
                    SettingsManager.Save();
                    MainWindow.ApplyPaletteToResources(appRes, settings);
                }

                return Task.CompletedTask;
            });
        }
        finally
        {
            SettingsManager.OverrideSettingsPath = null;
            SettingsManager.ClearCache();
        }
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _responder;

        public StubHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _responder(request, cancellationToken);
    }
}
