using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.CLI.Framework;
using LogicFlow.Dashboard;
using LogicFlow.Guardian;
using LogicFlow.Storage.Engine.Container;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using OmniLicense;
using OmniPulse;
using OmniService;
using Xunit;

namespace LogicFlow.Tests;

[Collection("CliConsoleExecution")]
public sealed class Round2AuditRemediationTests
{
    [Theory]
    [InlineData("BOOST", App.PipeCommandAction.BoostOn)]
    [InlineData("/boost", App.PipeCommandAction.BoostOn)]
    [InlineData("--boost", App.PipeCommandAction.BoostOn)]
    [InlineData("-boost", App.PipeCommandAction.BoostOn)]
    [InlineData("BOOST_OFF", App.PipeCommandAction.BoostOff)]
    [InlineData("/boost-off", App.PipeCommandAction.BoostOff)]
    [InlineData("--boost-off", App.PipeCommandAction.BoostOff)]
    [InlineData("SHOW", App.PipeCommandAction.Restore)]
    [InlineData("ACTIVATE", App.PipeCommandAction.Restore)]
    [InlineData("RESTORE", App.PipeCommandAction.Restore)]
    [InlineData("RESTORE_AFTER_BOOST", App.PipeCommandAction.None)]
    [InlineData("FOOBOOSTBAR", App.PipeCommandAction.None)]
    [InlineData("BOOST_SOMETHING_ELSE", App.PipeCommandAction.None)]
    [InlineData("", App.PipeCommandAction.None)]
    [InlineData("   ", App.PipeCommandAction.None)]
    [InlineData(null, App.PipeCommandAction.None)]
    public void ParsePipeCommand_UsesExactTokenMatching_NeverSubstringFalsePositives(
        string? rawLine,
        App.PipeCommandAction expected)
    {
        Assert.Equal(expected, App.ParsePipeCommand(rawLine));
    }

    [Fact]
    public void TurboMode_TimerResolutionAndNotificationCallback_ExecuteInCorrectOrderAndRestoreCleanly()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"lf_turbo_test_{Guid.NewGuid():N}");
        string regSubKey = $@"Software\LogicFlowTests\Turbo_{Guid.NewGuid():N}";
        Directory.CreateDirectory(tempDir);
        var calls = new List<(uint Desired, bool Set)>();

        try
        {
            using (var setupKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regSubKey, writable: true))
            {
                setupKey.SetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED", 1, RegistryValueKind.DWord);
            }

            var turbo = new TurboMode(NullLogger<TurboMode>.Instance)
            {
                StateFilePathOverride = Path.Combine(tempDir, "turbo_state.json"),
                OverrideNotificationsRegistrySubKey = regSubKey,
                TimerResolutionInvoker = (desired, set) =>
                {
                    calls.Add((desired, set));
                    return (0, desired);
                }
            };

            var minimalProfile = new TurboMode.TurboProfile
            {
                Name = "TestTimerAndNotifications",
                SwitchPowerPlan = false,
                ServicesToStop = [],
                ProcessesToKill = [],
                DisableNotifications = true,
                SetHighPriority = false,
                OptimizeCpuAffinity = false,
                OptimizeNetwork = false,
                DisableVisualEffects = false,
                SetTimerResolution = true,
                BoostGpuPriority = false
            };

            int? toastStateDuringCallback = null;
            var result = turbo.Activate(
                minimalProfile,
                beforeSuppressNotifications: _ =>
                {
                    using var checkKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false);
                    toastStateDuringCallback = checkKey?.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED") as int?;
                });

            Assert.True(result.Activated);
            // Balloon callback MUST run while toasts are still enabled (1), BEFORE SuppressNotifications sets 0
            Assert.Equal(1, toastStateDuringCallback);

            using (var suppressedKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false))
            {
                Assert.Equal(0, suppressedKey?.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED") as int?);
            }

            Assert.Single(calls);
            Assert.Equal((5000u, true), calls[0]);

            var deactivateResult = turbo.Deactivate();
            Assert.False(deactivateResult.Activated);
            Assert.Equal(2, calls.Count);
            // RestoreTimerResolution MUST pass the saved desired resolution (5000) with SetResolution=false
            Assert.Equal((5000u, false), calls[1]);

            using (var restoredKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regSubKey, writable: false))
            {
                Assert.Equal(1, restoredKey?.GetValue("NOC_GLOBAL_SETTING_TOASTS_ENABLED") as int?);
            }
        }
        finally
        {
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(regSubKey, throwOnMissingSubKey: false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(@"Software\LogicFlowTests", throwOnMissingSubKey: false); } catch { }
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task ScanExclusions_StrictBoundaryMatching_InDiskSpaceAnalyzerAndLfcWriter()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"lf_excl_test_{Guid.NewGuid():N}");
        string excludedDir = Path.Combine(tempRoot, "Cache");
        string siblingNotExcludedDir = Path.Combine(tempRoot, "CacheBackup");
        string lfcPath = Path.Combine(tempRoot, "packed.lfc");

        Directory.CreateDirectory(excludedDir);
        Directory.CreateDirectory(siblingNotExcludedDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(excludedDir, "secret.bin"), new string('X', 4096));
            await File.WriteAllTextAsync(Path.Combine(siblingNotExcludedDir, "keep.txt"), "keep-this-content");

            var analyzer = new DiskSpaceAnalyzer(NullLogger<DiskSpaceAnalyzer>.Instance)
            {
                ExcludedPaths = new[] { excludedDir }
            };
            var spaceReport = analyzer.Analyze(tempRoot, maxDepth: 3, topFilesCount: 10);
            Assert.DoesNotContain(spaceReport.LargestFiles, f => f.Path.Contains("secret.bin", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(spaceReport.LargestFiles, f => f.Path.Contains("keep.txt", StringComparison.OrdinalIgnoreCase));

            string sourceRoot = Path.Combine(tempRoot, "Source");
            string sourceExcluded = Path.Combine(sourceRoot, "SkipMe");
            string sourceSibling = Path.Combine(sourceRoot, "SkipMeNot");
            Directory.CreateDirectory(sourceExcluded);
            Directory.CreateDirectory(sourceSibling);
            await File.WriteAllTextAsync(Path.Combine(sourceExcluded, "dropped.txt"), "should-not-be-packed");
            await File.WriteAllTextAsync(Path.Combine(sourceSibling, "included.txt"), "must-be-packed");

            using var writer = new LfcWriter();
            var packOpts = new LfcPackOptions
            {
                TrainDictionary = false,
                ExcludedPaths = new[] { sourceExcluded }
            };
            await writer.PackDirectoryAsync(sourceRoot, lfcPath, packOpts);

            using var reader = new LfcReader();
            var info = reader.InspectArchive(lfcPath);
            Assert.Equal(1, info.TotalFiles);

            // Packing a root directory that itself is excluded must fail closed
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                writer.PackDirectoryAsync(sourceExcluded, Path.Combine(tempRoot, "blocked.lfc"), packOpts));
        }
        finally
        {
            if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public void CliEditionGate_BlocksMutatingCommandsOnFree_AndAllowsZeroHostageRevertsAndScans()
    {
        string tempAppData = Path.Combine(Path.GetTempPath(), $"lf_cligate_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempAppData);

        try
        {
            CliContext MakeCtx(params string[] args) => new()
            {
                IsJson = true,
                IsSilent = true,
                EnforceEditionGate = true,
                AppDataRootOverride = tempAppData,
                RegistryReaderOverride = (_, _) => null,
                StdOutOverride = new StringWriter(),
                StdErrOverride = new StringWriter(),
                RemainingArgs = args
            };

            // Undecided / Free tier: mutating Core and Pro commands are blocked with exit code 2
            Assert.Equal(Edition.Free, CliEditionGate.ResolveEdition(tempAppData, (_, _) => null));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("sys", "optimize-all"), "sys", "optimize-all"));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("sys", "turbo", "gaming"), "sys", "turbo"));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("store", "pack", "a", "b.lfc"), "store", "pack"));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("lazarus", "carve", "0"), "lazarus", "carve"));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("toolbox", "game-compact", "compress", "C:\\Games"), "toolbox", "game-compact"));

            // Zero-Hostage reverts and read-only scans MUST remain unlocked on Free (exit code 0)
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("sys", "status"), "sys", "status"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("sys", "turbo", "off"), "sys", "turbo"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("sys", "turbo", "status"), "sys", "turbo"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("store", "unpack", "b.lfc", "out"), "store", "unpack"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("store", "scan", "C:\\Temp"), "store", "scan"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("reg", "rollback", "backup.reg"), "reg", "rollback"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("driver", "rollback", "oem1.inf"), "driver", "rollback"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("toolbox", "game-compact", "decompress", "C:\\Games"), "toolbox", "game-compact"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("sec", "ai-guard", "revert"), "sec", "ai-guard"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("agent", "discover"), "agent", "discover"));

            // Record Community consent: Core commands unlock, AdvancedRecovery (lazarus carve) remains Pro-gated
            var consent = new ConsentStore(Path.Combine(tempAppData, "Pulse"), (_, _) => null);
            consent.Apply(EditionChoice.Community, PrivacyRegion.UnitedStates, wantsStandard: true, wantsExtended: true, "1.0", "deadbeef");
            Assert.Equal(Edition.Community, CliEditionGate.ResolveEdition(tempAppData, (_, _) => null));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("sys", "optimize-all"), "sys", "optimize-all"));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("store", "pack", "a", "b.lfc"), "store", "pack"));
            Assert.Equal(CliEditionGate.ExitEditionRequired, CliEditionGate.CheckAccess(MakeCtx("lazarus", "carve", "0"), "lazarus", "carve"));

            // Start 14-day Pro trial: AdvancedRecovery unlocks
            var trial = new TrialManager(NullLogger<TrialManager>.Instance, tempAppData);
            trial.StartTrial();
            Assert.Equal(Edition.Pro, CliEditionGate.ResolveEdition(tempAppData, (_, _) => null));
            Assert.Equal(0, CliEditionGate.CheckAccess(MakeCtx("lazarus", "carve", "0"), "lazarus", "carve"));
        }
        finally
        {
            if (Directory.Exists(tempAppData)) Directory.Delete(tempAppData, recursive: true);
        }
    }

    [Fact]
    public async Task GemmaAiEngine_EnforcesPinnedSha256_AllowsCustomHttpsOverride_AndRejectsInsecureHttp()
    {
        string tempAiDir = Path.Combine(Path.GetTempPath(), $"lf_gemma_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempAiDir);

        try
        {
            byte[] fakeModelBytes = Encoding.UTF8.GetBytes("FAKE-GGUF-WEIGHTS-FOR-SHA256-TEST");
            string actualModelSha = Convert.ToHexString(SHA256.HashData(fakeModelBytes));

            using var zipMs = new MemoryStream();
            using (var zip = new ZipArchive(zipMs, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = zip.CreateEntry(GemmaAiEngine.DefaultSidecarExeName);
                await using var es = entry.Open();
                await es.WriteAsync(Encoding.UTF8.GetBytes("MZ-FAKE-SIDECAR"));
            }
            byte[] fakeZipBytes = zipMs.ToArray();
            string actualZipSha = Convert.ToHexString(SHA256.HashData(fakeZipBytes));

            var handler = new StubHttpMessageHandler(req =>
            {
                var url = req.RequestUri!.ToString();
                byte[] payload = url.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? fakeZipBytes : fakeModelBytes;
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(payload)
                };
                resp.Content.Headers.ContentLength = payload.Length;
                return resp;
            });

            using var httpClient = new HttpClient(handler);

            // 1. Default pinned URL with mismatched SHA-256 MUST fail closed BY DEFAULT (even with custom HttpClient!) and clean up .part file
            var engineMismatch = new GemmaAiEngine(httpClient, tempAiDir);
            Assert.True(engineMismatch.EnforcePinnedSha256);
            await Assert.ThrowsAsync<InvalidDataException>(() => engineMismatch.DownloadSidecarBinaryAsync());
            Assert.False(File.Exists(engineMismatch.LocalSidecarFilePath));

            await Assert.ThrowsAsync<InvalidDataException>(() => engineMismatch.DownloadLocalModelAsync());
            Assert.False(File.Exists(engineMismatch.LocalModelFilePath));

            // 2. Non-loopback HTTP custom URL MUST fail closed
            var engineHttp = new GemmaAiEngine(httpClient, tempAiDir)
            {
                EnforcePinnedSha256 = true,
                ModelDownloadUrl = "http://insecure.example.com/model.gguf"
            };
            await Assert.ThrowsAsync<InvalidOperationException>(() => engineHttp.DownloadLocalModelAsync());

            // 3. Custom HTTPS URL override with matching SHA-256 succeeds
            var engineCustom = new GemmaAiEngine(httpClient, tempAiDir)
            {
                EnforcePinnedSha256 = true,
                ModelDownloadUrl = "https://models.example.com/custom-gemma.gguf",
                ExpectedModelSha256 = actualModelSha,
                SidecarDownloadUrl = "https://models.example.com/custom-llama.zip",
                ExpectedSidecarSha256 = actualZipSha
            };
            Assert.True(await engineCustom.DownloadSidecarBinaryAsync());
            Assert.True(File.Exists(engineCustom.LocalSidecarFilePath));
            Assert.True(await engineCustom.DownloadLocalModelAsync());
            Assert.True(File.Exists(engineCustom.LocalModelFilePath));
        }
        finally
        {
            if (Directory.Exists(tempAiDir)) Directory.Delete(tempAiDir, recursive: true);
        }
    }

    [Fact]
    public void HealthMonitorWorker_BlocksPreConsentAndFreeTierNetworkUpdates()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"lf_agent_consent_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 1. Pre-consent (empty profile): MUST NOT make network calls
            Assert.False(HealthMonitorWorker.IsNetworkUpdateAllowed(tempRoot, (_, _) => null));

            // 2. Free tier decision: MUST NOT make background update network calls
            var consent = new ConsentStore(Path.Combine(tempRoot, "Pulse"), (_, _) => null);
            consent.Apply(EditionChoice.Free, PrivacyRegion.UnitedStates, wantsStandard: false, wantsExtended: false, "1.0", "abc");
            Assert.False(HealthMonitorWorker.IsNetworkUpdateAllowed(tempRoot, (_, _) => null));

            // 3. Community tier decision: allowed when CheckForUpdatesAutomatically is not false
            consent.Apply(EditionChoice.Community, PrivacyRegion.UnitedStates, wantsStandard: true, wantsExtended: true, "1.0", "abc");
            Assert.True(HealthMonitorWorker.IsNetworkUpdateAllowed(tempRoot, (_, _) => null));

            // 4. Explicit CheckForUpdatesAutomatically = false in settings.json: blocked
            File.WriteAllText(Path.Combine(tempRoot, "settings.json"), """{"CheckForUpdatesAutomatically": false}""");
            Assert.False(HealthMonitorWorker.IsNetworkUpdateAllowed(tempRoot, (_, _) => null));
        }
        finally
        {
            if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public void DriverDatabase_TryAttachCloudAuthHeaders_EnforcesRegistryPolicy_PolicyVersion_AndKillUntil()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"lf_drv_consent_{Guid.NewGuid():N}");
        string pulseDir = Path.Combine(tempRoot, "Pulse");
        Directory.CreateDirectory(pulseDir);

        try
        {
            var body = Encoding.UTF8.GetBytes("""{"devices":[],"crashDigest":"test"}""");
            string validInstallId = "0123456789abcdef0123456789abcdef";

            // Valid consent.json with PolicyVersion == 2026-10-1 and no KillUntil
            File.WriteAllText(Path.Combine(pulseDir, "consent.json"), $$"""
            {
              "DecidedAt": "2026-11-11T00:00:00Z",
              "EulaAcceptedAt": "2026-11-11T00:00:00Z",
              "PolicyVersion": "2026-10-1",
              "Level": "Extended",
              "InstallId": "{{validInstallId}}"
            }
            """);

            // 1. Group Policy TelemetryDisabled = 1 MUST fail closed even when consent.json & license exist
            Directory.CreateDirectory(Path.Combine(tempRoot, "License"));
            File.WriteAllText(Path.Combine(tempRoot, "License", "license_token.json"), """{"Payload":"abc","Signature":"def"}""");
            using var gpReq = new HttpRequestMessage(HttpMethod.Post, "https://api.delgadologic.tech/v1/drivers/ai-scan");
            Assert.False(DriverDatabase.TryAttachCloudAuthHeaders(
                gpReq,
                body,
                tempRoot,
                (key, name) => key.Contains(@"Policies\DelgadoLogic\LogicFlow") && name == "TelemetryDisabled" ? 1 : null));
            Assert.False(gpReq.Headers.Contains("X-LF-License-Token"));
            File.Delete(Path.Combine(tempRoot, "License", "license_token.json"));

            // 2. Outdated PolicyVersion MUST fail closed
            File.WriteAllText(Path.Combine(pulseDir, "consent.json"), $$"""
            {
              "DecidedAt": "2026-11-11T00:00:00Z",
              "EulaAcceptedAt": "2026-11-11T00:00:00Z",
              "PolicyVersion": "2025-01-01",
              "Level": "Extended",
              "InstallId": "{{validInstallId}}"
            }
            """);
            using var oldPolicyReq = new HttpRequestMessage(HttpMethod.Post, "https://api.delgadologic.tech/v1/drivers/ai-scan");
            Assert.False(DriverDatabase.TryAttachCloudAuthHeaders(oldPolicyReq, body, tempRoot, (_, _) => null));

            // 3. Active KillUntil MUST fail closed
            string futureIso = DateTimeOffset.UtcNow.AddHours(2).ToString("O");
            File.WriteAllText(Path.Combine(pulseDir, "consent.json"), $$"""
            {
              "DecidedAt": "2026-11-11T00:00:00Z",
              "EulaAcceptedAt": "2026-11-11T00:00:00Z",
              "PolicyVersion": "2026-10-1",
              "KillUntil": "{{futureIso}}",
              "Level": "Extended",
              "InstallId": "{{validInstallId}}"
            }
            """);
            using var killReq = new HttpRequestMessage(HttpMethod.Post, "https://api.delgadologic.tech/v1/drivers/ai-scan");
            Assert.False(DriverDatabase.TryAttachCloudAuthHeaders(killReq, body, tempRoot, (_, _) => null));
        }
        finally
        {
            if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Theory]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "on" }, "gaming", Capability.Core)]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "enable" }, "gaming", Capability.Core)]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "off" }, "off", Capability.Scan)]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "disable" }, "off", Capability.Scan)]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "stop" }, "off", Capability.Scan)]
    [InlineData("sys", "turbo", new[] { "sys", "turbo", "status" }, "status", Capability.Scan)]
    [InlineData("boost", "on", new[] { "boost", "on" }, "gaming", Capability.Core)]
    [InlineData("/boost", "on", new[] { "/boost", "on" }, "gaming", Capability.Core)]
    [InlineData("--boost", "on", new[] { "--boost", "on" }, "gaming", Capability.Core)]
    [InlineData("-boost", "", new[] { "-boost" }, "gaming", Capability.Core)]
    [InlineData("boost", "off", new[] { "boost", "off" }, "off", Capability.Scan)]
    [InlineData("boost", "disable", new[] { "boost", "disable" }, "off", Capability.Scan)]
    [InlineData("/boost-off", "", new[] { "/boost-off" }, "off", Capability.Scan)]
    [InlineData("--boost-off", "", new[] { "--boost-off" }, "off", Capability.Scan)]
    [InlineData("-boost-off", "", new[] { "-boost-off" }, "off", Capability.Scan)]
    [InlineData("boost-off", "", new[] { "boost-off" }, "off", Capability.Scan)]
    public void CliEditionGate_ResolvesBoostAndTurboAliases_PreservingZeroHostageRevert(
        string group,
        string command,
        string[] remainingArgs,
        string expectedMode,
        Capability expectedCapability)
    {
        Assert.Equal(expectedMode, CliEditionGate.ResolveTurboMode(remainingArgs, group, command));
        Assert.True(CliEditionGate.IsValidTurboMode(expectedMode));
        Assert.Equal(expectedCapability, CliEditionGate.GetRequiredCapability(group, command, remainingArgs));

        var freeCtx = new CliContext
        {
            IsJson = true,
            IsSilent = true,
            EnforceEditionGate = true,
            EditionOverride = Edition.Free,
            RemainingArgs = remainingArgs
        };

        int expectedGateExit = expectedCapability == Capability.Scan ? 0 : CliEditionGate.ExitEditionRequired;
        Assert.Equal(expectedGateExit, CliEditionGate.CheckAccess(freeCtx, group, command));
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responder(request));
    }
}
