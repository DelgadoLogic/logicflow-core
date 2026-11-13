using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.CLI.Commands;
using LogicFlow.Dashboard;
using LogicFlow.Guardian;
using LogicFlow.Guardian.Worker;
using LogicFlow.Sentinel;
using LogicFlow.VoiceAgent;
using Microsoft.Extensions.Logging.Abstractions;
using OmniCore.Engine;
using Xunit;

namespace LogicFlow.Tests;

public sealed class CategoryBAndGemmaTests
{
    // ─────────────────────────────────────────────────────────────────────────
    // 1. FullScreenGameGuard — PID Exclusion & Sidecar Unload Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void FullScreenGameGuard_ExcludesOwnProcessId_AndRegisteredSidecarPids()
    {
        int ownPid = Environment.ProcessId;
        using var guard = new FullScreenGameGuard();
        Assert.True(guard.IsExcludedCounterInstance($"pid_{ownPid}_luid_0x00000000_0x00012345_phys_0_eng_0_engtype_3D"));

        int sidecarPid = 999888;
        guard.RegisterExcludedProcessId(sidecarPid);
        try
        {
            Assert.True(guard.IsExcludedCounterInstance($"pid_{sidecarPid}_luid_0x00000000_0x00012345_phys_0_eng_0_engtype_3D"));
            Assert.False(guard.IsExcludedCounterInstance("pid_424242_luid_0x00000000_0x00012345_phys_0_eng_0_engtype_3D"));
        }
        finally
        {
            guard.UnregisterExcludedProcessId(sidecarPid);
        }

        Assert.False(guard.IsExcludedCounterInstance($"pid_{sidecarPid}_luid_0x00000000_0x00012345_phys_0_eng_0_engtype_3D"));
    }

    [Fact]
    public void FullScreenGameGuard_Sensor3_IgnoresSelfAndSidecarGpuLoad_AndUnloadsSidecarOnRealGame()
    {
        int ownPid = Environment.ProcessId;
        int sidecarPid = 777666;
        using var guard = new FullScreenGameGuard();
        guard.RegisterExcludedProcessId(sidecarPid);
        guard.UserNotificationStateProvider = () => LogicFlow.Native.SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_ACCEPTS_NOTIFICATIONS;
        guard.FullScreenWindowProvider = () => false;

        bool gameDetectedFired = false;
        void OnGameDetected() => gameDetectedFired = true;
        FullScreenGameGuard.GlobalGameDetected += OnGameDetected;

        try
        {
            // Case A: Only LogicFlow.exe and llama-server sidecar have high 3D engine usage (95%)
            guard.GpuCounterInstancesProvider = () => new[]
            {
                ($"pid_{ownPid}_luid_0x0_engtype_3D", 55.0),
                ($"pid_{sidecarPid}_luid_0x0_engtype_3D", 40.0),
                ("pid_1234_luid_0x0_engtype_Copy", 90.0)
            };

            Assert.False(guard.CheckIsGameRunning());
            Assert.False(gameDetectedFired);

            // Case B: External game process exceeds 35% 3D engine threshold
            guard.GpuCounterInstancesProvider = () => new[]
            {
                ($"pid_{ownPid}_luid_0x0_engtype_3D", 15.0),
                ("pid_554433_luid_0x0_engtype_3D", 62.5)
            };

            Assert.True(guard.CheckIsGameRunning());
            Assert.True(gameDetectedFired);
        }
        finally
        {
            FullScreenGameGuard.GlobalGameDetected -= OnGameDetected;
            guard.UnregisterExcludedProcessId(sidecarPid);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. LogicFlowFunctionDispatcher, VoiceAgentEngine & TurboMode Smart Boost
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LogicFlowFunctionDispatcher_FilterAndDispatchJunkCleanScope_SelectsExactCategories()
    {
        var sampleCategories = new List<JunkCleanerEngine.JunkScanResult>
        {
            new() { Category = JunkCleanerEngine.JunkCategory.WindowsTemp },
            new() { Category = JunkCleanerEngine.JunkCategory.UserTemp },
            new() { Category = JunkCleanerEngine.JunkCategory.BrowserCache },
            new() { Category = JunkCleanerEngine.JunkCategory.CrashDumps }
        };

        var tempOnly = LogicFlowFunctionDispatcher.FilterScanResultsByScope(sampleCategories, "temp_only");
        Assert.Equal(2, tempOnly.Count(c => c.IsSelected));
        Assert.All(tempOnly.Where(c => c.IsSelected), c =>
            Assert.True(c.Category is JunkCleanerEngine.JunkCategory.WindowsTemp or JunkCleanerEngine.JunkCategory.UserTemp));

        var browserOnly = LogicFlowFunctionDispatcher.FilterScanResultsByScope(sampleCategories, "browser_only");
        Assert.Single(browserOnly.Where(c => c.IsSelected));
        Assert.Equal(JunkCleanerEngine.JunkCategory.BrowserCache, browserOnly.Single(c => c.IsSelected).Category);

        var full = LogicFlowFunctionDispatcher.FilterScanResultsByScope(sampleCategories, "full");
        Assert.Equal(4, full.Count(c => c.IsSelected));

        // Verify DispatchAsync routes scope through CustomCleanHandler
        string? observedScope = null;
        var dispatcher = new LogicFlowFunctionDispatcher(
            NullLogger<LogicFlowFunctionDispatcher>.Instance,
            new JunkCleanerEngine(),
            new SystemInfoEngine())
        {
            CustomCleanHandler = scope =>
            {
                observedScope = scope;
                return new JunkCleanerEngine.CleanResult { FilesDeleted = 12, BytesCleaned = 1048576 };
            }
        };

        using var argsDoc = JsonDocument.Parse("{\"scope\":\"browser_only\"}");
        await dispatcher.DispatchAsync(new FunctionCall
        {
            Id = "call_clean_1",
            Name = "junk_clean",
            Args = argsDoc.RootElement.Clone()
        });

        Assert.Equal("browser_only", observedScope);
    }

    [Theory]
    [InlineData("Gaming", "🎮 Gaming Turbo")]
    [InlineData("Streaming", "📺 Streaming Mode")]
    [InlineData("Rendering", "🎨 Rendering Mode")]
    [InlineData("Benchmarking", "🏁 Benchmarking Mode")]
    [InlineData("Minimum", "🪶 Minimum Overhead")]
    [InlineData("Work", "💼 Work Focus")]
    [InlineData("Battery", "🔋 Battery Saver")]
    [InlineData("Server", "🖥️ Server Mode")]
    public void TurboMode_GetProfileByName_ResolvesAll8Profiles(string profileKey, string expectedName)
    {
        var profile = TurboMode.GetProfileByName(profileKey);
        Assert.Equal(expectedName, profile.Name);
        Assert.NotEmpty(profile.ServicesToStop);
    }

    [Fact]
    public async Task TurboMode_SelectSmartProfileAsync_SelectsStreamingAndExcludesObsAndDiscord()
    {
        var prevMode = GemmaAiEngine.Instance.Mode;
        var prevTransport = GemmaAiEngine.Instance.CustomTransport;
        try
        {
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.Disabled;
            var turbo = new TurboMode();
            var rec = await turbo.SelectSmartProfileAsync(new[] { "obs64", "Discord", "Cyberpunk2077" });

            Assert.Equal("Streaming", rec.ProfileKey);
            Assert.False(rec.UsedAiEngine);
            Assert.DoesNotContain("Discord", rec.Profile.ProcessesToKill, StringComparer.OrdinalIgnoreCase);
            Assert.Contains("Discord", rec.DynamicExcludedProcesses, StringComparer.OrdinalIgnoreCase);
            Assert.False(string.IsNullOrWhiteSpace(rec.PreBoostBottleneck));

            // Now verify AI-guided recommendation when Gemma 4 E2B is enabled
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.HybridAuto;
            GemmaAiEngine.Instance.CustomTransport = (_, _) => Task.FromResult(new GemmaChatResponse
            {
                Success = true,
                Text = "{\"profile\":\"Rendering\",\"rationale\":\"Detected Blender 3D rendering pipeline.\"}"
            });

            var aiRec = await turbo.SelectSmartProfileAsync(new[] { "blender", "OneDrive" });
            Assert.Equal("Rendering", aiRec.ProfileKey);
            Assert.True(aiRec.UsedAiEngine);
            Assert.Contains("Blender", aiRec.Rationale, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            GemmaAiEngine.Instance.CustomTransport = prevTransport;
            GemmaAiEngine.Instance.Mode = prevMode;
        }
    }

    [Fact]
    public async Task VoiceAgentEngine_ExecuteTextCommandAsync_AndAudioUtterance_DispatchesTools()
    {
        var prevMode = GemmaAiEngine.Instance.Mode;
        var prevTransport = GemmaAiEngine.Instance.CustomTransport;
        try
        {
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.HybridAuto;
            GemmaAiEngine.Instance.CustomTransport = (_, _) => Task.FromResult(new GemmaChatResponse
            {
                Success = true,
                ProviderUsed = "LocalSidecar(gemma-4-E2B-it)",
                Text = "<|thought|>User wants to clean browser cache.<|thought|><|tool_call|>call:junk_clean{scope:\"browser_only\"}<|tool_call|>"
            });

            string? cleanedScope = null;
            var dispatcher = new LogicFlowFunctionDispatcher(
                NullLogger<LogicFlowFunctionDispatcher>.Instance,
                new JunkCleanerEngine(),
                new SystemInfoEngine())
            {
                CustomCleanHandler = s =>
                {
                    cleanedScope = s;
                    return new JunkCleanerEngine.CleanResult { FilesDeleted = 5, BytesCleaned = 2048 };
                }
            };

            var engine = new VoiceAgentEngine(dispatcher)
            {
                LocalSttTranscriber = (_, _) => Task.FromResult("Clean my browser cache")
            };

            var audioRes = await engine.ProcessAudioUtteranceAsync(new byte[] { 1, 2, 3, 4 });
            Assert.True(audioRes.Success);
            Assert.Contains("junk_clean", audioRes.ExecutedTools);
            Assert.Equal("browser_only", cleanedScope);
        }
        finally
        {
            GemmaAiEngine.Instance.CustomTransport = prevTransport;
            GemmaAiEngine.Instance.Mode = prevMode;
        }
    }

    [Fact]
    public void LogicFlowFunctionDispatcher_ExposesAll12ToolDefinitions()
    {
        var tools = LogicFlowFunctionDispatcher.GetGemmaToolDefinitions();
        Assert.Equal(12, tools.Count);

        var expectedNames = new[]
        {
            "junk_scan",
            "junk_clean",
            "system_overview",
            "disk_health",
            "memory_status",
            "startup_analysis",
            "driver_scan",
            "network_optimize",
            "game_mode_toggle",
            "cpu_speed",
            "gpu_info",
            "logicflow_version"
        };

        foreach (var name in expectedNames)
        {
            Assert.Contains(tools, t => t.Name == name);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. StartupAuditor — Authenticode Verification, .lnk Deduplication & Tasks
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void StartupAuditor_IsTrustedExecutable_RejectsUnsignedPathWithMicrosoftInName()
    {
        // Previously, any command containing "microsoft" or "windows" was blindly trusted.
        string fakeTempDir = Path.Combine(Path.GetTempPath(), "LogicFlow_Test_microsoft_windows_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fakeTempDir);
        string fakeExe = Path.Combine(fakeTempDir, "microsoft_updater.exe");
        try
        {
            File.WriteAllBytes(fakeExe, new byte[] { 0x4D, 0x5A, 0x00, 0x00 }); // Unsigned dummy bytes
            Assert.False(StartupAuditor.IsTrustedExecutable($"\"{fakeExe}\" --silent"));
            Assert.NotEqual(StartupClassification.Trusted, StartupAuditor.ClassifyEntry("MicrosoftUpdater", $"\"{fakeExe}\" --silent"));
        }
        finally
        {
            if (Directory.Exists(fakeTempDir))
                Directory.Delete(fakeTempDir, recursive: true);
        }

        // Non-existent path with "windows" in name must also return false
        Assert.False(StartupAuditor.IsTrustedExecutable(@"C:\Users\Public\windows_helper\evil.exe"));
    }

    [Fact]
    public void StartupAuditor_ScanStartupFolder_DoesNotDuplicateLnkFiles()
    {
        string tempStartupDir = Path.Combine(Path.GetTempPath(), "LogicFlow_StartupTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempStartupDir);
        try
        {
            File.WriteAllBytes(Path.Combine(tempStartupDir, "Discord.lnk"), new byte[] { 0x01, 0x02 });
            File.WriteAllBytes(Path.Combine(tempStartupDir, "Steam.lnk"), new byte[] { 0x01, 0x02 });
            File.WriteAllBytes(Path.Combine(tempStartupDir, "Helper.exe"), new byte[] { 0x4D, 0x5A });
            File.WriteAllBytes(Path.Combine(tempStartupDir, "desktop.ini"), new byte[] { 0x00 });

            var auditor = new StartupAuditor(NullLogger<StartupAuditor>.Instance);
            var report = new StartupAuditReport();
            auditor.ScanStartupFolder(report, tempStartupDir, "User Startup Folder");

            // Should contain exactly 3 items (Discord.lnk, Steam.lnk, Helper.exe) — no duplicate .lnk entries and no desktop.ini
            Assert.Equal(3, report.Entries.Count);
            Assert.Equal(1, report.Entries.Count(i => i.Name == "Discord.lnk"));
            Assert.Equal(1, report.Entries.Count(i => i.Name == "Steam.lnk"));
            Assert.Equal(1, report.Entries.Count(i => i.Name == "Helper.exe"));
        }
        finally
        {
            if (Directory.Exists(tempStartupDir))
                Directory.Delete(tempStartupDir, recursive: true);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. DriverDatabase — API Base, Local Crash Digest & All 5 Event Patterns
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DriverDatabase_DefaultApiBase_AndCrashDigestAndPatternMatching()
    {
        Assert.Equal("https://api.delgadologic.tech/v1/drivers", DriverDatabase.DefaultApiBase);

        using var db = new DriverDatabase();
        string digestJson = db.CollectLocalCrashDigestJson(maxEvents: 5);
        Assert.False(string.IsNullOrWhiteSpace(digestJson));
        using var doc = JsonDocument.Parse(digestJson);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.GetProperty("events").ValueKind);

        var installedDrivers = new List<DriverReport>
        {
            new()
            {
                DeviceName = "NVIDIA GeForce RTX 4080",
                HardwareId = @"PCI\VEN_10DE&DEV_2704",
                Manufacturer = "NVIDIA",
                DriverVersion = "31.0.15.5123",
                DriverDate = "2024-01-15",
                InfName = "oem42.inf",
                DeviceClass = "Display",
                IsSigned = true
            },
            new()
            {
                DeviceName = "AMD PCIe Root Complex",
                HardwareId = @"PCI\VEN_1022&DEV_1480",
                Manufacturer = "AMD",
                DriverVersion = "5.12.0.38",
                DriverDate = "2024-02-01",
                InfName = "oem11.inf",
                DeviceClass = "System",
                IsSigned = true
            }
        };

        string sampleCrashPayload =
            "[{\"eventId\":4101,\"source\":\"Display\",\"message\":\"Display driver nvlddmkm stopped responding.\"}," +
            "{\"eventId\":14,\"source\":\"nvlddmkm\",\"message\":\"GPU fault\"}," +
            "{\"eventId\":1001,\"source\":\"BugCheck\",\"message\":\"The computer has rebooted from a bugcheck.\"}," +
            "{\"eventId\":41,\"source\":\"Kernel-Power\",\"message\":\"The system has rebooted without cleanly shutting down first.\"}," +
            "{\"eventId\":18,\"source\":\"Microsoft-Windows-WHEA-Logger\",\"message\":\"A fatal hardware error has occurred.\"}]";

        var recs = db.MatchLocalCrashPatterns(installedDrivers, sampleCrashPayload);
        Assert.NotEmpty(recs);
        Assert.Contains(recs, r => r.DriverName.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(recs, r => r.CrashSignatures.Contains("EventID:1001"));
        Assert.Contains(recs, r => r.CrashSignatures.Contains("EventID:41"));
        Assert.Contains(recs, r => r.CrashSignatures.Contains("WHEA-Logger"));

        // Verify GemmaAiEngine correlation takes priority when enabled
        var prevMode = GemmaAiEngine.Instance.Mode;
        var prevTransport = GemmaAiEngine.Instance.CustomTransport;
        try
        {
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.HybridAuto;
            GemmaAiEngine.Instance.CustomTransport = (_, _) => Task.FromResult(new GemmaChatResponse
            {
                Success = true,
                Text = "[{\"DriverName\":\"NVIDIA GeForce RTX 4080\",\"HardwareId\":\"PCI\\\\VEN_10DE&DEV_2704\",\"Reason\":\"Gemma 4 E2B correlated TDR 4101 + nvlddmkm fault\",\"Confidence\":0.97,\"Severity\":\"critical\",\"CrashSignatures\":[\"nvlddmkm.sys\"],\"CrashCount\":2}]"
            });

            var aiRecs = await db.GetAiRecommendationsAsync(installedDrivers, sampleCrashPayload);
            Assert.Contains(aiRecs, r => r.Confidence >= 0.96 && r.Reason.Contains("Gemma 4 E2B"));
        }
        finally
        {
            GemmaAiEngine.Instance.CustomTransport = prevTransport;
            GemmaAiEngine.Instance.Mode = prevMode;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. GemmaAiEngine & PulseQueryEngine — OpenAI Protocol, Download & Cache
    // ─────────────────────────────────────────────────────────────────────────

    private sealed class FakeChatHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _responseJson;
        private readonly long? _overrideContentLength;
        public string? LastRequestBody { get; private set; }

        public FakeChatHttpMessageHandler(string responseJson, long? overrideContentLength = null)
        {
            _responseJson = responseJson;
            _overrideContentLength = overrideContentLength;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Content != null)
            {
                LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            var content = new StringContent(_responseJson, Encoding.UTF8, "application/json");
            if (_overrideContentLength.HasValue)
            {
                content.Headers.ContentLength = _overrideContentLength.Value;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = content
            };
        }
    }

    [Fact]
    public async Task GemmaAiEngine_CloudEndpoint_ParsesToolCallsAndTextResponses()
    {
        string fakeOpenAiToolResponse = """
        {
          "choices": [
            {
              "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                  {
                    "id": "call_01",
                    "type": "function",
                    "function": {
                      "name": "junk_clean",
                      "arguments": "{\"scope\":\"temp_only\"}"
                    }
                  }
                ]
              }
            }
          ]
        }
        """;

        var handler = new FakeChatHttpMessageHandler(fakeOpenAiToolResponse);
        using var httpClient = new HttpClient(handler);
        using var engine = new GemmaAiEngine(httpClient)
        {
            Mode = GemmaExecutionMode.CloudEndpoint
        };

        var response = await engine.ChatAsync(new GemmaChatRequest
        {
            SystemPrompt = "You are LogicFlow.",
            UserPrompt = "Clean my temp files",
            Tools = LogicFlowFunctionDispatcher.GetGemmaToolDefinitions()
        });

        Assert.True(response.Success);
        Assert.Contains("CloudEndpoint", response.ProviderUsed);
        Assert.Single(response.ToolCalls);
        Assert.Equal("junk_clean", response.ToolCalls[0].Name);
        Assert.Contains("temp_only", response.ToolCalls[0].ArgumentsJson);
        Assert.NotNull(handler.LastRequestBody);
        Assert.Contains("gemma-4-E2B-it", handler.LastRequestBody);
    }

    [Fact]
    public async Task GemmaAiEngine_DownloadLocalModelAsync_VerifiesSha256AndDeletesModel()
    {
        string payload = "FAKE_GGUF_WEIGHTS_CONTENT_FOR_UNIT_TEST";
        string expectedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));

        string tempDir = Path.Combine(Path.GetTempPath(), "LogicFlow_GemmaDownload_" + Guid.NewGuid().ToString("N"));
        try
        {
            var handler = new FakeChatHttpMessageHandler(payload);
            using var httpClient = new HttpClient(handler);
            using var engine = new GemmaAiEngine(httpClient, tempDir)
            {
                ExpectedModelSha256 = expectedHash
            };

            bool ok = await engine.DownloadLocalModelAsync();
            Assert.True(ok);
            Assert.True(engine.IsLocalModelInstalled());

            bool deleted = engine.DeleteLocalModel();
            Assert.True(deleted);
            Assert.False(engine.IsLocalModelInstalled());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task PulseQueryEngine_QueryNaturalLanguageAsync_UsesTier1CacheAndGemmaForOpenEndedQueries()
    {
        var prevMode = GemmaAiEngine.Instance.Mode;
        var prevTransport = GemmaAiEngine.Instance.CustomTransport;
        try
        {
            int aiCallCount = 0;
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.HybridAuto;
            GemmaAiEngine.Instance.CustomTransport = (_, _) =>
            {
                aiCallCount++;
                return Task.FromResult(new GemmaChatResponse
                {
                    Success = true,
                    Text = "Gemma 4 E2B Analysis: Your game stuttered around 11 PM due to background shader compilation and RAM swap pressure."
                });
            };

            // 1. Exact standard Tier-1 query ("what is my gpu") should hit <5ms cache without calling AI
            string fastReply = await PulseQueryEngine.QueryNaturalLanguageAsync("what is my gpu");
            Assert.Contains("Graphics", fastReply, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, aiCallCount);

            // 2. Open-ended diagnostic question routes to Gemma 4 E2B
            string deepReply = await PulseQueryEngine.QueryNaturalLanguageAsync("Why did my game stutter around 11 PM last night?");
            Assert.Contains("Gemma 4 E2B Analysis", deepReply);
            Assert.Equal(1, aiCallCount);

            // 3. When AI is disabled, open-ended question gracefully falls back to deterministic output
            GemmaAiEngine.Instance.Mode = GemmaExecutionMode.Disabled;
            string fallbackReply = await PulseQueryEngine.QueryNaturalLanguageAsync("Why did my game stutter around 11 PM last night?");
            Assert.False(string.IsNullOrWhiteSpace(fallbackReply));
            Assert.Equal(1, aiCallCount);
        }
        finally
        {
            GemmaAiEngine.Instance.CustomTransport = prevTransport;
            GemmaAiEngine.Instance.Mode = prevMode;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. AgenticCommands — 10 CLI Command Groups Including 'store'
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AgenticCommands_GetDiscoverySchema_IncludesStoreCommandGroup()
    {
        string json = JsonSerializer.Serialize(AgenticCommands.GetDiscoverySchema());
        using var doc = JsonDocument.Parse(json);
        var groups = doc.RootElement.GetProperty("groups");

        Assert.Equal(10, groups.GetArrayLength());

        var storeGroup = groups.EnumerateArray().FirstOrDefault(g => g.GetProperty("name").GetString() == "store");
        Assert.Equal(JsonValueKind.Object, storeGroup.ValueKind);

        var commands = storeGroup.GetProperty("commands").EnumerateArray()
            .Select(c => c.GetString())
            .ToList();

        Assert.Contains("scan", commands);
        Assert.Contains("dedup", commands);
        Assert.Contains("pack", commands);
        Assert.Contains("unpack", commands);
    }
}
