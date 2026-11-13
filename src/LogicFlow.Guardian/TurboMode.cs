// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – TurboMode (v2 — Razer Cortex-level)
// Advanced system boost: power plan switching, CPU affinity, network
// optimization, visual effects toggle, timer resolution, GPU priority.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian;

/// <summary>
/// Turbo Mode — temporarily optimizes the system for maximum performance
/// during gaming or focused work. All changes are fully reversible.
/// </summary>
public sealed class TurboMode
{
    private readonly ILogger<TurboMode>? _logger;
    private readonly List<string> _stoppedServices = new();
    private readonly List<(int pid, string name)> _suspendedProcesses = new();
    private bool _isActive;
    private string _activeProfileName = "";

    // State to restore on deactivate
    private string _originalPowerPlan = "";
    private bool _notificationsDisabled;
    private bool _priorToastValueExisted;
    private int _priorToastValue = 1;
    private bool _visualEffectsDisabled;
    private int _priorClientAreaAnimation = 1;
    private int _priorMenuFade = 1;
    private int _priorDragFullWindows = 1;
    private int _priorComboBoxAnimation = 1;
    private int _priorListBoxSmoothScrolling = 1;
    private bool _priorTransparencyExisted;
    private int _priorTransparencyValue = 1;
    private bool _networkOptimized;
    private bool _timerResolutionSet;
    private uint _appliedTimerResolution = 5000;
    private bool _gpuPrioritySet;
    private int? _priorSystemResponsiveness;
    private int? _priorGpuPriority;
    private int? _priorGamesPriority;
    private string? _priorSchedulingCategory;
    private readonly Dictionary<string, int?> _originalNetworkValues = new();
    private readonly List<ProcessAffinitySnapshot> _pinnedProcesses = new();
    private int _boostedProcessId = -1;
    private long _boostedProcessStartTicksUtc;
    private ProcessPriorityClass _boostedOriginalPriority = ProcessPriorityClass.Normal;

    /// <summary>
    /// Optional hook for deterministic unit tests of NtSetTimerResolution request/release calls.
    /// </summary>
    public Func<uint, bool, (int Status, uint Current)>? TimerResolutionInvoker { get; set; }

    public uint AppliedTimerResolution => _appliedTimerResolution;

    private const string NotificationsSettingsSubKey = @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";
    private const string ToastEnabledValueName = "NOC_GLOBAL_SETTING_TOASTS_ENABLED";

    private static readonly string DefaultStateFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LogicFlow", "turbo_state.json");

    /// <summary>
    /// Optional path override for isolated unit tests so test runs never touch live %LOCALAPPDATA%\LogicFlow\turbo_state.json.
    /// </summary>
    public static string? OverrideStateFilePath { get; set; }

    /// <summary>
    /// Per-instance path override for parallel-safe unit tests of persisted Turbo Mode state.
    /// </summary>
    public string? StateFilePathOverride { get; set; }

    /// <summary>
    /// Optional registry subkey override (under HKCU) for isolated unit tests of toast notification state snapshotting.
    /// </summary>
    public string? OverrideNotificationsRegistrySubKey { get; set; }

    /// <summary>
    /// Optional provider returning the foreground non-shell application PID for deterministic testing.
    /// </summary>
    public Func<int>? ForegroundAppPidProvider { get; set; }

    /// <summary>
    /// Processes that must never be terminated by Turbo Mode (OS critical, shell, terminals, and LogicFlow itself).
    /// </summary>
    public HashSet<string> ProcessWhitelist { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "LogicFlow", "lf", "LogicFlow.CLI", "LogicFlowAgent",
        "dwm", "csrss", "lsass", "svchost", "services", "winlogon", "smss",
        "taskmgr", "cmd", "powershell", "pwsh", "WindowsTerminal", "conhost",
        "audiodg", "spoolsv"
    };

    // P/Invoke for advanced features
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref int pvParam, uint fWinIni);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

    private const uint SPI_GETDRAGFULLWINDOWS = 0x0026;
    private const uint SPI_SETDRAGFULLWINDOWS = 0x0025;
    private const uint SPI_GETCOMBOBOXANIMATION = 0x1004;
    private const uint SPI_SETCOMBOBOXANIMATION = 0x1005;
    private const uint SPI_GETLISTBOXSMOOTHSCROLLING = 0x1006;
    private const uint SPI_SETLISTBOXSMOOTHSCROLLING = 0x1007;
    private const uint SPI_GETMENUFADE = 0x1012;
    private const uint SPI_SETMENUFADE = 0x1013;
    private const uint SPI_GETCLIENTAREAANIMATION = 0x1042;
    private const uint SPI_SETCLIENTAREAANIMATION = 0x1043;
    private const uint SPIF_SENDCHANGE = 0x0002;

    public TurboMode(ILogger<TurboMode>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public bool IsActive => _isActive || (GetPersistedState()?.Active ?? false);

    public sealed class ProcessAffinitySnapshot
    {
        public int Pid { get; set; }
        public long StartTimeTicksUtc { get; set; }
        public long OriginalAffinityMask { get; set; }
        public string OriginalPriority { get; set; } = nameof(ProcessPriorityClass.Normal);
    }

    public sealed class TurboPersistedState
    {
        public bool Active { get; set; }
        public string ProfileName { get; set; } = "";
        public DateTimeOffset ActivatedAtUtc { get; set; }
        public string OriginalPowerPlan { get; set; } = "";
        public List<string> StoppedServices { get; set; } = new();
        public bool NotificationsDisabled { get; set; }
        public bool PriorToastValueExisted { get; set; }
        public int PriorToastValue { get; set; } = 1;
        public int BoostedProcessId { get; set; } = -1;
        public long BoostedProcessStartTicksUtc { get; set; }
        public string BoostedOriginalPriority { get; set; } = nameof(ProcessPriorityClass.Normal);
        public List<ProcessAffinitySnapshot> PinnedProcesses { get; set; } = new();
        public bool NetworkOptimized { get; set; }
        public Dictionary<string, int?> OriginalNetworkValues { get; set; } = new();
        public bool VisualEffectsDisabled { get; set; }
        public int PriorClientAreaAnimation { get; set; } = 1;
        public int PriorMenuFade { get; set; } = 1;
        public int PriorDragFullWindows { get; set; } = 1;
        public int PriorComboBoxAnimation { get; set; } = 1;
        public int PriorListBoxSmoothScrolling { get; set; } = 1;
        public bool PriorTransparencyExisted { get; set; }
        public int PriorTransparencyValue { get; set; } = 1;
        public bool GpuPrioritySet { get; set; }
        public int? PriorSystemResponsiveness { get; set; }
        public int? PriorGpuPriority { get; set; }
        public int? PriorGamesPriority { get; set; }
        public string? PriorSchedulingCategory { get; set; }
    }

    public sealed class TurboProfile
    {
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public string[] ServicesToStop { get; init; } = [];
        public string[] ProcessesToKill { get; init; } = [];
        public bool DisableNotifications { get; init; }
        public bool SetHighPriority { get; init; }
        // New v2 features
        public bool SwitchPowerPlan { get; init; }
        public bool OptimizeCpuAffinity { get; init; }
        public bool OptimizeNetwork { get; init; }
        public bool DisableVisualEffects { get; init; }
        public bool SetTimerResolution { get; init; }
        public bool BoostGpuPriority { get; init; }
    }

    public sealed class TurboResult
    {
        public bool Activated { get; init; }
        public int ServicesDisabled { get; init; }
        public int ProcessesKilled { get; init; }
        public long MemoryFreedBytes { get; init; }
        public string MemoryFreedFormatted => FormatBytes(MemoryFreedBytes);
        public List<string> Actions { get; init; } = new();
    }

    // ─── Built-in Profiles ───────────────────────────────────────────────

    public static readonly TurboProfile GamingProfile = new()
    {
        Name = "🎮 Gaming Turbo",
        Description = "Maximum GPU/CPU/network for games. Switches power plan, pins CPU cores, disables Nagle.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "Spooler", "TabletInputService", "WMPNetworkSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "YourPhone", "PhoneExperienceHost",
            "SearchApp", "SearchHost", "StartMenuExperienceHost",
            "GameBarPresenceWriter", "gamingservices",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = true,
        OptimizeNetwork = true,
        DisableVisualEffects = true,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile WorkProfile = new()
    {
        Name = "💼 Work Focus",
        Description = "Disable distractions, boost priority. Keeps network normal.",
        ServicesToStop = [
            "SysMain", "DiagTrack", "dmwappushservice",
            "WerSvc", "MapsBroker", "lfsvc",
            "WMPNetworkSvc", "XblAuthManager", "XblGameSave"
        ],
        ProcessesToKill = [
            "GameBar", "GameBarPresenceWriter",
            "Spotify", "YourPhone", "PhoneExperienceHost",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = false,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = false,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public static readonly TurboProfile BatteryProfile = new()
    {
        Name = "🔋 Battery Saver",
        Description = "Minimize background activity to extend battery. Stops everything non-essential.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "MapsBroker",
            "lfsvc", "WMPNetworkSvc", "PcaSvc",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc",
            "Fax", "PrintNotify", "Spooler"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "SearchApp", "SearchHost",
            "GameBar", "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = false,
        SwitchPowerPlan = false,  // Don't switch — let Windows battery saver handle
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = true,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public static readonly TurboProfile StreamingProfile = new()
    {
        Name = "📺 Streaming Mode",
        Description = "Optimized for OBS/streaming. Network + CPU priority without killing Discord/Spotify.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify"
        ],
        ProcessesToKill = [
            "YourPhone", "PhoneExperienceHost",
            "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = true,
        DisableVisualEffects = false,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile ServerProfile = new()
    {
        Name = "🖥️ Server Mode",
        Description = "Optimizes the system for hosting servers or background tasks. Prioritizes network and background performance.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "YourPhone", "PhoneExperienceHost",
            "GameBar", "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = true,
        DisableVisualEffects = true,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public static readonly TurboProfile RenderingProfile = new()
    {
        Name = "🎨 Rendering Mode",
        Description = "Optimized for 3D rendering, video encoding, and compilation (Blender, Premiere, DaVinci). High CPU/GPU priority and power plan without pinning cores or killing creative apps.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
        ],
        ProcessesToKill = [
            "YourPhone", "PhoneExperienceHost",
            "GameBar", "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = true,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile BenchmarkingProfile = new()
    {
        Name = "🏁 Benchmarking Mode",
        Description = "Maximum synthetic & hardware benchmark score mode. Strips all non-essential services, visual effects, and background tasks.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "Spooler", "TabletInputService", "WMPNetworkSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "YourPhone", "PhoneExperienceHost",
            "SearchApp", "SearchHost", "StartMenuExperienceHost",
            "GameBar", "GameBarPresenceWriter", "gamingservices",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = true,
        OptimizeNetwork = true,
        DisableVisualEffects = true,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile MinimumProfile = new()
    {
        Name = "🪶 Minimum Overhead",
        Description = "Light-touch boost: disables notifications and stops telemetry/search indexing without killing user apps or altering network/visual settings.",
        ServicesToStop = [
            "DiagTrack", "dmwappushservice", "WerSvc", "WSearch", "MapsBroker"
        ],
        ProcessesToKill = [
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = false,
        SwitchPowerPlan = false,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = false,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public sealed class SmartProfileRecommendation
    {
        public string ProfileKey { get; init; } = "Gaming";
        public TurboProfile Profile { get; init; } = GamingProfile;
        public string Rationale { get; init; } = "";
        public bool UsedAiEngine { get; init; }
        public string PreBoostBottleneck { get; set; } = "";
        public string PostBoostSummary { get; set; } = "";
        public List<string> DynamicExcludedProcesses { get; init; } = [];
        public TurboResult? ActivationResult { get; set; }
    }

    public static TurboProfile GetProfileByName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return GamingProfile;
        return name.Trim().ToLowerInvariant() switch
        {
            "gaming" or "game" => GamingProfile,
            "streaming" or "stream" => StreamingProfile,
            "rendering" or "render" => RenderingProfile,
            "benchmarking" or "benchmark" => BenchmarkingProfile,
            "minimum" or "min" or "minimal" => MinimumProfile,
            "work" or "focus" => WorkProfile,
            "battery" or "eco" => BatteryProfile,
            "server" => ServerProfile,
            _ => GamingProfile
        };
    }

    /// <summary>
    /// Alias for RecommendSmartProfileAsync per specification.
    /// </summary>
    public Task<SmartProfileRecommendation> SelectSmartProfileAsync(
        IEnumerable<string>? activeProcessNamesOverride = null,
        CancellationToken ct = default)
        => RecommendSmartProfileAsync(activeProcessNamesOverride, ct);

    /// <summary>
    /// Inspects running foreground/background processes and memory telemetry, selects the optimal
    /// TurboProfile via Gemma 4 E2B (or deterministic heuristics), dynamically excludes active
    /// creative/streaming tools from ProcessesToKill, activates the profile, and reports pre/post-boost bottlenecks.
    /// </summary>
    public async Task<SmartProfileRecommendation> SelectAndApplySmartProfileAsync(
        IEnumerable<string>? activeProcessNamesOverride = null,
        CancellationToken ct = default)
    {
        var rec = await RecommendSmartProfileAsync(activeProcessNamesOverride, ct).ConfigureAwait(false);
        var result = Activate(rec.Profile);
        rec.ActivationResult = result;
        rec.PostBoostSummary = result.Activated
            ? $"Applied {rec.Profile.Name}: freed {result.MemoryFreedBytes / (1024 * 1024)} MB RAM, paused {result.ServicesDisabled} service(s), terminated {result.ProcessesKilled} background process(es)."
            : (result.Actions.FirstOrDefault() ?? "Turbo Mode already active.");
        return rec;
    }

    /// <summary>
    /// Uses Gemma 4 E2B (or deterministic process/hardware heuristics if offline) to recommend
    /// the optimal TurboProfile for the current workload, dynamically excluding active user tools.
    /// </summary>
    public async Task<SmartProfileRecommendation> RecommendSmartProfileAsync(
        IEnumerable<string>? activeProcessNamesOverride = null,
        CancellationToken ct = default)
    {
        List<string> procNames;
        if (activeProcessNamesOverride != null)
        {
            procNames = activeProcessNamesOverride.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToList();
        }
        else
        {
            try
            {
                procNames = Process.GetProcesses()
                    .Select(p => { try { return p.ProcessName; } catch { return ""; } })
                    .Where(n => !string.IsNullOrEmpty(n))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
            catch
            {
                procNames = new List<string>();
            }
        }

        long availMemMb = GetAvailableMemory() / (1024 * 1024);
        string preBottleneck = availMemMb > 0 && availMemMb < 4096
            ? $"Memory pressure detected ({availMemMb:N0} MB available RAM across {procNames.Count} active process groups)"
            : $"Analyzed {procNames.Count} active process groups ({availMemMb:N0} MB free RAM)";

        // Deterministic baseline detection from active workloads
        string fallbackKey = "Gaming";
        string fallbackReason = "Defaulted to Gaming Turbo for maximum foreground responsiveness.";

        bool hasStreaming = procNames.Any(p =>
            p.Contains("obs64", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("obs32", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("obs", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("streamlabs", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("xsplit", StringComparison.OrdinalIgnoreCase));

        bool hasRendering = procNames.Any(p =>
            p.Contains("blender", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("premiere", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("afterfx", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("resolve", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("cinema4d", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("handbrake", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("ffmpeg", StringComparison.OrdinalIgnoreCase));

        bool hasBenchmark = procNames.Any(p =>
            p.Contains("3dmark", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("cinebench", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("furmark", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("geekbench", StringComparison.OrdinalIgnoreCase) ||
            p.Contains("timespy", StringComparison.OrdinalIgnoreCase));

        bool hasIdeOrWork = procNames.Any(p =>
            p.Equals("devenv", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("rider64", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("code", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("winword", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("excel", StringComparison.OrdinalIgnoreCase));

        var protectedTools = new List<string>();
        if (hasStreaming)
        {
            protectedTools.AddRange(["Discord", "obs64", "obs32", "Streamlabs", "Spotify"]);
        }
        if (hasRendering || hasIdeOrWork)
        {
            protectedTools.AddRange(["OneDrive", "Slack", "Teams", "Discord"]);
        }

        if (hasBenchmark)
        {
            fallbackKey = "Benchmarking";
            fallbackReason = "Detected active benchmark workload; selected Benchmarking Mode to strip all non-essential background services.";
        }
        else if (hasStreaming)
        {
            fallbackKey = "Streaming";
            fallbackReason = "Detected active broadcast/capture software (OBS/Streamlabs); selected Streaming Mode to preserve Discord/audio while boosting GPU & network.";
        }
        else if (hasRendering)
        {
            fallbackKey = "Rendering";
            fallbackReason = "Detected active 3D/video rendering workload; selected Rendering Mode for full multi-core CPU/GPU throughput.";
        }
        else if (hasIdeOrWork)
        {
            fallbackKey = "Work";
            fallbackReason = "Detected developer/productivity tools; selected Work Focus to reduce background distractions without disrupting network or desktop visuals.";
        }

        try
        {
            var ai = GemmaAiEngine.Instance;
            if (ai.Mode != GemmaExecutionMode.Disabled)
            {
                var sampleProcs = string.Join(", ", procNames.Take(40));
                var prompt =
                    "Select the single best LogicFlow TurboMode profile for this Windows PC right now.\n" +
                    "Allowed profiles: Gaming, Streaming, Rendering, Benchmarking, Minimum, Work, Battery, Server.\n" +
                    $"Notable running processes: {sampleProcs}\n" +
                    $"Telemetry snapshot: {preBottleneck}\n" +
                    $"Heuristic baseline suggestion: {fallbackKey}\n" +
                    "Respond with JSON only: {\"profile\": \"<ProfileName>\", \"rationale\": \"<1 concise sentence>\"}";

                var resp = await ai.ChatAsync(new GemmaChatRequest
                {
                    SystemPrompt = "You are the LogicFlow Smart Boost advisor powered by Gemma 4 E2B. Output valid JSON only.",
                    UserPrompt = prompt,
                    Temperature = 0.1,
                    MaxTokens = 160
                }, ct).ConfigureAwait(false);

                if (resp.Success && !string.IsNullOrWhiteSpace(resp.Content))
                {
                    var text = resp.Content.Trim();
                    int start = text.IndexOf('{');
                    int end = text.LastIndexOf('}');
                    if (start >= 0 && end > start)
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(text.Substring(start, end - start + 1));
                        if (doc.RootElement.TryGetProperty("profile", out var profProp))
                        {
                            var chosenKey = profProp.GetString() ?? fallbackKey;
                            var chosenRationale = doc.RootElement.TryGetProperty("rationale", out var ratProp)
                                ? (ratProp.GetString() ?? fallbackReason)
                                : fallbackReason;
                            var resolved = CustomizeProfileExclusions(GetProfileByName(chosenKey), protectedTools);
                            return new SmartProfileRecommendation
                            {
                                ProfileKey = chosenKey,
                                Profile = resolved,
                                Rationale = chosenRationale,
                                UsedAiEngine = true,
                                PreBoostBottleneck = preBottleneck,
                                DynamicExcludedProcesses = protectedTools
                            };
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Smart Boost AI recommendation fell back to heuristic");
        }

        return new SmartProfileRecommendation
        {
            ProfileKey = fallbackKey,
            Profile = CustomizeProfileExclusions(GetProfileByName(fallbackKey), protectedTools),
            Rationale = fallbackReason,
            UsedAiEngine = false,
            PreBoostBottleneck = preBottleneck,
            DynamicExcludedProcesses = protectedTools
        };
    }

    private static TurboProfile CustomizeProfileExclusions(TurboProfile baseProfile, List<string> protectedTools)
    {
        if (protectedTools.Count == 0)
            return baseProfile;

        var filteredKillList = baseProfile.ProcessesToKill
            .Where(p => !protectedTools.Any(pt => p.Equals(pt, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        if (filteredKillList.Length == baseProfile.ProcessesToKill.Length)
            return baseProfile;

        return new TurboProfile
        {
            Name = baseProfile.Name,
            Description = baseProfile.Description,
            ServicesToStop = baseProfile.ServicesToStop,
            ProcessesToKill = filteredKillList,
            DisableNotifications = baseProfile.DisableNotifications,
            SetHighPriority = baseProfile.SetHighPriority,
            SwitchPowerPlan = baseProfile.SwitchPowerPlan,
            OptimizeCpuAffinity = baseProfile.OptimizeCpuAffinity,
            OptimizeNetwork = baseProfile.OptimizeNetwork,
            DisableVisualEffects = baseProfile.DisableVisualEffects,
            SetTimerResolution = baseProfile.SetTimerResolution,
            BoostGpuPriority = baseProfile.BoostGpuPriority
        };
    }

    // ─── Activate ────────────────────────────────────────────────────────

    /// <summary>
    /// Activates Turbo Mode with the specified profile.
    /// Optional <paramref name="beforeSuppressNotifications"/> callback runs right before Windows toast notifications
    /// are suppressed so tray confirmation balloons are delivered cleanly.
    /// </summary>
    public TurboResult Activate(TurboProfile? profile = null, Action<TurboResult>? beforeSuppressNotifications = null)
    {
        if (IsActive)
        {
            return new TurboResult { Activated = false, Actions = ["Turbo Mode is already active. Deactivate first."] };
        }

        profile ??= GamingProfile;
        _logger?.LogInformation("⚡ Activating Turbo Mode: {Profile}", profile.Name);

        // Immediately unload local AI sidecar if running so 100% of VRAM and RAM is returned to the OS
        bool sidecarStopped = false;
        try
        {
            if (GemmaAiEngine.Instance.IsSidecarRunning)
            {
                GemmaAiEngine.Instance.StopSidecarImmediately();
                sidecarStopped = true;
            }
            else
            {
                GemmaAiEngine.Instance.StopSidecarImmediately();
            }
        }
        catch { }

        long memoryBefore = GetAvailableMemory();
        var actions = new List<string>();
        if (sidecarStopped)
        {
            actions.Add("🧠 Unloaded local Gemma 4 E2B AI sidecar (freed VRAM/RAM)");
        }
        int servicesDisabled = 0;
        int processesKilled = 0;

        // 1) Switch power plan to High Performance / Ultimate
        if (profile.SwitchPowerPlan)
        {
            var planResult = SwitchToHighPerformancePlan();
            if (planResult != null) actions.Add(planResult);
        }

        // 2) Stop services
        foreach (var svcName in profile.ServicesToStop)
        {
            try
            {
                if (!SvcHelper.ServiceExists(svcName)) continue;
                using var sc = new System.ServiceProcess.ServiceController(svcName);
                if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                {
                    if (SvcHelper.StopService(svcName))
                    {
                        _stoppedServices.Add(svcName);
                        servicesDisabled++;
                    }
                }
            }
            catch { }
        }
        if (servicesDisabled > 0)
            actions.Add($"⏹️ Stopped {servicesDisabled} background services");
        else if (profile.ServicesToStop.Length > 0)
            actions.Add("ℹ️ Background services unchanged (Administrator privileges required to stop services)");

        // Resolve active foreground non-shell application PID so we never terminate it and can boost its priority
        int fgPid = ResolveForegroundAppPid();

        // 3) Kill non-whitelisted background processes
        foreach (var procName in profile.ProcessesToKill)
        {
            if (ProcessWhitelist.Contains(procName)) continue;

            try
            {
                var processes = Process.GetProcessesByName(procName);
                foreach (var proc in processes)
                {
                    try
                    {
                        if (proc.Id == Environment.ProcessId || proc.Id == fgPid || ProcessWhitelist.Contains(proc.ProcessName))
                            continue;

                        _suspendedProcesses.Add((proc.Id, proc.ProcessName));
                        proc.Kill();
                        processesKilled++;
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }
        if (processesKilled > 0)
            actions.Add($"🔪 Terminated {processesKilled} background processes");

        // 4) Boost active foreground game / application priority (never LogicFlow.exe itself)
        _boostedProcessId = -1;
        _boostedProcessStartTicksUtc = 0;
        if (profile.SetHighPriority && fgPid > 0 && fgPid != Environment.ProcessId)
        {
            try
            {
                using var fgProc = Process.GetProcessById(fgPid);
                if (!ProcessWhitelist.Contains(fgProc.ProcessName))
                {
                    _boostedOriginalPriority = fgProc.PriorityClass;
                    try { _boostedProcessStartTicksUtc = fgProc.StartTime.ToUniversalTime().Ticks; }
                    catch { _boostedProcessStartTicksUtc = 0; }
                    fgProc.PriorityClass = ProcessPriorityClass.High;
                    _boostedProcessId = fgPid;
                    actions.Add($"🔺 Boosted foreground app '{fgProc.ProcessName}' (PID {fgPid}) to High CPU priority");
                }
            }
            catch { }
        }

        // 5) CPU affinity optimization — pin system processes to cores 0-1 (saving original affinity & priority)
        if (profile.OptimizeCpuAffinity)
        {
            var affinityResult = OptimizeCpuAffinity();
            if (affinityResult != null) actions.Add(affinityResult);
        }

        // 6) Network optimization — disable Nagle algorithm
        if (profile.OptimizeNetwork)
        {
            var networkResult = OptimizeNetwork();
            if (networkResult != null) actions.Add(networkResult);
        }

        // 7) Disable visual effects for GPU headroom
        if (profile.DisableVisualEffects)
        {
            var vfxResult = DisableVisualEffects();
            if (vfxResult != null) actions.Add(vfxResult);
        }

        // 8) Set high-precision timer resolution (0.5ms / 1ms)
        if (profile.SetTimerResolution)
        {
            var timerResult = SetHighTimerResolution();
            if (timerResult != null) actions.Add(timerResult);
        }

        // 9) Boost GPU scheduling priority
        if (profile.BoostGpuPriority)
        {
            var gpuResult = BoostGpuPriority();
            if (gpuResult != null) actions.Add(gpuResult);
        }

        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long memoryAfter = GetAvailableMemory();
        long memoryFreed = Math.Max(0, memoryAfter - memoryBefore);

        if (memoryFreed > 0)
            actions.Add($"💾 Freed {FormatBytes(memoryFreed)} of RAM");

        var result = new TurboResult
        {
            Activated = true,
            ServicesDisabled = servicesDisabled,
            ProcessesKilled = processesKilled,
            MemoryFreedBytes = memoryFreed,
            Actions = actions
        };

        // Deliver any tray confirmation balloon BEFORE silencing Windows toast notifications
        if (beforeSuppressNotifications != null)
        {
            try { beforeSuppressNotifications(result); } catch { }
        }

        // 10) Disable notifications via Focus Assist (snapshotting exact prior user state first)
        if (profile.DisableNotifications && SuppressNotifications())
        {
            actions.Add("🔕 Silenced toast notifications (saved prior Focus Assist state)");
        }

        _isActive = true;
        _activeProfileName = profile.Name;
        SavePersistedState();
        _logger?.LogInformation("Turbo Mode active ({Profile}). {ActionCount} optimizations applied.", profile.Name, actions.Count);

        return result;
    }

    /// <summary>
    /// Snapshots the user's current Windows toast notification state and suppresses toasts for Boost Mode.
    /// </summary>
    public bool SuppressNotifications()
    {
        try
        {
            string subKey = !string.IsNullOrWhiteSpace(OverrideNotificationsRegistrySubKey)
                ? OverrideNotificationsRegistrySubKey!
                : NotificationsSettingsSubKey;

            using (var existingKey = Registry.CurrentUser.OpenSubKey(subKey, writable: false))
            {
                var rawVal = existingKey?.GetValue(ToastEnabledValueName);
                if (rawVal is int existingInt)
                {
                    _priorToastValueExisted = true;
                    _priorToastValue = existingInt;
                }
                else
                {
                    _priorToastValueExisted = false;
                    _priorToastValue = 1;
                }
            }

            using (var writeKey = Registry.CurrentUser.CreateSubKey(subKey, writable: true))
            {
                writeKey?.SetValue(ToastEnabledValueName, 0, RegistryValueKind.DWord);
            }

            _notificationsDisabled = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ─── Preview & State Persistence Helpers ─────────────────────────────

    private int ResolveForegroundAppPid()
    {
        if (ForegroundAppPidProvider != null)
        {
            try { return ForegroundAppPidProvider(); }
            catch { return -1; }
        }

        return LogicFlow.Native.SensorsNative.TryGetForegroundAppProcessId(out int pid) ? pid : -1;
    }

    /// <summary>
    /// Previews which currently running processes would be terminated by the given <see cref="TurboProfile"/>,
    /// excluding whitelisted system/shell/terminal processes and the active foreground application.
    /// </summary>
    public List<(int Pid, string ProcessName)> PreviewTargetProcesses(TurboProfile profile)
    {
        var matches = new List<(int Pid, string ProcessName)>();
        if (profile?.ProcessesToKill is not { Length: > 0 }) return matches;

        int fgPid = ResolveForegroundAppPid();
        foreach (var procName in profile.ProcessesToKill)
        {
            if (ProcessWhitelist.Contains(procName)) continue;
            try
            {
                var procs = Process.GetProcessesByName(procName);
                foreach (var p in procs)
                {
                    try
                    {
                        if (p.Id != Environment.ProcessId && p.Id != fgPid && !ProcessWhitelist.Contains(p.ProcessName))
                        {
                            matches.Add((p.Id, p.ProcessName));
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }
        return matches;
    }

    private string EffectiveStateFilePath =>
        !string.IsNullOrWhiteSpace(StateFilePathOverride)
            ? StateFilePathOverride!
            : (!string.IsNullOrWhiteSpace(OverrideStateFilePath) ? OverrideStateFilePath! : DefaultStateFilePath);

    public TurboPersistedState? GetPersistedState()
    {
        try
        {
            var path = EffectiveStateFilePath;
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            return System.Text.Json.JsonSerializer.Deserialize<TurboPersistedState>(json);
        }
        catch
        {
            return null;
        }
    }

    private void SavePersistedState()
    {
        try
        {
            var path = EffectiveStateFilePath;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var state = new TurboPersistedState
            {
                Active = _isActive,
                ProfileName = _activeProfileName,
                ActivatedAtUtc = DateTimeOffset.UtcNow,
                OriginalPowerPlan = _originalPowerPlan,
                StoppedServices = new List<string>(_stoppedServices),
                NotificationsDisabled = _notificationsDisabled,
                PriorToastValueExisted = _priorToastValueExisted,
                PriorToastValue = _priorToastValue,
                BoostedProcessId = _boostedProcessId,
                BoostedProcessStartTicksUtc = _boostedProcessStartTicksUtc,
                BoostedOriginalPriority = _boostedOriginalPriority.ToString(),
                PinnedProcesses = new List<ProcessAffinitySnapshot>(_pinnedProcesses),
                NetworkOptimized = _networkOptimized,
                OriginalNetworkValues = new Dictionary<string, int?>(_originalNetworkValues),
                VisualEffectsDisabled = _visualEffectsDisabled,
                PriorClientAreaAnimation = _priorClientAreaAnimation,
                PriorMenuFade = _priorMenuFade,
                PriorDragFullWindows = _priorDragFullWindows,
                PriorComboBoxAnimation = _priorComboBoxAnimation,
                PriorListBoxSmoothScrolling = _priorListBoxSmoothScrolling,
                PriorTransparencyExisted = _priorTransparencyExisted,
                PriorTransparencyValue = _priorTransparencyValue,
                GpuPrioritySet = _gpuPrioritySet,
                PriorSystemResponsiveness = _priorSystemResponsiveness,
                PriorGpuPriority = _priorGpuPriority,
                PriorGamesPriority = _priorGamesPriority,
                PriorSchedulingCategory = _priorSchedulingCategory
            };
            File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(
                state,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private void ClearPersistedState()
    {
        try
        {
            var path = EffectiveStateFilePath;
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }

    // ─── Deactivate ──────────────────────────────────────────────────────

    /// <summary>
    /// Deactivates Turbo Mode and restores all original settings (across both in-memory and CLI persisted sessions).
    /// </summary>
    public TurboResult Deactivate()
    {
        if (!_isActive)
        {
            var persisted = GetPersistedState();
            if (persisted is { Active: true })
            {
                _isActive = true;
                _activeProfileName = persisted.ProfileName;
                _originalPowerPlan = persisted.OriginalPowerPlan;
                _stoppedServices.Clear();
                _stoppedServices.AddRange(persisted.StoppedServices);
                _notificationsDisabled = persisted.NotificationsDisabled;
                _priorToastValueExisted = persisted.PriorToastValueExisted;
                _priorToastValue = persisted.PriorToastValue;
                _boostedProcessId = persisted.BoostedProcessId;
                _boostedProcessStartTicksUtc = persisted.BoostedProcessStartTicksUtc;
                if (Enum.TryParse<ProcessPriorityClass>(persisted.BoostedOriginalPriority, ignoreCase: true, out var parsedPrio))
                {
                    _boostedOriginalPriority = parsedPrio;
                }
                _pinnedProcesses.Clear();
                if (persisted.PinnedProcesses != null)
                {
                    _pinnedProcesses.AddRange(persisted.PinnedProcesses);
                }
                _networkOptimized = persisted.NetworkOptimized;
                _originalNetworkValues.Clear();
                if (persisted.OriginalNetworkValues != null)
                {
                    foreach (var kvp in persisted.OriginalNetworkValues)
                        _originalNetworkValues[kvp.Key] = kvp.Value;
                }
                _visualEffectsDisabled = persisted.VisualEffectsDisabled;
                _priorClientAreaAnimation = persisted.PriorClientAreaAnimation;
                _priorMenuFade = persisted.PriorMenuFade;
                _priorDragFullWindows = persisted.PriorDragFullWindows;
                _priorComboBoxAnimation = persisted.PriorComboBoxAnimation;
                _priorListBoxSmoothScrolling = persisted.PriorListBoxSmoothScrolling;
                _priorTransparencyExisted = persisted.PriorTransparencyExisted;
                _priorTransparencyValue = persisted.PriorTransparencyValue;
                _gpuPrioritySet = persisted.GpuPrioritySet;
                _priorSystemResponsiveness = persisted.PriorSystemResponsiveness;
                _priorGpuPriority = persisted.PriorGpuPriority;
                _priorGamesPriority = persisted.PriorGamesPriority;
                _priorSchedulingCategory = persisted.PriorSchedulingCategory;
            }
            else
            {
                return new TurboResult { Activated = false, Actions = ["Turbo Mode is not active."] };
            }
        }

        _logger?.LogInformation("⏹️ Deactivating Turbo Mode...");
        var actions = new List<string>();
        int servicesRestarted = 0;

        // 1) Restore power plan
        if (!string.IsNullOrEmpty(_originalPowerPlan))
        {
            try
            {
                var psi = new ProcessStartInfo("powercfg", $"/setactive {_originalPowerPlan}")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                Process.Start(psi)?.WaitForExit(3000);
                actions.Add("🔌 Restored original power plan");
                _originalPowerPlan = "";
            }
            catch { }
        }

        // 2) Restart stopped services
        foreach (var svcName in _stoppedServices)
        {
            try
            {
                if (SvcHelper.StartService(svcName))
                    servicesRestarted++;
            }
            catch { }
        }
        _stoppedServices.Clear();
        _suspendedProcesses.Clear();
        if (servicesRestarted > 0)
            actions.Add($"▶️ Restarted {servicesRestarted} background services");

        // 3) Restore exact prior toast notification state (never force 1 if user had disabled toasts beforehand)
        if (_notificationsDisabled)
        {
            try
            {
                string subKey = !string.IsNullOrWhiteSpace(OverrideNotificationsRegistrySubKey)
                    ? OverrideNotificationsRegistrySubKey!
                    : NotificationsSettingsSubKey;

                using var writeKey = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
                if (writeKey != null)
                {
                    if (_priorToastValueExisted)
                    {
                        writeKey.SetValue(ToastEnabledValueName, _priorToastValue, RegistryValueKind.DWord);
                    }
                    else
                    {
                        writeKey.DeleteValue(ToastEnabledValueName, throwOnMissingValue: false);
                    }
                }
                actions.Add("🔔 Restored prior notification settings");
                _notificationsDisabled = false;
            }
            catch { }
        }

        // 4) Restore boosted foreground app process priority (only if PID still belongs to the same process instance)
        if (_boostedProcessId > 0)
        {
            try
            {
                using var fgProc = Process.GetProcessById(_boostedProcessId);
                bool sameProcess = true;
                if (_boostedProcessStartTicksUtc > 0)
                {
                    try { sameProcess = fgProc.StartTime.ToUniversalTime().Ticks == _boostedProcessStartTicksUtc; }
                    catch { sameProcess = false; }
                }

                if (sameProcess)
                {
                    fgProc.PriorityClass = _boostedOriginalPriority;
                    actions.Add($"🔽 Restored '{fgProc.ProcessName}' CPU priority to {_boostedOriginalPriority}");
                }
            }
            catch { /* Target app already exited */ }
            finally
            {
                _boostedProcessId = -1;
                _boostedProcessStartTicksUtc = 0;
            }
        }

        // 4b) Restore background process CPU affinity and priority
        if (_pinnedProcesses.Count > 0)
        {
            int restoredAffinities = RestoreCpuAffinity();
            if (restoredAffinities > 0)
                actions.Add($"🧠 Restored CPU affinity and priority on {restoredAffinities} background process(es)");
        }

        // 5) Restore network settings
        if (_networkOptimized)
        {
            RestoreNetwork();
            actions.Add("🌐 Restored network settings");
            _networkOptimized = false;
        }

        // 6) Restore visual effects
        if (_visualEffectsDisabled)
        {
            RestoreVisualEffects();
            actions.Add("✨ Restored visual effects");
            _visualEffectsDisabled = false;
        }

        // 7) Release process timer resolution request using saved DesiredResolution + SetResolution=false
        if (_timerResolutionSet)
        {
            RestoreTimerResolution();
        }

        // 8) Reset GPU priority
        if (_gpuPrioritySet)
        {
            RestoreGpuPriority();
            actions.Add("🎮 Restored GPU priority");
            _gpuPrioritySet = false;
        }

        _isActive = false;
        _activeProfileName = "";
        ClearPersistedState();
        _logger?.LogInformation("Turbo Mode deactivated. All settings restored.");

        return new TurboResult
        {
            Activated = false,
            ServicesDisabled = servicesRestarted,
            Actions = actions
        };
    }

    // ─── Power Plan Switching ────────────────────────────────────────────

    /// <summary>
    /// Switches to High Performance or Ultimate Performance power plan.
    /// Saves current plan GUID for restoration.
    /// </summary>
    private string? SwitchToHighPerformancePlan()
    {
        try
        {
            // Get current active plan
            var getActive = new ProcessStartInfo("powercfg", "/getactivescheme")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var result = Process.Start(getActive);
            var output = result?.StandardOutput.ReadToEnd() ?? "";
            result?.WaitForExit(3000);

            // Parse GUID from output via regex
            var match = System.Text.RegularExpressions.Regex.Match(output, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            if (match.Success)
            {
                _originalPowerPlan = match.Value;
            }

            // Try Ultimate Performance first (GUID: e9a42b02-d5df-448d-aa00-03f14749eb61)
            var ultimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61";
            var highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

            // Check if Ultimate Performance exists
            var listPlans = new ProcessStartInfo("powercfg", "/list")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var listResult = Process.Start(listPlans);
            var listOutput = listResult?.StandardOutput.ReadToEnd() ?? "";
            listResult?.WaitForExit(3000);

            string targetGuid;
            string planName;

            if (listOutput.Contains(ultimateGuid, StringComparison.OrdinalIgnoreCase))
            {
                targetGuid = ultimateGuid;
                planName = "Ultimate Performance";
            }
            else
            {
                // Try to create Ultimate Performance plan
                try
                {
                    var dup = new ProcessStartInfo("powercfg", $"/duplicatescheme {ultimateGuid}")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    var dupResult = Process.Start(dup);
                    dupResult?.WaitForExit(3000);
                    var dupOutput = dupResult?.StandardOutput.ReadToEnd() ?? "";

                    if (dupOutput.Contains("GUID", StringComparison.OrdinalIgnoreCase))
                    {
                        targetGuid = ultimateGuid;
                        planName = "Ultimate Performance";
                    }
                    else
                    {
                        targetGuid = highPerfGuid;
                        planName = "High Performance";
                    }
                }
                catch
                {
                    targetGuid = highPerfGuid;
                    planName = "High Performance";
                }
            }

            // Activate the plan
            var activate = new ProcessStartInfo("powercfg", $"/setactive {targetGuid}")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(activate)?.WaitForExit(3000);

            _logger?.LogInformation("Switched to {Plan} power plan", planName);
            return $"⚡ Switched to {planName} power plan";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to switch power plan");
            return null;
        }
    }

    // ─── CPU Affinity ────────────────────────────────────────────────────

    /// <summary>
    /// Pins low-priority system processes to cores 0-1 while snapshotting each process's
    /// original affinity mask and priority class so <see cref="Deactivate"/> restores them cleanly.
    /// </summary>
    private string? OptimizeCpuAffinity()
    {
        try
        {
            _pinnedProcesses.Clear();
            int coreCount = Environment.ProcessorCount;
            if (coreCount < 4) return null; // Not enough cores to optimize

            // Limit to cores 0-1 for system bloat
            var systemAffinity = (IntPtr)0x3; // Cores 0 and 1
            var systemProcesses = new[]
            {
                "RuntimeBroker", "SearchHost", "SearchApp",
                "backgroundTaskHost", "sihost", "ctfmon",
                "MusNotifyIcon", "SecurityHealthSystray"
            };

            int pinned = 0;
            foreach (var name in systemProcesses)
            {
                try
                {
                    foreach (var proc in Process.GetProcessesByName(name))
                    {
                        try
                        {
                            if (SnapshotAndApplyProcessAffinity(proc, systemAffinity, ProcessPriorityClass.BelowNormal))
                            {
                                pinned++;
                            }
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                catch { }
            }

            if (pinned > 0)
            {
                _logger?.LogInformation("Pinned {Count} system processes to cores 0-1", pinned);
                return $"🧠 Pinned {pinned} system processes to cores 0-1 (freed {coreCount - 2} cores)";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to optimize CPU affinity");
        }
        return null;
    }

    public bool SnapshotAndApplyProcessAffinity(Process proc, IntPtr targetAffinity, ProcessPriorityClass? targetPriority = null)
    {
        if (proc == null) return false;
        try
        {
            int pid = proc.Id;
            if (pid <= 0 || pid == Environment.ProcessId || pid == _boostedProcessId)
                return false;

            long origMask = proc.ProcessorAffinity.ToInt64();
            ProcessPriorityClass origPrio = proc.PriorityClass;
            long startTicks = 0;
            try { startTicks = proc.StartTime.ToUniversalTime().Ticks; } catch { }

            proc.ProcessorAffinity = targetAffinity;
            if (targetPriority.HasValue && origPrio != targetPriority.Value)
            {
                try { proc.PriorityClass = targetPriority.Value; } catch { }
            }

            if (!_pinnedProcesses.Any(s => s.Pid == pid && s.StartTimeTicksUtc == startTicks))
            {
                _pinnedProcesses.Add(new ProcessAffinitySnapshot
                {
                    Pid = pid,
                    StartTimeTicksUtc = startTicks,
                    OriginalAffinityMask = origMask,
                    OriginalPriority = origPrio.ToString()
                });
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public int RestoreCpuAffinity()
    {
        int restored = 0;
        foreach (var snap in _pinnedProcesses)
        {
            if (snap.Pid <= 0) continue;
            try
            {
                using var proc = Process.GetProcessById(snap.Pid);
                bool sameProcess = true;
                if (snap.StartTimeTicksUtc > 0)
                {
                    try { sameProcess = proc.StartTime.ToUniversalTime().Ticks == snap.StartTimeTicksUtc; }
                    catch { sameProcess = false; }
                }

                if (!sameProcess) continue;

                bool anyRestored = false;
                if (snap.OriginalAffinityMask != 0)
                {
                    try
                    {
                        proc.ProcessorAffinity = (IntPtr)snap.OriginalAffinityMask;
                        anyRestored = true;
                    }
                    catch { }
                }

                if (Enum.TryParse<ProcessPriorityClass>(snap.OriginalPriority, ignoreCase: true, out var origPrio))
                {
                    try
                    {
                        proc.PriorityClass = origPrio;
                        anyRestored = true;
                    }
                    catch { }
                }

                if (anyRestored) restored++;
            }
            catch { /* Process exited */ }
        }
        _pinnedProcesses.Clear();
        return restored;
    }

    // ─── Network Optimization ────────────────────────────────────────────

    /// <summary>
    /// Disables Nagle algorithm (TcpAckFrequency=1, TCPNoDelay=1) for lower
    /// network latency during gaming.
    /// </summary>
    private string? OptimizeNetwork()
    {
        try
        {
            var interfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            using var interfaces = Registry.LocalMachine.OpenSubKey(interfacesKey);
            if (interfaces == null) return null;

            int optimized = 0;
            foreach (var ifaceId in interfaces.GetSubKeyNames())
            {
                try
                {
                    using var iface = interfaces.OpenSubKey(ifaceId, writable: true);
                    if (iface == null) continue;

                    // Check if this interface has an IP address (active adapter)
                    var dhcpAddr = iface.GetValue("DhcpIPAddress")?.ToString();
                    var staticAddr = iface.GetValue("IPAddress");
                    if (string.IsNullOrEmpty(dhcpAddr) && staticAddr == null) continue;

                    // Save originals as nullable ints for JSON persistence
                    var key1 = $"{ifaceId}_TcpAckFrequency";
                    var key2 = $"{ifaceId}_TCPNoDelay";
                    _originalNetworkValues[key1] = iface.GetValue("TcpAckFrequency") is int v1 ? v1 : null;
                    _originalNetworkValues[key2] = iface.GetValue("TCPNoDelay") is int v2 ? v2 : null;

                    // Set low-latency values
                    iface.SetValue("TcpAckFrequency", 1, RegistryValueKind.DWord);
                    iface.SetValue("TCPNoDelay", 1, RegistryValueKind.DWord);
                    optimized++;
                }
                catch { }
            }

            if (optimized > 0)
            {
                _networkOptimized = true;
                _logger?.LogInformation("Optimized {Count} network interfaces for low latency", optimized);
                return $"🌐 Disabled Nagle algorithm on {optimized} adapters (lower ping)";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to optimize network");
        }
        return null;
    }

    private void RestoreNetwork()
    {
        try
        {
            var interfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            using var interfaces = Registry.LocalMachine.OpenSubKey(interfacesKey);
            if (interfaces == null) return;

            foreach (var ifaceId in interfaces.GetSubKeyNames())
            {
                try
                {
                    using var iface = interfaces.OpenSubKey(ifaceId, writable: true);
                    if (iface == null) continue;

                    var key1 = $"{ifaceId}_TcpAckFrequency";
                    var key2 = $"{ifaceId}_TCPNoDelay";

                    if (_originalNetworkValues.TryGetValue(key1, out var orig1))
                    {
                        if (orig1.HasValue)
                            iface.SetValue("TcpAckFrequency", orig1.Value, RegistryValueKind.DWord);
                        else
                            iface.DeleteValue("TcpAckFrequency", throwOnMissingValue: false);
                    }

                    if (_originalNetworkValues.TryGetValue(key2, out var orig2))
                    {
                        if (orig2.HasValue)
                            iface.SetValue("TCPNoDelay", orig2.Value, RegistryValueKind.DWord);
                        else
                            iface.DeleteValue("TCPNoDelay", throwOnMissingValue: false);
                    }
                }
                catch { }
            }
            _originalNetworkValues.Clear();
        }
        catch { }
    }

    // ─── Visual Effects ──────────────────────────────────────────────────

    /// <summary>
    /// Disables Windows animations, transparency, and visual effects
    /// to free GPU resources for gaming, snapshotting exact prior user settings first.
    /// </summary>
    private string? DisableVisualEffects()
    {
        try
        {
            // Snapshot exact prior user SPI settings (honoring users with Reduced Motion already set)
            SystemParametersInfo(SPI_GETCLIENTAREAANIMATION, 0, ref _priorClientAreaAnimation, 0);
            SystemParametersInfo(SPI_GETMENUFADE, 0, ref _priorMenuFade, 0);
            SystemParametersInfo(SPI_GETDRAGFULLWINDOWS, 0, ref _priorDragFullWindows, 0);
            SystemParametersInfo(SPI_GETCOMBOBOXANIMATION, 0, ref _priorComboBoxAnimation, 0);
            SystemParametersInfo(SPI_GETLISTBOXSMOOTHSCROLLING, 0, ref _priorListBoxSmoothScrolling, 0);

            int zero = 0;
            SystemParametersInfo(SPI_SETCLIENTAREAANIMATION, 0, ref zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETMENUFADE, 0, ref zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETDRAGFULLWINDOWS, 0, IntPtr.Zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETCOMBOBOXANIMATION, 0, ref zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETLISTBOXSMOOTHSCROLLING, 0, ref zero, SPIF_SENDCHANGE);

            // Snapshot & disable transparency via registry
            try
            {
                const string personalizeSubKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
                using (var readKey = Registry.CurrentUser.OpenSubKey(personalizeSubKey, writable: false))
                {
                    if (readKey?.GetValue("EnableTransparency") is int existingTransp)
                    {
                        _priorTransparencyExisted = true;
                        _priorTransparencyValue = existingTransp;
                    }
                    else
                    {
                        _priorTransparencyExisted = false;
                        _priorTransparencyValue = 1;
                    }
                }
                using (var writeKey = Registry.CurrentUser.CreateSubKey(personalizeSubKey, writable: true))
                {
                    writeKey?.SetValue("EnableTransparency", 0, RegistryValueKind.DWord);
                }
            }
            catch { }

            _visualEffectsDisabled = true;
            _logger?.LogInformation("Visual effects disabled for GPU headroom");
            return "🎨 Disabled animations & transparency (GPU headroom)";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to disable visual effects");
            return null;
        }
    }

    private void RestoreVisualEffects()
    {
        try
        {
            int clientAnim = _priorClientAreaAnimation;
            int menuFade = _priorMenuFade;
            int comboAnim = _priorComboBoxAnimation;
            int smoothScroll = _priorListBoxSmoothScrolling;

            SystemParametersInfo(SPI_SETCLIENTAREAANIMATION, 0, ref clientAnim, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETMENUFADE, 0, ref menuFade, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETDRAGFULLWINDOWS, (uint)(_priorDragFullWindows != 0 ? 1 : 0), IntPtr.Zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETCOMBOBOXANIMATION, 0, ref comboAnim, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETLISTBOXSMOOTHSCROLLING, 0, ref smoothScroll, SPIF_SENDCHANGE);

            try
            {
                const string personalizeSubKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
                using var writeKey = Registry.CurrentUser.CreateSubKey(personalizeSubKey, writable: true);
                if (writeKey != null)
                {
                    if (_priorTransparencyExisted)
                        writeKey.SetValue("EnableTransparency", _priorTransparencyValue, RegistryValueKind.DWord);
                    else
                        writeKey.DeleteValue("EnableTransparency", throwOnMissingValue: false);
                }
            }
            catch { }
        }
        catch { }
    }

    // ─── Timer Resolution ────────────────────────────────────────────────

    private (int Status, uint Current) InvokeTimerResolution(uint desiredResolution, bool setResolution)
    {
        if (TimerResolutionInvoker != null)
        {
            return TimerResolutionInvoker(desiredResolution, setResolution);
        }

        int status = NtSetTimerResolution(desiredResolution, setResolution, out uint current);
        return (status, current);
    }

    /// <summary>
    /// Requests high-precision Windows kernel timer resolution (0.5ms / 5000 100-ns units,
    /// falling back to 1.0ms / 10000 100-ns units) for smoother frame pacing.
    /// </summary>
    public string? SetHighTimerResolution(uint desiredResolution = 5000)
    {
        try
        {
            var (status, current) = InvokeTimerResolution(desiredResolution, true);
            if (status == 0)
            {
                _appliedTimerResolution = desiredResolution;
                _timerResolutionSet = true;
                double currentMs = current / 10000.0;
                _logger?.LogInformation("Timer resolution set to {Resolution}ms (requested {Desired})", currentMs, desiredResolution);
                return $"⏱️ Timer resolution: {currentMs:0.##}ms (smoother frame pacing)";
            }

            if (desiredResolution != 10000)
            {
                var (fallbackStatus, fallbackCurrent) = InvokeTimerResolution(10000, true);
                if (fallbackStatus == 0)
                {
                    _appliedTimerResolution = 10000;
                    _timerResolutionSet = true;
                    double currentMs = fallbackCurrent / 10000.0;
                    _logger?.LogInformation("Timer resolution set to {Resolution}ms (requested 10000)", currentMs);
                    return $"⏱️ Timer resolution: {currentMs:0.##}ms (smoother frame pacing)";
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to set timer resolution");
        }
        return null;
    }

    /// <summary>
    /// Releases this process's kernel timer resolution request by passing SetResolution=false
    /// with the exact saved DesiredResolution previously requested.
    /// </summary>
    public bool RestoreTimerResolution()
    {
        if (!_timerResolutionSet) return false;
        try
        {
            var (status, _) = InvokeTimerResolution(_appliedTimerResolution, false);
            _timerResolutionSet = false;
            return status == 0;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to restore timer resolution");
            _timerResolutionSet = false;
            return false;
        }
    }

    // ─── GPU Priority ────────────────────────────────────────────────────

    /// <summary>
    /// Sets GPU scheduling priority to prefer foreground apps via registry,
    /// snapshotting exact prior SystemProfile values first.
    /// </summary>
    private string? BoostGpuPriority()
    {
        try
        {
            const string sysProfileSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
            const string gamesSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games";

            using (var spRead = Registry.LocalMachine.OpenSubKey(sysProfileSubKey, writable: false))
            {
                _priorSystemResponsiveness = spRead?.GetValue("SystemResponsiveness") is int sr ? sr : null;
            }
            using (var gRead = Registry.LocalMachine.OpenSubKey(gamesSubKey, writable: false))
            {
                _priorGpuPriority = gRead?.GetValue("GPU Priority") is int gp ? gp : null;
                _priorGamesPriority = gRead?.GetValue("Priority") is int pr ? pr : null;
                _priorSchedulingCategory = gRead?.GetValue("Scheduling Category") as string;
            }

            // Set GPU scheduling priority (8 = highest for foreground apps)
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness", 0, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "GPU Priority", 8, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority", 6, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Scheduling Category", "High", RegistryValueKind.String);

            _gpuPrioritySet = true;
            _logger?.LogInformation("GPU scheduling priority boosted");
            return "🖥️ GPU scheduling priority set to maximum";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to boost GPU priority (need admin)");
            return null;
        }
    }

    private void RestoreGpuPriority()
    {
        try
        {
            const string sysProfileSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
            const string gamesSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games";

            using (var spWrite = Registry.LocalMachine.OpenSubKey(sysProfileSubKey, writable: true))
            {
                if (spWrite != null)
                {
                    if (_priorSystemResponsiveness.HasValue)
                        spWrite.SetValue("SystemResponsiveness", _priorSystemResponsiveness.Value, RegistryValueKind.DWord);
                    else
                        spWrite.SetValue("SystemResponsiveness", 20, RegistryValueKind.DWord);
                }
            }

            using (var gWrite = Registry.LocalMachine.OpenSubKey(gamesSubKey, writable: true))
            {
                if (gWrite != null)
                {
                    gWrite.SetValue("GPU Priority", _priorGpuPriority ?? 2, RegistryValueKind.DWord);
                    gWrite.SetValue("Priority", _priorGamesPriority ?? 2, RegistryValueKind.DWord);
                    gWrite.SetValue("Scheduling Category", _priorSchedulingCategory ?? "Medium", RegistryValueKind.String);
                }
            }
        }
        catch { }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static long GetAvailableMemory()
    {
        try
        {
            using var counter = new PerformanceCounter("Memory", "Available Bytes");
            return (long)counter.NextValue();
        }
        catch { return 0; }
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
