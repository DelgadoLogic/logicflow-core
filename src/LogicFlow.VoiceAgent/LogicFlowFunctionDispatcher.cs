// ─────────────────────────────────────────────────────────────────────────────
// LogicFlowFunctionDispatcher.cs — Maps Gemini function calls to LogicFlow modules
//
// This is the "brain" that connects the AI's function call requests
// to real LogicFlow engine operations.
//
// When the AI says "I'll clean junk files for you", it emits:
//   { "name": "junk_clean", "args": { "scope": "full" } }
// This dispatcher executes the real JunkCleanerEngine and returns structured results.
//
// All modules are safe to call (each checks for admin rights internally).
// Destructive actions (clean, repair, delete) log before executing.
// ─────────────────────────────────────────────────────────────────────────────

using System.Text.Json;
using Microsoft.Extensions.Logging;
using LogicFlow.Guardian;
using OmniCore.Engine;

namespace LogicFlow.VoiceAgent;

/// <summary>
/// Registers and dispatches all LogicFlow AI function tools.
/// Every method here corresponds to a FunctionDeclaration sent in the Gemini setup message.
/// </summary>
public sealed class LogicFlowFunctionDispatcher
{
    private readonly ILogger<LogicFlowFunctionDispatcher> _log;

    // Module references
    private readonly JunkCleanerEngine _junkCleaner;
    private readonly SystemInfoEngine _systemInfo;
    private readonly TurboMode _turboMode = new();

    public TurboMode TurboEngine => _turboMode;
    public Func<string, JunkCleanerEngine.CleanResult>? CustomCleanHandler { get; set; }

    /// <summary>
    /// Optional edition gate check invoked before mutating tools execute in interactive sessions.
    /// Receives (toolName, args) and returns (Allowed, DenialMessage).
    /// </summary>
    public Func<string, JsonElement, (bool Allowed, string? DenialMessage)>? FeatureGateValidator { get; set; }

    /// <summary>
    /// Optional user confirmation callback invoked before mutating tools (junk_clean, network_optimize, game_mode_toggle) execute.
    /// </summary>
    public Func<string, JsonElement, Task<bool>>? ConfirmMutatingToolAsync { get; set; }

    /// <summary>
    /// Current edition label reported by logicflow_version.
    /// </summary>
    public string ActiveEditionName { get; set; } = "Community";

    public static bool IsMutatingTool(string toolName) =>
        toolName is "junk_clean" or "network_optimize" or "game_mode_toggle";

    public LogicFlowFunctionDispatcher(
        ILogger<LogicFlowFunctionDispatcher> log,
        JunkCleanerEngine junkCleaner,
        SystemInfoEngine systemInfo)
    {
        _log = log;
        _junkCleaner = junkCleaner;
        _systemInfo = systemInfo;
    }

    // ── Function declarations to send to Gemini Live API / Gemma 4 E2B ────
    // These are injected into the LiveSetup or Gemma tool schema so the model knows what tools it has.

    public static List<FunctionDeclaration> GetDeclarations() =>
    [
        new FunctionDeclaration
        {
            Name = "junk_scan",
            Description = "Scans the system for junk files (temp files, browser caches, Windows update leftovers, recycle bin) and returns the total bytes recoverable without cleaning yet.",
        },
        new FunctionDeclaration
        {
            Name = "junk_clean",
            Description = "Cleans junk files from the system. Only call this after confirming with the user. Returns bytes freed.",
            Parameters = new FunctionParameters
            {
                Properties = new()
                {
                    ["scope"] = new ParameterProperty
                    {
                        Type = "string",
                        Description = "Cleaning scope",
                        Enum = ["temp_only", "browser_only", "full"],
                    }
                },
                Required = ["scope"]
            }
        },
        new FunctionDeclaration
        {
            Name = "system_overview",
            Description = "Returns a comprehensive snapshot of the system: CPU model, RAM total/available, disk health, OS version, uptime, and temperature if available. Best for answering 'what are my specs' or 'how is my system doing'.",
        },
        new FunctionDeclaration
        {
            Name = "disk_health",
            Description = "Checks SMART health data for all physical drives. Returns health score, model, and any warning attributes.",
        },
        new FunctionDeclaration
        {
            Name = "memory_status",
            Description = "Returns current RAM usage, total RAM, pagefile usage, and whether memory pressure is high.",
        },
        new FunctionDeclaration
        {
            Name = "startup_analysis",
            Description = "Lists all startup programs with their performance impact score (1-10, higher = slower boot). Identifies which to disable.",
        },
        new FunctionDeclaration
        {
            Name = "driver_scan",
            Description = "Scans all installed drivers and identifies outdated, missing, or problematic ones.",
        },
        new FunctionDeclaration
        {
            Name = "network_optimize",
            Description = "Flushes DNS cache, resets Winsock catalog, and tunes TCP auto-tuning for maximum network speed.",
        },
        new FunctionDeclaration
        {
            Name = "game_mode_toggle",
            Description = "Activates or deactivates High-Performance Turbo Mode (Gaming, Streaming, Rendering, Benchmarking, Minimum, Work, Battery, Server, or Smart) to optimize CPU/GPU priority, power plan, and RAM.",
            Parameters = new FunctionParameters
            {
                Properties = new()
                {
                    ["enable"] = new ParameterProperty
                    {
                        Type = "boolean",
                        Description = "True to activate Turbo Mode, False to deactivate."
                    },
                    ["profile"] = new ParameterProperty
                    {
                        Type = "string",
                        Description = "Optional Turbo Mode profile name when enabling.",
                        Enum = ["Gaming", "Streaming", "Rendering", "Benchmarking", "Minimum", "Work", "Battery", "Server", "Smart"]
                    }
                },
                Required = ["enable"]
            }
        },
        new FunctionDeclaration
        {
            Name = "cpu_speed",
            Description = "Returns the processor model, clock speed in GHz, core count, thread count, and current CPU utilization percentage.",
        },
        new FunctionDeclaration
        {
            Name = "gpu_info",
            Description = "Returns dedicated GPU details including graphics adapter model, driver version, and video memory (VRAM).",
        },
        new FunctionDeclaration
        {
            Name = "logicflow_version",
            Description = "Returns the current LogicFlow version, edition (Community/Pro/Enterprise), and license status.",
        },
    ];

    public static IReadOnlyList<GemmaToolDefinition> GetGemmaToolDefinitions()
    {
        var list = new List<GemmaToolDefinition>();
        foreach (var decl in GetDeclarations())
        {
            object schema;
            if (decl.Parameters != null)
            {
                var props = new Dictionary<string, object>();
                foreach (var kv in decl.Parameters.Properties)
                {
                    if (kv.Value.Enum is { Count: > 0 })
                    {
                        props[kv.Key] = new { type = kv.Value.Type, description = kv.Value.Description, @enum = kv.Value.Enum };
                    }
                    else
                    {
                        props[kv.Key] = new { type = kv.Value.Type, description = kv.Value.Description };
                    }
                }
                schema = new
                {
                    type = "object",
                    properties = props,
                    required = decl.Parameters.Required ?? new List<string>()
                };
            }
            else
            {
                schema = new { type = "object", properties = new Dictionary<string, object>() };
            }

            list.Add(new GemmaToolDefinition
            {
                Name = decl.Name,
                Description = decl.Description,
                ParametersSchema = schema
            });
        }
        return list;
    }

    public static List<JunkCleanerEngine.JunkScanResult> FilterScanResultsByScope(
        List<JunkCleanerEngine.JunkScanResult> scanResults,
        string? scope)
    {
        var normalized = string.IsNullOrWhiteSpace(scope) ? "full" : scope.Trim().ToLowerInvariant();
        foreach (var item in scanResults)
        {
            item.IsSelected = normalized switch
            {
                "temp_only" => item.Category is JunkCleanerEngine.JunkCategory.WindowsTemp
                    or JunkCleanerEngine.JunkCategory.UserTemp
                    or JunkCleanerEngine.JunkCategory.InstallerCache,
                "browser_only" => item.Category == JunkCleanerEngine.JunkCategory.BrowserCache,
                _ => item.IsSafeCategory
            };
        }
        return scanResults;
    }

    // ── Dispatch incoming function calls ──────────────────────────────────

    public async Task<object> DispatchAsync(FunctionCall call)
    {
        _log.LogInformation("[VoiceAgent] Dispatching: {Name} args={Args}", call.Name, call.Args);

        if (IsMutatingTool(call.Name))
        {
            if (FeatureGateValidator != null)
            {
                var (allowed, denialMsg) = FeatureGateValidator(call.Name, call.Args);
                if (!allowed)
                {
                    string msg = !string.IsNullOrWhiteSpace(denialMsg)
                        ? denialMsg!
                        : $"'{call.Name}' requires LogicFlow Community ($0) or Pro edition.";
                    _log.LogInformation("[VoiceAgent] Blocked gated tool {Name}: {Reason}", call.Name, msg);
                    return new
                    {
                        cancelled = true,
                        gated = true,
                        error = msg,
                        summary = msg
                    };
                }
            }

            if (ConfirmMutatingToolAsync != null)
            {
                bool confirmed = await ConfirmMutatingToolAsync(call.Name, call.Args).ConfigureAwait(false);
                if (!confirmed)
                {
                    string cancelMsg = $"Cancelled '{call.Name}' — action was declined by the user.";
                    _log.LogInformation("[VoiceAgent] User declined mutating tool {Name}", call.Name);
                    return new
                    {
                        cancelled = true,
                        summary = cancelMsg
                    };
                }
            }
        }

        return call.Name switch
        {
            "junk_scan"       => await JunkScanAsync(),
            "junk_clean"      => await JunkCleanAsync(call.Args),
            "system_overview" => await SystemOverviewAsync(),
            "cpu_speed"       => await CpuSpeedAsync(),
            "gpu_info"        => await GpuInfoAsync(),
            "disk_health"     => await DiskHealthAsync(),
            "memory_status"   => await MemoryStatusAsync(),
            "startup_analysis"=> await StartupAnalysisAsync(),
            "driver_scan"     => await DriverScanAsync(),
            "network_optimize"=> await NetworkOptimizeAsync(),
            "game_mode_toggle"=> await GameModeToggleAsync(call.Args),
            "logicflow_version"=> GetVersion(),
            _ => new { error = $"Unknown function: {call.Name}" }
        };
    }

    // ── Individual function implementations ───────────────────────────────

    private async Task<object> JunkScanAsync()
    {
        try
        {
            var result = await Task.Run(() => _junkCleaner.Scan());
            var totalBytes = result.Sum(r => r.TotalBytes);
            return new
            {
                total_bytes    = totalBytes,
                total_gb       = Math.Round(totalBytes / 1_073_741_824.0, 2),
                file_count     = result.Sum(r => r.FileCount),
                categories     = result.Select(r => new
                {
                    name   = r.Category,
                    bytes  = r.TotalBytes,
                    files  = r.FileCount,
                }).ToArray(),
                summary = $"Found {Math.Round(totalBytes / 1_073_741_824.0, 1)} GB of junk in {result.Sum(r => r.FileCount)} files."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] junk_scan failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> JunkCleanAsync(JsonElement args)
    {
        var scope = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("scope", out var s)
            ? (s.GetString() ?? "full")
            : "full";
        var normalizedScope = scope.Trim().ToLowerInvariant();
        _log.LogWarning("[VoiceAgent] Executing junk CLEAN with scope={Scope}", normalizedScope);

        try
        {
            JunkCleanerEngine.CleanResult result;
            if (CustomCleanHandler != null)
            {
                result = CustomCleanHandler(normalizedScope);
            }
            else if (normalizedScope is "temp_only" or "browser_only")
            {
                result = await Task.Run(() =>
                {
                    var scanned = _junkCleaner.Scan();
                    FilterScanResultsByScope(scanned, normalizedScope);
                    return _junkCleaner.Clean(scanned);
                });
            }
            else
            {
                result = await Task.Run(() => _junkCleaner.QuickClean());
            }

            return new
            {
                scope = normalizedScope,
                bytes_freed = result.BytesCleaned,
                gb_freed    = Math.Round(result.BytesCleaned / 1_073_741_824.0, 2),
                files_deleted = result.FilesDeleted,
                summary = $"Cleaned {Math.Round(result.BytesCleaned / 1_073_741_824.0, 1)} GB " +
                          $"({result.FilesDeleted} files, scope: {normalizedScope})."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] junk_clean failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> SystemOverviewAsync()
    {
        try
        {
            var info = await Task.Run(() => _systemInfo.CollectSnapshot());
            return new
            {
                cpu_name      = info.CpuName,
                cpu_cores     = info.CpuCores,
                cpu_load_pct  = info.CpuUsagePercent,
                ram_total_gb  = Math.Round(info.TotalRamBytes / 1_073_741_824.0, 1),
                ram_free_gb   = Math.Round(info.AvailableRamBytes / 1_073_741_824.0, 1),
                os_name       = info.OsName,
                os_build      = info.OsBuild,
                uptime_hours  = Math.Round(info.Uptime.TotalSeconds / 3600.0, 1),
                temperature_c = info.CpuTempCelsius,
                summary = $"{info.CpuName}, {Math.Round(info.TotalRamBytes / 1_073_741_824.0, 0)}GB RAM, " +
                          $"{info.OsName}, up {Math.Round(info.Uptime.TotalSeconds / 3600.0, 0)} hours."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] system_overview failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> DiskHealthAsync()
    {
        try
        {
            var diskHealth = new SmartDiskHealth();
            var drives = await Task.Run(() => diskHealth.ScanDrives());
            int healthy = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Healthy);
            int warning = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Warning);
            int critical = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Critical);

            return new
            {
                status = critical > 0 ? "critical" : (warning > 0 ? "warning" : "healthy"),
                total_drives = drives.Count,
                healthy_count = healthy,
                warning_count = warning,
                critical_count = critical,
                drives = drives.Select(d => new
                {
                    model = d.Model,
                    letter = d.DriveLetter,
                    health_score = d.HealthScore,
                    grade = d.HealthGrade,
                    status = d.Status.ToString(),
                    temperature_c = d.Temperature,
                    size = d.SizeFormatted
                }).ToArray(),
                summary = drives.Count == 0
                    ? "No physical drives detected."
                    : $"Scanned {drives.Count} drive(s): {healthy} healthy, {warning} warning, {critical} critical."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] disk_health failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> MemoryStatusAsync()
    {
        try
        {
            var info = await Task.Run(() => _systemInfo.CollectSnapshot());
            var totalMb = Math.Round(info.TotalRamBytes / (1024.0 * 1024.0), 0);
            var usedMb = Math.Round((info.TotalRamBytes - info.AvailableRamBytes) / (1024.0 * 1024.0), 0);
            return new
            {
                total_mb = totalMb,
                used_mb = usedMb,
                available_mb = Math.Round(info.AvailableRamBytes / (1024.0 * 1024.0), 0),
                pressure = info.RamUsagePercent,
                summary = $"RAM: {info.UsedRamFormatted} used of {info.TotalRamFormatted} total ({info.RamUsagePercent}%)."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] memory_status failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> StartupAnalysisAsync()
    {
        try
        {
            var optimizer = new StartupOptimizer(Microsoft.Extensions.Logging.Abstractions.NullLogger<StartupOptimizer>.Instance);
            var items = await Task.Run(() => optimizer.AnalyzeStartupItems());
            var highImpact = items.Where(i => i.ImpactScore >= 7).ToList();

            return new
            {
                total_items = items.Count,
                high_impact_count = highImpact.Count,
                items = items.Select(i => new
                {
                    name = i.Name,
                    command = i.Command,
                    impact = i.ImpactScore,
                    source = i.Source
                }).ToArray(),
                summary = $"Found {items.Count} startup programs ({highImpact.Count} high-impact on boot times)."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] startup_analysis failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> DriverScanAsync()
    {
        try
        {
            var auditor = new DriverAuditorEngine();
            var report = await Task.Run(() => auditor.AuditDrivers());
            return new
            {
                total_drivers  = report.TotalDrivers,
                unsigned       = report.UnsignedCount,
                problem_devices = report.ProblemDeviceCount,
                summary        = $"Scanned {report.TotalDrivers} drivers. Found {report.ProblemDeviceCount} problem devices and {report.UnsignedCount} unsigned drivers."
            };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private async Task<object> NetworkOptimizeAsync()
    {
        try
        {
            var optimizer = new NetworkOptimizerEngine();
            var result = await Task.Run(() => optimizer.OptimizeNetwork());
            return new
            {
                dns_flushed = result.DnsFlushed,
                winsock_reset = result.WinsockReset,
                tcp_autotuning = result.TcpAutoTuningApplied,
                summary = "Network optimization complete: DNS cache flushed, Winsock catalog reset, and TCP window auto-tuning set."
            };
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private async Task<object> GameModeToggleAsync(JsonElement args)
    {
        try
        {
            bool enable = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("enable", out var e) &&
                (e.ValueKind == JsonValueKind.True || (e.ValueKind == JsonValueKind.String && bool.TryParse(e.GetString(), out var b) && b));
            string? profileName = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("profile", out var p)
                ? p.GetString()
                : null;

            if (enable)
            {
                TurboMode.TurboProfile profile;
                string? smartRationale = null;
                if (string.Equals(profileName, "Smart", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(profileName, "auto", StringComparison.OrdinalIgnoreCase))
                {
                    var rec = await _turboMode.RecommendSmartProfileAsync();
                    profile = rec.Profile;
                    smartRationale = rec.Rationale;
                }
                else
                {
                    profile = TurboMode.GetProfileByName(profileName);
                }

                var result = await Task.Run(() => _turboMode.Activate(profile));
                return new
                {
                    active = _turboMode.IsActive,
                    activated = result.Activated,
                    profile = profile.Name,
                    smart_rationale = smartRationale,
                    services_paused = result.ServicesDisabled,
                    processes_stopped = result.ProcessesKilled,
                    memory_freed = result.MemoryFreedFormatted,
                    actions = result.Actions,
                    summary = $"{profile.Name} activated ({result.ServicesDisabled} services stopped, {result.ProcessesKilled} processes stopped, {result.MemoryFreedFormatted} RAM freed)."
                };
            }
            else
            {
                var result = await Task.Run(() => _turboMode.Deactivate());
                return new
                {
                    active = _turboMode.IsActive,
                    actions = result.Actions,
                    summary = "Turbo Mode deactivated. Normal system power scheme and background services restored."
                };
            }
        }
        catch (Exception ex)
        {
            return new { error = ex.Message };
        }
    }

    private async Task<object> CpuSpeedAsync()
    {
        try
        {
            var info = await Task.Run(() => _systemInfo.CollectSnapshot());
            return new
            {
                cpu_name = info.CpuName,
                clock_speed_ghz = info.CpuSpeedGHz,
                base_speed_ghz = info.CpuSpeedGHz,
                cores = info.CpuCores,
                threads = info.CpuThreads,
                usage_percent = info.CpuUsagePercent,
                temperature_c = info.CpuTempCelsius,
                summary = $"{info.CpuName} ({info.CpuCores} Cores, {info.CpuThreads} Threads) running at {info.CpuSpeedGHz:F2} GHz (Base Speed: {info.CpuSpeedGHz:F2} GHz), load: {info.CpuUsagePercent:F0}%."
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] cpu_speed failed");
            return new { error = ex.Message };
        }
    }

    private async Task<object> GpuInfoAsync()
    {
        try
        {
            var info = await Task.Run(() => _systemInfo.CollectSnapshot());
            return new
            {
                gpu_name = info.GpuName,
                driver_version = info.GpuDriverVersion,
                vram = info.GpuVramFormatted,
                summary = string.IsNullOrWhiteSpace(info.GpuName)
                    ? "No dedicated GPU detected or integrated graphics active."
                    : $"{info.GpuName} (VRAM: {info.GpuVramFormatted}, Driver: {info.GpuDriverVersion})"
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceAgent] gpu_info failed");
            return new { error = ex.Message };
        }
    }

    private object GetVersion() => new
    {
        version = "1.0.0",
        edition = ActiveEditionName,
        build   = "logicflow-v1.0",
        summary = $"LogicFlow 1.0.0 {ActiveEditionName} Edition."
    };
}
