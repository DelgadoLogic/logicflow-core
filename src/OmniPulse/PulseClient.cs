// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — PulseClient
// Consent-gated, offline-queued, batched telemetry client (API schema 1).
//
//  • Nothing is queued or sent unless ConsentStore.EffectiveLevel() allows it.
//  • Events are scrubbed, wrapped in an envelope and appended to a local JSONL queue.
//  • Flush sends gzip'd NDJSON, signed with HMAC-SHA256 (lowercase hex of the raw body).
//  • A reply only counts as success when it is JSON {"accepted":N,...} — an HTML 200 is a failure.
//  • Failures back off exponentially (persisted, capped at 24 h); a kill signal disables sending.
// ─────────────────────────────────────────────────────────────────────────────

using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>Construction options for <see cref="PulseClient"/> (all but <see cref="Consent"/> optional).</summary>
public sealed class PulseClientOptions
{
    public required ConsentStore Consent { get; init; }
    public string AppVersion { get; init; } = "1.0.0";
    public string ApiBase { get; init; } = PulseClient.DefaultApiBase;
    /// <summary>Returns free | community | pro for the envelope's tier field.</summary>
    public Func<string>? TierProvider { get; init; }
    /// <summary>Test seam for the HTTP stack.</summary>
    public HttpMessageHandler? Handler { get; init; }
    public Func<DateTimeOffset>? Clock { get; init; }
    /// <summary>Public per-build ingest key used for the HMAC (not a secret). Defaults to assembly metadata.</summary>
    public string? IngestKey { get; init; }
    public ILogger<PulseClient>? Logger { get; init; }
}

/// <summary>Privacy-first telemetry client for LogicFlow.</summary>
public sealed class PulseClient : IDisposable
{
    public const string DefaultApiBase = "https://api.delgadologic.tech/v1/telemetry";

    private const long MaxQueueBytes = 512 * 1024;
    private const int MaxBatchEvents = 100;
    private const int MaxBatchBytes = 256 * 1024;
    private const long MaxBaselineBytes = 2 * 1024 * 1024;
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromHours(24);
    private static readonly TimeSpan KillDuration = TimeSpan.FromDays(30);
    private static readonly TimeSpan HealthDigestInterval = TimeSpan.FromDays(7);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly PulseClientOptions _opt;
    private readonly ConsentStore _consent;
    private readonly ILogger<PulseClient>? _log;
    private readonly HttpClient _http;
    private readonly SystemFingerprint _fingerprint;
    private readonly byte[] _hmacKey;
    private readonly string _queueFile;
    private readonly string _statePath;
    private readonly string _configCachePath;
    private readonly object _queueLock = new();
    private readonly SemaphoreSlim _flushGate = new(1, 1);
    private Timer? _timer;

    public PulseClient(PulseClientOptions options)
    {
        _opt = options ?? throw new ArgumentNullException(nameof(options));
        _consent = options.Consent;
        _log = options.Logger;
        _fingerprint = new SystemFingerprint(installIdProvider: _consent.GetInstallId);
        _hmacKey = Encoding.UTF8.GetBytes(options.IngestKey ?? ReadIngestKey());

        System.IO.Directory.CreateDirectory(_consent.Directory);
        _queueFile = Path.Combine(_consent.Directory, "event_queue.jsonl");
        _statePath = Path.Combine(_consent.Directory, "pulse_state.json");
        _configCachePath = Path.Combine(_consent.Directory, "config_cache.json");
        BaselineLocalCopyPath = Path.Combine(_consent.Directory, "system_baseline.json");

        _http = options.Handler is not null
            ? new HttpClient(options.Handler, disposeHandler: false)
            : new HttpClient(new HttpClientHandler
            {
                UseProxy = true,
                DefaultProxyCredentials = CredentialCache.DefaultCredentials,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            });
        _http.Timeout = TimeSpan.FromSeconds(30);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"LogicFlow-Pulse/{options.AppVersion}");
    }

    /// <summary>Local, human-readable copy of the last captured baseline.</summary>
    public string BaselineLocalCopyPath { get; }

    private DateTimeOffset Now => _opt.Clock?.Invoke() ?? DateTimeOffset.UtcNow;

    /// <summary>The level allowed right now (None when undecided, Free, declined, policy-disabled or kill-switched).</summary>
    public ConsentLevel Level => _consent.EffectiveLevel(Now);

    // ─── Lifecycle ──────────────────────────────────────────────────────

    /// <summary>Flushes shortly after start (to send crashes from the last run) and then hourly.</summary>
    public void StartAutoFlush()
    {
        _timer?.Dispose();
        _timer = new Timer(async _ =>
        {
            try { await FlushAsync().ConfigureAwait(false); }
            catch (Exception ex) { _log?.LogDebug(ex, "Pulse auto-flush failed"); }
        }, null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _http.Dispose();
        _flushGate.Dispose();
    }

    // ─── Tracking ───────────────────────────────────────────────────────

    /// <summary>Queues a crash. Message and stack are scrubbed to schema v1 payload.crash fields.</summary>
    public void TrackCrash(Exception ex) => Enqueue("crash", ConsentLevel.Standard, ToElement(TelemetryScrubber.BuildCrashPayload(ex)));

    /// <summary>Queues a crash from raw text (used by the crash guard, which already has the report).</summary>
    public void TrackCrash(string exceptionType, string? message, string? stackTrace)
        => Enqueue("crash", ConsentLevel.Standard, ToElement(TelemetryScrubber.BuildCrashPayload(exceptionType, message, stackTrace)));

    /// <summary>Queues a non-fatal engine error matching schema v1 payload.error.</summary>
    public void TrackError(string engineName, string methodName, Exception ex, string? context = null)
        => Enqueue("error", ConsentLevel.Standard,
            ToElement(TelemetryScrubber.BuildErrorPayload(engineName, methodName, ex, context)));

    /// <summary>Queues a telemetry event mapped to schema v1 payload structures. Unknown names are dropped.</summary>
    public void Track(string eventType, object payload)
    {
        var (type, min) = Classify(eventType);
        if (type is null || payload is null) return;

        var element = BuildSchemaPayload(eventType, type, payload);
        if (element is null) return;

        Enqueue(type, min, element.Value);
    }

    public void TrackFeature(string featureName)
        => Enqueue("usage", ConsentLevel.Standard, ScrubElement(ToElement(new UsagePayload
        {
            Feature = TelemetryScrubber.Truncate(TelemetryScrubber.ScrubText(featureName), 64, "unknown"),
            Action = "invoke",
            Count = 1
        })));

    public void TrackOptimization(string toolName, bool succeeded, long durationMs, Dictionary<string, string>? metrics = null)
    {
        List<TelemetryProp>? props = null;
        if (metrics is { Count: > 0 })
        {
            props = metrics.Take(16)
                .Select(kv => new TelemetryProp
                {
                    Key = TelemetryScrubber.Truncate(TelemetryScrubber.ScrubText(kv.Key, maskTokens: false), 32, "k"),
                    Value = TelemetryScrubber.Truncate(TelemetryScrubber.ScrubText(kv.Value), 64)
                })
                .ToList();
        }
        Enqueue("usage", ConsentLevel.Standard, ScrubElement(ToElement(new UsagePayload
        {
            Feature = TelemetryScrubber.Truncate(TelemetryScrubber.ScrubText(toolName), 64, "tool"),
            Action = succeeded ? "optimize_ok" : "optimize_fail",
            DurationMs = Math.Max(0, durationMs),
            Count = 1,
            Props = props
        })));
    }

    public void TrackDriverScan(DriverFingerprint fingerprint) => Track("driver_scan", fingerprint);
    public void TrackAiRecommendationFeedback(AiRecommendationFeedback feedback) => Track("ai_recommendation_feedback", feedback);
    public void TrackTweakFeedback(TweakFeedback feedback) => Track("tweak_feedback", feedback);
    public void TrackScanPerformance(ScanPerformanceEvent scanEvent) => Track("scan_performance", scanEvent);
    public void TrackSessionFlow(SessionFlow flow) => Track("session_flow", flow);

    /// <summary>Maps a legacy event name to (envelope type, minimum consent level). Type is null when unsupported.</summary>
    internal static (string? Type, ConsentLevel Min) Classify(string eventType) => eventType switch
    {
        "crash" => ("crash", ConsentLevel.Standard),
        "error" or "engine_error" => ("error", ConsentLevel.Standard),
        "feature_usage" or "optimization" or "session_flow" or "tweak_feedback" or "ai_recommendation_feedback" or "usage"
            => ("usage", ConsentLevel.Standard),
        "scan_performance" or "scan" => ("scan", ConsentLevel.Standard),
        "driver_scan" or "system_health" => ("scan", ConsentLevel.Extended),
        "baseline" => ("baseline", ConsentLevel.Extended),
        _ => (null, ConsentLevel.None)
    };

    private static JsonElement? BuildSchemaPayload(string eventType, string type, object payload)
    {
        switch (type)
        {
            case "crash":
                if (payload is CrashPayload cp) return ToElement(cp);
                if (payload is Exception ex) return ToElement(TelemetryScrubber.BuildCrashPayload(ex));
                return null;

            case "error":
                if (payload is ErrorPayload ep) return ToElement(ep);
                if (payload is CrashPayload cpErr)
                {
                    return ToElement(new ErrorPayload
                    {
                        Code = TelemetryScrubber.Truncate(cpErr.ExceptionType, 64, "Error"),
                        Component = TelemetryScrubber.Truncate(cpErr.Module, 64, "unknown"),
                        Severity = "error",
                        Message = cpErr.Message,
                        HResult = cpErr.HResult,
                        Frames = cpErr.Frames
                    });
                }
                if (payload is Exception errEx) return ToElement(TelemetryScrubber.BuildErrorPayload("LogicFlow", eventType, errEx));
                return null;

            case "usage":
                if (payload is UsagePayload up) return ScrubElement(ToElement(up));
                if (payload is AiRecommendationFeedback af)
                {
                    return ScrubElement(ToElement(new UsagePayload
                    {
                        Feature = "assistant",
                        Action = TelemetryScrubber.Truncate(af.UserAction, 64, "feedback"),
                        Count = 1,
                        Props = new List<TelemetryProp>
                        {
                            new() { Key = "rec_id", Value = TelemetryScrubber.Truncate(af.RecommendationId, 64) },
                            new() { Key = "severity", Value = TelemetryScrubber.Truncate(af.Severity, 64) }
                        }
                    }));
                }
                if (payload is TweakFeedback tf)
                {
                    var revertMs = tf.TimeBeforeRevert is { TotalMilliseconds: > 0 } tbr ? (long?)tbr.TotalMilliseconds : null;
                    return ScrubElement(ToElement(new UsagePayload
                    {
                        Feature = TelemetryScrubber.Truncate(tf.TweakId, 64, "tweak"),
                        Action = TelemetryScrubber.Truncate(tf.Action, 64, "apply"),
                        DurationMs = revertMs,
                        Count = 1
                    }));
                }
                if (payload is SessionFlow sf)
                {
                    return ScrubElement(ToElement(new UsagePayload
                    {
                        Feature = "session",
                        Action = "complete",
                        DurationMs = Math.Max(0, (long)sf.SessionDuration.TotalMilliseconds),
                        Count = Math.Max(1, sf.TotalClicks)
                    }));
                }
                return BuildGenericUsageElement(eventType, payload);

            case "scan":
                if (payload is ScanPayload sp) return ScrubElement(ToElement(sp));
                if (payload is ScanPerformanceEvent spe)
                {
                    var name = TelemetryScrubber.Truncate(spe.EngineName, 64, "scan");
                    return ScrubElement(ToElement(new ScanPayload
                    {
                        ScanType = TelemetryScrubber.Truncate(spe.OperationType, 64, name),
                        DurationMs = Math.Max(0, spe.DurationMs),
                        ItemsFound = Math.Max(0, spe.ItemsProcessed),
                        ModulesRun = new List<string> { name }
                    }));
                }
                if (payload is DriverFingerprint df)
                {
                    var issues = df.KeyDrivers
                        .Take(100)
                        .Select(k => new ScanIssueCount
                        {
                            Id = TelemetryScrubber.Truncate($"{k.Provider}:{k.Class}:{k.Version}", 64, "driver"),
                            Count = k.Signed ? 0 : 1
                        })
                        .ToList();
                    return ScrubElement(ToElement(new ScanPayload
                    {
                        ScanType = "driver_scan",
                        ItemsFound = Math.Max(0, df.TotalDriverCount),
                        ModulesRun = new List<string> { "driver_index" },
                        Issues = issues.Count > 0 ? issues : null
                    }));
                }
                if (payload is SystemHealthDigest shd)
                {
                    var s = shd.StabilityScore;
                    var issues = Math.Max(0, s.ApplicationFailures + s.HardwareFailures + s.WindowsFailures + s.MiscFailures);
                    var score = Math.Clamp((int)Math.Round(s.StabilityIndex * 10.0), 0, 100);
                    return ScrubElement(ToElement(new ScanPayload
                    {
                        ScanType = "system_health",
                        ItemsFound = issues,
                        HealthScore = score
                    }));
                }
                return ScrubElement(ToElement(new ScanPayload
                {
                    ScanType = TelemetryScrubber.Truncate(eventType, 64, "scan")
                }));

            case "baseline":
                if (payload is BaselinePayload bp) return ScrubElement(ToElement(bp));
                if (payload is SystemBaseline sb) return ScrubElement(ToElement(MapBaselineToSchemaPayload(sb)));
                return null;

            default:
                return null;
        }
    }

    private static JsonElement BuildGenericUsageElement(string eventType, object payload)
    {
        var raw = ScrubElement(ToElement(payload));
        var feature = eventType;
        var action = "invoke";
        long? durationMs = null;
        long? count = 1;
        var props = new List<TelemetryProp>();

        if (raw.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in raw.EnumerateObject())
            {
                if (p.NameEquals("feature") || p.NameEquals("toolName"))
                {
                    if (p.Value.ValueKind == JsonValueKind.String && p.Value.GetString() is { Length: > 0 } f)
                        feature = f;
                }
                else if (p.NameEquals("action"))
                {
                    if (p.Value.ValueKind == JsonValueKind.String && p.Value.GetString() is { Length: > 0 } a)
                        action = a;
                }
                else if (p.NameEquals("succeeded") && (p.Value.ValueKind is JsonValueKind.True or JsonValueKind.False))
                {
                    action = p.Value.GetBoolean() ? "optimize_ok" : "optimize_fail";
                }
                else if (p.NameEquals("durationMs") && p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt64(out var d))
                {
                    durationMs = Math.Max(0, d);
                }
                else if (p.NameEquals("count") && p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt64(out var c))
                {
                    count = Math.Max(0, c);
                }
                else if (props.Count < 16)
                {
                    var valStr = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText();
                    props.Add(new TelemetryProp
                    {
                        Key = TelemetryScrubber.Truncate(p.Name, 32, "k"),
                        Value = TelemetryScrubber.Truncate(valStr, 64)
                    });
                }
            }
        }

        return ToElement(new UsagePayload
        {
            Feature = TelemetryScrubber.Truncate(feature, 64, "feature"),
            Action = TelemetryScrubber.Truncate(action, 64, "invoke"),
            DurationMs = durationMs,
            Count = count,
            Props = props.Count > 0 ? props : null
        });
    }

    internal static BaselinePayload MapBaselineToSchemaPayload(SystemBaseline baseline)
    {
        var sys = baseline.System ?? new SystemProfile();
        var bios = baseline.Bios ?? new BiosInfo();
        var diskTypeRaw = (sys.DiskType ?? "").Trim().ToLowerInvariant();
        var diskType = diskTypeRaw is "nvme" or "ssd" or "hdd" or "usb" ? diskTypeRaw : "other";

        var gpus = new List<BaselineGpu>();
        if (!string.IsNullOrWhiteSpace(sys.GpuName))
        {
            gpus.Add(new BaselineGpu
            {
                Name = TelemetryScrubber.Truncate(sys.GpuName, 128)
            });
        }

        var drivers = baseline.ProblemDevices
            .Take(200)
            .Select(d =>
            {
                // Keep only class prefix of hardware ID (e.g. PCI\VEN_10DE&DEV_2684), never device instance serial
                var parts = (d.HardwareId ?? "").Split('\\', StringSplitOptions.RemoveEmptyEntries);
                var hwidClass = parts.Length >= 2 ? $"{parts[0]}\\{parts[1]}" : parts.FirstOrDefault() ?? "";
                return new BaselineDriver
                {
                    Class = TelemetryScrubber.Truncate(d.DeviceClass, 32),
                    Name = TelemetryScrubber.Truncate(d.Name, 128),
                    HwidClass = TelemetryScrubber.Truncate(hwidClass, 64)
                };
            })
            .ToList();

        var kbs = baseline.Hotfixes
            .Select(h => (h.HotfixId ?? "").Trim().ToUpperInvariant())
            .Where(id => System.Text.RegularExpressions.Regex.IsMatch(id, "^KB[0-9]{6,8}$"))
            .Distinct(StringComparer.Ordinal)
            .Take(500)
            .ToList();

        var sec = new List<string>();
        if (!string.IsNullOrWhiteSpace(sys.AntivirusProduct))
            sec.Add(TelemetryScrubber.Truncate(sys.AntivirusProduct, 64));

        return new BaselinePayload
        {
            Windows = new BaselineWindows
            {
                Edition = TelemetryScrubber.Truncate(sys.OsVersion, 64),
                DisplayVersion = TelemetryScrubber.Truncate(sys.OsBuild, 32),
                Ubr = Math.Max(0, Environment.OSVersion.Version.Revision)
            },
            Hardware = new BaselineHardware
            {
                CpuName = TelemetryScrubber.Truncate(sys.CpuName, 128),
                CpuCores = Math.Max(0, sys.CpuCores),
                RamGb = Math.Round(Math.Clamp(sys.RamTotalMB / 1024.0, 0, 100000), 2),
                Gpus = gpus.Count > 0 ? gpus : null,
                BiosVendor = TelemetryScrubber.Truncate(bios.Manufacturer, 64),
                BiosVersion = TelemetryScrubber.Truncate(bios.Version, 64),
                DiskTypes = new List<string> { diskType }
            },
            Drivers = drivers.Count > 0 ? drivers : null,
            Kbs = kbs.Count > 0 ? kbs : null,
            SecurityProducts = sec.Count > 0 ? sec : null,
            ServicesRunning = Math.Max(0, baseline.RunningServiceCount)
        };
    }

    // ─── Queue ──────────────────────────────────────────────────────────

    private void Enqueue(string type, ConsentLevel min, JsonElement payload)
    {
        var level = Level;
        if (level == ConsentLevel.None || level < min) return;

        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "x64"
        };
        var rawTier = (_opt.TierProvider?.Invoke() ?? "community").Trim().ToLowerInvariant();
        var tier = rawTier is "pro" or "community" or "free" ? rawTier : "community";

        var envelope = new TelemetryEnvelope
        {
            EventId = Guid.NewGuid().ToString("D"),
            Type = type,
            Ts = Now.UtcDateTime.ToString("o"),
            InstallId = _consent.GetInstallId(),
            AppVersion = _opt.AppVersion,
            OsBuild = Environment.OSVersion.Version.ToString(),
            Arch = arch,
            Tier = tier,
            Region = _consent.Current.Region.Label(),
            Payload = payload
        };

        lock (_queueLock)
        {
            try
            {
                TrimQueueLocked();
                File.AppendAllText(_queueFile, JsonSerializer.Serialize(envelope, Json) + "\n");
            }
            catch (Exception ex) { _log?.LogDebug(ex, "Failed to enqueue telemetry event"); }
        }
    }

    private void TrimQueueLocked()
    {
        if (!File.Exists(_queueFile) || new FileInfo(_queueFile).Length < MaxQueueBytes) return;

        var lines = File.ReadAllLines(_queueFile);
        File.WriteAllLines(_queueFile, lines.Skip(lines.Length / 2));   // drop the oldest half
    }

    private List<TelemetryEnvelope> ReadQueue()
    {
        var result = new List<TelemetryEnvelope>();
        lock (_queueLock)
        {
            if (!File.Exists(_queueFile)) return result;
            foreach (var line in File.ReadAllLines(_queueFile))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var env = JsonSerializer.Deserialize<TelemetryEnvelope>(line, Json);
                    if (env is { Schema: TelemetryEnvelope.SchemaVersion } && env.EventId.Length > 0 && env.Payload.ValueKind != JsonValueKind.Undefined)
                        result.Add(env);
                }
                catch (JsonException) { /* legacy or corrupt line — discard */ }
            }
        }
        return result;
    }

    private void WriteQueue(IEnumerable<TelemetryEnvelope> remaining)
    {
        lock (_queueLock)
        {
            try
            {
                var lines = remaining.Select(e => JsonSerializer.Serialize(e, Json)).ToList();
                if (lines.Count == 0) { if (File.Exists(_queueFile)) File.Delete(_queueFile); }
                else File.WriteAllLines(_queueFile, lines);
            }
            catch (Exception ex) { _log?.LogDebug(ex, "Failed to rewrite telemetry queue"); }
        }
    }

    /// <summary>Deletes every queued event (used on opt-out, kill-switch and "Delete my data").</summary>
    public void ClearQueue()
    {
        lock (_queueLock)
        {
            try { if (File.Exists(_queueFile)) File.Delete(_queueFile); }
            catch (Exception ex) { _log?.LogDebug(ex, "Failed to clear telemetry queue"); }
        }
    }

    internal int QueuedCount => ReadQueue().Count;

    private static bool AllowedAt(TelemetryEnvelope e, ConsentLevel level)
    {
        if (level == ConsentLevel.None) return false;
        if (level >= ConsentLevel.Extended) return true;
        if (e.Type == "baseline") return false;
        if (e.Type == "scan" && e.Payload.ValueKind == JsonValueKind.Object)
        {
            if (e.Payload.TryGetProperty("scanType", out var st) && st.ValueKind == JsonValueKind.String &&
                Classify(st.GetString() ?? "").Min > level) return false;
            if (e.Payload.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String &&
                Classify(k.GetString() ?? "").Min > level) return false;
        }
        return true;
    }

    // ─── Flush ──────────────────────────────────────────────────────────

    /// <summary>Sends queued events. Safe to call at any time; does nothing without consent or during back-off.</summary>
    public async Task FlushAsync(bool includeSysHealth = true)
    {
        await RetryPendingDeleteAsync().ConfigureAwait(false);

        var level = Level;
        if (level == ConsentLevel.None)
        {
            ClearQueue();   // strict consent: never keep data we are not allowed to send
            return;
        }

        if (!await _flushGate.WaitAsync(0).ConfigureAwait(false)) return;
        try
        {
            var state = LoadState();
            if (state.NextAttemptUtc is { } next && next > Now) return;

            if (includeSysHealth && level >= ConsentLevel.Extended &&
                (state.LastHealthDigestUtc is not { } last || Now - last >= HealthDigestInterval))
            {
                await QueueHealthDigestAsync(state).ConfigureAwait(false);
            }

            var pending = ReadQueue().Where(e => AllowedAt(e, level)).ToList();
            if (pending.Count == 0) { WriteQueue(pending); return; }

            var sent = new HashSet<string>();
            foreach (var group in BuildGroups(pending))
            {
                var outcome = await SendGroupAsync(group, level).ConfigureAwait(false);
                if (outcome == SendOutcome.Kill)
                {
                    _consent.SetKillSwitch(Now + KillDuration);
                    ClearQueue();
                    return;
                }
                if (outcome == SendOutcome.Retry)
                {
                    RegisterFailure(state);
                    break;
                }
                // Ok and Drop both remove the group from the queue (Drop = permanently rejected, retrying cannot help).
                foreach (var e in group.Events) sent.Add(e.EventId);
                if (outcome == SendOutcome.Ok) { state.Failures = 0; state.NextAttemptUtc = null; SaveState(state); }
            }

            WriteQueue(pending.Where(e => !sent.Contains(e.EventId)));
        }
        finally { _flushGate.Release(); }
    }

    private async Task QueueHealthDigestAsync(PulseState state)
    {
        try
        {
            var digest = await Task.Run(() => new HealthDigestAggregator().BuildDigest(daysBack: 7)).ConfigureAwait(false);
            Track("system_health", digest);
            state.LastHealthDigestUtc = Now;
            SaveState(state);
        }
        catch (Exception ex) { _log?.LogDebug(ex, "Pulse: system health collection failed (non-blocking)"); }
    }

    private sealed record Group(string Endpoint, List<TelemetryEnvelope> Events, bool Ndjson);

    private static IEnumerable<Group> BuildGroups(List<TelemetryEnvelope> events)
    {
        foreach (var e in events.Where(e => e.Type == "crash")) yield return new Group("crash", new() { e }, false);
        foreach (var e in events.Where(e => e.Type == "baseline")) yield return new Group("baseline", new() { e }, false);

        var batch = new List<TelemetryEnvelope>();
        var bytes = 0;
        foreach (var e in events.Where(e => e.Type is not ("crash" or "baseline")))
        {
            var size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(e, Json)) + 1;
            if (batch.Count > 0 && (batch.Count >= MaxBatchEvents || bytes + size > MaxBatchBytes))
            {
                yield return new Group("events", batch, true);
                batch = new List<TelemetryEnvelope>();
                bytes = 0;
            }
            batch.Add(e);
            bytes += size;
        }
        if (batch.Count > 0) yield return new Group("events", batch, true);
    }

    private enum SendOutcome { Ok, Retry, Drop, Kill }

    private async Task<SendOutcome> SendGroupAsync(Group group, ConsentLevel level)
    {
        var body = Encoding.UTF8.GetBytes(string.Join("\n", group.Events.Select(e => JsonSerializer.Serialize(e, Json))));
        var (status, text, kill) = await PostAsync(group.Endpoint, body, group.Ndjson ? "application/x-ndjson" : "application/json",
            group.Events[0].InstallId, level.ToString().ToLowerInvariant()).ConfigureAwait(false);

        if (kill || status == HttpStatusCode.Gone) return SendOutcome.Kill;
        if (status is null) return SendOutcome.Retry;

        var code = (int)status.Value;
        if (code is >= 200 and < 300)
        {
            if (!TryParseAccepted(text, out _, out var killBody)) return SendOutcome.Retry;   // HTML/garbage 200 ≠ success
            if (killBody) return SendOutcome.Kill;
            ProcessServerResponse(text);
            return SendOutcome.Ok;
        }
        if (code == 408 || code == 429 || code >= 500) return SendOutcome.Retry;
        return SendOutcome.Drop;   // other 4xx: the server will never accept this payload
    }

    private async Task<(HttpStatusCode? Status, string Text, bool Kill)> PostAsync(
        string endpoint, byte[] body, string contentType, string installId, string consentHeader)
    {
        try
        {
            using var gz = new MemoryStream();
            using (var z = new GZipStream(gz, CompressionLevel.Optimal, leaveOpen: true)) z.Write(body, 0, body.Length);

            var wire = gz.ToArray();
            using var req = new HttpRequestMessage(HttpMethod.Post, $"{_opt.ApiBase.TrimEnd('/')}/{endpoint}")
            {
                Content = new ByteArrayContent(wire)
            };
            req.Content.Headers.ContentType = new(contentType);
            req.Content.Headers.ContentEncoding.Add("gzip");
            req.Headers.Add("X-LF-Schema", TelemetryEnvelope.SchemaVersion.ToString());
            req.Headers.Add("X-LF-Install-Id", installId);
            req.Headers.Add("X-LF-Version", _opt.AppVersion);
            req.Headers.Add("X-LF-Consent", consentHeader);
            req.Headers.Add("X-LF-Sig", Sign(wire));   // server verifies the exact wire bytes before decompressing

            using var res = await _http.SendAsync(req).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            return (res.StatusCode, text, res.Headers.Contains("X-LF-Kill"));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException)
        {
            _log?.LogDebug(ex, "Pulse: request to {Endpoint} failed", endpoint);
            return (null, "", false);
        }
    }

    /// <summary>Lowercase hex HMAC-SHA256 of the request body exactly as sent on the wire (gzip bytes).</summary>
    internal string Sign(byte[] body) => Convert.ToHexString(HMACSHA256.HashData(_hmacKey, body)).ToLowerInvariant();

    /// <summary>True only for a JSON object with a non-negative integer "accepted" property and "schema": 1.</summary>
    internal static bool TryParseAccepted(string? body, out int accepted, out bool kill)
    {
        accepted = 0;
        kill = false;
        if (string.IsNullOrWhiteSpace(body)) return false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            if (!root.TryGetProperty("accepted", out var a) || a.ValueKind != JsonValueKind.Number || !a.TryGetInt32(out accepted) || accepted < 0)
                return false;
            if (!root.TryGetProperty("schema", out var s) || s.ValueKind != JsonValueKind.Number || !s.TryGetInt32(out var schema) || schema != TelemetryEnvelope.SchemaVersion)
                return false;
            kill = root.TryGetProperty("kill", out var k) && k.ValueKind == JsonValueKind.True;
            return true;
        }
        catch (JsonException) { return false; }
    }

    private void RegisterFailure(PulseState state)
    {
        state.Failures = Math.Min(state.Failures + 1, 30);
        var delay = TimeSpan.FromMinutes(Math.Pow(2, state.Failures - 1));
        if (delay > MaxBackoff) delay = MaxBackoff;
        state.NextAttemptUtc = Now + delay;
        SaveState(state);
    }

    // ─── Baseline (Extended only) ───────────────────────────────────────

    /// <summary>
    /// Captures and queues the one-time system baseline (services, BIOS/firmware, devices/drivers, KBs).
    /// Requires Extended consent; re-sent once after the install ID changes. Runs off the UI thread.
    /// </summary>
    public async Task<bool> SendBaselineAsync()
    {
        if (Level < ConsentLevel.Extended) return false;

        var installId = _consent.GetInstallId();
        var state = LoadState();
        if (string.Equals(state.BaselineSentFor, installId, StringComparison.Ordinal)) return false;

        try
        {
            var baseline = await Task.Run(() => _fingerprint.CaptureBaseline(_opt.AppVersion)).ConfigureAwait(false);
            var schemaBaseline = MapBaselineToSchemaPayload(baseline);
            var element = ScrubElement(ToElement(schemaBaseline));

            try   // readable local copy for "View what is sent"
            {
                File.WriteAllText(BaselineLocalCopyPath,
                    JsonSerializer.Serialize(element, new JsonSerializerOptions(Json) { WriteIndented = true }));
            }
            catch (Exception ex) { _log?.LogDebug(ex, "Failed to save baseline local copy"); }

            Enqueue("baseline", ConsentLevel.Extended, element);
            state.BaselineSentFor = installId;
            SaveState(state);
            await FlushAsync(includeSysHealth: false).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            _log?.LogWarning(ex, "Baseline capture failed — will retry on next launch");
            return false;
        }
    }

    // ─── User controls ──────────────────────────────────────────────────

    /// <summary>
    /// "Delete my data": wipes the local queue/baseline copy/state, retires the install ID and asks the server
    /// to delete everything held for it. If offline, the request is persisted and retried on later flushes.
    /// Returns true when the server confirmed (or there was nothing server-side to delete).
    /// </summary>
    public async Task<bool> DeleteMyDataAsync()
    {
        ClearQueue();
        TryDelete(BaselineLocalCopyPath);
        TryDelete(_statePath);
        TryDelete(_configCachePath);

        var old = _consent.ClearInstallId();
        if (old is null) return true;

        _consent.SetPendingDelete(old);
        return await RetryPendingDeleteAsync().ConfigureAwait(false);
    }

    private async Task<bool> RetryPendingDeleteAsync()
    {
        var pending = _consent.Current.PendingDeleteInstallId;
        if (string.IsNullOrEmpty(pending)) return true;

        var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { installId = pending }, Json));
        var consentHdr = Level == ConsentLevel.Extended ? "extended" : "standard";
        var (status, text, _) = await PostAsync("delete", body, "application/json", pending, consentHdr).ConfigureAwait(false);

        if (status is { } s && (int)s is >= 200 and < 300 && TryParseAccepted(text, out _, out _))
        {
            _consent.SetPendingDelete(null);
            return true;
        }
        _log?.LogDebug("Pulse: delete request not confirmed yet (status {Status}); will retry", status);
        return false;
    }

    /// <summary>Plain-text description of exactly what has been queued / would be sent at the current level.</summary>
    public string BuildPreview()
    {
        var level = Level;
        var sb = new StringBuilder();
        sb.AppendLine($"Telemetry level: {level}");
        sb.AppendLine($"Install ID (random, not hardware-derived): {(_consent.Current.InstallId is { Length: > 0 } id ? id : "(none)")}");
        sb.AppendLine($"Server: {_opt.ApiBase}");
        sb.AppendLine();

        if (level == ConsentLevel.None)
        {
            sb.AppendLine("Nothing is collected or sent.");
            return sb.ToString();
        }

        sb.AppendLine("Standard: crash/error reports (scrubbed message + code frames), feature usage, scan counts.");
        if (level >= ConsentLevel.Extended)
            sb.AppendLine("Extended: also a one-time system baseline (services, BIOS/firmware, devices/drivers, installed KBs) and a weekly driver/health digest.");
        sb.AppendLine("Never sent: usernames, file paths, file contents, IP addresses you control, hardware serials.");
        sb.AppendLine();

        var queued = ReadQueue().Where(e => AllowedAt(e, level)).ToList();
        sb.AppendLine($"Waiting to be sent: {queued.Count} event(s)");
        var indented = new JsonSerializerOptions(Json) { WriteIndented = true };
        foreach (var e in queued.TakeLast(25))
        {
            sb.AppendLine(JsonSerializer.Serialize(e, indented));
            sb.AppendLine();
        }

        if (level >= ConsentLevel.Extended && File.Exists(BaselineLocalCopyPath))
        {
            sb.AppendLine($"System baseline copy: {BaselineLocalCopyPath}");
        }
        return sb.ToString();
    }

    // ─── Server response / config cache ─────────────────────────────────

    private void ProcessServerResponse(string body)
    {
        try
        {
            var response = JsonSerializer.Deserialize<PulseResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (response is null) return;
            File.WriteAllText(_configCachePath, body);
        }
        catch (Exception ex) { _log?.LogDebug(ex, "Failed to process Pulse server response"); }
    }

    public List<HotfixConfig> GetCachedHotfixes() => ReadCachedResponse()?.Hotfixes ?? new();
    public List<KnownIssue> GetCachedKnownIssues() => ReadCachedResponse()?.KnownIssues ?? new();

    private PulseResponse? ReadCachedResponse()
    {
        try
        {
            return File.Exists(_configCachePath)
                ? JsonSerializer.Deserialize<PulseResponse>(File.ReadAllText(_configCachePath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                : null;
        }
        catch { return null; }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private static JsonElement ToElement(object payload) => JsonSerializer.SerializeToElement(payload, payload.GetType(), Json);

    /// <summary>Recursively scrubs every string value (paths, user/machine names, e-mails, IPs, SIDs).</summary>
    internal static JsonElement ScrubElement(JsonElement element)
    {
        var node = JsonNode.Parse(element.GetRawText());
        return JsonSerializer.SerializeToElement(ScrubNode(node), Json);
    }

    private static JsonNode? ScrubNode(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(kv => kv.Key).ToList())
                {
                    var current = obj[key];
                    var scrubbed = ScrubNode(current);
                    if (!ReferenceEquals(scrubbed, current)) obj[key] = scrubbed;
                }
                return obj;
            case JsonArray arr:
                for (var i = 0; i < arr.Count; i++)
                {
                    var current = arr[i];
                    var scrubbed = ScrubNode(current);
                    if (!ReferenceEquals(scrubbed, current)) arr[i] = scrubbed;
                }
                return arr;
            case JsonValue val when val.TryGetValue<string>(out var s):
                return JsonValue.Create(TelemetryScrubber.ScrubText(s, maskTokens: false));
            default:
                return node;
        }
    }

    private static bool IsJsonObject(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        try { using var d = JsonDocument.Parse(text); return d.RootElement.ValueKind == JsonValueKind.Object; }
        catch (JsonException) { return false; }
    }

    private static string ReadIngestKey()
    {
        var key = typeof(PulseClient).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "LogicFlowIngestKey")?.Value;
        return string.IsNullOrWhiteSpace(key) ? "logicflow-dev-ingest-key" : key;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
    }

    // ─── Persisted back-off / bookkeeping ───────────────────────────────

    private sealed class PulseState
    {
        public int Failures { get; set; }
        public DateTimeOffset? NextAttemptUtc { get; set; }
        public DateTimeOffset? LastHealthDigestUtc { get; set; }
        public string? BaselineSentFor { get; set; }
    }

    private PulseState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
                return JsonSerializer.Deserialize<PulseState>(File.ReadAllText(_statePath)) ?? new PulseState();
        }
        catch (Exception ex) { _log?.LogDebug(ex, "Pulse state unreadable — resetting"); }
        return new PulseState();
    }

    private void SaveState(PulseState state)
    {
        try { File.WriteAllText(_statePath, JsonSerializer.Serialize(state)); }
        catch (Exception ex) { _log?.LogDebug(ex, "Failed to persist Pulse state"); }
    }
}
