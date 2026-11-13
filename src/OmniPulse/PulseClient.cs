// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — PulseClient
// The main telemetry client. Queues events locally as JSONL, batches them,
// and sends to delgadologic.tech/api/pulse on a weekly schedule (or on crash).
// ─────────────────────────────────────────────────────────────────────────────

using System.IO.Compression;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Privacy-first telemetry client for LogicFlow.
/// Queues events locally, batches weekly, encrypts in transit (HTTPS).
/// All data is anonymous — no PII is ever collected or sent.
/// </summary>
public sealed class PulseClient : IDisposable
{
    private readonly ILogger<PulseClient>? _logger;
    private readonly HttpClient _http;
    private readonly SystemFingerprint _fingerprint;
    private readonly string _queueDir;
    private readonly string _queueFile;
    private readonly string _configCachePath;
    private readonly string _appVersion;
    private readonly object _writeLock = new();
    private readonly string _apiBase;

    private TelemetryLevel _level;
    private Timer? _flushTimer;

    private const long MaxQueueSizeBytes = 512 * 1024; // 500 KB max queue

    public PulseClient(
        string appVersion = "1.0.0",
        TelemetryLevel level = TelemetryLevel.Full,
        string apiBase = "https://delgadologic.tech/api/pulse",
        ILogger<PulseClient>? logger = null)
    {
        _appVersion = appVersion;
        _level = level;
        _apiBase = apiBase;
        _logger = logger;

        // Respect the installer's telemetry opt-out setting (registry)
        // Written by the installer: HKLM\SOFTWARE\DelgadoLogic\LogicFlow\TelemetryEnabled = 0 or 1
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\DelgadoLogic\LogicFlow");
            if (key?.GetValue("TelemetryEnabled") is int regValue && regValue == 0)
            {
                _level = TelemetryLevel.Off;
                logger?.LogInformation("Telemetry disabled by installer registry setting");
            }
        }
        catch { /* Registry not available — use default level */ }

        _fingerprint = new SystemFingerprint();

        // Use proxy-aware handler — handles corporate proxies, PAC files, and NTLM auth
        var handler = new HttpClientHandler
        {
            UseProxy = true,
            Proxy = System.Net.WebRequest.DefaultWebProxy, // Picks up IE/system proxy settings
            UseDefaultCredentials = true, // Handles NTLM proxy auth automatically
            AutomaticDecompression = System.Net.DecompressionMethods.GZip
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Add("User-Agent", $"LogicFlow-Pulse/{appVersion}");

        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow", "Pulse");
        Directory.CreateDirectory(appData);

        _queueDir = appData;
        _queueFile = Path.Combine(appData, "event_queue.jsonl");
        _configCachePath = Path.Combine(appData, "config_cache.json");
    }

    // ─── Configuration ──────────────────────────────────────────────────

    /// <summary>
    /// Gets or sets the current telemetry level.
    /// </summary>
    public TelemetryLevel Level
    {
        get => _level;
        set
        {
            _level = value;
            _logger?.LogInformation("Telemetry level changed to {Level}", value);
            if (value == TelemetryLevel.Off) ClearQueue();
        }
    }

    /// <summary>
    /// Starts the automatic weekly flush timer.
    /// </summary>
    public void StartAutoFlush()
    {
        if (_level == TelemetryLevel.Off) return;

        // Flush every 7 days (or on app close)
        _flushTimer = new Timer(async _ =>
        {
            try { await FlushAsync(); }
            catch (Exception ex) { _logger?.LogDebug(ex, "Auto-flush failed"); }
        }, null, TimeSpan.FromHours(1), TimeSpan.FromDays(7));

        _logger?.LogInformation("Pulse auto-flush started (weekly interval)");
    }

    // ─── First-Install Baseline ─────────────────────────────────────────

    private string BaselineSentinelPath => Path.Combine(_queueDir, ".baseline_sent");
    private string BaselineLocalCopyPath => Path.Combine(_queueDir, "system_baseline.json");

    /// <summary>Max baseline payload size (2 MB uncompressed). Typical baselines are ~100-200 KB.</summary>
    private const long MaxBaselineSizeBytes = 2 * 1024 * 1024;

    /// <summary>
    /// Captures and sends the first-install system baseline.
    /// Only runs once — uses a sentinel file to prevent re-sends.
    /// Sends directly via POST (bypasses the 512 KB event queue).
    /// Also saves a local copy for the user to review.
    /// </summary>
    public async Task<bool> SendBaselineAsync()
    {
        if (_level == TelemetryLevel.Off) return false;

        // Only send once
        if (File.Exists(BaselineSentinelPath))
        {
            _logger?.LogDebug("Baseline already sent — skipping");
            return false;
        }

        try
        {
            _logger?.LogInformation("First-install detected — capturing system baseline");

            // Capture the full baseline
            var baseline = _fingerprint.CaptureBaseline(_appVersion);

            // Serialize and check size
            var jsonOptions = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = false
            };
            var json = JsonSerializer.Serialize(baseline, jsonOptions);

            if (json.Length > MaxBaselineSizeBytes)
            {
                _logger?.LogWarning(
                    "Baseline too large ({Size} bytes > {Max} limit) — truncating services list",
                    json.Length, MaxBaselineSizeBytes);
                // Truncate services to top 100 (keep running ones prioritized)
                baseline = baseline with
                {
                    Services = baseline.Services
                        .OrderByDescending(s => s.Status == "Running" ? 1 : 0)
                        .Take(100)
                        .ToList()
                };
                json = JsonSerializer.Serialize(baseline, jsonOptions);
            }

            // Save local copy (user can review what was sent)
            try
            {
                var prettyJson = JsonSerializer.Serialize(baseline,
                    new JsonSerializerOptions
                    {
                        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
                        WriteIndented = true
                    });
                File.WriteAllText(BaselineLocalCopyPath, prettyJson);
                _logger?.LogInformation("Baseline saved locally: {Path}", BaselineLocalCopyPath);
            }
            catch (Exception ex) { _logger?.LogDebug(ex, "Failed to save baseline local copy"); }

            // Send directly (bypass queue — this is a one-time large payload)
            var compressed = GzipCompress(json);
            _logger?.LogInformation(
                "Baseline size: {Raw} KB raw → {Compressed} KB compressed ({Ratio:P0} ratio)",
                json.Length / 1024, compressed.Length / 1024,
                1.0 - (double)compressed.Length / json.Length);

            // Retry with exponential backoff (handles transient network issues,
            // DNS resolution delays after boot, firewall warmup, proxy negotiation)
            const int maxRetries = 3;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, $"{_apiBase}/baseline");
                    request.Content = new ByteArrayContent(compressed);
                    request.Content.Headers.ContentType = new("application/json");
                    request.Content.Headers.ContentEncoding.Add("gzip");
                    request.Headers.Add("X-Pulse-Version", _appVersion);
                    request.Headers.Add("X-Pulse-InstallId", _fingerprint.GetInstallId());
                    request.Headers.Add("X-Pulse-EventType", "first_install_baseline");

                    // Use longer timeout for baseline (60s) — first-boot network can be slow
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                    var response = await _http.SendAsync(request, cts.Token);

                    if (response.IsSuccessStatusCode)
                    {
                        // Mark as sent — never send again
                        File.WriteAllText(BaselineSentinelPath, DateTimeOffset.UtcNow.ToString("o"));
                        _logger?.LogInformation(
                            "✅ Baseline sent successfully ({Size} KB, {Services} services, {Problems} problem devices)",
                            compressed.Length / 1024, baseline.TotalServiceCount, baseline.ProblemDevices.Count);

                        // Process any server response
                        var responseBody = await response.Content.ReadAsStringAsync();
                        ProcessServerResponse(responseBody);
                        return true;
                    }
                    else
                    {
                        _logger?.LogWarning("Baseline upload attempt {Attempt}/{Max} failed: {Status}",
                            attempt, maxRetries, response.StatusCode);
                    }
                }
                catch (TaskCanceledException)
                {
                    _logger?.LogWarning("Baseline upload attempt {Attempt}/{Max} timed out", attempt, maxRetries);
                }
                catch (HttpRequestException ex)
                {
                    _logger?.LogWarning("Baseline upload attempt {Attempt}/{Max} network error: {Msg}",
                        attempt, maxRetries, ex.Message);
                }

                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt)); // 2s, 4s, 8s
                    _logger?.LogDebug("Retrying baseline in {Delay}...", delay);
                    await Task.Delay(delay);
                }
            }

            _logger?.LogWarning("Baseline upload failed after {Max} attempts — will retry on next launch", maxRetries);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Baseline capture/send failed — will retry on next launch");
            return false;
        }
    }

    // ─── Event Tracking ─────────────────────────────────────────────────

    /// <summary>
    /// Queues a telemetry event for later batch transmission.
    /// </summary>
    public void Track(string eventType, object payload)
    {
        if (_level == TelemetryLevel.Off) return;

        // CrashesOnly mode only allows crash events
        if (_level == TelemetryLevel.CrashesOnly && eventType != "crash") return;

        var evt = new PulseEvent
        {
            EventType = eventType,
            AppVersion = _appVersion,
            InstallId = _fingerprint.GetInstallId(),
            Payload = payload
        };

        EnqueueEvent(evt);
    }

    /// <summary>
    /// Tracks a feature usage event. e.g., TrackFeature("JunkCleaner.Scan")
    /// </summary>
    public void TrackFeature(string featureName)
        => Track("feature_usage", new { Feature = featureName, At = DateTimeOffset.UtcNow });

    /// <summary>
    /// Tracks an optimization result.
    /// </summary>
    public void TrackOptimization(string toolName, bool succeeded, long durationMs,
                                   Dictionary<string, string>? metrics = null)
    {
        Track("optimization", new OptimizationEvent
        {
            ToolName = toolName,
            Succeeded = succeeded,
            DurationMs = durationMs,
            Metrics = metrics ?? new()
        });
    }

    /// <summary>
    /// Tracks a non-fatal engine error.
    /// </summary>
    public void TrackError(string engineName, string methodName, Exception ex, string? context = null)
    {
        Track("engine_error", new EngineError
        {
            EngineName = engineName,
            MethodName = methodName,
            ErrorType = ex.GetType().Name,
            ErrorMessage = ex.Message,
            Context = context
        });
    }

    /// <summary>
    /// Tracks a driver scan result. Called after DriverDatabase.FullScanAsync().
    /// Captures a compact DriverFingerprint for crowd-sourced driver intelligence.
    /// Only "key" drivers (GPU, Audio, Network, WiFi, Storage, Chipset) are included
    /// to minimize bandwidth — HID/System/Printer are excluded.
    /// </summary>
    public void TrackDriverScan(DriverFingerprint fingerprint)
    {
        Track("driver_scan", fingerprint);
    }

    // ─── AI Self-Improvement Signals ─────────────────────────────────────

    /// <summary>
    /// Tracks whether the user followed an AI driver recommendation.
    /// Server aggregates acceptance/skip rates to calibrate AI confidence.
    /// </summary>
    public void TrackAiRecommendationFeedback(AiRecommendationFeedback feedback)
    {
        Track("ai_recommendation_feedback", feedback);
    }

    /// <summary>
    /// Tracks when users apply, skip, or revert tweaks.
    /// High revert rate → AI should stop recommending that tweak.
    /// </summary>
    public void TrackTweakFeedback(TweakFeedback feedback)
    {
        Track("tweak_feedback", feedback);
    }

    /// <summary>
    /// Tracks engine/scan performance (duration, items, success/failure).
    /// Helps optimize scan speed and detect slow WMI queries by hardware class.
    /// </summary>
    public void TrackScanPerformance(ScanPerformanceEvent scanEvent)
    {
        Track("scan_performance", scanEvent);
    }

    /// <summary>
    /// Tracks anonymous session flow (page sequence, dwell time, exit page).
    /// Helps discover features users never find → improve UX and onboarding.
    /// </summary>
    public void TrackSessionFlow(SessionFlow flow)
    {
        Track("session_flow", flow);
    }

    // ─── Queue Management ───────────────────────────────────────────────

    private void EnqueueEvent(PulseEvent evt)
    {
        lock (_writeLock)
        {
            try
            {
                // Check queue size limit
                if (File.Exists(_queueFile))
                {
                    var info = new FileInfo(_queueFile);
                    if (info.Length >= MaxQueueSizeBytes)
                    {
                        RotateQueue();
                    }
                }

                var json = JsonSerializer.Serialize(evt,
                    new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
                File.AppendAllText(_queueFile, json + "\n");
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Failed to enqueue telemetry event");
            }
        }
    }

    private void RotateQueue()
    {
        try
        {
            // Keep old queue as backup, start fresh
            var backupPath = Path.Combine(_queueDir,
                $"event_queue_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.bak");
            if (File.Exists(_queueFile))
                File.Move(_queueFile, backupPath, overwrite: true);

            // Clean old backups (keep last 4 weeks)
            var backups = Directory.GetFiles(_queueDir, "*.bak")
                .OrderByDescending(f => f).Skip(4);
            foreach (var old in backups)
            {
                try { File.Delete(old); } catch { }
            }
        }
        catch { }
    }

    private void ClearQueue()
    {
        lock (_writeLock)
        {
            try
            {
                if (File.Exists(_queueFile)) File.Delete(_queueFile);
                _logger?.LogInformation("Telemetry queue cleared (level set to Off)");
            }
            catch { }
        }
    }

    // ─── Flush / Send ───────────────────────────────────────────────────

    /// <summary>
    /// Sends all queued events to the Pulse API. Called weekly or on crash.
    /// On weekly flush, also collects deduplicated Windows system health data.
    /// </summary>
    public async Task FlushAsync(bool includeSysHealth = true)
    {
        if (_level == TelemetryLevel.Off) return;

        List<PulseEvent> events;

        lock (_writeLock)
        {
            if (!File.Exists(_queueFile) && !includeSysHealth) return;

            events = new List<PulseEvent>();

            if (File.Exists(_queueFile))
            {
                var lines = File.ReadAllLines(_queueFile);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var evt = JsonSerializer.Deserialize<PulseEvent>(line);
                        if (evt != null) events.Add(evt);
                    }
                    catch { /* Skip malformed lines */ }
                }
            }
        }

        // ─── Collect system health digest (deduplicated across all sources) ───
        if (includeSysHealth && _level == TelemetryLevel.Full)
        {
            try
            {
                var aggregator = new HealthDigestAggregator();
                var digest = aggregator.BuildDigest(daysBack: 7);
                events.Add(new PulseEvent
                {
                    EventType = "system_health",
                    AppVersion = _appVersion,
                    InstallId = _fingerprint.GetInstallId(),
                    Payload = digest
                });
                _logger?.LogInformation(
                    "Pulse: collected system health digest ({Events} events, stability={Score:F1})",
                    digest.Events.Count, digest.StabilityIndex);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Pulse: system health collection failed (non-blocking)");
            }
        }

        if (events.Count == 0) return;

        var batch = new PulseBatch
        {
            InstallId = _fingerprint.GetInstallId(),
            AppVersion = _appVersion,
            Events = events
        };

        try
        {
            var json = JsonSerializer.Serialize(batch);
            var compressed = GzipCompress(json);

            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_apiBase}/ingest");
            request.Content = new ByteArrayContent(compressed);
            request.Content.Headers.ContentType = new("application/json");
            request.Content.Headers.ContentEncoding.Add("gzip");
            request.Headers.Add("X-Pulse-Version", _appVersion);
            request.Headers.Add("X-Pulse-InstallId", _fingerprint.GetInstallId());

            var response = await _http.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                _logger?.LogInformation("Pulse: sent {Count} events ({Size} bytes compressed)",
                    events.Count, compressed.Length);

                // Clear the queue after successful send
                lock (_writeLock)
                {
                    try { File.Delete(_queueFile); } catch { }
                }

                // Process server response (hotfixes, known issues)
                var responseBody = await response.Content.ReadAsStringAsync();
                ProcessServerResponse(responseBody);
            }
            else
            {
                _logger?.LogWarning("Pulse: server returned {Status}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Pulse: failed to send telemetry batch (will retry next cycle)");
            // Events remain in queue for next flush attempt
        }
    }

    // ─── Server Response Processing ─────────────────────────────────────

    private void ProcessServerResponse(string responseBody)
    {
        try
        {
            var response = JsonSerializer.Deserialize<PulseResponse>(responseBody,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (response == null) return;

            // Cache hotfixes and known issues locally
            File.WriteAllText(_configCachePath, responseBody);

            if (response.Hotfixes.Count > 0)
                _logger?.LogInformation("Pulse: received {Count} hotfix configs", response.Hotfixes.Count);

            if (response.KnownIssues.Count > 0)
                _logger?.LogInformation("Pulse: received {Count} known issues", response.KnownIssues.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to process Pulse server response");
        }
    }

    /// <summary>
    /// Returns cached hotfix configs from the last successful sync.
    /// </summary>
    public List<HotfixConfig> GetCachedHotfixes()
    {
        try
        {
            if (!File.Exists(_configCachePath)) return new();
            var json = File.ReadAllText(_configCachePath);
            var response = JsonSerializer.Deserialize<PulseResponse>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return response?.Hotfixes ?? new();
        }
        catch { return new(); }
    }

    /// <summary>
    /// Returns cached known issues from the last successful sync.
    /// </summary>
    public List<KnownIssue> GetCachedKnownIssues()
    {
        try
        {
            if (!File.Exists(_configCachePath)) return new();
            var json = File.ReadAllText(_configCachePath);
            var response = JsonSerializer.Deserialize<PulseResponse>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return response?.KnownIssues ?? new();
        }
        catch { return new(); }
    }

    // ─── Compression ────────────────────────────────────────────────────

    private static byte[] GzipCompress(string data)
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
        {
            gzip.Write(bytes, 0, bytes.Length);
        }
        return output.ToArray();
    }

    // ─── Cleanup ────────────────────────────────────────────────────────

    public void Dispose()
    {
        _flushTimer?.Dispose();
        _http.Dispose();
    }
}
