// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Gemma 4 E2B (gemma-4-E2B-it) Hybrid Local & Cloud AI Engine
// Proprietary implementation by DelgadoLogic.Tech
//
// Supports two zero-friction execution modes:
//   Mode 1: Local Offline Sidecar (llama-server.exe + gemma-4-E2B-it-Q4_K_M.gguf)
//           - Bound strictly to 127.0.0.1
//           - Registers PID with FullScreenGameGuard.RegisterGlobalExcludedProcessId
//             so local GPU inference never self-sabotages Sensor 3 (>= 35% 3D load)
//           - Immediately unloaded when FullScreenGameGuard or TurboMode detects a game
//           - Auto-unloaded after 5 minutes of inactivity (0 MB idle footprint)
//   Mode 2: Self-Hosted Argon-vLLM / OpenAI-Compatible Cloud Endpoint
//           - Zero local disk/VRAM footprint
//           - Uses identical OpenAI /v1/chat/completions wire schema & tool definitions
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using LogicFlow.Guardian.Worker;

namespace LogicFlow.Guardian;

/// <summary>
/// Execution mode for the Gemma 4 E2B AI engine.
/// </summary>
public enum GemmaExecutionMode
{
    /// <summary>
    /// Automatically uses the local GGUF sidecar if installed, otherwise falls back to
    /// the configured cloud endpoint, and finally to deterministic rule-based heuristics.
    /// </summary>
    HybridAuto = 0,

    /// <summary>
    /// Runs 100% offline via the local llama-server.exe sidecar and gemma-4-E2B-it-Q4_K_M.gguf.
    /// </summary>
    LocalSidecar = 1,

    /// <summary>
    /// Uses the self-hosted Argon-vLLM / OpenAI-compatible cloud endpoint (zero local footprint).
    /// </summary>
    CloudEndpoint = 2,

    /// <summary>
    /// Disables all AI model calls and uses 100% deterministic local rule-based engines.
    /// </summary>
    Disabled = 3
}

/// <summary>
/// Represents a function tool definition exposed to Gemma 4 E2B via OpenAI-compatible tool schema.
/// </summary>
public sealed class GemmaToolDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("parameters")]
    public object Parameters { get; set; } = new { type = "object", properties = new Dictionary<string, object>() };

    [JsonIgnore]
    public object ParametersSchema
    {
        get => Parameters;
        set => Parameters = value;
    }
}

/// <summary>
/// Represents a parsed tool call emitted by Gemma 4 E2B (either via OpenAI tool_calls array
/// or via Gemma 4 native &lt;|tool_call|&gt; token formatting).
/// </summary>
public sealed class GemmaToolCall
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("arguments_json")]
    public string ArgumentsJson { get; set; } = "{}";

    [JsonIgnore]
    public JsonElement Arguments => ParseArgumentsElement();

    public JsonElement ParseArgumentsElement()
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(ArgumentsJson) ? "{}" : ArgumentsJson);
            return doc.RootElement.Clone();
        }
        catch
        {
            using var doc = JsonDocument.Parse("{}");
            return doc.RootElement.Clone();
        }
    }
}

/// <summary>
/// Request payload sent to GemmaAiEngine.
/// </summary>
public sealed class GemmaChatRequest
{
    public string SystemPrompt { get; set; } = string.Empty;
    public string UserPrompt { get; set; } = string.Empty;
    public IReadOnlyList<GemmaToolDefinition>? Tools { get; set; }
    public double Temperature { get; set; } = 0.2;
    public int MaxTokens { get; set; } = 512;
}

/// <summary>
/// Normalized response returned by GemmaAiEngine.
/// </summary>
public sealed class GemmaChatResponse
{
    public bool Success { get; set; }
    public string Text { get; set; } = string.Empty;
    public List<GemmaToolCall> ToolCalls { get; set; } = [];
    public string ProviderUsed { get; set; } = "None";
    public string? Error { get; set; }

    [JsonIgnore]
    public string Content
    {
        get => Text;
        set => Text = value;
    }

    [JsonIgnore]
    public string ActiveProvider
    {
        get => ProviderUsed;
        set => ProviderUsed = value;
    }

    [JsonIgnore]
    public string? ErrorMessage
    {
        get => Error;
        set => Error = value;
    }
}

/// <summary>
/// Download progress report for the on-demand Gemma 4 E2B GGUF model &amp; sidecar binary.
/// </summary>
public sealed class GemmaDownloadProgress
{
    public double Percentage { get; init; }
    public long BytesDownloaded { get; init; }
    public long TotalBytes { get; init; }
    public string Status { get; init; } = string.Empty;

    public string Stage => Status;
    public long BytesReceived => BytesDownloaded;
}

/// <summary>
/// Unified hybrid AI engine managing Google Gemma 4 E2B (gemma-4-E2B-it, Apache 2.0)
/// across local GGUF sidecar and Argon-vLLM OpenAI-compatible cloud inference.
/// </summary>
public sealed class GemmaAiEngine : IDisposable
{
    public const string DefaultModelId = "google/gemma-4-E2B-it";
    public const string DefaultGgufFileName = "gemma-4-E2B-it-Q4_K_M.gguf";
    public const string DefaultSidecarExeName = "llama-server.exe";
    public const string DefaultCloudEndpoint = "https://api.delgadologic.tech/v1/ai/chat/completions";
    public const string DefaultModelDownloadUrl = "https://huggingface.co/bartowski/google_gemma-4-E2B-it-GGUF/resolve/81012ba3538e061d5ee003f11f25335b17f82e2d/google_gemma-4-E2B-it-Q4_K_M.gguf";
    public const string DefaultModelSha256 = "923c4c86177d2ee173a7f5b4fa3d0ac65f5962ab15e6d6a5bc250aec4fd7bf7e";
    public const string DefaultSidecarDownloadUrl = "https://github.com/ggml-org/llama.cpp/releases/download/b12283/llama-b12283-bin-win-vulkan-x64.zip";
    public const string DefaultSidecarSha256 = "58c3426f7473bc08135c83333259366521fc940e4ad7bc6ad2b26755cc42cb03";
    public const int DefaultLocalPort = 38145;

    private static readonly Lazy<GemmaAiEngine> s_instance = new(() => new GemmaAiEngine());

    /// <summary>
    /// Shared singleton instance used across Guardian, Dashboard, CLI, and VoiceAgent.
    /// </summary>
    public static GemmaAiEngine Instance => s_instance.Value;

    private readonly object _sidecarLock = new();
    private readonly HttpClient _httpClient;
    private Process? _sidecarProcess;
    private int _sidecarPid = -1;
    private Timer? _idleTimer;
    private DateTime _lastActivityUtc = DateTime.MinValue;
    private bool _isDisposed;

    // ─── Configuration Properties ───
    public GemmaExecutionMode Mode { get; set; } = GemmaExecutionMode.HybridAuto;
    /// <summary>
    /// Controls whether HybridAuto is permitted to send prompts/telemetry to CloudEndpointUrl when the local model is absent.
    /// Defaults to false so Free/local users never transmit prompts off-device without explicit opt-in.
    /// </summary>
    public bool AllowHybridCloudFallback { get; set; } = false;
    public string LocalAiDirectory { get; set; }
    public int LocalSidecarPort { get; set; } = DefaultLocalPort;
    public string CloudEndpointUrl { get; set; } = DefaultCloudEndpoint;
    public string? CloudApiKey { get; set; }
    public string ModelDownloadUrl { get; set; } = DefaultModelDownloadUrl;
    public string? SidecarDownloadUrl { get; set; }
    public string? ExpectedModelSha256 { get; set; }
    public string? ExpectedSidecarSha256 { get; set; }
    /// <summary>
    /// Enforces pinned SHA-256 checksums for DefaultSidecarDownloadUrl and DefaultModelDownloadUrl fail-closed.
    /// Enabled automatically for production instances; custom URLs remain supported and verify Expected*Sha256 when provided.
    /// </summary>
    public bool EnforcePinnedSha256 { get; set; } = true;
    public string? LastModelSha256 { get; private set; }
    public string? LastSidecarSha256 { get; private set; }
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Optional test seam: allows injecting a deterministic async handler in unit tests
    /// without requiring network access or a 3.1 GB GGUF model on disk.
    /// </summary>
    public Func<GemmaChatRequest, CancellationToken, Task<GemmaChatResponse>>? CustomTransport { get; set; }

    /// <summary>
    /// Raised whenever the local sidecar starts or stops.
    /// </summary>
    public event Action<bool>? SidecarStateChanged;

    public GemmaAiEngine(HttpClient? httpClient = null, string? localAiDirectory = null)
    {
        EnforcePinnedSha256 = true;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
        LocalAiDirectory = !string.IsNullOrWhiteSpace(localAiDirectory)
            ? localAiDirectory
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow", "AI");

        // Subscribe to FullScreenGameGuard global game detection so the local sidecar is
        // immediately terminated when any game starts, freeing 100% of VRAM and RAM.
        FullScreenGameGuard.GlobalGameDetected += OnGlobalGameDetected;
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    public string LocalModelFilePath => Path.Combine(LocalAiDirectory, DefaultGgufFileName);
    public string LocalSidecarFilePath => Path.Combine(LocalAiDirectory, DefaultSidecarExeName);
    public string LocalEndpointUrl => $"http://127.0.0.1:{LocalSidecarPort}/v1/chat/completions";

    /// <summary>
    /// Returns true if the quantized gemma-4-E2B-it-Q4_K_M.gguf model file exists on disk.
    /// </summary>
    public bool IsLocalModelInstalled()
    {
        try
        {
            var fi = new FileInfo(LocalModelFilePath);
            return fi.Exists && fi.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true if llama-server.exe is present in LocalAiDirectory or on AppContext.BaseDirectory.
    /// </summary>
    public bool IsSidecarBinaryInstalled()
    {
        try
        {
            if (File.Exists(LocalSidecarFilePath))
                return true;

            var appBase = Path.Combine(AppContext.BaseDirectory, DefaultSidecarExeName);
            return File.Exists(appBase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true if the local sidecar process is currently running.
    /// </summary>
    public bool IsSidecarRunning
    {
        get
        {
            lock (_sidecarLock)
            {
                if (_sidecarProcess == null) return false;
                try
                {
                    return !_sidecarProcess.HasExited;
                }
                catch
                {
                    return false;
                }
            }
        }
    }

    /// <summary>
    /// Returns the PID of the active llama-server.exe sidecar process, or -1 if not running.
    /// </summary>
    public int ActiveSidecarProcessId
    {
        get
        {
            lock (_sidecarLock)
            {
                return IsSidecarRunning ? _sidecarPid : -1;
            }
        }
    }

    /// <summary>
    /// Returns a human-readable status summary of the Gemma 4 E2B AI subsystem.
    /// </summary>
    public string GetStatusSummary()
    {
        if (Mode == GemmaExecutionMode.Disabled)
            return "Disabled (100% deterministic local rules)";

        bool modelInstalled = IsLocalModelInstalled();
        bool running = IsSidecarRunning;

        if (Mode == GemmaExecutionMode.LocalSidecar)
        {
            if (running)
                return $"Local Gemma 4 E2B Active (PID {_sidecarPid} on 127.0.0.1:{LocalSidecarPort})";
            if (modelInstalled && IsSidecarBinaryInstalled())
                return "Local Gemma 4 E2B Ready (On-Demand Standby — 0 MB RAM)";
            if (modelInstalled)
                return "Local Gemma 4 E2B Sidecar Runtime Missing (Re-download Local AI Assets)";
            return "Local Gemma 4 E2B Model Not Downloaded (Using Deterministic Fallback)";
        }

        if (Mode == GemmaExecutionMode.CloudEndpoint)
        {
            return $"Cloud Endpoint ({CloudEndpointUrl})";
        }

        // HybridAuto
        if (running)
            return $"Hybrid: Local Gemma 4 E2B Active (PID {_sidecarPid})";
        if (modelInstalled && IsSidecarBinaryInstalled())
            return "Hybrid: Local Gemma 4 E2B Ready (Standby — 0 MB RAM)";
        return AllowHybridCloudFallback
            ? $"Hybrid: Cloud Opt-In ({CloudEndpointUrl}) + Deterministic Fallback"
            : "Hybrid (Privacy Safe): Local Deterministic Diagnostics (Download Gemma 4 E2B for Offline LLM)";
    }

    /// <summary>
    /// Downloads the llama-server.exe sidecar binary (either direct .exe or .zip release bundle)
    /// into %LOCALAPPDATA%\LogicFlow\AI\ if not already installed.
    /// </summary>
    public async Task<bool> DownloadSidecarBinaryAsync(
        IProgress<GemmaDownloadProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (IsSidecarBinaryInstalled())
            return true;

        string downloadUrl = !string.IsNullOrWhiteSpace(SidecarDownloadUrl)
            ? SidecarDownloadUrl.Trim()
            : DefaultSidecarDownloadUrl;
        ValidateDownloadUrl(downloadUrl, "sidecar");
        string? expectedSidecarSha = ResolveExpectedSidecarSha256(downloadUrl);

        Directory.CreateDirectory(LocalAiDirectory);
        bool isZip = downloadUrl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
        string tempFile = Path.Combine(LocalAiDirectory, isZip ? "llama-sidecar.zip.part" : (DefaultSidecarExeName + ".part"));

        try
        {
            progress?.Report(new GemmaDownloadProgress
            {
                Percentage = 0,
                BytesDownloaded = 0,
                TotalBytes = 0,
                Status = "Downloading llama-server.exe sidecar runtime..."
            });

            using var request = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            if (SidecarDownloadUrl is null && isZip &&
                string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            long totalBytes = response.Content.Headers.ContentLength ?? -1;
            long downloaded = 0;
            await using var contentStream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using (var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                byte[] buffer = new byte[81920];
                int read;
                while ((read = await contentStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    downloaded += read;

                    double pct = totalBytes > 0 ? Math.Round((double)downloaded / totalBytes * 100.0, 1) : 0;
                    progress?.Report(new GemmaDownloadProgress
                    {
                        Percentage = pct,
                        BytesDownloaded = downloaded,
                        TotalBytes = totalBytes,
                        Status = $"Downloading sidecar runtime ({pct:F1}%)..."
                    });
                }
            }

            if (totalBytes > 0 && downloaded != totalBytes)
            {
                throw new InvalidDataException($"Incomplete sidecar download: expected {totalBytes} bytes, received {downloaded} bytes.");
            }

            await using (var verifyStream = File.OpenRead(tempFile))
            {
                byte[] hashBytes = await SHA256.HashDataAsync(verifyStream, ct).ConfigureAwait(false);
                string actualHex = Convert.ToHexString(hashBytes);
                LastSidecarSha256 = actualHex;
                if (!string.IsNullOrWhiteSpace(expectedSidecarSha) &&
                    !string.Equals(actualHex, expectedSidecarSha, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"Sidecar SHA-256 mismatch. Expected {expectedSidecarSha}, got {actualHex}.");
                }
            }

            if (isZip)
            {
                using var archive = ZipFile.OpenRead(tempFile);
                foreach (var entry in archive.Entries)
                {
                    if (string.IsNullOrWhiteSpace(entry.Name))
                        continue;

                    if (entry.Name.Equals(DefaultSidecarExeName, StringComparison.OrdinalIgnoreCase) ||
                        entry.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        string destPath = Path.Combine(LocalAiDirectory, Path.GetFileName(entry.Name));
                        entry.ExtractToFile(destPath, overwrite: true);
                    }
                }
                try { File.Delete(tempFile); } catch { }
            }
            else
            {
                if (File.Exists(LocalSidecarFilePath))
                    File.Delete(LocalSidecarFilePath);
                File.Move(tempFile, LocalSidecarFilePath);
            }

            return IsSidecarBinaryInstalled();
        }
        catch
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Downloads the quantized gemma-4-E2B-it-Q4_K_M.gguf model on-demand into %LOCALAPPDATA%\LogicFlow\AI\
    /// with streaming progress, cancellation support, Content-Length verification, and optional SHA-256 verification.
    /// </summary>
    public async Task<bool> DownloadLocalModelAsync(
        IProgress<GemmaDownloadProgress>? progress = null,
        CancellationToken ct = default)
    {
        string modelUrl = !string.IsNullOrWhiteSpace(ModelDownloadUrl)
            ? ModelDownloadUrl.Trim()
            : DefaultModelDownloadUrl;
        ValidateDownloadUrl(modelUrl, "model");
        string? expectedModelSha = ResolveExpectedModelSha256(modelUrl);

        Directory.CreateDirectory(LocalAiDirectory);
        string tempFile = LocalModelFilePath + ".part";

        try
        {
            if (!IsSidecarBinaryInstalled())
            {
                await DownloadSidecarBinaryAsync(progress, ct).ConfigureAwait(false);
            }

            progress?.Report(new GemmaDownloadProgress
            {
                Percentage = 0,
                BytesDownloaded = 0,
                TotalBytes = 0,
                Status = "Connecting to model repository..."
            });

            using var request = new HttpRequestMessage(HttpMethod.Get, modelUrl);
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            long totalBytes = response.Content.Headers.ContentLength ?? -1;
            long downloaded = 0;
            await using var contentStream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using (var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                byte[] buffer = new byte[81920];
                int read;
                while ((read = await contentStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    downloaded += read;

                    double pct = totalBytes > 0 ? Math.Round((double)downloaded / totalBytes * 100.0, 1) : 0;
                    progress?.Report(new GemmaDownloadProgress
                    {
                        Percentage = pct,
                        BytesDownloaded = downloaded,
                        TotalBytes = totalBytes,
                        Status = totalBytes > 0
                            ? $"Downloading {DefaultGgufFileName}: {downloaded / (1024.0 * 1024):F1} / {totalBytes / (1024.0 * 1024):F1} MB ({pct:F1}%)"
                            : $"Downloading {DefaultGgufFileName}: {downloaded / (1024.0 * 1024):F1} MB"
                    });
                }
            }

            if (totalBytes > 0 && downloaded != totalBytes)
            {
                try { File.Delete(tempFile); } catch { }
                throw new InvalidDataException($"Incomplete model download: expected {totalBytes} bytes, received {downloaded} bytes.");
            }

            progress?.Report(new GemmaDownloadProgress
            {
                Percentage = 99,
                BytesDownloaded = downloaded,
                TotalBytes = totalBytes,
                Status = "Verifying SHA-256 cryptographic checksum..."
            });

            string actualModelHex;
            await using (var verifyStream = File.OpenRead(tempFile))
            {
                byte[] hashBytes = await SHA256.HashDataAsync(verifyStream, ct).ConfigureAwait(false);
                actualModelHex = Convert.ToHexString(hashBytes);
                LastModelSha256 = actualModelHex;
                if (!string.IsNullOrWhiteSpace(expectedModelSha) &&
                    !string.Equals(actualModelHex, expectedModelSha, StringComparison.OrdinalIgnoreCase))
                {
                    try { File.Delete(tempFile); } catch { }
                    throw new InvalidDataException($"Model SHA-256 mismatch. Expected {expectedModelSha}, got {actualModelHex}.");
                }
            }

            if (File.Exists(LocalModelFilePath))
                File.Delete(LocalModelFilePath);
            File.Move(tempFile, LocalModelFilePath);

            progress?.Report(new GemmaDownloadProgress
            {
                Percentage = 100,
                BytesDownloaded = downloaded,
                TotalBytes = totalBytes,
                Status = $"✅ Gemma 4 E2B (Q4_K_M GGUF) downloaded and SHA-256 verified ({actualModelHex[..Math.Min(12, actualModelHex.Length)]}...)."
            });

            return true;
        }
        catch
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Stops the sidecar and deletes the local GGUF model file to reclaim disk space.
    /// </summary>
    public bool DeleteLocalModel()
    {
        StopSidecarImmediately();
        try
        {
            if (File.Exists(LocalModelFilePath))
            {
                File.Delete(LocalModelFilePath);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private string? ResolveExpectedSidecarSha256(string downloadUrl)
    {
        if (!string.IsNullOrWhiteSpace(ExpectedSidecarSha256))
            return ExpectedSidecarSha256.Trim();

        if (EnforcePinnedSha256 &&
            string.Equals(downloadUrl, DefaultSidecarDownloadUrl, StringComparison.OrdinalIgnoreCase))
        {
            return DefaultSidecarSha256;
        }

        return null;
    }

    private string? ResolveExpectedModelSha256(string downloadUrl)
    {
        if (!string.IsNullOrWhiteSpace(ExpectedModelSha256))
            return ExpectedModelSha256.Trim();

        if (EnforcePinnedSha256 &&
            string.Equals(downloadUrl, DefaultModelDownloadUrl, StringComparison.OrdinalIgnoreCase))
        {
            return DefaultModelSha256;
        }

        return null;
    }

    private static void ValidateDownloadUrl(string url, string artifactLabel)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"Invalid {artifactLabel} download URL: '{url}'.");

        bool isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        bool isLoopbackHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback;
        if (!isHttps && !isLoopbackHttp)
            throw new InvalidOperationException($"Refusing insecure {artifactLabel} download URL '{url}'. HTTPS (or localhost loopback) is required.");
    }

    private static bool IsTcpPortInUse(int port)
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach (var ep in listeners)
            {
                if (ep.Port == port)
                    return true;
            }
        }
        catch
        {
            // Ignore inspection errors
        }
        return false;
    }

    /// <summary>
    /// Ensures the local llama-server.exe sidecar is running on 127.0.0.1 and registers its PID
    /// with FullScreenGameGuard so GPU 3D counters from local inference never self-sabotage game detection.
    /// </summary>
    public async Task<bool> EnsureSidecarRunningAsync(CancellationToken ct = default)
    {
        TouchActivityTimer();

        if (IsSidecarRunning)
            return true;

        string? exePath = File.Exists(LocalSidecarFilePath)
            ? LocalSidecarFilePath
            : (File.Exists(Path.Combine(AppContext.BaseDirectory, DefaultSidecarExeName))
                ? Path.Combine(AppContext.BaseDirectory, DefaultSidecarExeName)
                : null);

        if (exePath == null || !IsLocalModelInstalled())
            return false;

        lock (_sidecarLock)
        {
            if (IsSidecarRunning)
                return true;

            try
            {
                // Avoid port collision if another local service is bound to LocalSidecarPort
                if (IsTcpPortInUse(LocalSidecarPort))
                {
                    for (int candidate = DefaultLocalPort + 1; candidate < DefaultLocalPort + 50; candidate++)
                    {
                        if (!IsTcpPortInUse(candidate))
                        {
                            LocalSidecarPort = candidate;
                            break;
                        }
                    }
                }

                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = $"--host 127.0.0.1 --port {LocalSidecarPort} -m \"{LocalModelFilePath}\" -c 8192 --ngl 99 --reasoning-budget 0",
                    WorkingDirectory = LocalAiDirectory,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
                // Drain stdout and stderr asynchronously so the 4 KB OS pipe buffer never fills and deadlocks llama-server.exe
                proc.OutputDataReceived += static (_, _) => { };
                proc.ErrorDataReceived += static (_, _) => { };

                if (!proc.Start())
                {
                    proc.Dispose();
                    return false;
                }

                try { proc.BeginOutputReadLine(); } catch { }
                try { proc.BeginErrorReadLine(); } catch { }

                _sidecarProcess = proc;
                _sidecarPid = proc.Id;

                // CRITICAL: Exclude the llama-server.exe PID from FullScreenGameGuard Sensor 3 GPU 3D counters!
                FullScreenGameGuard.RegisterGlobalExcludedProcessId(_sidecarPid);
            }
            catch
            {
                _sidecarProcess = null;
                _sidecarPid = -1;
                return false;
            }
        }

        SidecarStateChanged?.Invoke(true);

        // Poll /health briefly (up to 4 seconds) for sidecar readiness
        string healthUrl = $"http://127.0.0.1:{LocalSidecarPort}/health";
        for (int i = 0; i < 16; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsSidecarRunning) return false;
            try
            {
                using var resp = await _httpClient.GetAsync(healthUrl, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                    return true;
            }
            catch
            {
                // Still warming up
            }
            await Task.Delay(250, ct).ConfigureAwait(false);
        }

        return IsSidecarRunning;
    }

    /// <summary>
    /// Immediately terminates the local llama-server.exe sidecar process and unregisters its PID
    /// from FullScreenGameGuard, returning 100% of VRAM and RAM to the OS.
    /// Called automatically when a game is detected, when TurboMode engages, or after 5 minutes of inactivity.
    /// </summary>
    public void StopSidecarImmediately()
    {
        Process? procToKill = null;
        int pidToUnregister = -1;

        lock (_sidecarLock)
        {
            procToKill = _sidecarProcess;
            pidToUnregister = _sidecarPid;
            _sidecarProcess = null;
            _sidecarPid = -1;

            _idleTimer?.Dispose();
            _idleTimer = null;
        }

        if (pidToUnregister > 0)
        {
            FullScreenGameGuard.UnregisterGlobalExcludedProcessId(pidToUnregister);
        }

        if (procToKill != null)
        {
            try
            {
                if (!procToKill.HasExited)
                {
                    procToKill.Kill(entireProcessTree: true);
                    procToKill.WaitForExit(1500);
                }
            }
            catch { }
            finally
            {
                try { procToKill.Dispose(); } catch { }
            }

            SidecarStateChanged?.Invoke(false);
        }
    }

    private void OnGlobalGameDetected()
    {
        StopSidecarImmediately();
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        StopSidecarImmediately();
    }

    private void TouchActivityTimer()
    {
        _lastActivityUtc = DateTime.UtcNow;
        lock (_sidecarLock)
        {
            if (_isDisposed) return;
            if (_idleTimer == null)
            {
                _idleTimer = new Timer(OnIdleTimerTick, null, IdleTimeout, Timeout.InfiniteTimeSpan);
            }
            else
            {
                try { _idleTimer.Change(IdleTimeout, Timeout.InfiniteTimeSpan); } catch { }
            }
        }
    }

    private void OnIdleTimerTick(object? state)
    {
        if (DateTime.UtcNow - _lastActivityUtc >= IdleTimeout)
        {
            StopSidecarImmediately();
        }
    }

    public bool IsLocalAssetsInstalled => IsLocalModelInstalled() && IsSidecarBinaryInstalled();
    public int SidecarProcessId => ActiveSidecarProcessId;

    /// <summary>
    /// Downloads both the llama-server.exe sidecar runtime (falling back to DefaultSidecarDownloadUrl when SidecarDownloadUrl is null)
    /// and the quantized Gemma 4 E2B GGUF weights, verifying SHA-256 checksums for both artifacts.
    /// </summary>
    public async Task<bool> DownloadLocalAssetsAsync(
        IProgress<GemmaDownloadProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (!IsSidecarBinaryInstalled())
        {
            bool sidecarOk = await DownloadSidecarBinaryAsync(progress, ct).ConfigureAwait(false);
            if (!sidecarOk)
                return false;
        }

        if (!IsLocalModelInstalled())
        {
            bool modelOk = await DownloadLocalModelAsync(progress, ct).ConfigureAwait(false);
            if (!modelOk)
                return false;
        }

        return IsLocalAssetsInstalled;
    }

    public Task<GemmaChatResponse> ChatAsync(
        GemmaChatRequest request,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return CompleteChatAsync(
            request.SystemPrompt,
            request.UserPrompt,
            request.Tools,
            request.Temperature,
            request.MaxTokens,
            ct);
    }

    /// <summary>
    /// Sends a chat/tool completion request to Gemma 4 E2B (via CustomTransport, Local Sidecar, or Cloud Endpoint).
    /// Never throws; returns a GemmaChatResponse with Success=false on unavailability so callers can seamlessly
    /// fall back to deterministic rule-based heuristics.
    /// </summary>
    public async Task<GemmaChatResponse> CompleteChatAsync(
        string systemPrompt,
        string userPrompt,
        IReadOnlyList<GemmaToolDefinition>? tools = null,
        double temperature = 0.2,
        int maxTokens = 512,
        CancellationToken ct = default)
    {
        if (Mode == GemmaExecutionMode.Disabled)
        {
            return new GemmaChatResponse
            {
                Success = false,
                ProviderUsed = "Disabled",
                Error = "Gemma 4 E2B AI Engine is disabled in Settings."
            };
        }

        var request = new GemmaChatRequest
        {
            SystemPrompt = systemPrompt ?? string.Empty,
            UserPrompt = userPrompt ?? string.Empty,
            Tools = tools,
            Temperature = temperature,
            MaxTokens = maxTokens
        };

        // 1. Test Seam / Custom Transport
        if (CustomTransport != null)
        {
            try
            {
                TouchActivityTimer();
                var customResp = await CustomTransport(request, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(customResp.Text))
                {
                    ExtractInlineGemmaToolCalls(customResp);
                }
                return customResp;
            }
            catch (Exception ex)
            {
                return new GemmaChatResponse
                {
                    Success = false,
                    ProviderUsed = "CustomTransport",
                    Error = ex.Message
                };
            }
        }

        // 2. Local Sidecar Mode (if LocalSidecar or HybridAuto)
        if (Mode is GemmaExecutionMode.LocalSidecar or GemmaExecutionMode.HybridAuto)
        {
            if (IsSidecarRunning || (IsLocalModelInstalled() && IsSidecarBinaryInstalled()))
            {
                bool ready = await EnsureSidecarRunningAsync(ct).ConfigureAwait(false);
                if (ready)
                {
                    var localResp = await SendOpenAiCompatibleRequestAsync(
                        LocalEndpointUrl,
                        null,
                        request,
                        "LocalSidecar(gemma-4-E2B-it)",
                        ct).ConfigureAwait(false);

                    if (localResp.Success || Mode == GemmaExecutionMode.LocalSidecar)
                        return localResp;
                }
            }

            if (Mode == GemmaExecutionMode.LocalSidecar)
            {
                return new GemmaChatResponse
                {
                    Success = false,
                    ProviderUsed = "LocalSidecar",
                    Error = "Local Gemma 4 E2B model or llama-server.exe sidecar is not installed."
                };
            }
        }

        // 3. Cloud Endpoint Mode (explicit CloudEndpoint, or HybridAuto ONLY when AllowHybridCloudFallback opt-in is enabled)
        if (Mode == GemmaExecutionMode.CloudEndpoint ||
            (Mode == GemmaExecutionMode.HybridAuto && AllowHybridCloudFallback))
        {
            if (!string.IsNullOrWhiteSpace(CloudEndpointUrl))
            {
                return await SendOpenAiCompatibleRequestAsync(
                    CloudEndpointUrl,
                    CloudApiKey,
                    request,
                    "CloudEndpoint(gemma-4-E2B-it)",
                    ct).ConfigureAwait(false);
            }
        }

        return new GemmaChatResponse
        {
            Success = false,
            ProviderUsed = Mode == GemmaExecutionMode.HybridAuto && !AllowHybridCloudFallback
                ? "LocalOnlyPrivacyGuard"
                : "None",
            Error = Mode == GemmaExecutionMode.HybridAuto && !AllowHybridCloudFallback
                ? "Cloud AI fallback is disabled for local privacy. Install the local Gemma 4 E2B model or enable Cloud AI in Settings."
                : "No AI provider available."
        };
    }

    private async Task<GemmaChatResponse> SendOpenAiCompatibleRequestAsync(
        string endpointUrl,
        string? apiKey,
        GemmaChatRequest req,
        string providerTag,
        CancellationToken ct)
    {
        try
        {
            TouchActivityTimer();

            var messages = new List<object>();
            if (!string.IsNullOrWhiteSpace(req.SystemPrompt))
            {
                messages.Add(new { role = "system", content = req.SystemPrompt });
            }
            messages.Add(new { role = "user", content = req.UserPrompt });

            var payloadDict = new Dictionary<string, object>
            {
                ["model"] = DefaultModelId,
                ["messages"] = messages,
                ["temperature"] = req.Temperature,
                ["max_tokens"] = req.MaxTokens,
                ["stream"] = false
            };

            if (req.Tools is { Count: > 0 })
            {
                payloadDict["tools"] = req.Tools.Select(t => new
                {
                    type = "function",
                    function = new
                    {
                        name = t.Name,
                        description = t.Description,
                        parameters = t.Parameters
                    }
                }).ToList();
                payloadDict["tool_choice"] = "auto";
            }

            string jsonBody = JsonSerializer.Serialize(payloadDict);
            using var httpReq = new HttpRequestMessage(HttpMethod.Post, endpointUrl)
            {
                Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
            };

            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                httpReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            }

            using var httpResp = await _httpClient.SendAsync(httpReq, ct).ConfigureAwait(false);
            if (!httpResp.IsSuccessStatusCode)
            {
                return new GemmaChatResponse
                {
                    Success = false,
                    ProviderUsed = providerTag,
                    Error = $"HTTP {(int)httpResp.StatusCode}"
                };
            }

            string respJson = await httpResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseOpenAiCompletionJson(respJson, providerTag);
        }
        catch (Exception ex)
        {
            return new GemmaChatResponse
            {
                Success = false,
                ProviderUsed = providerTag,
                Error = ex.Message
            };
        }
    }

    /// <summary>
    /// Parses an OpenAI-compatible /v1/chat/completions JSON response, including both
    /// standard OpenAI `tool_calls` arrays and Gemma 4 native `&lt;|tool_call|&gt;` blocks.
    /// </summary>
    public static GemmaChatResponse ParseOpenAiCompletionJson(string respJson, string providerTag = "Gemma4")
    {
        var result = new GemmaChatResponse
        {
            Success = true,
            ProviderUsed = providerTag
        };

        try
        {
            using var doc = JsonDocument.Parse(respJson);
            var root = doc.RootElement;

            if (root.TryGetProperty("choices", out var choices) &&
                choices.ValueKind == JsonValueKind.Array &&
                choices.GetArrayLength() > 0)
            {
                var firstChoice = choices[0];
                if (firstChoice.TryGetProperty("message", out var message))
                {
                    if (message.TryGetProperty("content", out var contentEl) &&
                        contentEl.ValueKind == JsonValueKind.String)
                    {
                        result.Text = contentEl.GetString() ?? string.Empty;
                    }

                    if (message.TryGetProperty("tool_calls", out var toolCallsEl) &&
                        toolCallsEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var tc in toolCallsEl.EnumerateArray())
                        {
                            string id = tc.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                                ? (idEl.GetString() ?? Guid.NewGuid().ToString("N")[..12])
                                : Guid.NewGuid().ToString("N")[..12];

                            if (tc.TryGetProperty("function", out var fnEl))
                            {
                                string fnName = fnEl.TryGetProperty("name", out var nEl) ? (nEl.GetString() ?? "") : "";
                                string fnArgs = "{}";
                                if (fnEl.TryGetProperty("arguments", out var aEl))
                                {
                                    fnArgs = aEl.ValueKind == JsonValueKind.String
                                        ? (aEl.GetString() ?? "{}")
                                        : aEl.GetRawText();
                                }

                                if (!string.IsNullOrWhiteSpace(fnName))
                                {
                                    result.ToolCalls.Add(new GemmaToolCall
                                    {
                                        Id = id,
                                        Name = fnName,
                                        ArgumentsJson = fnArgs
                                    });
                                }
                            }
                        }
                    }
                }
            }

            ExtractInlineGemmaToolCalls(result);
            return result;
        }
        catch (Exception ex)
        {
            return new GemmaChatResponse
            {
                Success = false,
                ProviderUsed = providerTag,
                Error = $"Failed to parse completion JSON: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Strips Gemma 4 `&lt;|thought|&gt;...&lt;|thought|&gt;` blocks and extracts native
    /// `&lt;|tool_call|&gt;call:func_name{...}&lt;|tool_call|&gt;` or JSON tool calls embedded in text.
    /// </summary>
    public static void ExtractInlineGemmaToolCalls(GemmaChatResponse response)
    {
        if (string.IsNullOrWhiteSpace(response.Text))
            return;

        string text = response.Text;

        // 1. Strip <|thought|>...<|thought|> or <thought>...</thought> reasoning blocks
        text = Regex.Replace(text, @"<\|thought\|>.*?<\|thought\|>", string.Empty, RegexOptions.Singleline | RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"<thought>.*?</thought>", string.Empty, RegexOptions.Singleline | RegexOptions.IgnoreCase);

        // 2. Match Gemma 4 native <|tool_call|>call:func_name{...}<|tool_call|> or <|tool_call|>{...}<|/tool_call|>
        var gemmaNativeMatches = Regex.Matches(
            text,
            @"<\|tool_call\|>\s*(?:call:([a-zA-Z0-9_]+)\s*(\{.*?\})|(\{.*?\}))\s*<\|/?tool_call\|?>",
            RegexOptions.Singleline);

        foreach (Match m in gemmaNativeMatches)
        {
            if (m.Groups[1].Success && !string.IsNullOrWhiteSpace(m.Groups[1].Value))
            {
                string fnName = m.Groups[1].Value.Trim();
                string rawArgs = m.Groups[2].Success ? m.Groups[2].Value.Trim() : "{}";
                response.ToolCalls.Add(new GemmaToolCall
                {
                    Name = fnName,
                    ArgumentsJson = NormalizeGemmaArgumentsToJson(rawArgs)
                });
            }
            else if (m.Groups[3].Success)
            {
                TryAddJsonToolCall(response, m.Groups[3].Value);
            }
        }

        if (gemmaNativeMatches.Count > 0)
        {
            text = Regex.Replace(
                text,
                @"<\|tool_call\|>.*?<\|/?tool_call\|?>",
                string.Empty,
                RegexOptions.Singleline).Trim();
        }

        response.Text = text.Trim();
    }

    private static void TryAddJsonToolCall(GemmaChatResponse response, string jsonCandidate)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonCandidate);
            var root = doc.RootElement;
            if (root.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String)
            {
                string name = nameEl.GetString() ?? "";
                string args = "{}";
                if (root.TryGetProperty("arguments", out var argsEl))
                {
                    args = argsEl.ValueKind == JsonValueKind.String
                        ? (argsEl.GetString() ?? "{}")
                        : argsEl.GetRawText();
                }
                else if (root.TryGetProperty("parameters", out var paramsEl))
                {
                    args = paramsEl.ValueKind == JsonValueKind.String
                        ? (paramsEl.GetString() ?? "{}")
                        : paramsEl.GetRawText();
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    response.ToolCalls.Add(new GemmaToolCall
                    {
                        Name = name,
                        ArgumentsJson = args
                    });
                }
            }
        }
        catch { }
    }

    private static string NormalizeGemmaArgumentsToJson(string rawArgs)
    {
        if (string.IsNullOrWhiteSpace(rawArgs))
            return "{}";

        try
        {
            using var _ = JsonDocument.Parse(rawArgs);
            return rawArgs;
        }
        catch
        {
            // Gemma 4 sometimes emits unquoted keys like {scope:"temp_only"} -> quote keys
            try
            {
                string normalized = Regex.Replace(rawArgs, @"(?<=\{|,)\s*([a-zA-Z0-9_]+)\s*:", "\"$1\":");
                using var _ = JsonDocument.Parse(normalized);
                return normalized;
            }
            catch
            {
                return "{}";
            }
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        FullScreenGameGuard.GlobalGameDetected -= OnGlobalGameDetected;
        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        StopSidecarImmediately();
    }
}
