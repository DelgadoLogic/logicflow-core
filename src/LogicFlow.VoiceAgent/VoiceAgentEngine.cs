// ─────────────────────────────────────────────────────────────────────────────
// VoiceAgentEngine.cs — Top-Level Orchestrator
//
// This is what the Dashboard calls to start/stop a voice session.
// It wires together:
//   1. VoiceSessionGateway   → license check + token + proxy WSS URL
//   2. MicrophoneReader      → captures PCM16 audio from default mic
//   3. GeminiLiveSession     → WebSocket to proxy (not directly to Google)
//   4. LogicFlowFunctionDispatcher → runs real LogicFlow modules
//   5. AudioPlayback         → plays AI audio response through speakers
//
// Usage from Dashboard:
//   var engine = services.GetRequiredService<VoiceAgentEngine>();
//   await engine.StartAsync(licenseKey, fingerprint, ct);
//   // ... user talks, AI responds in real-time ...
//   await engine.StopAsync();
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using DelgadoLogic.Core;
using LogicFlow.Guardian;

namespace LogicFlow.VoiceAgent;

public enum VoiceAgentState
{
    Idle,
    Connecting,
    Live,
    Stopping,
    Error,
}

public sealed class VoiceAgentCommandResult
{
    public bool Success { get; init; }
    public string ReplyText { get; init; } = "";
    public string ActiveProvider { get; init; } = "";
    public List<string> ExecutedTools { get; init; } = new();
    public List<object> ToolOutputs { get; init; } = new();
}

public sealed class VoiceAgentEngine : IAsyncDisposable
{
    private readonly VoiceSessionGateway _gateway;
    private readonly MicrophoneReader _mic;
    private readonly AudioPlayback _speaker;
    private readonly LogicFlowFunctionDispatcher _dispatcher;
    private readonly ILogger<VoiceAgentEngine> _log;

    private GeminiLiveSession? _session;
    private CancellationTokenSource? _sessionCts;
    private readonly Stopwatch _sessionTimer = new();
    private int _functionCallCount;

    private string _activeSessionToken = "";

    public VoiceAgentState State { get; private set; } = VoiceAgentState.Idle;

    /// <summary>Fired when the AI speaks a text chunk (for transcript display in Dashboard).</summary>
    public event Action<string>? TranscriptChunkReceived;

    /// <summary>Fired when state changes (for UI button enable/disable).</summary>
    public event Action<VoiceAgentState>? StateChanged;

    /// <summary>Fired when a function call completes (to animate Dashboard panels).</summary>
    public event Action<string>? FunctionExecuted;

    /// <summary>Fired with a user-facing error message when session fails.</summary>
    public event Action<string>? ErrorOccurred;

    /// <summary>
    /// Pluggable local VAD/STT transcription hook for 100% offline audio utterance processing
    /// (e.g., whisper.cpp / Windows System.Speech).
    /// </summary>
    public Func<ReadOnlyMemory<byte>, CancellationToken, Task<string>>? LocalSttTranscriber { get; set; }

    /// <summary>
    /// Pluggable local TTS synthesis hook for 100% offline voice playback
    /// (e.g., Windows SAPI / Piper TTS returning PCM16 24kHz audio).
    /// </summary>
    public Func<string, CancellationToken, Task<byte[]>>? LocalTtsSynthesizer { get; set; }

    public VoiceAgentEngine(
        VoiceSessionGateway gateway,
        MicrophoneReader mic,
        AudioPlayback speaker,
        LogicFlowFunctionDispatcher dispatcher,
        ILogger<VoiceAgentEngine> log)
    {
        _gateway    = gateway;
        _mic        = mic;
        _speaker    = speaker;
        _dispatcher = dispatcher;
        _log        = log;
    }

    public VoiceAgentEngine(
        LogicFlowFunctionDispatcher dispatcher,
        ILogger<VoiceAgentEngine>? log = null)
    {
        _dispatcher = dispatcher;
        _log        = log ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<VoiceAgentEngine>.Instance;
        _gateway    = null!;
        _mic        = null!;
        _speaker    = null!;
    }

    // ── Start session ────────────────────────────────────────────────────

    /// <summary>Voice &amp; Agentic Assistant is enabled via Gemma 4 E2B Local/Hybrid Engine + Sovereign Proxy.</summary>
    public static bool IsEnabledInV1 => true;

    /// <summary>
    /// Processes a raw PCM16 audio utterance through the local VAD/STT hook and routes the
    /// transcribed command into ExecuteTextCommandAsync + LogicFlowFunctionDispatcher, optionally
    /// synthesizing and enqueuing local TTS audio playback.
    /// </summary>
    public async Task<VoiceAgentCommandResult> ProcessAudioUtteranceAsync(
        ReadOnlyMemory<byte> pcm16Audio,
        SystemContextPayload? systemMetrics = null,
        CancellationToken ct = default)
    {
        if (pcm16Audio.IsEmpty || LocalSttTranscriber == null)
        {
            return new VoiceAgentCommandResult
            {
                Success = false,
                ReplyText = "No local STT transcriber configured or audio buffer was empty."
            };
        }

        string transcript = await LocalSttTranscriber(pcm16Audio, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(transcript))
        {
            return new VoiceAgentCommandResult
            {
                Success = false,
                ReplyText = "No speech detected in audio utterance."
            };
        }

        var result = await ExecuteTextCommandAsync(transcript, systemMetrics, ct).ConfigureAwait(false);
        if (result.Success && !string.IsNullOrWhiteSpace(result.ReplyText) && LocalTtsSynthesizer != null)
        {
            try
            {
                byte[] ttsPcm = await LocalTtsSynthesizer(result.ReplyText, ct).ConfigureAwait(false);
                if (ttsPcm is { Length: > 0 } && _speaker != null)
                {
                    _speaker.EnqueueBytes(ttsPcm);
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "[VoiceEngine] Local TTS synthesis failed; text transcript already delivered.");
            }
        }

        return result;
    }

    /// <summary>
    /// Executes a natural-language command through Gemma 4 E2B with full access to all 12
    /// LogicFlowFunctionDispatcher tools (junk_scan, junk_clean, game_mode_toggle, driver_scan, etc.).
    /// </summary>
    public async Task<VoiceAgentCommandResult> ExecuteTextCommandAsync(
        string userCommand,
        SystemContextPayload? systemMetrics = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userCommand))
        {
            return new VoiceAgentCommandResult
            {
                Success = false,
                ReplyText = "Please enter a command or question."
            };
        }

        string sysContext = systemMetrics != null
            ? $"Current system telemetry: {systemMetrics.ToJson()}"
            : "You can invoke any of the provided LogicFlow tools to inspect or optimize the PC.";

        var ai = GemmaAiEngine.Instance;
        var chatReq = new GemmaChatRequest
        {
            SystemPrompt =
                "You are the LogicFlow Guardian AI Assistant powered by Gemma 4 E2B. " +
                "When the user asks to inspect, scan, clean, or boost the PC, call the matching tool. " +
                sysContext,
            UserPrompt = userCommand,
            Tools = LogicFlowFunctionDispatcher.GetGemmaToolDefinitions(),
            Temperature = 0.15,
            MaxTokens = 512
        };

        var resp = await ai.ChatAsync(chatReq, ct).ConfigureAwait(false);
        var executedTools = new List<string>();
        var toolOutputs = new List<object>();

        if (resp.ToolCalls.Count > 0)
        {
            foreach (var tc in resp.ToolCalls)
            {
                _functionCallCount++;
                executedTools.Add(tc.Name);
                FunctionExecuted?.Invoke(tc.Name);

                var callResult = await _dispatcher.DispatchAsync(new FunctionCall
                {
                    Id = tc.Id,
                    Name = tc.Name,
                    Args = tc.Arguments
                }).ConfigureAwait(false);

                toolOutputs.Add(callResult);
            }

            var summaries = new List<string>();
            foreach (var output in toolOutputs)
            {
                var json = JsonSerializer.Serialize(output);
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("summary", out var sumProp) && sumProp.ValueKind == JsonValueKind.String)
                    {
                        summaries.Add(sumProp.GetString()!);
                        continue;
                    }
                }
                catch { }
                summaries.Add(json);
            }

            var combinedReply = !string.IsNullOrWhiteSpace(resp.Content)
                ? $"{resp.Content.Trim()}\n{string.Join("\n", summaries)}"
                : string.Join("\n", summaries);

            TranscriptChunkReceived?.Invoke(combinedReply);
            return new VoiceAgentCommandResult
            {
                Success = true,
                ReplyText = combinedReply,
                ActiveProvider = resp.ActiveProvider,
                ExecutedTools = executedTools,
                ToolOutputs = toolOutputs
            };
        }

        if (resp.Success && !string.IsNullOrWhiteSpace(resp.Content))
        {
            TranscriptChunkReceived?.Invoke(resp.Content);
            return new VoiceAgentCommandResult
            {
                Success = true,
                ReplyText = resp.Content,
                ActiveProvider = resp.ActiveProvider,
                ExecutedTools = executedTools,
                ToolOutputs = toolOutputs
            };
        }

        return new VoiceAgentCommandResult
        {
            Success = false,
            ReplyText = resp.ErrorMessage ?? "Gemma 4 E2B AI engine is currently offline.",
            ActiveProvider = resp.ActiveProvider
        };
    }

    public async Task StartAsync(string licenseKey, string machineFingerprint, SystemContextPayload systemMetrics, CancellationToken ct)
    {
        if (State != VoiceAgentState.Idle)
        {
            _log.LogWarning("[VoiceEngine] StartAsync called while not idle (state={State})", State);
            return;
        }

        SetState(VoiceAgentState.Connecting);

        // 1. License check via sovereign server — gets proxy WSS URL + session token
        var tokenResp = await _gateway.RequestSessionAsync(licenseKey, machineFingerprint, ct);
        if (tokenResp is null)
        {
            // Fallback to Local/Hybrid Gemma 4 E2B mode if enabled
            if (GemmaAiEngine.Instance.Mode != GemmaExecutionMode.Disabled)
            {
                _log.LogInformation("[VoiceEngine] Cloud voice proxy unavailable; running in Gemma 4 E2B hybrid assistant mode.");
                _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                _functionCallCount = 0;
                _sessionTimer.Restart();
                SetState(VoiceAgentState.Live);
                TranscriptChunkReceived?.Invoke("Gemma 4 E2B Local/Hybrid Assistant ready.");
                return;
            }

            SetState(VoiceAgentState.Error);
            ErrorOccurred?.Invoke("Voice Agent requires an active Pro license or Gemma 4 E2B AI Engine enabled.");
            return;
        }

        // 2. Build Live setup with function declarations and system context
        string systemPrompt = $"You are LogicFlow Guardian OS. Your system state is:\n{systemMetrics.ToJson()}";

        var setup = new LiveSetup
        {
            Setup = new LiveSetup.SetupBody
            {
                Model = "models/gemini-3.1-flash-live",
                GenerationConfig = new GenerationConfig
                {
                    ThinkingConfig = new ThinkingConfig { ThinkingBudget = "low" },
                },
                SystemInstruction = new SystemInstruction { Parts = [ new Part { Text = systemPrompt } ] },
                Tools =
                [
                    new ToolDeclaration
                    {
                        FunctionDeclarations = LogicFlowFunctionDispatcher.GetDeclarations()
                    }
                ],
            }
        };

        // 3. Connect WebSocket to THE PROXY (using tokenResp.ProxyWssUrl)
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _sessionCts.CancelAfter(TimeSpan.FromSeconds(tokenResp.MaxSessionSeconds));

        _session = new GeminiLiveSession(
            apiKey: tokenResp.SessionToken,
            setupMsg: setup,
            log: _log,
            proxyWssUrl: tokenResp.ProxyWssUrl);

        _session.TextReceived    += txt   => TranscriptChunkReceived?.Invoke(txt);
        _session.AudioReceived   += bytes => _speaker.EnqueueBytes(bytes);
        _session.TurnComplete    += ()    => _log.LogDebug("[VoiceEngine] Turn complete");
        _session.FunctionCallReceived += async call =>
        {
            _functionCallCount++;
            FunctionExecuted?.Invoke(call.Name);
            return await _dispatcher.DispatchAsync(call);
        };

        try
        {
            await _session.ConnectAsync(_sessionCts.Token);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[VoiceEngine] Failed to connect to proxy");
            SetState(VoiceAgentState.Error);
            ErrorOccurred?.Invoke("Failed to connect to LogicFlow Voice Server. Check your connection.");
            return;
        }

        _activeSessionToken = tokenResp.SessionToken;
        _functionCallCount  = 0;
        _sessionTimer.Restart();

        // 4. Start mic streaming
        _mic.Start(_session, _sessionCts.Token);

        SetState(VoiceAgentState.Live);
        _log.LogInformation("[VoiceEngine] Voice session is LIVE. Max={Max}s Quota={Q}s",
            tokenResp.MaxSessionSeconds, tokenResp.QuotaRemainingSeconds);
    }

    // ── Stop session ─────────────────────────────────────────────────────

    public async Task StopAsync()
    {
        if (State == VoiceAgentState.Idle) return;
        SetState(VoiceAgentState.Stopping);

        _mic.Stop();
        _sessionCts?.Cancel();

        if (_session is not null)
            await _session.CloseAsync(CancellationToken.None);

        _sessionTimer.Stop();
        var duration = (int)_sessionTimer.Elapsed.TotalSeconds;

        // Report billing to sovereign server (fire-and-forget)
        if (!string.IsNullOrEmpty(_activeSessionToken))
            _gateway.ReportSessionEnd(_activeSessionToken, duration, _functionCallCount);

        _log.LogInformation("[VoiceEngine] Session ended. Duration={D}s FunctionCalls={F}",
            duration, _functionCallCount);

        _session = null;
        SetState(VoiceAgentState.Idle);
    }

    private void SetState(VoiceAgentState state)
    {
        State = state;
        StateChanged?.Invoke(state);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _sessionCts?.Dispose();
    }
}
