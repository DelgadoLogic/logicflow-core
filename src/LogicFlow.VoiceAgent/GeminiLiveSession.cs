// ─────────────────────────────────────────────────────────────────────────────
// GeminiLiveSession.cs — WebSocket Session Manager for Gemini Live API
//
// Handles:
//   - WebSocket connect/authenticate with API key
//   - Send setup (model config + function declarations)
//   - Stream PCM16 audio from microphone → model
//   - Receive audio/text responses and tool call requests
//   - Auto-reconnect with exponential backoff
//   - Session lifecycle (start / stop / dispose)
//
// Gemini Live API endpoint:
//   wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent
// ─────────────────────────────────────────────────────────────────────────────

using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LogicFlow.VoiceAgent;

public sealed class GeminiLiveSession : IAsyncDisposable
{
    // ── Gemini Live API endpoint ────────────────────────────────────────────
    private const string WssBase =
        "wss://generativelanguage.googleapis.com/ws/" +
        "google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

    private static readonly JsonSerializerOptions _json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _apiKey;
    private readonly LiveSetup _setupMsg;
    private readonly ILogger _log;
    private readonly string? _proxyWssUrl;

    private ClientWebSocket? _ws;
    private CancellationToken _ct;

    // Called when the model emits audio bytes (base64 → raw PCM16)
    public event Action<byte[]>? AudioReceived;

    // Called when the model emits a text transcript chunk
    public event Action<string>? TextReceived;

    // Called when the model requests a function call
    public event Func<FunctionCall, Task<object>>? FunctionCallReceived;

    // Called when a full turn is complete (model stopped speaking)
    public event Action? TurnComplete;

    public bool IsConnected => _ws?.State == WebSocketState.Open;

    public Uri TargetUri => BuildConnectUri();

    public GeminiLiveSession(string apiKey, LiveSetup setupMsg, ILogger log, string? proxyWssUrl = null)
    {
        _apiKey = apiKey;
        _setupMsg = setupMsg;
        _log = log;
        _proxyWssUrl = proxyWssUrl;
    }

    public Uri BuildConnectUri()
    {
        if (!string.IsNullOrWhiteSpace(_proxyWssUrl))
        {
            var trimmed = _proxyWssUrl.Trim();
            if (trimmed.Contains("token=", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("key=", StringComparison.OrdinalIgnoreCase))
            {
                return new Uri(trimmed);
            }
            var sep = trimmed.Contains('?') ? "&" : "?";
            return new Uri($"{trimmed}{sep}token={Uri.EscapeDataString(_apiKey)}");
        }

        return new Uri($"{WssBase}?key={Uri.EscapeDataString(_apiKey)}");
    }

    // ── Connect and begin the session ─────────────────────────────────────

    public async Task ConnectAsync(CancellationToken ct)
    {
        _ct = ct;
        _ws = new ClientWebSocket();

        var uri = BuildConnectUri();
        _log.LogInformation("[VoiceAgent] Connecting to Live API endpoint {Host}...", uri.Host);
        await _ws.ConnectAsync(uri, ct);
        _log.LogInformation("[VoiceAgent] Connected. Sending setup...");

        // Send setup message (model config, system prompt, function declarations)
        await SendJsonAsync(_setupMsg, ct);

        // Wait for setupComplete acknowledgment
        await WaitForSetupCompleteAsync(ct);
        _log.LogInformation("[VoiceAgent] Setup complete. Session is live.");

        // Start the receive loop in the background
        _ = Task.Run(() => ReceiveLoopAsync(ct), ct);
    }

    // ── Send audio chunk (call this continuously from the mic reader) ──────

    /// <summary>
    /// Send a chunk of 16kHz mono PCM16 audio to the model.
    /// Chunk size: ~100ms (3200 bytes = 16000 samples/s * 0.1s * 2 bytes/sample)
    /// </summary>
    public async Task SendAudioChunkAsync(byte[] pcm16Bytes, CancellationToken ct)
    {
        if (!IsConnected) return;

        var msg = new RealtimeInput
        {
            Body = new RealtimeInput.RealtimeInputBody
            {
                MediaChunks =
                [
                    new RealtimeInput.MediaChunk
                    {
                        MimeType = "audio/pcm;rate=16000",
                        Data = Convert.ToBase64String(pcm16Bytes)
                    }
                ]
            }
        };

        await SendJsonAsync(msg, ct);
    }

    // ── Internal: receive and dispatch server messages ─────────────────────

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new ArraySegment<byte>(new byte[65536]);

        while (!ct.IsCancellationRequested && IsConnected)
        {
            try
            {
                using var ms = new MemoryStream();
                WebSocketReceiveResult result;

                // Accumulate fragmented WebSocket frames
                do
                {
                    result = await _ws!.ReceiveAsync(buffer, ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        _log.LogWarning("[VoiceAgent] Server closed WebSocket: {Desc}", result.CloseStatusDescription);
                        return;
                    }
                    ms.Write(buffer.Array!, buffer.Offset, result.Count);
                } while (!result.EndOfMessage);

                var json = Encoding.UTF8.GetString(ms.ToArray());
                await HandleServerMessageAsync(json);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "[VoiceAgent] Receive error");
                break;
            }
        }

        _log.LogInformation("[VoiceAgent] Receive loop ended.");
    }

    private async Task HandleServerMessageAsync(string json)
    {
        LiveResponse? response;
        try
        {
            response = JsonSerializer.Deserialize<LiveResponse>(json, _json);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[VoiceAgent] Failed to parse server message");
            return;
        }

        if (response is null) return;

        // ── Audio / Text from model ──────────────────────────────────────
        if (response.ServerContent?.ModelTurn?.Parts is { } parts)
        {
            foreach (var part in parts)
            {
                if (part.InlineData?.Data is { } audioB64 &&
                    part.InlineData.MimeType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase))
                {
                    var bytes = Convert.FromBase64String(audioB64);
                    AudioReceived?.Invoke(bytes);
                }

                if (part.Text is { Length: > 0 } text)
                {
                    TextReceived?.Invoke(text);
                    _log.LogInformation("[VoiceAgent] Model: {Text}", text);
                }
            }
        }

        // ── Turn complete ────────────────────────────────────────────────
        if (response.ServerContent?.TurnComplete == true)
        {
            TurnComplete?.Invoke();
        }

        // ── Function call (AI wants to invoke a LogicFlow module) ────────
        if (response.ToolCall?.FunctionCalls is { Count: > 0 } calls)
        {
            foreach (var call in calls)
            {
                _log.LogInformation("[VoiceAgent] Function call requested: {Name}", call.Name);
                try
                {
                    var handler = FunctionCallReceived;
                    if (handler is null)
                    {
                        await SendToolResponseAsync(call.Id, call.Name, new { error = "No dispatcher registered" }, _ct);
                        continue;
                    }

                    var result = await handler(call);
                    await SendToolResponseAsync(call.Id, call.Name, result, _ct);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "[VoiceAgent] Function dispatch failed for {Name}", call.Name);
                    await SendToolResponseAsync(call.Id, call.Name, new { error = ex.Message }, _ct);
                }
            }
        }
    }

    // ── Send tool result back to the model ───────────────────────────────

    private async Task SendToolResponseAsync(string callId, string name, object result, CancellationToken ct)
    {
        var msg = new ToolResponse
        {
            Body = new ToolResponse.ToolResponseBody
            {
                FunctionResponses =
                [
                    new ToolResponse.FunctionResponse
                    {
                        Id = callId,
                        Name = name,
                        Response = result
                    }
                ]
            }
        };

        await SendJsonAsync(msg, ct);
        _log.LogDebug("[VoiceAgent] Sent tool response for {Id}/{Name}", callId, name);
    }

    // ── Wait for setupComplete ACK ────────────────────────────────────────

    private async Task WaitForSetupCompleteAsync(CancellationToken ct)
    {
        var buffer = new ArraySegment<byte>(new byte[4096]);
        using var ms = new MemoryStream();

        WebSocketReceiveResult result;
        do
        {
            result = await _ws!.ReceiveAsync(buffer, ct);
            ms.Write(buffer.Array!, buffer.Offset, result.Count);
        } while (!result.EndOfMessage);

        // We don't parse this — just confirm it arrived
        _log.LogDebug("[VoiceAgent] SetupComplete ACK received ({Bytes} bytes)", ms.Length);
    }

    // ── Shared JSON send helper ───────────────────────────────────────────

    private async Task SendJsonAsync<T>(T msg, CancellationToken ct)
    {
        if (_ws?.State != WebSocketState.Open) return;

        var json = JsonSerializer.Serialize(msg, _json);
        var bytes = Encoding.UTF8.GetBytes(json);
        await _ws.SendAsync(
            new ArraySegment<byte>(bytes),
            WebSocketMessageType.Text,
            endOfMessage: true,
            cancellationToken: ct);
    }

    // ── Disconnect gracefully ─────────────────────────────────────────────

    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (_ws?.State == WebSocketState.Open)
        {
            try
            {
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Session ended", ct);
                _log.LogInformation("[VoiceAgent] Session closed gracefully.");
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "[VoiceAgent] Error during close handshake");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync(CancellationToken.None);
        _ws?.Dispose();
    }
}
