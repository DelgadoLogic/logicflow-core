// ─────────────────────────────────────────────────────────────────────────────
// MicrophoneReader.cs — Captures microphone audio and streams to Gemini Live
//
// Reads the default recording device using NAudio (WaveIn).
// Converts to 16kHz mono PCM16 as required by the Gemini Live API.
// Sends 100ms chunks (~3200 bytes each) continuously while live.
// ─────────────────────────────────────────────────────────────────────────────

using NAudio.Wave;
using Microsoft.Extensions.Logging;

namespace LogicFlow.VoiceAgent;

public sealed class MicrophoneReader : IDisposable
{
    // Gemini Live API requires: 16kHz, mono, 16-bit PCM
    private const int SampleRate  = 16000;
    private const int Channels    = 1;
    private const int BitsPerSamp = 16;

    // 100ms chunk: 16000 samples/s * 0.1s * 2 bytes/sample = 3200 bytes
    private const int ChunkMs     = 100;

    private readonly ILogger<MicrophoneReader> _log;
    private WaveInEvent? _waveIn;
    private GeminiLiveSession? _session;
    private CancellationToken _ct;
    private bool _running;

    public MicrophoneReader(ILogger<MicrophoneReader> log)
    {
        _log = log;
    }

    public bool IsMicrophoneAvailable { get; private set; } = true;

    public void Start(GeminiLiveSession session, CancellationToken ct)
    {
        if (_running) return;
        _session = session;
        _ct = ct;

        try
        {
            _waveIn = new WaveInEvent
            {
                WaveFormat         = new WaveFormat(SampleRate, BitsPerSamp, Channels),
                BufferMilliseconds = ChunkMs,
            };

            _waveIn.DataAvailable += OnDataAvailable;
            _waveIn.RecordingStopped += (_, e) =>
            {
                if (e.Exception is not null)
                    _log.LogError(e.Exception, "[Mic] Recording stopped with error");
                else
                    _log.LogInformation("[Mic] Recording stopped.");
            };

            _waveIn.StartRecording();
            _running = true;
            IsMicrophoneAvailable = true;
            _log.LogInformation("[Mic] Started recording: {Rate}Hz {Bits}-bit mono {Chunk}ms chunks",
                SampleRate, BitsPerSamp, ChunkMs);
        }
        catch (Exception ex)
        {
            _running = false;
            IsMicrophoneAvailable = false;
            try { _waveIn?.Dispose(); } catch { }
            _waveIn = null;
            _log.LogWarning(ex, "[Mic] No microphone input device available (e.g. RDP/headless); continuing without live mic stream.");
        }
    }

    private void OnDataAvailable(object? sender, WaveInEventArgs e)
    {
        if (!_running || _session is null || _ct.IsCancellationRequested) return;
        if (e.BytesRecorded == 0) return;

        var chunk = new byte[e.BytesRecorded];
        Buffer.BlockCopy(e.Buffer, 0, chunk, 0, e.BytesRecorded);

        // Fire-and-forget the async send (audio loop must not block WaveIn callback)
        _ = Task.Run(async () =>
        {
            try
            {
                await _session.SendAudioChunkAsync(chunk, _ct);
            }
            catch (OperationCanceledException) { /* session ended */ }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "[Mic] Failed to send audio chunk");
            }
        }, _ct);
    }

    public void Stop()
    {
        if (!_running) return;
        _running = false;

        try
        {
            _waveIn?.StopRecording();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[Mic] Error stopping recording");
        }

        _log.LogInformation("[Mic] Microphone stopped.");
    }

    public void Dispose()
    {
        Stop();
        _waveIn?.Dispose();
        _waveIn = null;
    }
}
