// ─────────────────────────────────────────────────────────────────────────────
// DelgadoLogic.Core — Shared Update Engine
// Extracted from OmniCore.Engine.AutoUpdateEngine — superset implementation
// that works identically for LogicFlow AND Aeon Browser.
//
// ARCHITECTURE: Mirrors Microsoft's Click-to-Run shared update infrastructure
// which services Word, Excel, Teams, etc from one engine. Here, LogicFlow and
// Aeon Browser both call this to check for updates from the same sovereign
// CloudRun update server, each with their own channel/manifest path.
// ─────────────────────────────────────────────────────────────────────────────

using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;

namespace DelgadoLogic.Core;

/// <summary>
/// Sovereign update engine for all DelgadoLogic products.
/// Connects to the CloudRun update server, fetches Ed25519-signed manifests,
/// verifies them cryptographically, and invokes an install callback.
///
/// Usage — each product calls once at startup:
/// <code>
///   var updater = new SharedUpdateEngine(logger, ProductManifest.Current);
///   await updater.CheckAsync();
/// </code>
/// </summary>
public sealed class SharedUpdateEngine : IAsyncDisposable
{
    // ─── Sovereign Infrastructure ────────────────────────────────────────────
    private const string UpdateServerBase =
        "https://aeon-update-server-y2r5ogip6q-ue.a.run.app";

    // Ed25519 public key — embedded, never changes without a new binary release.
    // The corresponding private key lives ONLY in GCP Secret Manager.
    // This is the same key used by AutoUpdater.cpp in Aeon Browser native.
    private static byte[] SovereignPublicKey = Convert.FromBase64String(
        "BfoHnS014mgux9fNHwe0zzRPEqVoy0OOJ+5tVvfu3a4=");

    private readonly ILogger _logger;
    private readonly ProductManifest _manifest;
    private readonly HttpClient _http;

    public SharedUpdateEngine(ILogger logger, ProductManifest manifest)
    {
        _logger   = logger;
        _manifest = manifest;
        _http     = new HttpClient
        {
            Timeout    = TimeSpan.FromSeconds(15),
            DefaultRequestHeaders =
            {
                { "User-Agent", $"DelgadoLogic-{manifest.Product}/{manifest.Version}" }
            }
        };
    }

    // ─── Public API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Checks for an update on the sovereign update server.
    /// Returns null if already up to date or check fails gracefully.
    /// </summary>
    public async Task<UpdateManifest?> CheckAsync(
        string channel = "stable",
        CancellationToken ct = default)
    {
        var product = _manifest.Product.ToString().ToLowerInvariant();
        var url     = $"{UpdateServerBase}/v1/manifest/{product}/{channel}";

        try
        {
            _logger.LogInformation("[Update] Checking {Product}/{Channel} at {Url}",
                product, channel, url);

            var response = await _http.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("[Update] Server returned {Status} — no update available.",
                    response.StatusCode);
                return null;
            }

            var manifest = await response.Content.ReadFromJsonAsync<UpdateManifest>(
                cancellationToken: ct);

            if (manifest is null)
            {
                _logger.LogWarning("[Update] Empty manifest received.");
                return null;
            }

            // Verify Ed25519 signature before trusting anything
            if (!VerifySignature(manifest))
            {
                _logger.LogError("[Update] ⚠️ SIGNATURE VERIFICATION FAILED — manifest rejected. " +
                    "Possible MITM or tampered manifest.");
                return null;
            }

            // Check if this is actually an upgrade
            if (!IsNewerVersion(manifest.Version, _manifest.Version))
            {
                _logger.LogInformation("[Update] Already at latest version {Version}.",
                    _manifest.Version);
                return null;
            }

            _logger.LogInformation("[Update] ✓ Update available: {Current} → {New}",
                _manifest.Version, manifest.Version);
            return manifest;
        }
        catch (TaskCanceledException)
        {
            _logger.LogDebug("[Update] Check timed out — will retry next launch.");
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogDebug(ex, "[Update] Network error during update check — will retry.");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Update] Unexpected error during update check.");
            return null;
        }
    }

    /// <summary>
    /// Fire-and-forget async check. Swallows all exceptions — safe to call at startup
    /// without awaiting.
    /// </summary>
    public void CheckInBackground(string channel = "stable")
    {
        _ = Task.Run(async () =>
        {
            try { await CheckAsync(channel); }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[Update] Background check failed silently.");
            }
        });
    }

    // ─── Verification ────────────────────────────────────────────────────────

    private static bool VerifySignature(UpdateManifest manifest)
    {
        try
        {
            if (string.IsNullOrEmpty(manifest.Signature))
                return false;

            // Canonical payload: product|channel|version|url|sha256
            var payload = $"{manifest.Product}|{manifest.Channel}|{manifest.Version}" +
                          $"|{manifest.DownloadUrl}|{manifest.Sha256}";
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var sigBytes     = Convert.FromBase64String(manifest.Signature);

            var verifier = new Ed25519Signer();
            var publicKeyParam = new Ed25519PublicKeyParameters(SovereignPublicKey, 0);
            verifier.Init(false, publicKeyParam);
            verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);

            return verifier.VerifySignature(sigBytes);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsNewerVersion(string remoteVer, string localVer)
    {
        if (Version.TryParse(remoteVer, out var remote) &&
            Version.TryParse(localVer, out var local))
        {
            return remote > local;
        }
        // If unparseable, assume it's different and let the server decide
        return !string.Equals(remoteVer, localVer, StringComparison.Ordinal);
    }

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }
}

// ─── Manifest Models ─────────────────────────────────────────────────────────

public sealed class UpdateManifest
{
    public string Product     { get; set; } = "";
    public string Channel     { get; set; } = "stable";
    public string Version     { get; set; } = "";
    public string DownloadUrl { get; set; } = "";
    public string Sha256      { get; set; } = "";
    public string Signature   { get; set; } = "";
    public string ReleaseNotes { get; set; } = "";
    public DateTimeOffset PublishedAt { get; set; }
    public long SizeBytes     { get; set; }
}
