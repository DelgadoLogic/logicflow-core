// OmniCore.Engine — AutoUpdateEngine
// Sovereign update client — calls api.delgadologic.tech
// Ed25519 signature verified before ANY update is applied.
// Used by: OmniService (background service) + LogicFlow.Dashboard (UI prompt)

using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;

namespace OmniCore.Engine;

/// <summary>
/// Result of a sovereign update check against api.delgadologic.tech
/// </summary>
public sealed record UpdateCheckResult(
    bool UpdateAvailable,
    string CurrentVersion,
    string LatestVersion,
    string? DownloadUrl,
    string? ReleaseNotes,
    string? Signature
);

/// <summary>
/// Calls the sovereign update server, verifies the Ed25519 manifest signature,
/// and determines whether a newer version of LogicFlow is available.
/// </summary>
public sealed class AutoUpdateEngine
{
    // ─── Sovereign Update Endpoint ───────────────────────────────────────────
    // Proxied: api.delgadologic.tech → Firebase → Cloud Run (aeon-update-server)
    private const string UpdateUrl =
        "https://api.delgadologic.tech/v1/update/logicflow/stable";

    // ─── Sovereign Public Key (Ed25519, PEM) ─────────────────────────────────
    // Generated 2026-03-27 by DelgadoLogic sovereign key ceremony.
    // Secret Manager: projects/aeon-browser-build/secrets/aeon-sovereign-signing-key/versions/2
    // This key is PINNED at build time. To rotate: update key + re-ship client.
    // Public counterpart published at:
    //   https://raw.githubusercontent.com/DelgadoLogic/aeon-sovereign/main/keys/aeon_sovereign_v1.pub.pem
    private const string SovereignPublicKeyPem =
        """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEABfoHnS014mgux9fNHwe0zzRPEqVoy0OOJ+5tVvfu3a4=
        -----END PUBLIC KEY-----
        """;

    // ─── Current Client Version ───────────────────────────────────────────────
    // Update this constant on every release. Matches AssemblyVersion.
    public const string CurrentVersion = "1.0.0";

    // ─── HTTP Client (singleton, thread-safe) ────────────────────────────────
    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
        DefaultRequestHeaders =
        {
            { "User-Agent", $"LogicFlow/{CurrentVersion} (Windows; DelgadoLogic)" },
            { "Accept", "application/json" },
            { "X-Client-Product", "logicflow" },
        }
    };

    private readonly ILogger<AutoUpdateEngine> _logger;

    public AutoUpdateEngine(ILogger<AutoUpdateEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Checks the sovereign server for a newer LogicFlow version.
    /// Signature is verified cryptographically before trusting any data.
    /// Returns null only on network failure or tampered response.
    /// </summary>
    public async Task<UpdateCheckResult?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("[AutoUpdate] Checking sovereign server at {Url}", UpdateUrl);

            var response = await _http.GetFromJsonAsync<SovereignResponse>(
                UpdateUrl,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true },
                ct);

            if (response?.Manifest is null)
            {
                _logger.LogWarning("[AutoUpdate] Empty or invalid response from sovereign server.");
                return null;
            }

            // ── Critical: verify before trusting anything ──
            if (!VerifySignature(response.Manifest, response.Signature))
            {
                _logger.LogError(
                    "[AutoUpdate] ⚠ SIGNATURE VERIFICATION FAILED. " +
                    "Manifest may be tampered. Ignoring update.");
                return null;
            }

            var manifest = response.Manifest;
            _logger.LogInformation(
                "[AutoUpdate] ✓ Signature verified. Server version: {Ver} | Status: {Status}",
                manifest.Version, manifest.Status);

            bool updateAvailable =
                manifest.Status != "no_update" &&
                IsNewer(manifest.Version, CurrentVersion);

            return new UpdateCheckResult(
                UpdateAvailable: updateAvailable,
                CurrentVersion: CurrentVersion,
                LatestVersion: manifest.Version,
                DownloadUrl: manifest.DownloadUrl,
                ReleaseNotes: manifest.ReleaseNotes,
                Signature: response.Signature
            );
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("[AutoUpdate] Update check timed out (15s). Will retry in 24h.");
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "[AutoUpdate] Network error reaching sovereign server.");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[AutoUpdate] Unexpected error during update check (non-fatal).");
            return null;
        }
    }

    // ─── Ed25519 Signature Verification ─────────────────────────────────────
    // Uses .NET 8 native Ed25519 support — no third-party dependencies.

    private static bool VerifySignature(UpdateManifest manifest, string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature))
        {
            return false;
        }

        try
        {
            // Canonical serialization must match server-side: sort_keys=True, no spaces
            var canonicalPayload = JsonSerializer.Serialize(manifest,
                new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                    WriteIndented = false,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                });

            var payloadBytes = Encoding.UTF8.GetBytes(canonicalPayload);
            var sigBytes = Convert.FromBase64String(signature);
            var pubKeyBytes = GetRawPublicKeyFromPem(SovereignPublicKeyPem);

            var verifier = new Ed25519Signer();
            var publicKeyParam = new Ed25519PublicKeyParameters(pubKeyBytes, 0);
            verifier.Init(false, publicKeyParam);
            verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);

            return verifier.VerifySignature(sigBytes);
        }
        catch (Exception)
        {
            // Malformed key, bad base64, etc. — treat as tampering
            return false;
        }
    }

    private static byte[] GetRawPublicKeyFromPem(string pem)
    {
        var lines = pem.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        var base64 = string.Join("", lines.Where(l => !l.StartsWith("-----")));
        var fullBytes = Convert.FromBase64String(base64);

        if (fullBytes.Length == 32)
        {
            return fullBytes;
        }
        else if (fullBytes.Length == 44) // SubjectPublicKeyInfo structure
        {
            var rawKey = new byte[32];
            Array.Copy(fullBytes, 12, rawKey, 0, 32);
            return rawKey;
        }
        
        throw new CryptographicException("Invalid Ed25519 public key format.");
    }

    // ─── Version Comparison ──────────────────────────────────────────────────

    private static bool IsNewer(string serverVersion, string clientVersion)
    {
        if (!Version.TryParse(serverVersion, out var sv)) return false;
        if (!Version.TryParse(clientVersion, out var cv)) return false;
        return sv > cv;
    }

    // ─── Response / Manifest Models ──────────────────────────────────────────

    private sealed class SovereignResponse
    {
        [JsonPropertyName("manifest")]
        public UpdateManifest? Manifest { get; set; }

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        [JsonPropertyName("pubkey_url")]
        public string? PubkeyUrl { get; set; }
    }

    private sealed class UpdateManifest
    {
        [JsonPropertyName("product")]
        public string Product { get; set; } = "logicflow";

        [JsonPropertyName("channel")]
        public string Channel { get; set; } = "stable";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "0.0.0";

        [JsonPropertyName("status")]
        public string Status { get; set; } = "no_update";

        [JsonPropertyName("download_url")]
        public string? DownloadUrl { get; set; }

        [JsonPropertyName("release_notes")]
        public string? ReleaseNotes { get; set; }

        [JsonPropertyName("min_os")]
        public string? MinOs { get; set; }

        [JsonPropertyName("sha256")]
        public string? Sha256 { get; set; }

        [JsonPropertyName("size_bytes")]
        public long? SizeBytes { get; set; }

        [JsonPropertyName("ts")]
        public string? Ts { get; set; }
    }
}
