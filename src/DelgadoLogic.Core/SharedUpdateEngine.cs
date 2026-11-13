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

using System.IO;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;

[assembly: InternalsVisibleTo("LogicFlow.Tests")]

namespace DelgadoLogic.Core;

/// <summary>
/// Sovereign update engine for all DelgadoLogic products.
/// Connects to the sovereign update endpoint, fetches canonical Ed25519-signed JSON envelopes,
/// verifies them cryptographically, and returns verified upgrade metadata.
/// </summary>
public sealed class SharedUpdateEngine : IAsyncDisposable
{
    // ─── Sovereign Infrastructure (proxied via api.delgadologic.tech → Cloud Run) ───
    private const string UpdateServerBase =
        "https://api.delgadologic.tech";

    // Ed25519 public key — embedded, never changes without a new binary release.
    // The corresponding private key lives ONLY in GCP Secret Manager.
    // This is the same key used by AutoUpdater.cpp in Aeon Browser native.
    private static byte[] SovereignPublicKey = Convert.FromBase64String(
        "BfoHnS014mgux9fNHwe0zzRPEqVoy0OOJ+5tVvfu3a4=");

    private static readonly Regex Hex64Regex = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);

    private readonly ILogger _logger;
    private readonly ProductManifest _manifest;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _baseUrl;

    public SharedUpdateEngine(ILogger logger, ProductManifest manifest)
    {
        _logger   = logger;
        _manifest = manifest;
        _baseUrl  = UpdateServerBase;
        _ownsHttp = true;
        _http     = new HttpClient
        {
            Timeout    = TimeSpan.FromSeconds(15),
            DefaultRequestHeaders =
            {
                { "User-Agent", $"DelgadoLogic-{manifest.Product}/{manifest.Version}" }
            }
        };
    }

    internal SharedUpdateEngine(
        ILogger logger,
        ProductManifest manifest,
        HttpClient httpClient,
        string? baseUrlOverride = null)
    {
        _logger   = logger;
        _manifest = manifest;
        _http     = httpClient;
        _ownsHttp = false;
        _baseUrl  = string.IsNullOrWhiteSpace(baseUrlOverride) ? UpdateServerBase : baseUrlOverride.TrimEnd('/');
    }

    // ─── Public API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Checks for an update on the sovereign update server.
    /// Verifies canonical sorted-key JSON Ed25519 signatures and fail-closed SHA-256 / HTTPS URL rules.
    /// Returns null if already up to date, tampered, or unreachable.
    /// </summary>
    public async Task<UpdateManifest?> CheckAsync(
        string channel = "stable",
        CancellationToken ct = default)
    {
        var product = _manifest.Product.ToString().ToLowerInvariant();
        var url     = $"{_baseUrl}/v1/update/{product}/{channel}";

        try
        {
            _logger.LogInformation("[Update] Checking {Product}/{Channel} at {Url}",
                product, channel, url);

            using var response = await _http.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("[Update] Server returned {Status} — no update available.",
                    response.StatusCode);
                return null;
            }

            var rawJson = await response.Content.ReadAsStringAsync(ct);
            if (!TryParseAndVerifyEnvelope(rawJson, out var manifest, out var status) || manifest is null)
            {
                _logger.LogError("[Update] ⚠️ SIGNATURE VERIFICATION FAILED — manifest rejected. " +
                    "Possible MITM or tampered manifest.");
                return null;
            }

            if (string.Equals(status, "no_update", StringComparison.OrdinalIgnoreCase) ||
                !IsNewerVersion(manifest.Version, _manifest.Version))
            {
                _logger.LogInformation("[Update] Already at latest version {Version}.",
                    _manifest.Version);
                return null;
            }

            if (!IsTrustedHttpsUrl(manifest.DownloadUrl) || !Hex64Regex.IsMatch(manifest.Sha256 ?? ""))
            {
                _logger.LogError("[Update] ⚠️ Signed manifest missing valid HTTPS download_url or 64-hex sha256.");
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

    internal static bool TryParseAndVerifyEnvelope(
        string rawJson,
        out UpdateManifest? manifest,
        out string status)
    {
        manifest = null;
        status = "";
        if (string.IsNullOrWhiteSpace(rawJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            JsonElement manifestElem;
            string? sigB64 = null;

            if (root.TryGetProperty("manifest", out var nested) && nested.ValueKind == JsonValueKind.Object)
            {
                manifestElem = nested;
                if (root.TryGetProperty("signature", out var topSig) && topSig.ValueKind == JsonValueKind.String)
                    sigB64 = topSig.GetString();
                else if (nested.TryGetProperty("signature", out var innerSig) && innerSig.ValueKind == JsonValueKind.String)
                    sigB64 = innerSig.GetString();
            }
            else
            {
                manifestElem = root;
                if (root.TryGetProperty("signature", out var flatSig) && flatSig.ValueKind == JsonValueKind.String)
                    sigB64 = flatSig.GetString();
            }

            if (string.IsNullOrWhiteSpace(sigB64))
                return false;

            string canonicalJson = BuildCanonicalJsonPayload(manifestElem);
            if (!VerifyCanonicalJsonSignature(canonicalJson, sigB64))
                return false;

            status = GetStringProp(manifestElem, "status", "Status");
            var ch = GetStringProp(manifestElem, "channel", "Channel");
            var parsed = new UpdateManifest
            {
                Product      = GetStringProp(manifestElem, "product", "Product"),
                Channel      = string.IsNullOrWhiteSpace(ch) ? "stable" : ch,
                Version      = GetStringProp(manifestElem, "version", "Version"),
                DownloadUrl  = GetStringProp(manifestElem, "download_url", "downloadUrl", "DownloadUrl"),
                Sha256       = GetStringProp(manifestElem, "sha256", "Sha256"),
                ReleaseNotes = GetStringProp(manifestElem, "release_notes", "releaseNotes", "ReleaseNotes"),
                Signature    = sigB64,
                CanonicalJson = canonicalJson,
                SizeBytes    = GetInt64Prop(manifestElem, "size_bytes", "sizeBytes", "SizeBytes"),
            };

            var pubRaw = GetStringProp(manifestElem, "ts", "published_at", "publishedAt", "PublishedAt");
            if (DateTimeOffset.TryParse(pubRaw, out var dto))
                parsed.PublishedAt = dto;

            if (string.IsNullOrWhiteSpace(parsed.Version))
                return false;

            manifest = parsed;
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal static string BuildCanonicalJsonPayload(JsonElement element)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions
        {
            Indented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }))
        {
            WriteCanonicalElement(writer, element, isRootObject: true);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void WriteCanonicalElement(Utf8JsonWriter writer, JsonElement elem, bool isRootObject)
    {
        switch (elem.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                var props = new List<JsonProperty>();
                foreach (var prop in elem.EnumerateObject())
                {
                    if (isRootObject && string.Equals(prop.Name, "signature", StringComparison.OrdinalIgnoreCase))
                        continue;
                    props.Add(prop);
                }
                props.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
                foreach (var prop in props)
                {
                    writer.WritePropertyName(prop.Name);
                    WriteCanonicalElement(writer, prop.Value, isRootObject: false);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in elem.EnumerateArray())
                    WriteCanonicalElement(writer, item, isRootObject: false);
                writer.WriteEndArray();
                break;

            default:
                elem.WriteTo(writer);
                break;
        }
    }

    private static bool VerifyCanonicalJsonSignature(string canonicalJson, string signatureBase64)
    {
        try
        {
            var payloadBytes = Encoding.UTF8.GetBytes(canonicalJson);
            var sigBytes = Convert.FromBase64String(signatureBase64);
            if (sigBytes.Length != 64)
                return false;

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

    private static bool VerifySignature(UpdateManifest manifest)
    {
        try
        {
            if (string.IsNullOrEmpty(manifest.Signature))
                return false;

            if (!string.IsNullOrEmpty(manifest.CanonicalJson))
                return VerifyCanonicalJsonSignature(manifest.CanonicalJson, manifest.Signature);

            // Legacy fallback for direct in-memory UpdateManifest unit tests without raw JSON envelope
            var payload = $"{manifest.Product}|{manifest.Channel}|{manifest.Version}" +
                          $"|{manifest.DownloadUrl}|{manifest.Sha256}";
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var sigBytes     = Convert.FromBase64String(manifest.Signature);
            if (sigBytes.Length != 64)
                return false;

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

    private static bool IsTrustedHttpsUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        var host = uri.Host.ToLowerInvariant();
        return host == "delgadologic.tech" ||
               host.EndsWith(".delgadologic.tech", StringComparison.Ordinal) ||
               host == "github.com" ||
               host.EndsWith(".githubusercontent.com", StringComparison.Ordinal) ||
               host == "storage.googleapis.com";
    }

    private static string GetStringProp(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString() ?? "";
        }
        return "";
    }

    private static long GetInt64Prop(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.Number && prop.TryGetInt64(out var val))
                return val;
        }
        return 0;
    }

    private static bool IsNewerVersion(string remoteVer, string localVer)
    {
        if (Version.TryParse(remoteVer.TrimStart('v', 'V'), out var remote) &&
            Version.TryParse(localVer.TrimStart('v', 'V'), out var local))
        {
            return remote > local;
        }
        return false;
    }

    public ValueTask DisposeAsync()
    {
        if (_ownsHttp)
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
    internal string? CanonicalJson { get; set; }
}
