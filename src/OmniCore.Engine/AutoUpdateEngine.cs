// OmniCore.Engine — AutoUpdateEngine
// Sovereign update client — calls api.delgadologic.tech
// Ed25519 signature verified before ANY update is applied.
// Used by: OmniService (background service) + LogicFlow.Dashboard (UI prompt)

using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;

[assembly: InternalsVisibleTo("LogicFlow.Dashboard")]
[assembly: InternalsVisibleTo("LogicFlow.Tests")]

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
)
{
    public string? Sha256 { get; init; }
    public long? SizeBytes { get; init; }
}

public sealed record VerifiedManifestData(
    string Product,
    string Channel,
    string Version,
    string Status,
    string? DownloadUrl,
    string? ReleaseNotes,
    string? Sha256,
    long? SizeBytes,
    string? Tag,
    bool? IsCritical,
    DateTimeOffset? ReleasedAt,
    string? Signature);

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
    private readonly HttpClient _httpClient;
    private readonly string _publicKeyPem;
    private readonly string _endpointUrl;

    public AutoUpdateEngine(ILogger<AutoUpdateEngine> logger)
    {
        _logger = logger;
        _httpClient = _http;
        _publicKeyPem = SovereignPublicKeyPem;
        _endpointUrl = UpdateUrl;
    }

    internal AutoUpdateEngine(
        ILogger<AutoUpdateEngine> logger,
        HttpClient httpClient,
        string? publicKeyPemOverride = null,
        string? endpointOverride = null)
    {
        _logger = logger;
        _httpClient = httpClient;
        _publicKeyPem = string.IsNullOrWhiteSpace(publicKeyPemOverride) ? SovereignPublicKeyPem : publicKeyPemOverride;
        _endpointUrl = string.IsNullOrWhiteSpace(endpointOverride) ? UpdateUrl : endpointOverride;
    }

    private static readonly JsonSerializerOptions SnakeCaseIgnoreNullOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Checks the sovereign server for a newer LogicFlow version.
    /// Signature is verified cryptographically against canonical sorted-key JSON before trusting any data.
    /// Returns null only on network failure or tampered/invalid response.
    /// </summary>
    public async Task<UpdateCheckResult?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("[AutoUpdate] Checking sovereign server at {Url}", _endpointUrl);

            using var httpResponse = await _httpClient.GetAsync(_endpointUrl, ct);
            httpResponse.EnsureSuccessStatusCode();
            var rawJson = await httpResponse.Content.ReadAsStringAsync(ct);

            if (!TryParseAndVerifyEnvelope(rawJson, _publicKeyPem, out var manifest, out var signature))
            {
                _logger.LogError(
                    "[AutoUpdate] ⚠ SIGNATURE VERIFICATION FAILED or invalid envelope. " +
                    "Manifest may be tampered. Ignoring update.");
                return null;
            }

            _logger.LogInformation(
                "[AutoUpdate] ✓ Signature verified. Server version: {Ver} | Status: {Status}",
                manifest!.Version, manifest.Status);

            bool updateAvailable =
                manifest.Status != "no_update" &&
                IsNewer(manifest.Version, CurrentVersion);

            if (updateAvailable)
            {
                if (!IsTrustedHttpsUrl(manifest.DownloadUrl) || !IsValidSha256Hex(manifest.Sha256))
                {
                    _logger.LogError(
                        "[AutoUpdate] ⚠ Manifest for v{Ver} rejected: missing valid HTTPS download_url or 64-hex sha256.",
                        manifest.Version);
                    return null;
                }
            }

            return new UpdateCheckResult(
                UpdateAvailable: updateAvailable,
                CurrentVersion: CurrentVersion,
                LatestVersion: manifest.Version,
                DownloadUrl: manifest.DownloadUrl,
                ReleaseNotes: manifest.ReleaseNotes,
                Signature: signature
            )
            {
                Sha256 = manifest.Sha256,
                SizeBytes = manifest.SizeBytes
            };
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

    public static bool TryParseAndVerifyEnvelope(
        string rawEnvelopeJson,
        string? publicKeyPemOverride,
        out VerifiedManifestData? manifest,
        out string? signature)
    {
        manifest = null;
        signature = null;

        if (string.IsNullOrWhiteSpace(rawEnvelopeJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(rawEnvelopeJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            if (!TryGetPropertyCaseInsensitive(root, "manifest", out var manifestElem) ||
                manifestElem.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (TryGetPropertyCaseInsensitive(root, "signature", out var sigElem) &&
                sigElem.ValueKind == JsonValueKind.String)
            {
                signature = sigElem.GetString();
            }

            if (!VerifyManifestElementSignature(manifestElem, signature, publicKeyPemOverride))
                return false;

            var dto = manifestElem.Deserialize<UpdateManifest>(SnakeCaseIgnoreNullOpts);
            if (dto == null || string.IsNullOrWhiteSpace(dto.Version))
                return false;

            manifest = new VerifiedManifestData(
                dto.Product,
                dto.Channel,
                dto.Version,
                dto.Status,
                dto.DownloadUrl,
                dto.ReleaseNotes,
                dto.Sha256,
                dto.SizeBytes,
                dto.Tag,
                dto.IsCritical,
                dto.ReleasedAt,
                signature);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetPropertyCaseInsensitive(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.TryGetProperty(name, out value))
            return true;

        foreach (var prop in obj.EnumerateObject())
        {
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    // ─── Ed25519 Signature Verification & Canonical JSON ────────────────────

    public static bool VerifyManifestElementSignature(
        JsonElement manifestElement,
        string? signature,
        string? publicKeyPemOverride = null)
    {
        if (manifestElement.ValueKind != JsonValueKind.Object || string.IsNullOrWhiteSpace(signature))
            return false;

        try
        {
            var canonicalPayload = BuildCanonicalManifestJson(manifestElement);
            var payloadBytes = Encoding.UTF8.GetBytes(canonicalPayload);
            var sigBytes = Convert.FromBase64String(signature);
            if (sigBytes.Length != 64)
                return false;

            var pem = string.IsNullOrWhiteSpace(publicKeyPemOverride) ? SovereignPublicKeyPem : publicKeyPemOverride;
            var pubKeyBytes = GetRawPublicKeyFromPem(pem);

            var verifier = new Ed25519Signer();
            var publicKeyParam = new Ed25519PublicKeyParameters(pubKeyBytes, 0);
            verifier.Init(false, publicKeyParam);
            verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);

            return verifier.VerifySignature(sigBytes);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifySignature(UpdateManifest manifest, string? signature)
    {
        if (manifest is null || string.IsNullOrWhiteSpace(signature))
            return false;

        try
        {
            var element = JsonSerializer.SerializeToElement(manifest, SnakeCaseIgnoreNullOpts);
            return VerifyManifestElementSignature(element, signature);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Produces canonical JSON identical to Python's json.dumps(obj, sort_keys=True, separators=(",", ":")).
    /// </summary>
    public static string BuildCanonicalManifestJson(JsonElement element)
    {
        var sb = new StringBuilder(256);
        AppendCanonicalElement(sb, element);
        return sb.ToString();
    }

    private static void AppendCanonicalElement(StringBuilder sb, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append('{');
                var props = new List<JsonProperty>();
                foreach (var p in element.EnumerateObject())
                    props.Add(p);
                props.Sort(static (a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));
                for (int i = 0; i < props.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    AppendCanonicalString(sb, props[i].Name);
                    sb.Append(':');
                    AppendCanonicalElement(sb, props[i].Value);
                }
                sb.Append('}');
                break;

            case JsonValueKind.Array:
                sb.Append('[');
                bool first = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!first) sb.Append(',');
                    first = false;
                    AppendCanonicalElement(sb, item);
                }
                sb.Append(']');
                break;

            case JsonValueKind.String:
                AppendCanonicalString(sb, element.GetString() ?? string.Empty);
                break;

            case JsonValueKind.Number:
                sb.Append(element.GetRawText());
                break;

            case JsonValueKind.True:
                sb.Append("true");
                break;

            case JsonValueKind.False:
                sb.Append("false");
                break;

            case JsonValueKind.Null:
            default:
                sb.Append("null");
                break;
        }
    }

    private static void AppendCanonicalString(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (char c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7E)
                    {
                        sb.Append("\\u");
                        sb.Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    // ─── Binary Integrity Helpers (Fail-Closed SHA-256) ─────────────────────

    public static bool IsTrustedHttpsUrl(string? url)
    {
        return !string.IsNullOrWhiteSpace(url) &&
               Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
               string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsValidSha256Hex(string? hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
            return false;
        var trimmed = hash.Trim();
        if (trimmed.Length != 64)
            return false;
        for (int i = 0; i < trimmed.Length; i++)
        {
            char c = trimmed[i];
            bool isHex = (c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
            if (!isHex) return false;
        }
        return true;
    }

    public static bool VerifyFileSha256(string filePath, string? expectedHash)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !IsValidSha256Hex(expectedHash) || !File.Exists(filePath))
            return false;

        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var actualBytes = sha256.ComputeHash(stream);
            var expectedBytes = Convert.FromHexString(expectedHash!.Trim());
            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
        }
        catch
        {
            return false;
        }
    }

    public static async Task<bool> VerifyFileSha256Async(string filePath, string? expectedHash, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !IsValidSha256Hex(expectedHash) || !File.Exists(filePath))
            return false;

        try
        {
            using var sha256 = SHA256.Create();
            await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            var actualBytes = await sha256.ComputeHashAsync(stream, ct);
            var expectedBytes = Convert.FromHexString(expectedHash!.Trim());
            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    public static byte[] GetRawPublicKeyFromPem(string pem)
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

    internal sealed class SovereignResponse
    {
        [JsonPropertyName("manifest")]
        public UpdateManifest? Manifest { get; set; }

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        [JsonPropertyName("pubkey_url")]
        public string? PubkeyUrl { get; set; }
    }

    internal sealed class UpdateManifest
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

        [JsonPropertyName("tag")]
        public string? Tag { get; set; }

        [JsonPropertyName("is_critical")]
        public bool? IsCritical { get; set; }

        [JsonPropertyName("released_at")]
        public DateTimeOffset? ReleasedAt { get; set; }

        [JsonPropertyName("ts")]
        public string? Ts { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? AdditionalFields { get; set; }
    }
}
