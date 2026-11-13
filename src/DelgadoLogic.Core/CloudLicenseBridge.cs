// ─────────────────────────────────────────────────────────────────────────────
// DelgadoLogic.Core — Cloud License Bridge
// Connects the local RSA license validator with the Firebase entitlement store.
// This is the "last mile" between PayPal payment and desktop license enforcement.
//
// FLOW:
//   1. User purchases LogicFlow Pro via PayPal → order recorded in Firestore
//   2. Desktop app calls ActivateAsync(orderId) → sends HWID + orderId to cloud
//   3. Cloud function verifies purchase, checks seat limits, signs token with RSA
//   4. Bridge stores the signed token locally → LicenseEngine validates offline
//   5. Periodic ValidateAsync() checks if license was revoked server-side
//
// ARCHITECTURE: Mirrors Adobe's activation server model — cloud-activated,
// locally-enforced. Works offline after initial activation.
// ─────────────────────────────────────────────────────────────────────────────

using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace DelgadoLogic.Core;

/// <summary>
/// Cloud license activation and validation bridge.
/// Communicates with the Firebase Cloud Functions to activate and
/// periodically re-validate licenses against the cloud entitlement store.
/// </summary>
public sealed class CloudLicenseBridge : IAsyncDisposable
{
    // ─── Sovereign Infrastructure ────────────────────────────────────────────
    private const string ActivationEndpoint =
        "https://us-central1-manuel-portfolio-2026.cloudfunctions.net/activateLicense";

    private const string ValidationEndpoint =
        "https://us-central1-manuel-portfolio-2026.cloudfunctions.net/validateLicense";

    private const string LicenseFileName = "license_token.json";
    private const string ActivationCacheFileName = "activation_cache.json";

    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly string _licensePath;
    private readonly string _cachePath;

    public CloudLicenseBridge(ILogger logger, string appDataPath, HttpClient? httpClient = null)
    {
        _logger = logger;
        _http = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30),
            DefaultRequestHeaders =
            {
                { "User-Agent", $"DelgadoLogic-LicenseBridge/1.0" }
            }
        };

        var licenseDir = Path.Combine(appDataPath, "License");
        Directory.CreateDirectory(licenseDir);
        _licensePath = Path.Combine(licenseDir, LicenseFileName);
        _cachePath = Path.Combine(licenseDir, ActivationCacheFileName);
    }

    // ─── Public API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Activates a license by sending the order ID and device HWID to the cloud.
    /// Returns the signed license token for local offline validation.
    /// </summary>
    public async Task<ActivationResult> ActivateAsync(
        string orderId,
        string? email = null,
        CancellationToken ct = default)
    {
        try
        {
            var identity = DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false);
            var hwid = identity.DeviceId;

            _logger.LogInformation("[License] Activating order {OrderId} for HWID {Hwid}...",
                orderId, hwid[..Math.Min(8, hwid.Length)]);

            var request = new ActivationRequest
            {
                OrderId = orderId,
                Hwid = hwid,
                Email = email ?? ""
            };

            var response = await _http.PostAsJsonAsync(ActivationEndpoint, request, ct);
            var responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
            {
                var errorMsg = $"HTTP {response.StatusCode}";
                try
                {
                    using var errorData = JsonDocument.Parse(responseBody);
                    if (errorData.RootElement.ValueKind == JsonValueKind.Object &&
                        errorData.RootElement.TryGetProperty("error", out var errProp) &&
                        errProp.ValueKind == JsonValueKind.String &&
                        !string.IsNullOrWhiteSpace(errProp.GetString()))
                    {
                        errorMsg = errProp.GetString()!;
                    }
                }
                catch { /* non-JSON error body: keep HTTP status fallback */ }

                _logger.LogWarning("[License] Activation failed: {Error}", errorMsg);
                return new ActivationResult(false, errorMsg, null, null);
            }

            var result = JsonSerializer.Deserialize<CloudActivationResponse>(responseBody);
            if (result is null)
            {
                return new ActivationResult(false, "Invalid server response", null, null);
            }

            // Activation succeeded: now persist shared device identity + license token
            DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: true);

            // Persist the license token locally for offline validation
            var localToken = new LocalLicenseToken
            {
                Payload = result.Token.Payload,
                Signature = result.Token.Signature,
                Alg = result.Token.Alg,
                Kid = result.Token.Kid,
                Tier = result.Tier,
                ExpiresAt = DateTimeOffset.Parse(result.ExpiresAt),
                ActivationId = result.ActivationId,
                ActivatedAt = DateTimeOffset.UtcNow,
                OrderId = orderId
            };

            var json = JsonSerializer.Serialize(localToken, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_licensePath, json, ct);

            // Also cache the activation result
            var cache = new ActivationCache
            {
                OrderId = orderId,
                Tier = result.Tier,
                Seats = result.Seats,
                LastValidated = DateTimeOffset.UtcNow,
                CloudValid = true
            };
            await File.WriteAllTextAsync(_cachePath,
                JsonSerializer.Serialize(cache, new JsonSerializerOptions { WriteIndented = true }), ct);

            _logger.LogInformation("[License] ✓ Activated {Tier} license — expires {Expiry}",
                result.Tier, result.ExpiresAt);

            return new ActivationResult(true, "License activated successfully", result.Tier, localToken);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "[License] Network error during activation — check internet connection.");
            return new ActivationResult(false, "Network error — check your internet connection.", null, null);
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("[License] Activation request timed out.");
            return new ActivationResult(false, "Request timed out. Please try again.", null, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[License] Unexpected activation error.");
            return new ActivationResult(false, ex.Message, null, null);
        }
    }

    /// <summary>
    /// Validates an existing license against the cloud entitlement store.
    /// Call this periodically (e.g., daily) to check for revocations.
    /// Returns cached result if offline.
    /// </summary>
    public async Task<ValidationResult> ValidateAsync(CancellationToken ct = default)
    {
        try
        {
            var localToken = LoadLocalToken();
            if (localToken is null)
            {
                return new ValidationResult(false, "No license found on this device.", null);
            }

            var identity = DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false);

            var request = new ValidationRequest
            {
                OrderId = localToken.OrderId,
                Hwid = identity.DeviceId
            };

            var response = await _http.PostAsJsonAsync(ValidationEndpoint, request, ct);
            var responseBody = await response.Content.ReadAsStringAsync(ct);
            var result = JsonSerializer.Deserialize<CloudValidationResponse>(responseBody);

            if (result is null)
            {
                return FallbackToCache();
            }

            // Update local cache
            var cache = new ActivationCache
            {
                OrderId = localToken.OrderId,
                Tier = result.Tier ?? localToken.Tier,
                LastValidated = DateTimeOffset.UtcNow,
                CloudValid = result.Valid
            };
            await File.WriteAllTextAsync(_cachePath,
                JsonSerializer.Serialize(cache, new JsonSerializerOptions { WriteIndented = true }), ct);

            if (!result.Valid)
            {
                _logger.LogWarning("[License] Cloud validation failed: {Reason}", result.Reason);
                return new ValidationResult(false, result.Reason ?? "License invalid", null);
            }

            DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: true);
            _logger.LogInformation("[License] ✓ Cloud validation passed — Tier={Tier}", result.Tier);
            return new ValidationResult(true, "Valid", result.Tier);
        }
        catch (HttpRequestException)
        {
            _logger.LogDebug("[License] Offline — falling back to cached validation.");
            return FallbackToCache();
        }
        catch (TaskCanceledException)
        {
            return FallbackToCache();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[License] Validation error — using cache.");
            return FallbackToCache();
        }
    }

    /// <summary>
    /// Loads the locally stored license token (for offline RSA validation).
    /// Returns null if no license exists on this device.
    /// </summary>
    public LocalLicenseToken? LoadLocalToken()
    {
        if (!File.Exists(_licensePath)) return null;

        try
        {
            var json = File.ReadAllText(_licensePath);
            return JsonSerializer.Deserialize<LocalLicenseToken>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[License] Failed to read local license file.");
            return null;
        }
    }

    /// <summary>
    /// Returns the current license tier from local storage.
    /// Fails closed to "Free" if no license is activated, expired, or has an unrecognised tier string.
    /// </summary>
    public string GetCurrentTier()
    {
        var token = LoadLocalToken();
        if (token is null) return "Free";
        if (token.ExpiresAt < DateTimeOffset.UtcNow) return "Free";
        return NormalizeTierFailClosed(token.Tier);
    }

    /// <summary>
    /// Returns true if this device has an active paid (Pro) license.
    /// Fails closed: Community, Free, and unknown values return false.
    /// </summary>
    public bool IsPaid() => string.Equals(GetCurrentTier(), "Pro", StringComparison.Ordinal);

    private static string NormalizeTierFailClosed(string? rawTier)
    {
        if (string.IsNullOrWhiteSpace(rawTier)) return "Free";
        var trimmed = rawTier.Trim();
        if (trimmed.Length == 0 || trimmed.Any(char.IsDigit)) return "Free";
        var normalized = trimmed.Replace("-", "").Replace("_", "").Trim();
        return normalized.ToLowerInvariant() switch
        {
            "pro" or "aeonpro" or "family" or "enterprise" or "enterpriseseat" or "sovereignsuite" or "suite" or "founderpass" or "founder" => "Pro",
            "community" => "Community",
            _ => "Free"
        };
    }

    // ─── Internals ───────────────────────────────────────────────────────────

    private ValidationResult FallbackToCache()
    {
        if (!File.Exists(_cachePath))
            return new ValidationResult(false, "No cached validation available.", null);

        try
        {
            var json = File.ReadAllText(_cachePath);
            var cache = JsonSerializer.Deserialize<ActivationCache>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (cache is null)
                return new ValidationResult(false, "Cache corrupt.", null);

            // Allow 30-day offline grace period
            if (cache.LastValidated.AddDays(30) < DateTimeOffset.UtcNow)
                return new ValidationResult(false, "Offline too long — connect to internet to re-validate.", null);

            return new ValidationResult(cache.CloudValid, "Cached validation", cache.Tier);
        }
        catch
        {
            return new ValidationResult(false, "Cache read error.", null);
        }
    }

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }
}

// ─── Request/Response DTOs ───────────────────────────────────────────────────

internal sealed class ActivationRequest
{
    [JsonPropertyName("orderId")] public string OrderId { get; set; } = "";
    [JsonPropertyName("hwid")]    public string Hwid { get; set; } = "";
    [JsonPropertyName("email")]   public string Email { get; set; } = "";
}

internal sealed class ValidationRequest
{
    [JsonPropertyName("orderId")] public string OrderId { get; set; } = "";
    [JsonPropertyName("hwid")]    public string Hwid { get; set; } = "";
}

internal sealed class CloudActivationResponse
{
    [JsonPropertyName("success")]       public bool Success { get; set; }
    [JsonPropertyName("token")]         public TokenPair Token { get; set; } = new();
    [JsonPropertyName("tier")]          public string Tier { get; set; } = "";
    [JsonPropertyName("seats")]         public int Seats { get; set; }
    [JsonPropertyName("expiresAt")]     public string ExpiresAt { get; set; } = "";
    [JsonPropertyName("activationId")]  public string ActivationId { get; set; } = "";
}

internal sealed class TokenPair
{
    [JsonPropertyName("payload")]   public string Payload { get; set; } = "";
    [JsonPropertyName("signature")] public string Signature { get; set; } = "";
    [JsonPropertyName("alg")]       public string? Alg { get; set; }
    [JsonPropertyName("kid")]       public string? Kid { get; set; }
}

internal sealed class CloudValidationResponse
{
    [JsonPropertyName("valid")]     public bool Valid { get; set; }
    [JsonPropertyName("tier")]      public string? Tier { get; set; }
    [JsonPropertyName("reason")]    public string? Reason { get; set; }
    [JsonPropertyName("expiresAt")] public string? ExpiresAt { get; set; }
}

// ─── Public Result Types ─────────────────────────────────────────────────────

/// <summary>Result of a license activation attempt.</summary>
public sealed record ActivationResult(
    bool Success,
    string Message,
    string? Tier,
    LocalLicenseToken? Token);

/// <summary>Result of a cloud license validation check.</summary>
public sealed record ValidationResult(
    bool IsValid,
    string Message,
    string? Tier);

/// <summary>Locally persisted license token — used for offline signature validation.</summary>
public sealed class LocalLicenseToken
{
    public string Payload       { get; set; } = "";
    public string Signature     { get; set; } = "";
    public string? Alg          { get; set; }
    public string? Kid          { get; set; }
    public string? Tier         { get; set; }
    public DateTimeOffset ExpiresAt    { get; set; }
    public string ActivationId  { get; set; } = "";
    public DateTimeOffset ActivatedAt  { get; set; }
    public string OrderId       { get; set; } = "";
}

/// <summary>Cached activation state for offline grace period.</summary>
internal sealed class ActivationCache
{
    public string OrderId        { get; set; } = "";
    public string? Tier          { get; set; }
    public int Seats             { get; set; }
    public DateTimeOffset LastValidated { get; set; }
    public bool CloudValid       { get; set; }
}
