#pragma warning disable CA1416
// OmniLicense — RSA License Validator & HWID Manager
// Delgado Creative Enterprises LLC d/b/a DelgadoLogic

using System.Security.Cryptography;
using System.Management;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace OmniLicense;

public sealed class HwidGenerator
{
    public string GenerateHwid()
    {
        var components = new StringBuilder();
        components.Append(GetWmi("Win32_Processor", "ProcessorId"));
        components.Append(GetWmi("Win32_BaseBoard", "SerialNumber"));
        components.Append(GetWmi("Win32_BIOS", "SerialNumber"));
        components.Append(GetWmi("Win32_DiskDrive", "SerialNumber"));
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(components.ToString())));
    }

    private static string GetWmi(string cls, string prop)
    {
        try
        {
            using var s = new ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
            foreach (var o in s.Get()) return o[prop]?.ToString()?.Trim() ?? "";
        } catch { }
        return "";
    }
}

public sealed class RsaLicenseValidator
{
    // ─── Sovereign RSA-2048 Public Key (DER, Base64) ─────────────────────────
    // Generated 2026-03-29 by DelgadoLogic license key ceremony.
    // Private key stored in Secret Manager:
    //   projects/manuel-portfolio-2026/secrets/logicflow-license-signing-key/versions/1
    // Rotate by generating new pair, updating this constant, and re-shipping client.
    private const string LicensePublicKeyB64 =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnKY2d5db/2/UsERcEKMH" +
        "FdMYMUj7msbr7tcbxxi8pZ/S/0ghaI5zgFjxvzx+a+y+H+L5tbQQQA5QG7B0F32J" +
        "1o/ynVgPc8E1S9PtwvvD3cUFvVn0cRTvR6pu3jup76uhy/t3gHit+bzxFcdMfmRV" +
        "hSuPXWO+qPzXm599++sgG8tr7eJwaFUVLNfri9G5G61ZWJR2zNZnTbQYryoKVhJO" +
        "UJfvPdyLmRiABzlqs/D3U0KmlwsnZ3tJWmZbOPE12k1WFVrISUGZ/EQje+z5QWd+" +
        "l8oO/lZ35YpbuLbFxvd3+4msMuKmXx03L8q/SsOy2E/JkefcpJdd09EgYM7IpDnR" +
        "LQIDAQAB";

    // ─── Sovereign Ed25519 Public Key (SPKI DER, Base64) ─────────────────────
    // Matches AutoUpdateEngine.SovereignPublicKeyPem and Cloud Functions license.js.
    public const string LicenseEd25519PublicKeyB64 =
        "MCowBQYDK2VwAyEABfoHnS014mgux9fNHwe0zzRPEqVoy0OOJ+5tVvfu3a4=";

    public const string Ed25519PublicKeyEnvVar = "LOGICFLOW_LICENSE_ED25519_PUBKEY";

    private static readonly byte[] Ed25519SpkiPrefix =
    [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
    ];

    private readonly RSA? _publicKey;
    private readonly Ed25519PublicKeyParameters? _ed25519PublicKey;
    private readonly ILogger<RsaLicenseValidator> _logger;

    public RsaLicenseValidator(ILogger<RsaLicenseValidator> logger)
    {
        _logger = logger;
        _publicKey = RSA.Create();
        // Load the pinned sovereign public key — no external dependency
        _publicKey.ImportSubjectPublicKeyInfo(Convert.FromBase64String(LicensePublicKeyB64), out _);

        var envEd25519 = Environment.GetEnvironmentVariable(Ed25519PublicKeyEnvVar);
        if (!string.IsNullOrWhiteSpace(envEd25519))
        {
            try
            {
                _ed25519PublicKey = ParseEd25519PublicKey(envEd25519);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[License] Invalid {EnvVar} override — Ed25519 verification disabled.", Ed25519PublicKeyEnvVar);
                _ed25519PublicKey = null;
            }
        }
        else
        {
            _ed25519PublicKey = ParseEd25519PublicKey(LicenseEd25519PublicKeyB64);
        }
    }

    private RsaLicenseValidator(
        ILogger<RsaLicenseValidator> logger,
        RSA? publicKey,
        Ed25519PublicKeyParameters? ed25519PublicKey)
    {
        _logger = logger;
        _publicKey = publicKey;
        _ed25519PublicKey = ed25519PublicKey;
    }

    /// <summary>Creates a validator bound to an isolated test RSA public key (for unit tests only).</summary>
    public static RsaLicenseValidator CreateForTesting(ILogger<RsaLicenseValidator> logger, RSA publicKey) =>
        new(logger, publicKey, null);

    /// <summary>Creates a validator bound to an isolated test Ed25519 public key (for unit tests only).</summary>
    public static RsaLicenseValidator CreateForTesting(ILogger<RsaLicenseValidator> logger, Ed25519PublicKeyParameters ed25519PublicKey) =>
        new(logger, null, ed25519PublicKey);

    /// <summary>Creates a validator bound to isolated test RSA and/or Ed25519 public keys (for unit tests only).</summary>
    public static RsaLicenseValidator CreateForTesting(
        ILogger<RsaLicenseValidator> logger,
        RSA? publicKey,
        Ed25519PublicKeyParameters? ed25519PublicKey) =>
        new(logger, publicKey, ed25519PublicKey);

    /// <summary>Parses an Ed25519 public key from PEM (including escaped-newline PEM), 44-byte SPKI Base64, or 32-byte raw Base64.</summary>
    public static Ed25519PublicKeyParameters ParseEd25519PublicKey(string keyMaterial)
    {
        if (string.IsNullOrWhiteSpace(keyMaterial))
            throw new CryptographicException("Ed25519 public key material is empty.");

        var normalized = keyMaterial.Replace("\\r\\n", "\n", StringComparison.Ordinal)
                                    .Replace("\\n", "\n", StringComparison.Ordinal);
        var lines = normalized
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => !l.StartsWith("-----", StringComparison.Ordinal));
        var base64 = string.Concat(lines);
        if (string.IsNullOrWhiteSpace(base64))
            throw new CryptographicException("Ed25519 public key material is empty.");

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Invalid Base64 in Ed25519 public key.", ex);
        }

        return ParseEd25519PublicKey(bytes);
    }

    /// <summary>Parses an Ed25519 public key from 44-byte SPKI DER bytes or 32-byte raw key bytes.</summary>
    public static Ed25519PublicKeyParameters ParseEd25519PublicKey(byte[] keyBytes)
    {
        ArgumentNullException.ThrowIfNull(keyBytes);
        if (keyBytes.Length == 32)
        {
            return new Ed25519PublicKeyParameters(keyBytes, 0);
        }
        if (keyBytes.Length == 44 && keyBytes.AsSpan(0, 12).SequenceEqual(Ed25519SpkiPrefix))
        {
            return new Ed25519PublicKeyParameters(keyBytes, 12);
        }
        throw new CryptographicException($"Invalid Ed25519 public key format ({keyBytes.Length} bytes).");
    }

    /// <summary>For key ceremony use only — not used at runtime.</summary>
    public static (string PublicKeyB64, string PrivateKeyB64) GenerateKeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (
            Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
            Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())
        );
    }

    public LicenseValidation Validate(LicenseToken token) => Validate(token, null);

    /// <summary>
    /// Validates a signed token. <paramref name="additionalAcceptedHwids"/> lets the host accept other stable device
    /// identifiers the activation server may have bound the token to (e.g. the DelgadoLogic device id).
    /// </summary>
    public LicenseValidation Validate(LicenseToken token, IEnumerable<string>? additionalAcceptedHwids)
    {
        try
        {
            if (token is null || string.IsNullOrEmpty(token.Payload) || string.IsNullOrWhiteSpace(token.Signature))
            {
                _logger.LogWarning("[License] Missing payload or signature.");
                return new(false, "Invalid signature", LicenseTier.Free);
            }

            var payloadBytes = Encoding.UTF8.GetBytes(token.Payload);
            var sigBytes     = Convert.FromBase64String(token.Signature);

            if (!VerifySignature(payloadBytes, sigBytes, token.Alg))
            {
                _logger.LogWarning("[License] Signature verification failed.");
                return new(false, "Invalid signature", LicenseTier.Free);
            }

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var claims = JsonSerializer.Deserialize<LicenseClaims>(token.Payload, options);
            if (claims is null)
            {
                _logger.LogWarning("[License] Payload deserialization failed.");
                return new(false, "Corrupt payload", LicenseTier.Free);
            }

            if (!string.IsNullOrWhiteSpace(token.Kid) &&
                !string.IsNullOrWhiteSpace(claims.Kid) &&
                !string.Equals(token.Kid.Trim(), claims.Kid.Trim(), StringComparison.Ordinal))
            {
                _logger.LogWarning("[License] Outer token Kid does not match signed payload Kid.");
                return new(false, "Invalid signature", LicenseTier.Free);
            }

            if (!HasRecognizedTierInPayload(token.Payload) || !Enum.IsDefined(claims.Tier))
            {
                _logger.LogWarning("[License] Unknown tier value in token — failing closed to Free.");
                return new(false, "Unknown license tier", LicenseTier.Free);
            }

            if (claims.ExpiresAt < DateTimeOffset.UtcNow)
            {
                _logger.LogWarning("[License] License expired at {Expiry}", claims.ExpiresAt);
                return new(false, "Expired", LicenseTier.Free);
            }

            var accepted = new List<string> { new HwidGenerator().GenerateHwid() };
            if (additionalAcceptedHwids is not null)
                accepted.AddRange(additionalAcceptedHwids.Where(h => !string.IsNullOrWhiteSpace(h)));

            if (string.IsNullOrWhiteSpace(claims.BoundHwid) ||
                !accepted.Any(h => string.Equals(claims.BoundHwid, h, StringComparison.Ordinal)))
            {
                _logger.LogWarning("[License] HWID mismatch — license is bound to a different machine.");
                return new(false, $"HWID mismatch — contact {PriceSheet.SupportEmail}", LicenseTier.Free);
            }

            _logger.LogInformation("[License] ✓ Valid license — Tier={Tier} Email={Email}", claims.Tier, claims.Email);
            return new(true, "Valid", claims.Tier);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[License] Unexpected validation error.");
            return new(false, ex.Message, LicenseTier.Free);
        }
    }

    private bool VerifySignature(byte[] payloadBytes, byte[] sigBytes, string? alg)
    {
        if (!string.IsNullOrWhiteSpace(alg))
        {
            var trimmedAlg = alg.Trim();
            if (string.Equals(trimmedAlg, "Ed25519", StringComparison.OrdinalIgnoreCase))
            {
                return sigBytes.Length == 64 && VerifyEd25519(payloadBytes, sigBytes);
            }
            if (string.Equals(trimmedAlg, "RSA", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(trimmedAlg, "RSA-2048", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(trimmedAlg, "RS256", StringComparison.OrdinalIgnoreCase))
            {
                return sigBytes.Length == 256 && VerifyRsa(payloadBytes, sigBytes);
            }
            return false;
        }

        return sigBytes.Length switch
        {
            64  => VerifyEd25519(payloadBytes, sigBytes),
            256 => VerifyRsa(payloadBytes, sigBytes),
            _   => false
        };
    }

    private bool VerifyEd25519(byte[] payloadBytes, byte[] sigBytes)
    {
        if (_ed25519PublicKey is null || sigBytes.Length != 64)
            return false;

        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, _ed25519PublicKey);
            verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
            return verifier.VerifySignature(sigBytes);
        }
        catch
        {
            return false;
        }
    }

    private bool VerifyRsa(byte[] payloadBytes, byte[] sigBytes)
    {
        if (_publicKey is null || sigBytes.Length != 256)
            return false;

        try
        {
            return _publicKey.VerifyData(payloadBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    private static bool HasRecognizedTierInPayload(string payload)
    {
        try
        {
            using var doc = JsonDocument.Parse(payload);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (!string.Equals(prop.Name, "tier", StringComparison.OrdinalIgnoreCase))
                    continue;

                return prop.Value.ValueKind switch
                {
                    JsonValueKind.String => TierPolicy.TryParseTierFailClosed(prop.Value.GetString(), out _),
                    JsonValueKind.Number => prop.Value.TryGetInt32(out var n) && Enum.IsDefined(typeof(LicenseTier), n),
                    _ => false
                };
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
}

public sealed class TrialManager
{
    private readonly string _trialFile;
    private readonly ILogger<TrialManager> _logger;

    public TrialManager(ILogger<TrialManager> logger, string appDataPath)
    {
        _logger = logger;
        Directory.CreateDirectory(Path.Combine(appDataPath, "License"));
        _trialFile = Path.Combine(appDataPath, "License", ".trial");
    }

    /// <summary>
    /// Internal legacy trial query/initializer retained solely for unit tests in LogicFlow.Tests.
    /// Production assemblies cannot call this method; they must use <see cref="PeekStatus"/> (side-effect-free)
    /// or <see cref="StartTrial"/> (explicit opt-in) so status checks can never accidentally start a trial.
    /// </summary>
    internal TrialStatus GetStatus()
    {
        if (!File.Exists(_trialFile)) return InitTrial();

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(File.ReadAllText(_trialFile)));
            var data = JsonSerializer.Deserialize<TrialData>(json);
            if (data is null) return InitTrial();

            var daysUsed      = (int)(DateTimeOffset.UtcNow - data.StartedAt).TotalDays;
            var daysRemaining = Math.Max(0, 14 - daysUsed);
            var tampered      = !string.Equals(data.BoundHwid, new HwidGenerator().GenerateHwid(), StringComparison.Ordinal);

            if (tampered)
                _logger.LogWarning("[Trial] HWID mismatch — trial file may have been moved.");

            return new(daysRemaining > 0 && !tampered, daysRemaining, 14, tampered);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Trial] Corrupt trial file — resetting.");
            return InitTrial();
        }
    }

    /// <summary>Returns the current trial status if a trial has been started, or null if no trial file exists. Fails closed on corrupt/tampered files.</summary>
    public TrialStatus? PeekStatus()
    {
        if (!File.Exists(_trialFile)) return null;

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(File.ReadAllText(_trialFile)));
            var data = JsonSerializer.Deserialize<TrialData>(json);
            if (data is null) return new(false, 0, 14, true);

            var daysUsed      = (int)(DateTimeOffset.UtcNow - data.StartedAt).TotalDays;
            var daysRemaining = Math.Max(0, 14 - daysUsed);
            var tampered      = !string.Equals(data.BoundHwid, new HwidGenerator().GenerateHwid(), StringComparison.Ordinal) || daysUsed < 0;

            return new(daysRemaining > 0 && !tampered, daysRemaining, 14, tampered);
        }
        catch
        {
            return new(false, 0, 14, true);
        }
    }

    /// <summary>Starts the 14-day Pro trial if not already started; otherwise returns the existing status.</summary>
    public TrialStatus StartTrial() => PeekStatus() ?? InitTrial();

    private TrialStatus InitTrial()
    {
        var data = new TrialData
        {
            StartedAt  = DateTimeOffset.UtcNow,
            BoundHwid  = new HwidGenerator().GenerateHwid()
        };
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(data)));
        File.WriteAllText(_trialFile, encoded);
        _logger.LogInformation("[Trial] New trial started — 14 days remaining.");
        return new(true, 14, 14, false);
    }
}

// ─── Models ───────────────────────────────────────────────────────────────────

public sealed record LicenseToken(
    string Payload,
    string Signature,
    string? Alg = null,
    string? Kid = null);
public sealed record LicenseValidation(bool IsValid, string Message, LicenseTier Tier);

public sealed class LicenseClaims
{
    public string          Email        { get; set; } = "";
    public string          BoundHwid    { get; set; } = "";
    public LicenseTier     Tier         { get; set; }
    public DateTimeOffset  IssuedAt     { get; set; }
    public DateTimeOffset  ExpiresAt    { get; set; }
    public string          OrderId      { get; set; } = "";
    public int             SeatCount    { get; set; } = 1;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int?            DeviceLimit  { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string?         Kid          { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int?            MajorVersion { get; set; }
}

/// <summary>
/// Licence tier carried in the signed token. The v1.0 product has three editions (Free / Community / Pro,
/// see <see cref="Edition"/>). Family, Enterprise (Team 10-pack), SovereignSuite and FounderPass are legacy
/// token values kept so previously issued tokens still deserialise; they all map to the Pro edition.
/// Numeric values are persisted in tokens, so new members must only be appended.
/// </summary>
[JsonConverter(typeof(LicenseTierJsonConverter))]
public enum LicenseTier { Free, Pro, Family, Enterprise, SovereignSuite, FounderPass, Community }

public sealed class LicenseTierJsonConverter : JsonConverter<LicenseTier>
{
    public override LicenseTier Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return TierPolicy.ParseTierFailClosed(reader.GetString());
        }
        if (reader.TokenType == JsonTokenType.Number)
        {
            if (reader.TryGetInt32(out var intVal) && Enum.IsDefined(typeof(LicenseTier), intVal))
            {
                return (LicenseTier)intVal;
            }
        }
        return LicenseTier.Free;
    }

    public override void Write(Utf8JsonWriter writer, LicenseTier value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}

/// <summary>
/// Maps each license tier to its maximum concurrent device (seat) count.
/// Used by the account-based license system to enforce device limits.
/// </summary>
public static class LicenseTierExtensions
{
    public static int MaxSeats(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free           => PriceSheet.FreeDevices,
        LicenseTier.Community      => PriceSheet.CommunityDevices,
        LicenseTier.Pro            => PriceSheet.ProDevices,
        LicenseTier.Family         => 5,   // legacy alias, honoured for already-issued tokens
        LicenseTier.SovereignSuite => 5,   // legacy alias
        LicenseTier.Enterprise     => PriceSheet.Team10PackSeats,   // Team 10-pack
        LicenseTier.FounderPass    => 10,  // legacy, retired
        _                          => 1
    };

    public static string DisplayName(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free           => "Free Edition",
        LicenseTier.Community      => "Community Edition",
        LicenseTier.Pro            => "Pro License",
        LicenseTier.Family         => "Family License",
        LicenseTier.SovereignSuite => "Sovereign Suite",
        LicenseTier.Enterprise     => "Enterprise License",
        LicenseTier.FounderPass    => "Founder Pass",
        _                          => "Unknown"
    };

    public static decimal Price(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free           => PriceSheet.FreePrice,
        LicenseTier.Community      => PriceSheet.CommunityPrice,
        LicenseTier.Pro            => PriceSheet.ProPrice,
        LicenseTier.Family         => 49.00m,   // legacy list price
        LicenseTier.SovereignSuite => 49.00m,   // legacy list price
        LicenseTier.Enterprise     => PriceSheet.Team10PackPrice,
        LicenseTier.FounderPass    => 149.00m,  // legacy list price (retired)
        _                          => 0m
    };
}

public sealed record TrialStatus(bool IsActive, int DaysRemaining, int TotalDays, bool IsTampered);

internal sealed class TrialData
{
    public DateTimeOffset StartedAt { get; set; }
    public string         BoundHwid { get; set; } = "";
}
