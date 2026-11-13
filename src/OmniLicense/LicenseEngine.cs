#pragma warning disable CA1416
// OmniLicense — RSA License Validator & HWID Manager
// Proprietary implementation by DelgadoLogic.Tech

using System.Security.Cryptography;
using System.Management;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

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

    private readonly RSA _publicKey;
    private readonly ILogger<RsaLicenseValidator> _logger;

    public RsaLicenseValidator(ILogger<RsaLicenseValidator> logger)
    {
        _logger = logger;
        _publicKey = RSA.Create();
        // Load the pinned sovereign public key — no external dependency
        _publicKey.ImportSubjectPublicKeyInfo(Convert.FromBase64String(LicensePublicKeyB64), out _);
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

    public LicenseValidation Validate(LicenseToken token)
    {
        try
        {
            var payloadBytes = Encoding.UTF8.GetBytes(token.Payload);
            var sigBytes     = Convert.FromBase64String(token.Signature);

            if (!_publicKey.VerifyData(payloadBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            {
                _logger.LogWarning("[License] Signature verification failed.");
                return new(false, "Invalid signature", LicenseTier.Free);
            }

            var claims = JsonSerializer.Deserialize<LicenseClaims>(token.Payload);
            if (claims is null)
            {
                _logger.LogWarning("[License] Payload deserialization failed.");
                return new(false, "Corrupt payload", LicenseTier.Free);
            }

            if (claims.ExpiresAt < DateTimeOffset.UtcNow)
            {
                _logger.LogWarning("[License] License expired at {Expiry}", claims.ExpiresAt);
                return new(false, "Expired", LicenseTier.Free);
            }

            var hwid = new HwidGenerator().GenerateHwid();
            if (!string.Equals(claims.BoundHwid, hwid, StringComparison.Ordinal))
            {
                _logger.LogWarning("[License] HWID mismatch — license is bound to a different machine.");
                return new(false, "HWID mismatch — contact support@delgadologic.tech", LicenseTier.Free);
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

    public TrialStatus GetStatus()
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

public sealed record LicenseToken(string Payload, string Signature);
public sealed record LicenseValidation(bool IsValid, string Message, LicenseTier Tier);

public sealed class LicenseClaims
{
    public string          Email      { get; set; } = "";
    public string          BoundHwid  { get; set; } = "";
    public LicenseTier     Tier       { get; set; }
    public DateTimeOffset  IssuedAt   { get; set; }
    public DateTimeOffset  ExpiresAt  { get; set; }
    public string          OrderId    { get; set; } = "";
    public int             SeatCount  { get; set; } = 1;
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum LicenseTier { Free, Pro, Family, Enterprise }

/// <summary>
/// Maps each license tier to its maximum concurrent device (seat) count.
/// Used by the account-based license system to enforce device limits.
/// </summary>
public static class LicenseTierExtensions
{
    public static int MaxSeats(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free       => 1,
        LicenseTier.Pro        => 2,   // Desktop + laptop
        LicenseTier.Family     => 5,   // Household
        LicenseTier.Enterprise => 10,  // Small business (expandable via seat add-ons)
        _                      => 1
    };

    public static string DisplayName(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free       => "Free Edition",
        LicenseTier.Pro        => "Pro License",
        LicenseTier.Family     => "Family License",
        LicenseTier.Enterprise => "Enterprise License",
        _                      => "Unknown"
    };

    public static decimal Price(this LicenseTier tier) => tier switch
    {
        LicenseTier.Free       => 0m,
        LicenseTier.Pro        => 29.99m,
        LicenseTier.Family     => 49.99m,
        LicenseTier.Enterprise => 79.99m,
        _                      => 0m
    };
}

public sealed record TrialStatus(bool IsActive, int DaysRemaining, int TotalDays, bool IsTampered);

internal sealed class TrialData
{
    public DateTimeOffset StartedAt { get; set; }
    public string         BoundHwid { get; set; } = "";
}
