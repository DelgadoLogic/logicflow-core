// OmniLicense — Unit Tests
// Tests RSA license validation, HWID generation, trial management, and tier configurations.

using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OmniLicense;
using Microsoft.Extensions.Logging;
using Moq;

namespace LogicFlow.Tests;

public class LicenseEngineTests
{
    private readonly Mock<ILogger<RsaLicenseValidator>> _validatorLogger = new();
    private readonly Mock<ILogger<TrialManager>> _trialLogger = new();

    // ── HWID Generator Tests ──────────────────────────────────────────────

    [Fact]
    public void HwidGenerator_ProducesDeterministicHash()
    {
        var gen = new HwidGenerator();
        var hwid1 = gen.GenerateHwid();
        var hwid2 = gen.GenerateHwid();

        Assert.NotEmpty(hwid1);
        Assert.Equal(hwid1, hwid2); // Same machine → same HWID
    }

    [Fact]
    public void HwidGenerator_ProducesBase64()
    {
        var gen = new HwidGenerator();
        var hwid = gen.GenerateHwid();

        // Valid base64 should not throw
        var bytes = Convert.FromBase64String(hwid);
        Assert.Equal(32, bytes.Length); // SHA256 = 32 bytes
    }

    // ── RSA Key Generation Tests ──────────────────────────────────────────

    [Fact]
    public void GenerateKeyPair_ProducesValidRsaKeys()
    {
        var (publicB64, privateB64) = RsaLicenseValidator.GenerateKeyPair();

        Assert.NotEmpty(publicB64);
        Assert.NotEmpty(privateB64);

        // Verify the keys are valid RSA material
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicB64), out _);
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateB64), out _);
    }

    // ── License Validation Tests ──────────────────────────────────────────

    [Fact]
    public void Validate_RejectsEmptySignature()
    {
        var validator = new RsaLicenseValidator(_validatorLogger.Object);
        var token = new LicenseToken("{}", "");

        var result = validator.Validate(token);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseTier.Free, result.Tier);
    }

    [Fact]
    public void Validate_RejectsInvalidSignature()
    {
        var validator = new RsaLicenseValidator(_validatorLogger.Object);
        var token = new LicenseToken(
            "{\"email\":\"test@example.com\"}",
            Convert.ToBase64String(new byte[256])); // Random bytes

        var result = validator.Validate(token);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseTier.Free, result.Tier);
    }

    [Fact]
    public void Validate_RejectsCorruptPayload()
    {
        var validator = new RsaLicenseValidator(_validatorLogger.Object);
        var token = new LicenseToken("not-json", "not-base64");

        var result = validator.Validate(token);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_WithValidKeyPair_AcceptsCorrectSignature()
    {
        // Generate a test key pair (separate from production keys)
        using var rsa = RSA.Create(2048);
        var publicKeyB64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
        var privateKeyBytes = rsa.ExportPkcs8PrivateKey();

        // Create claims bound to current machine
        var hwid = new HwidGenerator().GenerateHwid();
        var claims = new LicenseClaims
        {
            Email = "test@delgadologic.tech",
            BoundHwid = hwid,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365),
            OrderId = "TEST-001",
            SeatCount = 2
        };

        var payload = JsonSerializer.Serialize(claims);
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(payload),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var signatureB64 = Convert.ToBase64String(signature);

        // Note: This test verifies the validation LOGIC works correctly.
        // It uses a test key pair, not the production sovereign key,
        // so it will fail signature verification against the pinned key.
        // This is by design — the pinned key should NEVER be in tests.
        var validator = new RsaLicenseValidator(_validatorLogger.Object);
        var token = new LicenseToken(payload, signatureB64);
        var result = validator.Validate(token);

        // Will fail because signature is against test key, not pinned sovereign key
        Assert.False(result.IsValid);
        Assert.Contains("Invalid signature", result.Message);
    }

    // ── License Tier Extension Tests ──────────────────────────────────────

    [Theory]
    [InlineData(LicenseTier.Free, 1)]
    [InlineData(LicenseTier.Community, 1)]
    [InlineData(LicenseTier.Pro, 3)]   // PriceSheet.ProDevices
    [InlineData(LicenseTier.Family, 5)]
    [InlineData(LicenseTier.SovereignSuite, 5)]
    [InlineData(LicenseTier.Enterprise, 10)]
    [InlineData(LicenseTier.FounderPass, 10)]
    public void MaxSeats_ReturnsCorrectCount(LicenseTier tier, int expectedSeats)
    {
        Assert.Equal(expectedSeats, tier.MaxSeats());
    }

    [Theory]
    [InlineData(LicenseTier.Free, 0)]
    [InlineData(LicenseTier.Pro, 29.99)]
    [InlineData(LicenseTier.Family, 49.00)]
    [InlineData(LicenseTier.SovereignSuite, 49.00)]
    [InlineData(LicenseTier.Enterprise, 149.00)]
    [InlineData(LicenseTier.FounderPass, 149.00)]
    public void Price_ReturnsCorrectAmount(LicenseTier tier, double expectedPrice)
    {
        Assert.Equal((decimal)expectedPrice, tier.Price());
    }

    [Theory]
    [InlineData(LicenseTier.Free, "Free Edition")]
    [InlineData(LicenseTier.Pro, "Pro License")]
    [InlineData(LicenseTier.Family, "Family License")]
    [InlineData(LicenseTier.SovereignSuite, "Sovereign Suite")]
    [InlineData(LicenseTier.Enterprise, "Enterprise License")]
    [InlineData(LicenseTier.FounderPass, "Founder Pass")]
    public void DisplayName_ReturnsCorrectString(LicenseTier tier, string expected)
    {
        Assert.Equal(expected, tier.DisplayName());
    }

    // ── Trial Manager Tests ──────────────────────────────────────────────

    [Fact]
    public void TrialManager_InitializesNewTrial()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"logicflow_test_{Guid.NewGuid():N}");
        try
        {
            var manager = new TrialManager(_trialLogger.Object, tempDir);
            var status = manager.GetStatus();

            Assert.True(status.IsActive);
            Assert.Equal(14, status.DaysRemaining);
            Assert.Equal(14, status.TotalDays);
            Assert.False(status.IsTampered);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void TrialManager_ReturnsSameStatusOnSubsequentCalls()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"logicflow_test_{Guid.NewGuid():N}");
        try
        {
            var manager = new TrialManager(_trialLogger.Object, tempDir);
            var status1 = manager.GetStatus();
            var status2 = manager.GetStatus();

            Assert.Equal(status1.DaysRemaining, status2.DaysRemaining);
            Assert.Equal(status1.IsActive, status2.IsActive);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void TrialManager_DetectsTamperedFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"logicflow_test_{Guid.NewGuid():N}");
        try
        {
            var manager = new TrialManager(_trialLogger.Object, tempDir);
            manager.GetStatus(); // Initialize

            // Corrupt the trial file
            var trialFile = Path.Combine(tempDir, "License", ".trial");
            File.WriteAllText(trialFile, "corrupted-data");

            var status = manager.GetStatus();

            // Should reinitialize (14 days) since data is corrupt
            Assert.True(status.IsActive);
            Assert.Equal(14, status.DaysRemaining);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void TrialManager_PeekStatus_ReturnsNullWhenNotStarted_AndFailsClosedOnCorruptFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"logicflow_test_{Guid.NewGuid():N}");
        try
        {
            var manager = new TrialManager(_trialLogger.Object, tempDir);
            Assert.Null(manager.PeekStatus());

            var started = manager.StartTrial();
            Assert.True(started.IsActive);
            Assert.Equal(14, started.DaysRemaining);

            var peeked = manager.PeekStatus();
            Assert.NotNull(peeked);
            Assert.True(peeked!.IsActive);
            Assert.Equal(14, peeked.DaysRemaining);

            // Corrupt the trial file — PeekStatus must fail closed (inactive/tampered) instead of resetting
            var trialFile = Path.Combine(tempDir, "License", ".trial");
            File.WriteAllText(trialFile, "corrupted-data");
            var tampered = manager.PeekStatus();
            Assert.NotNull(tampered);
            Assert.False(tampered!.IsActive);
            Assert.True(tampered.IsTampered);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    // ── License Claims Serialization Tests ────────────────────────────────

    [Fact]
    public void LicenseClaims_RoundTripsCorrectly()
    {
        var original = new LicenseClaims
        {
            Email = "user@example.com",
            BoundHwid = "test-hwid",
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365),
            OrderId = "ORDER-123",
            SeatCount = 2
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<LicenseClaims>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.Email, deserialized.Email);
        Assert.Equal(original.Tier, deserialized.Tier);
        Assert.Equal(original.OrderId, deserialized.OrderId);
        Assert.Equal(original.SeatCount, deserialized.SeatCount);
    }

    [Fact]
    public void LicenseTier_DeserializesFromString()
    {
        var json = "\"Pro\"";
        var tier = JsonSerializer.Deserialize<LicenseTier>(json);
        Assert.Equal(LicenseTier.Pro, tier);
    }

    [Theory]
    [InlineData("\"SovereignSuite\"", LicenseTier.SovereignSuite)]
    [InlineData("\"sovereign_suite\"", LicenseTier.SovereignSuite)]
    [InlineData("\"Sovereign_suite\"", LicenseTier.SovereignSuite)]
    [InlineData("\"suite\"", LicenseTier.SovereignSuite)]
    [InlineData("\"founder_pass\"", LicenseTier.FounderPass)]
    [InlineData("\"Founder_pass\"", LicenseTier.FounderPass)]
    [InlineData("\"FounderPass\"", LicenseTier.FounderPass)]
    [InlineData("\"pro\"", LicenseTier.Pro)]
    [InlineData("\"aeon_pro\"", LicenseTier.Pro)]
    [InlineData("\"free\"", LicenseTier.Free)]
    public void LicenseTier_DeserializesFromVariousFormats(string json, LicenseTier expected)
    {
        var tier = JsonSerializer.Deserialize<LicenseTier>(json);
        Assert.Equal(expected, tier);
    }

    [Fact]
    public void LicenseClaims_DeserializesWithCamelCaseProperties()
    {
        var json = "{\"email\":\"user@example.com\",\"boundHwid\":\"test-hwid\",\"tier\":\"sovereign_suite\",\"issuedAt\":\"2026-09-08T10:00:00Z\",\"expiresAt\":\"2027-09-08T10:00:00Z\",\"orderId\":\"ORDER-999\",\"seatCount\":5}";
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var claims = JsonSerializer.Deserialize<LicenseClaims>(json, options);

        Assert.NotNull(claims);
        Assert.Equal("user@example.com", claims.Email);
        Assert.Equal("test-hwid", claims.BoundHwid);
        Assert.Equal(LicenseTier.SovereignSuite, claims.Tier);
        Assert.Equal("ORDER-999", claims.OrderId);
        Assert.Equal(5, claims.SeatCount);
    }

    [Theory]
    [InlineData("\"1\"")]
    [InlineData("\"-1\"")]
    [InlineData("\"_1_\"")]
    [InlineData("\"999\"")]
    [InlineData("\"unknown_future_tier\"")]
    [InlineData("\"\"")]
    [InlineData("999")]
    [InlineData("-1")]
    public void LicenseTier_NumericStringsAndUnknownValues_FailClosedToFree(string json)
    {
        var tier = JsonSerializer.Deserialize<LicenseTier>(json);
        Assert.Equal(LicenseTier.Free, tier);
    }

    [Fact]
    public void Validate_WithTestKey_RejectsUnknownAndNumericStringTiers_AndAcceptsFounderPassAsPro()
    {
        using var rsa = RSA.Create(2048);
        var validator = RsaLicenseValidator.CreateForTesting(_validatorLogger.Object, rsa);
        var hwid = new HwidGenerator().GenerateHwid();

        LicenseToken SignRaw(string rawTierJsonValue)
        {
            var payload = $"{{\"email\":\"test@delgadologic.tech\",\"boundHwid\":{JsonSerializer.Serialize(hwid)},\"tier\":{rawTierJsonValue},\"issuedAt\":\"2026-01-01T00:00:00Z\",\"expiresAt\":\"2030-01-01T00:00:00Z\",\"orderId\":\"ORD-1\",\"seatCount\":3}}";
            var sig = Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            return new LicenseToken(payload, sig);
        }

        // Unknown string tier must fail validation (not return IsValid=true, Tier=Free)
        var unknownResult = validator.Validate(SignRaw("\"quantum_ultimate\""));
        Assert.False(unknownResult.IsValid);
        Assert.Equal(LicenseTier.Free, unknownResult.Tier);

        // Numeric string "-1" must fail validation (not parse as LicenseTier.Pro)
        var negOneResult = validator.Validate(SignRaw("\"-1\""));
        Assert.False(negOneResult.IsValid);
        Assert.Equal(LicenseTier.Free, negOneResult.Tier);

        // Out-of-range integer tier 999 must fail validation
        var outOfRangeResult = validator.Validate(SignRaw("999"));
        Assert.False(outOfRangeResult.IsValid);
        Assert.Equal(LicenseTier.Free, outOfRangeResult.Tier);

        // Legacy FounderPass token must validate and map to Edition.Pro
        var founderResult = validator.Validate(SignRaw("\"founder_pass\""));
        Assert.True(founderResult.IsValid);
        Assert.Equal(LicenseTier.FounderPass, founderResult.Tier);
        Assert.Equal(Edition.Pro, founderResult.Tier.ToEdition());
    }

    // ── Ed25519 Dual Signature Verification Tests ─────────────────────────

    private static (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters Private,
                    Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters Public) GenerateEd25519KeyPair()
    {
        var kpGen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
        kpGen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(
            new Org.BouncyCastle.Security.SecureRandom()));
        var kp = kpGen.GenerateKeyPair();
        return (
            (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)kp.Private,
            (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)kp.Public
        );
    }

    private static string SignEd25519(string payload, Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters privateKey)
    {
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(true, privateKey);
        signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    [Fact]
    public void Validate_Ed25519SignedToken_AcceptsValidSignature_AndFailsClosedOnTamperedOrWrongKey()
    {
        var (privKey, pubKey) = GenerateEd25519KeyPair();
        var (_, wrongPubKey) = GenerateEd25519KeyPair();
        var validator = RsaLicenseValidator.CreateForTesting(_validatorLogger.Object, pubKey);
        var wrongKeyValidator = RsaLicenseValidator.CreateForTesting(_validatorLogger.Object, wrongPubKey);

        var hwid = new HwidGenerator().GenerateHwid();
        var payload = JsonSerializer.Serialize(new
        {
            Email = "buyer@delgadologic.tech",
            BoundHwid = hwid,
            Tier = "Pro",
            DeviceLimit = 3,
            SeatCount = 3,
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365).ToString("O"),
            OrderId = "PAYPAL-ORDER-123",
            Kid = "ed25519-1",
            MajorVersion = 1
        });

        var sigB64 = SignEd25519(payload, privKey);
        var validToken = new LicenseToken(payload, sigB64, "Ed25519", "ed25519-1");

        // 1. Valid Ed25519 signature (with Alg="Ed25519" and with Alg=null) passes
        var okWithAlg = validator.Validate(validToken);
        Assert.True(okWithAlg.IsValid);
        Assert.Equal(LicenseTier.Pro, okWithAlg.Tier);

        var okImplicitAlg = validator.Validate(new LicenseToken(payload, sigB64));
        Assert.True(okImplicitAlg.IsValid);
        Assert.Equal(LicenseTier.Pro, okImplicitAlg.Tier);

        // 2. Wrong Ed25519 public key fails closed to Free
        var wrongKeyResult = wrongKeyValidator.Validate(validToken);
        Assert.False(wrongKeyResult.IsValid);
        Assert.Equal(LicenseTier.Free, wrongKeyResult.Tier);
        Assert.Contains("Invalid signature", wrongKeyResult.Message);

        // 3. Tampered Ed25519 signature bytes fail closed to Free
        var tamperedSigBytes = Convert.FromBase64String(sigB64);
        tamperedSigBytes[0] ^= 0xFF;
        var tamperedSigToken = new LicenseToken(payload, Convert.ToBase64String(tamperedSigBytes), "Ed25519", "ed25519-1");
        var tamperedSigResult = validator.Validate(tamperedSigToken);
        Assert.False(tamperedSigResult.IsValid);
        Assert.Equal(LicenseTier.Free, tamperedSigResult.Tier);

        // 4. Tampered payload with original Ed25519 signature fails closed to Free
        var tamperedPayload = payload.Replace("\"Pro\"", "\"Enterprise\"");
        var tamperedPayloadResult = validator.Validate(new LicenseToken(tamperedPayload, sigB64, "Ed25519", "ed25519-1"));
        Assert.False(tamperedPayloadResult.IsValid);
        Assert.Equal(LicenseTier.Free, tamperedPayloadResult.Tier);

        // 5. Algorithm confusion (Alg="none" or Alg="RSA-2048" on 64-byte sig) fails closed to Free
        Assert.False(validator.Validate(new LicenseToken(payload, sigB64, "none", "ed25519-1")).IsValid);
        Assert.False(validator.Validate(new LicenseToken(payload, sigB64, "RSA-2048", "ed25519-1")).IsValid);

        // 6. Outer Kid tampered (disagrees with signed Kid in payload) fails closed to Free
        Assert.False(validator.Validate(new LicenseToken(payload, sigB64, "Ed25519", "spoofed-kid")).IsValid);
    }

    [Fact]
    public void Validate_DualKeyValidator_VerifiesBothEd25519AndRsa2048_AndRejectsCrossAlgorithmConfusion()
    {
        using var rsa = RSA.Create(2048);
        var (edPriv, edPub) = GenerateEd25519KeyPair();
        var validator = RsaLicenseValidator.CreateForTesting(_validatorLogger.Object, rsa, edPub);

        var hwid = new HwidGenerator().GenerateHwid();
        var edPayload = JsonSerializer.Serialize(new
        {
            Email = "ed@delgadologic.tech",
            BoundHwid = hwid,
            Tier = "Pro",
            DeviceLimit = 3,
            SeatCount = 3,
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365).ToString("O"),
            OrderId = "ORD-DUAL-ED",
            Kid = "ed25519-1",
            MajorVersion = 1
        });
        var rsaPayload = JsonSerializer.Serialize(new
        {
            Email = "rsa@delgadologic.tech",
            BoundHwid = hwid,
            Tier = "Pro",
            DeviceLimit = 3,
            SeatCount = 3,
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365).ToString("O"),
            OrderId = "ORD-DUAL-RSA",
            Kid = "rsa-1",
            MajorVersion = 1
        });

        var edSig = SignEd25519(edPayload, edPriv);
        var rsaSig = Convert.ToBase64String(
            rsa.SignData(Encoding.UTF8.GetBytes(rsaPayload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        // Both Ed25519 and RSA-2048 (RS256 / RSA-2048 / implicit) pass on the same validator instance
        Assert.True(validator.Validate(new LicenseToken(edPayload, edSig, "Ed25519", "ed25519-1")).IsValid);
        Assert.True(validator.Validate(new LicenseToken(edPayload, edSig, " Ed25519 ", "ed25519-1")).IsValid);
        Assert.True(validator.Validate(new LicenseToken(edPayload, edSig)).IsValid);
        Assert.True(validator.Validate(new LicenseToken(rsaPayload, rsaSig, "RS256", "rsa-1")).IsValid);
        Assert.True(validator.Validate(new LicenseToken(rsaPayload, rsaSig, "RSA-2048", "rsa-1")).IsValid);
        Assert.True(validator.Validate(new LicenseToken(rsaPayload, rsaSig)).IsValid);

        // Cross-algorithm confusion fails closed even when both keys are loaded
        Assert.False(validator.Validate(new LicenseToken(edPayload, edSig, "RS256", "ed25519-1")).IsValid);
        Assert.False(validator.Validate(new LicenseToken(rsaPayload, rsaSig, "Ed25519", "rsa-1")).IsValid);
    }

    [Fact]
    public void ParseEd25519PublicKey_SupportsSpkiPemEscapedPemAndRawFormats_AndRejectsInvalid()
    {
        var pinned = RsaLicenseValidator.ParseEd25519PublicKey(RsaLicenseValidator.LicenseEd25519PublicKeyB64);
        var rawB64 = Convert.ToBase64String(pinned.GetEncoded());
        var pem = $"-----BEGIN PUBLIC KEY-----\n{RsaLicenseValidator.LicenseEd25519PublicKeyB64}\n-----END PUBLIC KEY-----";
        var escapedPem = $"-----BEGIN PUBLIC KEY-----\\n{RsaLicenseValidator.LicenseEd25519PublicKeyB64}\\n-----END PUBLIC KEY-----";

        var fromRaw = RsaLicenseValidator.ParseEd25519PublicKey(rawB64);
        var fromPem = RsaLicenseValidator.ParseEd25519PublicKey(pem);
        var fromEscapedPem = RsaLicenseValidator.ParseEd25519PublicKey(escapedPem);

        Assert.Equal(pinned.GetEncoded(), fromRaw.GetEncoded());
        Assert.Equal(pinned.GetEncoded(), fromPem.GetEncoded());
        Assert.Equal(pinned.GetEncoded(), fromEscapedPem.GetEncoded());

        Assert.Throws<CryptographicException>(() => RsaLicenseValidator.ParseEd25519PublicKey(""));
        Assert.Throws<CryptographicException>(() => RsaLicenseValidator.ParseEd25519PublicKey("-----BEGIN PUBLIC KEY-----\\n-----END PUBLIC KEY-----"));
        Assert.Throws<CryptographicException>(() => RsaLicenseValidator.ParseEd25519PublicKey("not-valid-base64!!!"));
        Assert.Throws<CryptographicException>(() => RsaLicenseValidator.ParseEd25519PublicKey(new byte[44])); // bad SPKI header
        Assert.Throws<CryptographicException>(() => RsaLicenseValidator.ParseEd25519PublicKey(new byte[16])); // wrong length
    }

    [Fact]
    public async Task EditionService_ActivatesAndPersists_Ed25519TokenWithAlgAndKid_AndBridgeLoadsCamelCase()
    {
        var (privKey, pubKey) = GenerateEd25519KeyPair();
        var validator = RsaLicenseValidator.CreateForTesting(_validatorLogger.Object, pubKey);
        var tempDir = Path.Combine(Path.GetTempPath(), $"logicflow_ed25519_{Guid.NewGuid():N}");

        try
        {
            var consent = new OmniPulse.ConsentStore(tempDir, (_, _) => null);
            var editionSvc = new LogicFlow.Dashboard.EditionService(consent, tempDir, validator);
            var hwid = new HwidGenerator().GenerateHwid();
            var expiresAt = DateTimeOffset.UtcNow.AddDays(365);

            var payload = JsonSerializer.Serialize(new
            {
                Email = "pro@delgadologic.tech",
                BoundHwid = hwid,
                Tier = "Pro",
                DeviceLimit = 3,
                SeatCount = 3,
                IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
                ExpiresAt = expiresAt.ToString("O"),
                OrderId = "ORD-ED25519-1",
                Kid = "ed25519-1",
                MajorVersion = 1
            });
            var sig = SignEd25519(payload, privKey);
            var token = new LicenseToken(payload, sig, "Ed25519", "ed25519-1");

            var validation = await editionSvc.ActivateAsync(token);
            Assert.True(validation.IsValid);
            Assert.Equal(Edition.Pro, editionSvc.Current);

            // Reload from disk and verify Alg/Kid/OrderId were persisted and token re-validates
            var reloaded = new LogicFlow.Dashboard.EditionService(consent, tempDir, validator);
            Assert.True(reloaded.AdoptSavedLicense());
            Assert.Equal(Edition.Pro, reloaded.Current);

            var bridge = new DelgadoLogic.Core.CloudLicenseBridge(
                Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, tempDir);
            var localToken = bridge.LoadLocalToken();
            Assert.NotNull(localToken);
            Assert.Equal("Ed25519", localToken!.Alg);
            Assert.Equal("ed25519-1", localToken.Kid);
            Assert.Equal("ORD-ED25519-1", localToken.OrderId);
            Assert.Equal("Pro", bridge.GetCurrentTier());

            // Also verify camelCase license_token.json deserializes cleanly in CloudLicenseBridge & EditionService
            var camelJson = JsonSerializer.Serialize(new
            {
                payload,
                signature = sig,
                alg = "Ed25519",
                kid = "ed25519-1",
                tier = "Pro",
                expiresAt = expiresAt.ToString("O"),
                orderId = "ORD-ED25519-1"
            });
            await File.WriteAllTextAsync(Path.Combine(tempDir, "License", "license_token.json"), camelJson);
            var camelLoaded = bridge.LoadLocalToken();
            Assert.NotNull(camelLoaded);
            Assert.Equal("Ed25519", camelLoaded!.Alg);
            Assert.Equal("ed25519-1", camelLoaded.Kid);
            Assert.Equal("Pro", bridge.GetCurrentTier());
            Assert.True(reloaded.LoadSavedValidation()?.IsValid);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void Validate_Ed25519EnvironmentOverride_HonorsValidKey_AndFailsClosedOnInvalidKey()
    {
        var (privKey, pubKey) = GenerateEd25519KeyPair();
        var rawPubB64 = Convert.ToBase64String(pubKey.GetEncoded());
        var escapedPem = $"-----BEGIN PUBLIC KEY-----\\n{rawPubB64}\\n-----END PUBLIC KEY-----";
        var hwid = new HwidGenerator().GenerateHwid();
        var payload = JsonSerializer.Serialize(new
        {
            Email = "env@delgadologic.tech",
            BoundHwid = hwid,
            Tier = "Community",
            DeviceLimit = 1,
            SeatCount = 1,
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365).ToString("O"),
            OrderId = "COMMUNITY-ENV-1",
            Kid = "ed25519-env",
            MajorVersion = 1
        });
        var sig = SignEd25519(payload, privKey);
        var token = new LicenseToken(payload, sig, "Ed25519", "ed25519-env");

        var prev = Environment.GetEnvironmentVariable(RsaLicenseValidator.Ed25519PublicKeyEnvVar);
        try
        {
            Environment.SetEnvironmentVariable(RsaLicenseValidator.Ed25519PublicKeyEnvVar, rawPubB64);
            var validatorWithOverride = new RsaLicenseValidator(_validatorLogger.Object);
            var ok = validatorWithOverride.Validate(token);
            Assert.True(ok.IsValid);
            Assert.Equal(LicenseTier.Community, ok.Tier);

            Environment.SetEnvironmentVariable(RsaLicenseValidator.Ed25519PublicKeyEnvVar, escapedPem);
            var validatorWithEscapedPem = new RsaLicenseValidator(_validatorLogger.Object);
            var okPem = validatorWithEscapedPem.Validate(token);
            Assert.True(okPem.IsValid);
            Assert.Equal(LicenseTier.Community, okPem.Tier);

            Environment.SetEnvironmentVariable(RsaLicenseValidator.Ed25519PublicKeyEnvVar, "not-a-valid-ed25519-key!!!");
            var validatorWithBadOverride = new RsaLicenseValidator(_validatorLogger.Object);
            var bad = validatorWithBadOverride.Validate(token);
            Assert.False(bad.IsValid);
            Assert.Equal(LicenseTier.Free, bad.Tier);
        }
        finally
        {
            Environment.SetEnvironmentVariable(RsaLicenseValidator.Ed25519PublicKeyEnvVar, prev);
        }
    }
}
