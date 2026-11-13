// OmniCore.Engine — AutoUpdateEngine Unit Tests
// Tests version comparison, response handling, and signature verification flows.

using OmniCore.Engine;
using Microsoft.Extensions.Logging;
using Moq;

namespace LogicFlow.Tests;

public class AutoUpdateEngineTests
{
    private readonly Mock<ILogger<AutoUpdateEngine>> _logger = new();

    // ── Version Constant Tests ────────────────────────────────────────────

    [Fact]
    public void CurrentVersion_IsValidSemver()
    {
        Assert.True(Version.TryParse(AutoUpdateEngine.CurrentVersion, out var version));
        Assert.True(version.Major >= 1);
    }

    [Fact]
    public void CurrentVersion_Matches_1_0_0()
    {
        Assert.Equal("1.0.0", AutoUpdateEngine.CurrentVersion);
    }

    // ── Construction Tests ────────────────────────────────────────────────

    [Fact]
    public void Constructor_DoesNotThrow()
    {
        var engine = new AutoUpdateEngine(_logger.Object);
        Assert.NotNull(engine);
    }

    // ── CheckForUpdate Tests (Network-dependent) ──────────────────────────

    [Fact]
    public async Task CheckForUpdate_ReturnsNullOnNetworkError()
    {
        // The sovereign server likely isn't running in test environment
        var engine = new AutoUpdateEngine(_logger.Object);
        var result = await engine.CheckForUpdateAsync(CancellationToken.None);

        // Should gracefully return null (not throw) on network timeout/error
        // This validates the error handling path
        Assert.Null(result);
    }

    [Fact]
    public async Task CheckForUpdate_RespectsCancel()
    {
        var engine = new AutoUpdateEngine(_logger.Object);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await engine.CheckForUpdateAsync(cts.Token);
        Assert.Null(result);
    }

    // ── UpdateCheckResult Model Tests ─────────────────────────────────────

    [Fact]
    public void UpdateCheckResult_NoUpdate_IsCorrect()
    {
        var result = new UpdateCheckResult(
            UpdateAvailable: false,
            CurrentVersion: "1.0.0",
            LatestVersion: "1.0.0",
            DownloadUrl: null,
            ReleaseNotes: null,
            Signature: null);

        Assert.False(result.UpdateAvailable);
        Assert.Equal("1.0.0", result.CurrentVersion);
        Assert.Equal("1.0.0", result.LatestVersion);
    }

    [Fact]
    public void UpdateCheckResult_UpdateAvailable_IsCorrect()
    {
        var result = new UpdateCheckResult(
            UpdateAvailable: true,
            CurrentVersion: "1.0.0",
            LatestVersion: "1.1.0",
            DownloadUrl: "https://api.delgadologic.tech/downloads/logicflow/1.1.0",
            ReleaseNotes: "Bug fixes and performance improvements",
            Signature: "dGVzdA==");

        Assert.True(result.UpdateAvailable);
        Assert.Equal("1.1.0", result.LatestVersion);
        Assert.NotNull(result.DownloadUrl);
        Assert.NotNull(result.ReleaseNotes);
    }

    // ── Ed25519 Signature Verification Tests ─────────────────────────────────

    [Fact]
    public void VerifySignature_WithInvalidSignature_ReturnsFalse()
    {
        var manifestType = typeof(AutoUpdateEngine).GetNestedType("UpdateManifest", System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(manifestType);
        
        var manifest = Activator.CreateInstance(manifestType);
        Assert.NotNull(manifest);

        var json = "{\"product\":\"logicflow\",\"channel\":\"stable\",\"version\":\"1.0.0\",\"status\":\"no_update\"}";
        var deserializedManifest = System.Text.Json.JsonSerializer.Deserialize(json, manifestType);

        var verifyMethod = typeof(AutoUpdateEngine).GetMethod("VerifySignature", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(verifyMethod);

        var badSig = Convert.ToBase64String(new byte[64]);
        var result = verifyMethod.Invoke(null, new[] { deserializedManifest, badSig });

        Assert.False((bool)result!);
    }

    [Fact]
    public void VerifySignature_WithEmptySignature_ReturnsFalse()
    {
        var manifestType = typeof(AutoUpdateEngine).GetNestedType("UpdateManifest", System.Reflection.BindingFlags.NonPublic);
        var manifest = Activator.CreateInstance(manifestType!);
        
        var verifyMethod = typeof(AutoUpdateEngine).GetMethod("VerifySignature", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        
        var result = verifyMethod!.Invoke(null, new[] { manifest, "" });
        Assert.False((bool)result!);
    }

    [Fact]
    public void SharedUpdateEngine_VerifySignature_ValidSignature_ReturnsTrue()
    {
        // 1. Generate a test Ed25519 key pair
        var kpGen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
        kpGen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
        var keyPair = kpGen.GenerateKeyPair();
        var privateKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)keyPair.Private;
        var publicKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)keyPair.Public;
        var pubKeyBytes = publicKey.GetEncoded();

        // 2. Temporarily set the SovereignPublicKey field in SharedUpdateEngine to our test public key
        var keyField = typeof(DelgadoLogic.Core.SharedUpdateEngine).GetField("SovereignPublicKey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(keyField);
        
        var originalKey = (byte[])keyField.GetValue(null)!;
        try
        {
            keyField.SetValue(null, pubKeyBytes);

            // 3. Create a valid manifest and sign it
            var manifest = new DelgadoLogic.Core.UpdateManifest
            {
                Product = "logicflow",
                Channel = "stable",
                Version = "1.1.0",
                DownloadUrl = "https://example.com/download",
                Sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            };

            // Canonical payload format: product|channel|version|url|sha256
            var payload = $"{manifest.Product}|{manifest.Channel}|{manifest.Version}" +
                          $"|{manifest.DownloadUrl}|{manifest.Sha256}";
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);

            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
            var signatureBytes = signer.GenerateSignature();
            manifest.Signature = Convert.ToBase64String(signatureBytes);

            // 4. Invoke VerifySignature via reflection
            var verifyMethod = typeof(DelgadoLogic.Core.SharedUpdateEngine).GetMethod("VerifySignature", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            Assert.NotNull(verifyMethod);

            var result = (bool)verifyMethod.Invoke(null, new object[] { manifest })!;
            Assert.True(result);
        }
        finally
        {
            // Restore the original public key
            keyField.SetValue(null, originalKey);
        }
    }
}
