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

    [Fact]
    public async Task SharedUpdateEngine_CheckAsync_VerifiesCanonicalJsonEnvelope_AndRejectsTamperedManifest()
    {
        var kpGen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
        kpGen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
        var keyPair = kpGen.GenerateKeyPair();
        var privateKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)keyPair.Private;
        var publicKey = (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)keyPair.Public;
        var pubKeyBytes = publicKey.GetEncoded();

        var keyField = typeof(DelgadoLogic.Core.SharedUpdateEngine).GetField(
            "SovereignPublicKey",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var originalKey = (byte[])keyField.GetValue(null)!;
        try
        {
            keyField.SetValue(null, pubKeyBytes);
            var prodManifest = DelgadoLogic.Core.ProductManifest.Register(DelgadoLogic.Core.DelgadoProduct.LogicFlow, "1.0.0");

            string rawManifestObj = """{"version":"1.2.0","tag":"v1.2.0","status":"update_available","product":"logicflow","channel":"stable","download_url":"https://delgadologic.tech/downloads/LogicFlowSetup.exe","sha256":"923c4c86177d2ee173a7f5b4fa3d0ac65f5962ab15e6d6a5bc250aec4fd7bf7e","size_bytes":130000000}""";
            using var doc = System.Text.Json.JsonDocument.Parse(rawManifestObj);
            string canonicalJson = DelgadoLogic.Core.SharedUpdateEngine.BuildCanonicalJsonPayload(doc.RootElement);
            var canonicalBytes = System.Text.Encoding.UTF8.GetBytes(canonicalJson);

            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(canonicalBytes, 0, canonicalBytes.Length);
            string sigB64 = Convert.ToBase64String(signer.GenerateSignature());

            string validEnvelope = $$"""{"manifest":{{rawManifestObj}},"signature":"{{sigB64}}"}""";
            string? observedUrl = null;
            using var validHttp = new System.Net.Http.HttpClient(new StubHttpHandler(req =>
            {
                observedUrl = req.RequestUri?.ToString();
                return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new System.Net.Http.StringContent(validEnvelope, System.Text.Encoding.UTF8, "application/json")
                };
            }));

            await using var engine = new DelgadoLogic.Core.SharedUpdateEngine(
                Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance,
                prodManifest,
                validHttp,
                "https://api.delgadologic.tech");

            var upgrade = await engine.CheckAsync("stable");
            Assert.Equal("https://api.delgadologic.tech/v1/update/logicflow/stable", observedUrl);
            Assert.NotNull(upgrade);
            Assert.Equal("1.2.0", upgrade!.Version);
            Assert.Equal("923c4c86177d2ee173a7f5b4fa3d0ac65f5962ab15e6d6a5bc250aec4fd7bf7e", upgrade.Sha256);

            // Tampered version in envelope MUST fail closed (null)
            string tamperedEnvelope = validEnvelope.Replace("\"1.2.0\"", "\"9.9.9\"");
            using var tamperedHttp = new System.Net.Http.HttpClient(new StubHttpHandler(_ =>
                new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new System.Net.Http.StringContent(tamperedEnvelope, System.Text.Encoding.UTF8, "application/json")
                }));
            await using var tamperedEngine = new DelgadoLogic.Core.SharedUpdateEngine(
                Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance,
                prodManifest,
                tamperedHttp,
                "https://api.delgadologic.tech");
            Assert.Null(await tamperedEngine.CheckAsync("stable"));
        }
        finally
        {
            keyField.SetValue(null, originalKey);
        }
    }

    // ── Canonical Sorted-Key Ed25519 + Fail-Closed SHA-256 Tests ──────────

    private static (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters priv, string pubPem) GenerateTestKeyPairPem()
    {
        var kpGen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
        kpGen.Init(new Org.BouncyCastle.Crypto.Parameters.Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
        var kp = kpGen.GenerateKeyPair();
        var priv = (Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters)kp.Private;
        var pub = (Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)kp.Public;

        // Wrap raw 32-byte Ed25519 public key in RFC 8410 SubjectPublicKeyInfo (44 bytes)
        byte[] prefix = [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
        var spki = new byte[44];
        Array.Copy(prefix, 0, spki, 0, 12);
        Array.Copy(pub.GetEncoded(), 0, spki, 12, 32);
        var pem = $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(spki)}\n-----END PUBLIC KEY-----";
        return (priv, pem);
    }

    private static string SignBytesEd25519(Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters priv, string canonicalJson)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(canonicalJson);
        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(true, priv);
        signer.BlockUpdate(bytes, 0, bytes.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    [Fact]
    public async Task OmniCoreAutoUpdate_VerifiesSortedKeyCanonicalJson_IncludingTagAndUnicode()
    {
        var (priv, pubPem) = GenerateTestKeyPairPem();
        const string sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Python json.dumps(manifest_dict, sort_keys=True, separators=(",", ":")) exact canonical output:
        const string pythonCanonical =
            "{\"channel\":\"stable\",\"download_url\":\"https://api.delgadologic.tech/downloads/LogicFlowSetup_v1.2.0.exe\"," +
            "\"min_os\":\"windows-10-1607\",\"product\":\"logicflow\",\"release_notes\":\"Boost \\u2014 zero hostage\"," +
            "\"sha256\":\"" + sha + "\",\"size_bytes\":123456,\"status\":\"available\",\"tag\":\"v1.2.0\"," +
            "\"ts\":\"2026-11-11T00:00:00+00:00\",\"version\":\"1.2.0\"}";

        var sig = SignBytesEd25519(priv, pythonCanonical);

        // Intentionally scramble property order in wire envelope (like Flask/JSON transport) + UTF-8 literal em-dash
        var wireEnvelope = $$"""
        {
          "signature": "{{sig}}",
          "pubkey_url": "https://api.delgadologic.tech/v1/keys/aeon_sovereign_v1.pub.pem",
          "manifest": {
            "version": "1.2.0",
            "tag": "v1.2.0",
            "product": "logicflow",
            "status": "available",
            "channel": "stable",
            "release_notes": "Boost — zero hostage",
            "download_url": "https://api.delgadologic.tech/downloads/LogicFlowSetup_v1.2.0.exe",
            "sha256": "{{sha}}",
            "size_bytes": 123456,
            "min_os": "windows-10-1607",
            "ts": "2026-11-11T00:00:00+00:00"
          }
        }
        """;

        var handler = new StubHttpHandler(_ => new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new System.Net.Http.StringContent(wireEnvelope, System.Text.Encoding.UTF8, "application/json")
        });
        using var http = new System.Net.Http.HttpClient(handler);
        var engine = new AutoUpdateEngine(_logger.Object, http, pubPem, "https://api.delgadologic.tech/v1/update/logicflow/stable");

        var res = await engine.CheckForUpdateAsync();
        Assert.NotNull(res);
        Assert.True(res!.UpdateAvailable);
        Assert.Equal("1.2.0", res.LatestVersion);
        Assert.Equal(sha, res.Sha256);
    }

    [Fact]
    public async Task DashboardAutoUpdate_RejectsUnsignedOrTamperedManifest_AndVerifiesDownloadAndApply()
    {
        var (priv, pubPem) = GenerateTestKeyPairPem();
        var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "lf_upd_test_" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(tempDir);

        try
        {
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes("FAKE_SIGNED_INSTALLER_BINARY_V1_2_0");
            var actualSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payloadBytes)).ToLowerInvariant();

            var canonical =
                "{\"channel\":\"stable\",\"download_url\":\"https://api.delgadologic.tech/dl/LogicFlowSetup.exe\"," +
                "\"product\":\"logicflow\",\"sha256\":\"" + actualSha + "\",\"size_bytes\":" + payloadBytes.Length + "," +
                "\"status\":\"available\",\"tag\":\"v1.2.0\",\"version\":\"1.2.0\"}";
            var validSig = SignBytesEd25519(priv, canonical);

            // 1. Unsigned envelope -> rejected
            var unsignedEnv = "{\"manifest\":{\"product\":\"logicflow\",\"channel\":\"stable\",\"version\":\"1.2.0\",\"status\":\"available\",\"download_url\":\"https://api.delgadologic.tech/dl/LogicFlowSetup.exe\",\"sha256\":\"" + actualSha + "\"}}";
            using (var badEngine = new LogicFlow.Dashboard.AutoUpdateEngine("1.0.0", "stable",
                new StubHttpHandler(_ => new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new System.Net.Http.StringContent(unsignedEnv, System.Text.Encoding.UTF8, "application/json")
                }), tempDir, pubPem))
            {
                string? failReason = null;
                badEngine.UpdateFailed += r => failReason = r;
                var badInfo = await badEngine.CheckForUpdateAsync();
                Assert.Null(badInfo);
                Assert.NotNull(failReason);
            }

            // 2. Valid signed envelope + verified binary download + TOCTOU tamper blocked in ApplyUpdate
            var validEnv = "{\"signature\":\"" + validSig + "\",\"manifest\":{\"version\":\"1.2.0\",\"tag\":\"v1.2.0\",\"product\":\"logicflow\",\"channel\":\"stable\",\"status\":\"available\",\"download_url\":\"https://api.delgadologic.tech/dl/LogicFlowSetup.exe\",\"sha256\":\"" + actualSha + "\",\"size_bytes\":" + payloadBytes.Length + "}}";
            using var goodEngine = new LogicFlow.Dashboard.AutoUpdateEngine("1.0.0", "stable",
                new StubHttpHandler(req =>
                {
                    if (req.RequestUri!.AbsolutePath.Contains("/v1/update/"))
                    {
                        return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                        {
                            Content = new System.Net.Http.StringContent(validEnv, System.Text.Encoding.UTF8, "application/json")
                        };
                    }
                    return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                    {
                        Content = new System.Net.Http.ByteArrayContent(payloadBytes)
                    };
                }), tempDir, pubPem);

            var info = await goodEngine.CheckForUpdateAsync();
            Assert.NotNull(info);
            Assert.Equal("1.2.0", info!.Version);
            Assert.Equal(actualSha, info.Sha256Hash);

            // Download with wrong hash must fail closed and discard file
            var tamperedInfo = new LogicFlow.Dashboard.UpdateInfo
            {
                Version = "1.2.0",
                DownloadUrl = info.DownloadUrl,
                Sha256Hash = new string('0', 64)
            };
            Assert.Null(await goodEngine.DownloadUpdateAsync(tamperedInfo));

            // Download with empty hash must fail closed
            var emptyHashInfo = new LogicFlow.Dashboard.UpdateInfo
            {
                Version = "1.2.0",
                DownloadUrl = info.DownloadUrl,
                Sha256Hash = ""
            };
            Assert.Null(await goodEngine.DownloadUpdateAsync(emptyHashInfo));

            // Download with matching hash succeeds
            var downloadedPath = await goodEngine.DownloadUpdateAsync(info);
            Assert.NotNull(downloadedPath);
            Assert.True(System.IO.File.Exists(downloadedPath!));

            // Tamper with the downloaded file on disk before ApplyUpdate -> ApplyUpdate MUST refuse to execute!
            await System.IO.File.WriteAllTextAsync(downloadedPath!, "CORRUPTED_AFTER_DOWNLOAD");
            Assert.False(goodEngine.ApplyUpdate(downloadedPath!));

            // Unverified arbitrary file in %TEMP% -> ApplyUpdate MUST refuse to execute!
            var unverifiedTempExe = System.IO.Path.Combine(tempDir, "LogicFlowSetup_Update.exe");
            await System.IO.File.WriteAllBytesAsync(unverifiedTempExe, payloadBytes);
            Assert.False(goodEngine.ApplyUpdate(unverifiedTempExe));
        }
        finally
        {
            try { System.IO.Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private sealed class StubHttpHandler(Func<System.Net.Http.HttpRequestMessage, System.Net.Http.HttpResponseMessage> responder)
        : System.Net.Http.HttpMessageHandler
    {
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
