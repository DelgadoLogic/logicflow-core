// LogicFlow.Dashboard — Auto-Update Engine
// Proprietary implementation by DelgadoLogic.Tech
// Version check, SHA-256 hash verification, and self-update mechanism
// Sovereign update endpoint: api.delgadologic.tech (proxied → Cloud Run)
// Ed25519 manifest signature verified before applying any update.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

[assembly: InternalsVisibleTo("LogicFlow.Tests")]

namespace LogicFlow.Dashboard;

/// <summary>
/// Handles automatic updates for LogicFlow via the DelgadoLogic sovereign update server.
/// Verifies canonical Ed25519 manifest signatures and fail-closed SHA-256 binary hashes
/// before downloading or executing any update package.
/// Endpoint: https://api.delgadologic.tech/v1/update/logicflow/{channel}
/// </summary>
public sealed class AutoUpdateEngine : IDisposable
{
    // ─── Sovereign Server (api.delgadologic.tech → Firebase Proxy → Cloud Run) ─
    private const string SovereignBase = "https://api.delgadologic.tech";
    private const string ProductId     = "logicflow";
    private const int    MaxRetries    = 3;
    private const int    RetryDelayMs  = 2000;

    private readonly HttpClient _http;
    private readonly ILogger<AutoUpdateEngine>? _logger;
    private readonly string _currentVersion;
    private readonly string _channel;
    private readonly string _updateDir;
    private readonly string? _publicKeyPemOverride;
    private readonly ConcurrentDictionary<string, string> _verifiedBinaryHashes =
        new(StringComparer.OrdinalIgnoreCase);

    public event Action<UpdateInfo>? UpdateAvailable;
    public event Action<double>?     DownloadProgress;
    public event Action<string>?     UpdateFailed;

    public AutoUpdateEngine(string currentVersion = "1.0.0", string channel = "stable", ILogger<AutoUpdateEngine>? logger = null)
    {
        _logger         = logger;
        _currentVersion = currentVersion;
        _channel        = channel;
        _http           = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Add("User-Agent", $"LogicFlow/{currentVersion} (DelgadoLogic)");
        _updateDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow", "Updates");
        Directory.CreateDirectory(_updateDir);
    }

    internal AutoUpdateEngine(
        string currentVersion,
        string channel,
        HttpMessageHandler handler,
        string? updateDirOverride = null,
        string? publicKeyPemOverride = null,
        ILogger<AutoUpdateEngine>? logger = null)
    {
        _logger               = logger;
        _currentVersion       = currentVersion;
        _channel              = channel;
        _publicKeyPemOverride = publicKeyPemOverride;
        _http                 = new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.Add("User-Agent", $"LogicFlow/{currentVersion} (DelgadoLogic)");
        _updateDir = string.IsNullOrWhiteSpace(updateDirOverride)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow", "Updates")
            : updateDirOverride;
        Directory.CreateDirectory(_updateDir);
    }

    // ─── Public API ────────────────────────────────────────────────────────

    /// <summary>
    /// Checks the sovereign update server for a newer version.
    /// Verifies the Ed25519 signature over canonical sorted-key JSON before trusting the manifest.
    /// Returns null if up-to-date, tampered, or unreachable.
    /// </summary>
    public async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        var endpoint = $"{SovereignBase}/v1/update/{ProductId}/{_channel}";

        for (int attempt = 1; attempt <= MaxRetries; attempt++)
        {
            try
            {
                var json = await _http.GetStringAsync(endpoint, ct);

                if (!OmniCore.Engine.AutoUpdateEngine.TryParseAndVerifyEnvelope(
                        json, _publicKeyPemOverride, out var verifiedManifest, out var signature) ||
                    verifiedManifest == null)
                {
                    const string sigMsg = "Ed25519 manifest signature verification failed — update rejected.";
                    _logger?.LogError("[AutoUpdate] {Message}", sigMsg);
                    UpdateFailed?.Invoke(sigMsg);
                    return null;
                }

                var info = MapToUpdateInfo(verifiedManifest, signature);

                if (info != null && verifiedManifest.Status != "no_update" && IsNewerVersion(info.Version))
                {
                    if (!OmniCore.Engine.AutoUpdateEngine.IsTrustedHttpsUrl(info.DownloadUrl) ||
                        !OmniCore.Engine.AutoUpdateEngine.IsValidSha256Hex(info.Sha256Hash))
                    {
                        const string integrityMsg = "Signed manifest is missing a valid HTTPS download_url or 64-hex SHA-256 hash.";
                        _logger?.LogError("[AutoUpdate] {Message}", integrityMsg);
                        UpdateFailed?.Invoke(integrityMsg);
                        return null;
                    }

                    _logger?.LogInformation("Update available: {Version} (critical={Critical})",
                        info.Version, info.IsCritical);
                    UpdateAvailable?.Invoke(info);
                    return info;
                }

                _logger?.LogDebug("No update — current={Current}, remote={Remote}",
                    _currentVersion, info?.Version ?? "0.0.0");
                return null;
            }
            catch (TaskCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Update check attempt {Attempt} failed", attempt);
                if (attempt < MaxRetries)
                    await Task.Delay(RetryDelayMs * attempt, ct);
            }
        }

        return null;
    }

    /// <summary>
    /// Downloads the update package with progress reporting and mandatory SHA-256 verification.
    /// </summary>
    public async Task<string?> DownloadUpdateAsync(UpdateInfo info, CancellationToken ct = default)
    {
        if (info == null ||
            !OmniCore.Engine.AutoUpdateEngine.IsTrustedHttpsUrl(info.DownloadUrl) ||
            !OmniCore.Engine.AutoUpdateEngine.IsValidSha256Hex(info.Sha256Hash))
        {
            const string msg = "Refusing update download: missing valid HTTPS URL or expected SHA-256 digest.";
            _logger?.LogError("[AutoUpdate] {Message}", msg);
            UpdateFailed?.Invoke(msg);
            return null;
        }

        string? partPath = null;
        try
        {
            var safeVersion = SanitizeVersionToken(info.Version);
            var destPath = Path.GetFullPath(Path.Combine(_updateDir, $"LogicFlowSetup_v{safeVersion}.exe"));

            if (File.Exists(destPath) && await VerifyHashAsync(destPath, info.Sha256Hash, ct))
            {
                _verifiedBinaryHashes[destPath] = info.Sha256Hash;
                _logger?.LogInformation("Installer already present and SHA-256 verified: {Path}", destPath);
                return destPath;
            }

            partPath = destPath + ".part";
            using var response = await _http.GetAsync(
                info.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? 0;
            var buffer     = new byte[81920];
            long downloaded = 0;

            await using (var contentStream = await response.Content.ReadAsStreamAsync(ct))
            await using (var fileStream    = new FileStream(partPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                int bytesRead;
                while ((bytesRead = await contentStream.ReadAsync(buffer, ct)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
                    downloaded += bytesRead;
                    if (totalBytes > 0)
                        DownloadProgress?.Invoke((double)downloaded / totalBytes * 100);
                }
                await fileStream.FlushAsync(ct);
            }

            // Fail-closed SHA-256 verification before promoting .part file
            if (!await VerifyHashAsync(partPath, info.Sha256Hash, ct))
            {
                TryDeleteFile(partPath);
                const string msg = "SHA-256 hash verification failed — download discarded";
                _logger?.LogError("[AutoUpdate] {Message}", msg);
                UpdateFailed?.Invoke(msg);
                return null;
            }

            File.Move(partPath, destPath, overwrite: true);
            _verifiedBinaryHashes[destPath] = info.Sha256Hash;
            _logger?.LogInformation("Download SHA-256 verified: {Path}", destPath);
            return destPath;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            if (partPath != null) TryDeleteFile(partPath);
            throw;
        }
        catch (Exception ex)
        {
            if (partPath != null) TryDeleteFile(partPath);
            UpdateFailed?.Invoke(ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Re-verifies the downloaded installer's SHA-256 hash against the signed manifest record
    /// immediately before execution, launches it with /SILENT /RESTARTAPPLICATIONS, and exits.
    /// </summary>
    public bool ApplyUpdate(string setupPath) => ApplyUpdate(setupPath, expectedSha256: null);

    public bool ApplyUpdate(string setupPath, string? expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(setupPath))
        {
            UpdateFailed?.Invoke("Update installer path is empty.");
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(setupPath);
        }
        catch
        {
            UpdateFailed?.Invoke("Invalid update installer path.");
            return false;
        }

        if (!File.Exists(fullPath))
        {
            UpdateFailed?.Invoke("Update installer file does not exist.");
            return false;
        }

        var hashToCheck = !string.IsNullOrWhiteSpace(expectedSha256)
            ? expectedSha256
            : (_verifiedBinaryHashes.TryGetValue(fullPath, out var recorded) ? recorded : null);

        if (!OmniCore.Engine.AutoUpdateEngine.VerifyFileSha256(fullPath, hashToCheck))
        {
            const string msg = "Refusing to launch update installer: SHA-256 verification failed or binary was not verified.";
            _logger?.LogError("[AutoUpdate] {Message} ({Path})", msg, fullPath);
            UpdateFailed?.Invoke(msg);
            return false;
        }

        var proc = Process.Start(new ProcessStartInfo
        {
            FileName        = fullPath,
            Arguments       = "/SILENT /RESTARTAPPLICATIONS",
            UseShellExecute = true,
            Verb            = "runas"
        });

        if (proc == null)
        {
            UpdateFailed?.Invoke("Failed to start update installer process.");
            return false;
        }

        System.Windows.Application.Current?.Shutdown();
        return true;
    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    private bool IsNewerVersion(string remoteVersion)
    {
        if (Version.TryParse(remoteVersion, out var remote) &&
            Version.TryParse(_currentVersion, out var current))
            return remote > current;
        return false;
    }

    private static string SanitizeVersionToken(string version)
    {
        if (string.IsNullOrWhiteSpace(version)) return "0.0.0";
        var chars = version.Where(static c => char.IsLetterOrDigit(c) || c == '.' || c == '-').ToArray();
        return chars.Length > 0 ? new string(chars) : "0.0.0";
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static UpdateInfo MapToUpdateInfo(OmniCore.Engine.VerifiedManifestData m, string? signature)
    {
        if (string.IsNullOrEmpty(m.Version) || m.Status == "no_update")
            return new UpdateInfo { Version = m.Version ?? "0.0.0", Signature = signature ?? "" };

        return new UpdateInfo
        {
            Version      = m.Version,
            DownloadUrl  = m.DownloadUrl ?? "",
            ReleaseNotes = m.ReleaseNotes ?? "",
            Sha256Hash   = m.Sha256 ?? "",
            SizeBytes    = m.SizeBytes ?? 0,
            ReleasedAt   = m.ReleasedAt ?? default,
            IsCritical   = m.IsCritical ?? false,
            Signature    = signature ?? ""
        };
    }

    private static Task<bool> VerifyHashAsync(string filePath, string expectedHash, CancellationToken ct) =>
        OmniCore.Engine.AutoUpdateEngine.VerifyFileSha256Async(filePath, expectedHash, ct);

    public void Dispose() => _http.Dispose();
}

// ─── Sovereign Manifest envelope (retained for internal compatibility) ────

internal sealed class UpdateEnvelope
{
    [JsonPropertyName("manifest")]
    public SovereignManifest? Manifest   { get; set; }
    [JsonPropertyName("signature")]
    public string?            Signature  { get; set; }
    [JsonPropertyName("pubkey_url")]
    public string?            PubkeyUrl  { get; set; }
}

internal sealed class SovereignManifest
{
    [JsonPropertyName("product")]
    public string?          Product      { get; set; }
    [JsonPropertyName("channel")]
    public string?          Channel      { get; set; }
    [JsonPropertyName("version")]
    public string?          Version      { get; set; }
    [JsonPropertyName("status")]
    public string?          Status       { get; set; }
    [JsonPropertyName("download_url")]
    public string?          DownloadUrl  { get; set; }
    [JsonPropertyName("release_notes")]
    public string?          ReleaseNotes { get; set; }
    [JsonPropertyName("sha256")]
    public string?          Sha256Hash   { get; set; }
    [JsonPropertyName("size_bytes")]
    public long             SizeBytes    { get; set; }
    [JsonPropertyName("released_at")]
    public DateTimeOffset   ReleasedAt   { get; set; }
    [JsonPropertyName("is_critical")]
    public bool             IsCritical   { get; set; }
    [JsonPropertyName("tag")]
    public string?          Tag          { get; set; }
    [JsonPropertyName("ts")]
    public string?          Ts           { get; set; }
}

// ─── Public UpdateInfo contract (backwards-compatible) ────────────────────

/// <summary>Update information returned to callers of CheckForUpdateAsync.</summary>
public sealed class UpdateInfo
{
    public string           Version      { get; set; } = "";
    public string           DownloadUrl  { get; set; } = "";
    public string           ReleaseNotes { get; set; } = "";
    public string           Sha256Hash   { get; set; } = "";
    public long             SizeBytes    { get; set; }
    public DateTimeOffset   ReleasedAt   { get; set; }
    public bool             IsCritical   { get; set; }
    public string           Signature    { get; set; } = "";
}
