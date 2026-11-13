// ─────────────────────────────────────────────────────────────────────────────
// DelgadoLogic.Core — Shared Identity Engine
// Hardware-bound pseudonymous device identity used for licensing across DelgadoLogic products.
// Privacy-first: no PII, no names, no email — only hardware fingerprint.
// Mirrors Apple's device identity model and Adobe's machine fingerprinting.
// ─────────────────────────────────────────────────────────────────────────────

using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DelgadoLogic.Core;

/// <summary>
/// Generates and persists a stable, hardware-bound device identity
/// that is shared across all installed DelgadoLogic products.
///
/// The identity is:
/// - Pseudonymous: no name, email, or personal data
/// - Persistent: survives reboots and app reinstalls
/// - Hardware-bound: changes if significant hardware changes
/// - Shared: LogicFlow and Aeon Browser read the same identity file
/// </summary>
public sealed class DelgadoLogicIdentity
{
    private const string IdentityFileName = "device_identity.json";

    private static readonly object _sync = new();
    private static DelgadoLogicIdentity? _instance;
    private readonly DeviceIdentityRecord _record;
    private bool _isPersisted;

    /// <summary>
    /// Optional directory override for isolated unit tests so test runs never touch live %APPDATA%\DelgadoLogic\Shared.
    /// </summary>
    public static string? OverrideSharedRootForTesting { get; set; }

    private static string EffectiveSharedRoot =>
        !string.IsNullOrWhiteSpace(OverrideSharedRootForTesting)
            ? OverrideSharedRootForTesting!
            : ProductManifest.SharedAppDataRoot;

    private DelgadoLogicIdentity(DeviceIdentityRecord record, bool isPersisted)
    {
        _record = record;
        _isPersisted = isPersisted;
    }

    // ─── Public Surface ──────────────────────────────────────────────────

    /// <summary>
    /// Stable hardware device ID — SHA-256 of CPU + board + BIOS + disk serials.
    /// Used exclusively for license binding across installed DelgadoLogic products (never linked to OmniPulse telemetry installId).
    /// </summary>
    public string DeviceId => _record.DeviceId;

    /// <summary>
    /// Whether this identity record has been persisted to disk.
    /// False in Free ($0 — Zero Telemetry) ephemeral mode.
    /// </summary>
    public bool IsPersisted => _isPersisted;

    /// <summary>
    /// When this device identity was first established.
    /// </summary>
    public DateTimeOffset FirstSeenAt => _record.FirstSeenAt;

    /// <summary>
    /// How many times has any DelgadoLogic product been launched on this device.
    /// </summary>
    public int TotalLaunchCount => _record.TotalLaunchCount;

    /// <summary>
    /// List of product IDs that have been activated on this device.
    /// </summary>
    public IReadOnlyList<string> RegisteredProducts => _record.RegisteredProducts;

    // ─── Factory ────────────────────────────────────────────────────────

    /// <summary>
    /// Loads or creates the shared device identity.
    /// When <paramref name="allowDiskPersistence"/> is false (Free tier / zero-telemetry mode),
    /// computes or reads the identity strictly in memory without creating directories or writing device_identity.json.
    /// </summary>
    public static DelgadoLogicIdentity LoadOrCreate(bool allowDiskPersistence = true)
    {
        lock (_sync)
        {
            if (_instance is not null)
            {
                if (allowDiskPersistence && !_instance._isPersisted)
                {
                    _instance._record.TotalLaunchCount = Math.Max(1, _instance._record.TotalLaunchCount);
                    _instance.PersistRecord();
                    _instance._isPersisted = true;
                }
                return _instance;
            }

            var sharedRoot = EffectiveSharedRoot;
            var identityFile = Path.Combine(sharedRoot, IdentityFileName);

            DeviceIdentityRecord? record = null;

            if (File.Exists(identityFile))
            {
                try
                {
                    var json = File.ReadAllText(identityFile);
                    record = JsonSerializer.Deserialize<DeviceIdentityRecord>(json);
                }
                catch { /* corrupt file — regenerate below */ }
            }

            if (record is null)
            {
                record = new DeviceIdentityRecord
                {
                    DeviceId           = GenerateHwid(),
                    FirstSeenAt        = DateTimeOffset.UtcNow,
                    TotalLaunchCount   = 0,
                    RegisteredProducts = []
                };
            }

            if (allowDiskPersistence)
            {
                Directory.CreateDirectory(sharedRoot);
                record.TotalLaunchCount++;
                File.WriteAllText(identityFile, JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));
            }

            _instance = new DelgadoLogicIdentity(record, isPersisted: allowDiskPersistence && File.Exists(identityFile));
            return _instance;
        }
    }

    /// <summary>
    /// Deletes %APPDATA%\DelgadoLogic\Shared\device_identity.json (and the Shared folder if empty)
    /// and clears the cached singleton. Used when switching to Free tier or purging local privacy data.
    /// </summary>
    public static bool PurgePersistedIdentity()
    {
        lock (_sync)
        {
            _instance = null;
            try
            {
                var sharedRoot = EffectiveSharedRoot;
                var identityFile = Path.Combine(sharedRoot, IdentityFileName);
                bool deleted = false;
                if (File.Exists(identityFile))
                {
                    File.Delete(identityFile);
                    deleted = true;
                }
                if (Directory.Exists(sharedRoot) && !Directory.EnumerateFileSystemEntries(sharedRoot).Any())
                {
                    Directory.Delete(sharedRoot, recursive: false);
                }

                // Also purge any legacy %LOCALAPPDATA%\DelgadoLogic\device.json artifact
                if (string.IsNullOrWhiteSpace(OverrideSharedRootForTesting))
                {
                    try
                    {
                        var localDelgadoDir = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                            "DelgadoLogic");
                        var legacyDeviceJson = Path.Combine(localDelgadoDir, "device.json");
                        if (File.Exists(legacyDeviceJson))
                        {
                            File.Delete(legacyDeviceJson);
                            deleted = true;
                        }
                        if (Directory.Exists(localDelgadoDir) && !Directory.EnumerateFileSystemEntries(localDelgadoDir).Any())
                        {
                            Directory.Delete(localDelgadoDir, recursive: false);
                        }
                    }
                    catch { }
                }

                return deleted;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Resets the in-memory singleton (used in isolated unit tests).
    /// </summary>
    public static void ResetCacheForTesting()
    {
        lock (_sync)
        {
            _instance = null;
        }
    }

    /// <summary>
    /// Registers a product as installed/activated on this device.
    /// </summary>
    public void RegisterProduct(DelgadoProduct product)
    {
        var key = product.ToString();
        if (!_record.RegisteredProducts.Contains(key))
        {
            _record.RegisteredProducts.Add(key);
            if (_isPersisted)
            {
                PersistRecord();
            }
        }
    }

    // ─── HWID Generation ────────────────────────────────────────────────

    private static string GenerateHwid()
    {
        var sb = new StringBuilder();

        AppendWmi(sb, "Win32_Processor", "ProcessorId");
        AppendWmi(sb, "Win32_BaseBoard", "SerialNumber");
        AppendWmi(sb, "Win32_BIOS", "SerialNumber");
        AppendWmi(sb, "Win32_DiskDrive", "SerialNumber");

        // Fallback: use machine GUID from registry if WMI fails
        if (sb.Length == 0)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography");
                sb.Append(key?.GetValue("MachineGuid")?.ToString() ?? Environment.MachineName);
            }
            catch { sb.Append(Environment.MachineName); }
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToBase64String(hash)[..32]; // 32-char truncated base64
    }

    private static void AppendWmi(StringBuilder sb, string wmiClass, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (var obj in searcher.Get())
            {
                sb.Append(obj[property]?.ToString()?.Trim() ?? "");
                break;
            }
        }
        catch { /* WMI unavailable — handled by fallback */ }
    }

    private void PersistRecord()
    {
        var sharedRoot = EffectiveSharedRoot;
        var identityFile = Path.Combine(sharedRoot, IdentityFileName);
        Directory.CreateDirectory(sharedRoot);
        File.WriteAllText(identityFile, JsonSerializer.Serialize(_record, new JsonSerializerOptions { WriteIndented = true }));
    }
}

// ─── Internal Record ─────────────────────────────────────────────────────────

internal sealed class DeviceIdentityRecord
{
    public string DeviceId { get; set; } = "";
    public DateTimeOffset FirstSeenAt { get; set; }
    public int TotalLaunchCount { get; set; }
    public List<string> RegisteredProducts { get; set; } = [];
}
