// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — ConsentStore
// Per-user telemetry/EULA consent record (%LOCALAPPDATA%\LogicFlow\Pulse\consent.json).
// Single source of truth for "may we send anything, and what". Fails closed:
// no record, unreadable record, undecided first run, kill-switch or machine policy => nothing is sent.
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OmniPulse;

/// <summary>How much data the user has agreed to share.</summary>
public enum ConsentLevel
{
    /// <summary>Nothing is collected or sent.</summary>
    None = 0,

    /// <summary>Crash/error reports, pseudonymous feature usage, scan counts.</summary>
    Standard = 1,

    /// <summary>Standard plus the system baseline (services, BIOS/firmware, devices/drivers, KB list) for the crowd-sourced driver index.</summary>
    Extended = 2
}

/// <summary>The edition the user picked on first run (the licence token can still upgrade this to Pro).</summary>
public enum EditionChoice
{
    Free = 0,
    Community = 1,
    Pro = 2
}

/// <summary>Region group used only to decide how consent is presented. No IP lookup is ever performed.</summary>
public enum PrivacyRegion
{
    RestOfWorld = 0,
    EuEea = 1,
    UnitedKingdom = 2,
    Switzerland = 3,
    UnitedStates = 4,
    Canada = 5,
    Mexico = 6,
    AustraliaNewZealand = 7,
    Japan = 8,
    SouthKorea = 9,
    Brazil = 10,
    India = 11
}

public static class PrivacyRegionExtensions
{
    /// <summary>
    /// Strict-consent jurisdictions (EU/EEA, UK, Switzerland, Canada, Brazil, Japan, South Korea, India)
    /// require Extended diagnostics to be unchecked by default (opt-in). Non-strict regions (United States,
    /// Mexico, Australia/NZ, Rest of world) pre-check Extended by default while keeping it user-toggleable.
    /// </summary>
    public static bool IsStrict(this PrivacyRegion region) => region switch
    {
        PrivacyRegion.EuEea => true,
        PrivacyRegion.UnitedKingdom => true,
        PrivacyRegion.Switzerland => true,
        PrivacyRegion.Canada => true,
        PrivacyRegion.Brazil => true,
        PrivacyRegion.Japan => true,
        PrivacyRegion.SouthKorea => true,
        PrivacyRegion.India => true,
        _ => false
    };

    /// <summary>Alias for <see cref="IsStrict"/>: true when Extended must default to unchecked.</summary>
    public static bool RequiresGranularExtendedConsent(this PrivacyRegion region) => region.IsStrict();

    /// <summary>Coarse label sent with events (matches the server's ^([A-Z]{2}|unknown)$ rule). Never a specific city.</summary>
    public static string Label(this PrivacyRegion region) => region switch
    {
        PrivacyRegion.EuEea => "EU",
        PrivacyRegion.UnitedKingdom => "GB",
        PrivacyRegion.Switzerland => "CH",
        PrivacyRegion.UnitedStates => "US",
        PrivacyRegion.Canada => "CA",
        PrivacyRegion.Mexico => "MX",
        PrivacyRegion.AustraliaNewZealand => "AU",
        PrivacyRegion.Japan => "JP",
        PrivacyRegion.SouthKorea => "KR",
        PrivacyRegion.Brazil => "BR",
        PrivacyRegion.India => "IN",
        _ => "unknown"
    };

    /// <summary>Human-readable display name for UI presentation.</summary>
    public static string DisplayName(this PrivacyRegion region) => region switch
    {
        PrivacyRegion.UnitedStates => "United States",
        PrivacyRegion.Canada => "Canada",
        PrivacyRegion.Mexico => "Mexico",
        PrivacyRegion.EuEea => "European Union / EEA",
        PrivacyRegion.UnitedKingdom => "United Kingdom",
        PrivacyRegion.Switzerland => "Switzerland",
        PrivacyRegion.AustraliaNewZealand => "Australia / New Zealand",
        PrivacyRegion.Japan => "Japan",
        PrivacyRegion.SouthKorea => "South Korea",
        PrivacyRegion.Brazil => "Brazil",
        PrivacyRegion.India => "India",
        _ => "Other / Rest of world"
    };

    private static readonly HashSet<string> EeaCountries = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE","IT","LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE",
        "IS","LI","NO"
    };

    /// <summary>Maps an ISO-3166 alpha-2 code (from the Windows region setting) to a region group.</summary>
    public static PrivacyRegion FromCountryCode(string? iso2)
    {
        if (string.IsNullOrWhiteSpace(iso2)) return PrivacyRegion.RestOfWorld;
        var code = iso2.Trim().ToUpperInvariant();
        if (EeaCountries.Contains(code)) return PrivacyRegion.EuEea;
        return code switch
        {
            "US" => PrivacyRegion.UnitedStates,
            "CA" => PrivacyRegion.Canada,
            "MX" => PrivacyRegion.Mexico,
            "GB" or "UK" => PrivacyRegion.UnitedKingdom,
            "CH" => PrivacyRegion.Switzerland,
            "AU" or "NZ" => PrivacyRegion.AustraliaNewZealand,
            "JP" => PrivacyRegion.Japan,
            "KR" => PrivacyRegion.SouthKorea,
            "BR" => PrivacyRegion.Brazil,
            "IN" => PrivacyRegion.India,
            _ => PrivacyRegion.RestOfWorld
        };
    }

    /// <summary>
    /// Reads the 2-letter ISO country code from Windows Geo settings (HKCU\Control Panel\International\Geo -> Name),
    /// falling back to <see cref="System.Globalization.RegionInfo.CurrentRegion"/>.
    /// </summary>
    public static string DetectWindowsIsoCode(Func<string, string, object?>? registryReader = null)
    {
        try
        {
            object? geoVal = null;
            if (registryReader is not null)
            {
                geoVal = registryReader(@"HKCU\Control Panel\International\Geo", "Name");
            }
            else
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Control Panel\International\Geo", writable: false);
                geoVal = key?.GetValue("Name");
            }

            if (geoVal is string geoStr && !string.IsNullOrWhiteSpace(geoStr))
            {
                var trimmed = geoStr.Trim().ToUpperInvariant();
                if (trimmed.Length == 2 && char.IsLetter(trimmed[0]) && char.IsLetter(trimmed[1]))
                    return trimmed;
            }
        }
        catch { }

        try
        {
            var twoLetter = System.Globalization.RegionInfo.CurrentRegion.TwoLetterISORegionName;
            if (!string.IsNullOrWhiteSpace(twoLetter))
                return twoLetter.Trim().ToUpperInvariant();
        }
        catch { }

        return "US";
    }

    /// <summary>Best guess from the user's Windows region setting (Settings → Time &amp; language → Region). Used only to pre-select the "Where are you?" answer.</summary>
    public static PrivacyRegion DetectFromWindowsRegion(Func<string, string, object?>? registryReader = null)
    {
        try { return FromCountryCode(DetectWindowsIsoCode(registryReader)); }
        catch { return PrivacyRegion.RestOfWorld; }
    }
}

/// <summary>Pure consent rules, separated from storage so they can be unit-tested.</summary>
public static class ConsentPolicy
{
    /// <summary>
    /// Computes the consent level implied by the user's choices.
    /// Free: never. Community: Standard is mandatory; Extended follows <paramref name="wantsExtended"/>
    /// (pre-checked by default in non-strict regions and unchecked by default in strict regions, toggleable in both).
    /// Pro: optional, off unless the user opts in.
    /// </summary>
    public static ConsentLevel Compute(EditionChoice edition, PrivacyRegion region, bool wantsStandard, bool wantsExtended)
    {
        switch (edition)
        {
            case EditionChoice.Community:
                return wantsExtended ? ConsentLevel.Extended : ConsentLevel.Standard;

            case EditionChoice.Pro:
                if (!wantsStandard && !wantsExtended) return ConsentLevel.None;
                return wantsExtended ? ConsentLevel.Extended : ConsentLevel.Standard;

            default:
                return ConsentLevel.None;
        }
    }

    /// <summary>Community requires at least Standard. Anything weaker is not a valid Community consent.</summary>
    public static bool SatisfiesCommunityCondition(ConsentLevel level) => level >= ConsentLevel.Standard;
}

/// <summary>Persisted consent record. Plain data; do not add fields that identify the machine or user.</summary>
public sealed class ConsentRecord
{
    public int Schema { get; set; } = 1;
    public EditionChoice Edition { get; set; } = EditionChoice.Free;
    public ConsentLevel Level { get; set; } = ConsentLevel.None;
    public PrivacyRegion Region { get; set; } = PrivacyRegion.RestOfWorld;
    public bool RegionConfirmed { get; set; }

    /// <summary>Version of the telemetry disclosure the user saw.</summary>
    public string PolicyVersion { get; set; } = "";
    public string EulaVersion { get; set; } = "";

    /// <summary>SHA-256 (hex) of the EULA text the user accepted.</summary>
    public string EulaSha256 { get; set; } = "";
    public DateTimeOffset? EulaAcceptedAt { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }

    /// <summary>Random, rotatable, deletable. Never derived from hardware.</summary>
    public string InstallId { get; set; } = "";
    public DateTimeOffset? InstallIdCreatedAt { get; set; }

    /// <summary>Set when a delete request could not reach the server; retried on next launch.</summary>
    public string? PendingDeleteInstallId { get; set; }

    /// <summary>Server kill-switch: nothing is sent until this time.</summary>
    public DateTimeOffset? KillUntil { get; set; }
}

/// <summary>
/// Reads/writes the per-user consent record. Thread-safe. All I/O errors fail closed (treated as "no consent").
/// </summary>
public sealed class ConsentStore
{
    /// <summary>Version of the in-app telemetry disclosure. Bump when the collected data changes; users are re-prompted.</summary>
    public const string CurrentPolicyVersion = "2026-10-1";

    private const string FileName = "consent.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly object _lock = new();
    private readonly string _dir;
    private readonly string _path;
    private readonly Func<string, string, object?> _registryReader;
    private ConsentRecord? _cached;

    /// <summary>Creates a store rooted at <paramref name="directory"/> (default: %LOCALAPPDATA%\LogicFlow\Pulse).</summary>
    /// <param name="registryReader">(keyPath, valueName) → value, used for the machine-policy kill switch. Injectable for tests.</param>
    public ConsentStore(string? directory = null, Func<string, string, object?>? registryReader = null)
    {
        _dir = directory ?? DefaultDirectory;
        _path = Path.Combine(_dir, FileName);
        _registryReader = registryReader ?? ReadRegistryValue;
    }

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow", "Pulse");

    public string Directory => _dir;

    // ─── Read ────────────────────────────────────────────────────────────

    /// <summary>A snapshot copy of the current record.</summary>
    public ConsentRecord Current
    {
        get { lock (_lock) { return Clone(Load()); } }
    }

    /// <summary>True once the user has accepted the EULA and made an edition/telemetry choice.</summary>
    public bool HasDecided
    {
        get { lock (_lock) { var r = Load(); return r.EulaAcceptedAt is not null && r.DecidedAt is not null; } }
    }

    /// <summary>True when the stored decision predates the current disclosure version (user must be re-prompted).</summary>
    public bool NeedsReconsent
    {
        get
        {
            lock (_lock)
            {
                var r = Load();
                return r.DecidedAt is not null &&
                       !string.Equals(r.PolicyVersion, CurrentPolicyVersion, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>
    /// True when the user chose Community and the mandatory Standard sharing is still in force.
    /// A server kill-switch does NOT revoke this (the user did not withdraw consent); an IT policy off-switch does.
    /// </summary>
    public bool CommunityConditionAccepted()
    {
        if (IsDisabledByPolicy()) return false;
        lock (_lock)
        {
            var r = Load();
            return r.EulaAcceptedAt is not null && r.DecidedAt is not null &&
                   string.Equals(r.PolicyVersion, CurrentPolicyVersion, StringComparison.Ordinal) &&
                   r.Edition == EditionChoice.Community && ConsentPolicy.SatisfiesCommunityCondition(r.Level);
        }
    }

    /// <summary>Machine-level policy off-switch (HKLM or HKCU Policies key, or the legacy installer value).</summary>
    public bool IsDisabledByPolicy()
    {
        foreach (var root in new[] { @"HKLM\SOFTWARE\Policies\DelgadoLogic\LogicFlow", @"HKCU\SOFTWARE\Policies\DelgadoLogic\LogicFlow" })
        {
            if (_registryReader(root, "TelemetryDisabled") is int v && v == 1) return true;
        }
        foreach (var root in new[] { @"HKLM\SOFTWARE\DelgadoLogic\LogicFlow", @"HKCU\SOFTWARE\DelgadoLogic\LogicFlow" })
        {
            if (_registryReader(root, "TelemetryEnabled") is int v && v == 0) return true;
        }
        return false;
    }

    /// <summary>True when the user already accepted the EULA during installation (recorded in HKLM/HKCU\SOFTWARE\DelgadoLogic\LogicFlow -> EulaAcceptedVersion).</summary>
    public bool IsInstallerEulaAccepted()
    {
        foreach (var root in new[] { @"HKLM\SOFTWARE\DelgadoLogic\LogicFlow", @"HKCU\SOFTWARE\DelgadoLogic\LogicFlow" })
        {
            if (_registryReader(root, "EulaAcceptedVersion") is string ver && !string.IsNullOrWhiteSpace(ver))
                return true;
        }
        return false;
    }

    /// <summary>Detects the 2-letter ISO country code from the Windows region setting using this store's registry reader.</summary>
    public string DetectWindowsIsoCode() => PrivacyRegionExtensions.DetectWindowsIsoCode(_registryReader);

    /// <summary>Detects the PrivacyRegion from the Windows region setting using this store's registry reader.</summary>
    public PrivacyRegion DetectRegionFromWindows() => PrivacyRegionExtensions.DetectFromWindowsRegion(_registryReader);

    /// <summary>
    /// The level actually allowed right now. None when undecided, re-consent needed, policy-disabled,
    /// kill-switched, or when the stored combination is not valid for the chosen edition.
    /// </summary>
    public ConsentLevel EffectiveLevel(DateTimeOffset? now = null)
    {
        if (IsDisabledByPolicy()) return ConsentLevel.None;
        lock (_lock)
        {
            var r = Load();
            if (r.EulaAcceptedAt is null || r.DecidedAt is null) return ConsentLevel.None;
            if (!string.Equals(r.PolicyVersion, CurrentPolicyVersion, StringComparison.Ordinal)) return ConsentLevel.None;
            if (r.KillUntil is { } kill && kill > (now ?? DateTimeOffset.UtcNow)) return ConsentLevel.None;

            return r.Edition switch
            {
                EditionChoice.Free => ConsentLevel.None,
                EditionChoice.Community => ConsentPolicy.SatisfiesCommunityCondition(r.Level) ? r.Level : ConsentLevel.None,
                EditionChoice.Pro => r.Level,
                _ => ConsentLevel.None
            };
        }
    }

    // ─── Write ───────────────────────────────────────────────────────────

    /// <summary>
    /// Records the first-run (or re-consent) decision. Returns the resulting level.
    /// A Community choice always yields at least Standard; to decline, call <see cref="SwitchToFree"/>.
    /// </summary>
    public ConsentLevel Apply(EditionChoice edition, PrivacyRegion region, bool wantsStandard, bool wantsExtended,
                              string eulaVersion, string eulaSha256)
    {
        lock (_lock)
        {
            var r = Load();
            var previous = r.Level;
            var level = ConsentPolicy.Compute(edition, region, wantsStandard, wantsExtended);

            r.Edition = edition;
            r.Level = level;
            r.Region = region;
            r.RegionConfirmed = true;
            r.PolicyVersion = CurrentPolicyVersion;
            r.EulaVersion = eulaVersion;
            r.EulaSha256 = eulaSha256;
            r.EulaAcceptedAt = DateTimeOffset.UtcNow;
            r.DecidedAt = DateTimeOffset.UtcNow;
            r.KillUntil = null;

            // A fresh relationship with the server gets a fresh identifier.
            if (previous == ConsentLevel.None && level != ConsentLevel.None) RotateInstallIdLocked(r);
            else EnsureInstallId(r);

            Save(r);
            return level;
        }
    }

    /// <summary>Settings toggle for Pro. Community cannot go below Standard (use <see cref="SwitchToFree"/>).</summary>
    public ConsentLevel SetOptionalTelemetry(bool standard, bool extended)
    {
        lock (_lock)
        {
            var r = Load();
            var previous = r.Level;
            r.Edition = EditionChoice.Pro;
            r.Level = ConsentPolicy.Compute(EditionChoice.Pro, r.Region, standard, extended);
            r.PolicyVersion = CurrentPolicyVersion;
            r.EulaAcceptedAt ??= DateTimeOffset.UtcNow;
            r.DecidedAt ??= DateTimeOffset.UtcNow;
            if (previous == ConsentLevel.None && r.Level != ConsentLevel.None) RotateInstallIdLocked(r);
            else EnsureInstallId(r);
            Save(r);
            return r.Level;
        }
    }

    /// <summary>Community or Pro Extended toggle; Community cannot drop below Standard.</summary>
    public ConsentLevel SetExtended(bool extended)
    {
        lock (_lock)
        {
            var r = Load();
            if (r.Edition == EditionChoice.Free) return ConsentLevel.None;
            if (r.Level == ConsentLevel.None) return ConsentLevel.None;
            r.Level = extended ? ConsentLevel.Extended : ConsentLevel.Standard;
            Save(r);
            return r.Level;
        }
    }

    /// <summary>User declined the Community condition (or chose Free): drop to Free, no telemetry.</summary>
    public void SwitchToFree(string eulaVersion, string eulaSha256)
    {
        lock (_lock)
        {
            var r = Load();
            r.Edition = EditionChoice.Free;
            r.Level = ConsentLevel.None;
            r.PolicyVersion = CurrentPolicyVersion;
            r.EulaVersion = eulaVersion;
            r.EulaSha256 = eulaSha256;
            r.EulaAcceptedAt = DateTimeOffset.UtcNow;
            r.DecidedAt = DateTimeOffset.UtcNow;
            Save(r);
        }
    }

    /// <summary>Records the user's region answer without changing anything else.</summary>
    public void SetRegion(PrivacyRegion region)
    {
        lock (_lock)
        {
            var r = Load();
            r.Region = region;
            r.RegionConfirmed = true;
            Save(r);
        }
    }

    public void SetKillSwitch(DateTimeOffset until)
    {
        lock (_lock)
        {
            var r = Load();
            r.KillUntil = until;
            Save(r);
        }
    }

    // ─── Install ID ──────────────────────────────────────────────────────

    /// <summary>The random install identifier (created on first use). Never derived from hardware.</summary>
    public string GetInstallId()
    {
        lock (_lock)
        {
            var r = Load();
            if (EnsureInstallId(r)) Save(r);
            return r.InstallId;
        }
    }

    /// <summary>Issues a new random identifier. Returns the old one so a delete request can be sent for it.</summary>
    public string RotateInstallId()
    {
        lock (_lock)
        {
            var r = Load();
            var old = r.InstallId;
            RotateInstallIdLocked(r);
            Save(r);
            return old;
        }
    }

    public void SetPendingDelete(string? installId)
    {
        lock (_lock)
        {
            var r = Load();
            r.PendingDeleteInstallId = installId;
            Save(r);
        }
    }

    /// <summary>Removes the install id (used by "Delete my data"); a new one is created if telemetry is ever re-enabled.</summary>
    public string? ClearInstallId()
    {
        lock (_lock)
        {
            var r = Load();
            var old = string.IsNullOrEmpty(r.InstallId) ? null : r.InstallId;
            r.InstallId = "";
            r.InstallIdCreatedAt = null;
            Save(r);
            return old;
        }
    }

    // ─── Internals ───────────────────────────────────────────────────────

    private static bool EnsureInstallId(ConsentRecord r)
    {
        if (!string.IsNullOrWhiteSpace(r.InstallId))
        {
            if (r.InstallIdCreatedAt is { } created && (DateTimeOffset.UtcNow - created).TotalDays >= 90)
            {
                RotateInstallIdLocked(r);
                return true;
            }
            r.InstallIdCreatedAt ??= DateTimeOffset.UtcNow;
            return false;
        }
        RotateInstallIdLocked(r);
        return true;
    }

    private static void RotateInstallIdLocked(ConsentRecord r)
    {
        r.InstallId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        r.InstallIdCreatedAt = DateTimeOffset.UtcNow;
    }

    private ConsentRecord Load()
    {
        if (_cached is not null) return _cached;
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                _cached = JsonSerializer.Deserialize<ConsentRecord>(json, JsonOptions);
            }
        }
        catch
        {
            // Corrupt or unreadable file: treat as "no decision" (fail closed).
            _cached = null;
        }
        _cached ??= new ConsentRecord();
        return _cached;
    }

    private void Save(ConsentRecord record)
    {
        _cached = record;
        try
        {
            System.IO.Directory.CreateDirectory(_dir);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(record, JsonOptions));
            File.Move(tmp, _path, overwrite: true);
        }
        catch
        {
            // If we cannot persist, the in-memory record still applies for this session;
            // on the next launch the missing file means "undecided", which sends nothing.
        }
    }

    private static ConsentRecord Clone(ConsentRecord r) =>
        JsonSerializer.Deserialize<ConsentRecord>(JsonSerializer.Serialize(r, JsonOptions), JsonOptions) ?? new ConsentRecord();

    private static object? ReadRegistryValue(string keyPath, string valueName)
    {
        try
        {
            var idx = keyPath.IndexOf('\\');
            if (idx < 0) return null;
            var hive = keyPath[..idx];
            var sub = keyPath[(idx + 1)..];
            var root = hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
                ? Microsoft.Win32.Registry.LocalMachine
                : Microsoft.Win32.Registry.CurrentUser;
            using var key = root.OpenSubKey(sub);
            return key?.GetValue(valueName);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Deletes the consent file (tests, and the final step of a full local reset).</summary>
    public void DeleteLocalFile()
    {
        lock (_lock)
        {
            _cached = null;
            try { if (File.Exists(_path)) File.Delete(_path); } catch { }
        }
    }
}
