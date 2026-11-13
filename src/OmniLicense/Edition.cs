namespace OmniLicense;

/// <summary>User-visible product edition. Derived from the signed licence token plus the telemetry condition.</summary>
public enum Edition
{
    /// <summary>No telemetry, scan-only. 1 device.</summary>
    Free = 0,

    /// <summary>$0 (no monetary cost); all core features; personal non-commercial use; 1 device; Standard diagnostics sharing is mandatory.</summary>
    Community = 1,

    /// <summary>$29.99 one-time; 3 devices; commercial use; background automation; advanced recovery; telemetry optional.</summary>
    Pro = 2
}

/// <summary>Gateable capabilities. Each maps to the lowest edition that includes it (see <see cref="TierPolicy.RequiredEdition"/>).</summary>
public enum Capability
{
    /// <summary>Read-only scans and diagnostics (all editions).</summary>
    Scan,

    /// <summary>Apply fixes, clean, optimise, manual HyperStore/Game Vault operations, basic recovery (Community+).</summary>
    Core,

    /// <summary>Scheduled scans and auto-fix in the background agent (Pro).</summary>
    BackgroundAutomation,

    /// <summary>HyperStore autonomous background worker (Pro).</summary>
    HyperStoreAutonomousWorker,

    /// <summary>Game Vault automatic compaction of patched/updated titles (Pro).</summary>
    GameVaultAutoCompact,

    /// <summary>Lazarus deep scan and NTFS MFT recovery (Pro).</summary>
    AdvancedRecovery,

    /// <summary>Commercial / business use (Pro).</summary>
    CommercialUse,

    /// <summary>Priority support (Pro).</summary>
    PrioritySupport
}

/// <summary>
/// Pure, side-effect-free tier policy. Everything here fails closed: anything that is not positively
/// recognised as a paid/consented tier resolves to <see cref="Edition.Free"/>.
/// </summary>
public static class TierPolicy
{
    /// <summary>Maps a (possibly legacy or undefined) licence tier to a v1.0 edition. Unknown values fail closed to Free.</summary>
    public static Edition ToEdition(this LicenseTier tier) => tier switch
    {
        LicenseTier.Pro            => Edition.Pro,
        LicenseTier.Family         => Edition.Pro,
        LicenseTier.Enterprise     => Edition.Pro,
        LicenseTier.SovereignSuite => Edition.Pro,
        LicenseTier.FounderPass    => Edition.Pro,   // retired: honoured as Pro
        LicenseTier.Community      => Edition.Community,
        LicenseTier.Free           => Edition.Free,
        _                          => Edition.Free   // undefined enum value: fail closed
    };

    /// <summary>
    /// Parses a tier string coming from an untrusted source (cloud response, settings file).
    /// Anything unknown, empty or numeric-but-undefined returns <see cref="LicenseTier.Free"/> — never Pro.
    /// </summary>
    public static LicenseTier ParseTierFailClosed(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return LicenseTier.Free;
        var trimmed = value.Trim();
        // Numeric strings ("1", "-1", "999") would parse as enum ordinals — never accept them.
        if (trimmed.Length == 0 || trimmed.Any(char.IsDigit)) return LicenseTier.Free;
        return TryParseTierFailClosed(trimmed, out var tier) ? tier : LicenseTier.Free;
    }

    /// <summary>
    /// Attempts to parse a recognised licence tier name (including legacy token aliases).
    /// Rejects empty, whitespace, numeric/digit-containing, and unknown strings and sets <paramref name="tier"/> to <see cref="LicenseTier.Free"/>.
    /// </summary>
    public static bool TryParseTierFailClosed(string? value, out LicenseTier tier)
    {
        tier = LicenseTier.Free;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim();
        if (trimmed.Length == 0 || trimmed.Any(char.IsDigit)) return false;
        var normalized = trimmed.Replace("-", "").Replace("_", "").Trim();
        if (normalized.Length == 0) return false;
        if (Enum.TryParse<LicenseTier>(normalized, ignoreCase: true, out var parsed) && Enum.IsDefined(parsed))
        {
            tier = parsed;
            return true;
        }
        if (string.Equals(normalized, "suite", StringComparison.OrdinalIgnoreCase)) { tier = LicenseTier.SovereignSuite; return true; }
        if (string.Equals(normalized, "founder", StringComparison.OrdinalIgnoreCase)) { tier = LicenseTier.FounderPass; return true; }
        if (string.Equals(normalized, "aeonpro", StringComparison.OrdinalIgnoreCase)) { tier = LicenseTier.Pro; return true; }
        if (string.Equals(normalized, "enterpriseseat", StringComparison.OrdinalIgnoreCase)) { tier = LicenseTier.Enterprise; return true; }
        return false;
    }

    /// <summary>
    /// Resolves the effective edition.
    /// A Pro edition requires a <i>valid</i> signed token. Otherwise the user is Community when the mandatory
    /// Standard telemetry condition is accepted, and Free when it is not.
    /// </summary>
    public static Edition Resolve(LicenseValidation? validation, bool standardTelemetryAccepted)
    {
        if (validation is { IsValid: true } && validation.Tier.ToEdition() == Edition.Pro)
            return Edition.Pro;

        return standardTelemetryAccepted ? Edition.Community : Edition.Free;
    }

    public static Edition RequiredEdition(Capability capability) => capability switch
    {
        Capability.Scan                       => Edition.Free,
        Capability.Core                       => Edition.Community,
        Capability.BackgroundAutomation       => Edition.Pro,
        Capability.HyperStoreAutonomousWorker => Edition.Pro,
        Capability.GameVaultAutoCompact       => Edition.Pro,
        Capability.AdvancedRecovery           => Edition.Pro,
        Capability.CommercialUse              => Edition.Pro,
        Capability.PrioritySupport            => Edition.Pro,
        _                                     => Edition.Pro   // new/unknown capability: fail closed
    };

    public static bool IsAllowed(Edition edition, Capability capability) =>
        edition >= RequiredEdition(capability);

    public static bool IsAllowed(LicenseTier tier, Capability capability) =>
        IsAllowed(tier.ToEdition(), capability);

    public static string DisplayName(this Edition edition) => edition switch
    {
        Edition.Pro       => "Pro",
        Edition.Community => "Community",
        _                 => "Free"
    };

    public static string CapabilityName(Capability capability) => capability switch
    {
        Capability.Scan                       => "Scanning",
        Capability.Core                       => "Applying fixes and cleanups",
        Capability.BackgroundAutomation       => "Scheduled scans and auto-fix",
        Capability.HyperStoreAutonomousWorker => "HyperStore autonomous worker",
        Capability.GameVaultAutoCompact       => "Game Vault auto-compact",
        Capability.AdvancedRecovery           => "Lazarus deep scan / MFT recovery",
        Capability.CommercialUse              => "Commercial use",
        Capability.PrioritySupport            => "Priority support",
        _                                     => capability.ToString()
    };

    /// <summary>Text for the upgrade prompt shown when a gated capability is used on a lower edition.</summary>
    public static string UpgradeMessage(Edition current, Capability capability)
    {
        var needed = RequiredEdition(capability);
        var name = CapabilityName(capability);
        return needed == Edition.Community
            ? $"{name} is not available in the Free edition.\n\n" +
              "Switch to Community ($0 — with Standard diagnostics sharing) in Settings, or upgrade to Pro " +
              $"({PriceSheet.Format(PriceSheet.ProLaunchPrice)} launch / {PriceSheet.Format(PriceSheet.ProPrice)} regular one-time, {PriceSheet.ProDevices} devices, telemetry optional)."
            : $"{name} is a Pro feature (you are on {current.DisplayName()}).\n\n" +
              $"LogicFlow Pro is {PriceSheet.Format(PriceSheet.ProLaunchPrice)} launch ({PriceSheet.Format(PriceSheet.ProPrice)} regular) one-time for {PriceSheet.ProDevices} devices, " +
              $"{PriceSheet.UpdatesPolicy.ToLowerInvariant()}, with a {PriceSheet.RefundDays}-day refund.";
    }
}
