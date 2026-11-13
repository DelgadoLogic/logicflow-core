// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow Dashboard — EditionService
// Single source of truth for "which edition is this user on". Fails closed:
// anything that is not a valid signed Pro token or an accepted Community consent is Free.
// ─────────────────────────────────────────────────────────────────────────────

using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using DelgadoLogic.Core;
using Microsoft.Extensions.Logging.Abstractions;
using OmniCore.Engine;
using OmniLicense;
using OmniPulse;

namespace LogicFlow.Dashboard;

/// <summary>Resolves the effective <see cref="Edition"/> from the licence token + consent store.</summary>
public sealed class EditionService
{
    /// <summary>Version of the EULA text shipped with this build (shown on the consent screen).</summary>
    public const string EulaVersion = "1.0";

    private readonly object _sync = new();
    private readonly RsaLicenseValidator _validator;
    private readonly string _licenseFilePath;

    public static EditionService Instance { get; } = new();

    public ConsentStore Consent { get; }

    public TrialManager Trial { get; }

    public TrialStatus? ActiveTrial { get; private set; }

    /// <summary>Validated licence tier (Free when there is no valid token).</summary>
    public LicenseTier LicenseTier { get; private set; } = LicenseTier.Free;

    public Edition Current { get; private set; } = Edition.Free;

    /// <summary>Raised after <see cref="Refresh"/> changes anything the UI may display.</summary>
    public event Action? Changed;

    private EditionService() : this(new ConsentStore()) { }

    public EditionService(ConsentStore consent, string? appDataPath = null, RsaLicenseValidator? validator = null)
    {
        var root = appDataPath ?? new LogicFlowConfig().AppDataPath;
        Consent = consent;
        Trial = new TrialManager(NullLogger<TrialManager>.Instance, root);
        _validator = validator ?? new RsaLicenseValidator(NullLogger<RsaLicenseValidator>.Instance);
        _licenseFilePath = Path.Combine(root, "License", "license_token.json");
    }

    public static string LicenseFilePath => Path.Combine(new LogicFlowConfig().AppDataPath, "License", "license_token.json");

    /// <summary>"free" | "community" | "pro" — used in telemetry envelopes.</summary>
    public string TierName => Current.ToString().ToLowerInvariant();

    public bool Allows(Capability capability) => TierPolicy.IsAllowed(Current, capability);

    // ─── Resolution ──────────────────────────────────────────────────────

    public void Refresh()
    {
        lock (_sync)
        {
            var validation = LoadSavedValidation();
            ActiveTrial = Trial.PeekStatus();
            if (validation is { IsValid: true } && validation.Tier.ToEdition() == Edition.Pro)
            {
                LicenseTier = validation.Tier;
                Current = Edition.Pro;
            }
            else if (ActiveTrial is { IsActive: true, IsTampered: false })
            {
                LicenseTier = LicenseTier.Pro;
                Current = Edition.Pro;
            }
            else
            {
                LicenseTier = validation is { IsValid: true } ? validation.Tier : LicenseTier.Free;
                Current = TierPolicy.Resolve(validation, Consent.CommunityConditionAccepted());
            }
        }
        Changed?.Invoke();
    }

    /// <summary>Starts the 14-day Pro trial (if not previously started) and refreshes the active edition.</summary>
    public TrialStatus StartProTrial()
    {
        var status = Trial.StartTrial();
        if (status.IsActive && !status.IsTampered && Consent.Current.Edition != EditionChoice.Pro)
        {
            var c = Consent.Current;
            Consent.Apply(EditionChoice.Pro, c.Region, wantsStandard: false, wantsExtended: false, EulaVersion, EulaSha256());
        }
        Refresh();
        return status;
    }

    /// <summary>
    /// Re-reads the saved token. When the user has already made their first-run choice and the token is a valid Pro
    /// licence, moves the consent record to Pro (telemetry optional, off by default). Returns true when the edition is Pro.
    /// </summary>
    public bool AdoptSavedLicense()
    {
        Refresh();
        if (Current == Edition.Pro && Consent.HasDecided && Consent.Current.Edition != EditionChoice.Pro)
        {
            var c = Consent.Current;
            Consent.Apply(EditionChoice.Pro, c.Region, wantsStandard: false, wantsExtended: false, EulaVersion, EulaSha256());
            Refresh();
        }
        return Current == Edition.Pro;
    }

    /// <summary>Validates the token stored on disk. Any read/parse problem → null (Free).</summary>
    public LicenseValidation? LoadSavedValidation()
    {
        try
        {
            if (!File.Exists(_licenseFilePath)) return null;
            var token = ParseStoredToken(File.ReadAllText(_licenseFilePath));
            return token is null ? null : Validate(token);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[License] Check failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>Validates a token against this machine (WMI HWID or the DelgadoLogic device id used by cloud activation) without writing disk state in Free tier.</summary>
    public LicenseValidation Validate(LicenseToken token)
    {
        var extra = new List<string>();
        try { extra.Add(DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false).DeviceId); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[License] Device id unavailable: {ex.Message}"); }
        return _validator.Validate(token, extra);
    }

    /// <summary>Validates and, if valid, persists a token and refreshes the edition. Pro activation moves consent to Pro (telemetry off by default).</summary>
    public async Task<LicenseValidation> ActivateAsync(LicenseToken token)
    {
        var result = Validate(token);
        if (!result.IsValid) return result;

        try { DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: true).RegisterProduct(DelgadoProduct.LogicFlow); }
        catch { /* non-fatal */ }

        LicenseClaims? claims = null;
        try
        {
            claims = JsonSerializer.Deserialize<LicenseClaims>(
                token.Payload,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { /* validated above */ }

        Directory.CreateDirectory(Path.GetDirectoryName(_licenseFilePath)!);
        var saved = JsonSerializer.Serialize(new LocalLicenseToken
        {
            Payload = token.Payload,
            Signature = token.Signature,
            Alg = token.Alg,
            Kid = !string.IsNullOrWhiteSpace(token.Kid) ? token.Kid : claims?.Kid,
            Tier = result.Tier.ToString(),
            ActivatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = claims is { ExpiresAt: var exp } && exp > DateTimeOffset.UtcNow
                ? exp
                : DateTimeOffset.UtcNow.AddYears(10),
            OrderId = !string.IsNullOrWhiteSpace(claims?.OrderId) ? claims.OrderId : "OFFLINE-RSA"
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_licenseFilePath, saved).ConfigureAwait(false);

        if (result.Tier.ToEdition() == Edition.Pro && Consent.Current.Edition != EditionChoice.Pro)
        {
            var c = Consent.Current;
            Consent.Apply(EditionChoice.Pro, c.Region, wantsStandard: false, wantsExtended: false, EulaVersion, EulaSha256());
        }

        Refresh();
        return result;
    }

    /// <summary>Accepts the stored token formats (local wrapper, plain {Payload,Signature}).</summary>
    private static LicenseToken? ParseStoredToken(string json)
    {
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        try
        {
            var local = JsonSerializer.Deserialize<LocalLicenseToken>(json, opts);
            if (local is not null && !string.IsNullOrEmpty(local.Payload))
                return new LicenseToken(local.Payload, local.Signature, local.Alg, local.Kid);
        }
        catch (JsonException) { /* fall through */ }

        try { return JsonSerializer.Deserialize<LicenseToken>(json, opts); }
        catch (JsonException) { return null; }
    }

    // ─── EULA ────────────────────────────────────────────────────────────

    /// <summary>The EULA text embedded at build time (Docs\EULA.txt), or null if the build did not include it.</summary>
    public static string? EulaText()
    {
        var asm = typeof(EditionService).Assembly;
        using var stream = asm.GetManifestResourceStream("EULA.txt");
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>SHA-256 (hex) of the embedded EULA text; falls back to a hash of the version string.</summary>
    public static string EulaSha256()
    {
        var text = EulaText() ?? $"LogicFlow-EULA-{EulaVersion}";
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n")))).ToLowerInvariant();
    }
}
