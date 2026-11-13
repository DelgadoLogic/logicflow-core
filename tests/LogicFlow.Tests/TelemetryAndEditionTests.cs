using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using OmniLicense;
using OmniPulse;

namespace LogicFlow.Tests;

/// <summary>Edition gating: pure policy rules. Anything unknown must fail closed to Free / require Pro.</summary>
public class TierPolicyTests
{
    [Theory]
    [InlineData(LicenseTier.Free, Edition.Free)]
    [InlineData(LicenseTier.Community, Edition.Community)]
    [InlineData(LicenseTier.Pro, Edition.Pro)]
    [InlineData(LicenseTier.Family, Edition.Pro)]
    [InlineData(LicenseTier.Enterprise, Edition.Pro)]
    [InlineData(LicenseTier.SovereignSuite, Edition.Pro)]
    [InlineData(LicenseTier.FounderPass, Edition.Pro)]
    public void ToEdition_MapsKnownTiers(LicenseTier tier, Edition expected) =>
        Assert.Equal(expected, tier.ToEdition());

    [Theory]
    [InlineData(999)]
    [InlineData(-1)]
    [InlineData(42)]
    public void ToEdition_UndefinedTier_FailsClosedToFree(int raw) =>
        Assert.Equal(Edition.Free, ((LicenseTier)raw).ToEdition());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("garbage")]
    [InlineData("999")]
    [InlineData("-1")]
    [InlineData("pro; DROP TABLE")]
    public void ParseTierFailClosed_UnknownOrNumericGarbage_IsFree(string? value) =>
        Assert.Equal(LicenseTier.Free, TierPolicy.ParseTierFailClosed(value));

    [Theory]
    [InlineData("pro", LicenseTier.Pro)]
    [InlineData("PRO", LicenseTier.Pro)]
    [InlineData("community", LicenseTier.Community)]
    [InlineData("Sovereign-Suite", LicenseTier.SovereignSuite)]
    [InlineData("suite", LicenseTier.SovereignSuite)]
    [InlineData("founder_pass", LicenseTier.FounderPass)]
    [InlineData("founder", LicenseTier.FounderPass)]
    [InlineData("aeon_pro", LicenseTier.Pro)]
    [InlineData("enterprise_seat", LicenseTier.Enterprise)]
    public void ParseTierFailClosed_KnownNames_Parse(string value, LicenseTier expected) =>
        Assert.Equal(expected, TierPolicy.ParseTierFailClosed(value));

    [Fact]
    public void Resolve_NoLicence_NoConsent_IsFree() =>
        Assert.Equal(Edition.Free, TierPolicy.Resolve(null, standardTelemetryAccepted: false));

    [Fact]
    public void Resolve_NoLicence_WithConsent_IsCommunity() =>
        Assert.Equal(Edition.Community, TierPolicy.Resolve(null, standardTelemetryAccepted: true));

    [Fact]
    public void Resolve_InvalidProToken_IsNotPro()
    {
        var bad = new LicenseValidation(false, "bad signature", LicenseTier.Pro);
        Assert.Equal(Edition.Free, TierPolicy.Resolve(bad, false));
        Assert.Equal(Edition.Community, TierPolicy.Resolve(bad, true));
    }

    [Fact]
    public void Resolve_ValidProToken_IsProRegardlessOfConsent()
    {
        var ok = new LicenseValidation(true, "ok", LicenseTier.Pro);
        Assert.Equal(Edition.Pro, TierPolicy.Resolve(ok, false));
    }

    [Fact]
    public void Resolve_ValidTokenWithUndefinedTier_DoesNotGrantPro()
    {
        var weird = new LicenseValidation(true, "ok", (LicenseTier)777);
        Assert.Equal(Edition.Free, TierPolicy.Resolve(weird, false));
    }

    [Theory]
    [InlineData(Edition.Free, Capability.Scan, true)]
    [InlineData(Edition.Free, Capability.Core, false)]
    [InlineData(Edition.Community, Capability.Core, true)]
    [InlineData(Edition.Community, Capability.BackgroundAutomation, false)]
    [InlineData(Edition.Community, Capability.AdvancedRecovery, false)]
    [InlineData(Edition.Community, Capability.CommercialUse, false)]
    [InlineData(Edition.Pro, Capability.BackgroundAutomation, true)]
    [InlineData(Edition.Pro, Capability.HyperStoreAutonomousWorker, true)]
    [InlineData(Edition.Pro, Capability.GameVaultAutoCompact, true)]
    [InlineData(Edition.Pro, Capability.AdvancedRecovery, true)]
    [InlineData(Edition.Pro, Capability.PrioritySupport, true)]
    public void IsAllowed_Matrix(Edition edition, Capability capability, bool expected) =>
        Assert.Equal(expected, TierPolicy.IsAllowed(edition, capability));

    [Fact]
    public void UnknownCapability_RequiresPro()
    {
        Assert.Equal(Edition.Pro, TierPolicy.RequiredEdition((Capability)9999));
        Assert.False(TierPolicy.IsAllowed(Edition.Community, (Capability)9999));
    }

    [Fact]
    public void PriceSheet_MatchesUserDecisions()
    {
        Assert.Equal(29.99m, PriceSheet.ProPrice);
        Assert.Equal(19.99m, PriceSheet.ProLaunchPrice);
        Assert.Equal(3, PriceSheet.ProDevices);
        Assert.Equal(1, PriceSheet.CommunityDevices);
        Assert.Equal(9.99m, PriceSheet.ExtraSeatPrice);
        Assert.Equal(149.00m, PriceSheet.Team10PackPrice);
        Assert.Equal(60, PriceSheet.RefundDays);
        Assert.Equal("Delgado Creative Enterprises LLC d/b/a DelgadoLogic", PriceSheet.LegalEntity);
    }

    [Fact]
    public void LaunchPromo_AppliesForSixtyDays()
    {
        var launch = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(PriceSheet.ProLaunchPrice, PriceSheet.CurrentProPrice(launch, launch.AddDays(59)));
        Assert.Equal(PriceSheet.ProPrice, PriceSheet.CurrentProPrice(launch, launch.AddDays(60)));
    }
}

/// <summary>Per-user consent record. Everything fails closed.</summary>
public sealed class ConsentStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lf-consent-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private ConsentStore NewStore(Func<string, string, object?>? registry = null) =>
        new(_dir, registry ?? ((_, _) => null));

    [Fact]
    public void Fresh_Store_SendsNothing()
    {
        var s = NewStore();
        Assert.False(s.HasDecided);
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());
        Assert.False(s.CommunityConditionAccepted());
    }

    [Theory]
    [InlineData(PrivacyRegion.UnitedStates)]
    [InlineData(PrivacyRegion.Canada)]
    [InlineData(PrivacyRegion.Mexico)]
    [InlineData(PrivacyRegion.EuEea)]
    [InlineData(PrivacyRegion.UnitedKingdom)]
    [InlineData(PrivacyRegion.Switzerland)]
    [InlineData(PrivacyRegion.AustraliaNewZealand)]
    [InlineData(PrivacyRegion.Japan)]
    [InlineData(PrivacyRegion.SouthKorea)]
    [InlineData(PrivacyRegion.Brazil)]
    [InlineData(PrivacyRegion.India)]
    [InlineData(PrivacyRegion.RestOfWorld)]
    public void Community_HonorsWantsExtended_AcrossAllRegions(PrivacyRegion region)
    {
        var s = NewStore();
        Assert.Equal(ConsentLevel.Standard, s.Apply(EditionChoice.Community, region, true, false, "1.0", "abc"));
        Assert.True(s.CommunityConditionAccepted());
        Assert.Equal(ConsentLevel.Standard, s.EffectiveLevel());

        Assert.Equal(ConsentLevel.Extended, s.Apply(EditionChoice.Community, region, true, true, "1.0", "abc"));
        Assert.True(s.CommunityConditionAccepted());
        Assert.Equal(ConsentLevel.Extended, s.EffectiveLevel());

        Assert.Equal(ConsentLevel.Standard, s.SetExtended(false));
        Assert.Equal(ConsentLevel.Extended, s.SetExtended(true));
    }

    [Theory]
    [InlineData(PrivacyRegion.EuEea)]
    [InlineData(PrivacyRegion.UnitedKingdom)]
    [InlineData(PrivacyRegion.Switzerland)]
    [InlineData(PrivacyRegion.Canada)]
    [InlineData(PrivacyRegion.Brazil)]
    [InlineData(PrivacyRegion.Japan)]
    [InlineData(PrivacyRegion.SouthKorea)]
    [InlineData(PrivacyRegion.India)]
    public void Community_StrictRegion_ExtendedIsSeparateOptIn(PrivacyRegion region)
    {
        Assert.True(region.IsStrict());
        Assert.True(region.RequiresGranularExtendedConsent());
        var s = NewStore();
        Assert.Equal(ConsentLevel.Standard, s.Apply(EditionChoice.Community, region, true, false, "1.0", "abc"));
        Assert.Equal(ConsentLevel.Extended, s.Apply(EditionChoice.Community, region, true, true, "1.0", "abc"));
    }

    [Theory]
    [InlineData(PrivacyRegion.UnitedStates)]
    [InlineData(PrivacyRegion.Mexico)]
    [InlineData(PrivacyRegion.AustraliaNewZealand)]
    [InlineData(PrivacyRegion.RestOfWorld)]
    public void NonStrictRegions_AreIdentifiedCorrectly(PrivacyRegion region)
    {
        Assert.False(region.IsStrict());
        Assert.False(region.RequiresGranularExtendedConsent());
    }

    [Fact]
    public void Pro_TelemetryIsOffUnlessOptedIn()
    {
        var s = NewStore();
        Assert.Equal(ConsentLevel.None, s.Apply(EditionChoice.Pro, PrivacyRegion.RestOfWorld, false, false, "1.0", "abc"));
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());
        Assert.Equal(ConsentLevel.Standard, s.SetOptionalTelemetry(standard: true, extended: false));
        Assert.Equal(ConsentLevel.None, s.SetOptionalTelemetry(false, false));
    }

    [Fact]
    public void Free_And_DeclinedCommunity_SendNothing()
    {
        var s = NewStore();
        s.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "abc");
        s.SwitchToFree("1.0", "abc");
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());
        Assert.False(s.CommunityConditionAccepted());
    }

    [Fact]
    public void Community_CannotDropBelowStandard_ViaSetExtended()
    {
        var s = NewStore();
        s.Apply(EditionChoice.Community, PrivacyRegion.EuEea, true, true, "1.0", "abc");
        Assert.Equal(ConsentLevel.Standard, s.SetExtended(false));
        Assert.True(s.CommunityConditionAccepted());
    }

    [Fact]
    public void Decision_Persists_AcrossInstances()
    {
        NewStore().Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "hash");
        var again = NewStore();
        Assert.True(again.HasDecided);
        Assert.Equal(ConsentLevel.Extended, again.EffectiveLevel());
        Assert.Equal("hash", again.Current.EulaSha256);
    }

    [Fact]
    public void CorruptFile_FailsClosed()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "consent.json"), "{ not json <html>");
        var s = NewStore();
        Assert.False(s.HasDecided);
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());
    }

    [Fact]
    public void StalePolicyVersion_RequiresReconsent_AndSendsNothing()
    {
        var s = NewStore();
        s.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "abc");
        var path = Path.Combine(_dir, "consent.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace(ConsentStore.CurrentPolicyVersion, "1999-01-1"));

        var reloaded = NewStore();
        Assert.True(reloaded.NeedsReconsent);
        Assert.Equal(ConsentLevel.None, reloaded.EffectiveLevel());
    }

    [Fact]
    public void MachinePolicy_Disables_Telemetry()
    {
        var s = NewStore((key, value) => key.StartsWith("HKLM", StringComparison.Ordinal) && value == "TelemetryDisabled" ? 1 : null);
        s.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "abc");
        Assert.True(s.IsDisabledByPolicy());
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());
    }

    [Fact]
    public void KillSwitch_BlocksSending_UntilExpiry()
    {
        var s = NewStore();
        s.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "abc");
        var until = DateTimeOffset.UtcNow.AddDays(1);
        s.SetKillSwitch(until);
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel(DateTimeOffset.UtcNow));
        Assert.Equal(ConsentLevel.Extended, s.EffectiveLevel(until.AddSeconds(1)));
    }

    [Fact]
    public void InstallId_IsRandom_Rotatable_Deletable()
    {
        var s = NewStore();
        var first = s.GetInstallId();
        Assert.Equal(32, first.Length);
        Assert.Equal(first, s.GetInstallId());

        var old = s.RotateInstallId();
        Assert.Equal(first, old);
        Assert.NotEqual(first, s.GetInstallId());

        var cleared = s.ClearInstallId();
        Assert.NotNull(cleared);
        Assert.Equal("", s.Current.InstallId);
    }

    [Fact]
    public void InstallId_RotatesAutomaticallyAfter90Days()
    {
        var s = NewStore();
        var initial = s.GetInstallId();
        var path = Path.Combine(_dir, "consent.json");
        var expiredTimestamp = DateTimeOffset.UtcNow.AddDays(-91).ToString("O");
        var json = File.ReadAllText(path);
        var updatedJson = System.Text.RegularExpressions.Regex.Replace(
            json,
            "\"InstallIdCreatedAt\":\\s*\"[^\"]+\"",
            $"\"InstallIdCreatedAt\": \"{expiredTimestamp}\"");
        File.WriteAllText(path, updatedJson);

        var reloaded = NewStore();
        var rotated = reloaded.GetInstallId();
        Assert.Equal(32, rotated.Length);
        Assert.NotEqual(initial, rotated);
    }

    [Fact]
    public void UpgradeFromCommunityOrFree_AllowsProOptionalTelemetryToggle()
    {
        var s = NewStore();
        s.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "abc");
        Assert.Equal(ConsentLevel.Extended, s.EffectiveLevel());

        // User upgrades to Pro and turns telemetry off in Settings
        Assert.Equal(ConsentLevel.None, s.SetOptionalTelemetry(standard: false, extended: false));
        Assert.Equal(EditionChoice.Pro, s.Current.Edition);
        Assert.Equal(ConsentLevel.None, s.EffectiveLevel());

        // User turns Standard back on
        Assert.Equal(ConsentLevel.Standard, s.SetOptionalTelemetry(standard: true, extended: false));
        Assert.Equal(ConsentLevel.Standard, s.EffectiveLevel());
    }

    [Theory]
    [InlineData(PrivacyRegion.UnitedStates, "US")]
    [InlineData(PrivacyRegion.Canada, "CA")]
    [InlineData(PrivacyRegion.Mexico, "MX")]
    [InlineData(PrivacyRegion.EuEea, "EU")]
    [InlineData(PrivacyRegion.UnitedKingdom, "GB")]
    [InlineData(PrivacyRegion.Switzerland, "CH")]
    [InlineData(PrivacyRegion.AustraliaNewZealand, "AU")]
    [InlineData(PrivacyRegion.Japan, "JP")]
    [InlineData(PrivacyRegion.SouthKorea, "KR")]
    [InlineData(PrivacyRegion.Brazil, "BR")]
    [InlineData(PrivacyRegion.India, "IN")]
    [InlineData(PrivacyRegion.RestOfWorld, "unknown")]
    public void Label_MatchesServerRegionPattern(PrivacyRegion region, string expected)
    {
        Assert.Equal(expected, region.Label());
        Assert.Matches("^([A-Z]{2}|unknown)$", region.Label());
        Assert.False(string.IsNullOrWhiteSpace(region.DisplayName()));
    }

    [Theory]
    [InlineData("US", PrivacyRegion.UnitedStates)]
    [InlineData("CA", PrivacyRegion.Canada)]
    [InlineData("MX", PrivacyRegion.Mexico)]
    [InlineData("DE", PrivacyRegion.EuEea)]
    [InlineData("fr", PrivacyRegion.EuEea)]
    [InlineData("NO", PrivacyRegion.EuEea)]
    [InlineData("GB", PrivacyRegion.UnitedKingdom)]
    [InlineData("UK", PrivacyRegion.UnitedKingdom)]
    [InlineData("CH", PrivacyRegion.Switzerland)]
    [InlineData("AU", PrivacyRegion.AustraliaNewZealand)]
    [InlineData("NZ", PrivacyRegion.AustraliaNewZealand)]
    [InlineData("JP", PrivacyRegion.Japan)]
    [InlineData("KR", PrivacyRegion.SouthKorea)]
    [InlineData("BR", PrivacyRegion.Brazil)]
    [InlineData("IN", PrivacyRegion.India)]
    [InlineData("ZA", PrivacyRegion.RestOfWorld)]
    [InlineData("", PrivacyRegion.RestOfWorld)]
    [InlineData(null, PrivacyRegion.RestOfWorld)]
    public void Region_FromCountryCode(string? iso, PrivacyRegion expected) =>
        Assert.Equal(expected, PrivacyRegionExtensions.FromCountryCode(iso));

    [Fact]
    public void DetectFromWindowsRegion_PrioritizesGeoRegistryOverCulture()
    {
        var iso = PrivacyRegionExtensions.DetectWindowsIsoCode((key, name) =>
            key == @"HKCU\Control Panel\International\Geo" && name == "Name" ? "JP" : null);
        Assert.Equal("JP", iso);
        var region = PrivacyRegionExtensions.DetectFromWindowsRegion((key, name) =>
            key == @"HKCU\Control Panel\International\Geo" && name == "Name" ? "JP" : null);
        Assert.Equal(PrivacyRegion.Japan, region);
    }

    [Fact]
    public void IsInstallerEulaAccepted_DetectsRegistryOrTimestamp()
    {
        var sNo = NewStore();
        Assert.False(sNo.IsInstallerEulaAccepted());

        var sReg = NewStore((key, val) =>
            key == @"HKLM\SOFTWARE\DelgadoLogic\LogicFlow" && val == "EulaAcceptedVersion" ? "1.0" : null);
        Assert.True(sReg.IsInstallerEulaAccepted());
    }

    [Fact]
    public void UserSettings_DefaultValues_AreSafe()
    {
        var settings = new LogicFlow.Dashboard.UserSettings();
        Assert.False(settings.EnableTelemetryBlocking);
        Assert.False(settings.StartWithWindows);
        Assert.True(settings.MinimizeToTray);
        Assert.True(settings.CheckForUpdatesAutomatically);
        Assert.True(settings.ScanSmartOnStartup);
    }
}

/// <summary>Scrubbing must remove paths, user/machine names, e-mail and IP addresses before anything leaves the PC.</summary>
public class TelemetryScrubberTests
{
    [Fact]
    public void ScrubText_RemovesPersonalData()
    {
        var raw = @"Could not read C:\Users\Alice Smith\Documents\taxes.pdf for alice@example.com from 192.168.1.25 " +
                  @"via \\fileserver\share\data on host DESKTOP-ALICE";
        var scrubbed = TelemetryScrubber.ScrubText(raw, userName: "alice", machineName: "DESKTOP-ALICE");

        Assert.DoesNotContain("Alice Smith", scrubbed);
        Assert.DoesNotContain("taxes.pdf", scrubbed);
        Assert.DoesNotContain("example.com", scrubbed);
        Assert.DoesNotContain("192.168.1.25", scrubbed);
        Assert.DoesNotContain("fileserver", scrubbed);
        Assert.DoesNotContain("DESKTOP-ALICE", scrubbed);
    }

    [Fact]
    public void ScrubText_Truncates_AndHandlesNull()
    {
        Assert.Equal("", TelemetryScrubber.ScrubText(null));
        Assert.True(TelemetryScrubber.ScrubText(new string('x', 5000)).Length <= TelemetryScrubber.MaxMessageLength);
    }

    [Fact]
    public void CrashPayload_HasNoPersonalData_AndStableFingerprint()
    {
        Exception Make()
        {
            try { throw new InvalidOperationException(@"Failed C:\Users\Bob\secret\a.txt for bob@corp.example 10.0.0.7"); }
            catch (Exception ex) { return ex; }
        }

        var a = TelemetryScrubber.BuildCrashPayload(Make());
        var b = TelemetryScrubber.BuildCrashPayload(Make());

        Assert.Equal("System.InvalidOperationException", a.ExceptionType);
        Assert.DoesNotContain("Bob", a.ScrubbedMessage);
        Assert.DoesNotContain("corp.example", a.ScrubbedMessage);
        Assert.DoesNotContain("10.0.0.7", a.ScrubbedMessage);
        Assert.Equal(64, a.Fingerprint.Length);
        Assert.Equal(a.Fingerprint, b.Fingerprint);
    }

    [Fact]
    public void NormalizeStack_DropsArgumentsFilesAndLineNumbers()
    {
        var frames = TelemetryScrubber.NormalizeStack(
            "   at LogicFlow.Guardian.JunkCleanerEngine.Clean(String path) in C:\\Users\\Bob\\src\\Junk.cs:line 42\n" +
            "   at System.Threading.Tasks.Task.Run()");

        Assert.Equal("LogicFlow.Guardian.JunkCleanerEngine.Clean", frames[0]);
        Assert.DoesNotContain(frames, f => f.Contains("Bob") || f.Contains("line 42") || f.Contains("("));
    }
}

/// <summary>PulseClient honours consent, validates server replies and backs off.</summary>
public sealed class PulseClientTests : IDisposable
{
    private const string Key = "test-ingest-key";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lf-pulse-" + Guid.NewGuid().ToString("N"));
    private readonly StubHandler _handler = new();
    private DateTimeOffset _now = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private ConsentStore NewConsent(bool community)
    {
        var store = new ConsentStore(_dir, (_, _) => null);
        if (community) store.Apply(EditionChoice.Community, PrivacyRegion.EuEea, true, false, "1.0", "hash");
        return store;
    }

    private PulseClient NewClient(ConsentStore consent) => new(new PulseClientOptions
    {
        Consent = consent,
        AppVersion = "1.0.0",
        ApiBase = "https://api.test.invalid/v1/telemetry",
        IngestKey = Key,
        Handler = _handler,
        Clock = () => _now,
        TierProvider = () => "community"
    });

    private static Exception Crash()
    {
        try { throw new InvalidOperationException(@"boom at C:\Users\Carol\data.txt carol@example.org 172.16.0.9"); }
        catch (Exception ex) { return ex; }
    }

    [Fact]
    public async Task NoConsent_NothingQueued_NothingSent()
    {
        using var client = NewClient(NewConsent(community: false));
        client.TrackCrash(Crash());
        client.TrackFeature("scan");
        await client.FlushAsync();

        Assert.Empty(_handler.Requests);
        Assert.Contains("Nothing is collected", client.BuildPreview());
    }

    [Fact]
    public async Task Crash_IsScrubbed_Signed_AndPostedToCrashEndpoint()
    {
        using var client = NewClient(NewConsent(community: true));
        client.TrackCrash(Crash());
        _handler.Reply = new(HttpStatusCode.OK, "{\"accepted\":1,\"schema\":1}");
        await client.FlushAsync(includeSysHealth: false);

        var req = Assert.Single(_handler.Requests);
        Assert.EndsWith("/v1/telemetry/crash", req.Uri.AbsolutePath);
        Assert.Equal("1", req.Headers["X-LF-Schema"]);
        Assert.Equal("standard", req.Headers["X-LF-Consent"]);
        Assert.Equal(32, req.Headers["X-LF-Install-Id"].Length);
        Assert.Equal(Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Key), req.Wire)).ToLowerInvariant(), req.Headers["X-LF-Sig"]);

        var body = Encoding.UTF8.GetString(req.Body);
        Assert.DoesNotContain("Carol", body);
        Assert.DoesNotContain("example.org", body);
        Assert.DoesNotContain("172.16.0.9", body);
        Assert.Contains("\"type\":\"crash\"", body);
        Assert.Contains("\"tier\":\"community\"", body);
        Assert.Contains("Waiting to be sent: 0", client.BuildPreview());
    }

    [Fact]
    public async Task Html200_IsNotTreatedAsSuccess_EventIsKept()
    {
        using var client = NewClient(NewConsent(community: true));
        client.TrackFeature("scan");
        _handler.Reply = new(HttpStatusCode.OK, "<html><body>Welcome to Firebase</body></html>");
        await client.FlushAsync(includeSysHealth: false);

        Assert.Single(_handler.Requests);
        Assert.Contains("Waiting to be sent: 1", client.BuildPreview());
    }

    [Theory]
    [InlineData("{\"accepted\":-1}")]
    [InlineData("{\"accepted\":\"1\"}")]
    [InlineData("[1,2,3]")]
    [InlineData("")]
    public async Task MalformedJsonReply_IsNotSuccess(string reply)
    {
        using var client = NewClient(NewConsent(community: true));
        client.TrackFeature("scan");
        _handler.Reply = new(HttpStatusCode.OK, reply);
        await client.FlushAsync(includeSysHealth: false);

        Assert.Contains("Waiting to be sent: 1", client.BuildPreview());
    }

    [Fact]
    public async Task ServerError_BacksOff_ThenRetriesAfterDelay()
    {
        using var client = NewClient(NewConsent(community: true));
        client.TrackFeature("scan");
        _handler.Reply = new(HttpStatusCode.ServiceUnavailable, "{}");

        await client.FlushAsync(includeSysHealth: false);
        Assert.Single(_handler.Requests);

        await client.FlushAsync(includeSysHealth: false);          // still inside the back-off window
        Assert.Single(_handler.Requests);

        _now = _now.AddMinutes(5);
        _handler.Reply = new(HttpStatusCode.OK, "{\"accepted\":1,\"schema\":1}");
        await client.FlushAsync(includeSysHealth: false);
        Assert.Equal(2, _handler.Requests.Count);
        Assert.Contains("Waiting to be sent: 0", client.BuildPreview());
    }

    [Fact]
    public async Task KillSwitch_ClearsQueue_AndStopsSending()
    {
        var consent = NewConsent(community: true);
        using var client = NewClient(consent);
        client.TrackFeature("scan");
        _handler.Reply = new(HttpStatusCode.Gone, "{}");
        await client.FlushAsync(includeSysHealth: false);

        Assert.Equal(ConsentLevel.None, client.Level);
        Assert.NotNull(consent.Current.KillUntil);

        client.TrackFeature("again");
        await client.FlushAsync(includeSysHealth: false);
        Assert.Single(_handler.Requests);
    }

    [Fact]
    public async Task OptOut_DropsQueuedEvents_WithoutSending()
    {
        var consent = NewConsent(community: true);
        using var client = NewClient(consent);
        client.TrackFeature("scan");

        consent.SwitchToFree("1.0", "hash");
        await client.FlushAsync();

        Assert.Empty(_handler.Requests);
        Assert.Contains("Nothing is collected", client.BuildPreview());
    }

    [Fact]
    public async Task DeleteMyData_RetiresInstallId_AndPostsDelete()
    {
        var consent = NewConsent(community: true);
        using var client = NewClient(consent);
        client.TrackFeature("scan");
        var oldId = consent.GetInstallId();
        _handler.Reply = new(HttpStatusCode.OK, "{\"accepted\":0,\"schema\":1}");

        var confirmed = await client.DeleteMyDataAsync();

        Assert.True(confirmed);
        var req = Assert.Single(_handler.Requests);
        Assert.EndsWith("/delete", req.Uri.AbsolutePath);
        Assert.Contains(oldId, Encoding.UTF8.GetString(req.Body));
        Assert.Equal("", consent.Current.InstallId);
        Assert.Null(consent.Current.PendingDeleteInstallId);
    }

    [Fact]
    public async Task DeleteMyData_Offline_IsRetriedLater()
    {
        var consent = NewConsent(community: true);
        using var client = NewClient(consent);
        var oldId = consent.GetInstallId();
        _handler.Throw = true;

        Assert.False(await client.DeleteMyDataAsync());
        Assert.Equal(oldId, consent.Current.PendingDeleteInstallId);

        _handler.Throw = false;
        _handler.Reply = new(HttpStatusCode.OK, "{\"accepted\":0,\"schema\":1}");
        await client.FlushAsync(includeSysHealth: false);
        Assert.Null(consent.Current.PendingDeleteInstallId);
    }

    [Theory]
    [InlineData("{\"accepted\":1}")]
    [InlineData("{\"accepted\":1,\"schema\":2}")]
    [InlineData("{\"accepted\":1,\"schema\":\"1\"}")]
    public async Task ReplyWithoutSchema1_IsNotTreatedAsSuccess(string reply)
    {
        using var client = NewClient(NewConsent(community: true));
        client.TrackFeature("scan");
        _handler.Reply = new(HttpStatusCode.OK, reply);
        await client.FlushAsync(includeSysHealth: false);

        Assert.Single(_handler.Requests);
        Assert.Contains("Waiting to be sent: 1", client.BuildPreview());
    }

    [Fact]
    public async Task AllEventPayloads_ConformToIngestSchemaV1()
    {
        var consent = new ConsentStore(_dir, (_, _) => null);
        consent.Apply(EditionChoice.Community, PrivacyRegion.RestOfWorld, true, true, "1.0", "hash");
        using var client = NewClient(consent);

        client.TrackCrash(Crash());
        client.TrackError("LogicFlow.Guardian", "Clean", Crash(), "temp cleanup");
        client.TrackFeature("game_vault");
        client.TrackOptimization("junk_cleaner", true, 1200, new Dictionary<string, string> { ["reclaimed"] = "4096" });
        client.TrackScanPerformance(new ScanPerformanceEvent
        {
            EngineName = "LogicFlow.Guardian",
            OperationType = "full",
            DurationMs = 1200,
            ItemsProcessed = 5
        });

        _handler.Reply = new(HttpStatusCode.OK, "{\"accepted\":1,\"schema\":1}");
        await client.FlushAsync(includeSysHealth: false);

        // Expect 1 crash request (/crash) and 1 batch request (/events) with error, usage, scan
        Assert.Equal(2, _handler.Requests.Count);

        var uuidRegex = new System.Text.RegularExpressions.Regex(
            "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$");
        var envelopeAllowedKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            "schema", "eventId", "type", "ts", "installId", "appVersion", "osBuild", "arch", "tier", "region", "payload"
        };
        var seenTypes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var req in _handler.Requests)
        {
            var lines = Encoding.UTF8.GetString(req.Body)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert.NotEmpty(lines);

            foreach (var line in lines)
            {
                using var doc = System.Text.Json.JsonDocument.Parse(line);
                var ev = doc.RootElement;
                var envKeys = ev.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
                Assert.Equal(envelopeAllowedKeys, envKeys);
                Assert.Equal(1, ev.GetProperty("schema").GetInt32());
                Assert.Matches(uuidRegex, ev.GetProperty("eventId").GetString()!);
                Assert.Matches("^[A-Za-z0-9_-]{16,64}$", ev.GetProperty("installId").GetString()!);
                Assert.Matches("^([A-Z]{2}|unknown)$", ev.GetProperty("region").GetString()!);

                var type = ev.GetProperty("type").GetString()!;
                seenTypes.Add(type);
                var payload = ev.GetProperty("payload");
                var keys = payload.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

                switch (type)
                {
                    case "crash":
                        Assert.Contains("exceptionType", keys);
                        Assert.Contains("frames", keys);
                        Assert.Contains("isFatal", keys);
                        Assert.Subset(new HashSet<string> { "exceptionType", "message", "hresult", "frames", "inner", "component", "isFatal", "uptimeSec" }, keys);
                        break;
                    case "error":
                        Assert.Contains("code", keys);
                        Assert.Contains("component", keys);
                        Assert.Contains("severity", keys);
                        Assert.Subset(new HashSet<string> { "code", "component", "severity", "message", "hresult", "frames" }, keys);
                        break;
                    case "usage":
                        Assert.Contains("feature", keys);
                        Assert.Contains("action", keys);
                        Assert.Subset(new HashSet<string> { "feature", "action", "durationMs", "count", "props" }, keys);
                        break;
                    case "scan":
                        Assert.Contains("scanType", keys);
                        Assert.Contains("durationMs", keys);
                        Assert.Contains("itemsFound", keys);
                        Assert.Subset(new HashSet<string> { "scanType", "durationMs", "itemsFound", "bytesReclaimable", "healthScore", "modulesRun", "issues" }, keys);
                        break;
                    default:
                        Assert.Fail($"Unexpected event type: {type}");
                        break;
                }
            }
        }

        Assert.Equal(new HashSet<string> { "crash", "error", "usage", "scan" }, seenTypes);
    }

    [Fact]
    public void BaselinePayload_ConformsToIngestSchemaV1()
    {
        var baseline = new SystemBaseline
        {
            System = new SystemProfile
            {
                OsVersion = "Windows 11 Pro",
                OsBuild = "22631.3007",
                CpuName = "AMD Ryzen 9 7950X",
                CpuCores = 16,
                RamTotalMB = 32768,
                GpuName = "NVIDIA GeForce RTX 4090",
                DiskType = "NVMe",
                AntivirusProduct = "Windows Defender"
            },
            Bios = new BiosInfo
            {
                Manufacturer = "AMI",
                Version = "1.20"
            },
            ProblemDevices = new List<ProblemDevice>
            {
                new()
                {
                    HardwareId = @"PCI\VEN_10DE&DEV_2684\4&12345678&0&0008",
                    DeviceClass = "Display",
                    Name = "NVIDIA GeForce RTX 4090"
                }
            },
            Hotfixes = new List<HotfixEntry>
            {
                new() { HotfixId = "KB5034441" },
                new() { HotfixId = "invalid-id" }
            },
            RunningServiceCount = 85
        };

        var mapped = PulseClient.MapBaselineToSchemaPayload(baseline);
        var json = System.Text.Json.JsonSerializer.Serialize(mapped);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        var keys = root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("windows", keys);
        Assert.Contains("hardware", keys);
        Assert.Subset(new HashSet<string> { "windows", "hardware", "drivers", "kbs", "securityProducts", "servicesRunning" }, keys);

        // Verify device instance serial was stripped from hwidClass
        var drv = root.GetProperty("drivers")[0];
        Assert.Equal(@"PCI\VEN_10DE&DEV_2684", drv.GetProperty("hwidClass").GetString());

        // Verify only valid KB numbers match ^KB[0-9]{6,8}$
        var kbs = root.GetProperty("kbs").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Single(kbs);
        Assert.Equal("KB5034441", kbs[0]);
    }

    [Fact]
    public async Task PulseClient_And_EditionService_ConcurrentLoad_IsThreadSafe()
    {
        var consent = NewConsent(community: true);
        _handler.Reply = (HttpStatusCode.OK, "{\"accepted\":10,\"schema\":1}");
        using var client = NewClient(consent);
        var editionSvc = new LogicFlow.Dashboard.EditionService(consent, _dir);

        var tasks = Enumerable.Range(0, 16).Select(i => Task.Run(async () =>
        {
            for (int j = 0; j < 10; j++)
            {
                client.TrackFeature($"feature_{i}_{j}");
                editionSvc.Refresh();
                _ = editionSvc.Allows(Capability.Core);
                if (j % 5 == 0)
                    await client.FlushAsync();
            }
        })).ToArray();

        await Task.WhenAll(tasks);
        await client.FlushAsync();
        Assert.Equal(Edition.Community, editionSvc.Current);
        Assert.NotEmpty(_handler.Requests);
    }

    private sealed record Captured(Uri Uri, Dictionary<string, string> Headers, byte[] Body, byte[] Wire);

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly object _gate = new();
        public List<Captured> Requests { get; } = new();
        public (HttpStatusCode Status, string Body) Reply { get; set; } = (HttpStatusCode.OK, "{\"accepted\":1,\"schema\":1}");
        public bool Throw { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Throw) throw new HttpRequestException("offline");

            var raw = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            using var input = new MemoryStream(raw);
            using var gz = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            await gz.CopyToAsync(output, cancellationToken);

            var captured = new Captured(
                request.RequestUri!,
                request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value)),
                output.ToArray(),
                raw);
            lock (_gate)
            {
                Requests.Add(captured);
            }

            return new HttpResponseMessage(Reply.Status) { Content = new StringContent(Reply.Body, Encoding.UTF8, "application/json") };
        }
    }
}
