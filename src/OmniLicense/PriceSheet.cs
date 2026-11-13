namespace OmniLicense;

/// <summary>
/// Single source of truth for LogicFlow v1.x pricing, device limits and legal-entity strings.
/// CommerceEngine, the dashboard UI and the tests must read from here; do not duplicate literals.
/// </summary>
public static class PriceSheet
{
    // ─── Legal entity / support ──────────────────────────────────────────
    public const string LegalEntity = "Delgado Creative Enterprises LLC d/b/a DelgadoLogic";
    public const string Brand = "DelgadoLogic";
    public const string ProductName = "LogicFlow";
    public const string SupportEmail = "support@delgadologic.tech";
    public const string SiteBase = "https://delgadologic.tech";

    // ─── Prices (USD, one-time) ──────────────────────────────────────────
    public const string Currency = "USD";
    public const decimal FreePrice = 0m;
    public const decimal CommunityPrice = 0m;
    public const decimal ProPrice = 29.99m;
    public const decimal ProLaunchPrice = 19.99m;
    public const int LaunchPromoDays = 60;
    public const decimal ExtraSeatPrice = 9.99m;
    public const decimal Team10PackPrice = 149.00m;
    public const decimal V2UpgradePrice = 14.99m;

    // ─── Device limits ───────────────────────────────────────────────────
    public const int FreeDevices = 1;
    public const int CommunityDevices = 1;
    public const int ProDevices = 3;
    public const int Team10PackSeats = 10;

    // ─── Policy ──────────────────────────────────────────────────────────
    public const int RefundDays = 60;

    /// <summary>Pro includes free updates for every v1.x release; a major v2 is a paid upgrade.</summary>
    public const string UpdatesPolicy = "Free updates for all v1.x releases";

    public static string Format(decimal amount) =>
        amount == 0m ? "Free" : "$" + amount.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>Price shown on the upgrade button: launch price while the promo is live, list price afterwards.</summary>
    public static decimal CurrentProPrice(DateTimeOffset launchDate, DateTimeOffset now) =>
        now < launchDate.AddDays(LaunchPromoDays) ? ProLaunchPrice : ProPrice;

    public static string UpgradeLabel => $"Upgrade to Pro ({Format(ProLaunchPrice)})";

    public static string LegalUrl(string slug) => $"{SiteBase}/legal/{slug}";
    public static string EulaUrl => LegalUrl("eula");
    public static string TermsUrl => LegalUrl("terms");
    public static string PrivacyUrl => LegalUrl("privacy");
    public static string RefundUrl => LegalUrl("refund");
    public static string ThirdPartyUrl => LegalUrl("third-party");
    public static string SecurityUrl => $"{SiteBase}/security";
    public static string PricingUrl => $"{SiteBase}/pricing";
}
