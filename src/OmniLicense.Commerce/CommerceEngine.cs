// OmniLicense.Commerce — PayPal Commerce Engine (server-side tooling)
// Delgado Creative Enterprises LLC d/b/a DelgadoLogic
// Handles one-time purchases (LogicFlow Pro) AND subscriptions (Aeon Pro)
// via PayPal Orders API v2 + Subscriptions API.
// NOTE: never ship PayPal credentials in the client. Credentials come from environment variables only.

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace OmniLicense.Commerce;

/// <summary>
/// PayPal commerce service. Prices come from <see cref="PriceSheet"/>:
/// LogicFlow Pro $29.99 one-time (3 devices, free v1.x updates), launch offer $19.99 for the first 60 days,
/// extra seat $9.99, Team 10-pack $149, paid v2 upgrade $14.99. 60-day refund.
/// New products are added by creating ProductInfo or SubscriptionPlan entries.
/// </summary>
public sealed class CommerceEngine
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CommerceEngine> _logger;
    private readonly PayPalConfig _config;
    private string? _accessToken;
    private DateTimeOffset _tokenExpiry;

    public CommerceEngine(HttpClient httpClient, ILogger<CommerceEngine> logger, PayPalConfig config)
    {
        _httpClient = httpClient;
        _logger = logger;
        _config = config;
    }

    // ═══════════════════════════════════════════════════════════════
    //  AUTH
    // ═══════════════════════════════════════════════════════════════

    private async Task EnsureAuthenticatedAsync(CancellationToken ct)
    {
        if (_accessToken != null && _tokenExpiry > DateTimeOffset.UtcNow) return;

        if (!_config.IsConfigured)
            throw new InvalidOperationException(
                $"PayPal credentials are not configured. Set {PayPalConfig.ClientIdVar} and {PayPalConfig.ClientSecretVar} " +
                "(server-side only; the desktop client must route checkout through the backend API).");

        var authStr = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{_config.ClientId}:{_config.ClientSecret}"));

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v1/oauth2/token");
        request.Headers.Authorization = new("Basic", authStr);
        request.Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("grant_type", "client_credentials") });

        var response = await _httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(ct);
        var token = JsonDocument.Parse(json).RootElement;

        _accessToken = token.GetProperty("access_token").GetString();
        _tokenExpiry = DateTimeOffset.UtcNow.AddSeconds(token.GetProperty("expires_in").GetInt32() - 60);
    }

    // ═══════════════════════════════════════════════════════════════
    //  ONE-TIME PURCHASES (LogicFlow Pro, Aeon Lifetime)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a PayPal order for any one-time product (LogicFlow Pro or Aeon Lifetime).
    /// Returns the order ID and approval URL for the buyer.
    /// </summary>
    public async Task<OrderResult> CreateOrderAsync(ProductInfo product, string buyerEmail, string? discountCode = null, CancellationToken ct = default)
    {
        await EnsureAuthenticatedAsync(ct);

        var unitPrice = product.Price;
        // discountCode is accepted for API compatibility; no codes are defined in the v1.0 price sheet.
        string? appliedDiscount = null;

        var order = new
        {
            intent = "CAPTURE",
            purchase_units = new[]
            {
                new
                {
                    reference_id = $"{product.ReferencePrefix}-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}",
                    description = product.Description,
                    amount = new
                    {
                        currency_code = "USD",
                        value = unitPrice.ToString("F2"),
                        breakdown = new
                        {
                            item_total = new { currency_code = "USD", value = unitPrice.ToString("F2") }
                        }
                    },
                    items = new[]
                    {
                        new
                        {
                            name = product.Name,
                            description = product.Description,
                            unit_amount = new { currency_code = "USD", value = unitPrice.ToString("F2") },
                            quantity = "1",
                            category = "DIGITAL_GOODS"
                        }
                    }
                }
            },
            application_context = new
            {
                brand_name = PriceSheet.Brand,
                landing_page = "BILLING",
                user_action = "PAY_NOW",
                return_url = product.ReturnUrl,
                cancel_url = product.CancelUrl
            }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v2/checkout/orders");
        request.Headers.Authorization = new("Bearer", _accessToken);
        request.Content = new StringContent(
            JsonSerializer.Serialize(order), System.Text.Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));

        var orderId = result.RootElement.GetProperty("id").GetString() ?? "";
        var approvalUrl = "";
        foreach (var link in result.RootElement.GetProperty("links").EnumerateArray())
        {
            if (link.GetProperty("rel").GetString() == "approve")
            {
                approvalUrl = link.GetProperty("href").GetString() ?? "";
                break;
            }
        }

        _logger.LogInformation(
            "Created order {OrderId} for {Product} — {Email} — ${Price} (discount: {Discount})",
            orderId, product.Name, buyerEmail, unitPrice, appliedDiscount ?? "none");

        return new OrderResult(orderId, approvalUrl, unitPrice, appliedDiscount);
    }

    /// <summary>
    /// Captures a previously approved PayPal order (finalizes the payment).
    /// Call this after the buyer returns from PayPal approval URL.
    /// </summary>
    public async Task<CaptureResult> CaptureOrderAsync(string orderId, CancellationToken ct = default)
    {
        await EnsureAuthenticatedAsync(ct);

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v2/checkout/orders/{orderId}/capture");
        request.Headers.Authorization = new("Bearer", _accessToken);
        request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));

        var status = result.RootElement.GetProperty("status").GetString() ?? "";
        var captureId = "";
        try
        {
            captureId = result.RootElement
                .GetProperty("purchase_units")[0]
                .GetProperty("payments")
                .GetProperty("captures")[0]
                .GetProperty("id").GetString() ?? "";
        }
        catch { /* Capture ID extraction is best-effort */ }

        var success = status == "COMPLETED";
        _logger.LogInformation("Captured order {OrderId}: status={Status}, captureId={CaptureId}", orderId, status, captureId);

        return new CaptureResult(success, orderId, captureId, status);
    }

    // ═══════════════════════════════════════════════════════════════
    //  SUBSCRIPTIONS (Aeon Pro Monthly/Annual, Aeon Enterprise)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a PayPal catalog product (required before creating subscription plans).
    /// </summary>
    public async Task<string> CreateCatalogProductAsync(string name, string description, CancellationToken ct = default)
    {
        await EnsureAuthenticatedAsync(ct);
        var product = new
        {
            name,
            description,
            type = "SOFTWARE",
            category = "SOFTWARE"
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v1/catalogs/products");
        request.Headers.Authorization = new("Bearer", _accessToken);
        request.Content = new StringContent(JsonSerializer.Serialize(product), System.Text.Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return result.RootElement.GetProperty("id").GetString() ?? "";
    }

    /// <summary>
    /// Creates a PayPal subscription plan for recurring billing (Aeon Pro).
    /// </summary>
    public async Task<string> CreateSubscriptionPlanAsync(string productId, SubscriptionPlan plan, CancellationToken ct = default)
    {
        await EnsureAuthenticatedAsync(ct);
        var paypalPlan = new
        {
            product_id = productId,
            name = plan.Name,
            description = plan.Description,
            billing_cycles = new[]
            {
                new // Trial period (7 days free)
                {
                    frequency = new { interval_unit = "DAY", interval_count = 7 },
                    tenure_type = "TRIAL",
                    sequence = 1,
                    total_cycles = 1,
                    pricing_scheme = new { fixed_price = new { value = "0", currency_code = "USD" } }
                },
                new // Regular billing
                {
                    frequency = new { interval_unit = plan.IntervalUnit, interval_count = plan.IntervalCount },
                    tenure_type = "REGULAR",
                    sequence = 2,
                    total_cycles = 0,
                    pricing_scheme = new { fixed_price = new { value = plan.Price.ToString("F2"), currency_code = "USD" } }
                }
            },
            payment_preferences = new
            {
                auto_bill_outstanding = true,
                setup_fee_failure_action = "CONTINUE",
                payment_failure_threshold = 3
            }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v1/billing/plans");
        request.Headers.Authorization = new("Bearer", _accessToken);
        request.Content = new StringContent(JsonSerializer.Serialize(paypalPlan), System.Text.Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var planId = result.RootElement.GetProperty("id").GetString() ?? "";
        _logger.LogInformation("Created subscription plan: {Name} ({Id}) at ${Price}/{Interval}", plan.Name, planId, plan.Price, plan.IntervalUnit);
        return planId;
    }

    // ═══════════════════════════════════════════════════════════════
    //  WEBHOOK VERIFICATION
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Verifies a PayPal webhook signature to ensure the event is authentic.
    /// </summary>
    public async Task<bool> VerifyWebhookSignatureAsync(
        string webhookBody, string transmissionId, string transmissionTime,
        string certUrl, string authAlgo, string transmissionSig,
        CancellationToken ct = default)
    {
        await EnsureAuthenticatedAsync(ct);

        var verification = new
        {
            auth_algo = authAlgo,
            cert_url = certUrl,
            transmission_id = transmissionId,
            transmission_sig = transmissionSig,
            transmission_time = transmissionTime,
            webhook_id = _config.WebhookId,
            webhook_event = JsonDocument.Parse(webhookBody).RootElement
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.BaseUrl}/v1/notifications/verify-webhook-signature");
        request.Headers.Authorization = new("Bearer", _accessToken);
        request.Content = new StringContent(
            JsonSerializer.Serialize(verification), System.Text.Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) return false;

        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var verificationStatus = result.RootElement.GetProperty("verification_status").GetString();
        return verificationStatus == "SUCCESS";
    }

    // ═══════════════════════════════════════════════════════════════
    //  PRODUCT CATALOG — All DelgadoLogic Products
    // ═══════════════════════════════════════════════════════════════

    /// <summary>All purchasable products. Prices and limits come from <see cref="PriceSheet"/> only.</summary>
    public static class Products
    {
        private const string Success = PriceSheet.SiteBase + "/success";
        private const string Cancel = PriceSheet.SiteBase + "/pricing";

        // ── LogicFlow Pro: one-time, 3 devices, free updates for every v1.x release ──
        public static readonly ProductInfo LogicFlowPro = new(
            Name: "LogicFlow Pro",
            Description: $"LogicFlow Pro — {PriceSheet.ProDevices} devices, commercial use, background automation, advanced recovery, " +
                         $"{PriceSheet.UpdatesPolicy.ToLowerInvariant()}. Windows 10 (1607+) and Windows 11.",
            Price: PriceSheet.ProPrice,
            ReferencePrefix: "LF-PRO",
            ReturnUrl: Success,
            CancelUrl: Cancel
        );

        // ── Launch promo: same product, first PriceSheet.LaunchPromoDays days after launch ──
        public static readonly ProductInfo LogicFlowProLaunch = LogicFlowPro with
        {
            Name = "LogicFlow Pro (Launch Offer)",
            Price = PriceSheet.ProLaunchPrice,
            ReferencePrefix = "LF-PRO-LAUNCH"
        };

        // ── Team 10-pack: 10 seats, one-time ──
        public static readonly ProductInfo LogicFlowTeam10 = new(
            Name: "LogicFlow Pro — Team 10-Pack",
            Description: $"{PriceSheet.Team10PackSeats} Pro seats for a team or small business, one-time, {PriceSheet.UpdatesPolicy.ToLowerInvariant()}.",
            Price: PriceSheet.Team10PackPrice,
            ReferencePrefix: "LF-TEAM10",
            ReturnUrl: Success,
            CancelUrl: Cancel
        );

        // ── Extra seat for an existing Pro or Team license ──
        public static readonly ProductInfo LogicFlowSeatAddon = new(
            Name: "LogicFlow Pro — Extra Seat",
            Description: "Add 1 additional device to an existing Pro or Team license.",
            Price: PriceSheet.ExtraSeatPrice,
            ReferencePrefix: "LF-SEAT",
            ReturnUrl: Success,
            CancelUrl: Cancel
        );

        // ── Paid upgrade to the next major version (v2) for v1 Pro owners ──
        public static readonly ProductInfo LogicFlowV2Upgrade = new(
            Name: "LogicFlow Pro v2 — Upgrade",
            Description: "Upgrade from LogicFlow Pro v1.x to v2.",
            Price: PriceSheet.V2UpgradePrice,
            ReferencePrefix: "LF-V2UP",
            ReturnUrl: Success,
            CancelUrl: Cancel
        );
    }

    /// <summary>Aeon Browser subscription plans (recurring billing).</summary>
    public static List<SubscriptionPlan> GetAeonSubscriptionPlans() =>
    [
        new("Aeon Pro Monthly",  "Unlimited Agent queries, priority patches, AeonVPN — monthly",  4.99m, "MONTH", 1),
        new("Aeon Pro Annual",   "Unlimited Agent queries, priority patches, AeonVPN — annual",  39.00m, "YEAR",  1),
    ];
}

/// <summary>
/// Processes incoming PayPal webhook events for all product types.
/// Dispatches to LicenseEngine for key generation/revocation as needed.
/// </summary>
public sealed class WebhookHandler
{
    private readonly ILogger<WebhookHandler> _logger;
    public WebhookHandler(ILogger<WebhookHandler> logger) => _logger = logger;

    public WebhookResult ProcessEvent(string eventType, string resourceId)
    {
        _logger.LogInformation("PayPal webhook: {Type} for {Id}", eventType, resourceId);
        return eventType switch
        {
            // ── One-time purchase events (LogicFlow Pro, Aeon Lifetime) ──
            "CHECKOUT.ORDER.APPROVED"           => new(true, "Order approved — ready to capture"),
            "PAYMENT.CAPTURE.COMPLETED"         => new(true, "Payment captured — issue license key"),
            "PAYMENT.CAPTURE.DENIED"            => new(true, "Payment capture denied"),
            "PAYMENT.CAPTURE.REFUNDED"          => new(true, "Payment refunded — revoke license"),
            "PAYMENT.CAPTURE.REVERSED"          => new(true, "Payment reversed — revoke license"),

            // ── Subscription events (Aeon Pro Monthly/Annual) ──
            "BILLING.SUBSCRIPTION.ACTIVATED"    => new(true, "Subscription activated — grant Pro access"),
            "BILLING.SUBSCRIPTION.CANCELLED"    => new(true, "Subscription cancelled — schedule Pro revocation at cycle end"),
            "BILLING.SUBSCRIPTION.EXPIRED"      => new(true, "Subscription expired — revoke Pro access"),
            "BILLING.SUBSCRIPTION.SUSPENDED"    => new(true, "Subscription suspended — pause Pro access"),
            "BILLING.SUBSCRIPTION.RE-ACTIVATED" => new(true, "Subscription reactivated — restore Pro access"),

            // ── Recurring payment events ──
            "PAYMENT.SALE.COMPLETED"            => new(true, "Recurring payment received — extend Pro access"),
            "PAYMENT.SALE.DENIED"               => new(true, "Recurring payment denied"),
            "PAYMENT.SALE.REFUNDED"             => new(true, "Recurring payment refunded — revoke Pro access"),

            // ── Customer dispute events ──
            "CUSTOMER.DISPUTE.CREATED"          => new(true, "Dispute opened — flag license"),
            "CUSTOMER.DISPUTE.RESOLVED"         => new(true, "Dispute resolved"),

            _ => new(false, $"Unhandled event: {eventType}")
        };
    }
}

// ═══════════════════════════════════════════════════════════════════
//  DATA MODELS
// ═══════════════════════════════════════════════════════════════════

/// <summary>
/// PayPal REST configuration. No credentials are compiled into the assembly.
/// Values are loaded from environment variables (or a secret manager that exports them) by server-side tooling.
/// The shipped desktop client must NOT use <see cref="CommerceEngine"/>; checkout and licence activation are routed
/// through the DelgadoLogic backend API, which owns the PayPal credentials.
/// </summary>
public sealed class PayPalConfig
{
    public const string ClientIdVar = "LOGICFLOW_PAYPAL_CLIENT_ID";
    public const string ClientSecretVar = "LOGICFLOW_PAYPAL_CLIENT_SECRET";
    public const string WebhookIdVar = "LOGICFLOW_PAYPAL_WEBHOOK_ID";
    public const string BaseUrlVar = "LOGICFLOW_PAYPAL_BASE_URL";

    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string BaseUrl { get; set; } = "https://api-m.paypal.com";
    public string WebhookId { get; set; } = "";

    /// <summary>True when both the client id and secret are present.</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);

    /// <summary>Builds a configuration from environment variables. Missing values stay empty (fail closed).</summary>
    public static PayPalConfig FromEnvironment(Func<string, string?>? getVar = null)
    {
        getVar ??= Environment.GetEnvironmentVariable;
        var baseUrl = getVar(BaseUrlVar);
        return new PayPalConfig
        {
            ClientId = getVar(ClientIdVar)?.Trim() ?? "",
            ClientSecret = getVar(ClientSecretVar)?.Trim() ?? "",
            WebhookId = getVar(WebhookIdVar)?.Trim() ?? "",
            BaseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://api-m.paypal.com" : baseUrl.Trim()
        };
    }
}

/// <summary>A one-time purchasable product (LogicFlow Pro, Aeon Lifetime).</summary>
public sealed record ProductInfo(string Name, string Description, decimal Price, string ReferencePrefix, string ReturnUrl, string CancelUrl);

/// <summary>A recurring subscription plan (Aeon Pro Monthly/Annual).</summary>
public sealed record SubscriptionPlan(string Name, string Description, decimal Price, string IntervalUnit, int IntervalCount);

/// <summary>Result of creating a PayPal order.</summary>
public sealed record OrderResult(string OrderId, string ApprovalUrl, decimal FinalPrice, string? AppliedDiscount);

/// <summary>Result of capturing a PayPal order.</summary>
public sealed record CaptureResult(bool Success, string OrderId, string CaptureId, string Status);

/// <summary>Result of processing a webhook event.</summary>
public sealed record WebhookResult(bool Handled, string Message);
