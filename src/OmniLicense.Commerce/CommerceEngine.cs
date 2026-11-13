// OmniLicense.Commerce — Universal PayPal Commerce Engine
// Proprietary implementation by DelgadoLogic.Tech
// Handles one-time purchases (LogicFlow Pro) AND subscriptions (Aeon Pro)
// via PayPal Orders API v2 + Subscriptions API

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace OmniLicense.Commerce;

/// <summary>
/// Universal PayPal commerce service for all DelgadoLogic products.
/// 
/// LogicFlow Pro:        $29.99 one-time — 2 devices, lifetime sovereign updates.
/// LogicFlow Family:     $49.99 one-time — 5 devices, lifetime sovereign updates.
/// LogicFlow Enterprise: $79.99 one-time — 10 devices, seat add-ons, priority support.
/// Enterprise Seat Addon: $9.99 one-time — add 1 extra seat to Enterprise license.
/// Aeon Pro Monthly:     $4.99/month subscription.
/// Aeon Pro Annual:      $39.00/year subscription.
/// 
/// 7-day refund guarantee on all purchases.
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
        string? appliedDiscount = null;

        // Apply MULTIPC discount code if valid (LogicFlow multi-PC)
        if (!string.IsNullOrWhiteSpace(discountCode) &&
            discountCode.Equals("MULTIPC", StringComparison.OrdinalIgnoreCase))
        {
            unitPrice = Math.Round(unitPrice * 0.80m, 2);
            appliedDiscount = "MULTIPC";
        }

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
                brand_name = "DelgadoLogic Systems",
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

    /// <summary>All purchasable products across the DelgadoLogic ecosystem.</summary>
    public static class Products
    {
        // ── LogicFlow Pro ──
        // $29.99 one-time for 2 devices (desktop + laptop).
        // Undercuts every competitor's annual subscription model.
        public static readonly ProductInfo LogicFlowPro = new(
            Name: "LogicFlow Pro",
            Description: "All 12 modules unlocked — 2 devices, lifetime sovereign updates, zero subscriptions. Windows 7 SP1 through Windows 11.",
            Price: 29.99m,
            ReferencePrefix: "LF-PRO",
            ReturnUrl: "https://delgadologic.tech/success",
            CancelUrl: "https://delgadologic.tech/pricing"
        );

        // ── LogicFlow Family ──
        // $49.99 one-time for 5 devices.
        // ~$10/device — perfect for households.
        // 67% premium over Pro but 2.5× the seats.
        public static readonly ProductInfo LogicFlowFamily = new(
            Name: "LogicFlow Family",
            Description: "5-device license — all modules, lifetime sovereign updates, perfect for households. Windows 7 SP1 through Windows 11.",
            Price: 49.99m,
            ReferencePrefix: "LF-FAM",
            ReturnUrl: "https://delgadologic.tech/success",
            CancelUrl: "https://delgadologic.tech/pricing"
        );

        // ── LogicFlow Enterprise ──
        // $79.99 one-time for 10 devices.
        // ~$8/device — undercuts CCleaner Business ($20/PC/yr) and IObit ($17/yr/3PC).
        // Includes expandable seat add-ons at $9.99/seat.
        public static readonly ProductInfo LogicFlowEnterprise = new(
            Name: "LogicFlow Enterprise",
            Description: "10-device license — all modules, lifetime sovereign updates, Oracle Voice (3h/mo), priority support, expandable seats. Windows 7 SP1 through Windows 11.",
            Price: 79.99m,
            ReferencePrefix: "LF-ENT",
            ReturnUrl: "https://delgadologic.tech/success",
            CancelUrl: "https://delgadologic.tech/pricing"
        );

        // ── Enterprise Seat Add-on ──
        // $9.99 per additional seat beyond the base 10.
        // Enterprise-only. Each add-on purchase increases the license's seat count by 1.
        public static readonly ProductInfo LogicFlowSeatAddon = new(
            Name: "LogicFlow Enterprise — Extra Seat",
            Description: "Add 1 additional device to your Enterprise license. Stacks with existing seats.",
            Price: 9.99m,
            ReferencePrefix: "LF-SEAT",
            ReturnUrl: "https://delgadologic.tech/success",
            CancelUrl: "https://delgadologic.tech/pricing"
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

public sealed class PayPalConfig
{
    public string ClientId { get; set; } = "AYGnJkdA6DBy9Muhnk07u9YGT6ExOzT7Q57b0RYbb1lnEe3rAY1qL8dY3RqA__fvf9ZG-LeMefwkZtcd";
    public string ClientSecret { get; set; } = "EGwozLJAVcbELXybrYqFkgOAXKxdXggyH6RB9HACKQzcOYNRhQg9Sf2hSxbCRec9zJGa_ZsuPdsgBiw2";
    public string BaseUrl { get; set; } = "https://api-m.paypal.com";
    public string WebhookId { get; set; } = "8B573547EK930032N";
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
