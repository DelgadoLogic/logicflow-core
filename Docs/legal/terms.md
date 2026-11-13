# Terms of Service & Conditions of Sale

**Effective Date / Last Updated**: October 13, 2026  
**Provider**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic ("DelgadoLogic," "Company," "we," "us," or "our")  
**Website & APIs**: `https://delgadologic.tech`, `https://api.delgadologic.tech`, `https://docs.delgadologic.tech`

---

## 1. Acceptance of Terms

These Terms of Service and Conditions of Sale ("Terms") govern your access to and use of the `delgadologic.tech` website, documentation portals, customer license portal, cloud activation/telemetry endpoints, and your purchase of software licenses from **Delgado Creative Enterprises LLC d/b/a DelgadoLogic**, a District of Columbia limited liability company located at 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA.

Your installation and use of the **LogicFlow** desktop software application are additionally governed by the [LogicFlow End User License Agreement (EULA)](./eula.md). In the event of any direct conflict between these Terms and the EULA regarding desktop software usage rights, the EULA shall govern.

By accessing our website, placing an order, or activating a license, you confirm that you are at least **sixteen (16) years of age** and agree to be bound by these Terms.

---

## 2. Products, Editions & Pricing

DelgadoLogic distributes LogicFlow for 64-bit Microsoft Windows 10 (Version 1607+) and Windows 11 under the following editions and SKUs (all prices in United States Dollars, exclusive of applicable sales tax or VAT unless stated at checkout):

| SKU / Edition | Price (USD) | Device Seats | Commercial Use | Update Scope |
| :--- | :--- | :--- | :--- | :--- |
| **LogicFlow Free** (`LF-FREE`) | **$0.00** | 1 Device | No | v1.x updates |
| **LogicFlow Community** (`LF-COMM`) | **$0.00** *(Pseudonymous Telemetry Condition)* | 1 Device | No (Personal only) | v1.x updates |
| **LogicFlow Pro** (`LF-PRO`) | **$29.99** one-time *(Launch Promo: **$19.99** for 60 days)* | **3 Devices** | **Yes** | All v1.x updates included |
| **Extra Seat Add-On** (`LF-SEAT`) | **$9.99** one-time | +1 Device | Matches Pro license | Matches Pro license |
| **LogicFlow Team 10-Pack** (`LF-TEAM10`) | **$149.00** one-time | **10 Devices** | **Yes** | All v1.x updates included |

### 2.1 One-Time Purchase & "Lifetime" v1.x Definition
All paid LogicFlow v1.x SKUs are **one-time purchases, not recurring subscriptions**. Your one-time payment grants a perpetual license for the v1.x major release series and includes all minor updates, bug fixes, and security patches throughout the **LogicFlow v1.x lifecycle** (`1.0` through `1.x`). If DelgadoLogic introduces a major architectural successor release (e.g., `v2.0`), existing Pro customers may continue running `v1.x` indefinitely or purchase an optional major-version upgrade (anticipated at `~$14.99`).

### 2.2 Promotional Pricing
The **$19.99 USD** launch promotional price for LogicFlow Pro is valid for a 60-day promotional window following commercial launch. Promotional discounts cannot be combined with other coupon codes unless explicitly stated at checkout.

---

## 3. Checkout, Payment Processing & Taxes

1. **Payment Processors & Merchant of Record**: Orders placed on `delgadologic.tech` are processed via our third-party payment processors (including PayPal, Stripe, or an authorized Merchant of Record, as displayed at checkout). DelgadoLogic never receives or stores your raw credit card number or CVV.
2. **Order Fulfillment & Immediate Digital Delivery**: Upon payment confirmation (`PAYMENT.CAPTURE.COMPLETED` or equivalent webhook verification), our licensing backend automatically generates your cryptographic license record, displays your Order ID / activation details on the checkout confirmation screen, and sends a confirmation receipt to your checkout email address.
3. **Taxes**: Depending on your billing jurisdiction and the payment processor handling your checkout, applicable state sales tax, GST, or EU/UK Value Added Tax (VAT) may be calculated and collected at checkout.

---

## 4. 60-Day Money-Back Guarantee & EU/UK Statutory Withdrawal Waiver

1. **60-Day No-Questions-Asked Refund Policy**: We stand behind LogicFlow with a **60-day no-questions-asked money-back guarantee** on all direct purchases of LogicFlow Pro, Extra Seat Add-Ons, and Team 10-Packs. To request a full refund within 60 calendar days of purchase, email `billing@delgadologic.tech` or `support@delgadologic.tech` with your Order ID or checkout email address.
2. **EU/EEA/UK 14-Day Digital Content Withdrawal Waiver**: Pursuant to Article 16(m) of Directive 2011/83/EU (the EU Consumer Rights Directive) and Regulation 37 of the UK Consumer Contracts Regulations 2013, consumers in the EU, EEA, and UK who purchase digital content not supplied on a tangible medium are asked at checkout to tick an un-prechecked box providing their **prior express consent** to immediate digital delivery/license issuance and acknowledging that they thereby waive their 14-day statutory right of withdrawal once digital delivery begins. **Notwithstanding this statutory waiver for immediate delivery, DelgadoLogic contractually honors our full 60-day no-questions-asked money-back guarantee for all EU, EEA, and UK customers.** See our [Refund Policy](./refund.md) for complete terms.

---

## 5. Customer Portal, License Keys & Seat Management

1. **Account & Order Lookup**: You are responsible for maintaining the confidentiality of your Order ID, license files (`license_token.json` / `license.lic`), and checkout email address.
2. **Seat Activations**: A LogicFlow Pro license permits activation on up to three (3) distinct hardware fingerprints (`HWID`s), plus any purchased Extra Seats. A Team 10-Pack permits activation on up to ten (10) `HWID`s. If you replace a motherboard or decommission a PC and need a seat reset, contact `support@delgadologic.tech`.
3. **Revocation on Refund or Chargeback**: If an order is refunded, reversed, or subjected to a payment chargeback, the corresponding license record is immediately marked revoked (`status: refunded` / `revoked`), and all associated device activations cease to validate as Pro/Team.

---

## 6. Support Services & Service Level Objectives

| Edition | Support Channel | Target Response Time |
| :--- | :--- | :--- |
| **Free & Community** | Self-service documentation (`docs.delgadologic.tech`) & community issue reports (`support@delgadologic.tech` for privacy/billing) | 48 business hours (billing/privacy inquiries) |
| **Pro & Team 10-Pack** | Priority email support (`support@delgadologic.tech`) | **24 business hours** (48 business hours max) |

* **Business Hours**: Monday through Friday, 9:00 AM to 5:00 PM Eastern Standard Time (EST / EDT), excluding United States federal holidays.

---

## 7. Acceptable Use & Website Conduct

When using our websites, APIs (`api.delgadologic.tech`), or telemetry endpoints, you agree not to:
1. Submit forged, spoofed, or floods of requests to `/v1/telemetry/*`, `/activate`, `/validate`, or `/checkout`;
2. Attempt to probe, scan, or test the vulnerability of our infrastructure except in strict compliance with our [Security & Coordinated Vulnerability Disclosure Policy](./security-policy.md);
3. Scrape, mirror, or redistribute our proprietary software binaries or documentation for commercial resale; or
4. Violate our [Trademark Notice & Acceptable Use Policy](./trademark-and-acceptable-use.md).

---

## 8. Disclaimers & Limitation of Liability

1. **Website & Cloud Services "As Is"**: Our websites, documentation, driver compatibility lookup service, and cloud licensing endpoints are provided "AS IS" and "AS AVAILABLE" without warranties of any kind, to the fullest extent permitted by applicable law.
2. **Liability Cap**: To the fullest extent permitted by applicable law, DelgadoLogic's aggregate liability arising out of or relating to these Terms or any order placed on `delgadologic.tech` shall not exceed the greater of: (a) the total amount paid by you to DelgadoLogic in the twelve (12) months preceding the claim, or (b) **$30.00 USD**. Nothing in these Terms excludes or limits any non-waivable consumer rights under the District of Columbia Consumer Protection Procedures Act (D.C. Official Code §§ 28-3901 *et seq.*) or mandatory EU/UK consumer protection laws.

---

## 9. Governing Law & Venue

These Terms are governed by the laws of the **District of Columbia, United States of America**, without regard to conflict-of-law principles. Any judicial proceeding arising out of or relating to these Terms shall be brought exclusively in the state or federal courts located in **Washington, D.C.**, subject to mandatory consumer forum rights for EU/EEA/UK residents under Rome I / Brussels Ia.

---

## 10. Changes to These Terms & Contact Information

We may update these Terms from time to time by posting the revised version on `https://delgadologic.tech/terms` with an updated effective date. Material changes will apply prospectively.

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Support: `support@delgadologic.tech`  
Billing: `billing@delgadologic.tech`  
Legal: `legal@delgadologic.tech`
