# LogicFlow v1.0 — Commercial Pricing, Tier Architecture & Merchant-of-Record Rationale

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic (`https://delgadologic.tech`)

---

## 1. Executive Summary: The "Anti-Subscription" Value Proposition

The Windows system utility market in 2026 is dominated by two unpopular monetization models:
1. **Recurring $40–$90/year auto-renewing subscriptions** (CCleaner Professional, Avast Cleanup, IObit Advanced SystemCare, Restoro/Outbyte) that rely on dark-pattern renewal billing and aggressive upsell popups.
2. **"Free" utilities funded by undisclosed adware bundles or silent background data harvesting**.

LogicFlow v1.0 introduces a transparent **Three-Tier Value Exchange** designed to maximize grassroots adoption while generating high-margin, low-chargeback one-time commercial revenue:

| Edition / SKU | Price (USD) | Devices | Commercial Use | Telemetry Policy (`OmniPulse`) | Key Entitlements & Scope |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LogicFlow Free** (`LF-FREE`) | **$0.00** | 1 Device | No (Personal only) | **None** (`ConsentLevel.None` — never queued or sent) | Read-only diagnostic scanning and system health preview across all modules; manual inspection without automated remediation. |
| **LogicFlow Community** (`LF-COMM`) | **$0.00** | 1 Device | No (Personal non-commercial only) | **Mandatory Pseudonymous Telemetry Condition** (`Standard` required; `Extended` included outside EU/EEA/UK/CH, optional checkbox inside EU/EEA/UK/CH). Declining or withdrawing drops to **Free**. | Unlocks interactive core cleanup, optimization, registry repair with automatic `.reg` backup, WOF game compression, and security hardening for personal use. |
| **LogicFlow Pro** (`LF-PRO`) | **$29.99** one-time<br>*(Launch Promo: **$19.99** for 60 days)* | **3 Devices** | **Yes** (Commercial & professional use permitted) | **Optional & OFF by default** (`ConsentLevel.None` unless user explicitly opts in via Settings) | Everything in Community + **Background Automation** (`LogicFlowAgent` scheduled scans/auto-fix, HyperStore autonomous worker & Game Guard, Game Vault auto-compact), **Advanced Recovery** (Lazarus deep sector carving & NTFS MFT record recovery), **All v1.x Updates Included**, and **24h Priority Support**. |
| **Extra Seat Add-On** (`LF-SEAT`) | **$9.99** one-time | +1 Device | Matches base Pro license | Matches base Pro license | Adds 1 additional device activation seat to an existing LogicFlow Pro license. |
| **LogicFlow Team 10-Pack** (`LF-TEAM10`) | **$149.00** one-time | **10 Devices** | **Yes** (Commercial & enterprise fleet use) | **Optional & OFF by default** (configurable via Group Policy / Registry `TelemetryDisabled=1`) | All Pro entitlements for up to 10 machines, CLI headless deployment (`lf.exe --json`), and priority 24h support. |

---

## 2. Competitive Pricing Benchmark (October 2026)

| Product | Licensing Model | Year 1 Cost | 3-Year Total Cost (3 PCs) | Includes Storage Dedup / Game Compact? | Includes Deep File Recovery? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LogicFlow v1.0 Pro** | **One-Time Purchase (v1.x)** | **$29.99** ($19.99 launch) | **$29.99** ($19.99 launch) | **Yes (`HyperStore` + WOF)** | **Yes (`Lazarus` MFT + Sector Carve)** |
| **CCleaner Professional Plus** | Annual Subscription (3 PCs) | $59.95 / yr | $179.85 | No | Yes (Recuva) |
| **IObit Advanced SystemCare Ultimate** | Annual Subscription (3 PCs) | $49.99 / yr | $149.97 | No | Separate tool |
| **Avast Cleanup Premium** | Annual Subscription (1–10 PCs) | $69.99 / yr | $209.97 | No | No |
| **Bitsum Process Lasso Pro** | One-Time / Household License | $37.00 – $69.00 | $37.00 – $69.00 | No (CPU/RAM only) | No |

### Why $29.99 Regular / $19.99 Launch Promo Hits the Sweet Spot
1. **Impulse-Buy Threshold**: $19.99 (60-day launch promo) and $29.99 (regular) sit below the psychological $30 impulse-purchase ceiling for PC gamers, power users, and software engineers—eliminating procurement friction.
2. **83% Lower 3-Year TCO than CCleaner Pro Plus**: At $29.99 for 3 PCs across the entire v1.x lifecycle, a customer saves **$150+** over three years compared to CCleaner Professional Plus ($59.95/yr).
3. **Clear Upgrade Path from Free & Community to Pro**:
   - **Free → Community ($0)**: Users who want interactive cleanup, registry repair, WOF game compression, and Defender hardening without paying cash can choose the Community Edition by agreeing to share pseudonymous diagnostic telemetry.
   - **Community → Pro ($19.99 / $29.99)**: Users convert to Pro whenever they want **no telemetry by default (`ConsentLevel.None`)**, **autonomous background workers** (`LogicFlowAgent`, HyperStore background deduplication with Game Guard, Game Vault auto-compact), **Lazarus deep sector & NTFS MFT data recovery**, **3-device coverage**, **commercial use rights**, or **24-hour priority support**.

---

## 3. Why Legacy Experimental SKUs Were Retired

During pre-launch commercial architecture review, four earlier draft pricing concepts were permanently retired for LogicFlow v1.0:

1. **Retired "$149 Founder Pass (All Future DelgadoLogic Products Forever)"**:
   - *Why Retired*: Selling an open-ended "all future unbuilt products forever" pass creates an uncapped long-term accounting liability and triggers payment processor scrutiny (PayPal/Stripe classify "lifetime future unshipped software" passes as elevated chargeback/fulfillment risk). Replaced with the concrete, immediately fulfilled **$149.00 LogicFlow Team 10-Pack** (`LF-TEAM10`, 10 seats of LogicFlow v1.x Pro delivered immediately upon checkout).
2. **Retired "$49 / $59 Sovereign Suite Bundle" & "$49.99 Family Tier"**:
   - *Why Retired*: Bundling LogicFlow with pre-release Aeon Browser tiers before Aeon's commercial v1.0 launch created fulfillment ambiguity. Consolidating around **LogicFlow Pro ($29.99 / $19.99 launch for 3 devices)** plus **$9.99 Extra Seat Add-Ons** (`LF-SEAT`) covers multi-PC households cleanly at a lower entry price.
3. **Retired "$9.99 One-Time AI Health Audit Upsell"**:
   - *Why Retired*: Paywalling individual diagnostic reports behind a micro-transaction eroded user trust.
4. **Explicit "Lifetime v1.x" Contract Definition**:
   - To eliminate any ambiguity around "lifetime" licensing, our EULA and Terms define one-time purchases as covering the **entire LogicFlow v1.x major release series** (`1.0` through `1.x`). If a major re-architected `v2.0` is released in the future, `v1.x` licenses remain perpetual while `v2.0` may be offered as an optional discounted upgrade (`~$14.99`).

---

## 4. Payment Processing & Merchant of Record (MoR) Risk Analysis

### 4.1 Industry Category Classification Risk ("PC Cleaners & System Utilities")
In the payment processing industry, the **"PC Optimizer / Registry Cleaner / System Utility"** vertical is historically classified as restricted or elevated-risk by several Merchant of Record (MoR) platforms due to legacy bad actors who used scareware popups ("CRITICAL WARNING: 1,482 ERRORS FOUND!") and deceptive auto-renewals.

| Platform | Role | Policy Stance on System Utilities / Cleaners | Recommendation for LogicFlow v1.0 |
| :--- | :--- | :--- | :--- |
| **PayPal + Stripe (Direct)** *(Integrated in `Website/functions`)* | Direct Payment Processors | Permitted for legitimate, non-deceptive software utilities with transparent one-time pricing and low dispute rates (`< 0.5%`). | **Primary Checkout Rails for v1.0 Launch.** Integrated with cryptographic webhook verification (`handlePayPalWebhook`, `createCheckoutOrder`, `captureCheckoutOrder`). |
| **Paddle** | Merchant of Record (MoR) | Lists *"PC cleaners, system optimizers, registry cleaners, and driver updaters"* under restricted categories unless granted an explicit written underwriting exception. | **Do NOT onboard without prior written underwriting approval** demonstrating LogicFlow's non-scareware UI and FastCDC/WOF storage engineering focus. |
| **Lemon Squeezy** (Stripe-owned MoR) | Merchant of Record (MoR) | Prohibits deceptive "system tune-up / scareware" utilities under Acceptable Use Policies; legitimate developer/storage CLI tools may pass manual review (`lemonSqueezyWebhook` stub ready). | Viable secondary MoR option for automated global VAT/GST handling **only after** manual AUP pre-approval. |
| **Polar.sh** | Developer-Focused MoR | Built specifically for indie developer tools, CLIs, and desktop engineering utilities (`polarWebhook` stub ready). | **Recommended MoR Evaluation Target** for automated global VAT handling when positioning emphasizes developer/workstation storage deduplication (`HyperStore`) and CLI automation (`lf.exe`). |

### 4.2 Chargeback Prevention & Unit Economics
To keep payment processor dispute rates near **0.00%**:
1. **Zero Scareware UI**: LogicFlow never displays fake red "CRITICAL SYSTEM FAILURE" alarms or forces payment to undo an action.
2. **Free & Community Tiers Allow Real Testing Before Paying**: Users can inspect diagnostics in Free ($0) or run interactive core modules in Community ($0) before spending a dollar.
3. **60-Day No-Questions-Asked Refund Policy**: Granting a fast refund via `billing@delgadologic.tech` or `support@delgadologic.tech` (and revoking the license record in Firestore) prevents $15.00+ chargeback fees and protects merchant account standing.
4. **EU/EEA/UK 14-Day Right of Withdrawal Compliance**: Checkout includes an explicit, unticked consent checkbox under **Directive 2011/83/EU Art. 16(m)** for immediate digital license delivery, while contractually honoring our full **60-day no-questions-asked money-back guarantee**.

---

## 5. Net Margin Breakdown (Per Transaction)

| SKU | Gross Price | Processor Fee (~2.9% + $0.30) | Variable Cloud Fulfillment Cost (Firestore + SMTP) | Net Revenue | Gross Margin (%) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **LogicFlow Pro (`LF-PRO` Launch Promo)** | $19.99 | -$0.88 | < $0.01 | **$19.10** | **95.5%** |
| **LogicFlow Pro (`LF-PRO` Regular)** | $29.99 | -$1.17 | < $0.01 | **$28.81** | **96.1%** |
| **Extra Seat Add-On (`LF-SEAT`)** | $9.99 | -$0.59 | < $0.01 | **$9.39** | **94.0%** |
| **LogicFlow Team 10-Pack (`LF-TEAM10`)** | $149.00 | -$4.62 | < $0.01 | **$144.37** | **96.9%** |
