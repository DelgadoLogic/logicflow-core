# Cookie & Local Storage Notice

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity / Data Controller**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Applies To**: `https://delgadologic.tech`, `https://docs.delgadologic.tech`, `https://audit.delgadologic.tech`, and the LogicFlow v1.0 Desktop Application (`LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`)

---

## 1. Overview & Regulatory Basis

This Cookie & Local Storage Notice explains how **Delgado Creative Enterprises LLC d/b/a DelgadoLogic** ("**DelgadoLogic**," "**we**," "**us**," or "**our**") uses HTTP cookies, browser `localStorage`, browser `sessionStorage`, and local desktop configuration files when you visit `https://delgadologic.tech` (the "**Website**") or use the LogicFlow v1.0 desktop application (the "**Software**").

This Notice is provided in compliance with:
- **Directive 2002/58/EC** (the EU ePrivacy Directive, as amended by Directive 2009/136/EC), **Article 5(3)**;
- **European Data Protection Board (EDPB) Guidelines 2/2023** on the Technical Scope of Article 5(3) of the ePrivacy Directive;
- The **UK Privacy and Electronic Communications Regulations 2003 (PECR)**, Regulation 6;
- The **EU General Data Protection Regulation (GDPR)** (Regulation (EU) 2016/679) and **UK GDPR**; and
- The **California Consumer Privacy Act / California Privacy Rights Act (CCPA/CPRA)** (Cal. Civ. Code § 1798.100 *et seq.*).

---

## 2. No Ad-Tech & No Third-Party Behavioral Tracking Policy

DelgadoLogic operates under a strict **No Ad-Tech Policy** across both our Website and our Software:
- **No Advertising Cookies**: We do **not** use Google Ads, Meta Pixel, TikTok Pixel, LinkedIn Insight Tag, X/Twitter Pixel, or any behavioral advertising networks.
- **No Cross-Site Behavioral Analytics**: We do **not** deploy Google Analytics (`_ga`, `_gid`), Mixpanel, Hotjar, FullStory, PostHog, or Amplitude on `https://delgadologic.tech`.
- **No Data Broker Pixels**: We do **not** embed third-party scripts that share browsing behavior with data brokers or real-time bidding (RTB) exchanges.
- **Global Privacy Control (GPC) & Do Not Track (DNT)**: Our Website honors `Sec-GPC: 1` and `DNT: 1` browser signals by default because no cross-context behavioral advertising or data "sale"/"sharing" occurs for any visitor.

---

## 3. Website Storage (`https://delgadologic.tech`)

When you visit `https://delgadologic.tech`, only **strictly necessary** technical storage mechanisms are used. Under **Article 5(3) of the ePrivacy Directive** and **UK PECR Regulation 6(4)**, strictly necessary cookies and storage items that are essential to provide an information society service explicitly requested by the user (such as completing a checkout, authenticating into the customer portal, or rendering the site) do not require prior opt-in consent.

### 3.1 First-Party Website Storage (`delgadologic.tech`)

| Name / Key | Type | Provider | Purpose | Duration / Expiry | Category |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `dl_theme_pref` | `localStorage` | `delgadologic.tech` | Remembers UI display preference if toggled by the user. | Persistent (until cleared in browser) | Strictly Necessary / Preference |
| `dl_checkout_tier` | `sessionStorage` | `delgadologic.tech` | Temporarily holds the selected edition SKU (`LF-PRO`, `LF-SEAT`, `LF-TEAM10`) during checkout modal navigation. | Session (cleared when tab closes) | Strictly Necessary |
| `firebase:authUser:*` | `IndexedDB` / `localStorage` | Firebase Authentication (`delgadologic.tech`) | Maintains authenticated customer session state ONLY when you actively sign in to the `/portal` license management page. | Session / until sign-out | Strictly Necessary (Authentication) |

### 3.2 Third-Party Payment Processor Cookies (Loaded Only Upon Checkout Initiation)

Payment processor scripts and redirects are invoked **only** when you actively click a purchase button to initiate a commercial transaction:

| Cookie / Storage Name | Provider | Purpose | Duration | Privacy Documentation |
| :--- | :--- | :--- | :--- | :--- |
| `ts`, `ts_c`, `x-pp-s`, `nsid`, `enforce_policy` | PayPal, Inc. | Transaction security, CSRF protection, fraud detection, and session state during PayPal order approval. | Session to 1 year | [PayPal Cookie Statement](https://www.paypal.com/us/webapps/mpp/ua/cookie-full) |
| `__stripe_mid`, `__stripe_sid` | Stripe, Inc. | Fraud prevention and session identifier when Stripe Checkout is invoked. | 30 minutes to 1 year | [Stripe Cookie Policy](https://stripe.com/cookies-policy/legal) |

### 3.3 Self-Hosted Fonts & Infrastructure Delivery

- **Self-Hosted Web Fonts & Icons (`https://delgadologic.tech/fonts/*`)**: All typography (`Inter`, `JetBrains Mono`) and icon fonts (`Font Awesome Free`) on `delgadologic.tech` are self-hosted directly from our first-party origin so your browser does not leak your IP address or `Referer` header to third-party font CDNs (`fonts.googleapis.com` or `cdnjs.cloudflare.com`).
- **Cloudflare & Firebase Hosting**: Serve static HTML, CSS, and JavaScript bundles over TLS 1.3. We do not enable tracking or marketing cookies on our edge CDN; standard HTTP request headers and connecting IP addresses are processed transiently for DDoS mitigation and TLS termination.

---

## 4. Desktop Application Local Storage (ePrivacy Art. 5(3) & EDPB Guidelines 2/2023)

Under **Article 5(3) of the ePrivacy Directive** and **EDPB Guidelines 2/2023**, storing information on—or gaining access to information already stored in—a user's desktop terminal equipment (your Windows PC) is subject to transparency and consent rules unless the storage or access is **strictly necessary** to provide the software functionality requested by the user.

LogicFlow v1.0 stores the following local files on your Windows machine:

### 4.1 Strictly Necessary Local Application Files

These files are required for the Software to function, remember your configuration, verify your license, and allow you to roll back system optimizations:

| Local File Path | Purpose | Transmitted Over Network? | Category |
| :--- | :--- | :--- | :--- |
| `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json` | Per-user consent record (`OmniPulse.ConsentStore`) storing edition choice (`Free`, `Community`, `Pro`), `ConsentLevel` (`None`, `Standard`, `Extended`), region confirmation, `PolicyVersion`, `EulaVersion`, `EulaSha256`, decision timestamps, and pseudonymous `installId`. | `installId` and `region` are included in telemetry envelopes **only if** `EffectiveLevel()` is `Standard` or `Extended`. Fails closed to `None` if missing or outdated. | Strictly Necessary (Consent & Tier State) |
| `%LOCALAPPDATA%\LogicFlow\settings.json` | Stores local UI preferences, startup scan toggles, and tray behavior (`SettingsManager`). | **Never transmitted.** Stays 100% local on your disk. | Strictly Necessary (User Preferences) |
| `%PROGRAMDATA%\DelgadoLogic\license.lic` & `%LOCALAPPDATA%\LogicFlow\license_token.json` | Stores your RSA-2048 digitally signed offline license token (`OmniLicense`). | Verified offline via RSA-2048 (`SHA-256`). Sent only when you initiate online license activation/validation. | Strictly Necessary (License Verification) |
| `%LOCALAPPDATA%\LogicFlow\RegistryBackups\*.reg` | Stores timestamped `.reg` registry snapshots created prior to registry repairs or system tweaks so you can roll back changes at any time (`lf reg rollback`). | **Never transmitted.** Stays 100% local on your disk. | Strictly Necessary (Safety Rollback) |

### 4.2 Consent-Gated Local Telemetry Queue (Community Edition & Opt-In Pro Users Only)

| Local File Path | Purpose | Transmitted Over Network? | Category |
| :--- | :--- | :--- | :--- |
| `%LOCALAPPDATA%\LogicFlow\Pulse\event_queue.jsonl` & `system_baseline.json` | Local NDJSON buffer (capped at 512 KB) of PII-scrubbed pseudonymous diagnostic events queued for upload to `https://api.delgadologic.tech/v1/telemetry/*`. | **Yes, ONLY when `ConsentLevel` is `Standard` or `Extended`**. When `ConsentLevel` is `None`, `PulseClient` never writes to this queue and immediately deletes any existing queue file. | Consent-Gated (`ePrivacy Art. 5(3)` & `GDPR Art. 6(1)(a)/(b)`) |

For complete technical details on every field in the telemetry JSON schema, see our [Telemetry & Diagnostics Technical Disclosure](./telemetry-disclosure.md).

---

## 5. How to Manage or Clear Cookies & Local Storage

### 5.1 In Your Web Browser
You can delete `localStorage`, `sessionStorage`, `IndexedDB`, and cookies for `https://delgadologic.tech` at any time using your browser's developer tools (`F12` → **Application** → **Storage** → **Clear site data**) or browser privacy settings.

### 5.2 In the LogicFlow Desktop Application
- **Disable Telemetry & Purge Local Queue**: Open **LogicFlow → Settings → Security & Privacy** and set Diagnostics Sharing to **None** (or click **Delete my data**). This immediately wipes `event_queue.jsonl` and `system_baseline.json`.
- **IT / Enterprise Machine-Wide Suppression**: Set `HKLM\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled = 1` (DWORD).
- **Full Local Data Removal**: Uninstalling LogicFlow or deleting `%LOCALAPPDATA%\LogicFlow\` removes all local configuration, consent, and backup files from your PC.

---

## 6. Contact Us

For questions regarding this Cookie & Local Storage Notice, contact:
- **Privacy Contact**: `privacy@delgadologic.tech` (routes to `support@delgadologic.tech`)
- **Postal Address**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic, 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA
