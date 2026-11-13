# Privacy Policy

**Effective Date / Last Updated**: October 13, 2026  
**Policy Version**: `2026-10-1` (`ConsentStore.CurrentPolicyVersion`)  
**Data Controller / Business**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic ("DelgadoLogic," "we," "us," or "our")  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Privacy Contact**: `privacy@delgadologic.tech` (routes to `support@delgadologic.tech`)

---

## 1. Overview & Our Plain-English Privacy Commitment

Delgado Creative Enterprises LLC d/b/a DelgadoLogic builds **LogicFlow**, a Windows 10/11 system optimization, security hardening, storage deduplication, and data recovery utility, and operates `https://delgadologic.tech` and `https://api.delgadologic.tech`.

We design our software and cloud services around four verifiable privacy rules:
1. **Never Your Personal Files**: LogicFlow never reads, uploads, or transmits the contents of your personal documents, photos, browsing history, passwords, or private files.
2. **Tier-Specific Telemetry Control**:
   * **LogicFlow Free Edition ($0)**: Sends **no telemetry** (`ConsentLevel.None`).
   * **LogicFlow Pro & Team Editions ($29.99 / $149)**: Telemetry is **optional and OFF by default (`ConsentLevel.None`)**.
   * **LogicFlow Community Edition ($0)**: Unlocks interactive core features at $0 in exchange for **pseudonymous diagnostic telemetry** (`Standard` required across all regions; `Extended` baseline is **unchecked opt-in by default** in strict-consent regions [`EU/EEA`, `United Kingdom`, `Switzerland`, `Canada`, `Brazil`, `Japan`, `South Korea`, `India`] and **pre-selected by default** in non-strict regions [`United States`, `Mexico`, `Australia / New Zealand`, `Other / Rest of world`], where it can be unchecked on first run or disabled anytime in Settings while keeping Community access). Declining or withdrawing `Standard` telemetry drops the app to the Free Edition.
3. **Pseudonymous by Design — Never "Anonymous" Marketing Spin**: Because telemetry events carry a random, rotatable installation identifier (`installId`), we classify and protect them as **pseudonymous data** under the GDPR and CCPA/CPRA. We never derive `installId` from your hardware serial numbers, MAC address, or Windows username, and we **never store your IP address** in telemetry logs.
4. **One-Click Self-Service Erasure**: You can inspect what is queued locally, rotate your `installId`, or permanently erase all server-side telemetry associated with your `installId` directly inside the app (**Settings → Security & Privacy → Delete my data**), via our API (`POST https://api.delgadologic.tech/v1/telemetry/delete`), or via <https://delgadologic.tech/data-requests>.

---

## 2. Data Controller Identity & Contact

For purposes of the EU General Data Protection Regulation (GDPR), the UK GDPR, the California Consumer Privacy Act as amended by the CPRA (CCPA/CPRA), the District of Columbia Consumer Protection Procedures Act, and other applicable data protection laws, the data controller ("business") is:

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Email: `privacy@delgadologic.tech` / `support@delgadologic.tech`

---

## 3. Categories of Data We Collect, Sources & Purposes

We collect only the specific categories of information described below, depending on how you interact with DelgadoLogic:

### 3.1 Desktop Software Telemetry (`OmniPulse` — Community Edition & Opt-In Pro Users Only)
* **When Collected**: Only after you complete the first-run consent dialog (`ConsentWindow`) and only when your active `ConsentLevel` is `Standard` or `Extended`. Nothing is sent during installation or on the splash screen prior to consent.
* **Pseudonymous Identifier**:
  * `installId`: A randomly generated 128-bit cryptographic string (`16–64` characters) stored per-user in `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`. Rotated automatically on consent changes and every 90 days, or manually at any time in Settings.
  * `region`: Coarse 2-letter region code (`EU`, `GB`, `CH`, `US`, or `unknown`) read locally from your Windows OS regional settings and confirmed by you on first run. **We do not perform IP geolocation lookups.**
* **Standard Telemetry Level (`X-LF-Consent: standard`)**:
  * `crash` & `error` events: Exception type (e.g., `System.NullReferenceException`), PII-scrubbed message, `HRESULT` code, module name, and up to 30 normalized in-app stack frames (`Namespace.Type.Method` — stripped of file paths, line numbers, and method parameters).
  * `scan` events: Scan category, duration in milliseconds, count of items found, total bytes reclaimable, modules executed, and composite health score (`0–100`).
  * `usage` events (when enabled): Feature identifier, action verb, and duration in milliseconds.
* **Extended Telemetry Level (`X-LF-Consent: extended`)**:
  * Includes all `Standard` events plus a one-time `baseline` snapshot and weekly driver/health digest to power the crowd-sourced driver compatibility database:
    * Windows edition, display version, OS build, and CPU architecture (`x64`/`arm64`/`x86`);
    * Hardware class: CPU model name and core count, total RAM (GB), GPU vendor/name/driver version/date (up to 4 GPUs), BIOS vendor/version, baseboard vendor/model, and storage media types (`nvme`/`ssd`/`hdd`/`usb`);
    * Installed PnP device drivers (up to 200 entries: device class, vendor, driver name, version, date, and generic hardware ID class — **never device serial numbers**);
    * Installed Windows Update KB numbers (up to 500, e.g., `KB5034441`);
    * Registered Windows Security Center product names and running Windows service names/states.
* **Dual-Layer PII Scrubbing**: Before any telemetry event leaves your PC, `OmniPulse.TelemetryScrubber` strips Windows user profile paths (`C:\Users\<name>` → `<user>`), arbitrary drive and UNC paths, URL query strings, email addresses, IPv4/IPv6 addresses, Windows Security Identifiers (SIDs), machine hostnames, and 32+ character opaque tokens. Our ingestion server (`lf-telemetry-ingest`) runs a second independent PII scrubber before writing to storage.
* **IP Address Non-Persistence**: When your desktop client sends a telemetry batch to `https://api.delgadologic.tech/v1/telemetry/*`, our server hashes the source IP address in volatile memory using a rotating 6-hour random salt solely to enforce abuse rate limits (`120 req/min` per IP). **Raw IP addresses are never written to telemetry storage.**

### 3.2 License Activation & Commercial Orders (`OmniLicense` & Checkout)
* **Order & Billing Data**: When you purchase LogicFlow Pro, an Extra Seat, or a Team 10-Pack, our payment processor (PayPal, Stripe, or our authorized Merchant of Record) provides us with your checkout email address, name (if provided to the processor), billing country/postal code for tax compliance, transaction/order ID, capture ID, SKU purchased, and amount paid. **We never see or store your payment card number or bank credentials.**
* **License Hardware Fingerprint (`HWID`)**: When you activate a paid license via `activateLicense` or validate it via `validateLicense`, the app sends your Order ID, checkout email address, and a 44-character Base64 `HWID` (computed locally as the one-way `SHA-256` hash of `Win32_Processor.ProcessorId + Win32_BaseBoard.SerialNumber + Win32_BIOS.SerialNumber + Win32_DiskDrive.SerialNumber`). Raw serial numbers are never transmitted, and your `HWID` is never linked to your telemetry `installId`.

### 3.3 Optional Driver Compatibility Lookup (`LogicFlow.Guardian`)
* When you manually trigger an online driver check in the Driver Auditor module (`lf driver update`), the app queries our cloud driver index with generic PnP hardware/compatible ID strings (e.g., `PCI\VEN_10DE&DEV_...`) and current driver version/date to check for newer OEM releases.

### 3.4 Website Visits, Waitlist & Support Communications
* **Waitlist & Newsletter (`joinWaitlist`)**: If you voluntarily submit your email address to join a product waitlist on `delgadologic.tech`, we store your email address, signup timestamp, and source page in Firestore (`waitlist_users`), and you may unsubscribe at any time via `privacy@delgadologic.tech`.
* **Support & Data Subject Requests**: When you email `support@`, `privacy@`, `legal@`, `security@`, or `billing@delgadologic.tech`, or submit a request via `/data-requests`, we process the contact information and message contents you provide to resolve your inquiry.
* **Website Hosting Logs**: Standard edge/CDN access logs (Cloudflare and Firebase Hosting) transiently process connecting IP addresses and HTTP user-agent headers for DDoS mitigation and TLS delivery. We do not use third-party advertising trackers, behavioral profiling pixels, or cross-site tracking cookies on `delgadologic.tech`.

---

## 4. Legal Bases for Processing (GDPR / UK GDPR & ePrivacy Directive)

If you are located in the European Economic Area (EEA), the United Kingdom, or Switzerland, we process your personal data under the following legal bases:

| Processing Activity | GDPR / UK GDPR Legal Basis | ePrivacy Directive Art. 5(3) Basis |
| :--- | :--- | :--- |
| **Paid License Issuance, Activation (`HWID`), Delivery & Support** | **Art. 6(1)(b)** — Performance of a contract with you. | Strictly necessary to deliver the license and service explicitly requested by the subscriber/user. |
| **Community Edition `Standard` Telemetry (EU/EEA/UK/CH)** | **GDPR Art. 6(1)(a) & Art. 7(4) Freely Given Consent** and **ePrivacy Art. 5(3) Prior Consent** (under EDPB Guidelines 2/2019 & 2/2023 and EDPB Opinion 08/2024, both a free zero-telemetry edition [`LogicFlow Free`, $0] and a reasonably priced one-time paid zero-telemetry edition [`LogicFlow Pro`, $19.99 launch / $29.99 regular] are offered without data processing in accordance with EDPB Opinion 08/2024, plus contractual performance under **Art. 6(1)(b)** in jurisdictions where applicable). | **Art. 5(3) Prior Consent** — Affirmative opt-in consent on the first-run edition/consent screen (`ConsentWindow`) before any local telemetry queue is read or transmitted from terminal equipment (EDPB Guidelines 2/2023). |
| **Community Edition `Extended` System Baseline (EU/EEA/UK/CH)** | **Art. 6(1)(a)** — Freely given, granular, affirmative **opt-in consent** via a separate unchecked checkbox on the first-run screen (and toggleable at any time in Settings without losing Community Edition access). | **Art. 5(3) Prior Consent** — Explicit opt-in before reading or transmitting extended baseline data from terminal equipment. |
| **Pro / Team Optional Telemetry** | **Art. 6(1)(a)** — Explicit opt-in consent (OFF by default). | **Art. 5(3) Prior Consent**. |
| **Tax, Accounting & Refund Records** | **Art. 6(1)(c)** — Compliance with legal obligations (tax and financial record-keeping). | N/A (server-side transaction records). |
| **API Rate Limiting (In-Memory Salted IP Hash) & Security** | **Art. 6(1)(f)** — Legitimate interests in protecting our infrastructure from abuse, DDoS, and credential stuffing. | Strictly necessary for network security and service integrity. |

---

## 5. Data Retention Schedule (Category-by-Category Disclosure)

In compliance with GDPR Article 5(1)(e), CCPA/CPRA (Cal. Civ. Code § 1798.100(a)(3)), and the amended FTC COPPA Rule (16 C.F.R. § 312.10), we enforce strict, automated retention limits for every category of data:

| Data Category | Storage Location | Exact Retention Period | Disposition / End-of-Life Action |
| :--- | :--- | :--- | :--- |
| **Raw Telemetry Events & Ingest Stats** (`crash`, `error`, `scan`, `usage`, `baseline` linked to `installId`) | Google Cloud Storage (`v1/events/dt=YYYY-MM-DD/…`) | **90 calendar days** | Automatically hard-deleted via GCS Object Lifecycle Management rules (or purged earlier upon a `/delete` erasure request). |
| **Erasure Tombstones** (`sha256(installId)` only — raw ID never stored) | Google Cloud Storage (`v1/erasures/`) | **90 calendar days** (matching the maximum raw partition window) | Automatically purged once all raw partitions from before the erasure timestamp have expired. |
| **Daily Aggregated Telemetry Rollups** *(contains zero `installId` values)* | Google Cloud Storage (`v1/rollups/daily/`) & BigQuery | **13 months (395 days)** | Automatically deleted after 395 days. |
| **Deduplicated Crash Groups** *(stack fingerprint + counts only; zero `installId` values)* | Google Cloud Storage (`v1/crash_groups/`) | **Indefinite** (non-personal aggregate software defect catalog) | Retained for regression tracking across software versions. |
| **In-Memory Rate-Limit IP Hashes** | Cloud Run volatile RAM | **Maximum 6 hours** | Salt rotates every 6 hours and memory buckets are discarded. |
| **Commercial Sales, Invoices & License Records** (`sales`, `licenses`, `license_activations`) | Google Cloud Firestore | **Duration of active license + 7 years** | Retained to validate perpetual v1.x offline/online licenses and satisfy US/international tax and audit statutes. |
| **Waitlist Subscriptions** (`waitlist_users`) | Google Cloud Firestore | **Until product launch notification + 12 months**, or immediate upon unsubscribe | Permanently deleted from Firestore upon unsubscribe request. |
| **Support & Privacy Correspondence** | Email / Support inbox (`support@delgadologic.tech`) | **24 months** after ticket closure | Deleted after 24 months unless required for an active legal claim. |

---

## 6. Subprocessors & Third-Party Disclosures

We **never sell** your personal information, and we **never share** your personal information for cross-context behavioral advertising. We disclose data only to vetted infrastructure and payment subprocessors bound by data processing agreements:

1. **Google Cloud Platform (GCP) & Firebase (Google LLC)** — United States (`us-central1`): Cloud Run (`lf-telemetry-ingest`), Cloud Storage, BigQuery, Cloud Functions, Firestore, and Firebase Hosting.
2. **Cloudflare, Inc.** — Global Edge Network: Authoritative DNS, TLS termination, and DDoS protection.
3. **PayPal, Inc. / Stripe, Inc. (and Authorized Merchant of Record)** — United States / Global: Checkout payment processing, fraud prevention, and refund execution.

See [`subprocessors.md`](./subprocessors.md) for the complete subprocessor inventory.

---

## 7. International Data Transfers

DelgadoLogic is established in the United States (Washington, D.C.), and our primary cloud infrastructure (Google Cloud `us-central1`) is located in the United States. When personal data from the EEA, UK, or Switzerland is transferred to the United States, we rely on:
* The **EU-U.S. Data Privacy Framework (DPF)**, the UK Extension to the EU-U.S. DPF, and the Swiss-U.S. DPF for certified subprocessors (including Google LLC and Cloudflare, Inc.); and
* The European Commission's **Standard Contractual Clauses (SCCs)** (Commission Implementing Decision (EU) 2021/914, Module Two/Three) and the **UK International Data Transfer Addendum (IDTA)** incorporated into our subprocessors' Data Processing Addenda, reinforced by technical supplementary measures (TLS 1.3 in transit, AES-256 encryption at rest, client-side PII scrubbing, and non-persistence of IP addresses).

---

## 8. Your Privacy Rights & How to Exercise Them

Depending on your jurisdiction (including the EEA, UK, Switzerland, California, Virginia, Colorado, Connecticut, Texas, Oregon, and Washington, D.C.), you have the right to:
* **Access / Know**: Request confirmation of what personal data we hold about you and obtain a portable copy.
* **Delete / Erasure ("Right to be Forgotten")**: Request immediate deletion of your telemetry data or personal records.
* **Rectification / Correction**: Correct inaccurate personal information associated with your license record.
* **Withdraw Consent / Opt Out**: Switch telemetry levels or disable telemetry at any time in **Settings → Security & Privacy**.
* **Lodge a Complaint**: EU/EEA/UK residents have the right to lodge a complaint with their local Data Protection Authority (supervisory authority) or the UK Information Commissioner's Office (ICO).

### How to Delete Your Telemetry Data Immediately
1. **In-App (Instant)**: Open LogicFlow → **Settings → Security & Privacy** → click **Delete my data**. The app deletes your local queue and baseline copy, retires your `installId`, and sends a signed `POST https://api.delgadologic.tech/v1/telemetry/delete` request that immediately writes a cryptographic erasure tombstone (`sha256(installId)`), drops buffered events, excludes your ID from all views/digests, and rewrites raw GCS partitions.
2. **Via Web Form or Email**: Submit your `installId` or checkout email via <https://delgadologic.tech/data-requests> or email `privacy@delgadologic.tech`. See [`data-subject-requests.md`](./data-subject-requests.md) for full details.

---

## 9. California Privacy Rights (CCPA / CPRA Notice at Collection & Financial Incentive Disclosure)

If you are a California resident, the California Consumer Privacy Act (as amended by the CPRA, Cal. Civ. Code § 1798.100 *et seq.*) provides specific disclosures:

1. **Categories Collected in the Past 12 Months**:
   * *Identifiers*: Email address and Order ID (for paid license buyers and waitlist subscribers); random pseudonymous `installId` (for Community/opt-in telemetry users); hashed 4-component `HWID` (for paid license activation).
   * *Commercial Information*: Software SKU purchased, transaction date, and refund status.
   * *Internet or Electronic Network Activity Information*: Pseudonymous software crash logs, scan metrics, feature usage counts, and (when `Extended` telemetry is enabled) hardware/driver/KB baseline metadata.
   * *Approximate Geolocation*: Coarse 2-letter country/region code read from local Windows OS settings (`US`, `EU`, `GB`, `CH`, `unknown`). We **never** collect precise geolocation.
   * *Sensitive Personal Information*: We **do not** collect, infer, or process "Sensitive Personal Information" as defined by Cal. Civ. Code § 1798.140(ae).
2. **No Selling or Sharing**: We **do not "sell"** or **"share"** (for cross-context behavioral advertising) any category of personal information, including the personal information of minors under 16 years of age. We honor **Global Privacy Control (GPC)** browser signals on `delgadologic.tech`.
3. **Notice of Financial Incentive (Cal. Civ. Code § 1798.125 — Community Edition)**:
   * **Summary of Incentive**: Under the **LogicFlow Community Edition ($0)**, users receive access to interactive core optimization and hardening features (which are also included in the **$29.99 USD** one-time LogicFlow Pro Edition) in exchange for enabling pseudonymous diagnostic telemetry (`Standard` / `Extended`).
   * **Categories of Data Implicated**: Only the pseudonymous desktop telemetry fields tied to `installId` listed in Section 3.1.
   * **How to Opt In**: By selecting the Community Edition and accepting the telemetry disclosure on the first-run screen (`ConsentWindow`).
   * **Right to Withdraw at Any Time**: You may opt out at any time via **Settings → Security & Privacy** (which transitions the app to the $0 Free scan-only tier or allows you to activate a paid Pro license with telemetry OFF).
   * **Good-Faith Value Calculation**: We estimate the good-faith value of aggregated Community diagnostic telemetry to our engineering and driver compatibility indexing operations as equivalent to the amortized per-device cost of our Pro license (**$9.99 to $29.99 USD** over the v1.x product lifecycle), based on the direct engineering expenses saved in reproducing Windows KB regressions, hardware driver faults, and application crash signatures across diverse PC configurations.

---

## 10. Children's Privacy (COPPA & Age 16+ Policy)

LogicFlow and `delgadologic.tech` require users to be at least **sixteen (16) years of age**. Our Software and websites are **not directed to children under thirteen (13) years of age**, and we do not knowingly collect, use, or disclose personal information from children under 13. In accordance with the amended FTC Children's Online Privacy Protection Act (COPPA) Rule (effective April 22, 2026), if we obtain actual knowledge that we have inadvertently collected personal information from a child under 13 (or a minor under 16 without required authorization), we will immediately delete such information from our records. Parents or guardians who believe a minor has provided information to us may contact `privacy@delgadologic.tech`.

---

## 11. Information Security Program

We maintain a comprehensive written information security program incorporating administrative, technical, and physical safeguards appropriate to the sensitivity of the data we process, including:
* TLS 1.3 encryption in transit for all API, licensing, update, and telemetry endpoints;
* Per-build HMAC-SHA256 wire-level request authentication (`X-LF-Sig`) verified prior to gzip decompression;
* Dual-layer client and server PII scrubbing;
* Ed25519 digital signatures on update manifests and RSA-2048 signatures on license tokens; and
* Strict least-privilege IAM controls and automated 90-day lifecycle deletion on Google Cloud Storage.

---

## 12. Changes to This Privacy Policy

When we make material changes to this Privacy Policy, we increment the `PolicyVersion` identifier in both this document and the desktop client (`OmniPulse.ConsentStore`). If `PolicyVersion` changes, the desktop application automatically pauses telemetry (`EffectiveLevel() == None`) and re-prompts you on next launch before any further telemetry is transmitted.

**Contact Us**:  
Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
Email: `privacy@delgadologic.tech` / `support@delgadologic.tech`
