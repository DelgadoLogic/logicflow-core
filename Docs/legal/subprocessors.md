# Subprocessors & Infrastructure Service Providers

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Data Controller**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Privacy Contact**: `privacy@delgadologic.tech` (routes to `support@delgadologic.tech`)

---

## 1. Overview & Purpose

In accordance with **Article 28 and Articles 13/14 of the EU/UK General Data Protection Regulation (GDPR)** and the **California Consumer Privacy Act / California Privacy Rights Act (CCPA/CPRA)**, this page lists every third-party infrastructure provider, payment processor, and service provider ("**Subprocessor**") engaged by **Delgado Creative Enterprises LLC d/b/a DelgadoLogic** ("**DelgadoLogic**") to host `https://delgadologic.tech`, fulfill LogicFlow v1.0 software licenses, deliver transactional emails, and (for Community Edition and opt-in Pro users) process pseudonymous diagnostic telemetry.

DelgadoLogic does **not** use any advertising networks, data brokers, or cross-site behavioral tracking providers.

---

## 2. Active Subprocessors & Independent Payment Controllers (October 2026)

| Provider Name & Legal Entity | Service / Role | Categories of Data Processed | Applicable Product / Tier | Primary Processing Location | Cross-Border Transfer Mechanism (EEA/UK/CH) | Privacy & Security Documentation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google LLC** (Google Cloud Platform — Cloud Run, Cloud Storage, BigQuery) | Cloud infrastructure hosting for the pseudonymous telemetry ingestion service (`lf-telemetry-ingest` at `api.delgadologic.tech/v1/telemetry`), GCS storage, and BigQuery views | Pseudonymous `installId` (`16–64` char random token), OS build, coarse region (`EU`/`GB`/`CH`/`US`/`unknown`), and PII-scrubbed diagnostic/baseline events (90-day raw retention; 13-month daily rollups without `installId`; indefinite crash groups without `installId`; no client IPs stored) | **Community Edition** and **Pro / Team** (only if optionally opted in) | United States (`us-central1`) | EU-U.S. Data Privacy Framework (DPF), UK Extension, Swiss-U.S. DPF + EU Standard Contractual Clauses (SCCs) | [Google Cloud Privacy Notice](https://cloud.google.com/terms/cloud-privacy-notice) & [Google Cloud DPA](https://cloud.google.com/terms/data-processing-addendum) |
| **Google LLC** (Firebase Hosting, Cloud Functions for Firebase, Cloud Firestore) | Website hosting (`delgadologic.tech`, `docs.delgadologic.tech`, `audit.delgadologic.tech`), serverless checkout/webhook orchestration, and license fulfillment ledger (`sales`, `licenses`, `waitlist_users`) | Customer checkout email address, Order/Capture ID, signed license token, edition SKU, seat count, and 44-character Base64 SHA-256 hardware activation fingerprint (`HWID`) | Website visitors, Waitlist subscribers & **Pro / Extra Seat / Team 10-Pack** purchasers | United States (`us-central1`) | EU-U.S. Data Privacy Framework (DPF), UK Extension, Swiss-U.S. DPF + EU SCCs | [Firebase Privacy and Security](https://firebase.google.com/support/privacy) |
| **Cloudflare, Inc.** | Authoritative DNS, TLS 1.3 edge routing, and DDoS mitigation (`delgadologic.tech`) | Transient connecting IP addresses and standard HTTP request headers for edge routing and DDoS protection | Website & API visitors | Global Edge Network / United States | EU-U.S. Data Privacy Framework (DPF), UK Extension, Swiss-U.S. DPF + EU SCCs | [Cloudflare Privacy Policy](https://www.cloudflare.com/privacypolicy/) & [Cloudflare DPA](https://www.cloudflare.com/cloudflare-customer-dpa/) |
| **PayPal, Inc.** (and PayPal (Europe) S.à r.l. et Cie, S.C.A. for EEA/UK transactions) | Independent Payment Processor (PayPal Orders v2 & Webhook verification) | Payer name, PayPal email address, PayPal Order/Capture ID, billing country, and transaction fraud signals | **Pro**, **Extra Seat**, & **Team 10-Pack** purchasers paying via PayPal | United States & Luxembourg (EU) | Binding Corporate Rules (BCRs) + EU SCCs | [PayPal Privacy Statement](https://www.paypal.com/us/legalhub/privacy-full) |
| **Stripe, Inc.** (and Stripe Payments Europe, Limited for EEA/UK transactions) | Independent Payment Processor & Checkout Host (Credit/Debit Cards, Apple Pay, Google Pay) | Cardholder name, billing email, payment card details (PCI-DSS Level 1 tokenized; never seen by DelgadoLogic), billing address, and fraud-prevention signals | **Pro**, **Extra Seat**, & **Team 10-Pack** purchasers paying via Stripe | United States & Ireland (EU) | EU-U.S. Data Privacy Framework (DPF) + EU SCCs | [Stripe Privacy Center](https://stripe.com/privacy) |
| **Google Workspace / Transactional SMTP Relay** (via `nodemailer` TLS 1.3 in Cloud Functions) | Outbound transactional email delivery for license receipts, waitlist confirmations, and support/DSR replies | Recipient email address, order receipt summary, and SMTP delivery logs | License purchasers, waitlist subscribers & support correspondents | United States | EU-U.S. Data Privacy Framework (DPF) + EU SCCs | [Google Workspace Privacy](https://workspace.google.com/terms/dpa_terms.html) |
| **GitHub, Inc.** (a subsidiary of Microsoft Corporation) | Source code hosting, CI/CD automated build runners, and public issue tracking | Public issue reports or pull requests voluntarily submitted by GitHub users (no desktop telemetry or customer license data is stored on GitHub) | Public repository visitors / contributors only | United States | EU-U.S. Data Privacy Framework (DPF) + GitHub DPA | [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) |

---

## 3. Subprocessor Governance & Security Standards

Before engaging any Subprocessor that handles customer or telemetry data, DelgadoLogic verifies that the provider:
1. Executes a binding **Data Processing Addendum (DPA)** incorporating the **2021 European Commission Standard Contractual Clauses (SCCs)** and the **UK International Data Transfer Addendum** (or maintains active certification under the **EU-U.S. Data Privacy Framework**).
2. Maintains independent third-party security certifications (**ISO/IEC 27001**, **SOC 2 Type II**, and **PCI-DSS Level 1** for payment processors).
3. Encrypts all data in transit via **TLS 1.2 / TLS 1.3** and at rest via **AES-256**.
4. Is contractually prohibited from "selling" or "sharing" (for cross-context behavioral advertising under the CCPA/CPRA) any data processed on behalf of DelgadoLogic.

---

## 4. Subprocessor Change Notifications

We update this page whenever a Subprocessor is added, removed, or materially changed. Enterprise, Team 10-Pack, or Pro Edition customers who wish to receive advance email notification prior to the onboarding of a new Subprocessor may subscribe by emailing `privacy@delgadologic.tech` with the subject line **`Subprocessor Notification Subscription`**.
