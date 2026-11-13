# LogicFlow — Legal & Compliance Documentation Suite

**Licensor / Data Controller**: `Delgado Creative Enterprises LLC d/b/a DelgadoLogic`  
**Jurisdiction**: District of Columbia, United States of America  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Last Updated**: October 13, 2026 (EST)

> [!WARNING]
> **Attorney Review Notice**: These legal and regulatory compliance documents have been drafted in accordance with 2026 US/District of Columbia contract and consumer protection law (DC CPPA, D.C. Official Code §§ 28-3901 *et seq.*), GDPR / UK GDPR, the EU ePrivacy Directive (Art. 5(3) / EDPB Guidelines 2/2023), CCPA/CPRA (Cal. Civ. Code § 1798.100 *et seq.*), the amended FTC COPPA Rule (effective April 22, 2026), the EU Consumer Rights Directive (2011/83/EU Art. 16(m)), the EU Software Directive (2009/24/EC Art. 6), and the EU Cyber Resilience Act (Regulation (EU) 2024/2847 Art. 14). **They do not constitute formal legal advice. Review and sign-off by a licensed District of Columbia commercial/privacy attorney is strongly recommended prior to commercial public release.**

---

## Document Inventory

| File | Document Title | Primary Scope & Applicable Regulations |
| :--- | :--- | :--- |
| [`eula.md`](./eula.md) / [`../EULA.txt`](../EULA.txt) | **End User License Agreement (EULA)** | Software license grant across `Free`, `Community`, `Pro`, and `Team` editions; v1.x update scope; EU Software Directive Art. 6 interoperability carve-out; system access disclosures; warranties & liability caps; DC governing law. |
| [`terms.md`](./terms.md) | **Terms of Service & Conditions of Sale** | Website usage (`delgadologic.tech`), commercial checkout terms, pricing, license seat rules, age requirement (16+), EU/UK digital delivery terms, dispute resolution. |
| [`privacy.md`](./privacy.md) | **Privacy Policy** | Comprehensive GDPR / UK GDPR / CCPA-CPRA / COPPA privacy notice covering website, licensing/commerce, and desktop software telemetry, category-level retention schedules, international transfers, and statutory rights. |
| [`refund.md`](./refund.md) | **Refund & Withdrawal Policy** | **60-day no-questions-asked money-back guarantee**; EU/EEA/UK 14-day statutory cooling-off waiver checkbox wording (Directive 2011/83/EU Art. 16(m)) with preservation of the 60-day contractual refund right. |
| [`telemetry-disclosure.md`](./telemetry-disclosure.md) | **Telemetry & Diagnostics Technical Disclosure** | Granular technical specification of `None`, `Standard`, and `Extended` pseudonymous telemetry levels, first-run consent UX, EU/EEA/UK/CH separate `Extended` checkbox, dual-layer PII scrubbing, `installId` rotation, and IT Group Policy opt-out keys. |
| [`cookie-notice.md`](./cookie-notice.md) | **Cookie & Local Storage Notice** | ePrivacy Directive Art. 5(3) disclosure of strictly necessary web storage, authentication tokens, self-hosted assets, and desktop local configuration files (`consent.json`, `license_token.json`). |
| [`third-party-notices.md`](./third-party-notices.md) | **Third-Party Open-Source Software & Font Notices** | Complete attribution and license notices for all NuGet (`.csproj`), npm (`package.json`), and typography (`Inter`, `Outfit`, `JetBrains Mono`, `Font Awesome`) dependencies. |
| [`security-policy.md`](./security-policy.md) | **Security & Coordinated Vulnerability Disclosure Policy** | PSIRT reporting process (`security@delgadologic.tech`), safe harbor for good-faith security researchers, and **EU Cyber Resilience Act (CRA)** Article 14 reporting compliance (24h / 72h / 14d ENISA SRP workflow). |
| [`dmca.md`](./dmca.md) | **DMCA & Copyright Policy** | 17 U.S.C. § 512 takedown notice and counter-notice procedures and designated copyright agent contact (`legal@delgadologic.tech`). |
| [`subprocessors.md`](./subprocessors.md) | **Subprocessors & Infrastructure Providers** | Transparent inventory of cloud hosting, database, payment processing, and transactional email subprocessors (Google Cloud Platform, Firebase, Cloudflare, PayPal, Stripe). |
| [`data-subject-requests.md`](./data-subject-requests.md) | **Data Subject Access & Erasure Request Procedure** | Operational guide for exercising GDPR Articles 15–22 and CCPA/CPRA rights via in-app *Delete my data*, `POST /v1/telemetry/delete`, `/data-requests`, and `privacy@delgadologic.tech`. |
| [`trademark-and-acceptable-use.md`](./trademark-and-acceptable-use.md) | **Trademark Notice & Acceptable Use Policy (AUP)** | DelgadoLogic brand guidelines, third-party nominative fair-use disclaimers (Microsoft, Windows, Steam, Epic Games, GOG, NVIDIA, AMD, Intel), and prohibited uses of LogicFlow. |

---

## Synchronization Requirement

1. **`eula.md` and `../EULA.txt`**: The plain-text file `Products/LogicFlow/Docs/EULA.txt` is embedded directly into `LogicFlow.Dashboard.dll` as an `EmbeddedResource` (`LogicalName="EULA.txt"`), and its SHA-256 hash is recorded in `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json` when a user accepts the EULA on first run. Whenever `eula.md` is updated, `../EULA.txt` must be updated in lockstep.
2. **Canonical Facts**: All metrics, pricing, addresses, retention periods, and endpoints in this folder are governed by [`../FACTS.md`](../FACTS.md).
