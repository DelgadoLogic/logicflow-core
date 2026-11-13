# LogicFlow v1.0 — Production Launch Checklist (P0 / P1 / P2)

**Document Version**: 1.1.0  
**Last Updated**: November 13, 2026  
**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA

This checklist tracks every technical, security, legal, and commercial prerequisite required before accepting live public customer traffic for **LogicFlow v1.0** on `https://delgadologic.tech`.

---

## P0 — Launch Blockers (Must Complete Before Public Commercial Release)

### 1. Credential Rotation & Secret Management
- [x] **Scrub Exposed Credentials from Repository Markdown**: Removed plaintext PayPal Client ID, Client Secret, and Webhook ID values from `DELGADOLOGIC_MANIFEST.md`, `walkthrough.md`, and `MasterPlans/DELGADOLOGIC_ROADMAP.md`.
- [ ] **Rotate Live PayPal REST API Credentials**: Log into the PayPal Developer Dashboard (`developer.paypal.com`), immediately revoke/rotate the previously exposed live Client Secret, verify the active Webhook ID in the PayPal dashboard, and store them exclusively in **Google Cloud Secret Manager** (`paypal-client-id`, `paypal-secret`, `paypal-webhook-id`).
- [ ] **Provision Signing & Telemetry Secrets in Secret Manager**: Ensure `license-ed25519-private-key` / `OMNILICENSE_PRIVATE_KEY_PEM`, `lf-ingest-keys` (HMAC wire signing keys for `OmniPulse`), and `lf-admin-token` are populated in Google Cloud Secret Manager and never committed to git.
- [ ] **Git History Rewrite (`git filter-repo` / BFG)**: Before making any repository public or onboarding external contributors, purge historical git commits that contained the old PayPal credentials.

### 2. Corporate, Legal & Tax Compliance
- [x] **Canonical Fact Sheet & 12-Document Legal Suite Authored (`Products/LogicFlow/Docs/`)**:
  - Completed [`Docs/FACTS.md`](FACTS.md), plain-text [`Docs/EULA.txt`](EULA.txt), and all 12 markdown documents in [`Docs/legal/`](legal/README.md) (`eula.md`, `terms.md`, `privacy.md`, `refund.md`, `cookie-notice.md`, `telemetry-disclosure.md`, `third-party-notices.md`, `security-policy.md`, `dmca.md`, `subprocessors.md`, `data-subject-requests.md`, `trademark-and-acceptable-use.md`).
- [ ] **District of Columbia Trade Name Registration (`Form TN-1`)**: Confirm active filing of the trade name **"DelgadoLogic"** under **Delgado Creative Enterprises LLC** with the D.C. Department of Licensing and Consumer Protection (DLCP) Corporations Division (`corponline.dcra.dc.gov`), and calendar the two-year renewal window (April 1 of even-numbered years).
- [ ] **Verify Role Email Routing (`@delgadologic.tech`)**: Confirm that `support@delgadologic.tech`, `privacy@delgadologic.tech`, `legal@delgadologic.tech`, `security@delgadologic.tech`, and `billing@delgadologic.tech` resolve and deliver to monitored inboxes with SPF/DKIM/DMARC enabled.
- [ ] **Set `MAILING_ADDRESS` Environment Parameter in Cloud Functions**: Configure `6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA` in `Website/functions` environment settings so CAN-SPAM compliant waitlist and receipt emails include the required postal footer.

### 3. Cloud Infrastructure & Runtime Deployment
- [ ] **Deploy Cloud Functions on Node.js 22 Runtime (`Website/functions`)**:
  - *Critical Deadline*: Google Cloud Functions / Firebase Functions decommissions Node.js 20 on **October 30, 2026**. Verify `"engines": { "node": "22" }` in `Website/functions/package.json` and deploy all functions (`createCheckoutOrder`, `captureCheckoutOrder`, `handlePayPalWebhook`, `activateLicense`, `activateCommunityLicense`, `validateLicense`, `joinWaitlist`, `submitDataRequest`, `unsubscribe`, `pricingInfo`, `healthCheck`).
- [ ] **Deploy Telemetry Ingestion Service (`Products/LogicFlow/Infrastructure/telemetry-ingest`)**:
  - Run `deploy/deploy.ps1 -ProjectId manuel-portfolio-2026 -Bucket <bucket> -Execute` to deploy Cloud Run service `lf-telemetry-ingest` (`us-central1`, mapped behind `https://api.delgadologic.tech/v1/telemetry/**`), Cloud Run Job `lf-telemetry-digest`, BigQuery dataset `logicflow_telemetry`, and GCS lifecycle rules (`deploy/lifecycle.json`: **90-day raw deletion**, **395-day rollup deletion**).

### 4. Installer Security, Code Signing & Desktop Consent Gates
- [ ] **Authenticode Code Signing (Azure Artifact Signing / OV Certificate)**:
  - Sign `LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`, all `.dll` assemblies, `UninstallLogicFlow.exe`, and `LogicFlowSetup.exe` with a trusted SHA-256 Authenticode certificate + RFC 3161 timestamp (`.\package_and_deploy.ps1 -Sign`) so Windows SmartScreen and Defender ASR do not flag the installer.
- [x] **Verify Native C++ Installer Directory (`%ProgramFiles%\DelgadoLogic\LogicFlow`), ACL Hardening & Embedded EULA**:
  - Confirmed the native Win32 C++ installer (`Installer/src/LogicFlowInstaller.cpp`, producing `LogicFlowSetup.exe` and `UninstallLogicFlow.exe`) installs to `%ProgramFiles%\DelgadoLogic\LogicFlow` (with hardened `LocalSystem` [`NT AUTHORITY\SYSTEM`] + `Administrators` [`BUILTIN\Administrators`] ACLs), displays `Docs\EULA.txt`, registers `LogicFlowAgent.exe` (`%ProgramFiles%\DelgadoLogic\LogicFlow\Agent\LogicFlowAgent.exe`), and writes diagnostic install logs to `%ProgramData%\DelgadoLogic\LogicFlow\logs\install.log`.
- [x] **Verify First-Run Edition & Telemetry Consent Window (`ConsentWindow`)**:
  - Confirmed `LogicFlow.exe` sends no telemetry on splash/startup prior to consent, defaults to `ConsentLevel.None`, presents the 3-tier choice (*Free* vs. *Community* vs. *Pro*), and displays the separate optional `Extended` baseline checkbox for users in the **EU, EEA, UK, and Switzerland**.

---

## P1 — High-Priority Launch Verification (Complete During Launch Week)

### 5. Checkout, Fulfillment & EU/UK Consumer Compliance
- [ ] **End-to-End Live Checkout & Activation Verification**:
  - Test live checkout for `LF-PRO` ($19.99 launch promo / $29.99 regular, 3 devices), `LF-SEAT` ($9.99, +1 device), and `LF-TEAM10` ($149.00, 10 devices); verify webhook signature check, Firestore `sales` & `licenses` persistence, receipt email delivery, and desktop activation before flipping `CHECKOUT_ENABLED = true` in `Website/site/src/config/site.js`.
- [x] **EU/EEA/UK Immediate Digital Delivery Waiver Checkbox (Directive 2011/83/EU Art. 16(m))**:
  - Verified the checkout UI requires an unticked checkbox consenting to immediate digital license delivery and waiving the 14-day statutory cooling-off period while preserving our **60-day no-questions-asked money-back guarantee**.
- [x] **Build & Verify Public Legal Pages & `.well-known/security.txt` in `Website/site`**:
  - Built and verified all 12 legal routes (`/legal/*`) and `public/.well-known/security.txt` (`16/16` website tests pass, `28/28` Cloud Functions tests pass on Node.js `22`, `0` ESLint warnings).

### 6. Build & Automated Test Verification
- [x] **Clean Release Build & Test Suite Sign-Off**:
  - Verified `dotnet build Products/LogicFlow/LogicFlow.sln -c Release` (`0` errors) and full `dotnet test` (`1,839` passed across `54` test files, `0` failed, `0` skipped), including `GemmaAiEngine` (`gemma-4-E2B-it`), `LogicFlow.VoiceAgent` (shipped in v1.0 via `lf voice`), `58` CLI subcommands (`61` routes + `6` aliases), dual Ed25519 + RSA-2048 `OmniLicense`, `BrowserPrivacyCleanerEngine`, `BootPerformanceAnalyzer`, `DiskSpaceAnalyzer` squarified treemap, and `SystemRestoreEngine` VSS explorer/restore.
- [x] **Generate & Synchronize `release-manifest.json` & `downloads-manifest.json`**:
  - Synchronized `LogicFlowSetup.exe` (`174,744,576` bytes / `166.6 MB`, SHA-256 `7FC3FAC70FBA7964C9A87038A160FB6D20E59D85F37623E7E2CFB02B8B487F74`) across `Products/LogicFlow/dist/release-manifest.json`, `Website/site/public/downloads-manifest.json`, and `Website/site/dist/`.


---

## P2 — Post-Launch v1.1 Enhancements (First 30–60 Days Post-Launch)

- [ ] **Merchant of Record (MoR) Onboarding for Automated Global VAT/GST**: Submit LogicFlow v1.0 to Polar.sh or Lemon Squeezy for manual underwriting review once initial PayPal/Stripe transaction history demonstrates a `< 0.2%` dispute rate.
- [x] **Granular Browser SQLite Cleaner (v1.1)**: Added `BrowserPrivacyCleanerEngine` with closed-browser SQLite `VACUUM` (`winsqlite3.dll`) and selective per-domain cookie whitelist pruning for Chromium and Firefox profiles (`lf toolbox browser-clean`).
- [x] **Interactive Disk Space Treemap UI (v1.1)**: Added `DiskSpaceAnalyzer.ComputeTreemapLayout` squarified block map and interactive drill-down canvas in `PageHyperStore` (`lf toolbox disk-analyze`).
- [x] **Boot-Time Critical Path Flamegraph & Diagnostics (v1.1)**: Added `BootPerformanceAnalyzer` (`Event IDs 100–110` + fallback synthesis) in `PageGuardian` (`lf sys boot-analyze`).
- [x] **VSS Snapshot File Browser & Single-File Restore (v1.1)**: Added `SystemRestoreEngine` VSS shadow copy directory browser, live-disk diff comparison, and single-file restore in `PageLazarus` (`lf sys vss-list|vss-browse|vss-restore`).
- [x] **64-Bit Packaging & `win-x86` Retirement**: Shipped `win-x64` primary production build (`win-arm64` optional cross-target; `win-x86` 32-bit retired per `FACTS.md` §1) via `package_and_deploy.ps1`.
- [x] **WPF GUI `.lfc` Archive Pack & Unpack (`PageHyperStore`)**: Wired both `LfcWriter` (`Pack Directory to .lfc`) and `LfcReader` (`Unpack .lfc Archive`) in `MainWindow.xaml` and `HyperStoreViewModels.cs`.
- [x] **Calibrate Hardware-Sensitive Throughput & Latency Tests**: Stabilized `HyperStoreCoreEngineTests`, `HyperStoreE2ETests`, and `GameCompressionEngineEmpiricalStressTests` (`1,839/1,839` passing).


