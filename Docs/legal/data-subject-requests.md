# Data Subject Access & Erasure Request Procedure (DSAR Guide)

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Data Controller**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Privacy Contact**: `privacy@delgadologic.tech` (routes to `support@delgadologic.tech`)  
**Self-Service Portal**: <https://delgadologic.tech/data-requests>

---

## 1. Overview & Supported Privacy Rights

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic** ("**DelgadoLogic**," "**we**," "**us**," or "**our**") provides every LogicFlow user and website visitor—regardless of residency—with clear, instant self-service and email-assisted ways to exercise their statutory data protection rights under:
- **EU & UK General Data Protection Regulation (GDPR)** (Articles 7(3), 15–22);
- **California Consumer Privacy Act / California Privacy Rights Act (CCPA/CPRA)** (Cal. Civ. Code §§ 1798.105–1798.125);
- **Applicable U.S. State Comprehensive Privacy Laws** (including Virginia VCDPA, Colorado CPA, Connecticut CTDPA, Texas TDPSA, Oregon OCPA, Maryland MODPA, and D.C. CPPA);
- **Brazil LGPD**, **Canada PIPEDA**, and **Australia Privacy Act**.

### 1.1 Summary of Your Rights

| Right | Statutory Basis | What It Means for LogicFlow Users |
| :--- | :--- | :--- |
| **Right to Withdraw Consent / Opt Out of Telemetry** | GDPR Art. 7(3); ePrivacy Art. 5(3); CCPA § 1798.125 | You can immediately stop pseudonymous diagnostic telemetry in **Settings → Security & Privacy**. Local queued events in `%LOCALAPPDATA%\LogicFlow\Pulse\event_queue.jsonl` are wiped immediately. |
| **Right to Erasure / Deletion ("Right to Be Forgotten")** | GDPR Art. 17; CCPA § 1798.105 | You can trigger immediate server-side deletion of all telemetry linked to your `installId` via **Settings → Security & Privacy → Delete my data**, `POST /v1/telemetry/delete`, or `/data-requests`. |
| **Right of Access / Right to Know** | GDPR Art. 15; CCPA §§ 1798.100, 1798.110 | You can view what is sent locally via **View what is sent** (`PulseClient.BuildPreview()`) and request a copy of all records associated with your `installId` or checkout email address. |
| **Right to Rectification / Correction** | GDPR Art. 16; CCPA § 1798.106 | You can request correction of an inaccurate billing email address or license registration record. |
| **Right to Data Portability** | GDPR Art. 20; CCPA § 1798.100(d) | You receive your exported records in a structured, machine-readable **JSON** format. |
| **Right to Restriction & Right to Object** | GDPR Arts. 18, 21 | You can request that we restrict processing of your data during a dispute or object to processing based on legitimate interests. |
| **Right to Non-Discrimination** | CCPA § 1798.125 | We never penalize you for exercising a privacy right (see our [Privacy Policy](./privacy.md) Section 9 for the Community Edition telemetry condition disclosure). |

---

## 2. Instant Self-Service Telemetry Controls (No Email Required)

Because LogicFlow stores your consent record and pseudonymous `installId` locally on your Windows PC (`%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`), you can inspect, rotate, or permanently erase your telemetry data yourself in seconds:

### 2.1 View What Is Sent & Inspect Local Queue
1. Open **LogicFlow** → **Settings → Security & Privacy** → click **View what is sent**.
2. Or open File Explorer and inspect `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json`, `event_queue.jsonl`, and `system_baseline.json` in any text editor.

### 2.2 One-Click "Delete My Data" (Client + Server Erasure)
1. Open **LogicFlow** → **Settings → Security & Privacy** → click **Delete my data** (`PulseClient.DeleteMyDataAsync()`).
2. **What Happens Immediately on Your PC**:
   - Deletes `event_queue.jsonl`, `system_baseline.json`, and local telemetry state;
   - Retires your current `installId`.
3. **What Happens Immediately on Our Server (`POST https://api.delgadologic.tech/v1/telemetry/delete`)**:
   - Writes an irreversible cryptographic tombstone keyed by `sha256(installId)` (`GCS v1/erasures/<sha256>.json` — the raw `installId` is never stored in the tombstone);
   - Returns HTTP `410 Gone` if any client ever attempts to send another event with that `installId`;
   - Drops any buffered events in volatile server memory;
   - Immediately excludes that `installId` from all BigQuery views and daily digests; and
   - Rewrites raw GCS NDJSON partitions in the background to strip historical rows matching that `installId`.

---

## 3. Submitting a Request via Web Portal or Email

You can also submit a Data Subject Request (Erasure, Access/Export, Correction, or Waitlist Unsubscribe) via:
1. **Web Portal**: <https://delgadologic.tech/data-requests> (calls our `submitDataRequest` endpoint); or
2. **Email**: `privacy@delgadologic.tech` (Subject Line: `Privacy Request — [Erasure / Access / Correction / Portability]`).

### 3.1 How to Locate Your Identifier Depending on Your Edition

Because DelgadoLogic minimizes data collection and never attaches your name or email address to desktop telemetry events, please provide the identifier that matches the records you want us to locate:

#### A. For Telemetry Records (Community Edition or Opt-In Pro Users)
We only know telemetry events by your random pseudonymous **Install ID (`installId`)**:
1. Open **LogicFlow → Settings → Security & Privacy → View what is sent** to copy your `installId`, OR
2. Open `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json` in Notepad and copy the `"InstallId"` (`installId`) string (e.g., `"9f02a7b4c8e14d3a9012f5e6d7c8b9a0"`).

#### B. For Commercial License, Order, or Waitlist Records
1. Provide the **email address** used at checkout (or on the waitlist form), OR
2. Provide your **Order ID / Capture ID** (`OrderId` in your receipt or `license.lic`).

---

## 4. Identity Verification & Fraud Prevention

To protect your data against unauthorized disclosure or malicious deletion by third parties:
- **Telemetry Requests (`installId`)**: Because `installId` is a high-entropy 128-bit random token stored only in your local `%LOCALAPPDATA%\LogicFlow\Pulse\consent.json` file, possession of the exact `installId` is sufficient verification to erase or export matching pseudonymous telemetry records. **We will never ask you to provide a government ID to delete telemetry records.**
- **Commercial License Requests (`sales` / `licenses`)**: We verify ownership by confirming that the request originates from the registered purchase email address via a one-time verification reply.
- **Authorized Agents (CCPA/CPRA)**: If you submit a request through an authorized agent (Cal. Civ. Code § 1798.130(a)(3)), we require written authorization signed by you and direct email confirmation from the address on file (for commercial records).

---

## 5. Statutory Response Timelines & Retention Exceptions

| Milestone | Statutory Deadline |
| :--- | :--- |
| **In-App `Delete my data` / `POST /v1/telemetry/delete`** | **Immediate** logical erasure (`sha256(installId)` tombstone) + background partition rewrite |
| **Initial Receipt Acknowledgment (Email / Web DSR)** | Within **48 business hours** (statutory max: 10 business days) |
| **Substantive Completion (GDPR / UK GDPR)** | Within **30 calendar days** (extendable by up to 60 days for complex requests with written notice under GDPR Art. 12(3)) |
| **Substantive Completion (CCPA/CPRA & U.S. State Laws)** | Within **45 calendar days** (extendable by up to 45 days with written notice under Cal. Civ. Code § 1798.130(a)(2)) |

### 5.1 Statutory Exceptions to Deletion (Tax, Accounting & Active Licenses)
- **Telemetry Data**: Raw telemetry events are purged immediately upon a `/delete` request and are automatically deleted after **90 calendar days** even without a request.
- **Commercial Accounting & Tax Records**: Under **GDPR Article 17(3)(b)** and **California Civil Code § 1798.105(d)(8)**, we are legally required to retain core financial transaction records (invoice amount, date, tax jurisdiction, and payment processor reference) for **7 years** to comply with U.S. federal and District of Columbia tax audit obligations.

---

## 6. Right to Appeal & Supervisory Authorities

If we decline to take action on your request (for example, due to a statutory tax retention obligation), we will explain our reasoning in writing.
- **Internal Appeal**: You may appeal any decision by replying to our response or emailing `legal@delgadologic.tech` with the subject line **`Privacy Appeal`**. We will review and respond to your appeal within **30 calendar days**.
- **Regulatory Escalation**:
  - **EEA Residents**: Your national Data Protection Authority ([edpb.europa.eu](https://www.edpb.europa.eu/about-edpb/about-edpb/members_en)).
  - **UK Residents**: Information Commissioner's Office ([ico.org.uk](https://ico.org.uk/)).
  - **U.S. / D.C. / California Residents**: Office of the Attorney General for the District of Columbia ([oag.dc.gov](https://oag.dc.gov/)) or the California Privacy Protection Agency ([cppa.ca.gov](https://cppa.ca.gov/)).

---

## 7. Contact Information

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Privacy: `privacy@delgadologic.tech`  
Legal: `legal@delgadologic.tech`
