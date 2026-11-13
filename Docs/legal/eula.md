# END USER LICENSE AGREEMENT (EULA)

**LogicFlow — Windows System Optimization, Security Hardening, Storage Deduplication & Data Recovery Suite**  
**Effective Date / Last Updated**: October 13, 2026  
**Version**: 1.0 (v1.x Release Series)  
**Licensor**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic ("DelgadoLogic," "Company," "we," "us," or "our")

---

**IMPORTANT — READ CAREFULLY**: This End User License Agreement ("Agreement" or "EULA") is a binding legal contract between you (either an individual natural person at least sixteen (16) years of age or a single legal entity, referred to as "You" or "User") and **Delgado Creative Enterprises LLC d/b/a DelgadoLogic**, a District of Columbia limited liability company located at 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA, governing your download, installation, activation, and use of the **LogicFlow** desktop software application, command-line interface (`lf.exe`), background service (`LogicFlowAgent.exe`), associated libraries, update manifests, and documentation (collectively, the "Software").

BY DOWNLOADING, INSTALLING, ACTIVATING, COPYING, CLICKING "ACCEPT," OR OTHERWISE USING THE SOFTWARE, YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTOOD THIS AGREEMENT AND AGREE TO BE BOUND BY ITS TERMS. IF YOU DO NOT AGREE TO THIS AGREEMENT, OR IF YOU ARE UNDER SIXTEEN (16) YEARS OF AGE, DO NOT INSTALL OR USE THE SOFTWARE.

---

## 1. Eligibility & Age Requirement

You must be at least **sixteen (16) years of age** to download, install, purchase, or use the Software. If you are entering into this Agreement on behalf of a company, organization, or other legal entity (permitted only under a Pro or Team 10-Pack license), you represent and warrant that you have full legal authority to bind that entity to this Agreement. The Software is not directed to children under the age of thirteen (13).

---

## 2. License Grant & Edition Tiers

Subject to your continuous compliance with this Agreement (including payment of applicable license fees or satisfaction of applicable edition conditions), DelgadoLogic grants you a limited, revocable, non-exclusive, non-transferable, non-sublicensable license to install and execute the object-code version of the Software on devices running a supported 64-bit Microsoft Windows 10 (Version 1607 / Build 14393 or newer) or Windows 11 operating system that you own or lawfully control, strictly in accordance with the edition tier activated on your installation:

### 2.1 LogicFlow Free Edition ($0)
* **Device Limit**: One (1) personal computer.
* **Permitted Use**: Personal, non-commercial evaluation and diagnostic use only.
* **Functional Scope**: Read-only diagnostic scanning and system health preview across Software modules. Automated repairs, background service automation, and deep recovery are not enabled.
* **Telemetry**: None (`ConsentLevel.None`). No diagnostic or telemetry data is queued or transmitted to DelgadoLogic.

### 2.2 LogicFlow Community Edition ($0 — Telemetry Conditioned)
* **Device Limit**: One (1) personal computer.
* **Permitted Use**: Personal, non-commercial household use only. Commercial, professional, managed service provider (MSP), or enterprise use is strictly prohibited under the Community Edition.
* **Functional Scope**: Unlocks interactive core cleanup, system optimization, registry repair with automatic snapshot backup, Windows Overlay Filter (WOF) game compression, and security hardening controls. Excludes Pro-only background automation and advanced Lazarus deep sector/MFT recovery.
* **Contractual Telemetry Condition**: The Community Edition is provided at $0 in exchange for your agreement to share pseudonymous diagnostic telemetry with DelgadoLogic to help identify Windows update regressions, software crashes, and hardware driver issues:
  * **Standard Telemetry (Required across all regions for Community Edition)**: Scrubbed crash and error reports, aggregate scan metrics, and pseudonymous feature usage counts linked to a random, rotatable installation identifier (`installId`).
  * **Extended System Baseline**: Includes a one-time system configuration baseline and weekly driver/health digest (OS build, CPU/RAM/GPU class, BIOS version, running service names/states, PnP driver versions/error codes, and installed Windows Update KB numbers) used to power the crowd-sourced driver compatibility index. For users outside the European Union (EU), European Economic Area (EEA), United Kingdom (UK), and Switzerland (CH), Extended telemetry is included in the Community Edition condition. For users located in the **EU, EEA, UK, or CH** (determined via your local Windows region setting and confirmed on first run without IP geolocation), only **Standard** telemetry is required for the Community Edition, and **Extended** baseline sharing is presented as a separate, optional opt-in checkbox.
  * **Declining or Withdrawing**: You may decline or withdraw from telemetry sharing at any time via the first-run screen or **Settings → Security & Privacy**. If you decline or withdraw telemetry sharing on a Community installation (and do not hold an active Pro or Team license), your installation automatically transitions to the **LogicFlow Free Edition** (scan-only preview with no telemetry).

### 2.3 LogicFlow Pro Edition ($29.99 One-Time; $19.99 Launch Promotional Price)
* **Device Limit**: Up to **three (3) computers** per Pro license key, plus any **Extra Seat Add-Ons** ($9.99 one-time per additional seat) purchased for that license.
* **Permitted Use**: Both personal and commercial/professional use are permitted on licensed devices.
* **Functional Scope**: Unlocks all Software modules and Pro capabilities, including:
  * **Background Automation**: Autonomous scheduled scanning and maintenance via `LogicFlowAgent`, HyperStore autonomous background deduplication worker with Full-Screen Game Guard, and Game Vault automatic decay recompaction.
  * **Advanced Data Recovery**: Lazarus deep raw-sector file carving (25+ signatures) and NTFS Master File Table (MFT) record recovery.
  * **Priority Support**: 24-business-hour priority email support (`support@delgadologic.tech`).
* **Telemetry**: **Optional and OFF by default (`ConsentLevel.None`)**. Activating a Pro license automatically resets diagnostic sharing to `None` unless you affirmatively opt in via **Settings → Security & Privacy**.

### 2.4 LogicFlow Team 10-Pack ($149.00 One-Time)
* **Device Limit**: Up to **ten (10) computers** within your business, organization, or enterprise.
* **Permitted Use**: Commercial, professional, and internal enterprise fleet deployment, including headless CLI execution (`lf.exe --json`). Does not grant a right to resell or redistribute the Software to unaffiliated third parties unless covered by a separate written MSP agreement.
* **Telemetry**: **Optional and OFF by default**, with support for machine-wide Group Policy / Registry suppression (`HKLM\SOFTWARE\Policies\DelgadoLogic\LogicFlow\TelemetryDisabled = 1`).

---

## 3. Scope of "Lifetime" v1.x Updates & Major Upgrades

1. **v1.x Update Entitlement**: A one-time purchase of LogicFlow Pro, an Extra Seat Add-On, or a Team 10-Pack grants a perpetual license to use the v1.x major release series of the Software (`v1.0` through `v1.x`) and includes all minor feature updates, bug fixes, security patches, and signature updates released during the commercial lifecycle of the **v1.x major version** at no additional recurring cost.
2. **Future Major Versions (v2.0+)**: "Lifetime" refers to the lifetime of the **LogicFlow v1.x major release series**. If DelgadoLogic releases a substantially re-architected major version in the future (such as `LogicFlow v2.0`), existing Pro license holders may continue using their licensed `v1.x` build indefinitely or optionally upgrade to `v2.0` at a discounted upgrade price (anticipated at approximately `$14.99` USD).
3. **Cryptographic Update Verification**: When automatic update checks are enabled, the Software polls `https://api.delgadologic.tech/v1/update/logicflow/stable` and verifies update packages using SHA-256 hashes and Ed25519 digital signatures prior to installation. You may disable automatic update checks in **Settings**.

---

## 4. License Activation, Hardware Binding & Anti-Piracy

1. **Hardware Fingerprint (`HWID`)**: To enforce seat limits on paid Pro and Team licenses, the Software computes a one-way cryptographic SHA-256 hash of four local Windows Management Instrumentation (WMI) hardware identifiers (`Win32_Processor.ProcessorId`, `Win32_BaseBoard.SerialNumber`, `Win32_BIOS.SerialNumber`, and `Win32_DiskDrive.SerialNumber`), encoded as a 44-character Base64 string. Raw hardware serial numbers never leave your device.
2. **Offline RSA-2048 Tokens**: Upon activation via `https://api.delgadologic.tech`, our licensing service issues an RSA-2048 digitally signed license token (`license_token.json` / `license.lic`) bound to your device's `HWID`, allowing subsequent offline verification without continuous internet connectivity.
3. **Strict Separation from Telemetry**: Your license `HWID` is used strictly for license enforcement and seat management and is never combined with, substituted for, or linked to your pseudonymous telemetry `installId`.

---

## 5. Restrictions & Mandatory Statutory Exceptions

### 5.1 General Restrictions
Except as expressly permitted by this Agreement or by mandatory applicable law, you may **not**:
1. Copy, distribute, publicly display, resell, rent, lease, lend, or commercialize the Software, license keys, or activation tokens;
2. Reverse engineer, decompile, disassemble, or attempt to derive the source code, underlying algorithms, or cryptographic signing keys of the Software;
3. Modify, translate, adapt, patch, or create derivative works based upon the Software;
4. Bypass, disable, tamper with, or circumvent any license validation, seat counter, edition gate, or cryptographic verification mechanism in the Software;
5. Remove, obscure, or alter any copyright, trademark, or third-party attribution notices included in the Software; or
6. Use the Software to develop a competing commercial system optimization, security hardening, or storage deduplication product.

### 5.2 European Union & UK Statutory Interoperability Carve-Out
**Nothing in Section 5.1 restricts any non-waivable rights you hold under applicable law.** Specifically, if you are a lawful user located in the European Economic Area (EEA) or the United Kingdom, nothing in this Agreement prevents you from observing, studying, or testing the functioning of the Software in accordance with **Article 5(3)** of Directive 2009/24/EC (the EU Software Directive), or from performing decompilation strictly to the extent indispensable to obtain the information necessary to achieve the interoperability of an independently created computer program with other programs in accordance with and subject to the conditions of **Article 6 of Directive 2009/24/EC** (and equivalent UK copyright law).

---

## 6. System Access, Administrative Privileges & Operational Risk Disclosures

The Software is an advanced system utility that interacts directly with the Microsoft Windows operating system, filesystem drivers, Windows Registry, physical storage devices, and security subsystem. By installing and executing the Software, you acknowledge and authorize the following operations when initiated by you (or by Pro scheduled automation you configure):

1. **Administrator Elevation**: The Software requires Windows Administrator privileges (`requireAdministrator`) to query S.M.A.R.T. disk health, modify system-wide registry keys, harden Microsoft Defender policies, compress files via the Windows Overlay Filter (`wofutil.dll`), deduplicate extents, and scan raw disk sectors.
2. **Windows Registry Modifications & Automatic Backups**: Before applying registry repairs or system tweaks, the Software generates timestamped `.reg` backup snapshots stored locally in `%LOCALAPPDATA%\LogicFlow\RegistryBackups`. However, modifying the Windows Registry carries inherent risks. You are responsible for reviewing flagged items before applying repairs and for maintaining independent system backups.
3. **HyperStore Deduplication & Game Compression**: HyperStore (`LogicFlow.Storage.Engine` / `VolumeAwareDeduplicator`) uses ReFS block cloning (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`), NTFS hard links (`CreateHardLinkW`), `.lfc` container archiving, and Windows Overlay Filter (`FSCTL_SET_EXTERNAL_BACKING`) compression. While mutable user document extensions are excluded by default unless overridden (`--allow-mutable`), you should never run live deduplication or compression on volumes experiencing hardware faults or without current backups.
4. **Lazarus Data Recovery Disclaimer**: Data recovery (`LogicFlow.Lazarus`) reads raw physical sectors (`\\.\PhysicalDriveX`) and NTFS Master File Table (`MFT`) records. **DATA RECOVERY IS NOT GUARANTEED.** Once disk sectors are overwritten by the operating system or SSD TRIM/garbage collection, files cannot be recovered by any software. Never write recovered files back to the same drive from which you are recovering data.
5. **Security Hardening & Not Antivirus Notice**: `LogicFlow.Sentinel` configures native Microsoft Defender Attack Surface Reduction (ASR) rules, Controlled Folder Access, hosts-file protections, and persistence audits. **THE SOFTWARE IS A SECURITY HARDENING AND DIAGNOSTIC CONFIGURATION TOOL, NOT A REPLACEMENT FOR REAL-TIME ANTIVIRUS OR ENDPOINT DETECTION AND RESPONSE (EDR) SOFTWARE.** Enabling strict ASR rules or disabling system services may block certain macros, installers, or legacy applications until reverted.
6. **Background Service (`LogicFlowAgent`)**: The installer registers the `LogicFlowAgent` Windows service and logon tray task to support system health monitoring and update checks. You may disable startup execution or stop the background service at any time via Windows Services (`services.msc`) or the Software's **Settings** view.

---

## 7. Refund Policy & EU/UK Right of Withdrawal

1. **60-Day Contractual Money-Back Guarantee**: If you purchase LogicFlow Pro, an Extra Seat Add-On, or a Team 10-Pack directly from DelgadoLogic (or our authorized Merchant of Record) and are dissatisfied for any reason, you may request a **full, no-questions-asked refund within sixty (60) calendar days** of your original purchase date by contacting `billing@delgadologic.tech` or `support@delgadologic.tech` with your Order ID or purchase email. Upon refund issuance, your license token and activated seats are immediately revoked, and you must cease using paid features.
2. **EU/EEA/UK 14-Day Statutory Right of Withdrawal**: Under the EU Consumer Rights Directive (2011/83/EU, Article 16(m)) and the UK Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013, consumers in the EU, EEA, and UK ordinarily have a fourteen (14) day statutory cooling-off period to withdraw from a distance contract unless they expressly consent to immediate performance of digital content delivery and acknowledge the loss of the statutory withdrawal right. Even when you provide that express consent at checkout to receive your license key immediately, **DelgadoLogic voluntarily honors our broader 60-day contractual money-back guarantee for all EU, EEA, and UK consumers.** See our full [Refund Policy](./refund.md) for details.

---

## 8. Intellectual Property, Open-Source Components & Feedback

1. **Ownership**: The Software is licensed, not sold. Delgado Creative Enterprises LLC d/b/a DelgadoLogic retains all right, title, and interest in and to the Software, the `DelgadoLogic` and `LogicFlow` trademarks, logos, visual interfaces, and all associated intellectual property rights worldwide.
2. **Third-Party Open-Source Software**: The Software incorporates third-party open-source libraries and fonts governed by their respective licenses (including MIT, Apache-2.0, BSD, and SIL Open Font License 1.1), as detailed in [`third-party-notices.md`](./third-party-notices.md). To the extent required by any applicable open-source license, the terms of that open-source license govern your use of the corresponding component in lieu of this Agreement.
3. **Feedback License**: If you voluntarily submit bug reports, feature suggestions, or usability feedback to DelgadoLogic (excluding pseudonymous telemetry governed by our Privacy Policy), you grant DelgadoLogic a perpetual, irrevocable, worldwide, royalty-free license to use and incorporate such feedback into our products without compensation or attribution.

---

## 9. Disclaimer of Warranties

TO THE MAXIMUM EXTENT PERMITTED BY MANDATORY APPLICABLE LAW, THE SOFTWARE AND ALL RELATED SERVICES ARE PROVIDED **"AS IS"** AND **"AS AVAILABLE,"** WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND. DELGADOLOGIC EXPRESSLY DISCLAIMS ALL WARRANTIES, WHETHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, QUIET ENJOYMENT, AND ACCURACY.

DELGADOLOGIC DOES NOT WARRANT THAT: (A) THE SOFTWARE WILL MEET YOUR SPECIFIC REQUIREMENTS; (B) THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED, ERROR-FREE, OR FREE OF FALSE POSITIVES; (C) ANY DELETED, CORRUPTED, OR LOST FILES WILL BE RECOVERABLE VIA LAZARUS; OR (D) REGISTRY, DRIVER, STORAGE DEDUPLICATION, OR SECURITY HARDENING OPERATIONS WILL NOT AFFECT THIRD-PARTY APPLICATION COMPATIBILITY OR SYSTEM STABILITY.

**Statutory Consumer Rights Carve-Out**: Some jurisdictions (including the European Union, the United Kingdom, Australia, and certain US states) do not allow the exclusion of statutory consumer guarantees or implied warranties. If you are a consumer protected by such mandatory laws, the exclusions above apply only to the extent permitted by your local law, and nothing in this Agreement affects your non-waivable statutory rights (including statutory conformity guarantees for digital content under EU Directive (EU) 2019/770 or the UK Consumer Rights Act 2015).

---

## 10. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY MANDATORY APPLICABLE LAW:

1. **Exclusion of Consequential Damages**: IN NO EVENT SHALL DELGADO CREATIVE ENTERPRISES LLC D/B/A DELGADOLOGIC, ITS PRINCIPAL, AFFILIATES, LICENSORS, OR SUPPLIERS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, CONSEQUENTIAL, SPECIAL, EXEMPLARY, OR PUNITIVE DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF DATA, CORRUPTION OF FILES OR STORAGE VOLUMES, SYSTEM DOWNTIME, LOSS OF PROFITS, BUSINESS INTERRUPTION, OR COST OF PROCUREMENT OF SUBSTITUTE SOFTWARE) ARISING OUT OF OR RELATING TO THE USE OF OR INABILITY TO USE THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
2. **Aggregate Liability Cap**: DELGADOLOGIC'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT OR THE SOFTWARE, WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, OR OTHERWISE, SHALL NOT EXCEED THE GREATER OF: (A) THE ACTUAL AMOUNT PAID BY YOU FOR THE SOFTWARE LICENSE IN THE TWELVE (12) MONTHS IMMEDIATELY PRECEDING THE EVENT GIVING RISE TO LIABILITY; OR (B) **THIRTY UNITED STATES DOLLARS ($30.00 USD)**.
3. **Mandatory Exceptions**: Nothing in this Agreement limits or excludes liability for death or personal injury caused by negligence, fraud or fraudulent misrepresentation, willful misconduct, or any other liability that cannot lawfully be excluded or limited under applicable law (including the District of Columbia Consumer Protection Procedures Act, D.C. Official Code §§ 28-3901 *et seq.*).

---

## 11. Export Controls, Sanctions & U.S. Government End Users

1. **Export Compliance**: The Software incorporates cryptographic functionality (including RSA-2048, Ed25519, BLAKE3, and SHA-256) and is subject to United States export control and economic sanctions laws, including the Export Administration Regulations (EAR) administered by the U.S. Department of Commerce and sanctions regulations administered by the U.S. Treasury Department's Office of Foreign Assets Control (OFAC). You represent and warrant that you are not located in, organized under the laws of, or ordinarily resident in any country or territory subject to comprehensive U.S. embargoes, and that you are not listed on any U.S. Government denied-party or restricted-person list.
2. **U.S. Government Restricted Rights**: The Software and accompanying documentation are "commercial computer software" and "commercial computer software documentation" as defined in FAR 12.212 (48 C.F.R. § 12.212) and DFARS 227.7202 (48 C.F.R. § 227.7202). Use, duplication, reproduction, or disclosure by the United States Government is subject solely to the commercial license rights and restrictions set forth in this Agreement.

---

## 12. Term & Termination

1. **Term**: This Agreement is effective upon your first download, installation, or use of the Software and remains in force until terminated.
2. **Termination by You**: You may terminate this Agreement at any time by uninstalling the Software and destroying all copies of the Software and license files in your possession.
3. **Termination for Breach**: This Agreement and your license rights will terminate automatically if you materially breach any provision of this Agreement (including unauthorized key sharing or circumvention of license checks).
4. **Effect of Termination**: Upon termination, all license grants immediately cease. Sections 4, 5, 6, 8, 9, 10, 11, 13, and 14 shall survive any termination of this Agreement.

---

## 13. Governing Law, Jurisdiction & Dispute Resolution

1. **Governing Law**: This Agreement and any dispute or claim arising out of or in connection with it or the Software shall be governed by and construed in accordance with the laws of the **District of Columbia, United States of America**, without giving effect to any choice-of-law or conflict-of-law rules (whether of the District of Columbia or any other jurisdiction), and excluding the United Nations Convention on Contracts for the International Sale of Goods (CISG).
2. **Venue**: Any legal suit, action, or proceeding arising out of or related to this Agreement shall be instituted exclusively in the federal courts of the United States or the courts of the District of Columbia located in **Washington, D.C.**, and each party irrevocably submits to the personal jurisdiction of such courts.
3. **Mandatory Consumer Forum Protection**: If you are a consumer habitually residing in the European Union, European Economic Area, or the United Kingdom, the choice of law and venue above does not deprive you of the protection afforded to you by mandatory provisions of the law of your country of habitual residence (pursuant to Article 6(2) of the Rome I Regulation (EC) No 593/2008), nor of your right to bring proceedings in the courts of your place of domicile.
4. **Informal Resolution First**: Before initiating any formal court proceeding, you agree to contact us at `legal@delgadologic.tech` with a written description of the issue and allow thirty (30) calendar days to resolve the dispute informally.

---

## 14. General Provisions & Contact Information

1. **Entire Agreement**: This Agreement, together with our [Privacy Policy](./privacy.md), [Refund Policy](./refund.md), and [Terms of Service](./terms.md), constitutes the entire agreement between you and DelgadoLogic relating to the Software and supersedes all prior or contemporaneous understandings.
2. **Severability**: If any provision of this Agreement is held to be invalid, illegal, or unenforceable by a court of competent jurisdiction, that provision shall be modified to the minimum extent necessary to make it enforceable, and the remaining provisions shall remain in full force and effect.
3. **No Waiver**: No failure or delay by DelgadoLogic in exercising any right or remedy under this Agreement shall operate as a waiver thereof.
4. **Assignment**: You may not assign or transfer this Agreement or your license rights without DelgadoLogic's prior written consent (except for seat reassignments expressly permitted via your Pro or Team license). DelgadoLogic may assign this Agreement in connection with a merger, acquisition, reorganization, or sale of substantially all assets relating to the Software.
5. **Notices & Contact**: All legal notices, questions, or support inquiries regarding this Agreement should be directed to:

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Website: <https://delgadologic.tech>  
Support: `support@delgadologic.tech`  
Legal: `legal@delgadologic.tech`  
Privacy: `privacy@delgadologic.tech`  
Security: `security@delgadologic.tech`  
Billing & Refunds: `billing@delgadologic.tech`
