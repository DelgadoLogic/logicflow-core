# Trademark Notice & Acceptable Use Policy (AUP)

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Applies To**: All DelgadoLogic Brand Assets, `https://delgadologic.tech`, LogicFlow v1.0, and Cloud APIs (`https://api.delgadologic.tech`)

---

## 1. Overview

This document sets forth:
1. The **Trademark Notice & Brand Usage Guidelines** (Part I) governing the use of trademarks, service marks, trade names, and logos owned by **Delgado Creative Enterprises LLC d/b/a DelgadoLogic** ("**DelgadoLogic**"), together with third-party nominative fair-use attributions; and
2. The **Acceptable Use Policy (AUP)** (Part II) governing your interaction with the LogicFlow v1.0 software (`LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`), our website (`https://delgadologic.tech`), our licensing endpoints, and our telemetry infrastructure (`https://api.delgadologic.tech/v1/telemetry`).

---

## Part I: Trademark Notice & Brand Usage Guidelines

### 2. DelgadoLogic Trademarks & Canonical Brand Spelling

The following names, wordmarks, and logos (collectively, the "**DelgadoLogic Marks**") are proprietary trademarks and trade names of **Delgado Creative Enterprises LLC**:

- **DelgadoLogic™** — Always written as a **single compound word in PascalCase (`DelgadoLogic`)** with no internal space. Never write the brand name as two separate words or in spaced all-caps.
- **Delgado Creative Enterprises™** / **Delgado Creative Enterprises LLC** — The corporate parent entity.
- **Delgado Creative Books™** — Our publishing imprint.
- **LogicFlow™** — Always written as a single compound word in PascalCase (`LogicFlow`).
- **HyperStore™**, **Lazarus™**, **OmniPulse™**, **OmniLicense™**, and **OmniCore™**.
- The **DelgadoLogic** "D" shield mark, **LogicFlow** 3D Sentinel shield icon, and visual trade dress.

### 3. Third-Party Trademarks & Nominative Fair-Use Disclaimer

All third-party product names, logos, and brands referenced in LogicFlow or its documentation are the property of their respective owners and are used solely for factual compatibility identification (nominative fair use):
- **Microsoft®, Windows®, Windows 10®, Windows 11®, Windows Server®, Windows Defender®, DirectX®, DirectStorage®, WinGet®, and BitLocker®** are registered trademarks of Microsoft Corporation.
- **Steam®** is a registered trademark of Valve Corporation.
- **Epic Games® and Unreal Engine®** are trademarks or registered trademarks of Epic Games, Inc.
- **GOG.com®** is a trademark of GOG sp. z o.o.
- **Battle.net®** is a registered trademark of Blizzard Entertainment, Inc.
- **NVIDIA® and GeForce®** are registered trademarks of NVIDIA Corporation.
- **AMD® and Radeon®** are registered trademarks of Advanced Micro Devices, Inc.
- **Intel®** is a registered trademark of Intel Corporation.

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic is an independent software company and is not affiliated with, endorsed by, or sponsored by Microsoft Corporation, Valve Corporation, Epic Games, Inc., or any other third-party trademark holder listed above.**

### 4. Permitted Nominative Fair Use of DelgadoLogic Marks

You may make truthful, non-misleading reference to **DelgadoLogic** and **LogicFlow** without prior written permission for the following purposes:
1. **Reviews, Benchmarks & Journalism**: Publishing independent technical reviews, performance comparisons, articles, or video tutorials about LogicFlow.
2. **Compatibility & Documentation**: Stating truthfully that your script, IT deployment package, or workflow invokes or integrates with the `lf.exe` CLI.
3. **Academic & Security Research**: Referencing LogicFlow in coordinated vulnerability disclosures or academic analysis.

### 5. Prohibited Brand & Trademark Uses

Without an express written license agreement from Delgado Creative Enterprises LLC, you must **NOT**:
1. **Impersonate Official Distribution Channels**: Register domain names, social media handles, or package repository namespaces containing `delgadologic` or `logicflow` that could confuse users into believing your site is an official download mirror.
2. **Distribute Modified or Repackaged Binaries Under Our Marks**: If you modify, patch, wrap, or bundle any DelgadoLogic binary, you may not distribute it under the **LogicFlow** or **DelgadoLogic** name or icon.
3. **Bid on Brand Keywords for Phishing / Typosquatting**: Run paid search ads that impersonate `delgadologic.tech` or direct users to third-party installer wrappers or adware bundles.
4. **Alter Brand Typography or Logos**: Distort, recolor, or split `DelgadoLogic` or `LogicFlow` into spaced words.

---

## Part II: Acceptable Use Policy (AUP)

### 6. Permitted Use on Authorized Hardware

LogicFlow v1.0 includes administrative Windows utilities—including Microsoft Defender ASR hardening (`LogicFlow.Sentinel`), persistence scanning, Windows hosts-file and Windows Firewall outbound rules, WOF game compression, ReFS/NTFS extent deduplication (`LogicFlow.Storage.Engine`), and raw sector file recovery (`LogicFlow.Lazarus`).

You may run LogicFlow **only** on Windows computers, virtual machines, and lab environments that:
1. You personally own; or
2. You have explicit written or administrative authorization from the system owner to manage and maintain.

### 7. Prohibited Conduct

When using LogicFlow, `https://delgadologic.tech`, or our cloud endpoints (`https://api.delgadologic.tech`), you agree **NOT** to engage in any of the following activities:

#### 7.1 Unauthorized Computer Access & Sabotage
- Deploying or executing `LogicFlow.exe`, `lf.exe`, or `LogicFlowAgent.exe` on any third-party computer, corporate network, or server without the system owner's authorization.
- Using `FileShredder`, `VolumeAwareDeduplicator`, `DefenderHardenerEngine`, or `Registry.RepairEngine` to intentionally destroy user data or disrupt system availability on a machine without the owner's consent.

#### 7.2 License Key Abuse, Piracy & Circumvention
- Generating, forging, sharing, reselling, or publishing counterfeit `license_token.json` / `license.lic` files, activation codes, or RSA key-patching loaders.
- Using the **LogicFlow Community Edition ($0)** or **LogicFlow Free Edition ($0)** for commercial, professional, enterprise fleet, or paid PC-repair/MSP services (which require a **LogicFlow Pro** or **Team 10-Pack** license).
- Sharing a 3-device Pro Edition license or 10-device Team 10-Pack across machines in excess of your purchased seat count.

#### 7.3 Cloud Infrastructure & Telemetry Endpoint Abuse
- Flooding `https://api.delgadologic.tech/v1/telemetry/*` or `https://api.delgadologic.tech/*` with automated traffic exceeding our published rate limits (`30 req/min` per install, `120 req/min` per IP), volumetric Denial-of-Service (DoS/DDoS) attacks, or oversized payloads (`> 1 MiB` wire).
- Intentionally injecting personally identifiable information (PII), unlawful content, or forged HMAC signatures into synthetic telemetry requests.
- Probing, scanning, or attempting to exploit `delgadologic.tech` or our Firebase/Google Cloud backend outside the scope of our [Security Policy Safe Harbor](/security).

#### 7.4 Malware Bundling & Deceptive Redistribution
- Wrapping the LogicFlow installer (`LogicFlowSetup.exe`) in third-party download managers, adware bundlers, cryptominers, or trojans.

---

## 8. Enforcement & Remedies

Violations of this Acceptable Use Policy or our Trademark Guidelines may result in:
1. **Immediate IP or Install Rate-Limiting / Kill-Switch Activation** at our Google Cloud Run / Cloudflare edge load balancers;
2. **Revocation of License Activation Rights** (`status: "revoked"` in our Cloud Firestore license ledger) in accordance with Section 12 of the [End User License Agreement (EULA)](/legal/eula);
3. **DMCA / Trademark Takedown Notices** to hosting providers, registrars, and search engines; and
4. **Civil or Criminal Referral** for unauthorized computer access, payment fraud, or malware distribution.

---

## 9. Contact Information

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Trademark & Legal Inquiries: `legal@delgadologic.tech`  
Abuse & Security Reports: `security@delgadologic.tech`  
General Support: `support@delgadologic.tech`
