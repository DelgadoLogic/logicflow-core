# Security Policy, Coordinated Vulnerability Disclosure & EU CRA Compliance

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Security Contact**: `security@delgadologic.tech` (routes to `support@delgadologic.tech`)

---

## 1. Purpose & Supported Versions

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic** ("**DelgadoLogic**") takes the security of LogicFlow—an administrative Windows system utility (`LogicFlow.exe`, `lf.exe`), background service (`LogicFlowAgent.exe`), and cloud licensing/telemetry infrastructure—seriously. Because LogicFlow executes privileged Windows maintenance operations, we treat privilege escalation, arbitrary file write/deletion, signature bypass, and cryptographic flaws as critical priority issues.

### 1.1 Supported Product Versions & Security Support Period

In accordance with the **EU Cyber Resilience Act (Regulation (EU) 2024/2847, "CRA")**, DelgadoLogic commits to providing security updates and vulnerability remediation for LogicFlow v1.x for a minimum support period of **five (5) years** from release (or the product's active commercial lifecycle, whichever is longer):

| Product / Component | Version | Security Update Status | End of Security Support |
| :--- | :--- | :--- | :--- |
| **LogicFlow Desktop (`LogicFlow.exe`), CLI (`lf.exe`) & Service (`LogicFlowAgent.exe`)** | `1.0.x` | **Actively Supported** | October 13, 2031 (5 years) |
| **DelgadoLogic Web & Cloud Licensing API (`api.delgadologic.tech`)** | `v1` | **Actively Supported** | Continuous (Hosted Service) |
| **DelgadoLogic Telemetry Ingest Service (`api.delgadologic.tech/v1/telemetry`)** | `v1` (`schema: 1`) | **Actively Supported** | Continuous (Hosted Service) |
| **Pre-1.0 Alpha / Internal Prototypes** | `< 1.0.0` | Unsupported (Upgrade to `1.0.x`) | Ended |

---

## 2. How to Report a Security Vulnerability

If you discover a security vulnerability in LogicFlow, `delgadologic.tech`, or `api.delgadologic.tech`, please report it privately to our Product Security Incident Response Team (PSIRT):

- **Primary Email**: `security@delgadologic.tech`
- **Subject Line**: `[SECURITY] LogicFlow <Component> — <Brief Summary>`
- **Well-Known Security Metadata (RFC 9116)**: `https://delgadologic.tech/.well-known/security.txt`

### 2.1 What to Include in Your Report
To help us triage and reproduce the issue rapidly, please include:
1. **Affected Component & Version**: e.g., `LogicFlow.exe v1.0.0`, `LogicFlowAgent.exe`, `LogicFlow.Storage.Engine`, `lf.exe`, `Installer`, or `api.delgadologic.tech`.
2. **Vulnerability Class / CWE**: e.g., Local Privilege Escalation (LPE), symlink/junction traversal (`CWE-59`), path injection, signature verification bypass, or SSRF/injection.
3. **Environment Details**: Windows 10/11 build number (`winver`), user privilege level (Standard User vs. Local Administrator).
4. **Step-by-Step Reproduction / Proof of Concept (PoC)**: Minimal reproduction script, command-line invocation, or payload.
5. **Impact Assessment**: What an attacker can achieve under realistic preconditions.

---

## 3. SLA Response & Remediation Timelines

We commit to the following coordinated vulnerability disclosure (CVD) service-level targets:

| Milestone | Target SLA |
| :--- | :--- |
| **Initial Acknowledgment** | Within **24–48 business hours** of receipt |
| **Triage & Severity Classification (CVSS v4.0)** | Within **5 business days** |
| **Remediation Patch — Critical (CVSS 9.0–10.0) / Actively Exploited** | Within **7 calendar days** |
| **Remediation Patch — High (CVSS 7.0–8.9)** | Within **14 calendar days** |
| **Remediation Patch — Medium (CVSS 4.0–6.9)** | Within **30 calendar days** |
| **Remediation Patch — Low (CVSS 0.1–3.9)** | Next scheduled minor maintenance release |
| **Coordinated Public Advisory Disclosure** | Up to **90 days** after report (or immediately upon patch availability if mutually agreed) |

---

## 4. EU Cyber Resilience Act (CRA) Article 14 Mandatory Reporting Protocol

LogicFlow v1.0 is classified as a standard **Product with Digital Elements** under **Regulation (EU) 2024/2847 (Cyber Resilience Act)**. While the CRA's general conformity assessment and CE-marking obligations enter into force on **December 11, 2027**, **Article 14 (Reporting Obligations of Manufacturers)** applies beginning **September 11, 2026**.

In strict compliance with **CRA Article 14**, whenever DelgadoLogic becomes aware of any **actively exploited vulnerability** contained in LogicFlow or any **severe incident having an impact on the security of LogicFlow**, DelgadoLogic executes the following mandatory notification workflow via the **ENISA Single Reporting Platform (SRP)** and the designated **CSIRT coordinator**:

1. **24-Hour Early Warning Notification (Art. 14(2)(a) & Art. 14(4)(a))**:
   - Within **24 hours** of becoming aware of an actively exploited vulnerability or severe security incident affecting EU users, DelgadoLogic submits an early warning notification via the ENISA Single Reporting Platform indicating whether the vulnerability is known or suspected of being unlawfully or maliciously exploited and whether cross-border impact across EU Member States is anticipated.
2. **72-Hour Vulnerability / Incident Notification (Art. 14(2)(b) & Art. 14(4)(b))**:
   - Within **72 hours** of becoming aware, DelgadoLogic submits a detailed notification providing the general nature of the exploit or incident, affected LogicFlow version(s), severity and impact assessment, and any interim mitigation or corrective measures available to users.
3. **14-Day / 1-Month Final Report (Art. 14(2)(c) & Art. 14(4)(c))**:
   - Within **14 days** after a corrective security patch is made available (for an actively exploited vulnerability) or within **1 month** of the 72-hour notification (for a severe security incident), DelgadoLogic submits a comprehensive final report detailing the root cause (CWE/CVE), threat actor vector (if known), and the deployed permanent remediation.
4. **User Security Advisory (Art. 14(8))**:
   - Without undue delay—and after any necessary coordination with ENISA/CSIRT—DelgadoLogic notifies impacted users via `https://delgadologic.tech/security`, the signed LogicFlow update manifest (`https://api.delgadologic.tech/v1/update/logicflow/stable`), and direct email (for registered license holders) with instructions to apply the fixed release.

---

## 5. Safe Harbor for Good-Faith Security Researchers

DelgadoLogic provides **legal safe harbor** for security researchers who conduct vulnerability testing in good faith and in accordance with this policy:

- **Authorization**: If your security research complies with the scope and rules in Section 5.1, DelgadoLogic considers your testing **authorized** under the U.S. **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**, the **Digital Millennium Copyright Act (DMCA, 17 U.S.C. § 1201)** anti-circumvention exemptions for good-faith security research (37 C.F.R. § 201.40), and equivalent international computer misuse laws. We will not initiate or support civil or criminal legal action against you.
- **No Waiver of User Rights**: Attempting to identify security flaws in your own local installation of LogicFlow will never result in termination of your paid Pro or Team license.

### 5.1 Rules of Engagement
To qualify for Safe Harbor, you must:
1. **Perform Local Binary Testing on Your Own Machines**: Test `LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`, and the installer on devices and virtual machines you own or are authorized to test.
2. **Avoid Service Disruption (DoS)**: Do not perform volumetric Denial-of-Service, DDoS, or automated load-exhaustion attacks against `delgadologic.tech` or `api.delgadologic.tech`.
3. **Protect Third-Party Data**: Do not access, modify, or exfiltrate data belonging to other DelgadoLogic customers. If you inadvertently encounter customer data or credentials, stop immediately and report the finding to `security@delgadologic.tech`.
4. **Practice Coordinated Disclosure**: Allow DelgadoLogic a reasonable window (consistent with our Section 3 SLAs, up to 90 days maximum) to release a patch before publishing technical exploit details publicly.

---

## 6. Architecture Security Controls in LogicFlow v1.0

For transparency to enterprise administrators and security auditors, LogicFlow v1.0 incorporates the following architectural security controls:
- **Installation Directory ACL Hardening**: The native Win32 C++ installer (`Installer/src/LogicFlowInstaller.cpp`, producing `LogicFlowSetup.exe` and `UninstallLogicFlow.exe`) installs binaries to `%ProgramFiles%\DelgadoLogic\LogicFlow` (with explicit hardened ACLs writable only by `LocalSystem` [`NT AUTHORITY\SYSTEM`] and `Administrators` [`BUILTIN\Administrators`], and installation logs written to `%ProgramData%\DelgadoLogic\LogicFlow\logs\install.log`) so unprivileged local users cannot overwrite `LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`, or `UninstallLogicFlow.exe`.
- **Cryptographic Update & License Verification**: Auto-update manifests (`OmniCore.Engine.AutoUpdateEngine`) are verified with **Ed25519** digital signatures and **SHA-256** binary hashes prior to execution. Offline license tokens (`OmniLicense`) are verified with **RSA-2048 (`SHA-256`)** signatures.
- **Wire-Level Telemetry Authentication (`X-LF-Sig`)**: Telemetry payloads (`OmniPulse.PulseClient`) are signed with HMAC-SHA256 over the compressed wire bytes, and verified by `lf-telemetry-ingest` in constant time **before** gzip decompression.
- **Symlink & Reparse Point Guards**: `LogicFlow.Storage.Engine`, `VolumeAwareDeduplicator`, `GameCompressionEngine`, and `JunkCleanerEngine` inspect `FileAttributes.ReparsePoint` and protected Windows path prefixes to prevent arbitrary file deletion or junction-based privilege escalation.
- **Pre-Change Registry Snapshots**: Registry mutations generate timestamped `.reg` backups in `%LOCALAPPDATA%\LogicFlow\RegistryBackups\` prior to execution (`lf reg rollback`).

---

## 7. Contact Information

**Delgado Creative Enterprises LLC d/b/a DelgadoLogic**  
6218 Georgia Avenue NW, Ste 1-698  
Washington, DC 20011, USA  
Security / PSIRT: `security@delgadologic.tech`  
General Support: `support@delgadologic.tech`
