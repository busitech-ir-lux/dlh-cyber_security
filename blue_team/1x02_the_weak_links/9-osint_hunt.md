# The OSINT Hunt

## 1. FortiGate FortiOS

**Source:**  
[NVD: CVE-2024-55591](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)

**CVE:** CVE-2024-55591

**Affected Product:** MedDefense FortiGate 100F running FortiOS 7.0.0–7.0.16

**Why the Scan Missed It:** The scan focused on internal hosts and may not have checked the firewall firmware or management interface.

**CVSS / Severity:** 9.8 — Critical

**MedDefense Impact:** A remote attacker could bypass authentication and gain super-admin access to the firewall. This could allow changes to VPNs, firewall rules and network traffic.

**Recommendation:** Check the FortiOS version immediately, upgrade to a fixed release, restrict management access and review administrator logs. This CVE is also listed in CISA KEV.

---

## 2. Microsoft Office 365 / Entra ID

**Source:**  
[Microsoft: Defending against evolving identity attack techniques](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/)

**CVE:** N/A — Attack technique

**Affected Product:** Microsoft 365 E3 and Microsoft Entra ID

**Attack Technique:** Adversary-in-the-middle phishing

**Why the Scan Missed It:** Microsoft 365 and other cloud services were outside the scan scope.

**CVSS / Severity:** N/A — High risk

**MedDefense Impact:** An attacker could steal user credentials and session cookies, bypass normal MFA and access email, SharePoint or other cloud data.

**Recommendation:** Use phishing-resistant MFA such as passkeys, enable Conditional Access, block legacy authentication and monitor risky sign-ins and unusual mailbox rules. Microsoft reports that attackers continue to use adversary-in-the-middle phishing against cloud identities.

---

## 3. Synology DSM

**Source:**  
[NVD: CVE-2024-10441](https://nvd.nist.gov/vuln/detail/CVE-2024-10441)

**CVE:** CVE-2024-10441

**Affected Product:** `NAS-01` running Synology DSM 7

**Why the Scan Missed It:** The scanner detected the exposed DSM interface but may not have identified the exact DSM build or had authenticated access.

**CVSS / Severity:** 9.8 — Critical

**MedDefense Impact:** A remote attacker could execute code on the backup NAS. This could expose, delete or encrypt MedDefense backups and seriously affect ransomware recovery.

**Recommendation:** Check the exact DSM build and update to at least the fixed version for the installed DSM branch. Restrict DSM management access to administrator systems and keep offline or immutable backups. NVD lists affected DSM 7.2, 7.2.1 and 7.2.2 versions before their corrected builds.
