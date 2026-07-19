## The OSINT Hunt

## 1. FortiGate FortiOS

**Source:**  
[https://nvd.nist.gov/vuln/detail/CVE-2024-55591](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)  
[https://www.fortiguard.com/psirt/FG-IR-24-535](https://www.fortiguard.com/psirt/FG-IR-24-535)

**CVE:** CVE-2024-55591

**Affected Product:** MedDefense FortiGate 100F, **only if it runs FortiOS 7.0.0 through 7.0.16**.

**Why the Scan Missed It:** The internal scan did not confirm the firewall firmware version or assess the FortiGate management interface.

**CVSS / Severity:** 9.8 — Critical

**MedDefense Impact:** A remote attacker could gain super-admin privileges and change firewall rules, VPN settings and network access.

**Recommendation:** Check the installed FortiOS version. If it is 7.0.0–7.0.16, upgrade to FortiOS 7.0.17 or later and restrict management access.

Fortinet and NVD both identify FortiOS 7.0.0–7.0.16 as affected and state that crafted requests can provide super-admin access.

---

## 2. Microsoft 365 / Entra ID

**Source:**  
[https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/)

**CVE:** N/A — OSINT-backed attack technique

**Attack Technique:** Adversary-in-the-middle phishing

**Affected Product:** MedDefense Microsoft 365 and Entra ID user accounts.

**Why the Scan Missed It:** Microsoft 365 was explicitly outside the scope of the internal vulnerability scan.

**CVSS / Severity:** N/A — High risk

**MedDefense Impact:** Attackers could steal credentials and session cookies, bypass normal MFA and access email, SharePoint or other Microsoft 365 services.

**Recommendation:** Use phishing-resistant MFA, apply Conditional Access, monitor suspicious sign-ins and revoke stolen sessions when compromise is suspected.

Microsoft identifies AiTM credential phishing as a common identity attack that attempts to bypass traditional MFA. This is an attack technique, not a software CVE.

---

## 3. Synology DSM

**Source:**  
[https://nvd.nist.gov/vuln/detail/CVE-2024-10441](https://nvd.nist.gov/vuln/detail/CVE-2024-10441)  
[https://www.synology.com/en-af/security/advisory/Synology_SA_24_20](https://www.synology.com/en-af/security/advisory/Synology_SA_24_20)

**CVE:** CVE-2024-10441

**Affected Product:** MedDefense `NAS-01`, **only if its DSM version is older than one of the fixed versions listed below**:

- DSM 7.2 before 7.2-64570-4
    
- DSM 7.2.1 before 7.2.1-69057-6
    
- DSM 7.2.2 before 7.2.2-72806-1
    

**Why the Scan Missed It:** The scan detected the DSM interface but did not record the exact DSM version needed to confirm this CVE.

**CVSS / Severity:** 9.8 — Critical

**MedDefense Impact:** A remote attacker could execute arbitrary code on the NAS. This could expose, delete or encrypt backup data.

**Recommendation:** Check the exact DSM version and update it if it is within the affected range. Restrict the DSM management interface to authorized administrator systems.

NVD and Synology identify CVE-2024-10441 as a Critical remote-code-execution vulnerability affecting specific unpatched DSM 7 versions.
