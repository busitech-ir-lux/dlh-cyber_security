# MedDefense Prioritized Threat Assessment

## Rank 1

**Threat:** BlackReef-style ransomware attack causing patient-data theft and organization-wide encryption
**Actor Type:** Ransomware Groups — Organized Crime
**Primary Vector:** Exploitation of the FortiGate VPN, followed by phishing or stolen credentials
**Primary Target:** Active Directory, EHR system and backup infrastructure

**Likelihood:** **Critical**
Healthcare accounted for 25% of reported ransomware incidents across critical infrastructure. MedDefense also matches the preferred target profile: a 350-bed hospital with regulated data, limited security resources, unpatched systems and three similar hospitals attacked nearby.

**Impact:** **Critical**
Compromise could make the EHR unavailable, expose patient records, encrypt workstations and destroy backups. A comparable hospital experienced 11 days of downtime, ambulance diversions and approximately $5 million in recovery and lost revenue.

**Overall Priority:** **Critical**

**Key Gap:** **M-01 — Network Segmentation**
The flat network allows a VPN or workstation compromise to reach Active Directory, EHR, backups and medical devices.

**Recommended Action:** **Long-term**
Create separate VLANs for users, servers, medical devices, backups and vendor access. Apply internal firewall rules so each zone can reach only required services.

---

## Rank 2

**Threat:** Accidental patient-data exposure or network compromise caused by negligent employees
**Actor Type:** Insider — Negligent
**Primary Vector:** Shadow IT, unrestricted USB devices, shared credentials or phishing
**Primary Target:** EHR records, PACS data and clinical workstations

**Likelihood:** **High**
Negligent insiders are more common than malicious insiders in healthcare. MedDefense already has shared PACS credentials, personal storage devices, unmanaged iPads and low training completion among clinical staff.
**Impact:** **High**
Patient records could be lost, copied to an unauthorized device or disclosed to the wrong person. An unmanaged device could also provide an external attacker with an internal foothold.

**Overall Priority:** **High**

**Key Gap:** **Unnumbered DLP and removable-device control gap**
MedDefense cannot detect or prevent patient information from being copied to USB, email, personal cloud storage or unmanaged devices.

**Recommended Action:** **Short-term**
Enable endpoint device control to block unapproved USB storage and deploy DLP first on EHR, billing and administrative workstations.

---

## Rank 3

**Threat:** Automated exploitation of vulnerable or unsupported MedDefense systems
**Actor Type:** Unskilled or Opportunistic Attacker
**Primary Vector:** Vulnerable software exploitation and internet scanning
**Primary Target:** `billing-srv-01`, the patient portal and other exposed services

**Likelihood:** **High**
MedDefense has already experienced this threat. An automated attacker exploited `billing-srv-01` and installed a cryptocurrency miner. Apache 2.4.29, Ubuntu 18.04, Windows XP and Windows Server 2012 R2 create further opportunities.
**Impact:** **High**
The initial compromise may begin as mining or malware installation, but the flat network allows movement toward Active Directory, databases and medical devices.

**Overall Priority:** **High**

**Key Gap:** **Unnumbered patch-management gap**
MedDefense has no documented risk-based process or deadline for patching critical public-facing systems.

**Recommended Action:** **Quick Win**
Patch or replace `billing-srv-01` immediately and establish a 48-hour remediation requirement for critical vulnerabilities affecting VPNs, web servers and remote-access systems.

---

## Rank 4

**Threat:** EHR compromise through a breached maintenance vendor
**Actor Type:** Organized Crime using a supply-chain pathway
**Primary Vector:** Stolen MedTech Solutions vendor credentials
**Primary Target:** `ehr-srv-01` and `ehr-db-01`

**Likelihood:** **Medium**
A compromise requires the attacker to first breach MedTech or steal a technician account. However, MedTech has direct maintenance access to MedDefense’s most critical application, making this a realistic trusted-access pathway.

**Impact:** **Critical**
The attacker could steal patient records, modify the EHR application or interrupt clinical access. The flat network may also allow movement from the EHR server to Active Directory and backups.

**Overall Priority:** **High**

**Key Gap:** **M-05 — No MFA**
Vendor access may depend only on a username, password or existing maintenance credential.

**Recommended Action:** **Short-term**
Route all vendor access through a controlled jump server using unique accounts, MFA, time-limited approval and full session recording.

---

## Rank 5

**Threat:** Intentional theft or misuse of patient information by an employee or former contractor
**Actor Type:** Insider — Malicious
**Primary Vector:** Abuse of legitimate access
**Primary Target:** EHR, billing database and PACS records

**Likelihood:** **Medium**
MedDefense employees require broad access to patient information. Shared accounts, delayed offboarding, unrestricted USB use and the absence of behavioral monitoring make intentional misuse difficult to detect.

**Impact:** **High**
An insider could steal thousands of records, disclose sensitive medical information or sabotage systems. The result could include regulatory investigation, patient notification, legal costs and reputational damage.

**Overall Priority:** **High**

**Key Gap:** **M-04 — Absence of Monitoring and Detection**
EHR, VPN, Active Directory and application logs exist, but they are not centralized or reviewed continuously.

**Recommended Action:** **Short-term**
Deploy centralized monitoring for EHR access, VPN authentication and privileged account activity. Alert on bulk record access, off-hours logins and use of accounts after termination.

# Strategic Recommendation

If MedDefense can fund only two initiatives next quarter, it should fund **network segmentation** and **centralized security monitoring**. Segmentation addresses **M-01** and prevents one compromised user, server or vendor account from reaching every critical asset. A SIEM with endpoint monitoring addresses **M-04** and provides early warning for ransomware discovery activity, credential theft, insider data access, backup deletion and vendor misuse. Together, these controls interrupt more kill chains than any other funded combination. MFA should also be enabled immediately for VPN, administrator and vendor accounts because much of it can use existing Microsoft licensing with limited additional cost.

