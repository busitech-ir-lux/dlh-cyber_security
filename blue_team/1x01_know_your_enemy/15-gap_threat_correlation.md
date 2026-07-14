# MedDefense Gap–Threat Correlation

## Gap M-01

**Gap ID:** M-01
**Gap Description:** The MedDefense network is flat, with no VLANs or internal firewalls separating workstations, servers, medical devices and remote sites.
**Original Risk Level:** Critical

**Threat Actors:**

* Ransomware groups
* Nation-state actors
* Malicious insiders
* Opportunistic attackers
* External attackers entering through vendors
* Negligent insiders who introduce compromised shadow IT

**Kill Chains:**

* Kill Chain 1: VPN Exploit to Enterprise Ransomware
* Kill Chain 2: Phishing to Domain Compromise
* Kill Chain 3: Public Server Exploit to Medical-Device Compromise
* Kill Chain 4: Shadow IT to EHR Data Exposure
* Kill Chain 5: Compromised EHR Vendor Access

**Scenarios:**

* Scenario 1: BlackReef VPN-to-Ransomware Attack
* Scenario 2: Billing Employee Data Theft
* Scenario 3: Compromised MedTech Maintenance Account

**Updated Risk Level:** **Critical — Same**

**Justification:**
M-01 appears in all five kill chains and all three scenarios. It turns a compromise of one workstation, VPN account, vendor connection or unmanaged device into access to Active Directory, EHR, backups and medical devices. The comparable hospital attack in the intelligence dossier also used a flat network to reach the Domain Controller and deploy ransomware across the organization.

---

## Gap M-02

**Gap ID:** M-02
**Gap Description:** Production backups are stored on `NAS-01`, which is on the same network and in the same server room as production systems.
**Original Risk Level:** Critical

**Threat Actors:**

* Ransomware groups
* Malicious insiders with administrative access
* Destructive nation-state actors

**Kill Chains:**

* Kill Chain 1: VPN Exploit to Enterprise Ransomware

**Scenarios:**

* Scenario 1: BlackReef VPN-to-Ransomware Attack

**Updated Risk Level:** **Critical — Same**

**Justification:**
M-02 appears in fewer attack paths, but it determines whether MedDefense can recover from its most likely high-impact threat. BlackReef specifically instructs affiliates to destroy reachable backups before encryption. If `NAS-01` is deleted or encrypted, recovery may depend on monthly tapes and create up to 30 days of data loss.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Gap M-03

**Gap ID:** M-03
**Gap Description:** Approximately 200 medical devices are connected to the general network, with weak firmware management, accessible web interfaces and possible default credentials.
**Original Risk Level:** High

**Threat Actors:**

* Opportunistic attackers
* Ransomware groups
* Nation-state actors
* Malicious insiders
* External attackers entering through medical-device vendors

**Kill Chains:**

* Kill Chain 3: Public Server Exploit to Medical-Device Compromise

**Scenarios:**

* No selected scenario depends mainly on M-03, although Scenario 1 could reach medical devices after domain compromise.

**Updated Risk Level:** **Critical — Upgraded**

**Justification:**
The technical analysis showed that a compromised server or workstation can reach infusion pumps, monitors and nurse-call systems because there is no segmentation. The possible impact is not limited to data loss: device configuration changes could affect medication delivery or patient monitoring. This patient-safety consequence raises M-03 from High to Critical.

---

## Gap M-04

**Gap ID:** M-04
**Gap Description:** MedDefense has no SIEM, IDS/IPS, centralized log collection or automated security alerting.
**Original Risk Level:** High

**Threat Actors:**

* Ransomware groups
* Nation-state actors
* Malicious insiders
* Negligent insiders
* Hacktivists
* Opportunistic attackers
* Supply-chain attackers

**Kill Chains:**

* Kill Chain 1: VPN Exploit to Enterprise Ransomware
* Kill Chain 2: Phishing to Domain Compromise
* Kill Chain 3: Public Server Exploit to Medical-Device Compromise
* Kill Chain 4: Shadow IT to EHR Data Exposure
* Kill Chain 5: Compromised EHR Vendor Access

**Scenarios:**

* Scenario 1: BlackReef VPN-to-Ransomware Attack
* Scenario 2: Billing Employee Data Theft
* Scenario 3: Compromised MedTech Maintenance Account

**Updated Risk Level:** **Critical — Upgraded**

**Justification:**
M-04 appears in every kill chain and every scenario. It allows VPN anomalies, credential dumping, internal scanning, unusual EHR exports, vendor misuse, backup deletion and data exfiltration to continue without alerts. The crypto-miner on `billing-srv-01` already operated for at least two weeks before performance problems exposed it.

---

## Gap M-05

**Gap ID:** M-05
**Gap Description:** MFA is not enabled for VPN, EHR, Active Directory administration or the patient portal administration panel.
**Original Risk Level:** High

**Threat Actors:**

* Ransomware groups
* Nation-state actors
* Hacktivists
* Opportunistic credential-stuffing attackers
* Malicious insiders and former contractors
* Supply-chain attackers using stolen vendor credentials

**Kill Chains:**

* Kill Chain 1: VPN Exploit to Enterprise Ransomware
* Kill Chain 2: Phishing to Domain Compromise
* Kill Chain 5: Compromised EHR Vendor Access

**Scenarios:**

* Scenario 1: BlackReef VPN-to-Ransomware Attack
* Scenario 2: Billing Employee Data Theft
* Scenario 3: Compromised MedTech Maintenance Account

**Updated Risk Level:** **Critical — Upgraded**

**Justification:**
M-05 supports six of the eight selected kill-chain and scenario paths. Healthcare ransomware commonly enters through phishing, valid credentials and external remote services. Without MFA, one stolen employee, administrator or vendor password can become direct access to the MedDefense environment.

---

## Gap M-06

**Gap ID:** M-06
**Gap Description:** Westside uses a consumer-grade router, lacks a managed firewall and has weak physical protection, while its VPN has broad access to Central.
**Original Risk Level:** High

**Threat Actors:**

* Ransomware groups
* Opportunistic attackers
* Nation-state actors
* Malicious insiders
* External attackers compromising the router or an endpoint

**Kill Chains:**

* None of the five selected kill chains begins at Westside.
* It could provide an alternative entry route for Kill Chains 1, 2 or 3.

**Scenarios:**

* None of the three selected scenarios directly depends on M-06.
* Scenario 1 could follow the same ransomware path after a Westside compromise.

**Updated Risk Level:** **High — Same**

**Justification:**
Westside provides a trusted path into Central, but it was not required by the most critical selected scenarios. Its consumer router and permissive VPN still make it a credible secondary entry point, so the High rating remains appropriate.

---

## Gap M-07

**Gap ID:** M-07
**Gap Description:** Radiology uses the shared account `raduser/radiology1`, preventing individual accountability for PACS access.
**Original Risk Level:** Medium

**Threat Actors:**

* Malicious insiders
* Negligent insiders
* Opportunistic attackers who obtain the shared credentials
* External attackers using a compromised Radiology workstation

**Kill Chains:**

* None of the selected five kill chains directly depends on M-07.

**Scenarios:**

* None of the selected three scenarios directly depends on M-07.

**Updated Risk Level:** **High — Upgraded**

**Justification:**
The original rating relied on PACS access being limited to on-site use. Later threat analysis showed that this does not remove the risk. A malicious employee, an unattended workstation or an attacker who compromises the Windows XP MRI workstation could use the shared identity. MedDefense would be unable to prove who viewed, exported or altered medical images. Because PACS supports diagnosis and contains sensitive patient information, the lack of accountability has both clinical and regulatory impact.

---

## Gap M-08

**Gap ID:** M-08
**Gap Description:** `print-srv-01` runs unsupported Windows Server 2012 R2 and no longer receives normal security patches.
**Original Risk Level:** Low

**Threat Actors:**

* Opportunistic attackers
* Ransomware groups after gaining internal access
* Advanced attackers seeking a weak internal foothold

**Kill Chains:**

* None of the selected five kill chains depends on `print-srv-01`.

**Scenarios:**

* None of the selected three scenarios depends on M-08.

**Updated Risk Level:** **Low — Same**

**Justification:**
The print server could be exploited after an attacker enters the network, but it is not a primary target and does not appear in the highest-priority attack paths. The unsupported system should still be replaced, but M-01 is the larger problem because the flat network allows a low-value server to become a possible pivot.

# Re-prioritized Gap List

| Rank | Gap                                     | Threat-Informed Risk | Change                   |                                 Path Frequency |
| ---: | --------------------------------------- | -------------------- | ------------------------ | ---------------------------------------------: |
|    1 | **M-01 — Network Segmentation**         | Critical             | Same                     |                     5 kill chains, 3 scenarios |
|    2 | **M-04 — Monitoring and Detection**     | Critical             | **Upgraded from High**   |                     5 kill chains, 3 scenarios |
|    3 | **M-05 — No MFA**                       | Critical             | **Upgraded from High**   |                     3 kill chains, 3 scenarios |
|    4 | **M-02 — Backup Isolation**             | Critical             | Same                     |                       1 kill chain, 1 scenario |
|    5 | **M-03 — Medical IoT Exposure**         | Critical             | **Upgraded from High**   |       1 kill chain, indirect scenario exposure |
|    6 | **M-06 — Westside Security**            | High                 | Same                     |                              Alternative route |
|    7 | **M-07 — Shared Radiology Credentials** | High                 | **Upgraded from Medium** | No selected path; strong insider/PACS exposure |
|    8 | **M-08 — Print Server EOL**             | Low                  | Same                     |                               No selected path |

# The Critical Three

## 1. M-01 — Network Segmentation

M-01 appears in all five kill chains and all three scenarios. Closing it would restrict movement from compromised VPN accounts, workstations, vendors and shadow IT toward Active Directory, EHR, backups and medical devices.

## 2. M-04 — Monitoring and Detection

M-04 also appears in every kill chain and scenario. Central monitoring could expose attacks during reconnaissance, credential theft, data collection or exfiltration before ransomware or a reportable breach occurs.

## 3. M-05 — No MFA

M-05 appears in three kill chains and all three scenarios. MFA would interrupt stolen employee credentials, former-user VPN access and compromised vendor accounts near the start of the attack instead of after the attacker reaches critical assets.

# The Surprise

**M-07 — Shared Credentials in Radiology** should move from Medium to High. The original assessment reduced its rating because PACS access was on-site. Threat analysis showed that on-site access does not guarantee safety: malicious insiders, unattended sessions, physical intruders and attackers entering through the legacy MRI workstation can all use the shared account. The account removes attribution, which makes unauthorized image access or tampering difficult to investigate. In a healthcare environment, altered or exposed medical images can affect diagnosis as well as patient privacy.

