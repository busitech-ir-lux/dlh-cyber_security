# The Predecessor’s Notes

## Part 1: Comparative Analysis

### Comparison Table

| Finding                                | Marcus’s Assessment                                                                                      | Your Assessment                                                                                                                        | Agree / Disagree                                | Resolution                                                                                                                                                                                                                            |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M-01: Network Segmentation**         | Critical. Flat network allows any compromised device to reach servers, workstations and medical devices. | **GAP-001: Critical.** The network scan confirmed that all internal subnets are reachable without restrictions.                        | **Agree**                                       | Marcus’s conclusion is correct. This remains one of MedDefense’s highest priorities because it increases the impact of every other compromise.                                                                                        |
| **M-02: Backup Isolation**             | Critical. Production systems and backups could be lost together.                                         | **GAP-004: Critical.** `NAS-01` is in the same room and network as production systems, with no offsite or immutable copy.              | **Agree, with correction**                      | The main risk is correct. However, Marcus mentions a monthly offsite tape rotation, while the later backup artifact states that no offsite backup exists. The newer artifact should be treated as the current evidence.               |
| **M-03: Medical IoT Exposure**         | High, possibly Critical because patient safety may be affected.                                          | **GAP-002: Critical.** Patient monitors, infusion pumps and the MRI are reachable from the wider network.                              | **Partly disagree**                             | The finding is valid, but the correct rating is **Critical**, not High, because manipulation or outage of infusion pumps and patient monitors could directly affect patient care.                                                     |
| **M-04: No Monitoring and Detection**  | High. No SIEM, IDS, centralized logs or automated alerts.                                                | **GAP-005: Critical.** Local logs exist, but no centralized monitoring or alerting exists.                                             | **Partly disagree**                             | Marcus correctly identified the weakness, but the rating should be **Critical** because the gap affects Critical assets and there is no reliable detective control. The crypto-miner and healthcare breach examples confirm the risk. |
| **M-05: No MFA**                       | High. Password-only access is used for VPN, EHR and administrator accounts.                              | **GAP-007: Critical** after the real-world breach review.                                                                              | **Partly disagree**                             | The finding is correct, but the rating should be **Critical**. A stolen or retained password could provide access to patient records and internal systems without a second authentication factor.                                     |
| **M-06: Westside Clinic Security**     | High. Consumer router, no dedicated firewall, unmanaged switch and unlocked server closet.               | Covered partly by **GAP-001**, **GAP-012** and the control review, but not written as one separate gap.                                | **Agree**                                       | This is a valid finding that should be added as a separate gap because Westside’s weak controls create a direct route into Central through the VPN.                                                                                   |
| **M-07: Shared Radiology Credentials** | Medium because PACS access is limited to on-site users.                                                  | Covered under **GAP-007** and **GAP-013**, but rated as part of a wider Critical identity and EHR-access problem.                      | **Disagree on rating**                          | The weakness is valid, but **High** is more appropriate. PACS contains Restricted imaging data, and shared accounts remove accountability and allow unauthorized access or modification.                                              |
| **M-08: Unsupported Print Server**     | Low because it is an internal, low-value system.                                                         | Included in **GAP-009: Legacy and Unsupported Systems**, which was rated Critical because it also includes the MRI and billing server. | **Agree on the asset, not the combined rating** | The print server alone is Low or Medium. The broader gap remains Critical because the same category includes the Windows XP MRI workstation.                                                                                          |
| **TLS 1.0 on Patient Portal**          | TLS 1.0 remains enabled and should be disabled.                                                          | Not clearly identified in the earlier gap analysis.                                                                                    | **Agree — missed finding**                      | This is valid and should be added as a new gap because the patient portal handles Restricted patient information.                                                                                                                     |
| **No DLP**                             | Sensitive data can leave through email, USB or cloud upload without detection.                           | **GAP-017: Critical.** No DLP or export monitoring exists.                                                                             | **Agree**                                       | This was later identified during the healthcare breach comparison.                                                                                                                                                                    |
| **Unrestricted USB Storage**           | USB storage is allowed on all workstations.                                                              | Not identified as a separate gap.                                                                                                      | **Agree — missed finding**                      | This is valid and should be added because it allows malware introduction and data exfiltration from clinical and administrative endpoints.                                                                                            |
| **HQ Building Network Risk**           | MedDefense depends on landlord-managed infrastructure without visibility.                                | Mentioned as an unknown in the Asset Registry and Data Map but not treated as a formal gap.                                            | **Agree — missed finding**                      | This is valid. The site-to-site VPN depends on third-party infrastructure that MedDefense cannot inspect or directly manage.                                                                                                          |
| **No Formal Change Management**        | Changes are made without testing, documentation or approval.                                             | Not identified as a separate gap, although the failed backup cron job and EHR migration showed the effects.                            | **Agree — missed finding**                      | This is valid and important. It should be added because untested changes have already caused backup failure and a nine-hour EHR outage.                                                                                               |

Marcus’s draft confirms many of the most important findings already identified in the project. It also contains several useful details that were not formalized in the earlier gap analysis.

---

# New Gaps Identified from Marcus’s Draft

## GAP-020 — Weak Security at Westside Clinic

**Affected Asset(s):**
Westside router, `ws-srv-01`, clinic workstations and the VPN connection to Central — **High**

**Data at Risk:**
Patient scheduling, local files and possible clinical information — **Restricted and Confidential**

**Current Control Status:**
Westside has a site-to-site VPN, but it uses a consumer-grade Netgear router, an unmanaged switch and an unlocked server closet.

**What is Missing:**
Technical Preventive and Physical Preventive controls, including a managed firewall, restricted VPN rules, a managed switch and a locked server closet.

**Risk Level:** **High**

**Risk Justification:**
Westside has weaker controls than Central but has broad VPN access to the Central server subnet.

**Potential Impact:**
A compromised Westside endpoint or router could allow attackers to reach Central systems, access patient information or disrupt services at both sites.

---

## GAP-021 — Deprecated TLS Enabled on Patient Portal

**Affected Asset(s):**
`web-srv-01` and patient portal — **Critical**

**Data at Risk:**
Patient portal credentials and patient information — **Restricted**

**Current Control Status:**
HTTPS is enabled, and inbound web traffic is filtered by the FortiGate.

**What is Missing:**
Technical Preventive control requiring modern TLS versions and secure cipher configuration.

**Risk Level:** **High**

**Risk Justification:**
The portal handles Restricted data, but TLS 1.0 is outdated and provides weaker protection for information in transit.

**Potential Impact:**
Attackers may be better able to downgrade, intercept or weaken protected communication between patients and the portal.

---

## GAP-022 — Unrestricted USB Storage

**Affected Asset(s):**
Clinical and administrative workstations — **Critical or High**

**Data at Risk:**
Patient records, employee records, billing data and internal files — **Restricted and Confidential**

**Current Control Status:**
Sophos protects many Windows endpoints, but no policy or GPO limits removable storage.

**What is Missing:**
Technical Preventive and Detective controls for USB storage, removable-media encryption and file-copy monitoring.

**Risk Level:** **High**

**Risk Justification:**
Users can copy sensitive data to removable media or introduce malware without a technical restriction.

**Potential Impact:**
Patient or employee data could be removed from the hospital, or malware could be introduced into clinical workstations and spread through the flat network.

---

## GAP-023 — Limited Oversight of HQ Building Network

**Affected Asset(s):**
Corporate HQ workstations, laptops and the HQ-to-Central VPN — **High**

**Data at Risk:**
HR, finance, legal and executive information — **Confidential**

**Current Control Status:**
HQ has a dedicated VLAN and a site-to-site VPN, but the building network is managed by the landlord.

**What is Missing:**
Administrative and Technical Preventive controls defining landlord security obligations, network assurance, incident notification and access restrictions.

**Risk Level:** **High**

**Risk Justification:**
MedDefense depends on infrastructure it cannot directly inspect or manage, while that infrastructure connects to Central.

**Potential Impact:**
A weakness in the building network could expose HQ systems or provide a path toward Central through the VPN.

---

## GAP-024 — No Formal Change Management

**Affected Asset(s):**
Servers, network devices, EHR, backups and critical applications — **Critical**

**Data at Risk:**
Patient records, backups, financial data and system configurations — **Restricted and Confidential**

**Current Control Status:**
System administrators make changes, but no formal approval, testing, rollback or documentation process is described.

**What is Missing:**
Administrative Preventive and Corrective controls for change approval, testing, documentation, rollback and post-change review.

**Risk Level:** **Critical**

**Risk Justification:**
Poorly controlled changes have already caused a three-week backup gap and a nine-hour EHR outage.

**Potential Impact:**
An untested change could interrupt clinical systems, corrupt data, disable backups or introduce a new security weakness.

---

# Findings You Identified That Marcus Missed

## 1. No Formal Incident Response and Disaster Recovery Plan

Marcus mentioned weak response capability but did not document it as a formal finding.

Your assessment identified:

* **GAP-006 — No Formal Incident Response or Disaster Recovery Plan**
* no tested clinical downtime procedure;
* no full disaster recovery exercise;
* no approved ransomware or data-breach playbooks.

He may have missed this because the draft was incomplete and he had focused mainly on technical weaknesses.

## 2. PACS Is Not Backed Up

Your assessment identified:

* **GAP-003 — PACS and Medical Images Are Not Backed Up**

Marcus discussed backup isolation but did not identify that the PACS server itself is excluded from backup coverage. He may not have had access to the later Veeam configuration extract.

## 3. Server Endpoint Protection Is Missing

Your assessment identified:

* **GAP-008 — Server Endpoint Protection Is Missing**

Marcus documented the crypto-miner but did not formally state that no Windows or Linux servers are protected by Sophos. He may not have seen the current Sophos deployment report.

## 4. Shadow IT

Your assessment identified:

* **GAP-010 — Shadow IT Devices**
* Cardiology personal NAS;
* Marketing Google Drive;
* Raspberry Pi;
* two unknown Linux devices from the network scan.

Marcus knew about possible informal systems, but the full shadow IT picture became visible only after the scan and helpdesk disclosure.

## 5. Automated Account Offboarding

Your assessment identified:

* **GAP-016 — No Automated Account Offboarding**

This emerged from the external healthcare breach comparison. Marcus focused on shared credentials and MFA but did not assess the complete identity lifecycle.

## 6. DMZ Outbound Restrictions

Your assessment identified:

* **GAP-019 — DMZ Outbound Access Is Not Properly Restricted**

Marcus noted the portal and flat network but did not formally evaluate the DMZ-to-internal attack path. The later real-world medical-device breach made this risk more visible.

## 7. Physical Security of Central IT Areas

Your assessment identified:

* **GAP-012 — Weak Physical Protection of Critical IT Areas**

Marcus had previously left informal notes about server-room access, but the draft does not contain a complete physical-security finding. The walk-through provided stronger evidence, including the unlocked network closet and exposed switch credentials.

---

# Overall Resolution

Marcus’s draft was generally accurate and technically strong. His main weakness was not incorrect analysis but incomplete scope and, in several cases, risk ratings that were too low when patient safety and Restricted data were considered. The later network scan, control artifacts, physical walk-through, healthcare breach summaries and data mapping provided evidence that allowed several of his findings to be upgraded and several new gaps to be added.

---

# Part 2: The Last Page

Marcus’s unfinished threat-landscape work is the natural continuation of the internal assessment. The completed assessment shows that MedDefense has several weaknesses commonly exploited by ransomware groups, insiders and attackers targeting public-facing systems, including a flat network, no MFA, weak monitoring, legacy devices and incomplete recovery controls. Understanding the external threat landscape would show which actors are most likely to target these weaknesses and which attack methods they commonly use. Mapping those techniques to MedDefense’s architecture through MITRE ATT&CK and STRIDE would help the organization move from reacting to known weaknesses toward anticipating realistic attack paths.

