# MedDefense Prioritized Gap Analysis

## This analysis combines the Asset Criticality Matrix, Data Map, Complete Control Matrix and Shadow IT findings. The supporting evidence comes from the onboarding packet, control artifacts and network scan.

## GAP-001 — No Internal Network Segmentation

**Affected Asset(s):**
Network Core, EHR, PACS, Medical IoT and Identity Infrastructure — **Critical**

**Data at Risk:**
Patient records, medical images and medication data — **Restricted**

**Current Control Status:**
The FortiGate provides perimeter filtering and a default-deny rule. VPN connections are also present.

**What is Missing:**
Technical Preventive and Compensating controls inside the hospital network, especially VLAN separation and internal firewall rules.

**Risk Level:** **Critical**

**Risk Justification:**
Critical clinical systems and Restricted data share a reachable network, while there is no effective internal isolation to limit an attacker.

**Potential Impact:**
A compromised workstation, medical device or shadow system could be used to reach the EHR, PACS, domain controllers, infusion pumps and patient monitors. One infection could spread across the hospital and interrupt patient care.

---

## GAP-002 — Medical Devices Are Exposed to the Wider Network

**Affected Asset(s):**
Patient monitors, infusion pumps, MRI and nurse call system — **Critical**

**Data at Risk:**
Patient-monitoring and medication information — **Restricted**

**Current Control Status:**
Basic network connectivity and physical access controls exist. Proposed MRI compensating controls have not been implemented.

**What is Missing:**
Technical Preventive, Detective, Corrective and Compensating controls for medical devices.

**Risk Level:** **Critical**

**Risk Justification:**
Medical devices directly affect patient care, but their management interfaces are reachable across the internal network and there is no dedicated monitoring or tested recovery process.

**Potential Impact:**
An attacker could interrupt monitoring, change device settings, interfere with dosage updates or make devices unavailable during treatment.

---

## GAP-003 — PACS and Medical Images Are Not Backed Up

**Affected Asset(s):**
`pacs-srv-01`, PACS application, MRI and CT imaging services — **Critical**

**Data at Risk:**
Medical images and diagnostic studies — **Restricted**

**Current Control Status:**
PACS uses access controls and network services, but it is excluded from Veeam backups because of storage limitations.

**What is Missing:**
Technical Corrective control and tested recovery capability.

**Risk Level:** **Critical**

**Risk Justification:**
PACS is a Critical clinical system containing Restricted diagnostic data, but there is no effective corrective control if the data is encrypted, deleted or corrupted.

**Potential Impact:**
Radiology staff may lose access to previous and current imaging studies. Diagnosis and treatment could be delayed, and lost images may need to be recreated where possible.

---

## GAP-004 — Backups Are Not Isolated or Offsite

**Affected Asset(s):**
EHR, billing, Active Directory, file shares, patient portal and backup infrastructure — **Critical**

**Data at Risk:**
Patient records, billing data, credentials and internal files — **Restricted and Confidential**

**Current Control Status:**
C-014 performs nightly backups to `NAS-01` with 14-day retention.

**What is Missing:**
Technical Corrective and Compensating controls, including immutable or offsite backup copies.

**Risk Level:** **Critical**

**Risk Justification:**
Backups protect several Critical assets, but the NAS is located in the same room and network as the production systems. A single event could remove both production and recovery copies.

**Potential Impact:**
Ransomware, fire, flooding or physical damage could prevent MedDefense from restoring the EHR, billing system, domain services and file shares.

---

## GAP-005 — No Centralized Security Monitoring

**Affected Asset(s):**
EHR, Network Core, Identity Infrastructure, PACS, Medical IoT and Billing — **Critical or High**

**Data at Risk:**
Patient, financial, credential and audit information — **Restricted and Confidential**

**Current Control Status:**
C-003, C-008, C-013 and C-022 produce local logs and malware alerts.

**What is Missing:**
Technical Detective controls such as centralized log management, automated alerting and a SIEM.

**Risk Level:** **Critical**

**Risk Justification:**
Critical assets have some local logs, but no effective method exists to identify and connect suspicious activity across systems.

**Potential Impact:**
Attackers may remain undetected for days or weeks, steal data, create accounts, move between systems and cause larger outages before IT notices.

---

## GAP-006 — No Formal Incident Response or Disaster Recovery Plan

**Affected Asset(s):**
All Critical clinical and IT assets

**Data at Risk:**
All Restricted and Confidential information

**Current Control Status:**
Backups exist, and staff have previously responded to incidents informally.

**What is Missing:**
Administrative Corrective controls, including approved incident-response, business-continuity and disaster-recovery plans.

**Risk Level:** **Critical**

**Risk Justification:**
Critical systems have no tested organization-wide procedure for containment, recovery, communication or continued clinical operation.

**Potential Impact:**
During another ransomware event or major outage, teams may repeat the uncoordinated four-day response used after the billing incident. Patient care and regulatory reporting may be delayed.

---

## GAP-007 — Weak Protection of Privileged and Remote Accounts

**Affected Asset(s):**
Identity Infrastructure, EHR, PACS, servers, VPN and administrative systems — **Critical**

**Data at Risk:**
Credentials, patient data and administrative information — **Restricted**

**Current Control Status:**
Password policy, account lockout, password history and SSH keys on `ehr-srv-01` exist.

**What is Missing:**
Technical Preventive controls, especially mandatory MFA, unique accounts and stronger privileged-access management.

**Risk Level:** **High**

**Risk Justification:**
Preventive controls exist, but MFA is not required, shared PACS accounts are used and most Linux servers still allow password-based SSH.

**Potential Impact:**
A stolen password could allow an attacker to access clinical systems, change permissions, view patient information or gain administrator-level access.

---

## GAP-008 — Server Endpoint Protection Is Missing

**Affected Asset(s):**
EHR servers, billing server, PACS, domain controllers, file server and web server — **Critical or High**

**Data at Risk:**
Patient records, billing data, credentials and internal documents — **Restricted and Confidential**

**Current Control Status:**
C-012 and C-013 protect and monitor 372 Windows workstations.

**What is Missing:**
Technical Preventive and Detective controls for Windows and Linux servers.

**Risk Level:** **Critical**

**Risk Justification:**
Several Critical servers process Restricted data, but Sophos does not cover any Linux servers or Windows servers. The billing server has already suffered ransomware and crypto-mining compromises.

**Potential Impact:**
Malware could execute on key servers without being blocked or detected, resulting in data theft, unauthorized changes or service outages.

---

## GAP-009 — Legacy and Unsupported Systems Remain Active

**Affected Asset(s):**
MRI workstation — **Critical**; billing server and print server — **High or Medium**

**Data at Risk:**
Medical imaging, billing information and internal documents — **Restricted or Confidential**

**Current Control Status:**
Basic network and password controls exist. Proposed MRI isolation controls are not implemented.

**What is Missing:**
Technical Compensating and Preventive controls for systems that cannot be patched or upgraded.

**Risk Level:** **Critical**

**Risk Justification:**
The Windows XP MRI workstation is a Critical clinical asset and cannot receive normal security updates. It remains on the same reachable network as other systems.

**Potential Impact:**
Attackers could exploit known weaknesses, use the MRI workstation to move across the network or interrupt approximately 45 MRI studies per day.

---

## GAP-010 — Shadow IT Devices on the Internal Network

**Affected Asset(s):**
Network Core, EHR, PACS, Cardiology research storage and other internal systems — **Critical or High**

**Data at Risk:**
Possible patient research data, network information and internal system data — **Restricted or Confidential**

**Current Control Status:**
The perimeter firewall and some workstation antivirus controls exist.

**What is Missing:**
Administrative and Technical Preventive and Detective controls, including approval, inventory, network-access control, patching and monitoring.

**Risk Level:** **Critical**

**Risk Justification:**
The personal NAS, Raspberry Pi and unidentified Linux systems are unmanaged and may access Critical assets through the flat network. Their patching, users and stored data are unknown.

**Potential Impact:**
A compromised shadow device could expose patient research data, capture network traffic or become an entry point into clinical systems.

---

## GAP-011 — Marketing Data Uses a Personal Google Account

**Affected Asset(s):**
Marketing Google Drive and administrative cloud services — **High**

**Data at Risk:**
Press communications, internal plans and media files — **Confidential or Internal**

**Current Control Status:**
MedDefense uses O365, but the Google Drive operates outside official account and access controls.

**What is Missing:**
Administrative and Technical Preventive controls for approved cloud use, access reviews, retention and account ownership.

**Risk Level:** **High**

**Risk Justification:**
Confidential business information is stored under a personal account with incomplete organizational control.

**Potential Impact:**
MedDefense could lose access to files when the account owner leaves, or an attacker could leak or change press statements and internal communications.

---

## GAP-012 — Weak Physical Protection of Critical IT Areas

**Affected Asset(s):**
Server room, network core, switches, storage and administrative offices — **Critical or High**

**Data at Risk:**
Patient data, credentials, backups and internal information — **Restricted and Confidential**

**Current Control Status:**
C-016, C-017, C-018 and C-023 provide limited guards, cameras and badge controls.

**What is Missing:**
Physical Preventive and Detective controls covering the actual server room, network closets and restricted offices.

**Risk Level:** **Critical**

**Risk Justification:**
Critical infrastructure can be reached using generic badges, while the network closet is unlocked and no cameras cover important IT areas.

**Potential Impact:**
An unauthorized person could disconnect systems, steal equipment, change network settings, use displayed credentials or destroy backup and production infrastructure.

---

## GAP-013 — EHR and Database Access Is Too Broad

**Affected Asset(s):**
EHR application and `ehr-db-01` — **Critical**

**Data at Risk:**
Patient medical records for more than 50,000 patients — **Restricted**

**Current Control Status:**
The EHR has authentication, SSH protections, audit logs and backups.

**What is Missing:**
Technical Preventive controls restricting PostgreSQL access only to required application systems, plus stronger user-session controls.

**Risk Level:** **High**

**Risk Justification:**
Controls exist, but the database is reachable from the wider internal network and unattended clinical sessions expose patient information in use.

**Potential Impact:**
An internal attacker or compromised endpoint could attempt direct database access, while visitors or unauthorized staff could view or change patient records from unattended workstations.

---

## GAP-014 — Security Training Is Incomplete

**Affected Asset(s):**
Clinical endpoints, email, EHR, patient data and administrative systems — **Critical or High**

**Data at Risk:**
Patient, employee and business information — **Restricted and Confidential**

**Current Control Status:**
C-020 and C-021 provide annual general security training.

**What is Missing:**
Administrative Preventive controls covering all staff, role-specific risks, PHI handling, medical-device security and phishing simulations.

**Risk Level:** **Medium**

**Risk Justification:**
Some training exists, which reduces risk, but completion is only 71% at Central and 58% at Westside, and the content is not healthcare-specific.

**Potential Impact:**
Staff may fall for phishing, mishandle patient information, allow tailgating or fail to report unusual activity quickly.

---

# Gap Distribution Summary

## Gaps by Risk Level

| Risk Level   | Number of Gaps |
| ------------ | -------------: |
| **Critical** |              9 |
| **High**     |              4 |
| **Medium**   |              1 |
| **Low**      |              0 |
| **Total**    |         **14** |

## Asset Categories with the Most Gaps

| Asset Category                         | Related Gaps |
| -------------------------------------- | -----------: |
| **Network Core and Connectivity**      |            6 |
| **EHR and Clinical Data Systems**      |            5 |
| **Medical IoT and Imaging**            |            5 |
| **Identity and Access Infrastructure** |            3 |
| **Backup and Recovery**                |            3 |
| **Administrative and Cloud Systems**   |            3 |
| **Physical Security Infrastructure**   |            2 |

A single gap can affect several asset categories, so these totals overlap.

## Control Areas with the Most Gaps

The gaps are mainly concentrated in:

1. **Technical Detective controls**
   There is no SIEM, centralized alerting or dedicated medical-device monitoring.

2. **Technical Corrective controls**
   Backups are incomplete, not isolated and not supported by a tested disaster-recovery process.

3. **Technical Compensating controls**
   Unsupported and unpatchable systems, especially the MRI workstation, have not been isolated.

4. **Administrative Corrective controls**
   Incident-response, business-continuity and disaster-recovery plans are missing.

5. **Technical Preventive controls**
   Internal segmentation, MFA, server endpoint protection and least-privilege firewall rules are incomplete.

## Overall Finding

MedDefense has basic preventive controls, such as a firewall, passwords, VPNs and workstation antivirus, but its detection, recovery and compensating controls are much weaker. The largest risks affect systems that support direct patient care, meaning a successful attack could become both a cybersecurity incident and a patient-safety incident.

