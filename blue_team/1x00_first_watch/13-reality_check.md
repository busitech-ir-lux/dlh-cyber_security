# The Reality Check

## Breach 1: Regional Hospital Alpha — Ransomware Through VPN

### Attack Vector Identification

**Initial entry point:**
Attackers exploited an unpatched vulnerability in the hospital’s VPN appliance.

**Weaknesses exploited:**

* Critical VPN patch was not applied.
* VPN provided direct access to internal servers.
* Internal network was flat.
* No network monitoring or intrusion detection existed.
* Backups were stored on the production network.
* No tested incident-response plan existed.
* A compromised domain administrator account allowed ransomware deployment through Group Policy.

### MedDefense Correlation

The following MedDefense gaps could allow a similar attack:

* **GAP-001 — No Internal Network Segmentation:** A compromised VPN connection could provide access to servers, workstations and medical devices.
* **GAP-004 — Backups Are Not Isolated or Offsite:** MedDefense’s NAS is on the same network and in the same room as production systems.
* **GAP-005 — No Centralized Security Monitoring:** Reconnaissance and lateral movement may not generate alerts.
* **GAP-006 — No Formal Incident Response or Disaster Recovery Plan:** MedDefense previously improvised its ransomware response.
* **GAP-007 — Weak Protection of Privileged and Remote Accounts:** MFA is not required for VPN or privileged access.
* **GAP-008 — Server Endpoint Protection Is Missing:** MedDefense’s servers are not protected by Sophos.

### Blind Spot Check

This breach reveals a major gap that was not clearly documented: **formal vulnerability and patch management for perimeter systems**.

---

## New Gap: GAP-015 — No Formal Perimeter Patch Management

**Affected Asset(s):**
FortiGate firewall, VPN connections and other internet-facing systems — **Critical**

**Data at Risk:**
Patient records, credentials, financial data and internal files — **Restricted and Confidential**

**Current Control Status:**
The FortiGate provides firewall and VPN services, but no documented process confirms that critical security updates are tracked and applied within defined deadlines.

**What is Missing:**
Administrative and Technical Preventive controls for vulnerability scanning, vendor-advisory monitoring, patch ownership and emergency patching.

**Risk Level:** **Critical**

**Risk Justification:**
The firewall and VPN protect access to the entire MedDefense environment. An exploitable perimeter vulnerability could bypass other preventive controls and provide attackers with internal network access.

**Potential Impact:**
Attackers could enter through the VPN, compromise Active Directory, deploy ransomware and interrupt the EHR, billing, imaging and clinical systems.

---

# Breach 2: Health Network Beta — Insider and Credential Abuse

### Attack Vector Identification

**Initial entry point:**
A former employee continued using active VPN and EHR credentials after termination.

**Weaknesses exploited:**

* Account deactivation depended on a manual manager ticket.
* The account remained active for 47 days.
* No MFA was required.
* No dormant-account detection existed.
* EHR access logs were not reviewed.
* No alerts existed for unusual login times, locations or download volumes.
* No DLP control limited large exports of patient records.

### MedDefense Correlation

The following existing gaps apply:

* **GAP-005 — No Centralized Security Monitoring:** MedDefense cannot reliably identify unusual hours, IP addresses or access patterns.
* **GAP-007 — Weak Protection of Privileged and Remote Accounts:** MFA is not mandatory.
* **GAP-013 — EHR and Database Access Is Too Broad:** EHR sessions and database access are not sufficiently restricted.
* **GAP-014 — Security Training Is Incomplete:** Managers and staff may not understand their access-removal responsibilities.

### Blind Spot Check

Two important weaknesses were not clearly identified:

1. No formal employee account lifecycle and offboarding control.
2. No DLP or unusual-volume monitoring for Restricted data.

---

## New Gap: GAP-016 — No Automated Account Offboarding

**Affected Asset(s):**
Active Directory, VPN, EHR, O365 and departmental systems — **Critical**

**Data at Risk:**
Patient records, employee records, credentials and business data — **Restricted and Confidential**

**Current Control Status:**
Password rules and account lockout exist, but there is no evidence that HR termination automatically triggers account deactivation.

**What is Missing:**
Administrative and Technical Preventive controls linking HR records to account creation, review and immediate deactivation.

**Risk Level:** **Critical**

**Risk Justification:**
Former staff may retain valid access to Critical systems and Restricted data without creating obvious signs of compromise.

**Potential Impact:**
A former employee could access or download patient records, use email accounts, enter the VPN or misuse internal systems after leaving MedDefense.

---

## New Gap: GAP-017 — No Data Loss Prevention or Export Monitoring

**Affected Asset(s):**
EHR, file shares, O365, billing system and HR systems — **Critical or High**

**Data at Risk:**
Patient records, Social Security numbers, insurance data, employee records and financial information — **Restricted and Confidential**

**Current Control Status:**
Applications create some logs, but no control monitors or limits large downloads, copying or external transfer of sensitive data.

**What is Missing:**
Technical Detective and Preventive controls for DLP, export restrictions, unusual-volume alerts and removable-media monitoring.

**Risk Level:** **Critical**

**Risk Justification:**
Restricted data could be copied in large quantities without being blocked or detected.

**Potential Impact:**
An insider or compromised account could export thousands of patient records, causing regulatory reporting, legal action, financial loss and reputational damage.

---

# Breach 3: Community Hospital Gamma — Medical Device Pivot

### Attack Vector Identification

**Initial entry point:**
Attackers exploited an unpatched vulnerability in the public patient portal.

**Weaknesses exploited:**

* Patient portal patch was not applied.
* DMZ server could connect to the internal network.
* Medical devices were not segmented.
* Infusion-pump management interfaces used default credentials.
* Medical-device firmware contained known vulnerabilities.
* No network monitoring detected lateral movement or crypto-mining.
* Medical-device isolation recommendations were not followed.

### MedDefense Correlation

The following MedDefense gaps could allow the same attack:

* **GAP-001 — No Internal Network Segmentation**
* **GAP-002 — Medical Devices Are Exposed to the Wider Network**
* **GAP-005 — No Centralized Security Monitoring**
* **GAP-008 — Server Endpoint Protection Is Missing**
* **GAP-009 — Legacy and Unsupported Systems Remain Active**
* **GAP-013 — EHR and Database Access Is Too Broad**

MedDefense also hosts its patient portal on `web-srv-01`, while the true DMZ separation has not been fully verified.

### Blind Spot Check

This breach reveals two additional weaknesses:

1. No confirmed secure management of default or vendor credentials on medical devices.
2. No clear control limiting outbound traffic from the DMZ to internal systems.

---

## New Gap: GAP-018 — Default and Vendor Credentials on Medical Devices Are Not Controlled

**Affected Asset(s):**
Infusion pumps, patient monitors, MRI, nurse call system and other Medical IoT — **Critical**

**Data at Risk:**
Patient names, monitoring information and medication dosage data — **Restricted**

**Current Control Status:**
Medical devices have network connectivity and some physical protection, but no documented credential inventory, password-change process or vendor-account review exists.

**What is Missing:**
Technical and Administrative Preventive controls for changing default credentials, managing vendor accounts and reviewing device access.

**Risk Level:** **Critical**

**Risk Justification:**
Medical devices directly affect patient care and may expose Restricted data. Default credentials could provide immediate unauthorized access without requiring a complex exploit.

**Potential Impact:**
Attackers could view medication data, change device settings, disrupt clinical functions or use the devices to move across the network.

---

## New Gap: GAP-019 — DMZ Outbound Access Is Not Properly Restricted

**Affected Asset(s):**
`web-srv-01`, patient portal, internal servers and Medical IoT — **Critical**

**Data at Risk:**
Patient portal information, patient records, credentials and medical-device data — **Restricted**

**Current Control Status:**
Inbound traffic to `web-srv-01` is limited to HTTP and HTTPS, but the real separation between the DMZ and internal network has not been confirmed.

**What is Missing:**
Technical Preventive controls limiting DMZ-to-internal communication to explicitly required systems and ports.

**Risk Level:** **Critical**

**Risk Justification:**
A compromised public server could become a direct bridge into the hospital network if outbound internal access is permitted.

**Potential Impact:**
Attackers could move from the patient portal to EHR, Active Directory, PACS, workstations and medical devices.

---

# Priority Reassessment

## Gaps to Upgrade

### GAP-007 — Weak Protection of Privileged and Remote Accounts

**Previous level:** High
**Updated level:** **Critical**

The insider breach shows that valid credentials without MFA can expose thousands of patient records without malware or technical exploitation. MedDefense has Restricted patient data, remote VPN access and weak monitoring, so credential abuse should be treated as a Critical risk.

### GAP-013 — EHR and Database Access Is Too Broad

**Previous level:** High
**Updated level:** **Critical**

The real-world breach shows that EHR audit logs are not enough when nobody actively reviews them. MedDefense has unattended EHR sessions, broad database reachability and no behavioral monitoring, creating a direct risk to records for more than 50,000 patients.

### GAP-014 — Security Training Is Incomplete

**Previous level:** Medium
**Updated level:** **High**

Training alone would not stop these breaches, but poor offboarding, phishing awareness and weak reporting can contribute to successful attacks. The low completion rate among clinical staff makes this more serious than originally rated.

## Gaps Remaining Critical

The following priorities are strongly confirmed by the breach data:

* **GAP-001:** Network segmentation
* **GAP-002:** Medical-device exposure
* **GAP-004:** Backup isolation
* **GAP-005:** Centralized monitoring
* **GAP-006:** Incident response and disaster recovery
* **GAP-008:** Server endpoint protection
* **GAP-009:** Legacy-system compensating controls

## Gaps to Downgrade

No existing gap should be downgraded. The three breaches generally confirm that MedDefense’s current Critical and High priorities are realistic rather than overstated.

# Pattern Analysis

All three breaches began with one manageable weakness—an unpatched system or an active account—but became major incidents because several controls failed together. Flat networks allowed lateral movement, MFA and account controls were weak, logs were not reviewed, medical devices were exposed, backups were reachable and response plans were missing. MedDefense should therefore focus its limited budget first on **network segmentation, MFA and account lifecycle management, centralized monitoring, isolated backups and rapid patch management for internet-facing systems**, because these controls reduce the impact of several different attack types rather than solving only one problem.

