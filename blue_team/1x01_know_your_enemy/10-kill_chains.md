# MedDefense Critical Kill Chains

## Kill Chain #1: VPN Exploit to Enterprise Ransomware

**Threat Actor:** Ransomware Group — Organized Crime, using the BlackReef-style RaaS model
**Target Asset:** Identity and Access Infrastructure — `ad-dc-01` and `ad-dc-02`
**Expected Impact:** Organization-wide ransomware, patient-data theft and loss of clinical services; affects confidentiality, integrity and availability.

### Step 1 — Initial Access

**Vector:** VPN appliance exploit
**Surface:** External
**Detail:** An affiliate or Initial Access Broker exploits an unpatched vulnerability in the FortiGate 100F. This gives the attacker access to the internal network without needing an employee account.

### Step 2 — Establish Foothold

**Action:** The attacker creates a persistent account, installs a remote-access tool or uses the compromised VPN session repeatedly.
**MedDefense Weakness:** **M-04: Absence of Monitoring and Detection** means unusual VPN locations, access times and internal scanning may not generate alerts.

### Step 3 — Lateral Movement and Escalation

**Action:** The attacker scans the network, steals credentials and reaches the domain controllers through Kerberos, LDAP and SMB. After obtaining Domain Admin privileges, the attacker identifies the EHR and backup systems.
**MedDefense Weakness:** **M-01: Network Segmentation** allows the VPN foothold to reach servers, workstations, medical devices and Active Directory without internal firewall restrictions.

### Step 4 — Objective Execution

**Action:** The attacker exfiltrates patient data from `ehr-db-01`, deletes or encrypts backups on `NAS-01`, and distributes ransomware through Active Directory Group Policy.
**Data/System Affected:** EHR records, billing data, Windows workstations, domain controllers and backups.

### Step 5 — Impact

**Business Impact:** Ambulance diversion, cancelled procedures, manual clinical operations, recovery costs, lost revenue, breach notification and reputational damage.
**CIA Pillars:**

* **Confidentiality:** Patient records are stolen.
* **Integrity:** Systems and administrative settings may be modified.
* **Availability:** EHR, workstations and other services become unavailable.

**Gaps Exploited:** M-01, M-02, M-04 and M-05

**Break Points:**

* **Step 1:** Patch the FortiGate quickly and place remote access behind MFA.
* **Step 2:** Use a SIEM and EDR to alert on unusual VPN access, new accounts and reconnaissance.
* **Step 3:** Segment VPN users, servers, Active Directory and medical devices.
* **Step 4:** Maintain immutable or offline backups that domain administrators cannot delete.

A comparable regional hospital followed almost this exact sequence: VPN exploitation, movement across a flat network, Domain Controller compromise, data theft and ransomware deployment within five days.

---

## Kill Chain #2: Phishing to Domain Compromise

**Threat Actor:** Ransomware Group — Organized Crime
**Target Asset:** EHR System — `ehr-srv-01` and `ehr-db-01`
**Expected Impact:** Patient-data exposure and interruption of clinical care; affects all three CIA pillars.

### Step 1 — Initial Access

**Vector:** Phishing or spear phishing
**Surface:** Human
**Detail:** A clinical or IT employee receives a fake vendor invoice, password-reset message or urgent security notice. The employee opens a malicious attachment or enters credentials into a fake login page.

### Step 2 — Establish Foothold

**Action:** The attacker logs into the VPN using the stolen credentials or installs a remote-access trojan on the employee’s workstation.
**MedDefense Weakness:** **M-05: No MFA** means a stolen password can provide access to VPN, administrative or clinical systems.

### Step 3 — Lateral Movement and Escalation

**Action:** The attacker uses SMB, RDP or credential-dumping tools to move from the workstation toward Active Directory. The attacker then uses domain privileges to reach the EHR database and other servers.
**MedDefense Weakness:** **M-01** permits unrestricted communication between employee workstations and critical servers. RDP is also enabled on several reception and administrative computers.

### Step 4 — Objective Execution

**Action:** The attacker copies patient records from `ehr-db-01`, disables security tools and encrypts reachable systems.
**Data/System Affected:** EHR patient records, clinical workstations, file servers and Active Directory.

### Step 5 — Impact

**Business Impact:** Clinical delays, regulatory investigation, patient notification, financial losses and possible ransom payment.
**CIA Pillars:**

* **Confidentiality:** PHI is exfiltrated.
* **Integrity:** EHR and domain configurations may be changed.
* **Availability:** Clinical applications and workstations are encrypted.

**Gaps Exploited:** M-01, M-04 and M-05

**Break Points:**

* **Step 1:** Use email filtering, attachment sandboxing and healthcare-specific phishing training.
* **Step 2:** Require MFA for VPN, EHR and privileged accounts.
* **Step 3:** Deploy EDR to detect credential dumping, PsExec and unusual RDP connections.
* **Step 4:** Use DLP and outbound filtering to detect large patient-data transfers.

Training completion is only 71% at Central and 58% at Westside, and MedDefense has never conducted phishing simulations or role-specific training.

---

## Kill Chain #3: Public Server Exploit to Medical-Device Compromise

**Threat Actor:** Unskilled or Opportunistic Attacker
**Target Asset:** Medical IoT — BD Alaris infusion pumps and patient monitors
**Expected Impact:** Clinical disruption and possible patient-safety consequences; primarily affects integrity and availability.

### Step 1 — Initial Access

**Vector:** Vulnerable software exploit
**Surface:** External
**Detail:** An automated scanner identifies Apache 2.4.29 on `billing-srv-01` and exploits a known remote-code-execution weakness. MedDefense has already experienced a similar compromise when a crypto-miner was installed on this server.

### Step 2 — Establish Foothold

**Action:** The attacker installs a web shell, mining tool or remote-access utility and uses the server for continued access.
**MedDefense Weakness:** **M-04** allows malware to remain active because server logs are not centralized and servers do not have Sophos endpoint protection.

### Step 3 — Lateral Movement and Escalation

**Action:** The attacker scans the internal network and discovers medical-device web interfaces on ports 80 and 443. The attacker tests default vendor credentials against pumps and monitors.
**MedDefense Weakness:** **M-01** allows `billing-srv-01` to communicate directly with medical devices. **M-03** confirms that medical devices are not isolated and may use default credentials.

### Step 4 — Objective Execution

**Action:** The attacker changes a device configuration, disrupts connectivity or installs malware on a reachable medical interface.
**Data/System Affected:** BD Alaris infusion pumps, Philips patient monitors or the nurse call system.

### Step 5 — Impact

**Business Impact:** Removal of devices from service, delayed care, manual monitoring, safety investigation and possible patient harm.
**CIA Pillars:**

* **Confidentiality:** Device or patient-monitoring information may be exposed.
* **Integrity:** Device configurations or dosage information may be changed.
* **Availability:** Pumps, monitors or nurse call services may stop functioning.

**Gaps Exploited:** M-01, M-03 and M-04, plus the unnumbered patch-management weakness

**Break Points:**

* **Step 1:** Patch or replace `billing-srv-01`, remove unnecessary exposure and deploy server endpoint protection.
* **Step 2:** Use SIEM and EDR alerts for new web shells, mining traffic and unusual server processes.
* **Step 3:** Place medical devices in a dedicated VLAN with strict access rules.
* **Step 4:** Change default credentials and restrict device administration to approved clinical engineering workstations.

The scan found medical-device management interfaces on the same reachable environment as servers and workstations, while the MRI workstation also runs unsupported Windows XP.

---

## Kill Chain #4: Shadow IT to EHR Data Exposure

**Threat Actor:** Insider — Negligent, followed by an external opportunistic attacker
**Target Asset:** EHR System — patient records from `ehr-srv-01` and `ehr-db-01`
**Expected Impact:** Unauthorized disclosure of patient data and a possible internal foothold; mainly affects confidentiality.

### Step 1 — Initial Access

**Vector:** Unmanaged endpoint or shadow IT
**Surface:** Internal and Human
**Detail:** An employee connects a personal NAS, Raspberry Pi or unmanaged tablet to the MedDefense network for convenience. The device uses weak credentials, outdated software or an accidentally exposed internet service.

### Step 2 — Establish Foothold

**Action:** An external attacker finds and compromises the unmanaged device, then installs a backdoor.
**MedDefense Weakness:** MedDefense has an incomplete asset inventory, no Network Access Control and no MDM for physician iPads. Unknown Linux devices have already appeared on the network.

### Step 3 — Lateral Movement and Escalation

**Action:** The attacker uses the unmanaged device to scan the internal network and connect to EHR services or employee workstations.
**MedDefense Weakness:** **M-01** means an unknown device can communicate with critical servers. **M-04** means the new device and scanning activity may not be detected.

### Step 4 — Objective Execution

**Action:** The attacker steals patient files stored on the personal device or uses captured credentials to access the EHR. Data is uploaded to an external service.
**Data/System Affected:** Convenience copies of patient files, EHR accounts and patient records.

### Step 5 — Impact

**Business Impact:** Patient notification, regulatory reporting, forensic costs and loss of trust.
**CIA Pillars:**

* **Confidentiality:** Patient information is disclosed.
* **Integrity:** The attacker may change files or account settings.
* **Availability:** Usually limited, unless the device is used to introduce ransomware.

**Gaps Exploited:** M-01 and M-04, plus unnumbered gaps for incomplete asset inventory, no MDM and no DLP

**Break Points:**

* **Step 1:** Deploy Network Access Control to block unapproved devices.
* **Step 2:** Require MDM and minimum security standards for mobile and personal devices.
* **Step 3:** Segment unmanaged, guest and medical-device networks from EHR servers.
* **Step 4:** Use DLP to detect patient records copied to personal devices, email or cloud storage.

The First Watch assessment identifies unrestricted USB use, no DLP, no MDM and unknown devices operating inside MedDefense’s network.

---

## Kill Chain #5: Compromised EHR Vendor Access

**Threat Actor:** Organized Crime or Supply Chain Attacker
**Target Asset:** EHR System — `ehr-srv-01` and `ehr-db-01`
**Expected Impact:** Large-scale PHI theft, EHR manipulation and clinical downtime; affects confidentiality, integrity and availability.

### Step 1 — Initial Access

**Vector:** Supply chain compromise
**Surface:** External
**Detail:** An attacker compromises MedTech Solutions through phishing, malware or stolen support credentials. The attacker then uses MedTech’s trusted maintenance access to connect to MedDefense.

### Step 2 — Establish Foothold

**Action:** The attacker uses the vendor session to create a hidden account, deploy a remote-access tool or modify the EHR application.
**MedDefense Weakness:** Vendor access is not consistently protected by MFA, time-limited approval or centralized session recording.

### Step 3 — Lateral Movement and Escalation

**Action:** From `ehr-srv-01`, the attacker connects to `ehr-db-01` through PostgreSQL port 5432 and searches for Active Directory, backups and other servers.
**MedDefense Weakness:** The EHR database is reachable across the internal network, and **M-01** does not restrict the vendor session to only required systems.

### Step 4 — Objective Execution

**Action:** The attacker exports patient records, changes EHR application code or encrypts the EHR servers.
**Data/System Affected:** Patient demographics, medical histories, treatment information, insurance data and the EHR application.

### Step 5 — Impact

**Business Impact:** Loss of EHR access, incorrect or unavailable patient information, regulatory penalties, legal claims and damage to trust in MedDefense and its vendor.
**CIA Pillars:**

* **Confidentiality:** Patient records are stolen.
* **Integrity:** Medical records or application code may be modified.
* **Availability:** The EHR may become unavailable.

**Gaps Exploited:** M-01, M-04 and M-05, plus unnumbered third-party access and DLP gaps

**Break Points:**

* **Step 1:** Require vendor MFA, unique accounts and immediate notification of vendor security incidents.
* **Step 2:** Use a controlled jump server with time-limited access and full session recording.
* **Step 3:** Restrict MedTech access to `ehr-srv-01` and permit database connections only from approved application accounts.
* **Step 4:** Monitor unusual EHR exports and use DLP to block large unauthorized transfers.

The Asset Registry confirms that MedTech Solutions provides EHR maintenance, while the flat architecture places the EHR application and database inside the wider reachable network.

## Overall Break-Point Assessment

The most valuable defensive controls are **MFA, network segmentation, centralized monitoring and isolated backups**. MFA can stop stolen credentials at initial access. Segmentation can stop a compromised user, vendor or server from reaching every critical asset. SIEM and EDR can detect the attack before objective execution, while immutable backups reduce the final ransomware impact. These controls break several kill chains at once rather than addressing only one attack method.

