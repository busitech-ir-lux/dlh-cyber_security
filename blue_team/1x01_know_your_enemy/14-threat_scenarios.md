# The Three MedDefense Threat Scenarios

## Scenario 1 — BlackReef VPN-to-Ransomware Attack

**Threat Actor:** Organized crime — BlackReef RaaS affiliate
**Motivation:** Financial gain and blackmail
**Initial Vector:** Exploitation of the FortiGate VPN appliance
**Attack Surface Exploited:** External surface

### Attack Sequence

**Step 1 — Initial Access:**
The affiliate exploits an unpatched FortiGate vulnerability and gains access to the MedDefense internal network.
**ATT&CK Tactic:** Initial Access

**Step 2 — Persistence:**
The attacker installs a backdoor or creates a scheduled task so access continues if the original VPN session closes.
**ATT&CK Tactic:** Persistence

**Step 3 — Network Mapping:**
The attacker scans the flat `10.10.0.0/16` network and identifies `ad-dc-01`, `ehr-db-01`, `file-srv-01` and `NAS-01`.
**ATT&CK Tactic:** Discovery

**Step 4 — Credential Theft:**
Credential-dumping tools are used to obtain a privileged service-account or Domain Admin credential.
**ATT&CK Tactic:** Credential Access

**Step 5 — Domain Compromise:**
The attacker uses the stolen credential to access `ad-dc-01` and obtain control of Active Directory.
**ATT&CK Tactics:** Lateral Movement and Privilege Escalation

**Step 6 — Data Theft:**
Patient records, employee information and financial documents are compressed and uploaded to attacker-controlled cloud storage.
**ATT&CK Tactics:** Collection and Exfiltration

**Step 7 — Recovery Destruction:**
The attacker accesses `NAS-01`, deletes backup jobs and removes Windows Volume Shadow Copies.
**ATT&CK Tactic:** Impact

**Step 8 — Ransomware Deployment:**
BlackReef ransomware is distributed through Group Policy to domain-connected systems. The attackers demand payment for decryption and for not publishing the stolen data.
**ATT&CK Tactic:** Impact

BlackReef’s normal playbook includes network discovery, credential theft, data exfiltration, backup destruction and ransomware deployment. Its affiliates commonly target healthcare through vulnerable VPN appliances.

### STRIDE Categories Triggered

* **Spoofing:** Stolen administrator identities are used.
* **Tampering:** Group Policy, files and system settings are changed.
* **Repudiation:** Logs may be cleared to hide attacker activity.
* **Information Disclosure:** EHR and employee data are stolen.
* **Denial of Service:** Clinical and administrative systems are encrypted.
* **Elevation of Privilege:** The attacker becomes Domain Admin.

### MedDefense Assets Impacted

* `ad-dc-01` and `ad-dc-02`
* `ehr-srv-01` and `ehr-db-01`
* `billing-srv-01`
* `file-srv-01`
* `backup-srv-01` and `NAS-01`
* Clinical and administrative workstations
* Potentially PACS and medical devices

### Business Impact

* **Clinical:** Loss of EHR access, procedure cancellations and possible ambulance diversion.
* **Financial:** Ransom demand, recovery costs and lost patient revenue.
* **Regulatory:** Breach notification and investigation following PHI theft.
* **Reputational:** Loss of patient and community trust.

### Gaps Exploited

* **M-01 — Network Segmentation:** The flat network allows movement from the VPN to every critical system.
* **M-02 — Backup Isolation:** Backups are on the production network and can be deleted.
* **M-04 — Monitoring and Detection:** No SIEM or automated alerts identify pre-encryption activity.
* **M-05 — No MFA:** Stolen accounts can be used without a second factor.
* **Unnumbered patch-management gap:** Delayed VPN patching creates the initial entry point.

These gaps closely match the attack conditions identified in the First Watch assessment.

### Detection Opportunities

* **Steps 1–2:** VPN monitoring could detect unusual source locations, exploitation attempts and unexpected sessions.
* **Steps 3–4:** EDR and SIEM rules could detect network scanning, Mimikatz and LSASS access.
* **Step 6:** DLP and outbound-traffic monitoring could identify large encrypted uploads.
* **Step 7:** Backup alerts could immediately report deletion or configuration changes.
* **Step 8:** Group Policy monitoring could detect unauthorized deployment changes.

---

## Scenario 2 — Billing Employee Steals Patient Records

**Threat Actor:** Malicious insider — billing department employee
**Motivation:** Financial gain
**Initial Vector:** Abuse of legitimate EHR and billing access
**Attack Surface Exploited:** Internal and human surfaces

### Attack Sequence

**Step 1 — Valid Access:**
The employee uses her legitimate billing and read-only EHR account during normal working hours.
**ATT&CK Tactic:** Initial Access

**Step 2 — Access Review:**
She identifies which patient, insurance and prescription information can be viewed and exported through her current permissions.
**ATT&CK Tactic:** Discovery

**Step 3 — Data Export:**
She exports approximately 200 patient records each day using the EHR’s built-in CSV export function.
**ATT&CK Tactic:** Collection

**Step 4 — USB Transfer:**
The CSV files are copied to a personal USB drive because MedDefense does not restrict removable storage.
**ATT&CK Tactic:** Exfiltration

**Step 5 — Evidence Removal:**
The employee deletes the local CSV files and empties the workstation recycle bin.
**ATT&CK Tactic:** Defense Evasion

**Step 6 — Credential Collection:**
She discovers database credentials stored in a billing application configuration file and copies them to the USB drive.
**ATT&CK Tactic:** Credential Access

**Step 7 — Retained Access:**
Her VPN account remains active after termination because offboarding depends on a delayed manual ticket.
**ATT&CK Tactic:** Persistence

**Step 8 — Post-Employment Theft:**
She connects from home, uses the retained credentials to reach `billing-srv-01` and downloads additional patient records.
**ATT&CK Tactics:** Collection and Exfiltration

Healthcare insiders may use legitimate access for data theft, curiosity or revenge. Broad clinical and administrative access makes this activity difficult to distinguish from normal work without behavioral monitoring.

### STRIDE Categories Triggered

* **Spoofing:** After termination, the active account still presents her as an authorized employee.
* **Repudiation:** She deletes local evidence and may deny the activity.
* **Information Disclosure:** Patient and insurance records are removed.
* **Elevation of Privilege:** Database credentials allow her to bypass the normal application interface.

### MedDefense Assets Impacted

* `ehr-srv-01`
* `ehr-db-01`
* `billing-srv-01`
* Patient and insurance records
* Employee workstation
* VPN service

### Business Impact

* **Clinical:** Patients may lose trust in MedDefense’s handling of medical information.
* **Financial:** Investigation, notification and possible legal costs.
* **Regulatory:** Unauthorized PHI access and reportable data exposure.
* **Reputational:** Public concern that employees can remove records without detection.

### Gaps Exploited

* **M-01 — Network Segmentation:** A VPN user can directly reach internal database services.
* **M-04 — Monitoring and Detection:** EHR exports and unusual access volumes are not reviewed.
* **M-05 — No MFA:** The active VPN password remains enough to reconnect.
* **Unnumbered DLP gap:** Patient data can leave through USB without an alert.
* **Unnumbered USB-control gap:** Personal storage devices are unrestricted.
* **Unnumbered offboarding gap:** Account deactivation is manual and delayed.

The First Watch assessment specifically identifies the absence of DLP, unrestricted USB storage and weak accountability controls.

### Detection Opportunities

* **Steps 2–3:** EHR monitoring could alert when one employee accesses or exports unusually large numbers of records.
* **Step 4:** Endpoint DLP could block or record PHI copied to USB.
* **Step 5:** EDR could report bulk deletion of recently created CSV files.
* **Step 6:** File monitoring could alert when application configuration files containing secrets are accessed.
* **Step 7:** HR-integrated offboarding could disable the account immediately.
* **Step 8:** SIEM rules could detect VPN access by a terminated user.

---

## Scenario 3 — Compromised MedTech Maintenance Account

**Threat Actor:** External cybercriminal using MedTech Solutions as a stepping stone
**Motivation:** Financial gain and blackmail
**Initial Vector:** Compromised vendor maintenance credentials
**Attack Surface Exploited:** Third-party external access leading to the internal surface

### Attack Sequence

**Step 1 — Vendor Compromise:**
The attacker phishes a MedTech technician and steals their support credentials.
**ATT&CK Tactic:** Initial Access

**Step 2 — Trusted Entry:**
The attacker uses MedTech’s approved maintenance pathway to connect directly to `ehr-srv-01`. The activity appears to come from a trusted vendor.
**ATT&CK Tactic:** Initial Access

**Step 3 — Persistent Access:**
A hidden maintenance account or web shell is created on the EHR application server.
**ATT&CK Tactic:** Persistence

**Step 4 — Environment Mapping:**
The attacker examines EHR configuration files, network connections, service accounts and the location of `ehr-db-01`.
**ATT&CK Tactic:** Discovery

**Step 5 — Database Access:**
A service credential is recovered from an application configuration file and used to connect to PostgreSQL on port 5432.
**ATT&CK Tactics:** Credential Access and Lateral Movement

**Step 6 — Patient Data Collection:**
The attacker exports patient demographics, medical histories, insurance details and prescription information.
**ATT&CK Tactic:** Collection

**Step 7 — Data Exfiltration:**
The files are uploaded through HTTPS to an external cloud-storage account.
**ATT&CK Tactic:** Exfiltration

**Step 8 — Application Tampering:**
The attacker changes EHR logging or application settings to hide the activity and retain access. The stolen data is then used for blackmail or sold.
**ATT&CK Tactics:** Defense Evasion and Impact

MedTech Solutions provides EHR maintenance under a four-hour critical-response SLA, creating a trusted route to MedDefense’s most critical application.

### STRIDE Categories Triggered

* **Spoofing — EHR-S2:** The attacker appears to be a legitimate MedTech technician.
* **Tampering — EHR-T2:** EHR application files, settings or database records may be changed.
* **Repudiation — EHR-R2:** Logs may be altered or removed.
* **Information Disclosure — EHR-I1:** Direct database access exposes patient records.
* **Elevation of Privilege — EHR-E2:** Service credentials provide access beyond the original vendor session.

### MedDefense Assets Impacted

* `ehr-srv-01`
* `ehr-db-01`
* EHR service and vendor accounts
* Active Directory, if the attacker moves beyond the EHR environment
* Patient and insurance information

### Business Impact

* **Clinical:** Altered or unreliable EHR information may affect treatment decisions.
* **Financial:** Investigation, recovery, legal claims and extortion costs.
* **Regulatory:** Large-scale exposure of regulated patient information.
* **Reputational:** Loss of confidence in both MedDefense and its EHR provider.

### Gaps Exploited

* **M-01 — Network Segmentation:** Vendor access is not restricted to a tightly isolated maintenance zone.
* **M-04 — Monitoring and Detection:** Vendor sessions and database exports are not monitored centrally.
* **M-05 — No MFA:** Vendor and EHR access may depend only on credentials.
* **Unnumbered third-party access gap:** No consistent time-limited access or session recording is documented.
* **Unnumbered DLP gap:** Large exports can leave through HTTPS without detection.
* **Unnumbered least-privilege gap:** Vendor or service accounts may reach more systems than required.

The flat network, lack of MFA and absence of centralized monitoring allow a trusted vendor compromise to extend beyond the intended support activity.

### Detection Opportunities

* **Steps 1–2:** Vendor MFA and conditional-access rules could block stolen credentials.
* **Step 2:** A controlled jump server could record the vendor session and require MedDefense approval.
* **Step 3:** File-integrity monitoring could detect a new account, web shell or changed EHR file.
* **Steps 4–5:** SIEM and database monitoring could identify unusual discovery and PostgreSQL access.
* **Steps 6–7:** DLP could detect large patient-data exports and unexpected cloud uploads.
* **Step 8:** Protected, centralized audit logs could expose attempts to remove evidence.

