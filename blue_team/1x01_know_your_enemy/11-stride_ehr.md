# STRIDE Threat Model — MedDefense EHR System

## System Scope

The EHR environment includes:

* `ehr-srv-01` — Ubuntu 20.04 application server using ports 22, 443 and 8080
* `ehr-db-01` — Ubuntu 20.04 PostgreSQL server using ports 22 and 5432
* Clinical workstations used by doctors, nurses and administrative staff
* Network connections between workstations, the application server and database

PostgreSQL port 5432 is accessible from the entire internal network, and MedDefense has no internal network segmentation.

---

## Spoofing

### EHR-S1 — Stolen Clinician Account

**Category:** S — Spoofing
**Description:** An attacker uses a stolen doctor or nurse account to log in to the EHR and appears to be a legitimate clinical employee.
**Attack Vector:** Phishing, smishing, vishing or credential theft from a compromised workstation.
**Impact:** The attacker could view patient records, enter false information or collect data for extortion.
**Existing Control:** **C-009 Password Requirements Policy**, **C-010 Account Lockout** and **C-011 Password History**.
**Gap:** **M-05: No MFA on Any System.** EHR access depends only on a username and password.

### EHR-S2 — Compromised Vendor Identity

**Category:** S — Spoofing
**Description:** An attacker compromises a MedTech Solutions support account and connects to `ehr-srv-01` while appearing to be an approved maintenance technician.
**Attack Vector:** Supply-chain compromise or stolen vendor credentials.
**Impact:** The attacker could access the EHR application, install malware or create another account for persistent access.
**Existing Control:** **C-005 SSH Key Authentication**, **C-006 SSH Root Login Disabled** and **C-007 SSH Login Attempt Limit** protect SSH access to `ehr-srv-01`.
**Gap:** **M-05** and the unnumbered third-party access gap. Vendor access is not consistently protected by MFA, time limits or session monitoring.

---

## Tampering

### EHR-T1 — Unauthorized Patient Record Modification

**Category:** T — Tampering
**Description:** A malicious employee or attacker using a stolen account changes medication, allergy, diagnosis or treatment information in the EHR.
**Attack Vector:** Malicious insider or stolen EHR credentials.
**Impact:** Clinicians may make decisions based on incorrect information, creating a direct patient-safety risk.
**Existing Control:** **C-022 Local System and Application Logging** records EHR activity.
**Gap:** **M-04: Absence of Monitoring and Detection.** EHR logs are vendor-managed, take up to 48 hours to obtain and do not generate automated alerts.

### EHR-T2 — EHR Application or Database Tampering

**Category:** T — Tampering
**Description:** An attacker changes EHR application files on `ehr-srv-01` or directly modifies records in `ehr-db-01`.
**Attack Vector:** Compromised vendor access, vulnerable application exploit or lateral movement from another internal system.
**Impact:** Large numbers of patient records could be changed, deleted or corrupted without authorization.
**Existing Control:** **C-005 SSH Key Authentication**, **C-006 SSH Root Login Disabled** and nightly backups under **C-014**.
**Gap:** **M-01: Network Segmentation** because PostgreSQL port 5432 is accessible network-wide, plus the unnumbered lack of formal change management.

---

## Repudiation

### EHR-R1 — User Denies Accessing a Patient Record

**Category:** R — Repudiation
**Description:** An employee views a patient record without a valid clinical reason and later denies performing the action.
**Attack Vector:** Valid account misuse, unattended workstation or stolen credentials.
**Impact:** MedDefense may be unable to prove who disclosed protected health information or respond quickly to a privacy complaint.
**Existing Control:** **C-022 Local System and Application Logging** and the EHR audit log.
**Gap:** **M-04.** Audit data is not centralized, reviewed continuously or protected by automated integrity controls.

### EHR-R2 — Administrator Deletes Evidence of Changes

**Category:** R — Repudiation
**Description:** A privileged user changes the EHR configuration or database and then clears local logs to hide the activity.
**Attack Vector:** Malicious administrator, compromised administrator credentials or supply-chain access.
**Impact:** MedDefense may not be able to reconstruct the incident, identify affected patients or prove what was changed.
**Existing Control:** **C-008 SSH Security Logging** and **C-022 Local System and Application Logging**.
**Gap:** **M-04.** Logs remain on local systems with no central collection, write-once storage or automated alerting.

---

## Information Disclosure

### EHR-I1 — Direct Access to the EHR Database

**Category:** I — Information Disclosure
**Description:** An attacker on any internal subnet connects to PostgreSQL port 5432 on `ehr-db-01` and attempts to steal patient information.
**Attack Vector:** Compromised workstation, VPN account, shadow IT device or vulnerable internal server.
**Impact:** Patient identities, diagnoses, treatments and insurance information could be exposed.
**Existing Control:** Database authentication and **C-009 Password Requirements Policy** provide partial protection.
**Gap:** **M-01.** Database access should be limited to `ehr-srv-01`, but it is currently available across the internal network.

### EHR-I2 — Patient Data Copied to an Unmanaged Device

**Category:** I — Information Disclosure
**Description:** A clinician or other employee copies EHR records to a USB drive, personal NAS, unmanaged iPad, email account or cloud service.
**Attack Vector:** Negligent or malicious insider using removable devices or shadow IT.
**Impact:** Protected health information could be lost, stolen or disclosed outside MedDefense.
**Existing Control:** **C-012 Sophos Endpoint Protection** and **C-013 Malware Detection and Quarantine** protect most managed Windows workstations from malware.
**Gap:** No numbered gap was created for this issue. The First Watch assessment identified no DLP, unrestricted USB storage and no MDM for physician iPads.

---

## Denial of Service

### EHR-D1 — EHR Ransomware Encryption

**Category:** D — Denial of Service
**Description:** Ransomware encrypts `ehr-srv-01`, `ehr-db-01` and the backup NAS after an attacker gains domain or internal network access.
**Attack Vector:** VPN exploit, phishing, stolen credentials or supply-chain compromise.
**Impact:** Clinicians lose access to patient histories, medication details and treatment information, forcing manual operations and possible ambulance diversion.
**Existing Control:** **C-014 Nightly Veeam Backups** and limited restore testing under **C-015**.
**Gap:** **M-02: Backup Isolation** and **M-01.** Production systems and backups are reachable on the same network, and no immutable offsite copy exists.

### EHR-D2 — Application or Database Resource Exhaustion

**Category:** D — Denial of Service
**Description:** A compromised internal device sends excessive requests to EHR ports 443 or 8080, or opens many PostgreSQL connections on port 5432.
**Attack Vector:** Compromised workstation, malicious insider or malware inside the flat network.
**Impact:** The EHR becomes slow or unavailable during clinical operations, delaying treatment and registration.
**Existing Control:** The FortiGate provides external filtering through **C-001 Inbound Web Traffic Filtering** and **C-002 Default Deny Firewall Rule**.
**Gap:** **M-01** and **M-04.** The firewall does not separate internal devices, and there is no IDS or automated alerting for abnormal internal traffic.

---

## Elevation of Privilege

### EHR-E1 — Clinician Account Becomes Administrative Access

**Category:** E — Elevation of Privilege
**Description:** An attacker compromises a clinical workstation, steals privileged credentials from memory and gains EHR, server or domain administrator rights.
**Attack Vector:** Phishing, malware, credential dumping and lateral movement.
**Impact:** The attacker could change EHR permissions, create accounts, disable controls and access all patient records.
**Existing Control:** **C-009 Password Requirements Policy**, **C-010 Account Lockout**, **C-012 Sophos Endpoint Protection** and **C-013 Malware Detection and Quarantine**.
**Gap:** **M-01**, **M-04** and **M-05.** Workstations can reach critical servers, privileged access has no MFA and credential-dumping activity may not be detected.

### EHR-E2 — Application Exploit Gains Server or Database Privileges

**Category:** E — Elevation of Privilege
**Description:** An attacker exploits the EHR application on port 8080 or abuses a service account to move from normal application access to operating-system or database administrator access.
**Attack Vector:** Vulnerable software exploit, compromised vendor session or misuse of excessive service-account permissions.
**Impact:** The attacker gains control of the EHR application and database, allowing data theft, tampering or ransomware deployment.
**Existing Control:** **C-005 SSH Key Authentication**, **C-006 SSH Root Login Disabled**, **C-007 SSH Login Attempt Limit** and **C-008 SSH Security Logging** reduce direct SSH attacks.
**Gap:** **M-04** and the unnumbered patch-management and least-privilege gaps. Current SSH protections do not stop privilege escalation through the EHR application itself.

---

## STRIDE Summary for EHR

**Tampering represents the greatest risk to the MedDefense EHR system.** Information disclosure and denial of service are also serious, but incorrect clinical data may directly influence medication, diagnosis and treatment decisions. An attacker does not need to delete the entire database to cause harm; changing one allergy, dosage or patient identity could lead to an unsafe medical decision. This risk is increased by the flat network under **M-01**, the lack of MFA under **M-05**, and the absence of real-time monitoring under **M-04**. MedDefense may therefore fail to detect that a record was changed until a clinician relies on the incorrect information.

