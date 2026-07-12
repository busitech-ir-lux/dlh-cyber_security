# MedDefense Security Control Inventory

## C-001

**Control Name:** Inbound Web Traffic Filtering  
**Description:** The FortiGate allows only HTTP and HTTPS traffic from the internet to `web-srv-01` in the DMZ.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Public website, patient portal, internal network  
**Source:** Artifact 1 – Firewall Configuration

---

## C-002

**Control Name:** Default Deny Firewall Rule  
**Description:** The FortiGate blocks traffic that is not allowed by another firewall rule and records the denied traffic.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Central network, servers and DMZ  
**Source:** Artifact 1 – Firewall Configuration

---

## C-003

**Control Name:** Firewall Traffic Logging  
**Description:** The FortiGate records accepted and denied network traffic. Logs are stored locally for 30 days.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Central network, VPN connections and public web server  
**Source:** Artifacts 1 and 8 – Firewall Configuration and Log Management

---

## C-004

**Control Name:** VPN Connections  
**Description:** Westside Clinic and Corporate HQ connect to Central through VPN tunnels. The VPN protects data while it travels between sites.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Inter-site communications and Central server subnet  
**Source:** Artifact 1 – Firewall Configuration

---

## C-005

**Control Name:** SSH Key Authentication  
**Description:** `ehr-srv-01` accepts SSH keys and does not allow password authentication.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** EHR application server  
**Source:** Artifact 2 – SSH Configuration

---

## C-006

**Control Name:** SSH Root Login Disabled  
**Description:** Direct SSH login using the root account is disabled on `ehr-srv-01`.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** EHR application server  
**Source:** Artifact 2 – SSH Configuration

---

## C-007

**Control Name:** SSH Login Attempt Limit  
**Description:** SSH allows a maximum of three authentication attempts and gives users 60 seconds to log in.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** EHR application server  
**Source:** Artifact 2 – SSH Configuration

---

## C-008

**Control Name:** SSH Security Logging  
**Description:** SSH authentication events are recorded using verbose logging.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** EHR application server  
**Source:** Artifact 2 – SSH Configuration

---

## C-009

**Control Name:** Password Requirements Policy  
**Description:** Passwords must contain at least eight characters, including uppercase, lowercase, a number and a special character.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** Employee, contractor and vendor accounts  
**Source:** Artifact 3 – Password Policy

---

## C-010

**Control Name:** Account Lockout  
**Description:** Accounts are locked for 30 minutes after five failed login attempts.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Active Directory user accounts  
**Source:** Artifact 3 – Password Policy

---

## C-011

**Control Name:** Password History  
**Description:** Active Directory remembers the last five passwords to reduce immediate password reuse.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** Windows user accounts  
**Source:** Artifact 3 – Password Policy

---

## C-012

**Control Name:** Sophos Endpoint Protection  
**Description:** Sophos scans managed Windows workstations and can block or quarantine detected malware and harmful links.  
**Category:** Technical  
**Function:** Preventive  
**Asset(s) Protected:** 372 managed Windows workstations  
**Source:** Artifact 4 – Sophos Antivirus Report

---

## C-013

**Control Name:** Malware Detection and Quarantine  
**Description:** Sophos records detected threats and blocks or quarantines them.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Managed Windows workstations  
**Source:** Artifact 4 – Sophos Antivirus Report

---

## C-014

**Control Name:** Nightly Server Backups  
**Description:** Veeam creates a full backup of selected Central servers every day at 2:00 AM and keeps backups for 14 days.  
**Category:** Technical  
**Function:** Corrective  
**Asset(s) Protected:** EHR, billing, domain controller, file server and web server data  
**Source:** Artifact 5 – Backup Configuration

---

## C-015

**Control Name:** Backup Restore Testing  
**Description:** IT performed a partial restore test of `file-srv-01` to confirm that backup data could be recovered.  
**Category:** Administrative  
**Function:** Detective  
**Asset(s) Protected:** Backup and recovery process  
**Source:** Artifact 5 – Backup Configuration

---

## C-016

**Control Name:** Visitor Registration and Badge Checking  
**Description:** A security guard registers visitors and checks badges at the Central Hospital main entrance.  
**Category:** Physical  
**Function:** Preventive  
**Asset(s) Protected:** Central Hospital staff, facilities and systems  
**Source:** Artifact 6 – Physical Security Contract

---

## C-017

**Control Name:** Security Guard Presence  
**Description:** A uniformed guard is present at the Central Hospital main entrance from Monday to Friday, 7:00 AM to 7:00 PM.  
**Category:** Physical  
**Function:** Deterrent  
**Asset(s) Protected:** Central Hospital main entrance  
**Source:** Artifact 6 – Physical Security Contract

---

## C-018

**Control Name:** Security Cameras  
**Description:** Cameras record activity at the main entrance, ER entrance and parking garage entrance.  
**Category:** Physical  
**Function:** Detective  
**Asset(s) Protected:** Selected entrances and parking access at Central Hospital  
**Source:** Artifact 6 – Physical Security Contract

---

## C-019

**Control Name:** CCTV Recording Retention  
**Description:** Central camera footage is stored on a standalone DVR for 30 days.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Physical security evidence from monitored entrances  
**Source:** Artifact 6 – Physical Security Contract

---

## C-020

**Control Name:** Annual Security Awareness Training  
**Description:** Staff complete annual training covering passwords, phishing, physical security and reporting suspicious activity.  
**Category:** Administrative  
**Function:** Preventive  
**Asset(s) Protected:** Staff accounts, systems, facilities and organizational information  
**Source:** Artifact 7 – Training Records

---

## C-021

**Control Name:** Security Incident Reporting Training  
**Description:** The training teaches employees to report suspicious activity.  
**Category:** Administrative  
**Function:** Detective  
**Asset(s) Protected:** Organization-wide systems and information  
**Source:** Artifact 7 – Training Records

---

## C-022

**Control Name:** Local System Logging  
**Description:** Windows, Linux, Apache, Active Directory and the EHR application create logs that can be reviewed after an event.  
**Category:** Technical  
**Function:** Detective  
**Asset(s) Protected:** Servers, applications, Active Directory and EHR records  
**Source:** Artifact 8 – Log Management

---

# Control Summary Matrix

|Category|Preventive|Detective|Corrective|Compensating|Deterrent|
|---|---|---|---|---|---|
|**Technical**|C-001, C-002, C-004, C-005, C-006, C-007, C-010, C-011, C-012|C-003, C-008, C-013, C-019, C-022|C-014|||
|**Administrative**|C-009, C-020|C-015, C-021||||
|**Physical**|C-016|C-018|||C-017|

## Main gaps shown by the matrix

- No clear **compensating controls** were found.
    
- No administrative or physical **corrective controls** were documented.
    
- No technical **deterrent control** was identified.
    
- Several existing controls are incomplete or weak, such as overly broad VPN access, limited antivirus coverage and local-only backups.
    

