# MITRE ATT&CK Mapping — MedDefense

## Scenario Alpha: Operation Flatline

### Step 1: FortiGate target list purchased from an access broker

**Tactic:** Reconnaissance
**Technique:** **Active Scanning: Scanning IP Blocks — T1595.001**
**Alternative:** Active Scanning: Vulnerability Scanning — T1595.002

**MedDefense Factor:** MedDefense’s FortiGate interface is externally visible and can be associated with a healthcare organization through public information. The broker sold only targeting information, not confirmed access; therefore, Acquire Access — T1650 is not the best primary mapping.

---

### Step 2: Fortinet-themed spearphishing email and malicious document

**Tactic:** Initial Access
**Technique:** **Phishing: Spearphishing Link — T1566.002**

**Alternatives:**

* User Execution: Malicious File — T1204.002
* Command and Scripting Interpreter: PowerShell — T1059.001

**MedDefense Factor:** Sarah Park is responsible for the FortiGate and is likely to react to an urgent firmware warning. The fake portal and malicious document exploit her authority and responsibility.

---

### Step 3: Reverse shell and persistent scheduled task

**Tactic:** Persistence
**Technique:** **Scheduled Task/Job: Scheduled Task — T1053.005**

**Alternative:** Command and Control through the reverse-shell connection

**MedDefense Factor:** Sarah has local administrator rights, allowing the attacker to create a scheduled task disguised as Windows Update. MedDefense has no centralized monitoring to detect the recurring task or repeated outbound connections.

---

### Step 4: Internal network and system discovery

**Tactic:** Discovery
**Technique:** **Remote System Discovery — T1018**

**Alternatives:**

* Permission Groups Discovery: Domain Groups — T1069.002
* Network Service Discovery — T1046

**MedDefense Factor:** The flat network and permissive HQ-to-Central VPN allow Sarah’s compromised workstation to discover systems throughout `10.10.0.0/16`. The `net group "Domain Admins"` command also reveals privileged domain groups.

---

### Step 5: Mimikatz dumps the `svc_backup` hash

**Tactic:** Credential Access
**Technique:** **OS Credential Dumping: LSASS Memory — T1003.001**

**MedDefense Factor:** Sarah has local administrator rights, and a highly privileged backup account was previously used on her workstation. This left reusable credential material in memory.

---

### Step 6: Pass-the-hash access to `ad-dc-01`

**Tactic:** Lateral Movement
**Technique:** **Use Alternate Authentication Material: Pass the Hash — T1550.002**

**Alternative:** Valid Accounts — T1078

**MedDefense Factor:** The captured NTLM hash belongs to a Domain Admin service account. The flat network allows the compromised HQ workstation to authenticate directly to the domain controller.

---

### Step 7: Patient and business data exfiltrated with Rclone

**Tactic:** Exfiltration
**Technique:** **Exfiltration Over Web Service: Exfiltration to Cloud Storage — T1567.002**

**Alternatives:**

* Data from Information Repositories: Databases — T1213.006
* Archive Collected Data — T1560.001

**MedDefense Factor:** PostgreSQL port 5432 is accessible across the network, and Domain Admin access provides a path to patient, HR and financial information. MedDefense has no DLP or outbound-transfer alerts to detect Rclone uploading 43 GB over HTTPS.

---

### Step 8: Backups and Volume Shadow Copies deleted

**Tactic:** Impact
**Technique:** **Inhibit System Recovery — T1490**

**MedDefense Factor:** `NAS-01` is on the production network and its management interface is reachable internally. The attacker can delete both central backups and Windows Volume Shadow Copies before encryption.

---

### Step 9: Ransomware deployed through Group Policy

**Tactic:** Impact
**Technique:** **Data Encrypted for Impact — T1486**

**Alternatives:**

* Domain Policy Modification: Group Policy Modification — T1484.001
* Remote Services: SSH — T1021.004 for the Linux servers

**MedDefense Factor:** Domain Admin access allows the affiliate to deploy ransomware to all domain-joined Windows devices. The flat network and exposed credentials also permit separate SSH attacks against Linux servers.

---

## Scenario Beta: The Quiet Departure

### Step 1: Maria decides to misuse her legitimate access

**Tactic:** Initial Access
**Technique:** **Valid Accounts: Domain Accounts — T1078.002**

**MedDefense Factor:** Maria already has legitimate billing and read-only EHR access. Because she is an authorized insider, this is the closest ATT&CK mapping rather than a traditional external compromise. Her valid account allows malicious activity to resemble normal employee work.

---

### Step 2: Maria identifies the patient information available to her

**Tactic:** Discovery
**Technique:** **File and Directory Discovery — T1083**, as the closest available fit

**Alternative:** Data from Information Repositories: Databases — T1213.006

**MedDefense Factor:** Billing and EHR permissions expose more patient information than Maria requires. The applications do not warn on unusual record volumes or clearly restrict access based on treatment relationship.

ATT&CK does not have a precise technique for reviewing application-level data entitlements, so T1083 is an approximate mapping.

---

### Step 3: Patient records exported from the EHR

**Tactic:** Collection
**Technique:** **Data from Information Repositories: Databases — T1213.006**

**Alternative:** Automated Collection — T1119, if the exports were scripted

**MedDefense Factor:** The EHR export function is available to all read-only users, has no record-volume limit and does not require additional approval. Audit logs exist but are not reviewed proactively.

---

### Step 4: CSV files copied to a personal USB drive

**Tactic:** Exfiltration
**Technique:** **Exfiltration Over Physical Medium: Exfiltration over USB — T1052.001**

**MedDefense Factor:** MedDefense has no USB restriction Group Policy and no DLP control. Staff commonly use personal USB drives without challenge or monitoring.

---

### Step 5: Maria deletes the local CSV files

**Tactic:** Defense Evasion
**Technique:** **Indicator Removal: File Deletion — T1070.004**

**MedDefense Factor:** Maria can delete files from her workstation without generating an alert. The EHR audit logs remain available, but MedDefense does not review them and requires a vendor request to export them.

---

### Step 6: Database credentials copied from a configuration file

**Tactic:** Credential Access
**Technique:** **Unsecured Credentials: Credentials In Files — T1552.001**

**MedDefense Factor:** The billing application stores reusable database credentials in a workstation configuration file. This gives Maria a method to access the database outside the normal billing application.

---

### Step 7: Maria’s account remains active after departure

**Tactic:** Persistence
**Technique:** **Valid Accounts: Domain Accounts — T1078.002**

**MedDefense Factor:** Offboarding depends on a manual IT ticket, has no completion SLA and is not linked to HR termination records. Maria therefore keeps a valid domain and VPN account for five days.

---

### Step 8: Former employee reconnects through VPN and extracts records

**Tactic:** Persistence
**Technique:** **External Remote Services — T1133**

**Alternatives:**

* Valid Accounts: Domain Accounts — T1078.002
* Data from Information Repositories: Databases — T1213.006

**MedDefense Factor:** Maria’s VPN credentials remain valid after termination, and remote access does not require MFA. The retained database credentials then allow her to connect to `billing-srv-01` and collect additional records.

---

# ATT&CK Coverage Assessment

Both attacks include **Initial Access, Persistence, Discovery, Credential Access, Collection and Exfiltration** behavior, although the ransomware scenario also adds Lateral Movement and Impact. This shows that MedDefense needs detection most urgently around identities, endpoints and sensitive-data movement. Priority monitoring should include unusual VPN logins, accounts used after termination, scheduled-task creation, LSASS access, internal network discovery, abnormal EHR or database exports, USB copying and large HTTPS uploads to cloud-storage services. Centralizing these events in a SIEM would help MedDefense detect both an advanced ransomware affiliate and an employee misusing legitimate access before the final impact occurs.

