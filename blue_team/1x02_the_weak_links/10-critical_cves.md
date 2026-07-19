# The Critical CVEs

## 1. Finding 001

**Finding:** 001
**CVE:** CVE-2021-44790
**Host:** `billing-srv-01` — `10.10.2.15`
**Asset Role:** Billing application and financial-data server
**Asset Criticality:** Confidentiality: High, Integrity: High, Availability: High

### Technical Analysis

**Vulnerability Description:** Apache `mod_lua` can suffer a buffer overflow from a crafted remote request, possibly allowing unauthenticated code execution.

**CVSS Base Score:** 9.8 — Critical
**Exploit Availability:** 3/5 — public PoC exists, but reliable code execution needs more work
**CISA KEV Status:** Not listed
**CWE:** CWE-787 — Out-of-bounds Write

### Contextual Analysis

**Network Exposure:** Reachable through port 80 from the flat internal network.
**Kill Chain Position:** Initial access and execution on the billing server.
**Threat Actor:** Ransomware group using vulnerable public or internal services.
**Related Findings:** Combines with Finding 002 for root privilege escalation, Finding 006 for MySQL exposure and Finding 011 for unsupported Ubuntu.

**Adjusted Priority:** Critical

**Justification:** It is remotely exploitable without authentication, affects a critical server and can start a complete compromise chain.

---

## 2. Finding 003

**Finding:** 003
**CVE:** N/A — Misconfiguration
**Host:** `ehr-db-01` — `10.10.2.11`
**Asset Role:** Stores patient records and protected health information
**Asset Criticality:** Confidentiality: Critical, Integrity: Critical, Availability: High

### Technical Analysis

**Vulnerability Description:** PostgreSQL accepts connections from every system in `10.10.0.0/16` instead of only the EHR application server.

**CVSS Base Score:** N/A
**Exploit Availability:** N/A — no exploit is required
**CISA KEV Status:** N/A
**CWE:** N/A — configuration weakness

### Contextual Analysis

**Network Exposure:** Reachable from any compromised host on the flat internal network.
**Kill Chain Position:** Credential access, collection and patient-data theft after initial compromise.
**Threat Actor:** Ransomware group or malicious insider.
**Related Findings:** Combines with Finding 031, which may expose EHR database credentials.

**Adjusted Priority:** Critical

**Justification:** An attacker who compromises any internal device could directly target the patient database. No CVE exploit is needed.

---

## 3. Finding 004

**Finding:** 004
**CVE:** CVE-2017-0144 and other unpatched CVEs
**Host:** `WS-RAD-01` — `10.10.1.70`
**Asset Role:** MRI scanner control workstation
**Asset Criticality:** Confidentiality: High, Integrity: Critical, Availability: Critical

### Technical Analysis

**Vulnerability Description:** The workstation runs unsupported Windows XP and exposes vulnerable SMB and RDP services.

**CVSS Base Score:** CVE-2017-0144: 8.1 — High
**Exploit Availability:** 5/5 — weaponized EternalBlue exploit
**CISA KEV Status:** Listed
**CWE:** CWE-119 — Memory-buffer weakness

### Contextual Analysis

**Network Exposure:** Reachable from the workstation subnet with no VLAN isolation.
**Kill Chain Position:** Execution, lateral movement and disruption of clinical equipment.
**Threat Actor:** Ransomware group using SMB exploitation.
**Related Findings:** Flat-network exposure increases the effect of Findings 007, 018 and 019.

**Adjusted Priority:** Critical

**Justification:** The device controls an MRI system, cannot receive normal patches and is vulnerable to mature ransomware-related exploits. NVD records active exploitation of CVE-2017-0144.

---

## 4. Finding 007

**Finding:** 007
**CVE:** N/A — Misconfiguration
**Host:** `ad-dc-01` — `10.10.2.20`
**Asset Role:** Primary Active Directory domain controller
**Asset Criticality:** Confidentiality: Critical, Integrity: Critical, Availability: Critical

### Technical Analysis

**Vulnerability Description:** LDAP signing is not required and SMBv1 is enabled, allowing relay attacks and exposing an unsafe legacy protocol.

**CVSS Base Score:** N/A
**Exploit Availability:** N/A — standard attack tools can abuse the configuration
**CISA KEV Status:** N/A
**CWE:** N/A — configuration weakness

### Contextual Analysis

**Network Exposure:** Reachable from all hosts on the flat internal network.
**Kill Chain Position:** Credential access, privilege escalation and domain takeover.
**Threat Actor:** Ransomware group or advanced external attacker using credential relay.
**Related Findings:** Combines with weak Kerberos encryption in Finding 018 and DNS information exposure in Finding 025.

**Adjusted Priority:** Critical

**Justification:** Active Directory controls identities and access across MedDefense. Compromise could provide control over almost every connected system.

---

## 5. Finding 031

**Finding:** 031
**CVE:** CVE-2020-1938
**Host:** `ehr-srv-01` — `10.10.2.10`
**Asset Role:** Main EHR application server
**Asset Criticality:** Confidentiality: Critical, Integrity: Critical, Availability: Critical

### Technical Analysis

**Vulnerability Description:** The exposed Tomcat AJP connector allows an unauthenticated attacker to read application files, including files that may contain database credentials.

**CVSS Base Score:** 9.8 — Critical
**Exploit Availability:** 5/5 — working PoCs and a Metasploit module exist
**CISA KEV Status:** Listed
**CWE:** NVD-CWE-Other

### Contextual Analysis

**Network Exposure:** Port 8009 is reachable from compromised hosts on the flat network.
**Kill Chain Position:** Credential access and collection after initial internal compromise.
**Threat Actor:** Ransomware group seeking EHR credentials and patient data.
**Related Findings:** Combines directly with Finding 003 because stolen credentials could be used against the exposed PostgreSQL database.

**Adjusted Priority:** Critical

**Justification:** The vulnerability affects the EHR server, has automated exploitation and can expose credentials leading directly to patient data. NVD records active and automatable exploitation for CVE-2020-1938.

