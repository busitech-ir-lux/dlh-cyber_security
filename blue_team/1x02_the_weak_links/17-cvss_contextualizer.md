# The CVSS Contextualizer

## Finding 001 — CVE-2021-44790

**CVSS Base Score:** 9.8

### Factor 1 — Asset Criticality

**Asset:** `billing-srv-01`  
**CIA Rating:** Confidentiality: High, Integrity: High, Availability: High  
**Criticality Impact on Priority:** Raises urgency because the server processes financial and billing data.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Billing-server compromise kill chain  
**Chain Role:** Initial access  
**Kill Chain Impact on Priority:** Raises urgency because it provides unauthenticated remote access and enables Finding 002.

### Factor 3 — Exploitability

**Exploitability Score:** 3/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Public PoC availability raises urgency, although exploitation is not known to be widespread.

### Factor 4 — Compensating Controls

**Existing Controls:** Internal placement and basic endpoint monitoring  
**Control Impact on Priority:** Controls provide little protection because the flat network allows broad access.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H`; modified impact remains High for confidentiality, integrity and availability.  
**Adjusted Score:** 9.8

**Final Priority:** Critical

**Final Justification:** The vulnerability is remotely exploitable without authentication, affects a highly critical billing system and appears at the start of a kill chain. Existing controls do not sufficiently restrict network access, and exploitation could be followed by privilege escalation through Finding 002.

---

## Finding 002 — CVE-2019-0211

**CVSS Base Score:** 7.8

### Factor 1 — Asset Criticality

**Asset:** `billing-srv-01`  
**CIA Rating:** Confidentiality: High, Integrity: High, Availability: High  
**Criticality Impact on Priority:** Raises urgency because root access would expose the complete billing system.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Billing-server compromise kill chain  
**Chain Role:** Privilege escalation after Finding 001  
**Kill Chain Impact on Priority:** Raises urgency because it converts limited web-server access into full system control.

### Factor 3 — Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Working exploit code and known exploitation significantly raise urgency.

### Factor 4 — Compensating Controls

**Existing Controls:** Requires prior local access  
**Control Impact on Priority:** This lowers standalone urgency slightly, but Finding 001 provides the required access.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H`; exploit maturity set to functional; modified privileges remain Low and attack vector remains Local.  
**Adjusted Score:** 8.4

**Final Priority:** Critical

**Final Justification:** Its base score is High rather than Critical, but it forms a reliable chain with Finding 001. The criticality of billing data, public exploit availability and ability to gain root privileges raise its environmental priority significantly.

---

## Finding 004 — CVE-2019-0708 BlueKeep

**CVSS Base Score:** 9.8

### Factor 1 — Asset Criticality

**Asset:** `WS-RAD-01` MRI workstation  
**CIA Rating:** Confidentiality: High, Integrity: Critical, Availability: Critical  
**Criticality Impact on Priority:** Strongly raises urgency because compromise could interrupt clinical imaging and patient care.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Ransomware lateral-movement and medical-device disruption kill chains  
**Chain Role:** Lateral movement target and clinical-impact target  
**Kill Chain Impact on Priority:** Raises urgency because the workstation is reachable from the flat network.

### Factor 3 — Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Weaponized exploits and known exploitation make this an immediate threat.

### Factor 4 — Compensating Controls

**Existing Controls:** Physical controls around the MRI area  
**Control Impact on Priority:** Physical controls do not prevent network exploitation; no effective VLAN isolation exists.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H`; modified availability and integrity retained as High because of patient-safety impact.  
**Adjusted Score:** 10.0

**Final Priority:** Critical

**Final Justification:** BlueKeep affects an unsupported Windows XP medical workstation, has weaponized exploits and could directly disrupt MRI operations. The flat network and lack of effective technical controls increase both exploitation likelihood and patient-safety impact.

---

## Finding 005 — Obsolete TLS on Patient Portal

**CVSS Base Score:** 7.5

### Factor 1 — Asset Criticality

**Asset:** `web-srv-01` patient portal  
**CIA Rating:** Confidentiality: Critical, Integrity: High, Availability: High  
**Criticality Impact on Priority:** Raises urgency because the portal processes patient information.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Internet-facing patient-portal kill chain  
**Chain Role:** Initial access or traffic-interception enabler  
**Kill Chain Impact on Priority:** Raises urgency because the service is exposed to internet users.

### Factor 3 — Exploitability

**Exploitability Score:** 2/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Exploitation requires specific network and client conditions, which lowers urgency.

### Factor 4 — Compensating Controls

**Existing Controls:** HTTPS is enabled and modern TLS versions are also supported  
**Control Impact on Priority:** Existing encryption partially lowers the risk, but obsolete protocols remain available.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:M/AR:L`; modified confidentiality High, integrity Low and availability Low.  
**Adjusted Score:** 6.8

**Final Priority:** Medium

**Final Justification:** Internet exposure and sensitive patient data increase concern, but this weakness is less directly exploitable than remote-code-execution findings. Modern TLS support and the need for specific interception conditions reduce the environmental score.

---

## Finding 008 — CVE-2021-34527 PrintNightmare

**CVSS Base Score:** 8.8

### Factor 1 — Asset Criticality

**Asset:** `print-srv-01`  
**CIA Rating:** Confidentiality: Medium, Integrity: High, Availability: High  
**Criticality Impact on Priority:** Raises urgency because the server is domain-connected and supports organization-wide printing.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Ransomware and domain-compromise kill chains  
**Chain Role:** Privilege escalation and lateral-movement enabler  
**Kill Chain Impact on Priority:** Raises urgency because compromise could provide privileged access and access to other systems.

### Factor 3 — Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Public weaponized exploits and known exploitation significantly raise urgency.

### Factor 4 — Compensating Controls

**Existing Controls:** Internal-only exposure  
**Control Impact on Priority:** Internal placement lowers internet exposure but provides little protection on the flat network.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:M/IR:H/AR:H`; exploit maturity set to functional; attack vector remains Network.  
**Adjusted Score:** 9.1

**Final Priority:** Critical

**Final Justification:** Although the print server is not internet-facing, it is broadly reachable internally, unsupported and affected by a weaponized KEV vulnerability. Its value for privilege escalation and lateral movement raises the score from High to Critical.

---

## Finding 010 — CVE-2020-25165 / BD Alaris Network Weakness

**CVSS Base Score:** 7.5

### Factor 1 — Asset Criticality

**Asset:** BD Alaris infusion pumps  
**CIA Rating:** Confidentiality: Medium, Integrity: Critical, Availability: Critical  
**Criticality Impact on Priority:** Raises urgency because device disruption can affect medication delivery and patient care.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Medical-device disruption kill chain  
**Chain Role:** Final patient-safety target  
**Kill Chain Impact on Priority:** Raises urgency because successful exploitation could affect clinical operations.

### Factor 3 — Exploitability

**Exploitability Score:** 2/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Exploitation requires internal network access and specific affected configurations.

### Factor 4 — Compensating Controls

**Existing Controls:** Reported firmware version 12.1.2 may already contain the vendor correction  
**Control Impact on Priority:** Significantly lowers urgency if the firmware version is verified as fixed.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:M/IR:H/AR:H`; modified attack complexity raised because of required network position and configuration; remediation level set to official fix.  
**Adjusted Score:** 5.9

**Final Priority:** Medium pending validation

**Final Justification:** Patient-safety criticality raises the potential impact, but the detected firmware may already be newer than the vulnerable version. MedDefense must validate the device version before treating it as exploitable; network isolation and removal of default credentials remain necessary.

---

## Finding 029 — CVE-2021-43798 Grafana Path Traversal

**CVSS Base Score:** 7.5

### Factor 1 — Asset Criticality

**Asset:** Undocumented Grafana server at Westside Clinic  
**CIA Rating:** Unknown; potentially High confidentiality because monitoring files and credentials may be stored  
**Criticality Impact on Priority:** Raises urgency because the asset is undocumented and its data ownership is unknown.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** Westside-to-Central VPN attack path  
**Chain Role:** Initial access and credential-discovery point  
**Kill Chain Impact on Priority:** Raises urgency because exposed files may help an attacker pivot through the clinic VPN.

### Factor 3 — Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** Yes  
**Exploit Impact on Priority:** Exploitation is unauthenticated, trivial and publicly weaponized.

### Factor 4 — Compensating Controls

**Existing Controls:** Internal Westside location  
**Control Impact on Priority:** Provides limited protection because the system is undocumented and connected to the wider environment.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:M/AR:M`; exploit maturity set to functional; modified confidentiality retained as High.  
**Adjusted Score:** 8.6

**Final Priority:** High

**Final Justification:** The unknown asset has a trivial unauthenticated file-read vulnerability and could expose credentials or configuration information. Its connection to the Westside environment and possible VPN pivot raises its priority above the original base rating.

---

## Finding 031 — CVE-2020-1938 Ghostcat

**CVSS Base Score:** 9.8

### Factor 1 — Asset Criticality

**Asset:** `ehr-srv-01`  
**CIA Rating:** Confidentiality: Critical, Integrity: Critical, Availability: Critical  
**Criticality Impact on Priority:** Strongly raises urgency because the server supports the electronic health record system.

### Factor 2 — Kill Chain Position

**Appears in Kill Chain(s):** EHR compromise and patient-data theft kill chains  
**Chain Role:** Credential-access and final-target enabler  
**Kill Chain Impact on Priority:** Raises urgency because exposed configuration files may provide database credentials.

### Factor 3 — Exploitability

**Exploitability Score:** 5/5  
**CISA KEV:** No  
**Exploit Impact on Priority:** Multiple public PoCs and Metasploit support make exploitation practical.

### Factor 4 — Compensating Controls

**Existing Controls:** Internal-only AJP service  
**Control Impact on Priority:** Internal placement provides little protection because all compromised hosts on the flat network can reach port 8009.

### Environmental CVSS

**Environmental Metrics Applied:** `CR:H/IR:H/AR:H`; modified confidentiality and integrity remain High because of EHR credentials and patient records.  
**Adjusted Score:** 9.8

**Final Priority:** Critical

**Final Justification:** Ghostcat affects a mission-critical EHR server, is easy to exploit from the internal network and may reveal database credentials. The flat architecture removes most benefit from the service being internal-only, so the environmental priority remains Critical.

---

# Priority Comparison Table

|Finding|CVSS Base|Adjusted Score and Priority|Change Direction|
|---|--:|---|---|
|001|9.8 Critical|9.8 Critical|Same|
|**002**|**7.8 High**|**8.4 Critical priority due to chain context**|**Higher**|
|004|9.8 Critical|10.0 Critical|Higher|
|**005**|**7.5 High**|**6.8 Medium**|**Lower**|
|**008**|**8.8 High**|**9.1 Critical**|**Higher**|
|**010**|**7.5 High**|**5.9 Medium pending validation**|**Lower**|
|**029**|**7.5 High**|**8.6 High**|Higher|
|031|9.8 Critical|9.8 Critical|Same|

The largest contextual changes are Findings **002, 005, 008 and 010**. Findings 002 and 008 move higher because of exploit availability and kill-chain value. Finding 005 moves lower because exploitation requires specific conditions. Finding 010 moves lower because the reported firmware may already contain the vendor fix, although its patient-safety consequences still require validation.
