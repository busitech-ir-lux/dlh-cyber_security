# The Threat-Vulnerability Correlation

## Threat-Vulnerability Correlation Matrix

|Finding|Threat Actor(s)|Vector|Kill Chain|Scenario|Gap|
|---|---|---|---|---|---|
|**001 — CVE-2021-44790**|Ransomware organized crime; unskilled attacker|Exploitation of vulnerable public-facing or internal application|Billing-server compromise chain|Attacker exploits Apache, gains code execution and prepares privilege escalation|Unsupported billing server, outdated Apache and weak internal segmentation|
|**002 — CVE-2019-0211**|Ransomware organized crime; advanced external attacker|Local privilege escalation|Billing-server compromise chain|After exploiting Finding 001, the attacker uses CVE-2019-0211 to obtain root access|Weak patch management and unsupported Ubuntu system|
|**004 — BlueKeep/EternalBlue on Windows XP**|Ransomware organized crime; nation-state APT|Exploitation of vulnerable SMB or RDP services|Medical-device disruption and ransomware lateral-movement chains|Attacker moves across the flat network, compromises the MRI workstation and disrupts clinical imaging|Unsupported Windows XP, open SMB/RDP and no medical-device VLAN|
|**005 — Obsolete TLS**|Cybercriminal; nation-state APT|Network interception and weak cryptographic protocols|Internet-facing patient-portal chain|Attacker attempts to intercept or downgrade patient-portal communications|Legacy TLS enabled and insufficient secure-configuration management|
|**008 — CVE-2021-34527 PrintNightmare**|Ransomware organized crime; malicious insider|Exploitation of vulnerable network service|Domain-compromise and ransomware lateral-movement chains|Attacker exploits the Print Spooler, gains privileged execution and moves toward Active Directory|Unsupported Windows Server, exposed Print Spooler and flat network|
|**010 — BD Alaris weakness/default credentials**|Ransomware organized crime; malicious insider|Default credentials and insecure medical-device network communications|Medical-device disruption chain|Attacker accesses infusion pumps or interrupts communication with management systems|Default credentials, inadequate device isolation and weak medical-IoT management|
|**029 — CVE-2021-43798 Grafana**|Ransomware organized crime; unskilled attacker|Unauthenticated path traversal and file disclosure|Westside Clinic-to-Central network chain|Attacker reads Grafana files, discovers credentials and pivots through the clinic VPN|Undocumented asset, vulnerable software and weak asset inventory|
|**031 — CVE-2020-1938 Ghostcat**|Ransomware organized crime; nation-state APT|Exploitation of exposed AJP service|EHR compromise and patient-data theft chains|Attacker exploits AJP, reads application configuration files and obtains database credentials|Exposed AJP port, flat network and excessive database reachability|

## Highest-Damage Vulnerability

**Finding 031, CVE-2020-1938 on `ehr-srv-01`, would cause the most damage in the full threat context.** The EHR server is a critical asset containing access paths to patient records, and Ghostcat has public exploit code that can expose application files and database credentials. A ransomware group or capable external attacker could reach the vulnerable AJP service after compromising any internal endpoint because the network is flat. The stolen credentials could then be combined with Finding 003 to access the EHR database, resulting in patient-data theft, record manipulation and disruption of clinical operations.
