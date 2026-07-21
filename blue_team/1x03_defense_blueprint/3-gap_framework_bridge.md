

**Gap Reference:** M-05  
**Description:** VPN, EHR and administrator access rely only on passwords.  
**Vulnerability Evidence:** Finding 009 found password-based SSH access, and Finding 019 found RDP enabled on several systems.  
**Threat Context:** RaaS groups or credential thieves — valid-account and remote-access compromise chain.  
**NIST CSF Function:** Protect  
**CIS Control:** Control 6 — Access Control Management  
**Recommended Action:** Enable MFA first for VPN and administrator accounts, then extend it to the EHR and other critical applications.

---

## 6. Weak Westside Clinic Security

**Gap Reference:** M-06  
**Description:** Westside uses a consumer router that provides a direct VPN connection to the Central network.  
**Vulnerability Evidence:** Finding 014 identified the weak router, and Finding 029 found an undocumented vulnerable Grafana system at Westside.  
**Threat Context:** Opportunistic or third-party attacker — compromise Westside and enter Central through the VPN.  
**NIST CSF Function:** Protect  
**CIS Control:** Control 12 — Network Infrastructure Management  
**Recommended Action:** Replace the router with a managed firewall and restrict the VPN to only required systems and ports.

---

## 7. Shared PACS Credentials

**Gap Reference:** M-07  
**Description:** Radiology staff use one shared account, removing individual accountability.  
**Vulnerability Evidence:** Finding 024 found that PACS imaging traffic also crosses the network without encryption.  
**Threat Context:** Negligent or malicious insider — unauthorized PACS access and patient-data exposure chain.  
**NIST CSF Function:** Protect  
**CIS Control:** Control 5 — Account Management  
**Recommended Action:** Replace the shared account with individual badge or smart-card authentication and encrypt DICOM traffic.

---

## 8. Unsupported and Unpatched Systems

**Gap Reference:** 1x02 Findings 001, 002, 004, 008 and 011  
**Description:** Several important systems run old software with known exploitable vulnerabilities.  
**Vulnerability Evidence:** The scan found Apache remote code execution, an unsupported MRI workstation, an unsupported print server and an unsupported billing-server operating system.  
**Threat Context:** Opportunistic attacker or RaaS group — exploit a public or internal system, gain control and move laterally.  
**NIST CSF Function:** Protect  
**CIS Control:** Control 7 — Continuous Vulnerability Management  
**Recommended Action:** Patch the billing server immediately, isolate or replace the MRI workstation and establish monthly vulnerability scanning and remediation deadlines.

# Traceability Summary

|Gap|Vulnerability Evidence|Threat and Kill Chain|NIST Function|CIS Control|Main Action|
|---|---|---|---|---|---|
|M-01 Flat network|F003, F007, F010, F016, F031|RaaS — ransomware spread|Protect|12|Segment the network|
|M-02 Backup isolation|F015|RaaS — backup encryption|Recover|11|Create immutable offsite backups|
|M-03 Medical IoT|F010, F016|Ransomware/opportunistic — device disruption|Protect|12|Isolate medical devices|
|M-04 No monitoring|F001, F002|RaaS/opportunistic — hidden activity|Detect|8 and 13|Deploy centralized monitoring|
|M-05 No MFA|F009, F019|Credential theft — valid-account access|Protect|6|Enable MFA|
|M-06 Westside security|F014, F029|Remote/third-party — VPN entry|Protect|12|Replace router and restrict VPN|
|M-07 Shared PACS account|F024|Insider — patient-data misuse|Protect|5|Use individual accounts|
|Unpatched systems|F001, F002, F004, F008, F011|Opportunistic/RaaS — vulnerability exploitation|Protect|7|Patch and replace old systems|
