# The Noise Filter

## Full Triage

Finding 001 | 9.8 Critical | `billing-srv-01` | Category: AC | Reason: Unauthenticated remote code execution affects the billing server and can chain with Finding 002.

Finding 002 | 7.8 Critical | `billing-srv-01` | Category: AC | Reason: Public exploit code can escalate a compromised Apache process to root.

Finding 003 | Critical | `ehr-db-01` | Category: AC | Reason: Any host in `10.10.0.0/16` can directly attempt access to the patient database.

Finding 004 | Critical | `WS-RAD-01` | Category: AC | Reason: The MRI workstation is unsupported and exposes multiple weaponized remote-code-execution vulnerabilities.

Finding 005 | 7.5 High | `web-srv-01` | Category: AS | Reason: The internet-facing patient portal supports obsolete TLS protocols that may expose protected data.

Finding 006 | High | `billing-srv-01` | Category: AS | Reason: MySQL containing financial data accepts connections from the entire internal network.

Finding 007 | High | `ad-dc-01` | Category: AC | Reason: LDAP relay and SMBv1 weaknesses on the domain controller could support domain compromise.

Finding 008 | High | `print-srv-01` | Category: AS | Reason: The unsupported print server runs a spooler affected by weaponized PrintNightmare vulnerabilities.

Finding 009 | High | `billing-srv-01` | Category: AS | Reason: Password-based SSH without account lockout permits brute-force attacks.

Finding 010 | 7.5 High | BD Alaris pumps | Category: AC | Reason: Medical devices have default credentials and insufficient isolation, creating patient-safety and availability risk.

Finding 011 | High | `billing-srv-01` | Category: AS | Reason: Ubuntu 18.04 lacks ESM and is no longer receiving normal operating-system security patches.

Finding 012 | Medium | `web-srv-01` | Category: AS | Reason: Missing security headers weaken protection against clickjacking, XSS and SSL-stripping attacks.

Finding 013 | Medium | `web-srv-01` | Category: AS | Reason: The patient portal certificate will expire soon and has no automatic renewal.

Finding 014 | Medium | Westside router | Category: AS | Reason: A consumer router terminates the site-to-site VPN and lacks appropriate enterprise security controls.

Finding 015 | Medium | `NAS-01` | Category: AS | Reason: The backup-management interface and unencrypted backups are accessible from the flat network.

Finding 016 | Medium | Philips IntelliVue monitors | Category: AS | Reason: Unauthenticated web and HL7 interfaces expose clinical devices and patient data across the internal network.

Finding 017 | Medium | `ehr-srv-01` | Category: AS | Reason: Tomcat version and path disclosure helps attackers identify exploitable services such as Finding 031.

Finding 018 | Medium | `ad-dc-01`, `ad-dc-02` | Category: AS | Reason: DES and RC4 Kerberos support increases offline credential-cracking risk.

Finding 019 | Medium | Multiple workstations | Category: AS | Reason: RDP increases the brute-force and remote-access attack surface despite NLA being enabled.

Finding 020 | 9.8 Medium | `backup-srv-01` | Category: FP | Reason: Exploitation requires forwarded SSH-agent and PKCS#11 conditions that are unlikely to exist on this server.

Finding 021 | Medium | `web-srv-01` | Category: AS | Reason: HTTP TRACE is unnecessary and can support credential theft when combined with XSS.

Finding 022 | Low | `ehr-srv-01` | Category: I | Reason: A 47-second clock difference is a real operational issue but presents limited immediate security risk.

Finding 023 | Low | Clinical workstations | Category: AS | Reason: Unrestricted USB storage creates malware-introduction and patient-data exfiltration paths.

Finding 024 | Low | `pacs-srv-01` | Category: AS | Reason: Unencrypted DICOM traffic exposes patient identifiers and medical images to network interception.

Finding 025 | Low | `ad-dc-01` | Category: AS | Reason: Unrestricted DNS zone transfers reveal internal systems and support attacker reconnaissance.

Finding 026 | Low | `billing-srv-01` | Category: AS | Reason: The outdated kernel contains 47 known CVEs and can support privilege escalation after initial compromise.

Finding 027 | Informational | Windows workstations | Category: AS | Reason: Fifteen systems have inactive or non-reporting endpoint-protection agents and require investigation.

Finding 028 | Informational | `10.10.2.99` | Category: AS | Reason: An undocumented Linux device exposes Cockpit, SSH and Jupyter services on the server subnet.

Finding 029 | Informational | `10.10.10.200` | Category: AS | Reason: The undocumented Grafana server has a publicly exploitable unauthenticated file-read vulnerability.

Finding 030 | Informational | `ehr-srv-01` | Category: FP | Reason: The certificate correctly matches `ehr.meddefense.local`; warnings occur only when clients use the IP address.

Finding 031 | 9.8 High | `ehr-srv-01` | Category: AC | Reason: Ghostcat is remotely exploitable from the flat network and may expose EHR database credentials.

The classifications are based on the technical details, exposure and scanner notes in the complete 31-finding report.

## Triage Summary

|Category|Count|
|---|--:|
|Actionable Critical — AC|7|
|Actionable Standard — AS|20|
|Informational — I|2|
|False Positive — FP|2|
|**Total**|**31**|

## Actionable Findings List

### Actionable Critical — Immediate Remediation Within 24–48 Hours

1. Finding 004 — Unsupported MRI workstation with weaponized RCE vulnerabilities
    
2. Finding 003 — Patient database accessible across `10.10.0.0/16`
    
3. Finding 007 — Domain-controller LDAP relay and SMBv1 exposure
    
4. Finding 031 — Ghostcat on the EHR application server
    
5. Finding 001 — Apache unauthenticated RCE on the billing server
    
6. Finding 002 — Apache privilege escalation to root
    
7. Finding 010 — BD Alaris default credentials and inadequate isolation
    

### Actionable Standard — Scheduled Remediation Within 7–30 Days

1. Finding 029 — Vulnerable undocumented Grafana server
    
2. Finding 008 — Unsupported Windows print server and PrintNightmare
    
3. Finding 011 — Ubuntu 18.04 without ESM
    
4. Finding 006 — Unrestricted billing MySQL access
    
5. Finding 015 — Exposed backup NAS management and unencrypted backups
    
6. Finding 016 — Exposed Philips monitor interfaces
    
7. Finding 014 — Consumer router terminating the clinic VPN
    
8. Finding 005 — Weak TLS on the patient portal
    
9. Finding 009 — SSH password authentication
    
10. Finding 018 — Weak Kerberos encryption
    
11. Finding 027 — Inactive endpoint protection
    
12. Finding 028 — Undocumented server-subnet device
    
13. Finding 024 — Unencrypted DICOM traffic
    
14. Finding 023 — Unrestricted USB storage
    
15. Finding 026 — Outdated billing-server kernel
    
16. Finding 017 — Tomcat information disclosure
    
17. Finding 012 — Missing patient-portal security headers
    
18. Finding 013 — Expiring portal certificate
    
19. Finding 025 — DNS zone transfer enabled
    
20. Finding 019 — RDP enabled on multiple systems
    
21. Finding 021 — HTTP TRACE enabled
