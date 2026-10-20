# Gap Analysis: IR-2026-0414-01

## Gap Register

| Gap ID | Phase | Gap Description | Control Category | Recommended Improvement | Priority | Linked Findings |
|---|---|---|---|---|---|---|
| GAP-001 | Credential phishing | Credential-harvesting domain was reachable | preventive | Block ms0365-support.login-verification.click at secure DNS/web proxy and alert on lookalike Microsoft 365 login hosts | P1 | Summary IOC; phase 1 |
| GAP-002 | Foreign-origin access | Compliant-device policy suppressed sign-in risk signals; account was abused | preventive | Require phishing-resistant MFA or deny VPN logins from new countries; remove unsafe compliant-device bypass and alert on impossible travel | P1 | Summary open item (Azure AD); phase 2 |
| GAP-003 | LOLBin execution | PowerShell spawned MSBuild with malicious update.xml | detective | Deploy sigma_powershell_msbuild_lolbin.yml on Sysmon EID 1; route alerts to SOC | P1 | ART-002-M01; ART-001-F01 |
| GAP-004 | LOLBin C2 | MSBuild made outbound connections to two public C2 IPs | detective | Deploy sigma_msbuild_network_connection.yml on Sysmon EID 3; correlate with GAP-003 | P1 | ART-002-M02; ART-003-M01 |
| GAP-005 | LOLBin execution | No evidenced execution restriction for MSBuild on clinical systems | preventive | Pilot AppLocker executable rules denying MSBuild for standard clinical users, allow named build service identities | P1 | ART-001-E01; ART-002-M01 |
| GAP-006 | Credential access | NTLM material was exposed in LSASS memory | preventive | Enable supported Credential Guard and LSA protection on compatible Windows endpoints; verify state | P1 | ART-002-M04 |
| GAP-007 | Lateral movement | Kerberos-linked launch on a second workstation was not evidenced as blocked | detective | Alert on abnormal cross-host Kerberos sessions and MSBuild launch under reused identity | P1 | ART-003-M01 |
| GAP-008 | PHI access | Account read 14 lab-report PDFs through LIS_REPORTS$ | preventive | Reduce LIS_REPORTS$ share/NTFS access to authorized clinical roles and alert on unusual mass PDF reads | P1 | AD-LOG-01 |
| GAP-009 | PHI access | No DLP review is available to determine whether PHI left the network | corrective | Review egress/DLP logs for the incident window and document data-breach determination | P1 | Summary open item; AD-LOG-01 |
| GAP-010 | Persistence | Run key and scheduled task enabled logon persistence | detective | Detect new HKCU Run entries and unapproved scheduled tasks referencing user Temp executables | P2 | ART-001-R01; ART-001-R02 |
| GAP-011 | LOLBin execution | PowerShell initiated suspicious encoded execution | preventive | Pilot PowerShell CLM enforced through WDAC/AppLocker policy with clinical-app exception testing | P2 | Sysmon event; ART-002-M01 |

## Priority summary

- **GAP-001 (P1):** Credential-harvesting domain was reachable; block ms0365-support.login-verification.click at secure dns/web proxy and alert on lookalike microsoft 365 login hosts.
- **GAP-002 (P1):** Compliant-device policy suppressed sign-in risk signals; account was abused; require phishing-resistant mfa or deny vpn logins from new countries.
- **GAP-003 (P1):** PowerShell spawned MSBuild with malicious update.xml; deploy sigma_powershell_msbuild_lolbin.yml on sysmon eid 1.
- **GAP-004 (P1):** MSBuild made outbound connections to two public C2 IPs; deploy sigma_msbuild_network_connection.yml on sysmon eid 3.
- **GAP-005 (P1):** No evidenced execution restriction for MSBuild on clinical systems; pilot applocker executable rules denying msbuild for standard clinical users, allow named build service identities.
- **GAP-006 (P1):** NTLM material was exposed in LSASS memory; enable supported credential guard and lsa protection on compatible windows endpoints.
- **GAP-007 (P1):** Kerberos-linked launch on a second workstation was not evidenced as blocked; alert on abnormal cross-host kerberos sessions and msbuild launch under reused identity.
- **GAP-008 (P1):** Account read 14 lab-report PDFs through LIS_REPORTS$; reduce lis_reports$ share/ntfs access to authorized clinical roles and alert on unusual mass pdf reads.
- **GAP-009 (P1):** No DLP review is available to determine whether PHI left the network; review egress/dlp logs for the incident window and document data-breach determination.

## Evidence boundary

The forensic hand-off establishes attacker behavior but does not provide a complete inventory of configured preventive controls or SOC alerts. Absence of an alert in these artifacts is not proof that no alert existed. Verify each control status with the owners before final closure. External exfiltration is **not confirmed**.
