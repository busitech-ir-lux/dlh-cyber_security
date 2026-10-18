# Correlated Incident Timeline: LH-2026-0414-01

**Incident:** IR-2026-0414-01  
**Status:** PROVISIONAL. `proxy_log.jsonl`, `ad_auth_log.jsonl`, `siem_alert_export.json`, disk analysis outputs, and Volatility output were not supplied. Entries below are **investigative hypotheses from the task description**, except the expressly supplied patient-report finding summary. Do not treat them as forensically confirmed observations.

## Source and certainty rules

- **Confirmed:** directly demonstrated by reviewed artifact or log record at the stated precision.
- **Probable:** supported by two or more consistent traces but an important link is unverified.
- **Possible:** scenario claim, alert, or inference lacking underlying artifact inspection.
- Record real `YYYY-MM-DDTHH:MM:SSZ` values only after reviewing the source; do not manufacture precision or use sample log lines as evidence.
- Assign `LOG-PROXY`, `LOG-AD`, and `LOG-SIEM` as *source labels* until registered as evidence artifacts in the CoC. Replace pending source refs with exact filenames and line numbers after review.

## Candidate incident events (chronological placement pending validation)

| Timestamp (UTC) | Source (artifact/log type) | Event | ATT&CK technique | Certainty | Evidence ref / verification required |
|---|---|---|---|---|---|
| PENDING — reported Apr 13 | LOG-PROXY | Phishing URL clicked | T1566.002 | possible | `proxy_log.jsonl` line PENDING; HTTP request and user attribution |
| PENDING — reported Apr 13 | LOG-PROXY | Credentials submitted to typosquat login site | T1078/T1566.002 | possible | Proxy alone may show POST, not credentials; confirm form submission or identity logs |
| PENDING | LOG-AD / VPN | External VPN login using dmarsh account | T1078 | possible | `ad_auth_log.jsonl` line PENDING; VPN MFA/session evidence |
| PENDING | ART-002 / LOG-SIEM | Encoded PowerShell execution | T1059.001 | possible | `ART-002-M03` CMDLINE result pending |
| PENDING — by 2026-04-14T03:02Z if present | ART-002 / LOG-SIEM | PowerShell spawns MSBuild; suspected beacon | T1127.001, T1071.001 | possible | `ART-002-M02`, `ART-002-M04`; process tree/socket attribution pending |
| PENDING | ART-001 / disk | Suspected staged/dropped files under dmarsh Temp directory | T1105 | possible | `ART-001-Fxx` from TSK analysis pending |
| PENDING | ART-001 / registry/tasks | Scheduled task and Run-key persistence suspected | T1053.005, T1547.001 | possible | `ART-001-Rxx` from registry/Task XML pending |
| PENDING | ART-002 / memory | NTLM/Kerberos material allegedly accessible from LSASS | T1003.001 | possible | `ART-002-M07/M08` do **not** establish attacker access or ticket theft |
| PENDING | LOG-AD | Kerberos service ticket requested for `cifs/WST-WS-017` | T1550.003 (only if pass-the-ticket established) | possible | `ad_auth_log.jsonl` line PENDING; a routine TGS request alone is not malicious |
| PENDING | LOG-AD / ART-003 | Logon to WST-WS-017 attributed to attacker | T1021.002 (if SMB lateral movement supported) | possible | `ad_auth_log.jsonl` line PENDING; host/session attribution |
| PENDING — by 2026-04-14T03:38Z if present | ART-003 | Second suspected C2 beacon from WST-WS-017 | T1071.001 | possible | `ART-003-M02` netscan pending |
| PENDING | LOG-AD | Kerberos TGS for `cifs/LIS-WSIDE-01` | — | possible | `ad_auth_log.jsonl` line PENDING; ticket does not equal a completed logon |
| PENDING | LOG-AD | Logon to LIS-WSIDE-01 | T1021.002 (only if remote SMB access demonstrated) | possible | `ad_auth_log.jsonl` line PENDING |
| 2026-04-14T03:43Z–2026-04-14T03:44Z (minute precision) | SUPPLIED-FINDING / LIS audit summary | Fourteen patient laboratory report PDFs accessed under unauthorized dmarsh account in `/LIS/reports/daily/*.pdf` | T1005 (conditional on collection evidence) | **confirmed in supplied finding summary; independently unverified** | `SUPPLIED-SUMMARY-01`; original LIS audit log/filenames and unique patients PENDING |

## Acquisition and custody markers (not attacker events)

| Timestamp (UTC) | Source | Event | Evidence ref |
|---|---|---|---|
| 2026-04-14T03:02Z | acquisition notes | WST-WS-031 memory acquired while host reportedly beaconing | Acquisition record / ART-002 |
| 2026-04-14T03:38Z | acquisition notes | WST-WS-017 memory acquired | Acquisition record / ART-003 |
| 2026-04-14T04:51Z–06:14Z | acquisition notes | WST-WS-031 disk image acquired | Acquisition record / ART-001 |
| 2026-04-14T07:30Z | legal hold reference | Helena Reyes litigation hold | LH-2026-0414-01 |
| 2026-04-14T07:42Z | acquisition notes | Mike Torres signed transfer notes | Acquisition record |

## Correlation checks before finalizing

1. Normalize timezone and distinguish event time, ingest time and acquisition time.
2. Verify each proxy event's client/user mapping; distinguish an HTTP request from actual credential submission.
3. Match VPN principal, source IP, session ID, and MFA results to downstream AD events.
4. Compare process PID/PPID and time with memory acquisition time and disk MAC timestamps; use actual finding IDs from Tasks 3–5.
5. A Kerberos 4769 TGS is **not** evidence of a successful interactive/SMB logon; require corroboration (e.g. 4624, share access, host traces).
6. Confirm the count represents **14 distinct patients**, not merely 14 PDFs, using underlying LIS audit/record mapping.
7. Record evidence provenance, line numbers, clock-skew uncertainty and any contradictory trace; update certainty accordingly.

**Outstanding:** Without the supplementary logs and real forensic outputs, the requested fully corroborated timeline cannot be produced responsibly.
