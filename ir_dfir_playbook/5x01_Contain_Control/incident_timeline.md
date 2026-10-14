# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: On-call SOC Analyst
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: On-call SOC Analyst

## Legend

- OBSERVATION: raw fact from an alert, log, or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy logging system | Proxy recorded GET https://ms0365-support.login-verification.click/auth by dmarsh with HTTP 200 response | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert A-20260414-9841 reported powershell.exe (PID 7812) launching msbuild.exe (PID 8104) with C:\Users\dmarsh\AppData\Local\Temp\update.xml on WST-WS-031 under MEDDEFENSE\dmarsh | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert reported an ESTABLISHED outbound TCP connection from msbuild.exe (PID 8104) to 185.220.101.47:443; internal enrichment tagged the IP tor_exit_relay | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Declared incident IR-2026-0414-01 based on suspicious process execution, external connection, and prior suspicious proxy request | source=alert_A-20260414-9841.json + proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Assigned initial severity SEV2 (High) due to high-criticality clinical workstation, suspicious PowerShell-to-MSBuild execution, and outbound connection to a high-risk IP | source=alert_A-20260414-9841.json + MedDefense incident context | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Selected credential-exposure playbook PB-CRED-001 (alert recommended_playbook); instructed parallel investigation of suspicious endpoint execution | source=proxy_24h_dmarsh.log + alert_A-20260414-9841.json + project playbook choice | certainty=confirmed

<!-- Append subsequent entries below this line. Do not edit or delete previous entries. -->

- 2026-10-14T16:22:36Z | DECISION | On-call SOC Analyst (document author) | Recommended Option A (quarantine VLAN with forensic jumpbox-only access) after comparing network isolation, power-off, and targeted process kill/egress block; pending James Chen approval, clinical coordination, and Task 2 preservation completion; no containment executed | source=containment_decision.md + alert_A-20260414-9841.json + edr_wst_ws_031_24h.jsonl | certainty=confirmed

