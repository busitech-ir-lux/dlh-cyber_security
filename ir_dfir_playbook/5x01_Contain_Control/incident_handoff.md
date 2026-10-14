# Incident Handoff — IR-2026-0414-01

**Handoff status: OPEN / INCOMPLETE — not suitable for final closure or certified legal-hold release.** This package differentiates historical observations, mock recovery responses, plans, and actual executed actions. Sources are local project files and the Task 5 expansion excerpt; no missing approval, preservation, or containment result has been inferred.

## 1. Incident identity

| Field | Record |
|---|---|
| Incident ID | `IR-2026-0414-01` |
| Declared at (UTC) | `2026-04-14T02:51:04Z` — recorded in existing timeline; source confirmation of this exact declaration time unavailable |
| Initial severity | SEV2 / High |
| Current recommended severity | **SEV1 / Critical** after expanded scope and patient-report access; **source timeline header still states SEV2** (not retroactively edited) |
| Closed at | **NOT CLOSED** (`null`) |
| IR Commander | James Chen, SOC Lead |
| Scribe / declaration actor | On-call SOC Analyst (individual name not supplied) |
| Playbook | `PB-CRED-001` Credential Exposure; investigate endpoint compromise and lateral movement |
| Handoff prepared | Date of document generation; **not an incident action timestamp** |

## 2. Executive summary

- `2026-04-14T02:47:11Z`: WazuhEDR alert `A-20260414-9841` on clinical workstation `WST-WS-031`: PowerShell → MSBuild and connection to `185.220.101.47:443`.
- Previous day proxy logs show a Microsoft 365 lookalike login page, POST to `/auth/submit`, and download of `update.zip`; credential theft remains an inference.
- EDR indicates an `update.exe` execution/persistence chain; authentication logs include an Azure AD impossible-travel risk signal.
- Task 5 expansion evidence indicates movement `WST-WS-031` → `WST-WS-017` → `LIS-WSIDE-01`, with another suspect destination `91.234.99.107:443`.
- Fourteen LIS report PDFs were read at `03:43:30Z`; **exfiltration and breach notification criteria remain unconfirmed**.
- Severity should be reassessed to SEV1; General Counsel and executive sponsor should be notified, subject to verified communication records.
- Quarantine VLAN containment was **recommended, not proved executed**; the eradication checklist is **0 complete / 15 pending**.
- Mock API contains clean-state sample responses, but no actual evidence-store hash manifest or independently verified live recovery pass is available.

## 3. Scope

| Category | In scope / status |
|---|---|
| Identity | `MEDDEFENSE\dmarsh`, `dmarsh@meddefense.local` (potentially compromised; credential abuse suspected) |
| Initial host | `WST-WS-031` (`10.42.118.31`), West Campus Laboratory clinical workstation |
| Expanded hosts | `WST-WS-017` (suspicious execution and outbound traffic); `LIS-WSIDE-01` (network logon and report reads) |
| Investigative scope | Other hosts where `dmarsh` tickets/sessions were present during exposure; not automatically compromised |
| Data and services | LIS patient-report PDFs (14 reads), potentially patient-identifiable health information; LIS/EPIC application access and authentication context |
| Indicators | `185.220.101.47:443`, `91.234.99.107:443`, `update.xml`, `update.exe`, suspected persistence; see source exports |

## 4. Authoritative timeline — full unmodified contents of `incident_timeline.md`

The following is reproduced **verbatim**. It does **not** yet contain Task 5 reassessment or Task 4 completed actions. The original history must remain append-only; outstanding additions are listed below.

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

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy logging system | User dmarsh made a GET request to https://ms0365-support[.]login-verification[.]click/auth; proxy returned HTTP 200; phishing is suspected, not confirmed | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert A-20260414-9841 reported powershell.exe (PID 7812) launching msbuild.exe (PID 8104) with C:\Users\dmarsh\AppData\Local\Temp\update.xml on WST-WS-031 under MEDDEFENSE\dmarsh | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert reported established msbuild.exe connection to 185.220.101.47:443, enriched as a known Tor exit relay; malicious command-and-control or beaconing is not yet confirmed | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Declared incident IR-2026-0414-01 based on suspicious process execution, external connection, and prior suspicious proxy request | source=alert_A-20260414-9841.json + proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Assigned initial and current severity SEV2 (High): clinical workstation with LIS access, suspicious execution and established external connection; lateral movement, data theft, and service disruption not confirmed | source=alert_A-20260414-9841.json + MedDefense incident context | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | On-call SOC Analyst | Selected credential-exposure playbook PB-CRED-001 as best available initial fit given possible phishing; endpoint-compromise investigation also required | source=proxy_24h_dmarsh.log + alert_A-20260414-9841.json + project playbook choice | certainty=confirmed

<!-- Append subsequent entries below this line. Do not edit or delete previous entries. -->

- 2026-10-14T16:22:36Z | DECISION | On-call SOC Analyst (document author) | Recommended Option A (quarantine VLAN with forensic jumpbox-only access) after comparing network isolation, power-off, and targeted process kill/egress block; pending James Chen approval, clinical coordination, and Task 2 preservation completion; no containment executed | source=containment_decision.md + alert_A-20260414-9841.json + edr_wst_ws_031_24h.jsonl | certainty=confirmed

### Post-timeline source findings requiring new entries (not represented as prior actions)

| Source event UTC | Observation / implication | Status |
|---|---|---|
| `2026-04-14T03:22:47Z` | TGS request from `WST-WS-031` for `cifs/WST-WS-017` | Task 5 excerpt; not appended |
| `2026-04-14T03:23:01Z` | `dmarsh` type-3 network logon on `WST-WS-017` | Task 5 excerpt; not appended |
| `2026-04-14T03:27:13Z` | `WST-WS-017` MSBuild connection to `91.234.99.107:443` | Task 5 excerpt; not appended |
| `2026-04-14T03:41:52Z` | TGS request from `WST-WS-017` for `cifs/LIS-WSIDE-01` | Task 5 excerpt; not appended |
| `2026-04-14T03:42:08Z` | `dmarsh` network logon to `LIS-WSIDE-01` | Task 5 excerpt; not appended |
| `2026-04-14T03:43:30Z` | `LIS-WSIDE-01` read 14 PDFs under `/LIS/reports/daily/` | Task 5 excerpt; not appended |

**Timeline inconsistency:** The scenario says the scope was discovered at **03:34Z**, yet includes events timestamped **03:41–03:43Z**. These later events cannot have been known at 03:34Z without another explanation. Obtain a corrected discovery timestamp and append separate `OBSERVATION` and `DECISION` entries at verified recording times. Do not backdate them.

## 5. Decisions

| Decision | One-line basis and record |
|---|---|
| Declare incident SEV2 | Alert plus suspicious process, external connection and possible phishing; recorded `02:51:04Z` in timeline. |
| Choose `PB-CRED-001` | Credential exposure was best initial playbook fit, with parallel malware investigation; timeline. |
| Recommend network quarantine (Option A) | Preferred over power-off (volatile loss) and selective kill (missed persistence/C2); `containment_decision.md`. **Approval not evidenced.** |
| Reassess to SEV1 | Lateral movement into patient-report workstation and access to 14 PDFs raise confidentiality impact; Task 5 evidence. **Decision not formally appended/approved.** |
| Expand response | Investigate both additional hosts, identity sessions/tickets and second destination; proposals, not completed actions. |

**Execution record:** `containment_execution.md` contains pending VLAN, firewall, C2-gap, EDR flag and jumpbox access steps, with no proven execution time, authorized actor or post-action result.

## 6. Evidence index and chain of custody

**Designated acquisition store:** `/evidence/IR-2026-0414-01/`; canonical manifest: `/evidence/IR-2026-0414-01/hashes.txt` (from `evidence_store_init.sh`); optional task-named export: `IR-2026-0414-01-hashes.txt`. **Store/manifest not available in current runtime. No preserved-artifact hashes can be certified.** The hashes below describe *uploaded source copies*, not forensic acquisition records.

| Artifact | Available source-copy location | SHA-256 of uploaded copy | Acquisition evidence status |
|---|---|---|---|
| `alert_A-20260414-9841.json` | source upload `/mnt/data/alert_A-20260414-9841.json` (not verified in evidence store) | `535f02ef55927decc138e5542ad825dea3754a7370c6ee05f58f7d8480eaf6db` | Source-copy hash only |
| `edr_wst_ws_031_24h.jsonl` | source upload `/mnt/data/edr_wst_ws_031_24h.jsonl` (not verified in evidence store) | `f7e404df7556b47bb97f08d10746cad73db374622c4d84035ce23317a8a6c325` | Source-copy hash only |
| `proxy_24h_dmarsh.log` | source upload `/mnt/data/proxy_24h_dmarsh.log` (not verified in evidence store) | `7738cd69ce3c726273fa6ca1a3eac54bef3d22b63859af071a203cb90b80f303` | Source-copy hash only |
| `auth_24h_dmarsh.json` | source upload `/mnt/data/auth_24h_dmarsh.json` (not verified in evidence store) | `398aae6da40893af8c41da489b875c96e1cb74d9d3c5a6485645811031a92ced` | Source-copy hash only |

**Preservation-runbook inventory — acquisition status not demonstrated:**

| Evidence expected | Intended location under `/evidence/IR-2026-0414-01/` | Original hash |
|---|---|---|
| Memory image `WST-WS-031` | `memory/` | **UNAVAILABLE** |
| Process/parent PID/command-line snapshot | `process_tree/` | **UNAVAILABLE** |
| Active socket and connection snapshot | `network/` | **UNAVAILABLE** |
| 24h EDR export | `endpoint_telemetry/` | **UNAVAILABLE** |
| Original SIEM alert JSON | `siem/` | **UNAVAILABLE** |
| Proxy and DNS records | `proxy_dns/` (DNS source not supplied) | **UNAVAILABLE** |
| AD/Azure AD authentication export | `authentication/` | **UNAVAILABLE** |
| Expanded-host acquisitions and Task 4 command/PCAP exports | expected location not evidenced | **UNAVAILABLE** |

**Evidence integrity:** Require collector, acquisition UTC time, source, storage path, and original SHA-256 per item; verify with `cd /evidence/IR-2026-0414-01 && sha256sum -c hashes.txt`. Do not treat the source-copy hashes as proof of chain of custody.

## 7. Eradication status

Source: `eradication_checklist.yaml` — **0 complete; 15 pending; total 15**. Targets: three hosts, `dmarsh` credentials/sessions, machine accounts, conditional KRBTGT reset assessment, both malicious IPs and internal segmentation. All execution fields remain null; clean mock-state files do **not** change these statuses. The `krbtgt` double-reset is an **assessment**, not an established requirement: lateral movement alone does not prove forged TGTs or KRBTGT secret compromise.

## 8. Recovery status — actual `recovery_validation.sh` output

Invocation attempted against local `mock_validation_api` on `127.0.0.1:18765` in this file-generation runtime; local connections failed, so API failures reflect **test-environment accessibility**, not findings that production hosts are infected. The actual evidence store is absent. Exit code: **1 (FAIL)**.

```text
[FAIL] process tree: suspicious lineage, missing host, or API error
[FAIL] netflow: outbound traffic, missing deny, or API error
[FAIL] persistence: artifact found, missing data, or API error
[FAIL] service health: Epic or LIS unavailable or unhealthy
[FAIL] detection: rule disabled, synthetic hit missing, or API error
[FAIL] evidence hashes: no SHA-256 manifest found at /evidence/IR-2026-0414-01
FAILED 6 CHECK(S): process tree: suspicious lineage, missing host, or API error;netflow: outbound traffic, missing deny, or API error;persistence: artifact found, missing data, or API error;service health: Epic or LIS unavailable or unhealthy;detection: rule disabled, synthetic hit missing, or API error;evidence hashes: no SHA-256 manifest found at /evidence/IR-2026-0414-01
```

**Independent file review:** The supplied mock JSON files *describe* zero matching process trees, cleared persistence, zero flows to both IPs, an active detection rule and a successful synthetic hit; Epic/LIS mock health bodies are `OK`. These are supplied simulated after-state fixtures, not proof of a successful live validation of the actual incident.

## 9. Outstanding items — owners and deadlines

Deadlines are **relative operational requirements proposed for approval**, not previously agreed calendar commitments.

| Priority | Open item | Proposed owner | Deadline / trigger |
|---|---|---|---|
| P0 | Confirm SEV1 declaration, incident timeline amendment and commander approval | James Chen / on-call SOC | Immediately on handoff |
| P0 | Reconcile 03:34Z discovery vs 03:41–03:43Z event times | SOC analyst | Before timeline sign-off |
| P0 | Confirm volatile/disk/log preservation; obtain chain-of-custody manifest and verified hashes | Forensic lead / SOC | Before destructive remediation, unless urgent risk exception documented |
| P0 | Verify quarantine, both C2 denies, containment flags, jumpbox-only access and clinical workaround; append **actual** ACTION records | Network/EDR administrators + IR Commander | Before calling containment complete |
| P0 | Assess patient-report access, identity compromise, data movement and breach-notification threshold | Privacy officer + General Counsel | Immediately; follow applicable statutory clocks |
| P1 | Complete 15-item eradication checklist with recorded operators, UTC times and verifications | Endpoint/AD/Network teams | Before production release |
| P1 | Run mock/API validation in reachable lab, then validate real clinical services and recheck original evidence hashes | SOC + LIS/EPIC service owners | Before recovery sign-off |
| P1 | Record notifications (Legal, executive, clinical owner), send status updates and preserve communications | IR Commander / communications lead | Immediate escalation, then per IR cadence |
| P1 | Approve closure and evidence retention/legal hold | IR Commander + Legal/Privacy | Only after validated recovery and regulatory decisions |

## 10. Regulatory posture

**HIPAA breach notification assessment is triggered as an internal review requirement** because the incident includes unauthorized-looking access to potentially identifiable LIS patient-report PDFs during a suspected compromise. That does **not** automatically establish a reportable HIPAA breach, and HIPAA applicability depends on the organization's regulatory status and the data involved. The **Privacy Officer with General Counsel** should own fact-finding, risk assessment, potential notification decisions, preservation/hold instructions, and coordination with the IR Commander; assess any other applicable privacy regimes separately. No patient, regulator or external auditor notice is evidenced by the supplied records.

## 11. Communications log

| UTC timestamp | Sender → audience | Status/message | Template |
|---|---|---|---|
| Not supplied | James Chen → incident channel / on-call analyst | “You own this. Contain it. Document everything.” — scenario context; exact dispatch time unknown | Direct operational instruction; template not supplied |
| Not recorded | SOC → IR Commander | Initial SEV2 declaration: **timeline decision exists; transmission not evidenced** | Not supplied |
| Not recorded | SOC → General Counsel / Executive Sponsor | SEV1 PHI-related escalation **required, not evidenced as sent** | Not supplied |
| Not recorded | SOC → Clinical service owner | Isolation/operational impact coordination **required, not evidenced as sent** | Not supplied |
| Not recorded | IR/SOC → shift-relief analyst | This handoff document prepared; actual delivery not evidenced | `incident_handoff.md` |

**Authority/control note:** Only confirmed communications should be logged as `COMMUNICATION` timeline actions. Before legal hold or final closure, obtain immutable exports, unambiguous UTC source times, verified collection hashes, approver acknowledgments and a signed recovery decision.
