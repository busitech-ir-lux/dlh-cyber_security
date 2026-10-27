# Containment Decision — IR-2026-0420-01

**Status:** Proposed decision; authorization and execution pending. **Severity:** SEV1. **Time zone:** UTC.

## Evidence and scope

- Torres reported clinical workstation slowdown/changed filenames, abnormal `SCHED-SVR-01` disk activity, and suspicious `WinHealthSvc` installations (`torres_call_transcript.md`).
- **Schema/sample indicators, not independently verified forensic findings:** `sysmon_multihost.sample.jsonl` shows `svchost32.exe` communicating with `45.152.66.114:443` on four workstations, a suspicious process on `FILE-SVR-01` and `SCHED-SVR-01`, and staged `encryption_staging.ps1` on four workstations. `proxy_72h.sample.jsonl` also includes `FILE-SVR-01` egress. The full forensic artifacts must establish actual scope.
- Original containment scope: `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`, `FILE-SVR-01`. Add `SCHED-SVR-01` as **suspected sixth asset requiring immediate investigation and guarded containment**. Its role in clinical scheduling raises the availability risk.
- Candidate indicators: domain `staging.office365-cdn.net`, IP `45.152.66.114`, service `WinHealthSvc`, image `C:\ProgramData\Microsoft\svchost32.exe`, account `MEDDEFENSE\jdoe`. Validate these against real environment before change.

## Three strategies

| Strategy | Action / attacker impact | Patient-care impact | Evidence preserved / lost | Execution time | Reversible? |
|---|---|---|---|---|---|
| A. Immediate hard shutdown | Power off affected endpoints/servers; stops live activity | **High:** scheduling and clinical file access may abruptly fail | Disk evidence remains; **RAM, running connections, and active sessions lost** | Minutes once approved | Power can return; lost volatile evidence cannot |
| B. Full network isolation | EDR quarantine/network switch isolation of all implicated systems; cuts C2 and lateral paths | **High:** `FILE-SVR-01` and `SCHED-SVR-01` may become unavailable | RAM remains if powered on; remote evidence collection can be disrupted; active network sessions severed | Minutes to tens of minutes depending on EDR reachability | Yes, through controlled reconnect |
| C. Phased containment **(chosen)** | Immediately block known C2 at managed egress/DNS, acquire volatile evidence in parallel, isolate four workstations, restrict servers to vetted clinical traffic; revoke exposed credentials in coordinated order | **Lower but not zero:** keeps essential clinical services reachable while isolating attacker paths | Preserves RAM and disk evidence if acquired before disruptive host action; live C2 session details may be lost when blocking | Begin immediately; verification and server changes depend on operators | Yes; undo rules/quarantine under approval |

## Decision and trade-off

**Choose C, conditional on real-time scope verification and approval.** Four clinical workstations show suspected backdoor and ransomware staging; early egress denial limits attacker commands while evidence acquisition runs in parallel. Unlike shutting down all systems, restricting `FILE-SVR-01` and `SCHED-SVR-01` to approved clinical connections aims to preserve patient care. Existing connections and volatile C2 evidence may be lost during isolation, so acquisition owners must capture memory/network state first wherever clinically and operationally safe; do not delay emergency containment if encryption or exfiltration starts. If the server cannot be safely restricted, escalate to the clinical incident commander for downtime procedures and emergency isolation.

**Authorizing role:** Incident Commander / designated SEV1 authority, with Clinical Operations lead approving any impact to clinical services; Network/EDR operators execute. Actual named approvals: **pending**.

**Rollback trigger:** Essential patient-care endpoints fail after a change *and* the incident commander and clinical lead authorize a safer compensating configuration; never restore unrestricted external access to a suspected compromised server. If confirmed encryption/exfiltration continues, **escalate** instead of rolling back containment.

**Decision record:** Owner: on-call IR analyst (proposal); approval UTC: pending; signed approval: pending; execution record: `containment_execution.md`.
