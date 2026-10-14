# Containment Decision: IR-2026-0414-01

- affected_host: `WST-WS-031` (`10.42.118.31`)
- account: `MEDDEFENSE\dmarsh`
- current_severity: `SEV2` (per initial timeline; reassess as scope develops)
- status: **Option A recommended; approval, preservation completion, and execution not verified**
- supporting_sources: `alert_A-20260414-9841.json`, `edr_wst_ws_031_24h.jsonl`, `proxy_24h_dmarsh.log`, `auth_24h_dmarsh.json`, `evidence_preservation.md`

## Relevant evidence and risk

- The alert reports PowerShell PID 7812 launching MSBuild PID 8104 with `C:\Users\dmarsh\AppData\Local\Temp\update.xml`, and an established connection to `185.220.101.47:443` (classified as a Tor exit relay by internal threat intelligence).
- EDR records `update.exe` started by a logon-triggered scheduled task, the PowerShell → MSBuild process chain, and a suspicious executable memory region in MSBuild. This increases concern that stopping a single process will not remove persistence.
- Proxy logs show a POST to a Microsoft 365 lookalike site and retrieval of `update.zip`; authentication logs show a successful sign-in flagged for impossible travel. Credential theft and attacker attribution remain unconfirmed.
- The host is a **high-criticality clinical workstation** owned by West Campus Laboratory. The number and availability of alternative workstations have **not** been verified.

## Candidate strategies

### A. Network isolation — quarantine VLAN (preferred)

- **action:** With network-team/IR approval, place `WST-WS-031` in a quarantine VLAN (e.g., VLAN 999 *only if it exists and is approved*). Deny ordinary outbound and lateral traffic; permit tightly scoped, logged connections **only** from the designated forensic jumpbox and any explicitly approved management services. Validate both IPv4 and IPv6 filtering where applicable.
- **attacker effect:** Cuts off current external communication and restricts lateral movement; any attacker code already running locally may continue executing, so follow-on investigation is essential.
- **evidence effect:** Usually keeps the host powered on, preserving RAM, processes, and local disk. Active sessions will break and live connection state changes; snapshot them **before** isolation where safe. Verify that forensic access actually remains available.
- **patient care effect:** The affected workstation loses routine LIS and clinical-network access until cleared; the laboratory must confirm a safe alternate workflow and device availability. **Four spare workstations are not established by the supplied evidence.**
- **time to execute:** **Planning estimate ~5 minutes**, contingent on network controls and approvals; not an observed duration.
- **reversibility:** Generally reversible by restoring the original port/VLAN or EDR isolation policy, but only under incident-command approval; original sessions may not automatically resume.

### B. Host power-off

- **action:** Shut down or power off `WST-WS-031` immediately.
- **attacker effect:** Stops running code and live communications on that host until power returns, but does not remove persistence or stolen credentials.
- **evidence effect:** **Destroys volatile RAM state, running processes, and live connections**; may also trigger a clean-shutdown state change on disk. A cold forensic disk image remains possible.
- **patient care effect:** Immediately stops use of the workstation for laboratory work until it is restored; alternative clinical workflow must be coordinated.
- **time to execute:** **Planning estimate under 1 minute** for power-off; not an observed duration.
- **reversibility:** Power can be restored, but the lost volatile evidence cannot be recovered by turning the host back on.

### C. Selective process termination + targeted egress block

- **action:** After capturing process/memory/network evidence, block `185.220.101.47:443` at an approved enforcement point and terminate confirmed malicious processes (e.g., only when safely identified). Continue monitoring and investigate scheduled tasks and other persistence mechanisms.
- **attacker effect:** May stop the observed connection while leaving other processes, alternate destinations, stolen credentials, or persistence active; EDR shows a logon-triggered `update.exe` that could restart the chain.
- **evidence effect:** Leaves much of the system usable and observable, but termination irreversibly changes process state and can destroy in-memory clues. Firewall rules also change network evidence.
- **patient care effect:** Potentially maintains LIS availability on the workstation; a legitimate shared destination or misidentified process could still disrupt care.
- **time to execute:** **Planning estimate ~2–5 minutes** for rules and validated process actions; not an observed duration.
- **reversibility:** Firewall rules can be removed; killed processes and their lost volatile state cannot be restored exactly.

## Chosen strategy: A — Network isolation (quarantine VLAN)

**Rationale:** Option A offers the best balance for this SEV2 clinical-workstation incident: it limits the observed external connection and potential lateral movement while keeping the system powered on for forensic examination, and the quarantine policy can normally be rolled back. Option B acts quickly but irreversibly destroys volatile memory and process evidence; Option C may keep laboratory workflows running but risks missing the documented scheduled-task persistence and other attacker channels. Option A still interrupts the workstation's LIS access, so laboratory leadership must confirm an alternate clinical workflow; spare workstations cannot be assumed. Capture live connections/process state and needed memory first if safely feasible, or record an urgent-containment exception.

## Preservation-to-containment execution window

- **Preservation runbook:** `evidence_preservation.md`; evidence store `/evidence/IR-2026-0414-01/`.
- **Evidence preservation end (UTC):** **NOT PROVIDED / NOT VERIFIED**. Fill from actual acquisition records and SHA-256 manifest; creating the runbook does not mean evidence was collected.
- **Containment execution start (UTC):** **NOT PROVIDED / NOT EXECUTED IN THIS DOCUMENT**. Record the actual time during Task 4.
- **Gap duration:** Cannot yet be calculated. Once both UTC times exist, calculate `containment_start − preservation_end` and record it. Minimize the gap and monitor for additional activity throughout.
- **Pre-execution gate:** Confirm evidence status; verify approved quarantine policy and forensic jumpbox access; obtain clinical impact assessment and authorization; record approval and the actual command/action in the incident timeline.

## Approval

- **Approving authority:** **James Chen, SOC Lead / IR Commander** (named in incident context).
- **Approval status:** **PENDING VERIFICATION** — no approval timestamp or recorded authorization for this specific containment action was provided. Do not write “approved at 03:10Z” without an actual record.
- **Execution owner:** On-call SOC analyst with the authorized network/EDR administrator, as required by local change controls; specific person not recorded.

## Rollback plan

1. If quarantine unexpectedly disrupts essential laboratory operations, notify James Chen and the laboratory service owner immediately; assess patient-safety impact and confirm an approved replacement workstation or manual downtime process.
2. If rollback is authorized, remove the quarantine assignment and restore **only the documented prior network policy**. Avoid full unrestricted reconnection of a still-compromised host unless the clinical safety decision explicitly accepts and mitigates that security risk.
3. If the original workstation cannot remain isolated, use a controlled fallback: restricted access to explicitly required LIS endpoints, deny known attacker destinations, closely monitor EDR/network activity, and prioritize transferring care to a known-clean workstation. Do not assume that Option C alone contains persistence.
4. Confirm restored clinical function with the laboratory owner and check that security monitoring remains active. Record times, authorizer, changes, residual risks, and observed results in `incident_timeline.md`.

## Before proceeding to Task 4

- Record actual approval, clinical coordination, completed evidence acquisitions and hashes.
- Record the planned-to-actual decision transition as an additional timestamped timeline entry; **no containment action has yet been claimed**.
