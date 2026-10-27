# IR Activation — IR-2026-0420-01

- **Incident ID:** IR-2026-0420-01
- **Declaration time (UTC):** 2026-04-20T19:52:00Z (exercise target; confirm against the actual incident log)
- **Declared by:** On-call IR analyst (student; enter your name)
- **Initial severity:** SEV1 — Critical
- **Status:** Declaration draft; authorization, notifications, and actual send times require confirmation

## Severity reasoning

A nurse reported severe slowdown and changed-looking desktop filenames on clinical coordinator workstation `CS-WS-101` at the emergency department charge desk. Network engineer Mike Torres also reported sustained high CPU and disk activity on `SCHED-SVR-01` and SIEM rule `wz-edr-200214` indicating suspicious service installations on `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`. The service `WinHealthSvc` points to `C:\ProgramData\Microsoft\svchost32.exe`, an unusual path and filename. Multiple clinical systems, possible malicious persistence, potential file alteration, and possible disruption of patient care justify immediate SEV1 response. **At activation, ransomware execution, data exfiltration, and the precise cause of the scheduling-server load are not yet confirmed by the call transcript.**

## Playbook activated

- **Primary:** Major cybersecurity incident / suspected ransomware containment playbook from 5x00–5x04 (replace with exact existing playbook name and version).
- **Supporting:** Credential exposure and forensic evidence preservation procedures, pending scope confirmation.
- **Why:** Multiple affected clinical workstations, suspicious service installation, potential file alteration, and possible patient-care impact require coordinated containment and evidence capture.

## Notification register — complete with actual send records

| Required recipient | Purpose | Target UTC | Actual UTC | State |
|---|---|---|---|---|
| IR incident commander / James (role to verify) | Incident command and SEV1 escalation | 19:52 | Not provided | Pending verification |
| Mike Torres, network engineer | Bridge, acquisition and network containment coordination | 19:52 | Already on call since 19:43:18 | Confirmed present |
| Dr. Morales, executive sponsor | Executive escalation and patient-care risk | 19:54 | Not provided | Pending verification |
| Clinical operations / ED lead | Coordinate safe isolation without interrupting patient care | 19:56 | Not provided | Pending verification |
| Helena Reyes, General Counsel | Potential patient information exposure / breach assessment | 19:58 | Not provided | Pending verification |
| SOC / IT operations | Multi-host monitoring and containment support | 20:00 | Not provided | Pending verification |

The targets above are a proposed first-15-minute notification plan, **not evidence that messages were sent**. Replace recipient titles, targets and actual timestamps using the 5x00 communication matrix and communications log.

## First communication — draft, not confirmed sent

**Audience:** Dr. Morales (executive sponsor); intended at 20:05Z, subject to actual communication records.

> MedDefense has declared a critical security incident affecting clinical workstations at Main. A nurse has reported unusual file changes and poor workstation performance, while our monitoring has identified suspicious software installations on three additional clinical workstations. The scheduling server is also experiencing unusually high activity; its connection to the incident has not yet been established. We are coordinating with clinical operations to protect patient care, preserve evidence, determine the full scope, and contain the suspected threat. We will provide a further update as soon as the immediate containment status and operational impact are confirmed.

## Initial evidence and handling notes

- Primary source: `torres_call_transcript.md`, call started `2026-04-20T19:43:18Z`, reviewed and signed by Torres at `21:10Z`.
- Torres captured memory of `CS-WS-101` using WinPmem at `19:38Z`; file written to `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` at `19:41Z`.
- **No acquisition SHA-256 was recorded.** Compute a hash immediately, preserve the original, and explicitly note that later hashing cannot establish an acquisition-time baseline.
- Torres reported he had not isolated the host or touched the other systems. The nurse was instructed to stop interacting with `CS-WS-101`.
- The transcript's heading states 2026-04-20, which falls on a Monday; follow the evidence timestamps, and flag the narrative's 'Sunday' label for reconciliation.
