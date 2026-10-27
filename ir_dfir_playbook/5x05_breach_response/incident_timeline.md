# Incident Timeline — IR-2026-0420-01

**Rules:** Append-only. All times UTC. Never rewrite earlier records; add corrective entries. Each entry contains timestamp, type, actor, description, source, and certainty. Distinguish reported activity from direct forensic confirmation.

| Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| 2026-04-20T19:43:22Z | OBSERVATION | Mike Torres (relaying nurse report) | Nurse at Main reports `CS-WS-101` is very slow and desktop filenames look changed; Torres has not independently verified the file changes. | `torres_call_transcript.md`, 19:43:22–19:43:50 | Confirmed report; underlying change unverified |
| 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres | Reports SIEM rule `wz-edr-200214` fired for suspicious service installation on `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`; reports service `WinHealthSvc` at `C:\ProgramData\Microsoft\svchost32.exe` at 19:44:48. | `torres_call_transcript.md`, 19:44:20–19:44:48 | Confirmed report; SIEM records not yet independently reviewed |
| 2026-04-20T19:52:00Z | DECISION | On-call IR analyst (student) | **Proposed exercise declaration:** SEV1 major security incident `IR-2026-0420-01`; initiate major incident/suspected ransomware playbook and notify response stakeholders. Must be confirmed as an actual declaration from IR records. | Capstone Task 0 expected declaration time; transcript handoff notes at 19:52Z | Proposed; not independently verified |

**Pre-activation evidence to append after first three opening entries:** Torres states WinPmem acquisition at 19:38Z, writing the memory dump at 19:41Z, with no acquisition hash. Document in the evidence register and Task 1 chain of custody; do not retroactively present those events as logged actions by the student.
