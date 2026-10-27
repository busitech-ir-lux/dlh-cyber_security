# Evidence Preservation — IR-2026-0420-01

**Scope:** `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`, `FILE-SVR-01` (five hosts).  
**Status:** Acquisition plan and documented pre-existing capture; **not an execution report**. Times are UTC. Do not mark any planned collection as completed without evidence.  
**Principle:** Capture volatile memory as quickly as safely possible, in parallel where staff permit; preserve integrity and chain of custody; do not delay urgent containment if patients or systems are at imminent risk.

## 1. Priority and acquisition order

| Priority | Host | Capture first | Reason |
|---|---|---|---|
| Already captured | `CS-WS-101` | Memory taken at **19:38Z**; record and verify it; urgently image disk | Initial clinical coordinator workstation; possible active attacker process and ransomware preparation. Disk evidence may contain initial phishing document and persistence. |
| 1 (parallel with WS-101 disk) | `CS-WS-104` | Memory, then system/disk evidence | Suspicious `WinHealthSvc` service and `svchost32.exe` reported by SIEM; process/network data could vanish on isolation. |
| 2 (parallel if possible) | `CS-WS-107` | Memory, then system/disk evidence | Same suspicious service alert; prioritize volatile process, credentials, and connections. |
| 3 | `FILE-SVR-01` | Relevant logs and volatile state; disk or targeted forensic acquisition | Holds the patient-document access records and may be needed for clinical care. Coordinate collection with owner; avoid unnecessary outage. No beacon has been independently established on this server. |
| 4 | `CS-WS-112` | Memory, then system/disk evidence | Same service-install alert; capture promptly. Its lower order is an operational choice, **not proof** it has no active beacon. |

**Important distinction:** The transcript confirms suspicious *service installation alerts* on WS-104/107/112, **not** confirmed live beaconing on these hosts. The scenario names `SCHED-SVR-01` as a separate abnormal server; add it to investigation scope and preserve its logs, but it is not one of the five specified acquisition targets. If active ransomware/encryption is verified, containment takes priority over waiting for full disk imaging; log the exception.

## 2. Acquisition procedure (repeat on each host)

1. Assign unique artifact ID, UTC acquisition time, operator, source hostname, source path, and evidence storage destination. Use a restricted evidence share; do not work on originals.
2. **Memory (Windows, elevated IR shell):** use the approved/signed WinPmem binary and write to dedicated evidence storage. Example, after verifying the installed binary's supported syntax:

   ```powershell
   # Example: adapt approved WinPmem binary name, flags and destination to your lab
   .\winpmem_mini_x64.exe "\\evidence\share\IR-2026-0420-01\CS-WS-104.mem"
   ```

   Record capture start/end, tool/version, any errors, and whether the host was network-connected. Run comparable captures on `CS-WS-107`, `FILE-SVR-01` (if safe), and `CS-WS-112`. **Do not reacquire `CS-WS-101` merely to replace the original capture**; a second capture, if authorized, must be a separate artifact.
3. **Volatile system details:** export active process list, active connections, and relevant service/task status to per-host files (capture from a trusted remote-response session, minimizing changes):

   ```powershell
   Get-Process | Select-Object Id,ProcessName,Path,StartTime | Export-Csv "C:\IR\processes.csv" -NoTypeInformation
   Get-NetTCPConnection | Export-Csv "C:\IR\connections.csv" -NoTypeInformation
   Get-CimInstance Win32_Service | Select-Object Name,PathName,State,StartMode | Export-Csv "C:\IR\services.csv" -NoTypeInformation
   Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Export-Csv "C:\IR\tasks.csv" -NoTypeInformation
   ```

   **Caution:** Writing to `C:\IR` modifies the source host; prefer the evidence share or trusted EDR remote acquisition when available, and document any writes. Some properties may be missing or inaccessible. Export event logs using `wevtutil epl Security ...` and `wevtutil epl Microsoft-Windows-Sysmon/Operational ...` to the protected destination when authorized.
4. **Disk/non-volatile evidence:** collect bit-for-bit images with an approved write-protected forensic method (e.g., FTK Imager/E01 or raw `.dd`), or justified targeted acquisition for critical servers. Record exact tool/version, source volume(s), format, acquisition time, disk capacity, errors, and operator. Maintain immutable original; perform TSK analysis on a verified working copy. For `CS-WS-101`, the supplied image is called `cs-ws-101.dd` but its acquisition tool, timestamp, and hash are **not yet provided**.
5. **Hash before analysis:** compute SHA-256 on the received original, document the hash and verification time, compare against an **independently recorded acquisition hash**. Example on the Linux forensic workstation:

   ```bash
   sha256sum -- 'cs-ws-101.mem' 'cs-ws-101.dd'
   sha256sum -- 'CS-WS-104.mem'  # after this file is actually acquired
   # When a trusted manifest exists, run from the evidence directory:
   sha256sum -c acquisition_hashes.sha256
   ```

   Hash all exported EVTX/log files and images in the same way. Record hashes in the custody ledger (not only an unprotected local text file).
6. **Transfer and custody:** note each hand-off, sender/receiver, date/time, transfer mechanism, storage location, seal/access control, and hash at both ends. Verify that working-copy SHA-256 equals the recorded original hash before analysis. Do not publish raw memory or patient records in reports.

## 3. ART-001: already acquired CS-WS-101 memory

- **Source host:** `CS-WS-101` (initially compromised clinical coordinator workstation)
- **Operator:** Mike Torres, Network Engineer
- **Reported tool:** WinPmem (exact version/flags not recorded)
- **Capture reported at:** `2026-04-20T19:38:00Z`; exact start/end not supplied
- **File written at:** `2026-04-20T19:41:00Z`
- **Destination:** `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem`
- **Acquisition SHA-256:** **NOT RECORDED** (explicitly acknowledged by Torres)
- **Analyst SHA-256:** **PENDING**; calculate before analysis, record full output and timestamp
- **Integrity conclusion:** integrity **cannot be independently verified against acquisition state** without a baseline hash. A later hash establishes the received copy's baseline only; do not say "matches the acquisition hash".
- **Time interpretation:** acquisition at 19:38Z was **5m18s before** the call began (`19:43:18Z`), and written at 19:41Z **2m18s before** the call. The call itself lasted 4m22s. If using the exercise declaration time 19:52Z, acquisition preceded declaration by **14 minutes**.
- **Handling:** Torres did not isolate the workstation before the call; nurse was told to stop using the console (handoff note, no exact time). Preserve and verify the original; document any later transfer.

## 4. Per-host collection checklist

| Host | Memory | Non-volatile capture | Additional priority evidence | Execution status |
|---|---|---|---|---|
| `CS-WS-101` | `ART-001` reported captured; hash pending | `cs-ws-101.dd`: provenance/hash unknown | Word file, PowerShell script, suspect DLL, registry/services/tasks | **Partially reported; not verified** |
| `CS-WS-104` | WinPmem → `CS-WS-104.mem` | forensic disk image; Security/Sysmon EVTX | `WinHealthSvc`, process tree, open connections, account artifacts | **Planned** |
| `CS-WS-107` | WinPmem → `CS-WS-107.mem` | forensic disk image; Security/Sysmon EVTX | same as above | **Planned** |
| `FILE-SVR-01` | memory if safe and approved | `fileserver_access.evtx`, Security log, relevant volumes or targeted snapshot | file/object-access records, logons, account and patient-file paths | **Planned** |
| `CS-WS-112` | WinPmem → `CS-WS-112.mem` | forensic disk image; Security/Sysmon EVTX | `WinHealthSvc`, lateral logons, scheduled tasks | **Planned** |

## 5. Chain of custody register (five hosts)

| Artifact / Host | Acquired by / at (UTC) | Source and destination | SHA-256 status | Custodian / transfer | State |
|---|---|---|---|---|---|
| `ART-001` — `CS-WS-101.mem` | Mike Torres / reported 2026-04-20 19:38Z (written 19:41Z) | `CS-WS-101` → `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` | **Missing at acquisition; analyst hash pending** | Torres → evidence share; receiving custodian/time **not documented** | Reported captured |
| `ART-002` — `CS-WS-101.dd` | Unknown / pending confirmation | `CS-WS-101` → forensic repository (location pending) | Pending | Pending | Provided as case artifact; provenance unverified |
| `ART-003` — `CS-WS-104.mem` (+ disk/logs) | Assigned acquirer / **pending** | `CS-WS-104` → restricted evidence share | Pending | Pending | Planned |
| `ART-004` — `CS-WS-107.mem` (+ disk/logs) | Assigned acquirer / **pending** | `CS-WS-107` → restricted evidence share | Pending | Pending | Planned |
| `ART-005` — `FILE-SVR-01` memory/logs/image | Assigned acquirer / **pending** | `FILE-SVR-01` → restricted evidence share | Pending | Pending | Planned |
| `ART-006` — `CS-WS-112.mem` (+ disk/logs) | Assigned acquirer / **pending** | `CS-WS-112` → restricted evidence share | Pending | Pending | Planned |

**Ledger completion rule:** Enter actual acquisition/transfer times, operator, tool version, SHA-256 hashes, errors, and verification results when available. Do not fabricate or backfill them from the scenario. Record each subsequent hand-off as an additional custody transaction, never overwrite the original.

## 6. Gate before Task 2 containment

Confirm `ART-001` is hashed and stored immutably; acquire prioritized live memory as safely possible; obtain critical file-server logs; document remaining evidence-at-risk. If rapid containment is necessary to prevent ransomware or protect care delivery, obtain incident commander authorization and explicitly record any acquisition deferred and why.
