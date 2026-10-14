# Evidence Preservation Runbook: IR-2026-0414-01

- Incident: `IR-2026-0414-01` | Host: `WST-WS-031` | User: `MEDDEFENSE\dmarsh`
- Alert: `A-20260414-9841`, fired `2026-04-14T02:47:11Z`
- Evidence store: `/evidence/IR-2026-0414-01/` (default `EVIDENCE_ROOT=/evidence`)
- Hash algorithm: **SHA-256**
- Initializer's canonical manifest: `/evidence/IR-2026-0414-01/hashes.txt`
- Task-requested manifest copy: `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`
- Acquisition window represented by supplied exports: `2026-04-13T02:47:00Z` to `2026-04-14T02:47:00Z`. **These exports end 11 seconds before the alert**; preserve them unchanged, and obtain a supplemental tail export if the lab requires the alert itself within the complete lookback.
- **Status:** instructions only. The five supplied source files were reviewed; no live memory image, live process snapshot, live connection snapshot, DNS export, or evidence-store hash has been acquired by writing this runbook.

## 0. Initialize the store and record custody

The actual `evidence_store_init.sh` creates `memory/`, `disk/`, `process_tree/`, `network/`, `endpoint_telemetry/`, `siem/`, `proxy_dns/`, `authentication/`, `malware/`, and `correlation/`, and initializes **`hashes.txt`**, not the task's longer manifest filename. It refuses to overwrite an existing incident directory. There is **no SMB share mapping** created by this script.

On the **Linux evidence server**, from the lab directory containing the initializer and supplied exports:

```bash
#!/bin/bash
set -euo pipefail
# Run ONLY ONCE, if incident store does not already exist.
bash evidence_store_init.sh
STORE="${EVIDENCE_ROOT:-/evidence}/IR-2026-0414-01"
cd "$STORE"
# Add a provenance note to the incident timeline: collector, UTC time,
# collection method, source location and custody transfer for each artifact.
```

Run once only; if it already exists, skip initialization and inspect its contents. Restrict store write access to the evidence custodian. Obtain required administrative approval and free disk space before RAM acquisition. **Do not delete or reset artifacts to rerun the initializer.**

For every artifact moved to the store, calculate SHA-256 immediately and append one `sha256sum`-compatible line from inside the store:

```bash
cd "$STORE"
sha256sum relative/path/to/artifact >> hashes.txt
```

Store the original capture hash and acquisition metadata separately in the case log (time UTC, collector, host, tool version, transfer source/destination). When transfer is involved, hash at the acquisition location *and* after transfer and compare. Never overwrite a prior manifest entry; if a correction is needed, record it separately.

## 1. Full volatile memory — first if safely feasible

- **What:** Full RAM from `WST-WS-031`, including injected memory and process context. EDR telemetry includes a `process_memory_region` event at `02:47:14Z`, reinforcing the need for a memory image.
- **How:** From an elevated **Windows** console using a validated, approved WinPmem binary. Example for a build supporting `-o` (confirm with `winpmem.exe --help`):

```powershell
& 'C:\IRTools\winpmem.exe' -o 'C:\IRCapture\wst-ws-031.raw'
Get-FileHash 'C:\IRCapture\wst-ws-031.raw' -Algorithm SHA256
```

- **Where:** Acquire to secure, sufficiently large local/removable storage, then securely transfer the unchanged file to `$STORE/memory/wst-ws-031.raw`. The Linux initializer does **not** create a Windows share; use only an approved transfer route and document it. Compare the Windows `Get-FileHash` output against the store's `sha256sum`.
- **Store hash:** `sha256sum memory/wst-ws-031.raw >> hashes.txt`
- **Ordering:** Capture before shutdown/reboot/process kill. Network isolation does *not* inherently erase RAM, but may prevent remote memory acquisition. If active harm requires containment first, document the decision and evidence at risk.

## 2. Live process tree (PID, PPID, command line)

- **What:** Running processes, parent PIDs, process names, executable paths, command lines. Alert shows PowerShell PID `7812` -> MSBuild PID `8104`, running `C:\Users\dmarsh\AppData\Local\Temp\update.xml`. These PIDs may no longer exist at capture time.
- **How:** On the affected Windows workstation in elevated PowerShell:

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\IRCapture\wst-ws-031-processes.csv'
Get-FileHash 'C:\IRCapture\wst-ws-031-processes.csv' -Algorithm SHA256
```

- **Where:** Transfer without modification to `$STORE/process_tree/wst-ws-031-processes.csv`.
- **Store hash:** `sha256sum process_tree/wst-ws-031-processes.csv >> hashes.txt`
- **Ordering:** Before killing processes or rebooting; snapshot close in time to the network capture.

## 3. Active connections (TCP and UDP)

- **What:** Current source/destination addresses, ports, TCP state and owning PID, plus UDP endpoints. Alert reports MSBuild PID `8104` connected to `185.220.101.47:443` from `10.42.118.31:54917` at `02:47:02Z`.
- **How:** Elevated Windows PowerShell:

```powershell
Get-NetTCPConnection |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\IRCapture\wst-ws-031-tcp.csv'
Get-NetUDPEndpoint |
  Select-Object LocalAddress,LocalPort,OwningProcess |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\IRCapture\wst-ws-031-udp.csv'
Get-FileHash 'C:\IRCapture\wst-ws-031-tcp.csv' -Algorithm SHA256
Get-FileHash 'C:\IRCapture\wst-ws-031-udp.csv' -Algorithm SHA256
```

- **Where:** `$STORE/network/wst-ws-031-tcp.csv` and `$STORE/network/wst-ws-031-udp.csv` after documented transfer.
- **Store hashes:**

```bash
sha256sum network/wst-ws-031-tcp.csv >> hashes.txt
sha256sum network/wst-ws-031-udp.csv >> hashes.txt
```

- **Ordering:** Before network isolation or IP blocking because live sessions can disappear. Process and connection captures are quick and can be collected before a potentially lengthy RAM image if the incident demands it; document the actual order.

## 4. Endpoint telemetry — 24-hour export

- **What:** Original complete supplied `edr_wst_ws_031_24h.jsonl` (19 JSONL events), including file creation (`update.zip`, `update.xml`, `update.exe`), registry Run-key change, scheduled-task creation, process creation, and network activity. Events include the SIEM detection and a later connection entry at `02:47:30Z`, outside the nominal 24-hour window; **preserve original bytes and metadata instead of filtering it down**.
- **How:** On Linux, set `LAB` to the directory containing the five uploaded lab files; preserve the supplied export verbatim:

```bash
cp -p -- "$LAB/edr_wst_ws_031_24h.jsonl" "$STORE/endpoint_telemetry/edr_wst_ws_031_24h.jsonl"
(cd "$STORE" && sha256sum endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> hashes.txt)
```

- **Where:** `$STORE/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`.
- **Ordering:** Secure early against retention/rotation. Centrally retained telemetry normally remains accessible after isolation; it is not necessarily a blocking prerequisite for isolation. If the lab expects a fresh live export, the specific EDR export API/credentials are not supplied; confirm the WazuhEDR/SIEM export method before running one.

## 5. Original SIEM alert JSON

- **What:** `alert_A-20260414-9841.json`, including original fields, process tree, network connection, enrichment, and recommended playbook `PB-CRED-001 Credential Exposure`.
- **How:**

```bash
cp -p -- "$LAB/alert_A-20260414-9841.json" "$STORE/siem/alert_A-20260414-9841.json"
(cd "$STORE" && sha256sum siem/alert_A-20260414-9841.json >> hashes.txt)
```

- **Where:** `$STORE/siem/alert_A-20260414-9841.json`.
- **Ordering:** Secure original SIEM record before retention/changes; server-side alert remains accessible independently of host isolation. Do not paraphrase or reformat the original bytes.

## 6. Proxy and DNS logs — Daniel Marsh

- **What:** Existing `proxy_24h_dmarsh.log` for the stated 24-hour window. It records a `POST /auth/submit` at `2026-04-13T18:14:41Z`, an `update.zip` GET at `18:14:43Z`, and Tor-IP CONNECT entries around the alert. This supports a suspected phishing/endpoint-compromise chain but does not, alone, prove which credentials were disclosed. Also request actual DNS query/response records for host IP `10.42.118.31` (verify historical user-to-IP attribution).
- **How — provided proxy file:**

```bash
cp -p -- "$LAB/proxy_24h_dmarsh.log" "$STORE/proxy_dns/proxy_24h_dmarsh.log"
(cd "$STORE" && sha256sum proxy_dns/proxy_24h_dmarsh.log >> hashes.txt)
```

- **How — DNS:** The five supplied files contain **no independent DNS log export** or DNS API invocation. Export DNS records from the organization's authoritative resolver/SIEM for `2026-04-13T02:47:00Z`–`2026-04-14T02:47:11Z` with query timestamp, client IP, query, response and source, preserving raw format as `dns_24h_dmarsh.jsonl`. After the export exists:

```bash
# Execute only after the actual DNS export was produced in the store.
(cd "$STORE" && sha256sum proxy_dns/dns_24h_dmarsh.jsonl >> hashes.txt)
```

- **Where:** `$STORE/proxy_dns/proxy_24h_dmarsh.log`; `$STORE/proxy_dns/dns_24h_dmarsh.jsonl` **pending export**.
- **Ordering:** Central logs can usually be collected after host isolation, but promptly secure them before rotation and to correlate with authentication events. Do not claim the DNS export is complete until produced.

## 7. Authentication: Active Directory and Azure AD (Entra ID)

- **What:** Original `auth_24h_dmarsh.json`, which explicitly lists `ad_domain_controller_ms-dc01`, `ad_domain_controller_ms-dc02`, and `azure_ad_signin_log` as sources. Preserve all events and MFA/device-risk fields; notably, an Azure AD sign-in from `45.63.9.88` was marked `impossibleTravel` at `2026-04-13T18:14:41Z`, and the record contains successful workstation authentication around `02:44Z`. This is a risk indicator, not conclusive attribution to an attacker.
- **How:**

```bash
cp -p -- "$LAB/auth_24h_dmarsh.json" "$STORE/authentication/auth_24h_dmarsh.json"
(cd "$STORE" && sha256sum authentication/auth_24h_dmarsh.json >> hashes.txt)
```

- **Where:** `$STORE/authentication/auth_24h_dmarsh.json`.
- **Ordering:** Retained central identity events normally survive workstation isolation; preserve quickly before log rollover or credential/session remediation. A supplementary post-alert sign-in export may be necessary for full scope, but the lab supplies no live domain controller/Entra extraction tool or credentials.

## 8. Verification and integrity handoff

Only after the evidence is actually captured/transferred and the corresponding `hashes.txt` lines appended:

```bash
#!/bin/bash
set -euo pipefail
STORE="${EVIDENCE_ROOT:-/evidence}/IR-2026-0414-01"
cd "$STORE"
# Recompute hashes on evidence files and compare with the original manifest.
sha256sum --check hashes.txt
# Create the specifically requested named snapshot without rewriting hashes.txt.
cp -p -- hashes.txt IR-2026-0414-01-hashes.txt
# Independently verify against the named snapshot as well.
sha256sum --check IR-2026-0414-01-hashes.txt
```

Check that each acquired artifact has **one entry**, no unexpected missing items, and a documented source acquisition hash. `sha256sum --check` does not detect files omitted from the manifest. If a hash mismatch occurs, **do not replace evidence or overwrite a prior hash**; record the mismatch, UTC time, collector, and artifact in `incident_timeline.md` as a new `OBSERVATION`. Log incomplete acquisitions (especially live memory, live snapshots, or DNS) explicitly. Protect the manifest and its separately stored or signed custody copy from modification. Append an `EVIDENCE` timeline entry for each successful acquisition with path, SHA-256, method, UTC timestamp, and collector. Do not document any step as completed until its proof exists.

**Containment gate:** Before executing the chosen containment action, confirm that the live evidence which the action would destroy/invalidate has been acquired **or** document an emergency exception. Central SIEM/proxy/DNS/AD/Entra logs may be preserved immediately after isolation if retention and access are guaranteed.
