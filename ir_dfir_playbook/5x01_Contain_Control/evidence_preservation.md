# Evidence Preservation Runbook: IR-2026-0414-01

- Incident: `IR-2026-0414-01` | Host: `WST-WS-031` | User: `MEDDEFENSE\dmarsh`
- Alert: `A-20260414-9841`, fired `2026-04-14T02:47:11Z`
- Evidence store: `/evidence/IR-2026-0414-01/` (default `EVIDENCE_ROOT=/evidence`)
- Hash algorithm: **SHA-256**
- Initializer's canonical manifest: `/evidence/IR-2026-0414-01/hashes.txt`
- Task-requested manifest copy: `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`
- Acquisition window represented by supplied exports: `2026-04-13T02:47:00Z` to `2026-04-14T02:47:00Z`. **These exports end 11 seconds before the alert**; preserve them unchanged, and obtain a supplemental tail export if the lab requires the alert itself within the complete lookback.
- **Status:** instructions only. The five supplied source files were reviewed; no live acquisitions, DNS export, or evidence-store hashes are claimed to be completed merely by writing this runbook.

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
- **How (exact command):** From an elevated **Windows** console using a validated, approved WinPmem binary. Example for a build supporting `-o` (confirm with `winpmem.exe --help`):

```powershell
& 'C:\IRTools\winpmem.exe' -o 'C:\IRCapture\wst-ws-031.raw'
Get-FileHash 'C:\IRCapture\wst-ws-031.raw' -Algorithm SHA256
```

- **Where (evidence store path):** Acquire to secure, sufficiently large local/removable storage, then securely transfer the unchanged file to `$STORE/memory/wst-ws-031.raw`. The Linux initializer does **not** create a Windows share; use only an approved transfer route and document it. Compare the Windows `Get-FileHash` output against the store's `sha256sum`.
- **Hash algorithm and command (SHA-256):** `sha256sum memory/wst-ws-031.raw >> hashes.txt`
- **Ordering rationale:** Capture before shutdown/reboot/process kill. Network isolation does *not* inherently erase RAM, but may prevent remote memory acquisition. If active harm requires containment first, document the decision and evidence at risk.

## 2. Live process tree (PID, PPID, command line)

- **What:** Running processes, parent PIDs, process names, executable paths, command lines. Alert shows PowerShell PID `7812` -> MSBuild PID `8104`, running `C:\Users\dmarsh\AppData\Local\Temp\update.xml`. These PIDs may no longer exist at capture time.
- **How (exact command):** On the affected Windows workstation in elevated PowerShell:

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\IRCapture\wst-ws-031-processes.csv'
Get-FileHash 'C:\IRCapture\wst-ws-031-processes.csv' -Algorithm SHA256
```

- **Where (evidence store path):** Transfer without modification to `$STORE/process_tree/wst-ws-031-processes.csv`.
- **Hash algorithm and command (SHA-256):** `sha256sum process_tree/wst-ws-031-processes.csv >> hashes.txt`
- **Ordering rationale:** Before killing processes or rebooting; snapshot close in time to the network capture.

## 3. Active connections (TCP and UDP)

- **What:** Current source/destination addresses, ports, TCP state and owning PID, plus UDP endpoints. Alert reports MSBuild PID `8104` connected to `185.220.101.47:443` from `10.42.118.31:54917` at `02:47:02Z`.
- **How (exact command):** Elevated Windows PowerShell:

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

- **Where (evidence store path):** `$STORE/network/wst-ws-031-tcp.csv` and `$STORE/network/wst-ws-031-udp.csv` after documented transfer.
- **Hash algorithm and commands (SHA-256):**

```bash
sha256sum network/wst-ws-031-tcp.csv >> hashes.txt
sha256sum network/wst-ws-031-udp.csv >> hashes.txt
```

- **Ordering rationale:** Before network isolation or IP blocking because live sessions can disappear. Process and connection captures are quick and can be collected before a potentially lengthy RAM image if the incident demands it; document the actual order.

## 4. Endpoint telemetry — 24-hour export

- **What:** Original complete supplied `edr_wst_ws_031_24h.jsonl` (19 JSONL events), including file creation (`update.zip`, `update.xml`, `update.exe`), registry Run-key change, scheduled-task creation, process creation, and network activity. Events include the SIEM detection and a later connection entry at `02:47:30Z`, outside the nominal 24-hour window; **preserve original bytes and metadata instead of filtering it down**.
- **How (exact command):** On Linux, set `LAB` to the directory containing the five uploaded lab files; preserve the supplied export verbatim:

```bash
cp -p -- "$LAB/edr_wst_ws_031_24h.jsonl" "$STORE/endpoint_telemetry/edr_wst_ws_031_24h.jsonl"
(cd "$STORE" && sha256sum endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> hashes.txt)
```

- **Where (evidence store path):** `$STORE/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`.
- **Hash algorithm and command (SHA-256):** `(cd "$STORE" && sha256sum endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> hashes.txt)`
- **Ordering rationale:** Secure early against retention/rotation. Centrally retained telemetry normally remains accessible after isolation; it is not necessarily a blocking prerequisite for isolation. If the lab expects a fresh live export, the specific EDR export API/credentials are not supplied; confirm the WazuhEDR/SIEM export method before running one.

## 5. Original SIEM alert JSON

- **What:** `alert_A-20260414-9841.json`, including original fields, process tree, network connection, enrichment, and recommended playbook `PB-CRED-001 Credential Exposure`.
- **How (exact command):**

```bash
cp -p -- "$LAB/alert_A-20260414-9841.json" "$STORE/siem/alert_A-20260414-9841.json"
(cd "$STORE" && sha256sum siem/alert_A-20260414-9841.json >> hashes.txt)
```

- **Where (evidence store path):** `$STORE/siem/alert_A-20260414-9841.json`.
- **Hash algorithm and command (SHA-256):** `(cd "$STORE" && sha256sum siem/alert_A-20260414-9841.json >> hashes.txt)`
- **Ordering rationale:** Secure original SIEM record before retention/changes; server-side alert remains accessible independently of host isolation. Do not paraphrase or reformat the original bytes.

## 6. Complete identity and web activity preservation — Daniel Marsh, 24h before alert

**Required lookback (UTC):** `2026-04-13T02:47:11Z` through `2026-04-14T02:47:11Z`, anchored to alert `A-20260414-9841` at `02:47:11Z`. **Scope:** user `MEDDEFENSE\dmarsh` / `dmarsh@meddefense.local`, and workstation `WST-WS-031` / `10.42.118.31`. Preserve the original source exports without filtering or modifying them. The supplied proxy and auth exports specify `02:47:00Z`–`02:47:00Z`, offset by 11 seconds: **they are the provided 24-hour baseline, but not an exact 24-hour interval ending at alert time**. A supplemental collection is required to close that 11-second boundary difference where available.

The four required evidence types are separate, with a defined acquisition, destination, SHA-256 entry, and collection order. AD and Azure AD are present within **one supplied, original combined auth export**; preserve it once and additionally make separate, clearly labelled derived copies for independent inspection without altering the original.

### 6A. Proxy — 24-hour user web requests

- **What:** `dmarsh` HTTP/HTTPS requests in `proxy_24h_dmarsh.log`, including suspicious `POST /auth/submit`, ZIP download, and CONNECT to `185.220.101.47:443`.
- **How (exact command):**

```bash
cp -p -- "$LAB/proxy_24h_dmarsh.log" "$STORE/proxy_dns/proxy_24h_dmarsh.log"
```

- **Where:** `/evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log`.
- **Hash command (SHA-256):** `(cd "$STORE" && sha256sum proxy_dns/proxy_24h_dmarsh.log >> hashes.txt)`.
- **Ordering:** Capture centrally retained proxy history immediately after volatile host captures (or concurrently via another analyst), before log retention/rotation; it can normally be copied after host isolation if retention is assured.
- **24h validation:** `grep -F '# Window: 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z' "$STORE/proxy_dns/proxy_24h_dmarsh.log"` checks the supplied coverage. Request the 11-second boundary supplement from the proxy system when an exact alert-anchored interval is required. Do not infer missing events.

### 6B. DNS — 24-hour workstation DNS queries linked to dmarsh

- **What:** Resolver query/response events for `10.42.118.31` (the alert-confirmed IP of Daniel Marsh's host), from `2026-04-13T02:47:11Z` to `2026-04-14T02:47:11Z`. Preserve raw timestamps, queried FQDN, record type, answers, and client IP. DNS events are normally attributable to the host, not directly to a user; join with host/user logs.
- **How (exact command or tool invocation):** Export the complete time range using Splunk Search Export REST API, **if the SOC's DNS logs are stored in Splunk**. Configure the actual index, base URL and read-only token; the file is a collection destination, not a generated reconstruction:

```bash
: "${SPLUNK_URL:?Set the authorized Splunk management URL}"
: "${SPLUNK_TOKEN:?Set a read-only Splunk token}"
: "${DNS_INDEX:?Set the index that actually contains resolver logs}"

curl --fail --silent --show-error \
  -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
  --get "${SPLUNK_URL%/}/services/search/jobs/export" \
  --data-urlencode "search=search index=${DNS_INDEX} (src_ip=10.42.118.31 OR client_ip=10.42.118.31 OR src=10.42.118.31) | sort 0 _time" \
  --data-urlencode "earliest_time=2026-04-13T02:47:11Z" \
  --data-urlencode "latest_time=2026-04-14T02:47:12Z" \
  --data-urlencode "output_mode=json" \
  -o "$STORE/proxy_dns/dns_24h_dmarsh.jsonl"

test -s "$STORE/proxy_dns/dns_24h_dmarsh.jsonl"
jq -e -s 'length > 0 and all(.[]; has("result"))' \
  "$STORE/proxy_dns/dns_24h_dmarsh.jsonl" >/dev/null
```

  Note: Splunk uses an exclusive upper bound; `02:47:12Z` includes the alert's second. Adapt the query field names and time-bound syntax to the real DNS sourcetype if different; confirm every returned event is inside the requested window. If the organization uses a different DNS collector, execute its equivalent authenticated raw-event export instead.
- **Where:** `/evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.jsonl`.
- **Hash command (SHA-256):** `(cd "$STORE" && sha256sum proxy_dns/dns_24h_dmarsh.jsonl >> hashes.txt)` **after validating the export**.
- **Ordering:** Secure central resolver records promptly before rotation; do not delay urgent host containment if source logs are safely retained. Preserve DNS alongside proxy so phishing-domain lookup can be correlated.
- **Source availability:** **The five supplied lab files do not include actual DNS records or Splunk credentials/index details.** This command specifies how to preserve them; a completed DNS acquisition cannot truthfully be certified until the real export is obtained and hashed.

### 6C. Active Directory — 24-hour domain authentication

- **What:** Kerberos ticket requests and Windows logons for `MEDDEFENSE\dmarsh` from domain controllers `ms-dc01` and `ms-dc02`, in the supplied `auth_24h_dmarsh.json`; window recorded by source `2026-04-13T02:47:00Z` to `2026-04-14T02:47:00Z`.
- **How (exact commands, Linux evidence server):** Keep the complete original export, and write a clearly marked **derived AD view** for quick review:

```bash
cp -p -- "$LAB/auth_24h_dmarsh.json" "$STORE/authentication/auth_24h_dmarsh.json"
jq '{export_id,window_start,window_end,user_principal,sources,
     events: [.events[] | select(.source | startswith("ad_"))]}' \
  "$LAB/auth_24h_dmarsh.json" > "$STORE/authentication/ad_24h_dmarsh_derived.json"
```

- **Where:** `/evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json` (unmodified original); `/evidence/IR-2026-0414-01/authentication/ad_24h_dmarsh_derived.json` (derived subset).
- **Hash commands (SHA-256):**

```bash
(cd "$STORE" && sha256sum authentication/auth_24h_dmarsh.json >> hashes.txt)
(cd "$STORE" && sha256sum authentication/ad_24h_dmarsh_derived.json >> hashes.txt)
```

- **Ordering:** Preserve before password changes, ticket revocation or retention rollover. Domain logs reside off-host, so they ordinarily survive workstation isolation. Collect supplemental 11-second boundary events if obtainable.

### 6D. Azure AD (Microsoft Entra ID) — 24-hour cloud sign-ins

- **What:** `dmarsh@meddefense.local` sign-ins, IP/location, MFA result, risk flags and device compliance from the supplied **same original** `auth_24h_dmarsh.json` (source `azure_ad_signin_log`); specifically preserve the `impossibleTravel` flagged event.
- **How (exact command, Linux evidence server):** Generate a separate review copy from the already preserved combined authentication export (do not overwrite the original):

```bash
jq '{export_id,window_start,window_end,user_upn,sources,
     events: [.events[] | select(.source == "azure_ad")]}' \
  "$STORE/authentication/auth_24h_dmarsh.json" \
  > "$STORE/authentication/azure_ad_24h_dmarsh_derived.json"
```

- **Where:** `/evidence/IR-2026-0414-01/authentication/azure_ad_24h_dmarsh_derived.json` plus the unmodified original `authentication/auth_24h_dmarsh.json`.
- **Hash command (SHA-256):** `(cd "$STORE" && sha256sum authentication/azure_ad_24h_dmarsh_derived.json >> hashes.txt)`; the source file hash is recorded in 6C.
- **Ordering:** Copy before revoking cloud sessions or refresh tokens and before sign-in-log retention expires. The source is centrally stored and generally remains accessible after host isolation; request supplemental boundary records if available.

### Unified 24-hour coverage check (run before containment handoff)

| Required stream | Original evidence | Preserved-store path | Status at runbook creation |
|---|---|---|---|
| Proxy | `proxy_24h_dmarsh.log` | `proxy_dns/proxy_24h_dmarsh.log` | Supplied source; capture and hash required |
| DNS | Resolver export (not in lab uploads) | `proxy_dns/dns_24h_dmarsh.jsonl` | Collection command provided; **not acquired** |
| Active Directory | AD events in `auth_24h_dmarsh.json` | `authentication/auth_24h_dmarsh.json` and `ad_24h_dmarsh_derived.json` | Supplied source; capture and hash required |
| Azure AD / Entra | Azure AD events in `auth_24h_dmarsh.json` | `authentication/auth_24h_dmarsh.json` and `azure_ad_24h_dmarsh_derived.json` | Supplied source; capture and hash required |

All streams must cover the actual **24 hours immediately preceding the alert**, not merely contain a few relevant events. The supplied exports end 11 seconds before the alert; investigate and supplement that discrepancy. **Do not mark the full four-stream bundle complete without actual DNS acquisition, boundary coverage confirmation, successful SHA-256 hashes, and a custody entry for each artifact.**

## 9. Verification and integrity handoff

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
