# Forensic Findings — IR-2026-0420-01

**Status:** Preliminary — sample-derived leads, NOT a completed full-artifact forensic examination  
**Incident:** MedDefense, 17–20 April 2026 (UTC)  
**Analyst:** On-call IR analyst (student)  
**Evidence available for this draft:** `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`, `fileserver_access.sample.json`, and Torres's signed-off transcript (provided in chat).  
**Not supplied:** `cs-ws-101.mem`, `cs-ws-101.dd`, `proxy_72h.jsonl`, `sysmon_multihost.jsonl`, `fileserver_access.evtx`. The sample files are **schema references only under Task 4**; all operational conclusions must be rerun against originals before being promoted to `confirmed`.

## Evidence integrity gate

- **ART-001:** `cs-ws-101.mem` reportedly acquired with WinPmem at `2026-04-20T19:38Z`, written to evidence share at 19:41Z (Torres transcript). No acquisition hash was recorded. **Integrity status: pending.** A hash computed now is a starting baseline, **not verification against acquisition**.
- Work from read-only copies. Record analyst, UTC time, filename, original location, size, tool version, and SHA-256 in the chain-of-custody log. Preserve the originals.

```bash
# Run inside the directory holding the full forensic artifacts
sha256sum cs-ws-101.mem cs-ws-101.dd proxy_72h.jsonl sysmon_multihost.jsonl fileserver_access.evtx | tee analysis_sha256.txt
# Compare each against its documented acquisition hash, when one exists.
# For ART-001 note "no acquisition hash available", do not write "match".
```

## Memory examination — cs-ws-101.mem (pending)

Commands below must be run on the **full memory dump**, not sample JSON. Save relevant tool output and link each finding to its captured output/hash.

| Finding | Exact command | Evidence to record | ATT&CK | Status / certainty |
|---|---|---|---|---|
| MEM-001 process ancestry | `vol -f cs-ws-101.mem windows.pstree.PsTree` | `WINWORD.EXE` → `powershell.exe` → `svchost32.exe` with PIDs, paths, times | T1204.002, T1059.001, T1036.005 | Pending; possible |
| MEM-002 downloader command | `vol -f cs-ws-101.mem windows.cmdline.CmdLine` | Full PowerShell invocation and destination URL | T1059.001, T1105 | Pending; possible |
| MEM-003 C2 socket | `vol -f cs-ws-101.mem windows.netscan.NetScan` | PID, local and remote address/port, socket state at capture | T1071.001 | Pending; possible |
| MEM-004 suspicious memory | `vol -f cs-ws-101.mem windows.malfind.Malfind` | Suspicious regions, protections, owner PID, dump if needed | T1055 only if injection corroborated | Pending; possible |
| MEM-005 exposed credentials | `vol -f cs-ws-101.mem windows.hashdump.Hashdump` | Whether tool returns recoverable hashes; do **not** place hashes in reports | T1003 (subtechnique dependent on evidence) | Pending; possible |

**Caution:** `hashdump` may be unable to retrieve hashes from a standalone RAM image; it is not proof that credential dumping did or did not occur. Do not publish credential material in the final report.

## Disk examination — cs-ws-101.dd (pending)

```bash
mmls cs-ws-101.dd
# Set OFFSET to the Windows partition start sector reported by mmls
fsstat -o OFFSET cs-ws-101.dd
fls -r -p -m C: -o OFFSET cs-ws-101.dd > bodyfile.txt
mactime -b bodyfile.txt -d > disk_timeline.csv
# Inspect the timeline for AppData, Temp, Windows/Tasks and ProgramData.
# Use fls to find the metadata/inode number of each file, then:
icat -o OFFSET cs-ws-101.dd INODE > extracted_file.bin
sha256sum extracted_file.bin
```

| Finding | Required extraction / verification | ATT&CK | Status |
|---|---|---|---|
| DISK-001 malicious Word document | Find and extract `Invoice_Q4_2025.docm`; record SHA-256 | T1566.001, T1204.002 | Pending |
| DISK-002 PowerShell downloader | Recover script if present, record source path, body and hash | T1059.001, T1105 | Pending |
| DISK-003 suspected beacon payload | Extract actual binary/DLL/EXE, hash and inspect persistence | T1543.003, T1036.005 | Pending |
| DISK-004 persistence/timestamps | Recover tasks, service/registry artifacts and timestamps | T1053.005/T1543.003 only if observed | Pending |

**Do not invent inode numbers, memory output, hashes, partition offsets, or extracted malware names.** Samples indicate an EXE (`svchost32.exe`), not proof of a beacon DLL.

## Proxy log examination — full `proxy_72h.jsonl` required

```bash
# Phishing attachment download and the downloader request
jq -c 'select((.url // "" | contains("outlook.office.com/mail/download")) or (.url // "" | contains("inv_payload.ps1")))' proxy_72h.jsonl
# All observed connections to the suspected C2 destination
jq -c 'select((.dst_ip // "") == "45.152.66.114" or (.url // "" | contains("staging.office365-cdn.net"))) | {ts,host,src_ip,url,dst_ip,bytes}' proxy_72h.jsonl
# Group suspicious connection counts by host
jq -r 'select((.dst_ip // "") == "45.152.66.114") | .host' proxy_72h.jsonl | sort | uniq -c
```

**Sample-only leads (not verified in original logs):**

| ID | Sample observation (abridged, exact recorded values) | Interpretation | ATT&CK | Certainty |
|---|---|---|---|---|
| PROXY-001 | `2026-04-17T14:18:02Z`, `CS-WS-101`, `Invoice_Q4_2025.docm`, download status 200 | Candidate phishing attachment download; email provenance still to establish | T1566.001 | Possible (sample only) |
| PROXY-002 | `2026-04-17T14:22:19Z`, `GET .../updates/inv_payload.ps1`, status 200 | Downloader fetch candidate | T1105 | Possible (sample only) |
| PROXY-003 | `2026-04-17T14:23:07Z`, `CS-WS-101` → `45.152.66.114:443`; later periodic contacts | Suspected C2; periodicity must be measured over full dataset | T1071.001 | Possible (sample only) |
| PROXY-004 | First sample contacts: `CS-WS-104` 00:04:17Z, `CS-WS-107` 00:12:44Z, `CS-WS-112` 00:18:02Z, 19 April | Lateral-compromise/C2 candidates, **not proof of NTLM pass-the-hash** | T1021 (subtechnique unverified) | Possible (sample only) |
| PROXY-005 | `FILE-SVR-01` 19 April 02:14:22Z → same destination, sample `bytes=2400412` | Suspected outbound data transfer. **Direction and exfiltration not proven by `bytes` alone** | T1041 if confirmed | Possible (sample only) |
| PROXY-006 | `SCHED-SVR-01` absent from proxy sample | Network C2 from that server not established by these records | — | Unknown |

## Sysmon examination — full `sysmon_multihost.jsonl` required

```bash
# Process creation and service creation related to masquerading payload
jq -c 'select((.event_id == 1 or .event_id == 13) and (((.image // "") | ascii_downcase | contains("svchost32")) or ((.cmdline // "") | contains("WinHealthSvc")) or ((.target_object // "") | contains("WinHealthSvc"))))' sysmon_multihost.jsonl
# Outbound process connections to suspected C2
jq -c 'select(.event_id == 3 and .dst_ip == "45.152.66.114") | {ts,host,image,pid,dst_ip,dst_port}' sysmon_multihost.jsonl
# Dropped ransomware staging files
jq -c 'select(.event_id == 11 and ((.target // "") | contains("encryption_staging.ps1"))) | {ts,host,image,target}' sysmon_multihost.jsonl
# Credential access indicators (Sysmon Event 10 is process access, not authentication)
jq -c 'select(.event_id == 10 and ((.target_image // "") | ascii_downcase | contains("lsass.exe")))' sysmon_multihost.jsonl
```

| ID | Sample observation | Conclusion / limitation | ATT&CK | Certainty |
|---|---|---|---|---|
| SYSMON-001 | `WINWORD.EXE` spawned `powershell.exe` 17 April 14:22:14Z with an encoded **not** indicated command containing `DownloadString(...)` | Office→PowerShell execution chain; actual macro code not yet recovered | T1059.001, T1204.002 | Possible (sample only) |
| SYSMON-002 | `svchost32.exe` created 14:23:02Z and launched 14:23:14Z under PowerShell; `WinHealthSvc` service registry modification 14:23:28Z | Suspicious masquerading and possible service persistence | T1036.005, T1543.003 | Possible (sample only) |
| SYSMON-003 | `svchost32.exe` accessed `lsass.exe` at 14:25:02Z, granted access `0x1010` | Credential access concern, but **not proof of NTLM hash extraction** | T1003.001 (candidate) | Possible (sample only) |
| SYSMON-004 | `sc create WinHealthSvc ...` on `CS-WS-104` at 19 April 00:03:44Z; C2 connections also on 107 and 112 | Service installation on 104; lateral movement mechanism remains unproven | T1543.003 | Possible (sample only) |
| SYSMON-005 | `encryption_staging.ps1` created on CS-WS-101/104/107/112 from 20 April 14:23:18–14:26:14Z | Staged ransomware script, **execution/encryption not demonstrated** | T1105 (candidate) | Possible (sample only) |
| SYSMON-006 | `FILE-SVR-01` 19 April 02:14:01Z and `SCHED-SVR-01` 20 April 18:02:18Z: processes from `C:\ProgramData\Microsoft\svchost32.exe` | Scope extension to both servers requires independent verification | T1036.005 | Possible (sample only) |

**Authentication caution:** Sysmon process-create events mentioning `logon_type:3` do **not** establish NTLM authentication or pass-the-hash. Correlate Windows Security 4624 (authentication package), 4648, 4672, 4768/4769/4776, and source/target identifiers from original authentication logs. The file-server sample expressly says **Kerberos** for its 4624 event.

## File-server examination — full `fileserver_access.evtx` required

Export a **read-only copy** of the EVTX to JSON, using the available validated EVTX parser (schema shown by sample). Example with `evtx_dump` installed:

```bash
evtx_dump -o json fileserver_access.evtx > fileserver_full.json
# Inspect exported format, then normalize Event ID 4663 fields into JSONL.
# Count read events only after verifying the parser's output schema.
```

Suggested normalized JSONL schema: `{ts,event_id,user,logon_id,object_name,access_mask,process_name}`. Then:

```bash
jq -s '[.[] | select(.event_id == 4663 and .access_mask == "0x1")] | length' fileserver_4663.jsonl
jq -r 'select(.event_id == 4663) | .object_name' fileserver_4663.jsonl | sort -u | wc -l
jq -r 'select(.event_id == 4663) | .user' fileserver_4663.jsonl | sort | uniq -c
jq -r 'select(.event_id == 4663) | .object_name | if (ascii_downcase | contains("\\labs\\")) then "labs" elif (ascii_downcase | contains("\\notes\\")) then "notes" else "other" end' fileserver_4663.jsonl | sort | uniq -c
```

| ID | Sample observation | Assessment | ATT&CK | Certainty |
|---|---|---|---|---|
| FILE-001 | Sample summary asserts **1,847 Event ID 4663 ReadData events**, 19 April 02:14:01–02:41:12Z under `MEDDEFENSE\jdoe`; sample contains only five representative 4663 rows | Reports 1,847 access events; **1,847 unique files or patients not independently established** | T1005, T1039 (candidate) | Possible (sample-only; count unverified) |
| FILE-002 | Sample 4624 at 02:14:00.842Z shows logon type 3, Kerberos, source `10.30.12.101`, logon ID `0xAF12C4B8` | Account/session correlation; this particular logon is **not NTLM** | T1078 (candidate) | Possible (sample only) |
| FILE-003 | Representative records under `D:\clinical\labs\` and `D:\clinical\notes\`, PDF documents; sample notes user role is scheduling coordinator | Patient documentation exposure concern; file access does not itself prove exfiltration | T1005 | Possible (sample only) |

**Required follow-up:** Establish unique file count, patient count (with secure authorized mapping), precise lab-versus-note totals, source host/account authorization and whether read data left MedDefense. Do not invent these numbers.

## Attack chain summary (leads drawn from sample files; all require full-evidence verification)

| Stage | UTC time / range | ATT&CK | Hosts | Sample source / finding ID | Certainty |
|---|---|---|---|---|---|
| Attachment download | 17 Apr 14:18:02 | T1566.001 (candidate delivery), T1204.002 | CS-WS-101 | PROXY-001 | Possible |
| PowerShell execution | 17 Apr 14:22:14–14:22:19 | T1059.001, T1105 | CS-WS-101 | SYSMON-001, PROXY-002 | Possible |
| Payload + persistence | 17 Apr 14:23:02–14:23:28 | T1036.005, T1543.003 | CS-WS-101 | SYSMON-002 | Possible |
| C2 communications | 17 Apr 14:23:07 onward | T1071.001 | CS-WS-101/104/107/112; FILE-SVR-01 in samples | PROXY-003/004/005 | Possible |
| Credential access | 17 Apr 14:25:02 | T1003.001 (candidate) | CS-WS-101 | SYSMON-003 | Possible |
| Additional workstation activity | 19 Apr 00:03:44–00:18:02 | T1543.003; lateral technique TBD | CS-WS-104/107/112 | SYSMON-004, PROXY-004 | Possible |
| Patient document reads | 19 Apr 02:14:01–02:41:12 | T1005 | FILE-SVR-01 | FILE-001/002/003 | Possible |
| Suspected large outbound exchange | 19 Apr 02:14:22 | T1041 (candidate) | FILE-SVR-01 | PROXY-005 | Possible |
| Ransomware preparation | 20 Apr 14:23:18–14:26:14 | T1105 (candidate) | CS-WS-101/104/107/112 | SYSMON-005 | Possible |
| Further server compromise | 20 Apr 18:02:18 | T1036.005 | SCHED-SVR-01 | SYSMON-006 | Possible |

## Open questions / evidence requests

1. Supply original `cs-ws-101.mem` and `cs-ws-101.dd`, or the **saved actual outputs** of the listed Volatility and TSK commands. Include acquisition metadata and hashes.
2. Supply original `proxy_72h.jsonl`, `sysmon_multihost.jsonl`, `fileserver_access.evtx` (or complete lossless exports).
3. Provide corroborating Windows authentication events to determine whether NTLM pass-the-hash occurred. The file-server example shows Kerberos.
4. Verify whether `FILE-SVR-01` and `SCHED-SVR-01` ran attacker-controlled code; ensure response scope is updated if corroborated.
5. Prove or disprove exfiltration independently. A large proxy `bytes` value plus file reads is suspicious but not definitive.

**Release criterion:** Replace each sample-based excerpt with output from the corresponding full artifact, record actual hashes, and promote certainty **only when** original evidence supports the conclusion. Until then, this is a structured investigation worksheet, not a final validated forensic report.
