# Memory Analysis: ART-002 (`wst-ws-031.mem`) and ART-003 (`wst-ws-017.mem`)

**Case:** LH-2026-0414-01  
**Incident:** IR-2026-0414-01  
**Status:** COLLECTION/ANALYSIS PENDING. The memory images, hash baselines, and plugin output were not provided. The example commands and examples in the assignment are **not observed results**.

## Artifact verification and evidence handling

| Evidence | Acquisition information from Mike Torres | Baseline check | CoC record |
|---|---|---|---|
| ART-002 — `wst-ws-031.mem` | WinPmem v3.3-rc3, 2026-04-14T03:02:00Z, live/beaconing at capture | PENDING; no acquisition hash | PENDING |
| ART-003 — `wst-ws-017.mem` | WinPmem, 2026-04-14T03:38:00Z | PENDING; no acquisition hash | PENDING |

Mike Torres reported transferring the files to the SOC evidence share, with an undocumented interval of physical/network custody. Before analysis run `./verify_artifacts.sh`, check for **three PASS results**, and log each access in `chain_of_custody.md`. **Do not analyze** if any hash fails or the baseline has not yet been independently checked. Work on access-controlled copies; write plugin results outside the evidence directory. Time outputs from Windows plugins may be UTC, but verify timestamp formatting in the installed Volatility version.

## Commands and collection record

Run from a directory containing verified image copies; `vol` refers to the installed Volatility 3 entry point (some environments use `python3 vol.py`). Save stderr separately so plugin failures are not mistaken for empty findings.

```bash
# These commands must be run only after hash verification and CoC logging.
mkdir -p volatility_output
vol -f wst-ws-031.mem windows.pslist.PsList > volatility_output/031_pslist.txt 2> volatility_output/031_pslist.err
vol -f wst-ws-031.mem windows.pstree.PsTree > volatility_output/031_pstree.txt 2> volatility_output/031_pstree.err
vol -f wst-ws-031.mem windows.cmdline.CmdLine > volatility_output/031_cmdline.txt 2> volatility_output/031_cmdline.err
vol -f wst-ws-031.mem windows.netscan.NetScan > volatility_output/031_netscan.txt 2> volatility_output/031_netscan.err
# Replace the PID only after identifying a real MSBuild process.
vol -f wst-ws-031.mem windows.dlllist.DllList --pid <msbuild_pid> > volatility_output/031_msbuild_dlllist.txt
vol -f wst-ws-031.mem windows.malfind.Malfind > volatility_output/031_malfind.txt 2> volatility_output/031_malfind.err
# Replace with the actual lsass.exe PID from PsList.
vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid> > volatility_output/031_lsass_handles.txt
# Sensitive credential-derived output: only if explicitly authorized; store in restricted evidence storage.
vol -f wst-ws-031.mem windows.hashdump.Hashdump > volatility_output/031_hashdump_RESTRICTED.txt

vol -f wst-ws-017.mem windows.pslist.PsList > volatility_output/017_pslist.txt 2> volatility_output/017_pslist.err
vol -f wst-ws-017.mem windows.netscan.NetScan > volatility_output/017_netscan.txt 2> volatility_output/017_netscan.err
vol -f wst-ws-017.mem windows.cmdline.CmdLine > volatility_output/017_cmdline.txt 2> volatility_output/017_cmdline.err
```

**Protect sensitive output:** Restrict access to hashdump data, do not place NTLM hashes or credential material in a broadly distributed report, and do not claim that `windows.hashdump` extracts Kerberos tickets or LSA secrets. `hashdump` attempts to recover local SAM account password hashes; identifying Kerberos tickets requires separate, authorized methods. A failed or unavailable plugin is a documented limitation, not negative evidence.

## `wst-ws-031.mem`: plugin findings

| Finding ID | Plugin / output | Relevant fields to quote from actual results | PID | Conclusion and certainty | ATT&CK (only if confirmed by content) |
|---|---|---|---|---|---|
| ART-002-M01 | `windows.pslist.PsList` — `031_pslist.txt` | PID, PPID, name, create/exit UTC; **output pending** | PENDING | No process conclusions yet | — |
| ART-002-M02 | `windows.pstree.PsTree` — `031_pstree.txt` | Parent/child relation, create times; **output pending** | PENDING | Verify whether PowerShell spawned MSBuild | T1127.001 if misuse confirmed |
| ART-002-M03 | `windows.cmdline.CmdLine` — `031_cmdline.txt` | Actual command lines, e.g. encoded arguments; **output pending** | PENDING | Encoded PowerShell alone is suspicious, not proof of maliciousness | T1059.001 if supported |
| ART-002-M04 | `windows.netscan.NetScan` — `031_netscan.txt` | Local/remote addresses, ports, state, PID; **output pending** | PENDING | Connection attribution requires PID correlation; traffic destination alone does not prove C2 | T1071.001 if corroborated |
| ART-002-M05 | `windows.dlllist.DllList --pid <msbuild_pid>` — `031_msbuild_dlllist.txt` | Module paths, bases, potentially unusual loaded modules; **output pending** | PENDING | Unusual DLL needs corroboration and hash/reputation review | — |
| ART-002-M06 | `windows.malfind.Malfind` — `031_malfind.txt` | Process, VAD address, protection, hexdump, disassembly; **output pending** | PENDING | RWX/private executable regions or MZ bytes are *indicators*, not sufficient alone to confirm injection | T1055 if independently supported |
| ART-002-M07 | `windows.handles.Handles --pid <lsass_pid>` — `031_lsass_handles.txt` | Handle type/name/access; **output pending** | PENDING | LSASS holding handles is normal; this does not show another process dumping LSASS | — |
| ART-002-M08 | `windows.hashdump.Hashdump` — `031_hashdump_RESTRICTED.txt` | Report only success/failure and account count; redact hashes | N/A | Recoverable SAM hashes do not prove attacker extraction | T1003.002 only with evidence of malicious dumping |

**Relevant output excerpts:** PENDING — paste *actual* relevant lines from saved plugin outputs here; each excerpt must include a path to its preserved output and execution timestamp. **No observed PIDs, C2 IPs, executable regions or password hashes are available from the supplied evidence.**

## `wst-ws-017.mem`: minimum plugin findings

| Finding ID | Plugin/output | Required fields | Finding/certainty | ATT&CK |
|---|---|---|---|---|
| ART-003-M01 | `windows.pslist.PsList` — `017_pslist.txt` | Name, PID, PPID, create/exit time | PENDING — not assessed | — |
| ART-003-M02 | `windows.netscan.NetScan` — `017_netscan.txt` | Remote address/port, state, owning PID | PENDING — not assessed | T1071.001 only if C2 corroborated |
| ART-003-M03 | `windows.cmdline.CmdLine` — `017_cmdline.txt` | Process and arguments | PENDING — not assessed | — |

## Correlation and next steps

1. Correlate the actual PowerShell/MSBuild process timestamps, PID/PPID, command line, and NetScan socket ownership; ensure PID reuse and terminated processes are considered.
2. Compare any identified staged file paths to the *verified* disk findings `ART-001-Fxx`; use `siem_alert_export.json` as a lead, **not** proof.
3. Correlate memory network endpoints with `proxy_log.jsonl`, authentication records in `ad_auth_log.jsonl`, and the second image; preserve log line numbers as evidence references.
4. Where needed, perform additional approved LSASS process-access and Kerberos ticket analysis; do not infer NTLM/Kerberos theft from a hashdump or LSASS handle listing.
5. Record every tool invocation, access UTC timestamp, success/failure, hashes, and resulting files in CoC. Mark unresolved hypotheses **possible**, not **confirmed**.

## Limitations

Memory capture occurred at different times (ART-002 at 03:02Z and ART-003 at 03:38Z). Evidence after capture is not represented. Memory process/network artifacts may be incomplete and plugins may vary by OS/build or Volatility version. No live image, hashes, plugin output, or SIEM export was available for independent validation.
