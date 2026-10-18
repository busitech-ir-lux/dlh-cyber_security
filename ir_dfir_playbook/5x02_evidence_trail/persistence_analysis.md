# Persistence Artifact Analysis: ART-001 (`wst-ws-031.dd`)

**Case:** LH-2026-0414-01  
**Incident:** IR-2026-0414-01  
**Status:** PENDING EVIDENCE EXAMINATION. This document is a reproducible analysis worksheet, **not a statement that artifacts were extracted or that persistence was confirmed**.

## 1. Artifact verification and provenance

| Field | Recorded value |
|---|---|
| Evidence | ART-001 — `wst-ws-031.dd` (RAW disk image) |
| Acquirer | Mike Torres, Network Engineer |
| Acquisition tool | FTK Imager |
| Acquisition window | 2026-04-14 04:51Z–06:14Z |
| SHA-256 at acquisition | **Not collected** |
| Analysis-start SHA-256 | **PENDING** — record entire hash from `hashes.txt` and verifier output |
| Verification result | **PENDING** — must be `PASS` before any analysis |
| Read-only image access / mount | **PENDING** |
| Investigator / analysis time (UTC) | **PENDING** |
| Chain-of-custody access entry | **PENDING** — append time, actor, action and tool for every access |

**Known integrity and custody limitations:** The acquirer inspected the live filesystem read-write before imaging and viewed `update.xml`; this could have changed filesystem metadata. No acquisition-time hashes were taken, and intermediate physical/network access before SOC handoff was not recorded. Do not represent a first-access baseline as an acquisition-time hash.

**Pre-analysis commands (on investigation VM):**

```bash
export EVIDENCE_DIR="${EVIDENCE_DIR:-$PWD}"
export IMAGE="$EVIDENCE_DIR/wst-ws-031.dd"
export ACTOR="${ACTOR:-$(whoami)}"
./verify_artifacts.sh || exit 1
# If the first run prints BASELINE_SET, run it AGAIN; analysis requires PASS.
# Record timestamp and append the verification event to chain_of_custody.md.
date -u +'%Y-%m-%dT%H:%M:%SZ'
```

Use the read-only loop/mount steps recorded in `filesystem_analysis.md`; confirm the partition is read-only and do not alter the source image. TSK direct-image extraction (`icat`) avoids writing to the evidence source.

## 2. Evidence extraction (TSK)

Identify the **actual** NTFS start sector first; do not assume the example offset of 2048.

```bash
mmls "$IMAGE"
# Replace with the Start sector of the Windows NTFS partition from mmls:
OFFSET=REPLACE_WITH_ACTUAL_NTFS_START_SECTOR

# File-listing paths and metadata addresses (inode/MFT record numbers).
fls -r -p -o "$OFFSET" "$IMAGE" > persistence_fls.txt
# Narrow the listing to relevant hive / scheduled task / LNK locations.
grep -Ei '(/|\\)(NTUSER\.DAT|SYSTEM|SOFTWARE|Amcache\.hve|Tasks|Recent)(/|\\|$)' persistence_fls.txt > persistence_candidates.txt || true
```

Locate and extract the following **by confirmed inode** using `icat` into a restricted working directory, not into the evidence location:

| Source on image | Output (example) | Intended use |
|---|---|---|
| `C:\Users\dmarsh\NTUSER.DAT` | `extracted/NTUSER.DAT` | dmarsh Run, RunOnce, UserAssist |
| `C:\Windows\System32\config\SYSTEM` | `extracted/SYSTEM` | AppCompatCache / ShimCache |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | `extracted/Amcache.hve` | File inventory and possible execution context |
| `C:\Windows\System32\Tasks\*` | `extracted/tasks/*` | Scheduled task XML |
| `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` | `extracted/recent/*` | Recent shortcut targets |

```bash
mkdir -p extracted/tasks extracted/recent
# Use actual metadata address from fls; an address may include an attribute suffix.
icat -o "$OFFSET" "$IMAGE" INODE_OF_DMARSH_NTUSER > extracted/NTUSER.DAT
icat -o "$OFFSET" "$IMAGE" INODE_OF_SYSTEM_HIVE > extracted/SYSTEM
icat -o "$OFFSET" "$IMAGE" INODE_OF_AMCACHE > extracted/Amcache.hve
# Repeat icat for EACH identified Tasks XML and Recent .lnk file.
sha256sum extracted/NTUSER.DAT extracted/SYSTEM extracted/Amcache.hve > extracted_hashes.txt
```

**Extraction manifest (complete using actual values):**

| Source path | Inode / MFT reference | Extracted path | Size (bytes) | Extracted SHA-256 | UTC extraction time |
|---|---|---|---|---|---|
| `C:\Users\dmarsh\NTUSER.DAT` | PENDING | PENDING | PENDING | PENDING | PENDING |
| `C:\Windows\System32\config\SYSTEM` | PENDING | PENDING | PENDING | PENDING | PENDING |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | PENDING | PENDING | PENDING | PENDING | PENDING |
| Scheduled task XML files | PENDING | PENDING | PENDING | PENDING | PENDING |
| Recent LNK files | PENDING | PENDING | PENDING | PENDING | PENDING |

For consistency, preserve raw parser outputs and their tool versions. Record every source access and extraction in `chain_of_custody.md`.

## 3. Registry persistence — dmarsh Run / RunOnce

Inspect these paths **in the extracted dmarsh NTUSER.DAT**, not the analyst's workstation HKCU:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**Example analysis tool:** RegRipper (`rip.pl`); confirm the relevant plugins exist in the installed version:

```bash
# On a machine where RegRipper and plugins are installed:
# perl rip.pl -r extracted/NTUSER.DAT -p run > run_report.txt
# perl rip.pl -r extracted/NTUSER.DAT -p runonce > runonce_report.txt
# Or inspect both paths with another offline registry hive parser.
```

| Evidence ID | Registry key | Value name | Value data / command | Key last-write (UTC) | Significance | Assessment |
|---|---|---|---|---|---|---|
| ART-001-R01 | `...\CurrentVersion\Run` | PENDING | PENDING | PENDING | Assess autorun target, payload, path, signer and user context | UNDETERMINED |
| ART-001-R02 | `...\CurrentVersion\RunOnce` | PENDING | PENDING | PENDING | Assess one-time startup command and possible removal on use | UNDETERMINED |

**Interpretation:** A registry key's last-write time belongs to the **key**, not necessarily to an individual value. A suspicious entry is a persistence **candidate** until its target and context are validated. Absence from these locations does not rule out other persistence.

## 4. Scheduled task persistence

Examine **all** XML files under `C:\Windows\System32\Tasks\` (including subdirectories). Extract by inode. Parse `Triggers`, `Actions` and `Principals`; preserve task name and timestamps. Windows Task Scheduler XML uses namespaces, so a simple text grep may miss structures.

```bash
# After exporting task XML files to extracted/tasks/, this shows key fields.
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
for p in sorted(Path('extracted/tasks').rglob('*')):
    if not p.is_file():
        continue
    try:
        root = ET.parse(p).getroot()
        def values(path):
            return [x.text for x in root.findall(path) if x.text]
        print('TASK:', p)
        for tag in ('CalendarTrigger','BootTrigger','LogonTrigger','TimeTrigger','EventTrigger',
                    'Exec','ComHandler','UserId','GroupId','RunLevel'):
            matches = root.findall(f'.//{{*}}{tag}')
            for item in matches:
                print(' ',tag, ET.tostring(item, encoding='unicode').strip()[:1200])
    except (ET.ParseError, OSError) as e:
        print('UNPARSEABLE:', p, str(e))
PY
```

| Evidence ID | Task path | Trigger(s) | Action executable + arguments | Principal / run level | File MAC times (UTC) | XML hash | Significance |
|---|---|---|---|---|---|---|---|
| ART-001-R03 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | UNDETERMINED |

Correlate scheduled tasks with `TaskCache` registry keys and task scheduler event logs if available. A task file alone does not prove that the scheduled action executed.

## 5. Execution and activity evidence

### 5.1 UserAssist (dmarsh NTUSER.DAT)

- Hive: `C:\Users\dmarsh\NTUSER.DAT`
- Key: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
- Value names are **ROT13-encoded**; interpret binary fields with a version-aware UserAssist parser.

```bash
# Example, if a compatible RegRipper UserAssist plugin is installed:
# perl rip.pl -r extracted/NTUSER.DAT -p userassist > userassist_report.txt
```

| Evidence ID | Registry key/value (decoded) | Run count | Last execution (UTC) | Key last-write (UTC) | Significance |
|---|---|---|---|---|---|
| ART-001-E01 | PENDING (check for `msbuild.exe` and any suspect paths) | PENDING | PENDING | PENDING | User-session GUI activity indicator; not exhaustive execution proof |

**Caution:** UserAssist is associated with Explorer-mediated activity. Missing entries do not mean that a program did not run, and counts can be affected by Windows version and parsing behavior.

### 5.2 AppCompatCache / ShimCache (SYSTEM hive)

- Hive: `C:\Windows\System32\config\SYSTEM`
- Relevant data: `ControlSet00x\Control\Session Manager\AppCompatCache\AppCompatCache`; determine active control set from `SYSTEM\Select`.

```bash
# Use a version-compatible ShimCache/AppCompatCache parser on extracted/SYSTEM.
# Save the full ordered parser output as shimcache_report.txt.
# Record tool name, version, parsing options and timezone.
```

| Evidence ID | Ordered entry | Executable path | Cached modification time (UTC) | Execution interpretation | Significance |
|---|---|---|---|---|---|
| ART-001-E02 | PENDING | PENDING | PENDING | PENDING | Correlate with other execution artifacts |

**Caution:** ShimCache generally demonstrates that Windows recorded information about a path; it **does not reliably prove execution**, and ordering/timestamps vary by Windows version. Do not call it a confirmed execution record without independent corroboration.

### 5.3 Amcache (`Amcache.hve`)

- Hive: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Parse version-dependent file/program inventory entries, including any file SHA-1 field, path, publisher and available timestamps.

```bash
# Use a compatible Amcache parser; export machine-readable output if possible.
# Save raw output to amcache_report.csv or amcache_report.txt.
```

| Evidence ID | Amcache key / file path | SHA-1 (if present) | Relevant time field (UTC) | Executable name | Significance |
|---|---|---|---|---|---|
| ART-001-E03 | PENDING | PENDING | PENDING | PENDING | Correlate with staged payloads and task actions |

**Caution:** Amcache timestamps are **not universally first-execution timestamps**. Meaning depends on schema/version and entry; do not present any timestamp as first execution without validating the field's semantics and correlating other evidence.

### 5.4 Recent LNK files (dmarsh)

- Source: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`
- Parse each `.lnk` with a Windows shortcut parser to extract target path, volume information and embedded target timestamps; also collect the LNK file's own MAC times from TSK.

| Evidence ID | LNK source path | Target path | LNK file MAC times (UTC) | Embedded target timestamps (UTC) | Significance |
|---|---|---|---|---|---|
| ART-001-E04 | PENDING | PENDING | PENDING | PENDING | User activity / accessed item candidate |

**Caution:** Target timestamps embedded in an LNK are not identical to the LNK file's own timestamps; neither alone proves that a file executed.

## 6. Findings and persistence assessment

Do **not** promote the assignment's example names (`WindowsUpdateSvc`, `update.exe`, `msbuild.exe`) to findings unless the extracted artifacts confirm them. The acquisition notes mention an `update.xml` file checked on the live WST-WS-031 system; its presence, contents and persistence role must be independently verified from the image.

| Evidence ID | Mechanism / indicator | Supporting artifacts | Persistence confirmed? | Confidence | Eradication consideration |
|---|---|---|---|---|---|
| ART-001-R01/R02 | Run/RunOnce | PENDING | PENDING | PENDING | Remove only validated malicious entry and investigate referenced payload |
| ART-001-R03 | Scheduled task | PENDING | PENDING | PENDING | Disable/remove only validated malicious task and payload |
| ART-001-E01–E04 | Execution and recent activity context | PENDING | Not persistence by itself | PENDING | Use to corroborate timing and scope |

**Current conclusion:** **No persistence mechanism can be confirmed or excluded from the evidence currently supplied.** The disk image and extracted hive/task/LNK records are not available in this environment.

## 7. Chain of custody and follow-up

For each analysis session:

1. Require three `[PASS]` results from `verify_artifacts.sh` before touching evidence; if any fails, **stop** and record a `DEVIATION`.
2. Append **each** read-only mount, hive extraction, task/LNK extraction, parser access, and hash-verification event to `chain_of_custody.md` with actual UTC time, actor, artifact, action, tool, hash verification and notes.
3. Compute SHA-256 for every extracted output and retain an extraction manifest tied to the source inode and path.
4. Correlate disk findings against `filesystem_analysis.md` and `siem_alert_export.json`. The SIEM export is initial SOC detection context, **not** independently verified proof.
5. Preserve raw tool outputs; classify findings as confirmed, suspected or unsupported, and build eradication checklist entries only for verified malicious mechanisms.

**Evidence limitations and missing artifacts:** The source disk image, `hashes.txt`, extracted hives, XML task files, LNK files and SIEM export were not available here. Therefore no real registry values, timestamps, run counts, file hashes or malicious task names have been invented.
