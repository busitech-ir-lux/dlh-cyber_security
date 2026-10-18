# Filesystem Analysis: ART-001 (wst-ws-031.dd)

**Case:** LH-2026-0414-01  
**Incident:** IR-2026-0414-01  
**Status:** PENDING EXECUTION — disk image and SIEM export were not provided in this environment. This is an evidence-based investigation worksheet, **not a claim that TSK analysis has been performed**.

## 1. Artifact verification

- **Artifact:** ART-001 — `wst-ws-031.dd`
- **Acquisition:** Mike Torres; FTK Imager; 2026-04-14 04:51Z–06:14Z; RAW/dd.
- **SHA-256 at acquisition:** NOT TAKEN (per `acquisition_notes.md`).
- **Hash at analysis start:** PENDING — copy verified output from `verify_artifacts.sh`; do not use the example hash in the assignment.
- **Baseline match:** PENDING.
- **Mounted read-only:** PENDING — verify on investigation workstation.
- **CoC entry updated:** PENDING — append actual access time, actor, action and tool to `chain_of_custody.md`.
- **Known deviation:** Acquirer mounted the *live filesystem* read-write before acquisition and opened Explorer to inspect `update.xml`; file metadata may have changed. No disk-image acquisition hash exists. Custody between acquisition and handoff was not recorded.

### Commands: verify before accessing evidence

Run from your investigation project folder. Set `EVIDENCE_DIR` if your disk image is elsewhere.

```bash
export EVIDENCE_DIR="${EVIDENCE_DIR:-$PWD}"
export IMAGE="$EVIDENCE_DIR/wst-ws-031.dd"
export ACTOR="$(whoami)"

# Run the verification script for ALL three artifacts, then stop if any fails.
./verify_artifacts.sh || exit 1

# Copy the ART-001 [PASS] line and its actual UTC timestamp into this report.
date -u +'%Y-%m-%dT%H:%M:%SZ'
```

**Recorded verification output:** PENDING.

> The verification script writes to `verification_log.txt`; also append the corresponding ART-001 hash verification and subsequent access events to `chain_of_custody.md` (append-only).

## 2. Read-only setup

The image must **not** be mounted read-write. TSK commands read the image file directly; an NTFS mount is optional for browsing, but the assignment requests a read-only mount. Perform this step only after successful verification.

```bash
# Create read-only loop device for the image (no write access).
sudo losetup --find --show --read-only --partscan "$IMAGE"
# Record returned device, e.g. /dev/loop0. Verify partitions first.
lsblk -o NAME,RO,FSTYPE,SIZE,MOUNTPOINTS

# After mmls confirms the NTFS partition and lsblk shows its partition device:
# sudo mkdir -p /mnt/art001_ro
# sudo mount -t ntfs-3g -o ro /dev/loop0p1 /mnt/art001_ro
# mount | grep art001_ro

# After examination, unmount and detach the loop device:
# sudo umount /mnt/art001_ro
# sudo losetup -d /dev/loop0
```

**Loop device:** PENDING.  
**Read-only mount command/output:** PENDING.  
**Note:** Replace `/dev/loop0p1` with the real partition shown by `lsblk`. If the NTFS mount cannot be made safely, do not force it; continue with TSK direct-image access and document the deviation. The readonly loop device is not equivalent to a mounted filesystem.

## 3. Partition layout

```bash
mmls "$IMAGE" | tee mmls_output.txt
```

**Actual `mmls` output:** PENDING — paste unedited tool output here.  
**Main NTFS volume start sector (`OFFSET`):** PENDING — take the `Start` value from `mmls`, not from the assignment example.  
**Sector size:** PENDING — use the value reported by `mmls` (usually 512 bytes; verify).

For following commands, set the real offset:

```bash
OFFSET=REPLACE_WITH_NTFS_START_SECTOR
```

## 4. Filesystem metadata

```bash
fsstat -o "$OFFSET" "$IMAGE" | tee fsstat_output.txt
```

**Actual `fsstat` output:** PENDING — paste or refer to `fsstat_output.txt`.

| Field | Value |
|---|---|
| Filesystem type | PENDING |
| Volume serial number | PENDING |
| Sector/cluster information | PENDING |
| Last mount time (if exposed) | PENDING — not always available from `fsstat` |
| Other relevant metadata | PENDING |

Do not invent a last mount time if the tool does not expose it; document `not available from fsstat` and identify any alternative source separately.

## 5. Recursive listing and MAC timeline

```bash
# Human-readable recursive listing with metadata addresses and deletion flags.
fls -r -o "$OFFSET" "$IMAGE" > fls_output.txt

# IMPORTANT: mactime needs a BODY FILE, not the plain listing above.
fls -r -m C: -o "$OFFSET" "$IMAGE" > fls_body.txt

# Output includes CSV heading and UTC timestamps; keep a reproducible raw copy.
TZ=UTC mactime -b fls_body.txt -d > mac_timeline.csv

# Look for relevant artifact names and directories.
grep -Ei 'update\.xml|/Temp/|/System32/Tasks/|/Recent/|/History/' fls_output.txt > targeted_fls.txt || true
```

**Generated:** `fls_output.txt`, `fls_body.txt`, `mac_timeline.csv`, `targeted_fls.txt` — PENDING.

**Timeline caveat:** NTFS timestamps can be affected by file operations and different timestamp sources; access timestamps may be disabled, delayed, or modified. Corroborate using independent artifacts. `mactime` times are displayed in UTC by setting `TZ=UTC`.

## 6. Targeted artifact examination

| Target Windows path | What to examine | Result |
|---|---|---|
| `C:\Users\dmarsh\AppData\Local\Temp\` | `update.xml`, unusual executables/scripts, newly written staging files and timestamps | PENDING |
| `C:\Windows\System32\Tasks\` | Task XML, action/command, user context, triggers, creation times | PENDING |
| `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\` | `.lnk` targets, paths, file access context (use suitable LNK parser after extraction) | PENDING |
| `C:\Users\dmarsh\AppData\Local\Microsoft\Windows\History\` | Browser-related artifacts if present; check for browser-specific histories elsewhere too | PENDING |

Locate paths and identify *actual inode/metadata addresses* from the TSK listing:

```bash
grep -Ei 'update\.xml|Users/dmarsh/AppData/Local/Temp|Windows/System32/Tasks|Windows/Recent|Windows/History' fls_body.txt | head -80

# Replace INODE with the metadata address from fls (never guess it).
# Use a unique extracted filename and record the extraction in the CoC log.
# icat -o "$OFFSET" "$IMAGE" INODE > extracted_artifact.bin
# sha256sum extracted_artifact.bin
# stat -c '%s' extracted_artifact.bin
```

**Extraction note:** `icat` content output is a derived artifact. Record its exact source inode/path, SHA-256, size, extraction command, UTC time and destination. Do not execute extracted material; examine copies with appropriate static tools.

## 7. Key findings

No disk-backed findings can be confirmed until the image is available and the commands above have been run. The `update.xml` reference comes **only** from the acquisition notes (the acquirer said it was present), and any SIEM indicators must be treated as leads, not proof.

### ART-001-F01: Suspected `update.xml` staging artifact — UNCONFIRMED

- **Full path:** PENDING — identify from disk; acquisition notes do not provide its complete path.
- **Metadata address/inode:** PENDING.
- **Created (UTC):** PENDING.
- **Modified (UTC):** PENDING.
- **Accessed (UTC):** PENDING.
- **Size (bytes):** PENDING.
- **SHA-256 (extracted content):** PENDING.
- **Forensic significance:** Acquisition notes report that `update.xml` was observed on the live filesystem before imaging. Whether it is an MSBuild project, contains encoded code, or executed is **not established** without content inspection and corroboration.

### ART-001-F02: Potential second-stage payload — NOT YET IDENTIFIED

- **Full path:** PENDING.
- **MAC times (UTC):** PENDING.
- **Size / SHA-256:** PENDING.
- **Forensic significance:** Do not classify an extracted file as a second-stage payload without supporting evidence.

### ART-001-F03: Potential scheduled-task persistence — NOT YET IDENTIFIED

- **Full path:** PENDING.
- **MAC times (UTC):** PENDING.
- **Size / SHA-256:** PENDING.
- **Forensic significance:** Inspect task XML actions, arguments, principal and triggers; correlate with other evidence.

### Additional findings

Append one subsection per verified suspicious file with full Windows path, source inode, MAC times with their timestamp source, byte size, SHA-256 of exported content, and concise significance. Cite source filenames and log access events in the CoC.

## 8. SOC context and correlation

**`siem_alert_export.json` reviewed:** NO — not provided here. **Do not begin disk interpretation using SIEM assertions as proven facts.** Before disk analysis, review this file separately, write down the claimed events, times, hostnames, processes and filenames, and then test each against the disk evidence.

| SIEM claim (lead only) | Disk evidence to seek | Status |
|---|---|---|
| `update.xml` associated with suspicious activity (specific SIEM details not supplied) | Extracted file, content, timestamps, application execution evidence | PENDING |
| Additional alerts | Populate from original JSON | PENDING |

## 9. Preliminary timeline

| UTC time | Event | Evidence | Confidence |
|---|---|---|---|
| 2026-04-14 04:51 | Disk acquisition started | `acquisition_notes.md` | Documented by acquirer |
| 2026-04-14 06:14 | Disk acquisition finished | `acquisition_notes.md` | Documented by acquirer |
| PENDING | File creation / modification / access events | `mac_timeline.csv` and extracted artifacts | Not yet assessed |

Do not interpret acquisition events as attacker activity. Insert confirmed filesystem events in chronological order after reviewing the timeline.

## 10. Integrity and custody actions required

1. Verify all three evidence hashes successfully before the session; halt on any failure.
2. Record successful hash verification in `verification_log.txt` and append the access to `chain_of_custody.md`.
3. Record the read-only device setup/mount, `mmls`, `fsstat`, `fls`, `mactime` and each `icat` extraction as access or derivation events in the append-only CoC.
4. Flag **DEVIATION** if any baseline hash mismatches, if write access occurs, or if an artifact's chain cannot be substantiated. Do not silently correct historical gaps.
5. Preserve raw outputs and derived evidence; document derived file hashes separately.

**Conclusion:** No attacker filesystem timeline or malicious artifact classification has yet been established from this disk image in the current environment.
