# Chain of Custody: LH-2026-0414-01

## Case Header

- **Case number:** `LH-2026-0414-01`
- **Incident ID:** `IR-2026-0414-01`
- **Lead investigator:** `PENDING — analyst name not provided`
- **Date opened:** `PENDING — enter actual UTC date when this log is opened`
- **Litigation hold reference:** `Memo from Helena Reyes, 2026-04-14T07:30Z`
- **Source:** `acquisition_notes.md`, signed Mike Torres at `2026-04-14T07:42Z`

## Artifact Registry

| Artifact ID | Artifact Name | Format | Acquired By | Acquisition Timestamp (UTC) | Acquisition Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| ART-001 | `wst-ws-031.dd` | RAW/dd | Mike Torres | 2026-04-14 04:51Z–06:14Z | FTK Imager | NOT TAKEN; first-access baseline pending | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` (reported destination; verify) | PENDING verification; require read-only, IR team only |
| ART-002 | `wst-ws-031.mem` | RAW memory | Mike Torres | 2026-04-14 03:02Z | WinPmem v3.3-rc3 | NOT TAKEN; first-access baseline pending | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` (reported destination; verify) | PENDING verification; require read-only, IR team only |
| ART-003 | `wst-ws-017.mem` | RAW memory | Mike Torres | 2026-04-14 03:38Z | WinPmem (version not confirmed) | NOT TAKEN; first-access baseline pending | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` (reported destination; verify) | PENDING verification; require read-only, IR team only |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified (yes/no) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 2026-04-14 03:02Z | Mike Torres | ART-002 | acquisition | WinPmem v3.3-rc3 | no | Memory captured from live, beaconing WST-WS-031; no SHA-256 calculated. Historical event transcribed from acquisition notes. |
| 2026-04-14 03:38Z | Mike Torres | ART-003 | acquisition | WinPmem | no | Memory captured from WST-WS-017 console; no SHA-256 calculated. Historical event transcribed from acquisition notes. |
| 2026-04-14 04:51Z–06:14Z | Mike Torres | ART-001 | acquisition | FTK Imager | no | RAW disk image created after live filesystem had been mounted read-write; no SHA-256 calculated. Historical event transcribed from acquisition notes. |

## Acquisition and Custody Exceptions

- **DEVIATION — all artifacts:** No SHA-256 was calculated at acquisition. A hash calculated now establishes only a first-access baseline, not an acquisition-time hash. Do not backdate it.
- **DEVIATION — ART-001:** Mike Torres mounted the live filesystem read-write to check for `update.xml` and did not remount read-only before imaging. Potential metadata/access-time changes cannot be excluded; no intentional file edits were reported.
- **DEVIATION — all artifacts:** Physical and network access between acquisition and handoff to the SOC evidence share was not recorded. Historical custody cannot be reconstructed from the available notes.
- **PENDING:** Confirm actual evidence file locations, access controls, first-access SHA-256 values, and the lead investigator's identity.

## First-Access Procedure

1. Restrict evidence to read-only access and verify access controls before examination.
2. Record the actual UTC timestamp, analyst identity, and tool used for each hash operation.
3. Compute SHA-256 for each artifact using `sha256sum` and store the result as its **first-access baseline** in a separate hash manifest. Do not overwrite the registry's historical `NOT TAKEN` entry.
4. Append one `hash_verify` row per artifact, with `Hash Verified: no — acquisition hash unavailable; baseline established` on the initial calculation.
5. Before every later artifact access, compare its SHA-256 with the first-access baseline and append a new row. If mismatched, append a `DEVIATION` note immediately and stop substantive analysis pending review.
6. Keep this document append-only: never erase or rewrite existing custody entries; append corrections with timestamps and reasons.

**Status:** Registry prepared from acquisition notes. Evidence files were not supplied with this task, so no first-access hashes or analyst access events have been fabricated.
