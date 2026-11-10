# LIS Recovery Gap Analysis

**Version:** 1.1 | **Date:** 2026-11-10  
**Current evidence:** `recovery_test_record.md`, `recovery_test_log.txt`, and `evidence/retest/`

## Test Summary Table

| Measure | Result |
| --- | --- |
| Declared RTO | 30 minutes. |
| Actual recovery time | 35.571540306 seconds = 0.592859005 minutes; timer display 0m 36s. |
| Delta, actual minus declared | -29.407140995 minutes; within the local exercise target. |
| Overall result | CONDITIONAL PASS: all SQLite fixture checks passed; prescribed SSH-container and production recovery remain unverified. |
| RPO result | Not established by the historical fixture. |

This is the repeat run, with command-output review included in the running clock.
The original subsecond run remains archived. No historical 41-minute result is
substituted, and no artificial delay was inserted to produce a preferred duration.

## Condition Analysis

The time values below are observed discovery-to-resolution handling intervals,
recorded during the repeat test. They include diagnosis and review; they are not
causal estimates against an unmeasured error-free baseline.

| Condition | Category | Root cause | Handling time, minutes | Patient safety consequence |
| --- | --- | --- | --- | --- |
| Old staging path | Runbook Error | Retired runbook names /recovery/lis_dump.sql rather than the configured local workspace. | 0.100069 | Each extra minute extends manual specimen and result tracking, risking delayed critical results. |
| Production hostname | Configuration Drift | The fixture retains a production DB_HOST without a local SQLite validation rule. | 0.083495 | An uncorrected endpoint assumption may waste outage time or direct checks at the wrong system. |
| Missing row-count checkpoint in old procedure | Documentation Gap | The old runbook treats login as sufficient without checking the recovered dataset. | 0.144710, required validation time, not a fault | Missing orders could go unnoticed; count and critical-record checks prevent false release. |
| Manifest encoding and location | Environment Assumption | A UTF-8 marker prevents checksum parsing and its filename points to the original absolute workspace. | 0.082224 | Bypassing the check risks an untrusted restore; correcting it consumes part of the recovery window. |

The proposed BIA describes growing manual-work risk at one hour, strained
reconciliation at four hours, and severe continuity risk at 24 hours. Its two-hour
LIS MTD is a leadership escalation boundary, not a guarantee of safety until that
time. Each additional minute of outage adds one minute requiring manual handling.
A five-minute delay consumes 16.7% of the 30-minute target; the actual repeat run
consumed 1.976%. No order arrival rate or injury probability is supplied,
so a count of affected or injured patients cannot be responsibly calculated.

## Runbook Deficiencies

- The old procedure names the wrong decompression target.
- Checksum parsing and failure handling are not defined, including the supplied manifest's encoding.
- The old database restore step has no exact SQLite command or failed-import gate.
- Row count, both critical records, and database integrity are not acceptance checks in the old
  procedure.
- The production hostname is not separated from local recovery validation.
- The old notification step does not distinguish an exercise message from clinical release.

All ten steps in the corrected runbook below are marked [UPDATED] relative to the
supplied old procedure. The repeat record preserves exact executed command bodies;
the runbook wraps expected diagnostics in conditionals so future failures cannot
fall through to PASS when `set -e` is enabled.

## Revised RTO

Retain the **30-minute target provisionally**. The corrected local fixture workflow
completed in about 36 seconds, including output review and recorded corrections.
This supports the exercise workflow, not a shorter production target. Production
needs realistic data volume, dependency recovery, analyzer/interface validation,
clinical acceptance, and delivered notification. The nightly-only production
backup must also change before a one-hour RPO can be claimed.

If production testing misses 30 minutes, record the miss and either fund the needed
recovery design or approve a revised BIA with clinical justification and RTO below
MTD. Do not revise the number solely to turn a failed exercise into a pass.

## Updated LIS Recovery Runbook

### LIS recovery procedure



Use a fresh working directory containing `recovery_timer.sh`, `evidence/retest`,
and the supplied `./tmp/meddefense-dr-test/backup` and `config` fixtures. Preserve
old logs, state, and databases in a separate run directory before another test.
The task folder is the execution root for this package. No production service
is started. This is the ten-step SQLite exercise, not full hospital LIS recovery.

#### Configuration and timing

Load only the trusted lab config; never source `app_config.env`. In this extracted
project the config is `../opt/recovery_test/lab_config.env`; in the prescribed lab,
use `/opt/meddefense/materials/recovery_test/lab_config.env`. The following adapts
the configured absolute workspace paths to this task's relative fixture location:

```bash
set -euo pipefail
source ../opt/recovery_test/lab_config.env
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
mkdir -p evidence/retest
```

Time every numbered step with the exact step name using START then PASS or FAIL.
Keep the clock running while errors are diagnosed. Append discovery/resolution
timestamps and command exit statuses to the run journal as work progresses.
Do not use global `set -e` while deliberately recording a diagnostic failure.

#### 1. Identify recovery target [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Identify recovery target" START
ls -l "$BACKUP_DIR/"
ls -l "$RECOVERY_WORKSPACE/config/"
printf 'Selected backup date: %s\n' "$BACKUP_DATE"
find "$RECOVERY_WORKSPACE/backup/lis" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
./recovery_timer.sh "Identify recovery target" PASS
```

**Expected output:** The selected date is 2026-04-21 and all supplied files are listed.

**Verification:** Confirm no newer complete backup is available; a folder date does not prove actual
RPO.

**Deviation handling:** Missing files or an unverified newer point require reselection before
import.

#### 2. Verify backup integrity [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Verify backup integrity" START
cp "$MANIFEST_FILE" evidence/retest/backup_manifest.original.sha256
if sha256sum -c "$MANIFEST_FILE"; then
    printf 'Original manifest verified\n'
else
    marker=$(od -An -tx1 -N3 "$MANIFEST_FILE" | tr -d ' \n')
    test "$marker" = efbbbf || exit 1
    LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/retest/backup_manifest.normalized.sha256
    sed "s@/tmp/meddefense-dr-test/@./tmp/meddefense-dr-test/@g" evidence/retest/backup_manifest.normalized.sha256 > evidence/retest/backup_manifest.local.sha256
    sha256sum -c evidence/retest/backup_manifest.local.sha256
fi
./recovery_timer.sh "Verify backup integrity" PASS
```

The first command group is a diagnostic check whose nonzero result must be
recorded. Run the correction only for the documented condition; an unexpected
error calls for FAIL and investigation, not unconditional PASS. If a required
command aborts the step under `set -e`, record FAIL for that active step before
investigating; do not continue to its PASS marker.

**Expected output:** The original malformed manifest fails; after the documented repair the local
archive reports OK.

**Verification:** Require marker efbbbf before this repair and preserve the unchanged digest and
original manifest.

**Deviation handling:** If the original manifest already succeeds, skip repair. Any checksum
mismatch or other format defect stops recovery; never regenerate a digest to match damaged data.

#### 3. Create recovery workspace [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Create recovery workspace" START
mkdir -p "$RECOVERY_DIR" "$RECOVERY_WORKSPACE/validation"
test -d "$RECOVERY_DIR"
printf 'Recovery workspace ready\n'
./recovery_timer.sh "Create recovery workspace" PASS
```

**Expected output:** Recovery workspace ready.

**Verification:** Confirm the directory is writable and separate from production.

**Deviation handling:** Stop for permission or space errors.

#### 4. Stage SQL at corrected path [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Stage SQL at corrected path" START
if ls -l /recovery/lis_dump.sql; then
    printf 'Old path exists, but this test still uses the configured local target\n'
else
    printf 'Known old-path mismatch recorded; using STAGED_SQL\n'
fi
test ! -e "$STAGED_SQL" || exit 1
gzip -dc "$BACKUP_FILE" > "$STAGED_SQL" || exit 1
test -s "$STAGED_SQL" || exit 1
ls -l "$STAGED_SQL"
./recovery_timer.sh "Stage SQL at corrected path" PASS
```

The first command group is a diagnostic check whose nonzero result must be
recorded. Run the correction only for the documented condition; an unexpected
error calls for FAIL and investigation, not unconditional PASS. If a required
command aborts the step under `set -e`, record FAIL for that active step before
investigating; do not continue to its PASS marker.

**Expected output:** Old-path ls fails; the corrected local staged SQL is then listed.

**Verification:** Check gzip success and nonempty SQL at STAGED_SQL.

**Deviation handling:** Do not write to /recovery; archive a pre-existing staged file rather than
overwrite evidence.

#### 5. Restore SQLite database [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Restore SQLite database" START
test ! -e "$RECOVERY_DB" && test ! -e "$RECOVERY_DB.new" || exit 1
sqlite3 -bail "$RECOVERY_DB.new" < "$STAGED_SQL" || exit 1
mv "$RECOVERY_DB.new" "$RECOVERY_DB"
printf 'SQLite import completed\n'
./recovery_timer.sh "Restore SQLite database" PASS
```

**Expected output:** SQLite import completed.

**Verification:** Import uses sqlite3 -bail into a fresh .new file before rename.

**Deviation handling:** Stop on failed import or a pre-existing database; preserve failed output for
analysis.

#### 6. Validate row count [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Validate row count" START
count=$(sqlite3 -readonly "$RECOVERY_DB" "SELECT COUNT(*) FROM patient_orders;") || exit 1
printf '%s\n' "$count"
test "$count" = "$EXPECTED_ROW_COUNT"
./recovery_timer.sh "Validate row count" PASS
```

**Expected output:** 5

**Verification:** Require EXPECTED_ROW_COUNT=5 for this fixture.

**Deviation handling:** A different count fails validation even if SQLite opens successfully.

#### 7. Validate critical records [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Validate critical records" START
sqlite3 -readonly "$RECOVERY_DB" "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;" > evidence/retest/critical_records.txt || exit 1
cat evidence/retest/critical_records.txt
printf '%s\n' 'MRN-10043|BMP|K+: 6.1 mEq/L|1' 'MRN-10045|TROPONIN|0.08 ng/mL|1' > evidence/retest/critical_records.expected.txt
cmp evidence/retest/critical_records.expected.txt evidence/retest/critical_records.txt
./recovery_timer.sh "Validate critical records" PASS
```

**Expected output:** Both specified MRN records, exact test/result strings, and critical_flag=1
match.

**Verification:** cmp must succeed against the expected records.

**Deviation handling:** Missing or changed critical records block acceptance.

#### 8. Inspect configuration artifact [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Inspect configuration artifact" START
cat "$RECOVERY_WORKSPACE/config/app_config.env"
printf '\n'
grep '^DB_HOST=' "$RECOVERY_WORKSPACE/config/app_config.env"
./recovery_timer.sh "Inspect configuration artifact" PASS
```

**Expected output:** DB_HOST=lis-db-prod.meddefense.internal is visible.

**Verification:** Identify the production-host artifact before any application or network action.

**Deviation handling:** Do not source or edit the supplied application config; use local-path
validation next.

#### 9. Apply local validation override [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Apply local validation override" START
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s\n' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/retest/recovered_database_ls.txt
cat evidence/retest/recovered_database_ls.txt
./recovery_timer.sh "Apply local validation override" PASS
```

**Expected output:** Local recovery path, ok, 5, and the recovered file listing.

**Verification:** Require explicit SQLite path, integrity check, and count.

**Deviation handling:** Any integrity error fails the exercise; a local database check cannot
authorize production release.

#### 10. Record clinical notification [UPDATED]

**Command or action:**

```bash
./recovery_timer.sh "Record clinical notification" START
cat > evidence/retest/clinical_notification.txt <<'NOTICE'
EXERCISE ONLY - prepared, not sent.
To: Clinical Applications Lead 7300, Nursing Supervisor 7100, Laboratory accessioning 7500.
Five simulated patient orders restored; both required critical records verified; SQLite integrity check passed.
Production application, instruments, interfaces, and clinical operations were not tested.
Continue downtime procedures until the authorized clinical and incident leads confirm service acceptance.
Reconcile paper orders, specimens, critical-value calls, and outstanding results before ending downtime.
NOTICE
cat evidence/retest/clinical_notification.txt
./recovery_timer.sh "Record clinical notification" PASS
```

**Expected output:** An EXERCISE ONLY notification is saved.

**Verification:** Message states scope, validation, untested interfaces, continued downtime, and
reconciliation.

**Deviation handling:** Do not send a real restoration notice without authorized clinical and
incident acceptance.

#### Complete the exercise

```bash
./recovery_timer.sh SUMMARY
```

Preserve the full log, summary, command output, recovered file, and prepared message.
The record must state actual time and whether the declared 30-minute target was
met. The local test does not certify the prescribed SSH environment or production
application recovery.

## Remediation Roadmap

All dates below are proposed commitments measured from preparation; none imply
leadership acceptance or completed production work.

| Priority | Action | Owner Role | Target Completion | Success Criterion |
| --- | --- | --- | --- | --- |
| 1 | Approve BIA tolerances and downtime thresholds with clinical leaders. | CISO and Laboratory Medical Director | 2026-11-17 | Signed tolerances with RTO below MTD and funded response assumptions. |
| 1 | Replace nightly-only LIS recovery points with 30-minute consistent snapshots and monitored off-site delivery. | Laboratory Systems Lead and Infrastructure Manager | 2026-11-24 | Last verified off-site point stays within 60 minutes during demonstrated normal and missed-job tests. |
| 1 | Correct staged paths and publish a versioned recovery kit. | Laboratory Systems Lead | 2026-11-13 | Fresh-workspace restore uses only configured paths and preserves original evidence. |
| 1 | Generate marker-free authenticated checksum manifests; retain the tested legacy handling branch. | Backup Administrator | 2026-11-13 | Raw sha256sum check succeeds; altered archive and unexpected-format negative tests stop recovery. |
| 1 | Remove production endpoint assumptions from the exercise template and isolate recovery credentials. | Clinical Applications Lead | 2026-11-17 | Local validation cannot contact the production database and preserves the supplied source config. |
| 2 | Run production-sized, full-interface timed LIS recovery with clinical acceptance. | Laboratory Systems Lead and Nursing Supervisor | 2026-12-08 | Record actual end-to-end time, data age, interface checks, notifications, and sign-offs; preserve any miss. |
| 2 | Drill paper orders, read-back escalation, and reconciliation on night shift. | Nursing Supervisor and Chemistry Lead | 2026-11-24 | Staff locate forms and complete witnessed critical-value escalation and reconciliation without missing identifiers. |
| 2 | Prove network/identity/backup bootstrap at an alternate site. | Network Engineering Lead and Systems Administrator | 2026-12-08 | Independent credentials, keys, DNS, and catalog recover within documented dependency budgets. |

Focused checks of the revised checksum guard passed for a valid manifest,
a marker-prefixed manifest, a deliberately changed archive, and a malformed
manifest: valid copies passed and invalid copies stopped. Results are in
`evidence/validation_checks.txt` (initial checks; repeat checks are in
`evidence/retest/package_validation.txt`). These checks do not replace a complete corrected
workflow or production-scale retest. The original recovery evidence remains intact.
