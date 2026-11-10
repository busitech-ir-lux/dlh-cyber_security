# LIS Recovery Gap Analysis

**Version:** 1.0 | **Date:** 2026-11-10  
**Evidence:** `recovery_test_record.md`, `recovery_test_log.txt`, raw files in
`evidence/`, `condition_cards.md`, `old_lis_recovery_runbook.md`, and the proposed BIA

## Test Summary Table

| Measure | Result |
| --- | --- |
| Declared RTO | 30 minutes, 1,800 seconds. |
| Actual measured artifact recovery | 245,711,516 ns, approximately 0.246 seconds; displayed as 0m 01s. |
| Delta: actual minus target | -29.995904808 minutes; within target for this fixture. |
| Overall result | CONDITIONAL PASS; local SQLite checks passed after recorded correction, production service recovery not established. |
| RPO result | Not established; the April fixture is not a live point-in-time recovery demonstration. |

The delta uses the unrounded timer total, not the one-second display. There was no
observed 41-minute recovery in this project. The prior project's historical result
must not be substituted for this actual exercise, nor should the exercise be
slowed down to manufacture a missed target.

## Condition Analysis

The proposed BIA describes manageable but risky phone-and-paper work at one hour,
strained specimen/order reconciliation at four hours, and severe continuity risk
at 24 hours. Its two-hour LIS MTD is a proposed leadership escalation boundary;
it does not imply that every clinical workflow is safe until that point.

| Condition | Category | Root cause | Measured handling, minutes | Patient safety consequence |
| --- | --- | --- | --- | --- |
| Legacy staging path | Runbook Error | The old procedure embeds a root-level path from a retired environment. | 0.000089509; command handling, not isolated added delay. | Each minute spent locating SQL extends manual specimen/result tracking and delays result posting. |
| Production hostname in test config | Configuration Drift | A production-oriented application setting remains in the recovery fixture without an explicit local validation rule. | 0.000070179; command handling, not isolated added delay. | Following it could waste outage time or direct activity at the wrong system; explicit local validation avoids that exposure. |
| Row-count checkpoint absent from old procedure | Documentation Gap | The old runbook ends at login without defining dataset acceptance. | 0.000082060; command handling, not isolated added delay. | Without this check an incomplete restore could hide orders and leave critical tests untracked; the new check takes time but prevents false release. |
| UTF-8 marker in checksum manifest | Environment Assumption | The fixture manifest was encoded with a leading marker that sha256sum does not accept. | 0.000192033; command handling, not isolated added delay. | Unplanned verification diagnosis prolongs manual workflows; bypassing verification instead risks restoring corrupted data. |

For the configuration condition, separate local validation in Step 9 took
0.000134118 minutes.
The evidence does not support assigning a causal “minutes lost” value to each
condition: no equivalent clean baseline was timed. Report the measured work and
this limitation rather than inventing delays. Whole-second logs correctly show
zero seconds for these very short steps; high-resolution measurements retain the
nonzero intervals.

One additional minute of LIS downtime adds one minute in which pending electronic
orders and results require manual tracking. If the arrival rate were q orders per
minute, an additional d minutes would expose q × d orders to the manual process;
q is not supplied, so no patient count or harm probability can be calculated.
For planning, a five-minute delay consumes 16.7% of the 30-minute RTO and five
minutes of its 90-minute RTO-to-MTD margin. These are arithmetic exposure measures,
not predictions of injury. The actual total here consumed about 0.0137% of the RTO.

## Runbook Deficiencies

- The old staging instruction names `/recovery/lis_dump.sql` instead of the configured recovery
  workspace.
- The old procedure has no exact checksum command, encoding check, or rule forbidding verification
  bypass.
- “Restore the database” omits the SQLite import command and failed-import handling.
- Login is treated as sufficient despite missing row-count, critical-record, and integrity checks.
- The application configuration's production hostname is not isolated from local recovery
  validation.
- Timing, contemporaneous deviation output, and exercise-only notification content are not defined.
- Production startup, interface reconciliation, backup-point age, and clinical acceptance are not
  demonstrated by the simplified lab.

The initial Task 3 runbook already corrected the known condition-card failures
before execution. The test additionally confirmed the manifest encoding defect;
the updated version below requires checking those exact marker bytes before
normalizing. All ten steps are marked [UPDATED] relative to the supplied old runbook,
not a claim that every change was discovered for the first time in this test.

## Revised RTO

Retain the **30-minute LIS target provisionally**. Correct paths, non-production
validation, complete data checks, and an explicit manifest-handling rule made this
fixture workflow executable well inside 30 minutes. The result does not justify a
shorter production target or prove that the current production architecture meets
30 minutes. Cold restore performance, Epic/identity dependencies, analyzers,
clinical acceptance, and notification delivery require a production-scale exercise.

If that exercise exceeds 30 minutes, keep the miss visible and either fund the
warm-standby design or obtain clinical and CISO approval for an honest revised BIA
with RTO still below its approved MTD. Changing the number alone does not remove
the patient safety risk. The present nightly backup also needs redesign before
claiming a one-hour RPO.

## Updated LIS Recovery Runbook

### Scope and execution rules

**Scope:** Isolated SQLite exercise using the supplied archive. No live patient
system, network endpoint, or application service is restored. The declared exercise
RTO is 30 minutes. Use a new evidence working directory for every run; preserve
prior timer state, logs, databases, and source copies.

#### Preparation before the outage clock

Verify sqlite3, gzip, sha256sum, Bash, sed, and flock are present; install nothing.
In the prescribed lab, materials are `/opt/meddefense/materials`. In this extracted
project, use `<project>/opt`. Load only the trusted lab configuration, never the
application configuration. Stage supplied fixtures at their configured `/tmp`
paths before the exercise, record this staging, and do not count it as production
recovery. The timed test here used that local adaptation, not an SSH lab session.

```bash
MATERIALS=/opt/meddefense/materials
source "$MATERIALS/recovery_test/lab_config.env"
mkdir -p evidence
```

Run the timer from the evidence working directory. At each numbered step use
`./recovery_timer.sh "<step name>" START`, execute the listed commands, capture stdout
and stderr immediately, then use the same name with PASS or FAIL. The timer must
continue during diagnosis and correction. Stop on unhandled failure and preserve
results. Commands below match the recorded test actions; do not enable global
`set -e` when intentionally capturing the original manifest's nonzero status.

#### 1. Identify recovery target [UPDATED]

**Command or action:**

```bash
ls -l "$BACKUP_DIR/"
ls -l "$RECOVERY_WORKSPACE/config/"
printf 'Configured recovery target: %s
' "$BACKUP_DATE"
find "$RECOVERY_WORKSPACE/backup/lis" -mindepth 1 -maxdepth 1 -type d -printf '%f
' | sort
```

**Expected output:** Configured date 2026-04-21 and the supplied SQL archive, manifest, and
workspace configuration are listed.

**Verification:** Confirm this is the latest available candidate and record its date; a directory
name is not a proven transaction timestamp.

**Deviation handling:** If missing or a newer point exists, stop and reselect a complete verified
recovery point. Do not claim the dated fixture meets a live RPO.

#### 2. Verify backup integrity [UPDATED]

**Command or action:**

```bash
cp "$MANIFEST_FILE" evidence/backup_manifest.original.sha256
if sha256sum -c "$MANIFEST_FILE"; then
    printf 'Original manifest verified
'
else
    marker=$(od -An -tx1 -N3 "$MANIFEST_FILE" | tr -d ' \n')
    test "$marker" = efbbbf || exit 1
    LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/backup_manifest.normalized.sha256
    sha256sum -c evidence/backup_manifest.normalized.sha256 || exit 1
fi
```

**Expected output:** Original check fails with no properly formatted checksum lines; first bytes are
ef bb bf; normalized copy reports the SQL archive as OK.

**Verification:** Preserve the original manifest and error; verify the independently known SHA-256
value matches the archive after removing only the marker.

**Deviation handling:** Only the documented UTF-8 marker may be removed in a separate copy. For any
checksum mismatch, changed digest, other malformed content, or unexpected archive path, stop and
select another trusted copy.

#### 3. Create recovery workspace [UPDATED]

**Command or action:**

```bash
mkdir -p "$RECOVERY_DIR" "$RECOVERY_WORKSPACE/validation"
test -d "$RECOVERY_DIR" && printf 'Recovery workspace ready
'
```

**Expected output:** Recovery workspace ready.

**Verification:** Confirm recovery and validation directories exist and are writable.

**Deviation handling:** Stop on permissions or disk-space errors; do not redirect output into a
production path.

#### 4. Stage SQL at corrected path [UPDATED]

**Command or action:**

```bash
if test -e /recovery/lis_dump.sql; then
    printf 'Old path exists; it is not the configured recovery target
'
else
    printf 'Old runbook path /recovery/lis_dump.sql is absent
'
fi
test ! -e "$STAGED_SQL" || exit 1
gzip -dc "$BACKUP_FILE" > "$STAGED_SQL" || exit 1
ls -l "$STAGED_SQL"
```

**Expected output:** Old runbook path is absent; corrected staged SQL is listed under the configured
recovery directory.

**Verification:** Confirm gzip succeeds and staged SQL is nonempty; the old /recovery path is a
retained known failure mode.

**Deviation handling:** Do not create /recovery/lis_dump.sql. Use STAGED_SQL from the lab
configuration; preserve pre-existing staged evidence rather than overwrite it.

#### 5. Restore SQLite database [UPDATED]

**Command or action:**

```bash
test ! -e "$RECOVERY_DB" && test ! -e "$RECOVERY_DB.new" || exit 1
sqlite3 -bail "$RECOVERY_DB.new" < "$STAGED_SQL" || exit 1
mv "$RECOVERY_DB.new" "$RECOVERY_DB"
printf 'SQLite import completed
'
```

**Expected output:** SQLite import completed; a new recovered database exists.

**Verification:** Require sqlite3 -bail to succeed before renaming the temporary database.

**Deviation handling:** If an old result or .new file exists, archive it under a separate evidence
directory and choose a fresh run; never drop a production database or overwrite prior evidence.

#### 6. Validate row count [UPDATED]

**Command or action:**

```bash
count=$(sqlite3 -readonly "$RECOVERY_DB" "SELECT COUNT(*) FROM patient_orders;") || exit 1
printf '%s
' "$count"
test "$count" = "$EXPECTED_ROW_COUNT"
```

**Expected output:** 5

**Verification:** The actual count must equal EXPECTED_ROW_COUNT=5 for this fixture.

**Deviation handling:** A different count fails validation; preserve the database and investigate
the selected dump and import output.

#### 7. Validate critical records [UPDATED]

**Command or action:**

```bash
sqlite3 -readonly "$RECOVERY_DB" "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;" > evidence/critical_records.txt || exit 1
cat evidence/critical_records.txt
printf '%s
' 'MRN-10043|BMP|K+: 6.1 mEq/L|1' 'MRN-10045|TROPONIN|0.08 ng/mL|1' > evidence/critical_records.expected.txt
cmp evidence/critical_records.expected.txt evidence/critical_records.txt
```

**Expected output:** MRN-10043|BMP|K+: 6.1 mEq/L|1 and MRN-10045|TROPONIN|0.08 ng/mL|1, on separate
lines.

**Verification:** Compare exact sorted output with the two expected records; both records and
critical flags must match.

**Deviation handling:** Missing, changed, or duplicated required records block release even if the
total row count is five.

#### 8. Inspect configuration artifact [UPDATED]

**Command or action:**

```bash
cat "$RECOVERY_WORKSPACE/config/app_config.env"
printf '
'
grep '^DB_HOST=' "$RECOVERY_WORKSPACE/config/app_config.env"
```

**Expected output:** The workspace file includes DB_HOST=lis-db-prod.meddefense.internal.

**Verification:** Record this production hostname as a configuration artifact; do not connect to it.

**Deviation handling:** Do not source this application file or start a service that could use
production credentials or endpoints. Preserve the file unchanged.

#### 9. Apply local validation override [UPDATED]

**Command or action:**

```bash
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s
' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/recovered_database_ls.txt
cat evidence/recovered_database_ls.txt
```

**Expected output:** Local override names the configured recovered database; integrity_check returns
ok, count returns 5, and ls lists the database.

**Verification:** Use the explicit SQLite file path so DB_HOST is irrelevant; confirm the query does
not depend on network access.

**Deviation handling:** Any integrity error fails the test. Local SQL success alone cannot authorize
production or prove an application health check.

#### 10. Record clinical notification [UPDATED]

**Command or action:**

```bash
cat > evidence/clinical_notification.txt <<'NOTICE'
EXERCISE ONLY - not sent to clinical staff.
To: Clinical Applications Lead (7300), Nursing Supervisor (7100), lab accessioning (7500).
Local LIS recovery database restored; five orders and both required critical records verified.
Production LIS, interfaces, analyzer feeds, authentication, and clinical operation are not tested.
Continue downtime workflows; authorized clinical and incident leads must approve any return to service.
Reconcile paper orders, specimens, and critical-value calls before ending downtime.
NOTICE
cat evidence/clinical_notification.txt
```

**Expected output:** An EXERCISE ONLY notification file is saved; no message is sent.

**Verification:** Content names the scope tested, five rows, both critical values, untested
interfaces, and continued downtime.

**Deviation handling:** If a real incident, have the Clinical Applications Lead and Nursing
Supervisor verify and deliver an approved message, log acknowledgment, and reconcile paper work
before return to service.

#### Close the timed run

```bash
./recovery_timer.sh SUMMARY
```

Copy its entire output and the completed-step log into the test record. Preserve
the actual errors and timestamp precision. A successful fixture test does not end
clinical downtime or meet the full-site target without separate validation.

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
`evidence/validation_checks.txt`. These checks do not replace a complete corrected
workflow or production-scale retest. The original recovery evidence remains intact.
