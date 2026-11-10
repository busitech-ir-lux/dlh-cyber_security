# LIS Recovery Test Record

**Version:** 1.0  
**Test date:** 2026-11-10  
**Test conductor:** Local automated project exercise; no named clinician or human witness supplied  
**Declared RTO:** 30 minutes  
**Test environment:** `/tmp/meddefense-dr-test/`, copied from the supplied project fixture  
**Outcome:** CONDITIONAL PASS for local artifact recovery only

## Scope and preparation

This was an actual local command execution, not a fabricated transcript. The
prescribed SSH lab was not connected. A copy of the supplied fixture was staged
at the configured absolute paths before timing; the source files were unchanged.
The captured environment is therefore a local adaptation, not proof of execution
inside the named training container. No Docker commands, extra packages, production
connections, or internet resources were used during the exercise.

The timer begins at Step 1 and ends at completion of Step 10. It includes normal
command execution, corrections, validation, notification preparation, and timer
calls between steps. It excludes initial fixture staging, prior document reading,
and later report writing. The notification was saved as an exercise artifact and
was not sent. Production recovery would also require full application, interface,
identity, clinical acceptance, and notification delivery time.

## Step Timing Log

Exact completed-step log:

```text
[STEP 01] Identify recovery target         | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 02] Verify backup integrity          | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 03] Create recovery workspace        | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 04] Stage SQL at corrected path      | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 05] Restore SQLite database          | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 06] Validate row count               | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 07] Validate critical records        | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 08] Inspect configuration artifact   | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 09] Apply local validation override  | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
[STEP 10] Record clinical notification     | Start: 11:11:09 | End: 11:11:09 | Duration: 0m 00s | PASS
```

Exact `recovery_timer.sh SUMMARY` output:

```text
Total elapsed: 0m 01s (245711516 ns; rounded up to seconds)
RTO (30 minutes): PASS
Completed step failures: 0
Overall timer result: PASS
```

All steps started and ended within the same displayed second. The timer preserves
epoch nanoseconds for the total, approximately 0.246 seconds; the displayed total
is rounded upward to one second. Individual displayed step durations are whole
seconds rounded down, so they need not add up to the rounded total. Command-only
nanosecond durations and start timestamps are in `evidence/steps.json`; they exclude
timer call overhead and are not a second invented set of stopwatch results.

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 11:11:09 CET during Step 4; timestamp resolution one second.  
**Time added:** Not separately identifiable as causal delay; 0.000089509 minutes of measured command
handling.

**Runbook specified:** `/recovery/lis_dump.sql`  
**Actual path:** `/tmp/meddefense-dr-test/recovery/lis_dump.sql`

The recorded file-existence check confirmed the old path was absent. No invalid
write to the filesystem root was attempted. This was an encountered path mismatch,
not a claim that a failed gzip command was executed. The supplied lab configuration
provided the correct staging path.

**Resolution, exact commands executed:**

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

### Condition 2: Configuration artifact

**Discovered at:** 11:11:09 CET during Step 8; timestamp resolution one second.  
**Time added:** Not separately identifiable as causal delay; 0.000070179 minutes of measured command
handling.

**Expected:** Local recovered SQLite path for validation.  
**Actual:** `DB_HOST=lis-db-prod.meddefense.internal` remains in the workspace file.

The raw workspace configuration was captured in `evidence/step_08.stdout.txt`.
It was not sourced or edited. The explicit local database path overrides the
network-database assumption for the validation command; it does not claim to
reconfigure a working LIS application.

**Resolution, exact commands executed in Step 9:**

```bash
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s
' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/recovered_database_ls.txt
cat evidence/recovered_database_ls.txt
```

### Condition 3: Row count check

**Discovered at:** 11:11:09 CET during Step 6; timestamp resolution one second.  
**Time added:** Not separately identifiable as causal delay; 0.000082060 minutes of measured command
handling.

**Query:** `SELECT COUNT(*) FROM patient_orders;`  
**Expected:** 5  
**Actual:** 5  
**Outcome:** PASS

Exact query stdout:

```text
5
```

This required validation condition succeeded; it is not a recovery fault. A count
alone cannot prove that patient identifiers and critical results match, so Step 7
separately compared both required records.

### Condition 4: Additional finding: manifest encoding

**Discovered at:** 11:11:09 CET during Step 2; timestamp resolution one second.  
**Time added:** Not separately identifiable as causal delay; 0.000192033 minutes of measured command
handling.

The original manifest begins with bytes `ef bb bf`. The original verification
command returned exit code 1 and rejected its format. The check was corrected by
removing only the UTF-8 marker in a separately saved copy. The archive digest
remained `ac918cf7ffd5c5cad3fdec178207c684a00bcb02a19fdcf994b22314fdacf0e1`.

**Resolution, exact commands executed:**

```bash
cp "$MANIFEST_FILE" evidence/backup_manifest.original.sha256
sha256sum -c "$MANIFEST_FILE"
raw_status=$?
printf 'Original manifest command exit: %s\n' "$raw_status"
if [[ $raw_status != 0 ]]; then
    od -An -tx1 -N3 "$MANIFEST_FILE"
    LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/backup_manifest.normalized.sha256
    sha256sum -c evidence/backup_manifest.normalized.sha256 || exit 1
fi
```

Exact stderr from the original attempt:

```text
sha256sum: /tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256: no properly formatted checksum lines found
```

Exact combined command stdout, including the recorded exit and successful retry:

```text
Original manifest command exit: 1
 ef bb bf
/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK
```

The handling durations bound the work done in the affected step; they are not
proof of extra minutes relative to an unobserved error-free run. For the config
artifact, Step 9 adds a separately measured validation interval of
0.000134118 minutes of measured command handling.
Outputs were written to each step's stdout/stderr files before that step's PASS
entry was appended. This preserves the observed deviations as the run progressed;
the human-readable report was assembled afterward.

## Recovery Validation

**Recovered database file:** Exact `ls -l` output from execution:

```text
-rw-r--r--. 1 busitech busitech 12288 Nov 10 11:11 /tmp/meddefense-dr-test/recovery/lis_recovered.db
```

**Critical values accessible:** Exact query output:

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

`PRAGMA integrity_check` returned `ok`; see `evidence/step_09.stdout.txt`.
The query checks simulated fixture content, not clinical interpretation of these
values. `evidence/clinical_notification.txt` records the unsent exercise message.
The restored database is also submitted at
`../tmp/meddefense-dr-test/recovery/lis_recovered.db`.

## Test Result

**Actual recovery time:** 245,711,516 ns, approximately 0.246 seconds; timer display 0m 01s.  
**RTO met:** YES for the limited local artifact exercise.  
**Test outcome:** CONDITIONAL PASS.

All required fixture checks passed after the recorded manifest correction.
The result is conditional because there was no prescribed SSH-container execution,
production-sized data, actual LIS service startup, instrument/interface validation,
clinical acceptance, or notification delivery. The dated April fixture and missing
transaction-to-outage timestamps cannot demonstrate the production one-hour RPO.
No production RTO reduction or compliance certification follows from this result.
