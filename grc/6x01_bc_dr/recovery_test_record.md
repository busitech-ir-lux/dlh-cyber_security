# LIS Recovery Test Record

**Version:** 1.1  
**Test date:** 2026-11-10  
**Test conductor:** Codex, executing and reviewing commands; no clinical witness  
**Declared RTO:** 30 minutes  
**Test environment:** `./tmp/meddefense-dr-test/`, relative to the task execution directory  
**Execution:** Local repeat test using the supplied SQLite fixture

## Step Timing Log

The timer ran from the first START through the last completed step. Commands were
executed in stages and their output reviewed between steps, with no inserted
sleeps. Elapsed time includes that review and diagnosis. This five-row fixture is
not a production-sized workload. Original source backups and application config
were preserved; a fresh recovery directory was used.

The run took place in `/tmp/6x01_revision/tasks` before its artifacts were copied
to this project's `tasks` folder. The original config's absolute paths were
remapped to `./tmp/meddefense-dr-test/` for this local test. The required SSH lab
was not connected; this record does not claim execution in that container.

Full `recovery_test_log.txt` output:

```text
[STEP 01] Identify recovery target         | Start: 11:49:56 | End: 11:50:06 | Duration: 0m 09s | PASS
[STEP 02] Verify backup integrity          | Start: 11:50:06 | End: 11:50:11 | Duration: 0m 05s | PASS
[STEP 03] Create recovery workspace        | Start: 11:50:11 | End: 11:50:11 | Duration: 0m 00s | PASS
[STEP 04] Stage SQL at corrected path      | Start: 11:50:11 | End: 11:50:18 | Duration: 0m 06s | PASS
[STEP 05] Restore SQLite database          | Start: 11:50:18 | End: 11:50:18 | Duration: 0m 00s | PASS
[STEP 06] Validate row count               | Start: 11:50:18 | End: 11:50:27 | Duration: 0m 08s | PASS
[STEP 07] Validate critical records        | Start: 11:50:27 | End: 11:50:27 | Duration: 0m 00s | PASS
[STEP 08] Inspect configuration artifact   | Start: 11:50:27 | End: 11:50:27 | Duration: 0m 00s | PASS
[STEP 09] Apply local validation override  | Start: 11:50:32 | End: 11:50:32 | Duration: 0m 00s | PASS
[STEP 10] Record clinical notification     | Start: 11:50:32 | End: 11:50:32 | Duration: 0m 00s | PASS
```

Full `recovery_timer.sh SUMMARY` output:

```text
Total elapsed: 0m 36s (35571540306 ns; rounded up to seconds)
RTO (30 minutes): PASS
Completed step failures: 0
Overall timer result: PASS
```

The timer reports whole-second step durations and rounds the total upward.
The total includes gaps between steps, so adding the displayed step durations
is not the total recovery time.
`evidence/retest/journal.jsonl` preserves start/end events and discovery/resolution
timestamps at higher precision. Some very short steps correctly show zero whole
seconds. The original subsecond run remains in `evidence/initial_run/`.

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 2026-11-10T11:50:12.039986+01:00  
**Time added:** 0.100069 minutes of observed diagnosis and correction.

**Runbook specified:** `/recovery/lis_dump.sql`  
**Actual path:** `./tmp/meddefense-dr-test/recovery/lis_dump.sql`

The old-path check actually failed with exit code 2:

```text
ls: cannot access '/recovery/lis_dump.sql': No such file or directory
```

The SQL was then decompressed to the configured local staging path. No write to
the incorrect root-level path was attempted.

**Resolution: exact command bodies executed:**

```bash
printf 'Checking old runbook staging path\n'
ls -l /recovery/lis_dump.sql
```

```bash
test ! -e "$STAGED_SQL" || exit 1
gzip -dc "$BACKUP_FILE" > "$STAGED_SQL" || exit 1
test -s "$STAGED_SQL" || exit 1
ls -l "$STAGED_SQL"
```

### Condition 2: Configuration artifact

**Discovered at:** 2026-11-10T11:50:27.334437+01:00  
**Time added:** 0.083495 minutes of observed diagnosis and correction.

**Expected:** Validate the local recovered SQLite database.  
**Actual:** `DB_HOST=lis-db-prod.meddefense.internal` in the supplied config.

The config was inspected, not sourced. The explicit SQLite path in Step 9 provides
the local override; no production database connection was attempted and no source
configuration was edited.

**Resolution: exact command bodies executed:**

```bash
cat "$RECOVERY_WORKSPACE/config/app_config.env"
printf '\n'
grep '^DB_HOST=' "$RECOVERY_WORKSPACE/config/app_config.env"
```

```bash
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s\n' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/retest/recovered_database_ls.txt
cat evidence/retest/recovered_database_ls.txt
```

### Condition 3: Row count check

**Discovered at:** 2026-11-10T11:50:18.336991+01:00, during Step 6.  
**Category:** Documentation Gap.  
**What was wrong:** The old LIS runbook has a missing row-count checkpoint: it
requires a user-login check but does not verify the number of restored orders.
An incomplete restore could therefore be accepted without detecting missing orders.
`old_lis_recovery_runbook.md` explicitly lists the lack of row-count validation
under Known Problems. This procedural omission is the deviation recorded here.

**Resolution:** Add the missing checkpoint to the recovery procedure and execute
it against the recovered database before acceptance. Compare the returned count
with the fixture's configured `EXPECTED_ROW_COUNT=5`, and retain the exact output.
The repeat test executed these commands with
`RECOVERY_DB=./tmp/meddefense-dr-test/recovery/lis_recovered.db`:

```bash
count=$(sqlite3 -readonly "$RECOVERY_DB" "SELECT COUNT(*) FROM patient_orders;") || exit 1
printf '%s\n' "$count"
test "$count" = "$EXPECTED_ROW_COUNT"
```

**Time added:** 0.144710 minutes, approximately 8.683 seconds, to execute and review
the checkpoint added to address the runbook omission. This is the observed Step 6
start-to-completion interval in `evidence/retest/journal.jsonl`, including output
review. It is already included in the total recovery time and must not be added
again; it is not a measured difference against an error-free baseline.

**Query:** `SELECT COUNT(*) FROM patient_orders;`  
**Expected:** 5  
**Actual:** 5  
**Outcome:** PASS  
**Deviation status:** RESOLVED in the revised procedure: the missing checkpoint
was performed and the recovered row count matched the expected value.

**Failure handling:** If the query fails or the count is not 5, record FAIL,
preserve the database and error output, investigate the selected backup and import,
and withhold recovery acceptance. No row-count mismatch occurred in this test.

Exact recorded stdout:

```text
5
```

### Condition 4: Additional finding: manifest encoding

**Discovered at:** 2026-11-10T11:50:06.736224+01:00  
**Time added:** 0.082224 minutes of observed diagnosis and correction.

The raw `sha256sum -c` attempt returned exit code 1:

```text
sha256sum: ./tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256: no properly formatted checksum lines found
```

The original file was saved. A separate copy removes its leading UTF-8 marker,
and another copy maps its original absolute filename to the local fixture path.
The digest was not changed. The corrected verification actually printed:

```text
Manifest marker: efbbbf
./tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK
```

**Resolution: exact command bodies executed:**

```bash
cp "$MANIFEST_FILE" evidence/retest/backup_manifest.original.sha256
sha256sum -c "$MANIFEST_FILE"
```

```bash
marker=$(od -An -tx1 -N3 "$MANIFEST_FILE" | tr -d ' \n')
printf 'Manifest marker: %s\n' "$marker"
test "$marker" = efbbbf || exit 1
LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/retest/backup_manifest.normalized.sha256
# This supplied manifest names the original absolute workspace. Normalize only
# that location in a separate checked copy, preserving the trusted digest.
sed "s@/tmp/meddefense-dr-test/@./tmp/meddefense-dr-test/@g" evidence/retest/backup_manifest.normalized.sha256 > evidence/retest/backup_manifest.local.sha256
sha256sum -c evidence/retest/backup_manifest.local.sha256
```

The numeric “time added” values measure discovery-to-resolution handling
intervals recorded during this repeat test. They include review between commands;
they are not an estimate of patient harm or a causal comparison with an unobserved
error-free baseline. Condition 3 records the old runbook's missing validation
checkpoint as a procedural deviation; its successful query resolves that gap
without claiming that the recovered row count failed.
The timer continued throughout all corrections.

## Recovery Validation

**Recovered database file:** Exact `ls -l` output:

```text
-rw-r--r--. 1 busitech busitech 12288 Nov 10 11:50 ./tmp/meddefense-dr-test/recovery/lis_recovered.db
```

**Critical values accessible:** Exact query stdout:

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**Integrity and local-path validation:** Exact Step 9 stdout:

```text
Local override: RECOVERY_DB_PATH=./tmp/meddefense-dr-test/recovery/lis_recovered.db
ok
5
-rw-r--r--. 1 busitech busitech 12288 Nov 10 11:50 ./tmp/meddefense-dr-test/recovery/lis_recovered.db
```

Each command body, stdout, stderr, and exit status is retained in
`evidence/retest/`. The recovered database is
[tmp/meddefense-dr-test/recovery/lis_recovered.db](tmp/meddefense-dr-test/recovery/lis_recovered.db).
`evidence/retest/clinical_notification.txt` is the required prepared notification;
it is marked EXERCISE ONLY and was not sent.

## Test Result

**Actual recovery time:** 35.571540306 seconds (0.592859005 minutes); timer display **0m 36s**.  
**RTO met:** YES for the local SQLite recovery exercise.  
**Test outcome:** CONDITIONAL PASS.

All required data checks passed, including five rows, both critical records,
and `integrity_check=ok`. The condition is the execution scope: no prescribed SSH
container, real LIS application, instrument/interface validation, or clinical
acceptance was demonstrated. Those limits do not turn a genuine successful
fixture restore into production recovery evidence. The April backup cannot prove
a current one-hour RPO. A container rerun is still required for that environment
requirement; its evidence must replace neither this run nor its measured time.
