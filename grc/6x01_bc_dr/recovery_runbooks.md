# MedDefense Recovery Runbooks

**Version:** 1.1 | **Date:** 2026-11-10 | **Status:** Local LIS repeat test complete; AD
documentation-only

## LIS Recovery Runbook

Use a fresh working directory containing `recovery_timer.sh`, `evidence/retest`,
and the supplied `./tmp/meddefense-dr-test/backup` and `config` fixtures. Preserve
old logs, state, and databases in a separate run directory before another test.
The task folder is the execution root for this package. No production service
is started. This is the ten-step SQLite exercise, not full hospital LIS recovery.

### Configuration and timing

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

### 1. Identify recovery target [UPDATED]

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

### 2. Verify backup integrity [UPDATED]

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

### 3. Create recovery workspace [UPDATED]

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

### 4. Stage SQL at corrected path [UPDATED]

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

### 5. Restore SQLite database [UPDATED]

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

### 6. Validate row count [UPDATED]

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

### 7. Validate critical records [UPDATED]

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

### 8. Inspect configuration artifact [UPDATED]

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

### 9. Apply local validation override [UPDATED]

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

### 10. Record clinical notification [UPDATED]

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

### Complete the exercise

```bash
./recovery_timer.sh SUMMARY
```

Preserve the full log, summary, command output, recovered file, and prepared message.
The record must state actual time and whether the declared 30-minute target was
met. The local test does not certify the prescribed SSH environment or production
application recovery.

## Active Directory Recovery Runbook

**Scenario:** Confirmed unrecoverable DC01, healthy DC02, domain
`meddefense.local`. Systems Administrator executes; IT Security witnesses, and
Clinical Applications validates dependent access. This procedure is documentation
only. A full forest loss, suspected compromise, unhealthy DC02, or unverified backup
requires a separate recovery plan. Do not run Windows commands on this Linux host.

DC01 hardware loss does not mean the identity service is entirely unavailable:
healthy DC02 may keep it running. The BIA's 15-minute identity availability target
is distinct from rebuilding a redundant DC01. Confirm DNS clients can use DC02.
Use a clean supported replacement and verified backup; system-state recovery alone
is not bare-metal OS recovery. Preserve role, backup, and validation outputs.

### 1. Record existing FSMO role holders

On DC02, in an elevated command prompt:

```powershell
netdom query fsmo
```

**Expected:** The supplied example lists Schema master, Domain naming master, PDC,
RID pool manager, and Infrastructure master as `DC01.meddefense.local`, followed by
`The command completed successfully.` These are sample outputs, not live results.

**Check:** Save the actual listing and confirm DC02 health, DNS, time, Global
Catalog availability, and client access before choosing the recovery branch.
**Deviation:** If discovery fails or any role holder differs, stop and document
the real state; never apply the sample output as configuration.

### 2. Select nonauthoritative recovery or replacement

With DC02 healthy and holding valid current directory data, the normal restore
choice is **nonauthoritative**: DC01 receives current changes from DC02. Authoritative
object restoration is for explicitly approved recovery of deleted/incorrect objects
when replication would otherwise remove the restored objects. Authoritative SYSVOL
recovery is a separate controlled operation, not needed merely because DC01 failed.
Do not add `-authsysvol` to the single-DC procedure below.

**Check:** Confirm a supported, unexpired, clean system-state backup for the original
DC01 recovery identity and compatible OS/hardware or a supported prior bare-metal
recovery. Check backup age against actual directory retention/tombstone settings;
the April example date is not proof of a usable backup in November.

**Deviation and branch:** If hardware/OS cannot be recovered compatibly, use
DC02 as the trusted source and commission a new domain controller through a
separately approved rebuild/promotion procedure. If FSMO seizure is necessary to
maintain service, the IAM lead must authorize the role list and ensure the old
DC01 identity cannot reconnect. For example, on DC02 with the AD module:

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity DC02 -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster -Force
netdom query fsmo
```

This is a conditional documentation example, not an instruction to seize roles
routinely. After seizure and required metadata cleanup, do not follow the original
DC01 system-state rejoin branch; build/promote a clean replacement instead.
Do not revert arbitrary hypervisor snapshots, which can cause replication and
USN rollback problems. Forest compromise requires a different trust decision.

### 3. Perform the approved system-state branch

Run this branch only when the original DC01 identity is retained, roles have not
been seized away as part of a permanent replacement, and the supported OS recovery
prerequisites above are satisfied. On the isolated recovered DC01, in an elevated
command prompt, select a verified version and confirm DSRM credentials are available:

```powershell
wbadmin get versions -backuptarget:\\backup-srv\ad-backups\DC01 -machine:DC01
bcdedit /set {current} safeboot dsrepair
shutdown /r /t 0
```

Log in locally using Directory Services Restore Mode credentials. Confirm backup
access from DSRM; if the network share cannot be reached, use an approved local
staging copy with its verified backup target. Replace the version below with the
actual usable version from `get versions`; do not run the historical date blindly.

```powershell
wbadmin start systemstaterecovery -version:04/21/2026-01:00 -backuptarget:\\backup-srv\ad-backups\DC01 -machine:DC01 -quiet
```

**Expected:** Windows Backup completes system-state recovery successfully with no
reported failed components. The supplied material provides a command pattern,
not a genuine success transcript. Require the actual completion status before:

```powershell
bcdedit /deletevalue {current} safeboot
shutdown /r /t 0
```

**Check:** Boot normally only after a successful nonauthoritative restore and
controlled reconnection to DC02 for replication. Preserve the backup job/event logs.
**Deviation:** On restore failure, keep the host isolated and in the approved
recovery mode; do not declare success or overwrite the only good backup.

### 4. Verify replication

On the recovered DC01, then DC02:

```powershell
repadmin /showrepl DC01
repadmin /showrepl DC02
repadmin /replsummary
```

**Expected:** Successful recent inbound replication for all applicable naming
contexts and no replication failures. The supplied healthy excerpt for DC01 says:

```text
Default-First-Site-Name\DC01
==== INBOUND NEIGHBORS ======================================
DC=meddefense,DC=local
    Default-First-Site-Name\DC02 via RPC
        Last attempt @ 2026-04-21 09:42:13 was successful.
```

**Check:** Validate actual current timestamps, all naming contexts, and both
replication directions, not only this single-domain sample. **Deviation:** RPC,
DNS, time, access, SYSVOL, or replication errors block recovery declaration;
keep client changes controlled and escalate to the IAM lead.

### 5. Validate directory services and dependent login

```powershell
dcdiag /s:DC01 /test:Connectivity /test:SysVolCheck /test:NetLogons /v
dcdiag /s:DC01 /test:DNS /v
dcdiag /s:DC02 /test:Connectivity /test:SysVolCheck /test:NetLogons /v
netdom query fsmo
```

**Expected:** The first three tests pass as in `command_output_examples.md`:

```text
DC01 passed test Connectivity
DC01 passed test SysVolCheck
DC01 passed test NetLogons
```

**Check:** Save complete actual output, DNS test results, directory/SYSVOL event
logs, current role ownership, and an approved test user's new login to a clinical
application. Confirm account permissions and a representative service-account login
without recording passwords. **Deviation:** A passing ping or cached user session
is insufficient; unresolved diagnostic errors or stale replication block release.

### 6. Declare recovery and restore normal operations

The IAM lead may recommend release only after replication is current, required
DNS/SYSVOL/NetLogons tests pass, FSMO ownership is documented, no rollback or restore
errors remain, and new client and service authentication succeeds. IT Incident
Commander and clinical owner record acceptance time, residual issues, and clinical
notification. Verify scheduled backups resume and record a follow-up redundancy test.
Any failed criterion keeps the incident open; use healthy DC02 with monitored
capacity and a dated replacement plan rather than a false DC01 recovery declaration.

The restore distinction and command prerequisites follow
[Microsoft system-state recovery guidance](https://learn.microsoft.com/azure/backup/backup-azure-restore-system-state)
and the [AD recovery reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-nonauthoritative-restore).
These are conceptual references; local Windows version, backup support, and actual
replication state must be checked before applying a recovery branch.
