# MedDefense Recovery Runbooks

**Version:** 1.0 | **Date:** 2026-11-10 | **Status:** Proposed; LIS tested locally,
AD documentation-only

Source basis: `old_lis_recovery_runbook.md`, `old_ad_recovery_notes.md`,
`command_output_examples.md`, `lab_config.env`, and `app_config.env`. The old LIS
procedure's path and missing checks are retained as known failure modes. Expected
outputs are expectations, not claims of Windows commands executed in this lab.

## LIS Recovery Runbook

**Scope:** Isolated SQLite exercise using the supplied archive. No live patient
system, network endpoint, or application service is restored. The declared exercise
RTO is 30 minutes. Use a new evidence working directory for every run; preserve
prior timer state, logs, databases, and source copies.

### Preparation before the outage clock

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

### 1. Identify recovery target

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

### 2. Verify backup integrity

**Command or action:**

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

**Expected output:** Original check fails with no properly formatted checksum lines; first bytes are
ef bb bf; normalized copy reports the SQL archive as OK.

**Verification:** Preserve the original manifest and error; verify the independently known SHA-256
value matches the archive after removing only the marker.

**Deviation handling:** Only the documented UTF-8 marker may be removed in a separate copy. For any
checksum mismatch, changed digest, other malformed content, or unexpected archive path, stop and
select another trusted copy.

### 3. Create recovery workspace

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

### 4. Stage SQL at corrected path

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

### 5. Restore SQLite database

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

### 6. Validate row count

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

### 7. Validate critical records

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

### 8. Inspect configuration artifact

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

### 9. Apply local validation override

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

### 10. Record clinical notification

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

### Close the timed run

```bash
./recovery_timer.sh SUMMARY
```

Copy its entire output and the completed-step log into the test record. Preserve
the actual errors and timestamp precision. A successful fixture test does not end
clinical downtime or meet the full-site target without separate validation.

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
