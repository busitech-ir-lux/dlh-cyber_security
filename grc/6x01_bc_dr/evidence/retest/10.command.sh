#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
cat > evidence/retest/clinical_notification.txt <<'NOTICE'
EXERCISE ONLY - prepared, not sent.
To: Clinical Applications Lead 7300, Nursing Supervisor 7100, Laboratory accessioning 7500.
Five simulated patient orders restored; both required critical records verified; SQLite integrity check passed.
Production application, instruments, interfaces, and clinical operations were not tested.
Continue downtime procedures until the authorized clinical and incident leads confirm service acceptance.
Reconcile paper orders, specimens, critical-value calls, and outstanding results before ending downtime.
NOTICE
cat evidence/retest/clinical_notification.txt
