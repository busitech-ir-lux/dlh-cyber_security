#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
count=$(sqlite3 -readonly "$RECOVERY_DB" "SELECT COUNT(*) FROM patient_orders;") || exit 1
printf '%s\n' "$count"
test "$count" = "$EXPECTED_ROW_COUNT"
