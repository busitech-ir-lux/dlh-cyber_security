#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s\n' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/retest/recovered_database_ls.txt
cat evidence/retest/recovered_database_ls.txt
