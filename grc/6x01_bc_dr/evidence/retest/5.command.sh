#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
test ! -e "$RECOVERY_DB" && test ! -e "$RECOVERY_DB.new" || exit 1
sqlite3 -bail "$RECOVERY_DB.new" < "$STAGED_SQL" || exit 1
mv "$RECOVERY_DB.new" "$RECOVERY_DB"
printf 'SQLite import completed\n'
