#!/bin/bash
RECOVERY_DB_PATH="$RECOVERY_DB"
printf 'Local override: RECOVERY_DB_PATH=%s
' "$RECOVERY_DB_PATH"
sqlite3 -readonly "$RECOVERY_DB_PATH" "PRAGMA integrity_check; SELECT COUNT(*) FROM patient_orders;" || exit 1
ls -l "$RECOVERY_DB" > evidence/recovered_database_ls.txt
cat evidence/recovered_database_ls.txt
