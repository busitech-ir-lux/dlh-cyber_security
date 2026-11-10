#!/bin/bash
count=$(sqlite3 -readonly "$RECOVERY_DB" "SELECT COUNT(*) FROM patient_orders;") || exit 1
printf '%s
' "$count"
test "$count" = "$EXPECTED_ROW_COUNT"
