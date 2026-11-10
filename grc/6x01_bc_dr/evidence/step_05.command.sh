#!/bin/bash
test ! -e "$RECOVERY_DB" && test ! -e "$RECOVERY_DB.new" || exit 1
sqlite3 -bail "$RECOVERY_DB.new" < "$STAGED_SQL" || exit 1
mv "$RECOVERY_DB.new" "$RECOVERY_DB"
printf 'SQLite import completed
'
