#!/bin/bash
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
