#!/bin/bash
ls -l "$BACKUP_DIR/"
ls -l "$RECOVERY_WORKSPACE/config/"
printf 'Configured recovery target: %s
' "$BACKUP_DATE"
find "$RECOVERY_WORKSPACE/backup/lis" -mindepth 1 -maxdepth 1 -type d -printf '%f
' | sort
