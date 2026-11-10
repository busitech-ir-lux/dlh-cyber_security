#!/bin/bash
cat "$RECOVERY_WORKSPACE/config/app_config.env"
printf '
'
grep '^DB_HOST=' "$RECOVERY_WORKSPACE/config/app_config.env"
