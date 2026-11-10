#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
marker=$(od -An -tx1 -N3 "$MANIFEST_FILE" | tr -d ' \n')
printf 'Manifest marker: %s\n' "$marker"
test "$marker" = efbbbf || exit 1
LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/retest/backup_manifest.normalized.sha256
# This supplied manifest names the original absolute workspace. Normalize only
# that location in a separate checked copy, preserving the trusted digest.
sed "s@/tmp/meddefense-dr-test/@./tmp/meddefense-dr-test/@g" evidence/retest/backup_manifest.normalized.sha256 > evidence/retest/backup_manifest.local.sha256
sha256sum -c evidence/retest/backup_manifest.local.sha256
