#!/bin/bash
cp "$MANIFEST_FILE" evidence/backup_manifest.original.sha256
sha256sum -c "$MANIFEST_FILE"
raw_status=$?
printf 'Original manifest command exit: %s\n' "$raw_status"
if [[ $raw_status != 0 ]]; then
    od -An -tx1 -N3 "$MANIFEST_FILE"
    LC_ALL=C sed '1s/^\xEF\xBB\xBF//' "$MANIFEST_FILE" > evidence/backup_manifest.normalized.sha256
    sha256sum -c evidence/backup_manifest.normalized.sha256 || exit 1
fi
