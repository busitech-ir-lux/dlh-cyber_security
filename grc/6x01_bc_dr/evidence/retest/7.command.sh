#!/bin/bash
source '/run/media/busitech/T7/Docs/Obsidian/Cybersecurity_Academy/Defensive Path/grc/6x01_bc_dr/opt/recovery_test/lab_config.env'
original_workspace=$RECOVERY_WORKSPACE
for variable in BACKUP_DIR BACKUP_FILE MANIFEST_FILE RECOVERY_DIR STAGED_SQL RECOVERY_DB; do
    path=${!variable}
    printf -v "$variable" '%s' "./tmp/meddefense-dr-test${path#"$original_workspace"}"
done
RECOVERY_WORKSPACE=./tmp/meddefense-dr-test
sqlite3 -readonly "$RECOVERY_DB" "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;" > evidence/retest/critical_records.txt || exit 1
cat evidence/retest/critical_records.txt
printf '%s\n' 'MRN-10043|BMP|K+: 6.1 mEq/L|1' 'MRN-10045|TROPONIN|0.08 ng/mL|1' > evidence/retest/critical_records.expected.txt
cmp evidence/retest/critical_records.expected.txt evidence/retest/critical_records.txt
