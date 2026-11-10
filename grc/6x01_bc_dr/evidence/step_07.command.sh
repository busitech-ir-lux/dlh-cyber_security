#!/bin/bash
sqlite3 -readonly "$RECOVERY_DB" "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045') ORDER BY patient_mrn;" > evidence/critical_records.txt || exit 1
cat evidence/critical_records.txt
printf '%s
' 'MRN-10043|BMP|K+: 6.1 mEq/L|1' 'MRN-10045|TROPONIN|0.08 ng/mL|1' > evidence/critical_records.expected.txt
cmp evidence/critical_records.expected.txt evidence/critical_records.txt
