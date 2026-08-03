#!/bin/bash

hardening_index=$(grep  -m1 "^hardening" "$1" | cut -d'=' -f2)
findings=$(grep -E "^(warning\[\]|suggestion\[\]|manual_check|manual_control\[\])" /var/log/lynis-report.dat | while IFS="=" read -r key value; do
severity=$(echo "$key" | cut -d'[' -f1)
test_id=$(echo $value | cut -d'|' -f1)
message=$(echo $value | cut -d'|' -f2)

jq -n \
--arg severity "$severity" \
--arg test_id "$test_id" \
--arg message "$message" \
'{
	severity: $severity,
	test_id: $test_id,
	message: $message
}'
done | jq -s '.')

jq -n \
--arg hardening_index "$hardening_index" \
--argjson findings "$findings" \
'{
	hardening_index: $hardening_index,
	findings: $findings
}'
