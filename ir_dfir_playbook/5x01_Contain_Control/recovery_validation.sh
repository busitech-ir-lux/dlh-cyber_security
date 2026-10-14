#!/bin/bash
# MedDefense Task 7: Recovery validation
# Start the mock API: cd mock_validation_api && python3 -m http.server 8080 --bind 127.0.0.1
# Usage: ./recovery_validation.sh
# Optional: API_BASE=http://127.0.0.1:8080 EVIDENCE_ROOT=/evidence ./recovery_validation.sh

API_BASE="${API_BASE:-http://127.0.0.1:8080}"
INCIDENT_ID="IR-2026-0414-01"
STORE="${EVIDENCE_ROOT:-/evidence}/$INCIDENT_ID"
HOSTS=(WST-WS-031 WST-WS-017 LIS-WSIDE-01)
failures=()

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; failures+=("$1"); }

# Fetch JSON from the mock static server. It serves actual *.json filenames.
get_json() {
    local response
    response=$(curl -fsS --connect-timeout 3 --max-time 10 "$API_BASE/$1.json" 2>/dev/null) || return 1
    printf '%s\n' "$response" | jq -e '.status == "ok" and (.data | type == "object")' >/dev/null 2>&1 || return 1
    printf '%s\n' "$response"
}

# 1. Suspicious process lineage must be absent on all affected hosts.
process_ok=true
for host in "${HOSTS[@]}"; do
    json=$(get_json "endpoint/processtree/$host") || { process_ok=false; continue; }
    echo "$json" | jq -e --arg host "$host" \
        '.data.host == $host and .data.window_hours == 24 and
         .data.process_trees_matching.powershell_parent_msbuild_child == 0' >/dev/null || process_ok=false
done
if "$process_ok"; then
    pass "process tree: no PowerShell -> MSBuild on all three hosts (24h)"
else
    fail "process tree: suspicious lineage, missing host, or API error"
fi

# 2. No outbound traffic to either known C2 address; firewall deny also verified.
json=$(get_json "siem/netflow")
if [[ -n "$json" ]] && echo "$json" | jq -e '
    .data.window_hours == 24 and
    (.data.egress_deny_verified | index("185.220.101.47") != null) and
    (.data.egress_deny_verified | index("91.234.99.107") != null) and
    .data.connections_to_185_220_101_47.packets == 0 and
    .data.connections_to_185_220_101_47.bytes == 0 and
    .data.connections_to_91_234_99_107.packets == 0 and
    .data.connections_to_91_234_99_107.bytes == 0' >/dev/null; then
    pass "netflow: both C2 IPs blocked; zero packets and bytes (24h)"
else
    fail "netflow: outbound traffic, missing deny, or API error"
fi

# 3. No scheduled tasks, Run key entries or remaining dropped files.
persistence_ok=true
for host in "${HOSTS[@]}"; do
    json=$(get_json "endpoint/persistence/$host") || { persistence_ok=false; continue; }
    echo "$json" | jq -e --arg host "$host" '
        .data.host == $host and
        (.data.scheduled_tasks_with_guid_names | type == "array" and length == 0) and
        (.data.run_keys | type == "object" and length > 0 and all(.[]; type == "array" and length == 0)) and
        (.data.temp_dropped_payloads | type == "object" and all(.[]; . == "absent"))' >/dev/null || persistence_ok=false
done
if "$persistence_ok"; then
    pass "persistence: tasks, Run keys and dropped payloads clean on all hosts"
else
    fail "persistence: artifact found, missing data, or API error"
fi

# 4. The mock README specifies HTTP 200 + body OK (local HTTP, not TLS).
service_ok=true
for service in epic-api lis-api; do
    response=$(curl -sS --connect-timeout 3 --max-time 10 -w '\n%{http_code}' \
        "$API_BASE/service/$service/health" 2>/dev/null) || { service_ok=false; continue; }
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    body=$(printf "%s" "$body" | tr -d "\r\n")
    [[ "$code" == "200" && "$body" == "OK" ]] || service_ok=false
done
if "$service_ok"; then
    pass "service health: Epic and LIS returned HTTP 200 and OK"
else
    fail "service health: Epic or LIS unavailable or unhealthy"
fi

# 5. Rule must be enabled and a synthetic event must match it.
rule=$(get_json "siem/detection/wz-edr-100041")
test_hit=$(get_json "siem/detection/wz-edr-100041/synthetic")
if [[ -n "$rule" && -n "$test_hit" ]] && \
   echo "$rule" | jq -e '.data.rule_id == "wz-edr-100041" and .data.enabled == true' >/dev/null && \
   echo "$test_hit" | jq -e '.data.rule_id == "wz-edr-100041" and .data.synthetic_matched == true and (.data.synthetic_hit_at | type == "string" and length > 0)' >/dev/null; then
    hit_time=$(echo "$test_hit" | jq -r '.data.synthetic_hit_at')
    pass "detection: rule enabled; synthetic event matched at $hit_time"
else
    fail "detection: rule disabled, synthetic hit missing, or API error"
fi

# 6. Verify captured evidence against the append-only SHA-256 manifest.
# The initializer creates hashes.txt; the task may also create a named snapshot.
manifest="$STORE/hashes.txt"
[[ -f "$manifest" ]] || manifest="$STORE/$INCIDENT_ID-hashes.txt"
if [[ ! -f "$manifest" ]]; then
    fail "evidence hashes: no SHA-256 manifest found at $STORE"
else
    count=$(grep -Ec '^[[:xdigit:]]{64}  ' "$manifest" || true)
    if [[ "$count" -eq 0 ]]; then
        fail "evidence hashes: manifest contains no recorded artifacts"
    elif (cd "$STORE" && sha256sum --check --status "$(basename "$manifest")") 2>/dev/null; then
        pass "evidence hashes: $count/$count recorded SHA-256 values match"
    else
        fail "evidence hashes: missing or modified artifacts (of $count records)"
    fi
fi

# Every check must pass, or exit non-zero.
if [[ ${#failures[@]} -eq 0 ]]; then
    echo "ALL CHECKS PASSED"
    exit 0
fi
printf 'FAILED %s CHECK(S): ' "${#failures[@]}"
(IFS='; '; echo "${failures[*]}")
exit 1
