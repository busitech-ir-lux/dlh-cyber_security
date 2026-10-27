#!/bin/bash
# IR-2026-0420-01 — read-only recovery gate.
# All reports MUST be collected from the live SIEM/EDR, endpoint and firewall systems.
# A missing, malformed, incomplete or stale report is a FAIL, never a PASS.
set -u

REPORT_DIR="${REPORT_DIR:-./recovery_reports}"
FAIL=0
HOSTS='["CS-WS-101","CS-WS-104","CS-WS-107","CS-WS-112","FILE-SVR-01","SCHED-SVR-01"]'

pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=1; }

# Reject an incomplete evidence export or an outdated report (last 5 minutes).
check_report() {
    local name="$1" file="$REPORT_DIR/$1.json" now
    if [ ! -f "$file" ]; then fail "$name: missing $file"; return 1; fi
    if ! jq -e '.' "$file" >/dev/null 2>&1; then fail "$name: invalid JSON"; return 1; fi
    now=$(date -u +%s)
    if ! jq -e --argjson now "$now" '
      (.collected_epoch | type == "number") and
      (.collected_epoch <= $now) and
      (.collected_epoch >= ($now - 300)) and
      (.collection_complete == true)
    ' "$file" >/dev/null; then
        fail "$name: collection timestamp outside five minutes or incomplete"
        return 1
    fi
    return 0
}

# Host reports: one fresh result for every scoped asset (including server).
host_results() {
    local file="$1" expression="$2"
    jq -e --argjson hosts "$HOSTS" "
      (.hosts | type == \"array\") and
      ([.hosts[].host] | sort == (\$hosts | sort)) and
      (all(.hosts[]; $expression))
    " "$file" >/dev/null 2>&1
}

# 1. No malicious process/ancestry in complete 24h EDR telemetry.
# JSON: hosts:[{host,lookback_hours:24,telemetry_complete:true,malicious_matches:0}]
if check_report beacon; then
    if host_results "$REPORT_DIR/beacon.json" '(.lookback_hours >= 24 and .telemetry_complete == true and .malicious_matches == 0)'; then
        pass 'beacon: no malicious process lineage in last 24h on six hosts'
    else fail 'beacon: process history missing or suspicious matches found'; fi
fi

# 2. No successful C2 flows, and firewall denies are implemented.
# JSON: blocked_domain,blocked_ip,firewall_rule_active,hosts:[{host,lookback_hours:24,telemetry_complete:true,successful_c2_flows:0}]
if check_report c2; then
    if jq -e '.blocked_domain == "staging.office365-cdn.net" and .blocked_ip == "45.152.66.114" and .firewall_rule_active == true' "$REPORT_DIR/c2.json" >/dev/null &&
       host_results "$REPORT_DIR/c2.json" '(.lookback_hours >= 24 and .telemetry_complete == true and .successful_c2_flows == 0)'; then
        pass 'c2: no successful C2 egress in last 24h, firewall rule active'
    else fail 'c2: successful flows, ineffective block, or incomplete telemetry'; fi
fi

# 3. Endpoint file scans: inspect System32 and ProgramData recursively.
# JSON: hosts:[{host,scan_complete:true,paths_checked:["C:\\Windows\\System32","C:\\ProgramData"],malicious_scripts:0}]
if check_report staging; then
    if host_results "$REPORT_DIR/staging.json" '(.scan_complete == true and .malicious_scripts == 0 and (.paths_checked | index("C:\\Windows\\System32") != null) and (.paths_checked | index("C:\\ProgramData") != null))'; then
        pass 'staging: all six hosts scanned; no identified ransomware scripts'
    else fail 'staging: detection or incomplete path scan'; fi
fi

# 4. Clinical application health checks; provided by live service monitoring.
# JSON: services:[{name:"epic-api",http_status:200},...] and clinical_owner_approved:true
if check_report services; then
    if jq -e '(.clinical_owner_approved == true) and
      (([.services[] | select(.http_status == 200) | .name] | unique | sort) ==
      (["epic-api","lis-api","scheduling-api"] | sort))' "$REPORT_DIR/services.json" >/dev/null; then
        pass 'services: epic-api, lis-api and scheduling-api HTTP 200; clinical owner approved'
    else fail 'services: unhealthy or not approved'; fi
fi

# 5. EDR telemetry must be fresh from every host (last five minutes).
# JSON: hosts:[{host,online:true,last_seen_epoch:<unix epoch>}]
if check_report edr; then
    now=$(date -u +%s)
    if jq -e --argjson hosts "$HOSTS" --argjson now "$now" '
      ([.hosts[].host] | sort == ($hosts | sort)) and
      (all(.hosts[]; .online == true and (.last_seen_epoch | type == "number") and .last_seen_epoch <= $now and .last_seen_epoch >= ($now - 300)))
    ' "$REPORT_DIR/edr.json" >/dev/null; then
        pass 'edr: all six hosts reporting in the last five minutes'
    else fail 'edr: one or more agents missing/stale'; fi
fi

# 6. Sigma rule is active AND a synthetic detection was observed.
# JSON: rule_file,active,synthetic_test_hit
if check_report detection; then
    if jq -e '.rule_file == "sigma_cobalt_strike_beacon.yml" and .active == true and .synthetic_test_hit == true' "$REPORT_DIR/detection.json" >/dev/null; then
        pass 'detection: new Sigma rule deployed; synthetic test alerted'
    else fail 'detection: rule not active or synthetic test failed'; fi
fi

# 7. All forensic hashes in the case manifest must match their baselines.
# JSON: artifacts:[{id,baseline_sha256,current_sha256}] (baseline must be independently recorded).
if check_report evidence; then
    if jq -e '(.artifacts | type == "array" and length >= 1) and
      (all(.artifacts[]; (.baseline_sha256 | test("^[0-9a-fA-F]{64}$")) and .current_sha256 == .baseline_sha256)) and
      .manifest_complete == true' "$REPORT_DIR/evidence.json" >/dev/null; then
        pass 'evidence: all case-manifest artifact hashes match independent baselines'
    else fail 'evidence: baseline missing, mismatch or incomplete manifest'; fi
fi

if [ "$FAIL" -eq 0 ]; then
    echo 'ALL CHECKS PASSED'
    exit 0
fi
echo 'RECOVERY NOT VALIDATED'
exit 1
