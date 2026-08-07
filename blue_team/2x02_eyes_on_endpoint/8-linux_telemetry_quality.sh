#!/bin/bash

# name: 8-linux_telemetry_quality.sh
# purpose: Check completeness and quality of exported Linux telemetry.
# author: Mahdi Hamidi

set -e
set -u
set -o pipefail

INPUT="linux_events_export.json"
OUTPUT="linux_telemetry_quality.json"

echo "[*] Analyzing $INPUT..."

if [ ! -f "$INPUT" ]; then
    echo "[ERROR] $INPUT not found."
    exit 1
fi

total=$(jq 'length' "$INPUT")

# -----------------------------
# Event distribution
# -----------------------------

category_distribution=$(jq '
    group_by(.event_category) |
    map({
        event_category: .[0].event_category,
        count: length
    })' "$INPUT")

source_distribution=$(jq '
    group_by(.source_type) |
    map({
        source_type: .[0].source_type,
        count: length
    })' "$INPUT")


# -----------------------------
# Time coverage
# -----------------------------

events_per_hour=$(jq '
    group_by(.timestamp[0:13]) |
    map({
        hour: .[0].timestamp[0:13],
        count: length
    })' "$INPUT")

hours_with=$(echo "$events_per_hour" | jq 'length')
hours_without=$((24 - hours_with))

if [ "$hours_without" -lt 0 ]; then
    hours_without=0
fi


# -----------------------------
# Gap detection (>30 minutes)
# -----------------------------

gaps=$(jq '
    [.[].timestamp | fromdateiso8601] |
    sort |
    [range(1; length) as $i |
        if (.[ $i ] - .[$i-1]) > 1800 then
            {
                gap_minutes: ((.[ $i ] - .[$i-1]) / 60)
            }
        else empty end
    ]' "$INPUT")

gap_count=$(echo "$gaps" | jq 'length')


# -----------------------------
# Field completeness
# -----------------------------

percentage() {
    good="$1"
    all="$2"

    if [ "$all" -eq 0 ]; then
        echo "100"
    else
        awk "BEGIN {printf \"%.1f\", ($good/$all)*100}"
    fi
}

timestamp_good=$(jq '[.[] | select(.timestamp != null and .timestamp != "")] | length' "$INPUT")
hostname_good=$(jq '[.[] | select(.hostname != null and .hostname != "")] | length' "$INPUT")
source_good=$(jq '[.[] | select(.source_type != null and .source_type != "")] | length' "$INPUT")
category_good=$(jq '[.[] | select(.event_category != null and .event_category != "")] | length' "$INPUT")

timestamp_pct=$(percentage "$timestamp_good" "$total")
hostname_pct=$(percentage "$hostname_good" "$total")
source_pct=$(percentage "$source_good" "$total")
category_pct=$(percentage "$category_good" "$total")


# execve command line
exec_total=$(jq '[.[] | select(.event_category=="execve")] | length' "$INPUT")
exec_good=$(jq '[.[] | select(.event_category=="execve" and .command != null and .command != "")] | length' "$INPUT")
exec_pct=$(percentage "$exec_good" "$exec_total")


# SSH source IP and user
ssh_total=$(jq '[.[] | select(.event_category=="ssh_login_success" or .event_category=="ssh_login_failure")] | length' "$INPUT")

ssh_ip_good=$(jq '[.[] |
    select(
        (.event_category=="ssh_login_success" or .event_category=="ssh_login_failure")
        and .source_ip != null
        and .source_ip != ""
    )] | length' "$INPUT")

ssh_user_good=$(jq '[.[] |
    select(
        (.event_category=="ssh_login_success" or .event_category=="ssh_login_failure")
        and .user != null
        and .user != ""
    )] | length' "$INPUT")

ssh_ip_pct=$(percentage "$ssh_ip_good" "$ssh_total")
ssh_user_pct=$(percentage "$ssh_user_good" "$ssh_total")


# auditd file events
file_total=$(jq '[.[] | select(.event_category=="file_access")] | length' "$INPUT")

file_path_good=$(jq '[.[] |
    select(.event_category=="file_access" and .path != null and .path != "")
] | length' "$INPUT")

file_operation_good=$(jq '[.[] |
    select(.event_category=="file_access" and .operation != null and .operation != "")
] | length' "$INPUT")

file_key_good=$(jq '[.[] |
    select(.event_category=="file_access" and .key != null and .key != "")
] | length' "$INPUT")

file_path_pct=$(percentage "$file_path_good" "$file_total")
file_operation_pct=$(percentage "$file_operation_good" "$file_total")
file_key_pct=$(percentage "$file_key_good" "$file_total")


# -----------------------------
# Quality score
# -----------------------------

coverage_pct=$(awk "BEGIN {printf \"%.1f\", ($hours_with/24)*100}")

field_score=$(awk "BEGIN {
    print ($timestamp_pct+$hostname_pct+$source_pct+$category_pct+
           $exec_pct+$ssh_ip_pct+$ssh_user_pct+$file_path_pct+
           $file_operation_pct+$file_key_pct)/10
}")

if [ "$gap_count" -eq 0 ]; then
    gap_score=100
else
    gap_score=70
fi

score=$(awk "BEGIN {
    printf \"%.1f\", ($field_score*0.6)+($coverage_pct*0.3)+($gap_score*0.1)
}")

assessment="poor"

if awk "BEGIN {exit !($score >= 90)}"; then
    assessment="good"
elif awk "BEGIN {exit !($score >= 70)}"; then
    assessment="acceptable"
fi


# -----------------------------
# JSON report
# -----------------------------

jq -n \
    --argjson total "$total" \
    --argjson category_distribution "$category_distribution" \
    --argjson source_distribution "$source_distribution" \
    --argjson events_per_hour "$events_per_hour" \
    --argjson hours_with "$hours_with" \
    --argjson hours_without "$hours_without" \
    --argjson gaps "$gaps" \
    --arg timestamp "$timestamp_pct" \
    --arg hostname "$hostname_pct" \
    --arg source "$source_pct" \
    --arg category "$category_pct" \
    --arg execve "$exec_pct" \
    --arg ssh_ip "$ssh_ip_pct" \
    --arg ssh_user "$ssh_user_pct" \
    --arg file_path "$file_path_pct" \
    --arg file_operation "$file_operation_pct" \
    --arg file_key "$file_key_pct" \
    --arg score "$score" \
    --arg assessment "$assessment" \
'{
    total_events: $total,
    event_distribution: $category_distribution,
    source_distribution: $source_distribution,
    time_coverage: {
        events_per_hour: $events_per_hour,
        hours_with_events: $hours_with,
        hours_without_events: $hours_without
    },
    gaps: $gaps,
    field_completeness: {
        timestamp: $timestamp,
        hostname: $hostname,
        source_type: $source,
        event_category: $category,
        execve_command_line: $execve,
        ssh_source_ip: $ssh_ip,
        ssh_user: $ssh_user,
        auditd_file_path: $file_path,
        auditd_file_operation: $file_operation,
        auditd_file_key: $file_key
    },
    quality_score: $score,
    assessment: $assessment
}' > "$OUTPUT"


echo "Total events: $total"
echo "Hours with events: $hours_with/24"

if [ "$gap_count" -eq 0 ]; then
    echo "No gaps detected"
else
    echo "Gaps over 30 minutes: $gap_count"
fi

echo "execve command_line completeness: $exec_pct%"
echo "SSH source_ip completeness: $ssh_ip_pct%"
echo "auditd file path completeness: $file_path_pct%"
echo "Quality score: $score% ($assessment)"
echo "Report saved to: $OUTPUT"