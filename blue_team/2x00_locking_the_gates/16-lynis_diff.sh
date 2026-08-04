#!/bin/bash

# 16-lynis_diff.sh - Compare baseline and post-hardening Lynis findings
#
# Reads:
#   lynis_findings.json
#   lynis_post_findings.json
#
# Creates:
#   hardening_improvement.json
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BEFORE_FILE="$SCRIPT_DIR/lynis_findings.json"
AFTER_FILE="$SCRIPT_DIR/lynis_post_findings.json"
REPORT_FILE="$SCRIPT_DIR/hardening_improvement.json"

LYNIS_REPORT="/var/log/lynis-report.dat"
PARSER="$SCRIPT_DIR/2-lynis_parse.sh"


# Check required files

if [[ ! -f "$BEFORE_FILE" ]]; then
    echo "Missing file: lynis_findings.json"
    exit 1
fi

if [[ ! -f "$AFTER_FILE" ]]; then
    echo "[*] Post-hardening file not found. Running Lynis..."

    lynis audit system --quick >/dev/null 2>&1

    bash "$PARSER" "$LYNIS_REPORT" > "$AFTER_FILE"
fi


# Read scores

BEFORE_SCORE=$(jq -r '.hardening_index // .score // 0' "$BEFORE_FILE")
AFTER_SCORE=$(jq -r '.hardening_index // .score // 0' "$AFTER_FILE")

DELTA=$((AFTER_SCORE - BEFORE_SCORE))


# Read findings

BEFORE_FINDINGS=$(jq -c '
    [
        (.warnings // [])[],
        (.suggestions // [])[],
        (.manual_checks // [])[]
    ]
    | unique
' "$BEFORE_FILE")

AFTER_FINDINGS=$(jq -c '
    [
        (.warnings // [])[],
        (.suggestions // [])[],
        (.manual_checks // [])[]
    ]
    | unique
' "$AFTER_FILE")


# Compare findings

RESOLVED_FINDINGS=$(jq -n \
    --argjson before "$BEFORE_FINDINGS" \
    --argjson after "$AFTER_FINDINGS" \
    '[$before[] | select($after | index(.) | not)]')

REMAINING_FINDINGS=$(jq -n \
    --argjson before "$BEFORE_FINDINGS" \
    --argjson after "$AFTER_FINDINGS" \
    '[$before[] | select($after | index(.) != null)]')

NEW_FINDINGS=$(jq -n \
    --argjson before "$BEFORE_FINDINGS" \
    --argjson after "$AFTER_FINDINGS" \
    '[$after[] | select($before | index(.) | not)]')


# Count findings

RESOLVED_COUNT=$(jq 'length' <<< "$RESOLVED_FINDINGS")
REMAINING_COUNT=$(jq 'length' <<< "$REMAINING_FINDINGS")
NEW_COUNT=$(jq 'length' <<< "$NEW_FINDINGS")


# Residual risk summary

if [[ "$REMAINING_COUNT" -eq 0 && "$NEW_COUNT" -eq 0 ]]; then
    RISK_SUMMARY="No residual Lynis findings remain."
elif [[ "$NEW_COUNT" -gt 0 ]]; then
    RISK_SUMMARY="$REMAINING_COUNT findings remain and $NEW_COUNT new findings require review."
else
    RISK_SUMMARY="$REMAINING_COUNT findings remain after hardening."
fi


# Write final report

jq -n \
    --argjson before_score "$BEFORE_SCORE" \
    --argjson after_score "$AFTER_SCORE" \
    --argjson delta "$DELTA" \
    --argjson resolved_findings "$RESOLVED_FINDINGS" \
    --argjson remaining_findings "$REMAINING_FINDINGS" \
    --argjson new_findings "$NEW_FINDINGS" \
    --argjson resolved_count "$RESOLVED_COUNT" \
    --argjson remaining_count "$REMAINING_COUNT" \
    --argjson new_count "$NEW_COUNT" \
    --arg residual_risk_summary "$RISK_SUMMARY" \
    '{
        before_score: $before_score,
        after_score: $after_score,
        delta: $delta,
        resolved_findings: $resolved_findings,
        remaining_findings: $remaining_findings,
        new_findings: $new_findings,
        resolved_count: $resolved_count,
        remaining_count: $remaining_count,
        new_count: $new_count,
        residual_risk_summary: $residual_risk_summary
    }' > "$REPORT_FILE"


# Display summary

echo "Before: $BEFORE_SCORE"
echo "After: $AFTER_SCORE"

if [[ "$DELTA" -ge 0 ]]; then
    echo "Delta: +$DELTA"
else
    echo "Delta: $DELTA"
fi

echo "Findings resolved: $RESOLVED_COUNT"
echo "Findings remaining: $REMAINING_COUNT"
echo "New findings: $NEW_COUNT"
echo "Report saved to: hardening_improvement.json"
