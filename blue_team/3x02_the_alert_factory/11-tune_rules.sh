#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

RUNNER="./3-sigma_runner.sh"
EVENTS="$HANDOFF_DIR/data/normalized_events.json"
SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

mkdir -p rules/sigma/tuned
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BASE_START="$(jq -r '.baseline_window.start' "$SUMMARY")"
BASE_END="$(jq -r '.baseline_window.end' "$SUMMARY")"
EVAL_START="$(jq -r '.evaluation_window.start' "$SUMMARY")"
EVAL_END="$(jq -r '.evaluation_window.end' "$SUMMARY")"

REPORT="$TMP/report.jsonl"
TUNED=0
ACCEPTED=0

while read -r rule_id fp_before; do

    rule=""

    for f in rules/sigma/*.yml; do
        [[ "$(yq -r '.id' "$f")" == "$rule_id" ]] && rule="$f"
    done

    [[ -n "$rule" ]] || continue

    name="$(basename "$rule")"
    echo "tuning ${name%.yml}"

    before="$("$RUNNER" "$rule" --window "$BASE_START,$BASE_END")"
    eval_before="$("$RUNNER" "$rule" --window "$EVAL_START,$EVAL_END")"

    jq -r '.matches[].event_ref' <<<"$before" |
    while read -r ref; do
        jq -c --arg ref "$ref" '
            if type == "array" then .[] else . end
            | select(
                ((.event_ref // .record_id // .id // "") | tostring) == $ref
            )
        ' "$EVENTS"
    done > "$TMP/fp_events.jsonl"

    user="$(jq -r '.user // empty' "$TMP/fp_events.jsonl" |
        sort | uniq -c | sort -nr | head -1 | awk '{$1=""; sub(/^ /,""); print}')"

    host="$(jq -r '.hostname // empty' "$TMP/fp_events.jsonl" |
        sort | uniq -c | sort -nr | head -1 | awk '{$1=""; sub(/^ /,""); print}')"

    process="$(jq -r '.process_name // empty' "$TMP/fp_events.jsonl" |
        sort | uniq -c | sort -nr | head -1 | awk '{$1=""; sub(/^ /,""); print}')"

    tuned="rules/sigma/tuned/$name"
    cp "$rule" "$tuned"

    old_condition="$(yq -r '.detection.condition' "$tuned")"
    exclusions=0

    if [[ -n "$user" ]]; then
        USER_VALUE="$user" yq -i \
            '.detection.filter_tune_user.user = strenv(USER_VALUE)' "$tuned"
        exclusions=$((exclusions + 1))
    fi

    if [[ -n "$host" ]]; then
        HOST_VALUE="$host" yq -i \
            '.detection.filter_tune_host.hostname = strenv(HOST_VALUE)' "$tuned"
        exclusions=$((exclusions + 1))
    fi

    if [[ -n "$process" ]]; then
        PROCESS_VALUE="$process" yq -i \
            '.detection.filter_tune_process.process_name = strenv(PROCESS_VALUE)' "$tuned"
        exclusions=$((exclusions + 1))
    fi

    new_condition="($old_condition) and not 1 of filter_tune_*"

    CONDITION="$new_condition" yq -i \
        '.detection.condition = strenv(CONDITION)' "$tuned"

    NEW_ID="$(uuidgen)" yq -i '.id = strenv(NEW_ID)' "$tuned"

    after="$("$RUNNER" "$tuned" --window "$BASE_START,$BASE_END")"
    eval_after="$("$RUNNER" "$tuned" --window "$EVAL_START,$EVAL_END")"

    fp_after="$(jq '.match_count' <<<"$after")"
    tp_before="$(jq '.match_count' <<<"$eval_before")"
    tp_after="$(jq '.match_count' <<<"$eval_after")"

    status="REJECTED"

    if (( fp_after * 2 < fp_before && tp_after >= tp_before )); then
        status="ACCEPTED"
        ACCEPTED=$((ACCEPTED + 1))
    fi

    TUNED=$((TUNED + 1))

    echo "  exclusions added : $exclusions"
    echo "  fp $fp_before -> $fp_after    tp $tp_before -> $tp_after    $status"

    jq -n \
        --arg original "$rule_id" \
        --arg tuned "$(yq -r '.id' "$tuned")" \
        --arg status "$status" \
        --argjson before "$fp_before" \
        --argjson after "$fp_after" \
        --argjson tpb "$tp_before" \
        --argjson tpa "$tp_after" \
        --argjson exclusions "$exclusions" '
        {
          original_rule_id: $original,
          tuned_rule_id: $tuned,
          fp_before: $before,
          fp_after: $after,
          tp_before: $tpb,
          tp_after: $tpa,
          exclusions_added: $exclusions,
          tuning_justification: "Excluded common legitimate baseline values",
          status: $status
        }
    ' >> "$REPORT"

done < <(
    jq -r '.[] | select(.fp_count > 10) | "\(.rule_id) \(.fp_count)"' \
        fp_baseline.json
)

jq -s '.' "$REPORT" > tuning_report.json

echo "$TUNED rules tuned  $ACCEPTED accepted  $((TUNED - ACCEPTED)) rejected"
echo "tuning_report.json written"
