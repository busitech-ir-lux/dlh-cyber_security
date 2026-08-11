#!/bin/bash
#
# Name:        14-pipeline_test.sh
# Purpose:     End-to-end test of the patch pipeline using a simulated CVE feed
# Author:      Mahdi Hamidi
#

set -uo pipefail

readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCENARIO="simulated CVE advisory"
readonly CVE_FEED="${BASE_DIR}/cve_feed.json"
readonly CVE_BACKUP="${BASE_DIR}/cve_feed.json.bak"
readonly SIMULATED_FEED="${BASE_DIR}/cve_feed.simulated.json"
readonly EXPECTED_PLAN="${BASE_DIR}/patch_plan.expected.json"
readonly ACTUAL_PLAN="${BASE_DIR}/patch_plan.json"
readonly PIPELINE="${BASE_DIR}/13-patch_pipeline.sh"
readonly PATCH_EXECUTOR="${BASE_DIR}/4-patch_execute.sh"
readonly PIPELINE_REPORT="${BASE_DIR}/pipeline_run.json"
readonly REPORT_FILE="${BASE_DIR}/pipeline_test_results.json"

STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
FINISHED_AT=""
STAGES_OK=false
PLAN_MATCHES=false
VERDICT="fail"
BACKUP_CREATED=false
RESTORED=false

TMP_EXPECTED=""
TMP_ACTUAL=""
TMP_DIFF=""
TMP_REPORT=""

utc_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

cleanup_temp() {
    local file
    for file in "$TMP_EXPECTED" "$TMP_ACTUAL" "$TMP_DIFF" "$TMP_REPORT"; do
        [[ -n "$file" ]] && rm -f -- "$file" 2>/dev/null || true
    done
}

restore_feed_silent() {
    if [[ "$BACKUP_CREATED" == true && -f "$CVE_BACKUP" ]]; then
        if mv -f -- "$CVE_BACKUP" "$CVE_FEED"; then
            BACKUP_CREATED=false
            RESTORED=true
            return 0
        fi
        return 1
    fi
    return 0
}

on_exit() {
    restore_feed_silent >/dev/null 2>&1 || true
    cleanup_temp
}
trap on_exit EXIT INT TERM

normalize_plan() {
    local input="$1"
    local output="$2"

    # patch_plan.json currently has one volatile timestamp: generated_at.
    # Normalize it in both documents and sort object keys for deterministic diffing.
    jq -S '
        if type == "object" and has("generated_at")
        then .generated_at = "<TIMESTAMP>"
        else .
        end
    ' "$input" > "$output"
}

validate_pipeline_stages() {
    local pipeline_status pipeline_rc="$1"
    local count name status artifact artifact_path
    local ok=true

    [[ "$pipeline_rc" -eq 0 ]] || ok=false
    [[ -s "$PIPELINE_REPORT" ]] || { echo false; return; }
    jq -e . "$PIPELINE_REPORT" >/dev/null 2>&1 || { echo false; return; }

    pipeline_status="$(jq -r '.pipeline_status // ""' "$PIPELINE_REPORT")"
    if [[ "$pipeline_status" != "ok" && "$pipeline_status" != "deferred" ]]; then
        ok=false
    fi

    count="$(jq '.stages | length' "$PIPELINE_REPORT" 2>/dev/null || echo 0)"
    [[ "$count" -eq 9 ]] || ok=false

    while IFS=$'\t' read -r name status artifact; do
        [[ -n "$name" ]] || { ok=false; continue; }

        case "$status" in
            ok|deferred)
                # Every stage that actually ran must have emitted a non-empty,
                # syntactically valid JSON artifact.
                [[ -n "$artifact" ]] || { ok=false; continue; }
                artifact_path="${BASE_DIR}/${artifact}"
                if [[ ! -s "$artifact_path" ]] || ! jq -e . "$artifact_path" >/dev/null 2>&1; then
                    ok=false
                fi
                ;;
            skipped)
                # Deferred pipelines are allowed to skip execute/validate/drift.
                if [[ "$pipeline_status" != "deferred" ]]; then
                    ok=false
                fi
                case "$name" in
                    4-patch_execute.sh|5-post_patch_validate.sh|6-config_drift.sh) ;;
                    *) ok=false ;;
                esac
                ;;
            *)
                ok=false
                ;;
        esac
    done < <(jq -r '.stages[] | [.name, .status, (.artifact // "")] | @tsv' "$PIPELINE_REPORT" 2>/dev/null)

    echo "$ok"
}

write_results() {
    local diff_json='[]'

    FINISHED_AT="$(utc_now)"

    if [[ -n "$TMP_DIFF" && -f "$TMP_DIFF" ]]; then
        diff_json="$(jq -Rsc 'split("\n") | map(select(length > 0))' "$TMP_DIFF")"
    fi

    TMP_REPORT="$(mktemp "${BASE_DIR}/.pipeline-test-report.XXXXXX")"

    jq -n \
        --arg scenario "$SCENARIO" \
        --arg started "$STARTED_AT" \
        --arg finished "$FINISHED_AT" \
        --argjson stages_ok "$STAGES_OK" \
        --argjson plan_matches "$PLAN_MATCHES" \
        --argjson diff "$diff_json" \
        --arg verdict "$VERDICT" \
        '{
            scenario: $scenario,
            started_at: $started,
            finished_at: $finished,
            stages_ok: $stages_ok,
            plan_matches_expected: $plan_matches,
            diff: $diff,
            verdict: $verdict
        }' > "$TMP_REPORT"

    mv -f -- "$TMP_REPORT" "$REPORT_FILE"
    TMP_REPORT=""
}

fail_preflight() {
    local message="$1"
    echo "[!] $message" >&2
    VERDICT="fail"
    write_results
    echo "VERDICT: fail"
    echo "Report saved to: $(basename "$REPORT_FILE")"
    exit 1
}

main() {
    local cmd pipeline_rc diff_rc
    local prerequisites_ok=true

    echo "[*] Scenario: ${SCENARIO}"

    for cmd in jq diff cp mv mktemp date grep; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[!] Missing required command: $cmd" >&2
            prerequisites_ok=false
        fi
    done
    [[ "$prerequisites_ok" == true ]] || fail_preflight "Prerequisite check failed"

    [[ -f "$CVE_FEED" ]] || fail_preflight "Missing cve_feed.json"
    [[ -s "$SIMULATED_FEED" ]] || fail_preflight "Missing or empty cve_feed.simulated.json"
    [[ -s "$EXPECTED_PLAN" ]] || fail_preflight "Missing or empty patch_plan.expected.json"
    [[ -f "$PIPELINE" ]] || fail_preflight "Missing 13-patch_pipeline.sh"
    [[ -f "$PATCH_EXECUTOR" ]] || fail_preflight "Missing 4-patch_execute.sh"

    # Safety gate: never start the test unless the pipeline forwards --dry-run
    # and the executor explicitly implements dry-run handling.
    if ! grep -q 'PIPELINE_TEST' "$PIPELINE" || ! grep -q -- '--dry-run' "$PIPELINE"; then
        fail_preflight "13-patch_pipeline.sh does not forward --dry-run when PIPELINE_TEST=1"
    fi
    if ! grep -q 'DRY_RUN' "$PATCH_EXECUTOR" || ! grep -q -- '--dry-run' "$PATCH_EXECUTOR"; then
        fail_preflight "4-patch_execute.sh does not implement --dry-run; refusing a potentially destructive test"
    fi

    jq -e . "$CVE_FEED" >/dev/null 2>&1 || fail_preflight "cve_feed.json is invalid JSON"
    jq -e . "$SIMULATED_FEED" >/dev/null 2>&1 || fail_preflight "cve_feed.simulated.json is invalid JSON"
    jq -e . "$EXPECTED_PLAN" >/dev/null 2>&1 || fail_preflight "patch_plan.expected.json is invalid JSON"

    printf '%-48s' "[*] Backing up cve_feed.json..."
    if cp -p -- "$CVE_FEED" "$CVE_BACKUP"; then
        BACKUP_CREATED=true
        echo "OK"
    else
        echo "FAILED"
        fail_preflight "Could not back up cve_feed.json"
    fi

    printf '%-48s' "[*] Injecting cve_feed.simulated.json..."
    if cp -- "$SIMULATED_FEED" "$CVE_FEED"; then
        echo "OK"
    else
        echo "FAILED"
        fail_preflight "Could not inject simulated CVE feed"
    fi

    echo "[*] Running pipeline (PIPELINE_TEST=1)..."
    PIPELINE_TEST=1 bash "$PIPELINE"
    pipeline_rc=$?

    STAGES_OK="$(validate_pipeline_stages "$pipeline_rc")"

    TMP_EXPECTED="$(mktemp "${BASE_DIR}/.patch-plan-expected.XXXXXX")"
    TMP_ACTUAL="$(mktemp "${BASE_DIR}/.patch-plan-actual.XXXXXX")"
    TMP_DIFF="$(mktemp "${BASE_DIR}/.patch-plan-diff.XXXXXX")"

    printf '%-48s' "[*] Comparing patch_plan.json to expected..."
    if [[ -s "$ACTUAL_PLAN" ]] && jq -e . "$ACTUAL_PLAN" >/dev/null 2>&1 && \
       normalize_plan "$EXPECTED_PLAN" "$TMP_EXPECTED" && \
       normalize_plan "$ACTUAL_PLAN" "$TMP_ACTUAL"; then
        diff -u \
            --label patch_plan.expected.json \
            --label patch_plan.json \
            "$TMP_EXPECTED" "$TMP_ACTUAL" > "$TMP_DIFF"
        diff_rc=$?

        if [[ "$diff_rc" -eq 0 ]]; then
            PLAN_MATCHES=true
            echo "match"
        else
            PLAN_MATCHES=false
            echo "DIFFERENT"
        fi
    else
        PLAN_MATCHES=false
        printf '%s\n' \
            '--- patch_plan.expected.json' \
            '+++ patch_plan.json' \
            '@@ comparison failed @@' \
            '-expected and actual plans could not both be normalized' \
            > "$TMP_DIFF"
        echo "FAILED"
    fi

    printf '%-48s' "[*] Restoring cve_feed.json..."
    if restore_feed_silent; then
        echo "OK"
    else
        echo "FAILED"
        RESTORED=false
    fi

    if [[ "$STAGES_OK" == true && "$PLAN_MATCHES" == true && "$RESTORED" == true ]]; then
        VERDICT="pass"
    else
        VERDICT="fail"
    fi

    write_results

    echo "VERDICT: ${VERDICT}"
    echo "Report saved to: $(basename "$REPORT_FILE")"

    if [[ "$VERDICT" == "pass" ]]; then
        exit 0
    fi
    exit 1
}

main "$@"
