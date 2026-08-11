#!/bin/bash
#
# Name:        13-patch_pipeline.sh
# Purpose:     Orchestrate the complete MedDefense patch workflow
# Author: Mahdi Hamidi
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPORT_FILE="${BASE_DIR}/pipeline_run.json"
readonly TOTAL_STAGES=9

readonly -a STAGE_NAMES=(
    "0-vuln_inventory.sh"
    "1-service_deps.sh"
    "2-pre_patch_snapshot.sh"
    "3-patch_plan.sh"
    "11-maintenance_window.sh"
    "4-patch_execute.sh"
    "5-post_patch_validate.sh"
    "6-config_drift.sh"
    "12-change_log.sh"
)

readonly -a ARTIFACT_NAMES=(
    "vulnerability_inventory.json"
    "service_dependency_map.json"
    "pre_patch_state.json"
    "patch_plan.json"
    "maintenance_window.json"
    "patch_execution_log.json"
    "post_patch_validation.json"
    "config_drift.json"
    "patch_change_log.json"
)

STAGES_NDJSON="$(mktemp "${BASE_DIR}/.pipeline-stages.XXXXXX")"
TMP_FILES=("$STAGES_NDJSON")

cleanup() {
    local f
    for f in "${TMP_FILES[@]:-}"; do
        [[ -n "$f" ]] && rm -f -- "$f" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

utc_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

now_ns() {
    date +%s%N
}

seconds_between() {
    local start_ns="$1"
    local end_ns="$2"
    awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.3f", (e-s)/1000000000 }'
}

require_prerequisites() {
    local missing=0
    local cmd

    for cmd in jq awk date hostname mktemp cmp cp mv; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "ERROR: missing required command: $cmd" >&2
            missing=1
        fi
    done

    local stage
    for stage in "${STAGE_NAMES[@]}"; do
        if [[ ! -f "${BASE_DIR}/${stage}" ]]; then
            echo "ERROR: missing stage script: ${BASE_DIR}/${stage}" >&2
            missing=1
        fi
    done

    [[ "$missing" -eq 0 ]]
}

# Normalize only volatile run metadata.  If the measured state is otherwise
# identical, the previous artifact is restored byte-for-byte (including mtime).
normalized_json() {
    local stage="$1"
    local file="$2"

    case "$stage" in
        "0-vuln_inventory.sh"|"1-service_deps.sh"|"3-patch_plan.sh"|"5-post_patch_validate.sh")
            jq -S 'del(.generated_at)' "$file"
            ;;
        "2-pre_patch_snapshot.sh")
            jq -S 'del(.timestamp)' "$file"
            ;;
        "11-maintenance_window.sh")
            jq -S '
                del(.now, .now_display, .seconds_until_next)
                | if (.next_window? | type) == "object"
                  then .next_window |= del(.at)
                  else .
                  end
            ' "$file"
            ;;
        "4-patch_execute.sh")
            jq -S 'del(.started_at, .finished_at)' "$file"
            ;;
        *)
            jq -S '.' "$file"
            ;;
    esac
}

restore_if_semantically_unchanged() {
    local stage="$1"
    local previous="$2"
    local current="$3"

    [[ -n "$previous" && -f "$previous" && -f "$current" ]] || return 0
    jq -e . "$previous" >/dev/null 2>&1 || return 0
    jq -e . "$current"  >/dev/null 2>&1 || return 0

    local old_norm new_norm
    old_norm="$(mktemp "${BASE_DIR}/.pipeline-oldnorm.XXXXXX")"
    new_norm="$(mktemp "${BASE_DIR}/.pipeline-newnorm.XXXXXX")"
    TMP_FILES+=("$old_norm" "$new_norm")

    normalized_json "$stage" "$previous" > "$old_norm"
    normalized_json "$stage" "$current"  > "$new_norm"

    if cmp -s -- "$old_norm" "$new_norm"; then
        mv -f -- "$previous" "$current"
        return 0
    fi

    rm -f -- "$previous"
}

append_stderr() {
    local file="$1"
    shift
    printf '%s\n' "$*" >> "$file"
}

# Globals populated by execute_stage.
RUN_RC=0
RUN_DURATION="0.000"
RUN_STDOUT=""
RUN_STDERR=""
RUN_BACKUP=""

execute_stage() {
    local stage="$1"
    local artifact="$2"
    shift 2

    local script_path="${BASE_DIR}/${stage}"
    local artifact_path="${BASE_DIR}/${artifact}"
    local stdout_file stderr_file backup_file=""
    local start_ns end_ns rc

    stdout_file="$(mktemp "${BASE_DIR}/.pipeline-stdout.XXXXXX")"
    stderr_file="$(mktemp "${BASE_DIR}/.pipeline-stderr.XXXXXX")"
    TMP_FILES+=("$stdout_file" "$stderr_file")

    if [[ -f "$artifact_path" ]]; then
        backup_file="$(mktemp "${BASE_DIR}/.pipeline-artifact.XXXXXX")"
        cp -p -- "$artifact_path" "$backup_file"
        TMP_FILES+=("$backup_file")
    fi

    start_ns="$(now_ns)"
    set +e
    bash "$script_path" "$@" >"$stdout_file" 2>"$stderr_file"
    rc=$?
    set -e
    end_ns="$(now_ns)"

    # A successful/special-decision stage still has to emit valid JSON.
    if [[ "$rc" -eq 0 || ( "$stage" == "11-maintenance_window.sh" && "$rc" -eq 20 ) ]]; then
        if [[ ! -s "$artifact_path" ]]; then
            append_stderr "$stderr_file" "ERROR: expected artifact was not created: $artifact_path"
            rc=1
        elif ! jq -e . "$artifact_path" >/dev/null 2>&1; then
            append_stderr "$stderr_file" "ERROR: stage emitted invalid JSON: $artifact_path"
            rc=1
        fi
    fi

    RUN_RC="$rc"
    RUN_DURATION="$(seconds_between "$start_ns" "$end_ns")"
    RUN_STDOUT="$stdout_file"
    RUN_STDERR="$stderr_file"
    RUN_BACKUP="$backup_file"
}

record_stage() {
    local stage="$1"
    local artifact="$2"
    local status="$3"
    local exit_code="$4"
    local duration="$5"
    local stdout_file="$6"
    local stderr_file="$7"
    local command="$8"

    if [[ "$exit_code" == "null" ]]; then
        jq -nc \
            --arg name "$stage" \
            --arg command "$command" \
            --arg status "$status" \
            --arg artifact "$artifact" \
            --argjson duration "$duration" \
            --rawfile stdout "$stdout_file" \
            --rawfile stderr "$stderr_file" \
            '{name:$name,command:$command,status:$status,stdout:$stdout,stderr:$stderr,exit_code:null,duration_seconds:$duration,artifact:$artifact}' \
            >> "$STAGES_NDJSON"
    else
        jq -nc \
            --arg name "$stage" \
            --arg command "$command" \
            --arg status "$status" \
            --arg artifact "$artifact" \
            --argjson rc "$exit_code" \
            --argjson duration "$duration" \
            --rawfile stdout "$stdout_file" \
            --rawfile stderr "$stderr_file" \
            '{name:$name,command:$command,status:$status,stdout:$stdout,stderr:$stderr,exit_code:$rc,duration_seconds:$duration,artifact:$artifact}' \
            >> "$STAGES_NDJSON"
    fi
}

record_not_run() {
    local stage="$1"
    local artifact="$2"
    local status="$3"
    local reason="$4"
    local empty_out empty_err command

    empty_out="$(mktemp "${BASE_DIR}/.pipeline-emptyout.XXXXXX")"
    empty_err="$(mktemp "${BASE_DIR}/.pipeline-emptyerr.XXXXXX")"
    TMP_FILES+=("$empty_out" "$empty_err")
    : > "$empty_out"
    printf '%s\n' "$reason" > "$empty_err"

    command="./${stage}"
    [[ "$stage" == "11-maintenance_window.sh" ]] && command="./${stage} --check"

    record_stage "$stage" "$artifact" "$status" "null" "0" "$empty_out" "$empty_err" "$command"
}

stage_detail() {
    local stage="$1"
    local artifact_path="$2"

    case "$stage" in
        "11-maintenance_window.sh")
            jq -r 'if .active_window then (.active_window + " window active") else (.decision // "window checked") end' "$artifact_path" 2>/dev/null || true
            ;;
        "4-patch_execute.sh")
            jq -r '((.summary.succeeded // ([.entries[]? | select(.status == "success")] | length)) | tostring) + " packages"' "$artifact_path" 2>/dev/null || true
            ;;
        "5-post_patch_validate.sh")
            jq -r '(.passed|tostring) + "/" + (.total_checks|tostring) + " checks"' "$artifact_path" 2>/dev/null || true
            ;;
        "6-config_drift.sh")
            jq -r 'if (.summary.unexpected_drift // 0) == 0 then "no unexpected drift" else ((.summary.unexpected_drift|tostring) + " unexpected drift") end' "$artifact_path" 2>/dev/null || true
            ;;
        "12-change_log.sh")
            jq -r '(.summary.total_events // 0 | tostring) + " events"' "$artifact_path" 2>/dev/null || true
            ;;
        *)
            true
            ;;
    esac
}

write_report() {
    local started_at="$1"
    local finished_at="$2"
    local hostname_value="$3"
    local pipeline_status="$4"
    local temp_report

    temp_report="$(mktemp "${BASE_DIR}/.pipeline-report.XXXXXX")"
    TMP_FILES+=("$temp_report")

    jq -n \
        --arg started "$started_at" \
        --arg finished "$finished_at" \
        --arg hostname "$hostname_value" \
        --arg status "$pipeline_status" \
        --slurpfile stages "$STAGES_NDJSON" \
        '{
            started_at: $started,
            finished_at: $finished,
            hostname: $hostname,
            pipeline_status: $status,
            stages: $stages,
            artifacts: {
                "0-vuln_inventory.sh": "vulnerability_inventory.json",
                "1-service_deps.sh": "service_dependency_map.json",
                "2-pre_patch_snapshot.sh": "pre_patch_state.json",
                "3-patch_plan.sh": "patch_plan.json",
                "11-maintenance_window.sh": "maintenance_window.json",
                "4-patch_execute.sh": "patch_execution_log.json",
                "5-post_patch_validate.sh": "post_patch_validation.json",
                "6-config_drift.sh": "config_drift.json",
                "12-change_log.sh": "patch_change_log.json"
            }
        }' > "$temp_report"

    # Atomic replacement; if the complete report is byte-identical, keep mtime.
    if [[ -f "$REPORT_FILE" ]] && cmp -s -- "$temp_report" "$REPORT_FILE"; then
        rm -f -- "$temp_report"
    else
        mv -f -- "$temp_report" "$REPORT_FILE"
    fi
}

main() {
    local pipeline_start_ns pipeline_end_ns started_at finished_at hostname_value
    local pipeline_status="ok"
    local deferred=false
    local failed=false
    local failed_index=-1
    local i stage artifact artifact_path command logical_status detail

    pipeline_start_ns="$(now_ns)"
    started_at="$(utc_now)"
    hostname_value="$(hostname 2>/dev/null || echo unknown)"

    if ! require_prerequisites; then
        pipeline_status="failed"
        # Preserve the required nine-stage ordered array even when preflight fails.
        for i in "${!STAGE_NAMES[@]}"; do
            record_not_run "${STAGE_NAMES[$i]}" "${ARTIFACT_NAMES[$i]}" "not_run" "pipeline preflight failed"
        done
        finished_at="$(utc_now)"
        write_report "$started_at" "$finished_at" "$hostname_value" "$pipeline_status"
        echo "PIPELINE: failed"
        echo "Report saved to: $(basename "$REPORT_FILE")"
        exit 1
    fi

    for i in "${!STAGE_NAMES[@]}"; do
        stage="${STAGE_NAMES[$i]}"
        artifact="${ARTIFACT_NAMES[$i]}"
        artifact_path="${BASE_DIR}/${artifact}"
        command="./${stage}"

        # A deferred pipeline still runs the change-log stage, but must not
        # execute/validate/drift-check a patch that was intentionally not run.
        if [[ "$deferred" == true && ( "$stage" == "4-patch_execute.sh" || "$stage" == "5-post_patch_validate.sh" || "$stage" == "6-config_drift.sh" ) ]]; then
            record_not_run "$stage" "$artifact" "skipped" "skipped because maintenance window deferred patching"
            printf '[%d/%d] %-30s %s\n' "$((i+1))" "$TOTAL_STAGES" "$stage" "SKIPPED (pipeline deferred)"
            continue
        fi

        if [[ "$stage" == "11-maintenance_window.sh" ]]; then
            command="./${stage} --check"
            execute_stage "$stage" "$artifact" --check
        else
            execute_stage "$stage" "$artifact"
        fi

        logical_status="ok"

        if [[ "$stage" == "11-maintenance_window.sh" && "$RUN_RC" -eq 20 && -z "${MEDDEFENSE_EMERGENCY+x}" ]]; then
            logical_status="deferred"
            pipeline_status="deferred"
            deferred=true
        elif [[ "$RUN_RC" -ne 0 ]]; then
            logical_status="failed"
            pipeline_status="failed"
            failed=true
            failed_index="$i"
        fi

        # Preserve old JSON byte-for-byte when only volatile metadata changed.
        if [[ "$logical_status" == "ok" || "$logical_status" == "deferred" ]]; then
            restore_if_semantically_unchanged "$stage" "$RUN_BACKUP" "$artifact_path"
        elif [[ -n "$RUN_BACKUP" ]]; then
            rm -f -- "$RUN_BACKUP"
        fi

        record_stage "$stage" "$artifact" "$logical_status" "$RUN_RC" "$RUN_DURATION" "$RUN_STDOUT" "$RUN_STDERR" "$command"

        if [[ "$logical_status" == "deferred" ]]; then
            printf '[%d/%d] %-30s %s\n' "$((i+1))" "$TOTAL_STAGES" "$stage" "DEFERRED (outside maintenance window)"
        elif [[ "$logical_status" == "failed" ]]; then
            printf '[%d/%d] %-30s %s\n' "$((i+1))" "$TOTAL_STAGES" "$stage" "FAILED (exit ${RUN_RC}, ${RUN_DURATION}s)"
            if [[ -s "$RUN_STDERR" ]]; then
                tail -20 "$RUN_STDERR" >&2 || true
            fi
            break
        else
            detail="$(stage_detail "$stage" "$artifact_path")"
            if [[ -n "$detail" ]]; then
                printf '[%d/%d] %-30s OK  (%s, %ss)\n' "$((i+1))" "$TOTAL_STAGES" "$stage" "$detail" "$RUN_DURATION"
            else
                printf '[%d/%d] %-30s OK  (%ss)\n' "$((i+1))" "$TOTAL_STAGES" "$stage" "$RUN_DURATION"
            fi
        fi
    done

    # If a real failure stopped the pipeline, make the unexecuted remainder explicit.
    if [[ "$failed" == true ]]; then
        for ((i=failed_index+1; i<TOTAL_STAGES; i++)); do
            record_not_run "${STAGE_NAMES[$i]}" "${ARTIFACT_NAMES[$i]}" "not_run" "not run because a previous stage failed"
        done
    fi

    finished_at="$(utc_now)"
    pipeline_end_ns="$(now_ns)"
    write_report "$started_at" "$finished_at" "$hostname_value" "$pipeline_status"

    echo "PIPELINE: ${pipeline_status}"
    echo "Duration: $(seconds_between "$pipeline_start_ns" "$pipeline_end_ns")s"
    echo "Report saved to: $(basename "$REPORT_FILE")"

    if [[ "$pipeline_status" == "failed" ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
