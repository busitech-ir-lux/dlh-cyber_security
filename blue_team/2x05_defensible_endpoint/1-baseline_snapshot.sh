#!/bin/bash
#
# 1-baseline_snapshot.sh - Hawthorne capstone, Task 1 (Linux side)
#
# Runs a Lynis audit against hawthorne-app-01, persists the raw log and
# extracts the Hardening Index. That index is the denominator for the delta
# reported at the end of the capstone.
#
# Idempotency: the baseline is a one-shot measurement of the UNHARDENED host.
# Re-running after a hardening control has been applied would silently destroy
# the denominator, so an existing baseline is treated as state already in
# place: the script reports it and exits 0 without re-running Lynis. Pass -f
# to deliberately recapture (the previous record is kept as *.superseded).
#
# Usage:
#   sudo ./1-baseline_snapshot.sh [-o CAPSTONE_ROOT] [-f] [-u] [-h]
#
#   -o CAPSTONE_ROOT  Root that contains capstone/ (default: ., overridable
#                     with CAPSTONE_ROOT).
#   -f                Force recapture even if a baseline already exists.
#   -u                Allow an unprivileged run. Lynis will skip most root-only
#                     tests and the index will be misleading.
#   -h                Show usage.
#
# Output:
#   capstone/baseline/lynis_baseline.log   full Lynis stdout/stderr
#   capstone/baseline/lynis_baseline.dat   harvested Lynis report data
#   capstone/baseline/baseline_linux.json  timestamp, hostname, lynis_version,
#                                          hardening_index, warnings_count,
#                                          suggestions_count, log_path
#
# Exit codes:
#   0  success - baseline captured, or already present and left untouched
#   1  controlled failure - audit ran but the Hardening Index could not be
#      parsed, or Lynis reported a non-zero status
#   2  environment error - lynis missing, not root, unwritable output tree
#
set -euo pipefail

readonly SCRIPT_NAME="1-baseline_snapshot.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="baseline_snapshot"
readonly PHASE="pre_hardening"

# Paths are fixed by the capstone brief. Relative form is what goes into the
# record so Module 3 can resolve it against whatever root they unpack into.
readonly BASELINE_SUBDIR="capstone/baseline"
readonly LOG_RELPATH="capstone/baseline/lynis_baseline.log"
readonly DAT_RELPATH="capstone/baseline/lynis_baseline.dat"
readonly RECORD_BASENAME="baseline_linux.json"
readonly LYNIS_REPORT="/var/log/lynis-report.dat"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
FORCE=0
ALLOW_UNPRIVILEGED=0
PRIVILEGED="false"
TMP_JSON=""
COLLECTION_ERRORS=()

usage() {
    sed -n '3,38p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

record_error() {
    COLLECTION_ERRORS+=("$1")
    log "WARN  $1"
}

# shellcheck disable=SC2317  # invoked indirectly by the EXIT trap
cleanup() {
    if [[ -n "$TMP_JSON" && -f "$TMP_JSON" ]]; then
        rm -f "$TMP_JSON"
    fi
}
trap cleanup EXIT

json_escape() {
    local s
    s=$(printf '%s' "${1-}" | tr -d '\000-\010\013\014\016-\037')
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

jstr() {
    printf '"%s"' "$(json_escape "${1-}")"
}

jnum() {
    local v="${1-}"
    if [[ "$v" =~ ^-?[0-9]+$ ]]; then
        printf '%s' "$v"
    else
        printf 'null'
    fi
}

emit() {
    printf '%s\n' "$*" >>"$TMP_JSON"
}

get_hostname() {
    if command -v hostname >/dev/null 2>&1; then
        hostname
    else
        uname -n
    fi
}

# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

parse_lynis_version() {
    local version=""
    if [[ -r "$1" ]]; then
        version=$(awk -F= '$1=="lynis_version"{print $2; exit}' "$1" || true)
    fi
    if [[ -z "$version" ]] && command -v lynis >/dev/null 2>&1; then
        version=$(lynis show version 2>/dev/null | head -n 1 || true)
    fi
    printf '%s' "$version"
}

parse_hardening_index() {
    # Prefer the machine-readable report; fall back to the human log line
    # "Hardening index : 64 [######    ]".
    local dat="$1" logfile="$2" index=""

    if [[ -r "$dat" ]]; then
        index=$(awk -F= '$1=="hardening_index"{print $2; exit}' "$dat" || true)
    fi
    if [[ ! "$index" =~ ^[0-9]+$ && -r "$logfile" ]]; then
        index=$(grep -aoE 'Hardening index[[:space:]]*:[[:space:]]*[0-9]+' "$logfile" |
            grep -oE '[0-9]+' | tail -n 1 || true)
    fi
    printf '%s' "$index"
}

count_report_field() {
    # count_report_field <dat> <field-prefix>
    local dat="$1" field="$2" count=""
    if [[ -r "$dat" ]]; then
        count=$(grep -ac "^${field}\[\]=" "$dat" || true)
    fi
    printf '%s' "$count"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local opt hn base_dir log_file dat_file out_file
    local rc=0 timestamp lynis_version hardening_index warnings suggestions
    local i first=1

    while getopts ":o:fuh" opt; do
        case "$opt" in
            o) CAPSTONE_ROOT="$OPTARG" ;;
            f) FORCE=1 ;;
            u) ALLOW_UNPRIVILEGED=1 ;;
            h)
                usage
                exit 0
                ;;
            \?)
                log "ERROR unknown option: -$OPTARG"
                usage >&2
                exit 2
                ;;
            :)
                log "ERROR option -$OPTARG requires an argument"
                exit 2
                ;;
            *)
                exit 2
                ;;
        esac
    done

    if ! command -v lynis >/dev/null 2>&1; then
        log "ERROR lynis is not installed; install it before capturing the baseline"
        exit 2
    fi

    local dep
    for dep in awk grep sed date uname tr wc; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    if [[ "$(id -u)" -eq 0 ]]; then
        PRIVILEGED="true"
    elif [[ "$ALLOW_UNPRIVILEGED" -eq 1 ]]; then
        record_error "run is unprivileged, Lynis skipped root-only tests and the index is not comparable"
    else
        log "ERROR lynis must run as root for a meaningful index; use sudo, or -u to override"
        exit 2
    fi

    hn=$(get_hostname)
    base_dir="${CAPSTONE_ROOT}/${BASELINE_SUBDIR}"
    log_file="${CAPSTONE_ROOT}/${LOG_RELPATH}"
    dat_file="${CAPSTONE_ROOT}/${DAT_RELPATH}"
    out_file="${base_dir}/${RECORD_BASENAME}"

    if ! mkdir -p "$base_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $base_dir"
        exit 2
    fi
    if [[ ! -w "$base_dir" ]]; then
        log "ERROR output directory is not writable: $base_dir"
        exit 2
    fi

    # Idempotency gate: an existing baseline is state already in place.
    if [[ -f "$out_file" && "$FORCE" -eq 0 ]]; then
        log "INFO  baseline already present at $out_file; not re-running lynis (use -f to recapture)"
        printf '%s\n' "$out_file"
        exit 0
    fi
    if [[ -f "$out_file" && "$FORCE" -eq 1 ]]; then
        mv -f "$out_file" "${out_file}.superseded"
        log "INFO  previous baseline preserved as ${out_file}.superseded"
    fi

    log "INFO  running lynis audit on $hn (this takes a minute)"
    set +e
    lynis audit system --quick --no-colors >"${log_file}.partial" 2>&1
    rc=$?
    set -e
    mv -f "${log_file}.partial" "$log_file"

    if [[ "$rc" -ne 0 ]]; then
        record_error "lynis exited with status ${rc}; see ${LOG_RELPATH}"
    fi

    # Harvest the machine-readable report alongside the log so the evidence
    # package is self-contained and does not depend on /var/log surviving.
    if [[ -r "$LYNIS_REPORT" ]]; then
        cp -f "$LYNIS_REPORT" "$dat_file"
    else
        record_error "lynis report data not found at ${LYNIS_REPORT}; parsing from the log only"
        : >"$dat_file"
    fi

    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    lynis_version=$(parse_lynis_version "$dat_file")
    hardening_index=$(parse_hardening_index "$dat_file" "$log_file")
    warnings=$(count_report_field "$dat_file" "warning")
    suggestions=$(count_report_field "$dat_file" "suggestion")

    if [[ ! "$hardening_index" =~ ^[0-9]+$ ]]; then
        record_error "hardening index could not be parsed from the audit output"
    elif [[ "$hardening_index" -lt 0 || "$hardening_index" -gt 100 ]]; then
        record_error "hardening index ${hardening_index} is outside the expected 0-100 range"
    fi
    if [[ -z "$lynis_version" ]]; then
        record_error "lynis version could not be determined"
    fi

    TMP_JSON=$(mktemp "${base_dir}/.baseline.XXXXXX") || {
        log "ERROR cannot create temporary file in $base_dir"
        exit 2
    }

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "phase"): $(jstr "$PHASE"),"
    emit "  $(jstr "platform"): $(jstr "linux"),"
    emit "  $(jstr "timestamp"): $(jstr "$timestamp"),"
    emit "  $(jstr "hostname"): $(jstr "$hn"),"
    emit "  $(jstr "lynis_version"): $(jstr "$lynis_version"),"
    emit "  $(jstr "hardening_index"): $(jnum "$hardening_index"),"
    emit "  $(jstr "warnings_count"): $(jnum "$warnings"),"
    emit "  $(jstr "suggestions_count"): $(jnum "$suggestions"),"
    emit "  $(jstr "log_path"): $(jstr "$LOG_RELPATH"),"
    emit "  $(jstr "report_data_path"): $(jstr "$DAT_RELPATH"),"
    emit '  "collector": {'
    emit "    $(jstr "script"): $(jstr "$SCRIPT_NAME"),"
    emit "    $(jstr "version"): $(jstr "$SCRIPT_VERSION"),"
    emit "    $(jstr "command"): $(jstr "lynis audit system --quick --no-colors"),"
    emit "    $(jstr "exit_status"): $(jnum "$rc"),"
    emit "    $(jstr "privileged"): $([[ "$PRIVILEGED" == "true" ]] && printf 'true' || printf 'false')"
    emit '  },'
    emit '  "collection_errors": ['
    if [[ "${#COLLECTION_ERRORS[@]}" -gt 0 ]]; then
        for i in "${COLLECTION_ERRORS[@]}"; do
            if [[ "$first" -eq 0 ]]; then
                emit '    ,'
            fi
            first=0
            emit "    $(jstr "$i")"
        done
    fi
    emit '  ]'
    emit '}'

    chmod 0640 "$TMP_JSON"
    mv -f "$TMP_JSON" "$out_file"
    TMP_JSON=""

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$base_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
    else
        record_error "integrity: sha256sum unavailable, no digest written"
    fi

    log "INFO  hardening index ${hardening_index:-unparsed}, ${warnings:-?} warnings, ${suggestions:-?} suggestions"
    log "INFO  baseline record written to $out_file"
    printf '%s\n' "$out_file"

    if [[ "${#COLLECTION_ERRORS[@]}" -gt 0 ]]; then
        log "WARN  ${#COLLECTION_ERRORS[@]} issue(s) recorded; see .collection_errors"
        exit 1
    fi
    exit 0
}

main "$@"
