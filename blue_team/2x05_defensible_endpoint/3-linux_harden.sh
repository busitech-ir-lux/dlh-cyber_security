#!/bin/bash
#
# 3-linux_harden.sh - Hawthorne capstone, Task 3
#
# Orchestrates the Linux hardening pass on hawthorne-app-01. It does not
# reimplement the controls: it composes the 2x00 hardening scripts in a fixed
# order, captures structured evidence for each sub-step, re-measures the Lynis
# Hardening Index and checks the result against target_state.json.
#
# Idempotency: this orchestrator applies changes, so idempotency depends on the
# sub-steps being idempotent themselves. The orchestrator makes that visible
# rather than assuming it - each step is fingerprinted before and after it
# runs, and the "changed" flag in the evidence record reports whether that
# step actually altered system state. A correct second run must report
# changed=false for every step. That flag is the audit trail for the
# idempotency requirement.
#
# Usage:
#   sudo ./3-linux_harden.sh [-o CAPSTONE_ROOT] [-s STEP_DIR] [-m MIN_INDEX]
#                            [--list-steps] [--help]
#
#   -o CAPSTONE_ROOT  Root that contains capstone/ (default: ., overridable
#                     with CAPSTONE_ROOT).
#   -s STEP_DIR       Directory holding the 2x00 hardening scripts
#                     (default: /home/analyst/MedDefense_Lab/2x00,
#                     overridable with STEP_DIR).
#   -m MIN_INDEX      Override the Hardening Index floor. Normally read from
#                     target_state.json.
#   --list-steps      Print the resolved step order and paths, then exit.
#   --help            Show usage.
#
# Individual steps can be relocated without -s by exporting an override, e.g.
#   export STEP_SSH_HARDENING=/opt/hardening/harden_ssh.sh
#
# Output:
#   capstone/exec/linux_harden.log   full stdout/stderr of every sub-step
#   capstone/exec/lynis_after.log    the post-hardening Lynis run
#   capstone/exec/linux_harden.json  structured execution evidence
#
# Exit codes:
#   0  every sub-step exited 0 AND lynis_after >= the target-state floor
#   1  a sub-step failed, or the index floor was not met
#   2  environment error - not root, missing dependency, missing sub-step
#      script, missing or corrupt target_state.json, missing baseline
#
set -euo pipefail
# Stated explicitly as well: a sub-step whose work happens mid-pipeline must
# not have its failure masked by a later command in that pipeline succeeding.
set -o pipefail

readonly SCRIPT_NAME="3-linux_harden.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="hardening_execution"

readonly EXEC_SUBDIR="capstone/exec"
readonly LOG_RELPATH="capstone/exec/linux_harden.log"
readonly LYNIS_LOG_RELPATH="capstone/exec/lynis_after.log"
readonly RECORD_BASENAME="linux_harden.json"
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly BASELINE_RELPATH="capstone/baseline/baseline_linux.json"
readonly LYNIS_REPORT="/var/log/lynis-report.dat"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
STEP_DIR="${STEP_DIR:-/home/analyst/MedDefense_Lab/2x00}"
MIN_INDEX_OVERRIDE=""
LIST_ONLY=0
TMP_JSON=""

# Deterministic step order. Fields: name|default filename|controls touched.
# The control IDs are checked against target_state.json at preflight, so a
# rename in the contract surfaces here instead of silently mislabelling
# evidence.
readonly STEP_SPEC=(
    "ssh_hardening|harden_ssh.sh|LNX-SSH-01,LNX-SSH-02"
    "sysctl_hardening|harden_sysctl.sh|LNX-SYS-01,LNX-SYS-02"
    "permission_sweep|harden_permissions.sh|"
    "service_minimization|harden_services.sh|"
    "pam_configuration|harden_pam.sh|"
    "apparmor_enforcement|harden_apparmor.sh|LNX-APP-01"
    "auditd_deployment|deploy_auditd.sh|LNX-AUD-01,LNX-AUD-02,LNX-AUD-03"
)

STEP_NAMES=()
STEP_PATHS=()
STEP_CONTROLS=()
STEP_RCS=()
STEP_DURATIONS=()
STEP_CHANGED=()
STEP_FP_BEFORE=()
STEP_FP_AFTER=()

usage() {
    sed -n '3,46p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
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
    if [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
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
# JSON readers - jq preferred, python3 as fallback
# --------------------------------------------------------------------------

json_query() {
    # json_query <file> <jq-expression> <python-expression>
    local file="$1" jq_expr="$2" py_expr="$3" out=""
    if command -v jq >/dev/null 2>&1; then
        out=$(jq -r "$jq_expr" "$file" 2>/dev/null || true)
    elif command -v python3 >/dev/null 2>&1; then
        out=$(python3 -c "$py_expr" "$file" 2>/dev/null || true)
    fi
    if [[ "$out" == "null" ]]; then
        out=""
    fi
    printf '%s' "$out"
}

read_baseline_index() {
    json_query "$1" '.hardening_index // empty' \
        'import json,sys; d=json.load(open(sys.argv[1])); v=d.get("hardening_index"); print("" if v is None else v)'
}

read_target_index_floor() {
    # The contract expresses the floor as the expected_value of the linux
    # hardening-index control. Prefer matching on check_target so the check
    # survives a control-ID rename; fall back to the well-known ID.
    local file="$1" out=""
    out=$(json_query "$file" \
        '[.controls[] | select(.platform=="linux" and .check_type=="json_field_gte" and (.check_target|test("hardening_index$"))) | .expected_value] | first // empty' \
        'import json,sys
d=json.load(open(sys.argv[1]))
c=[x for x in d.get("controls",[]) if x.get("platform")=="linux" and x.get("check_type")=="json_field_gte" and str(x.get("check_target","")).endswith("hardening_index")]
print(c[0]["expected_value"] if c else "")')
    if [[ -z "$out" ]]; then
        out=$(json_query "$file" \
            '[.controls[] | select(.id=="LNX-LYN-01") | .expected_value] | first // empty' \
            'import json,sys
d=json.load(open(sys.argv[1]))
c=[x for x in d.get("controls",[]) if x.get("id")=="LNX-LYN-01"]
print(c[0]["expected_value"] if c else "")')
    fi
    printf '%s' "$out"
}

control_ids_in_contract() {
    json_query "$1" '.controls[].id' \
        'import json,sys
d=json.load(open(sys.argv[1]))
print("\n".join(x.get("id","") for x in d.get("controls",[])))'
}

# --------------------------------------------------------------------------
# Change detection
#
# Each step gets a fingerprint over exactly the state it is supposed to own.
# Comparing before and after tells us whether the step actually changed
# anything, which is what makes the idempotency claim checkable rather than
# asserted.
# --------------------------------------------------------------------------

fingerprint_step() {
    local name="$1"
    {
        case "$name" in
            ssh_hardening)
                cat /etc/ssh/sshd_config 2>/dev/null || true
                cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
                ;;
            sysctl_hardening)
                # Deliberately NOT `sysctl -a`: that includes volatile counters
                # (fs.file-nr, fs.inode-state, kernel.random.uuid) that differ
                # between two consecutive reads and would report a spurious
                # change on every run. Fingerprint the security-relevant keys
                # only - the same set the T0 intake records.
                local key
                for key in \
                    fs.protected_hardlinks fs.protected_symlinks fs.suid_dumpable \
                    kernel.dmesg_restrict kernel.kptr_restrict \
                    kernel.randomize_va_space kernel.sysrq \
                    kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope \
                    net.ipv4.conf.all.accept_redirects \
                    net.ipv4.conf.all.accept_source_route \
                    net.ipv4.conf.all.log_martians net.ipv4.conf.all.rp_filter \
                    net.ipv4.conf.all.send_redirects \
                    net.ipv4.conf.default.accept_redirects \
                    net.ipv4.conf.default.accept_source_route \
                    net.ipv4.conf.default.send_redirects \
                    net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.ip_forward \
                    net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra \
                    net.ipv6.conf.all.accept_redirects net.ipv6.conf.all.disable_ipv6; do
                    printf '%s=%s\n' "$key" "$(sysctl -n "$key" 2>/dev/null || printf 'unset')"
                done
                cat /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null || true
                ;;
            permission_sweep)
                find / -perm /6000 -type f 2>/dev/null | LC_ALL=C sort || true
                find / -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' \
                    2>/dev/null | LC_ALL=C sort || true
                ;;
            service_minimization)
                systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null |
                    LC_ALL=C sort || true
                ;;
            pam_configuration)
                cat /etc/pam.d/* 2>/dev/null || true
                cat /etc/security/pwquality.conf 2>/dev/null || true
                ;;
            apparmor_enforcement)
                aa-status 2>/dev/null || apparmor_status 2>/dev/null || true
                ;;
            auditd_deployment)
                cat /etc/audit/rules.d/*.rules 2>/dev/null || true
                cat /etc/audit/auditd.conf 2>/dev/null || true
                auditctl -l 2>/dev/null || true
                ;;
            *)
                printf 'no-fingerprint-defined\n'
                ;;
        esac
    } | sha256sum | awk '{print $1}'
}

# --------------------------------------------------------------------------
# Step execution
# --------------------------------------------------------------------------

run_step() {
    # run_step <name> <script_path> <controls_csv>
    local name="$1" script="$2" controls="$3"
    local before after rc start_ms end_ms elapsed_ms duration changed

    before=$(fingerprint_step "$name")

    {
        printf '===== STEP BEGIN %s =====\n' "$name"
        printf 'script: %s\n' "$script"
        printf 'started_at: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'controls_touched: %s\n' "${controls:-none}"
        printf -- '-----\n'
    } >>"$LOG_FILE"

    start_ms=$(date +%s%3N 2>/dev/null || echo "")
    # pipefail is on, so a failure anywhere in the step's own pipeline still
    # surfaces here rather than being masked by tee.
    set +e
    "$script" >>"$LOG_FILE" 2>&1
    rc=$?
    set -e
    end_ms=$(date +%s%3N 2>/dev/null || echo "")

    if [[ "$start_ms" =~ ^[0-9]+$ && "$end_ms" =~ ^[0-9]+$ ]]; then
        elapsed_ms=$((end_ms - start_ms))
        duration=$(printf '%d.%03d' "$((elapsed_ms / 1000))" "$((elapsed_ms % 1000))")
    else
        duration="0.000"
    fi

    after=$(fingerprint_step "$name")
    if [[ "$before" == "$after" ]]; then
        changed="false"
    else
        changed="true"
    fi

    {
        printf -- '-----\n'
        printf '===== STEP END %s rc=%s duration=%ss changed=%s =====\n\n' \
            "$name" "$rc" "$duration" "$changed"
    } >>"$LOG_FILE"

    STEP_NAMES+=("$name")
    STEP_PATHS+=("$script")
    STEP_CONTROLS+=("$controls")
    STEP_RCS+=("$rc")
    STEP_DURATIONS+=("$duration")
    STEP_CHANGED+=("$changed")
    STEP_FP_BEFORE+=("$before")
    STEP_FP_AFTER+=("$after")

    if [[ "$rc" -eq 0 ]]; then
        log "INFO  step ${name} ok (${duration}s, changed=${changed})"
    else
        log "WARN  step ${name} FAILED rc=${rc} (${duration}s)"
    fi
}

resolve_step_path() {
    # Env override wins: STEP_SSH_HARDENING=/path/to/script.sh
    local name="$1" default_file="$2" var_name value
    var_name="STEP_$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
    value="${!var_name-}"
    if [[ -n "$value" ]]; then
        printf '%s' "$value"
    else
        printf '%s/%s' "$STEP_DIR" "$default_file"
    fi
}

emit_steps_array() {
    local i first=1 controls c
    emit '  "steps": ['
    for i in "${!STEP_NAMES[@]}"; do
        if [[ "$first" -eq 0 ]]; then
            emit '    ,'
        fi
        first=0
        emit '    {'
        emit "      $(jstr "name"): $(jstr "${STEP_NAMES[$i]}"),"
        emit "      $(jstr "script_path"): $(jstr "${STEP_PATHS[$i]}"),"
        emit "      $(jstr "exit_code"): $(jnum "${STEP_RCS[$i]}"),"
        emit "      $(jstr "duration_seconds"): $(jnum "${STEP_DURATIONS[$i]}"),"
        emit "      $(jstr "changed"): ${STEP_CHANGED[$i]},"
        emit "      $(jstr "state_fingerprint_before"): $(jstr "${STEP_FP_BEFORE[$i]}"),"
        emit "      $(jstr "state_fingerprint_after"): $(jstr "${STEP_FP_AFTER[$i]}"),"
        emit "      $(jstr "controls_touched"): ["
        controls="${STEP_CONTROLS[$i]}"
        if [[ -n "$controls" ]]; then
            local inner=1
            while IFS= read -r c; do
                if [[ -z "$c" ]]; then
                    continue
                fi
                if [[ "$inner" -eq 0 ]]; then
                    emit '        ,'
                fi
                inner=0
                emit "        $(jstr "$c")"
            done <<<"$(printf '%s' "$controls" | tr ',' '\n')"
        fi
        emit '      ]'
        emit '    }'
    done
    emit '  ],'
}

emit_union_controls() {
    local all="" i c first=1
    for i in "${!STEP_CONTROLS[@]}"; do
        if [[ -n "${STEP_CONTROLS[$i]}" ]]; then
            all+="${STEP_CONTROLS[$i]},"
        fi
    done
    emit "  $(jstr "controls_touched"): ["
    if [[ -n "$all" ]]; then
        while IFS= read -r c; do
            if [[ -z "$c" ]]; then
                continue
            fi
            if [[ "$first" -eq 0 ]]; then
                emit '    ,'
            fi
            first=0
            emit "    $(jstr "$c")"
        done <<<"$(printf '%s' "$all" | tr ',' '\n' | LC_ALL=C sort -u)"
    fi
    emit '  ],'
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local arg hn exec_dir out_file target_state baseline_file
    local spec name default_file controls script_path
    local lynis_before lynis_after index_floor index_delta
    local rc_lynis=0 failed_steps=0 i status overall_ok="true"
    local contract_ids missing_controls=""

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                if [[ $# -lt 2 ]]; then
                    log "ERROR option -o requires an argument"
                    exit 2
                fi
                CAPSTONE_ROOT="$2"
                shift 2
                ;;
            -s)
                if [[ $# -lt 2 ]]; then
                    log "ERROR option -s requires an argument"
                    exit 2
                fi
                STEP_DIR="$2"
                shift 2
                ;;
            -m)
                if [[ $# -lt 2 ]]; then
                    log "ERROR option -m requires an argument"
                    exit 2
                fi
                MIN_INDEX_OVERRIDE="$2"
                shift 2
                ;;
            --list-steps)
                LIST_ONLY=1
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                log "ERROR unknown argument: $arg"
                usage >&2
                exit 2
                ;;
        esac
    done

    target_state="${CAPSTONE_ROOT}/${TARGET_STATE_RELPATH}"
    baseline_file="${CAPSTONE_ROOT}/${BASELINE_RELPATH}"
    exec_dir="${CAPSTONE_ROOT}/${EXEC_SUBDIR}"
    LOG_FILE="${CAPSTONE_ROOT}/${LOG_RELPATH}"
    LYNIS_LOG_FILE="${CAPSTONE_ROOT}/${LYNIS_LOG_RELPATH}"
    out_file="${exec_dir}/${RECORD_BASENAME}"

    # Resolve the step list first so --list-steps works without root.
    for spec in "${STEP_SPEC[@]}"; do
        IFS='|' read -r name default_file controls <<<"$spec"
        script_path=$(resolve_step_path "$name" "$default_file")
        STEP_NAMES+=("$name")
        STEP_PATHS+=("$script_path")
        STEP_CONTROLS+=("$controls")
    done

    if [[ "$LIST_ONLY" -eq 1 ]]; then
        printf '%-24s %-12s %s\n' "STEP" "CONTROLS" "PATH"
        for i in "${!STEP_NAMES[@]}"; do
            printf '%-24s %-12s %s\n' "${STEP_NAMES[$i]}" \
                "${STEP_CONTROLS[$i]:-none}" "${STEP_PATHS[$i]}"
        done
        exit 0
    fi

    # --- preflight: everything that makes the run impossible is exit 2 ---

    if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        log "ERROR neither jq nor python3 is available; cannot read the target state contract"
        exit 2
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        log "ERROR sha256sum is required for change detection"
        exit 2
    fi
    if ! command -v lynis >/dev/null 2>&1; then
        log "ERROR lynis is not installed; cannot re-measure the hardening index"
        exit 2
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR hardening must run as root; re-run with sudo"
        exit 2
    fi

    # A missing or corrupt contract is fatal for every downstream script.
    if [[ ! -f "$target_state" ]]; then
        log "FATAL target state contract is missing: $target_state (run 2-target_state.sh first)"
        exit 2
    fi
    contract_ids=$(control_ids_in_contract "$target_state")
    if [[ -z "$contract_ids" ]]; then
        log "FATAL target state contract is corrupt or declares no controls: $target_state"
        exit 2
    fi

    if [[ ! -f "$baseline_file" ]]; then
        log "FATAL baseline is missing: $baseline_file (run 1-baseline_snapshot.sh first)"
        exit 2
    fi

    # Every step script must exist and be executable before anything is applied.
    local missing=0
    for i in "${!STEP_NAMES[@]}"; do
        if [[ ! -f "${STEP_PATHS[$i]}" ]]; then
            log "ERROR step script not found: ${STEP_NAMES[$i]} -> ${STEP_PATHS[$i]}"
            missing=1
        elif [[ ! -x "${STEP_PATHS[$i]}" ]]; then
            log "ERROR step script is not executable: ${STEP_PATHS[$i]}"
            missing=1
        fi
    done
    if [[ "$missing" -eq 1 ]]; then
        log "ERROR use -s STEP_DIR, or export STEP_<NAME> for individual scripts; --list-steps shows the resolved paths"
        exit 2
    fi

    # Warn if the evidence references control IDs the contract does not declare.
    for i in "${!STEP_CONTROLS[@]}"; do
        if [[ -z "${STEP_CONTROLS[$i]}" ]]; then
            continue
        fi
        while IFS= read -r name; do
            if [[ -n "$name" ]] && ! printf '%s\n' "$contract_ids" | grep -qx "$name"; then
                missing_controls+="${name} "
            fi
        done <<<"$(printf '%s' "${STEP_CONTROLS[$i]}" | tr ',' '\n')"
    done
    if [[ -n "$missing_controls" ]]; then
        log "WARN  step registry references control IDs absent from the contract: ${missing_controls}"
    fi

    if ! mkdir -p "$exec_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $exec_dir"
        exit 2
    fi

    # --- run ---

    hn=$(get_hostname)
    lynis_before=$(read_baseline_index "$baseline_file")
    if [[ -n "$MIN_INDEX_OVERRIDE" ]]; then
        index_floor="$MIN_INDEX_OVERRIDE"
    else
        index_floor=$(read_target_index_floor "$target_state")
    fi
    if [[ ! "$index_floor" =~ ^[0-9]+$ ]]; then
        log "FATAL could not read the hardening index floor from $target_state"
        exit 2
    fi

    : >"$LOG_FILE"
    {
        printf '# %s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '# host: %s\n' "$hn"
        printf '# run_started_at: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# baseline hardening index: %s\n' "${lynis_before:-unknown}"
        printf '# required floor: %s\n\n' "$index_floor"
    } >>"$LOG_FILE"

    # Reset the accumulators; run_step repopulates them with results.
    local planned_names=("${STEP_NAMES[@]}")
    local planned_paths=("${STEP_PATHS[@]}")
    local planned_controls=("${STEP_CONTROLS[@]}")
    STEP_NAMES=()
    STEP_PATHS=()
    STEP_CONTROLS=()

    log "INFO  applying ${#planned_names[@]} hardening steps on $hn"
    for i in "${!planned_names[@]}"; do
        run_step "${planned_names[$i]}" "${planned_paths[$i]}" "${planned_controls[$i]}"
    done

    for i in "${!STEP_RCS[@]}"; do
        if [[ "${STEP_RCS[$i]}" -ne 0 ]]; then
            failed_steps=$((failed_steps + 1))
        fi
    done

    log "INFO  re-running lynis audit system to re-measure the hardening index"
    set +e
    lynis audit system --no-colors >"$LYNIS_LOG_FILE" 2>&1
    rc_lynis=$?
    set -e
    if [[ "$rc_lynis" -ne 0 ]]; then
        log "WARN  post-hardening lynis exited ${rc_lynis}; see ${LYNIS_LOG_RELPATH}"
    fi

    lynis_after=""
    if [[ -r "$LYNIS_REPORT" ]]; then
        lynis_after=$(awk -F= '$1=="hardening_index"{print $2; exit}' "$LYNIS_REPORT" || true)
    fi
    if [[ ! "$lynis_after" =~ ^[0-9]+$ ]]; then
        lynis_after=$(grep -aoE 'Hardening index[[:space:]]*:[[:space:]]*[0-9]+' "$LYNIS_LOG_FILE" 2>/dev/null |
            grep -oE '[0-9]+' | tail -n 1 || true)
    fi

    if [[ "$lynis_before" =~ ^[0-9]+$ && "$lynis_after" =~ ^[0-9]+$ ]]; then
        index_delta=$((lynis_after - lynis_before))
    else
        index_delta=""
    fi

    # --- verdict ---

    if [[ "$failed_steps" -gt 0 ]]; then
        overall_ok="false"
        log "WARN  ${failed_steps} sub-step(s) exited non-zero"
    fi
    if [[ ! "$lynis_after" =~ ^[0-9]+$ ]]; then
        overall_ok="false"
        log "WARN  post-hardening hardening index could not be parsed"
    elif [[ "$lynis_after" -lt "$index_floor" ]]; then
        overall_ok="false"
        log "WARN  hardening index ${lynis_after} is below the required floor ${index_floor}"
    fi

    # --- evidence ---

    TMP_JSON=$(mktemp "${exec_dir}/.linux_harden.XXXXXX") || {
        log "ERROR cannot create temporary file in $exec_dir"
        exit 2
    }

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "phase"): $(jstr "post_hardening"),"
    emit "  $(jstr "platform"): $(jstr "linux"),"
    emit "  $(jstr "timestamp"): $(jstr "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"),"
    emit "  $(jstr "hostname"): $(jstr "$hn"),"
    emit_steps_array
    emit "  $(jstr "lynis_before"): $(jnum "$lynis_before"),"
    emit "  $(jstr "lynis_after"): $(jnum "$lynis_after"),"
    emit "  $(jstr "index_delta"): $(jnum "$index_delta"),"
    emit "  $(jstr "index_floor"): $(jnum "$index_floor"),"
    emit "  $(jstr "floor_met"): $([[ "$lynis_after" =~ ^[0-9]+$ && "$lynis_after" -ge "$index_floor" ]] && printf 'true' || printf 'false'),"
    emit "  $(jstr "steps_failed"): $(jnum "$failed_steps"),"
    emit_union_controls
    emit "  $(jstr "log_path"): $(jstr "$LOG_RELPATH"),"
    emit "  $(jstr "lynis_log_path"): $(jstr "$LYNIS_LOG_RELPATH"),"
    emit "  $(jstr "target_state_path"): $(jstr "$TARGET_STATE_RELPATH"),"
    emit "  $(jstr "result"): $(jstr "$([[ "$overall_ok" == "true" ]] && printf 'pass' || printf 'fail')"),"
    emit '  "orchestrator": {'
    emit "    $(jstr "script"): $(jstr "$SCRIPT_NAME"),"
    emit "    $(jstr "version"): $(jstr "$SCRIPT_VERSION"),"
    emit "    $(jstr "step_dir"): $(jstr "$STEP_DIR"),"
    emit "    $(jstr "lynis_exit_status"): $(jnum "$rc_lynis")"
    emit '  }'
    emit '}'

    chmod 0640 "$TMP_JSON"
    mv -f "$TMP_JSON" "$out_file"
    TMP_JSON=""

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$exec_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
    fi

    log "INFO  index ${lynis_before:-?} -> ${lynis_after:-?} (delta ${index_delta:-?}, floor ${index_floor})"
    log "INFO  execution record written to $out_file"
    printf '%s\n' "$out_file"

    if [[ "$overall_ok" == "true" ]]; then
        status=0
    else
        status=1
    fi
    if [[ "$status" -eq 0 ]]; then
        exit 0
    fi
    exit 1
}

main "$@"
