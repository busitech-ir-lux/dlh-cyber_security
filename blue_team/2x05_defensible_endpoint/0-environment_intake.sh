#!/bin/bash
#
# 0-environment_intake.sh - Hawthorne capstone, Task 0 (Linux side)
#
# Captures the raw, pre-hardening state of hawthorne-app-01 and writes a single
# deterministic JSON intake record. Every later task measures its own success as
# a delta against this record.
#
# The script is read-only with respect to system state: it collects, it never
# configures. Idempotency therefore holds by construction - a second execution
# re-collects and atomically replaces the record at the same deterministic path
# and can neither corrupt state nor re-apply a change.
#
# Usage:
#   sudo ./0-environment_intake.sh [-o OUTPUT_ROOT] [-u] [-h]
#
#   -o OUTPUT_ROOT  Root of the artifact tree (default: ./artifacts,
#                   overridable with INTAKE_OUTPUT_ROOT).
#   -u              Allow an unprivileged run. The record is still written but
#                   is marked privileged=false and will be incomplete.
#   -h              Show usage.
#
# Output:
#   OUTPUT_ROOT/intake/<hostname>/environment_intake.json
#   OUTPUT_ROOT/intake/<hostname>/environment_intake.json.sha256
#   The absolute path of the record is printed on stdout; all logging goes to
#   stderr, so the caller can capture the path directly.
#
# Exit codes:
#   0  success - record written, every collector reported clean
#   1  controlled failure - record written, one or more collectors degraded
#      (listed in .collection_errors), or a required privilege was missing
#   2  environment error - missing dependency, unwritable output tree
#
set -euo pipefail

readonly SCRIPT_NAME="0-environment_intake.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="environment_intake"
readonly PHASE="pre_hardening"

readonly EXIT_OK=0
readonly EXIT_FAIL=1
readonly EXIT_ENV=2

# Module 3 handoff layout. Keep these two constants aligned with the telemetry
# handoff from 2x02 and the network artifact package from 2x04 - they are the
# only place the layout is defined.
readonly ARTIFACT_SUBDIR="intake"
readonly RECORD_BASENAME="environment_intake.json"

OUTPUT_ROOT="${INTAKE_OUTPUT_ROOT:-./artifacts}"
ALLOW_UNPRIVILEGED=0
PRIVILEGED="false"
TMP_JSON=""
COLLECTION_ERRORS=()

usage() {
    sed -n '3,32p' "$0" | sed 's/^# \{0,1\}//'
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

# --------------------------------------------------------------------------
# JSON emitters (no jq dependency, so the script runs on a bare host)
# --------------------------------------------------------------------------

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

jbool() {
    if [[ "${1-}" == "true" || "${1-}" == "1" ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

emit() {
    printf '%s\n' "$*" >>"$TMP_JSON"
}

emit_kv_str() {
    emit "    $(jstr "$1"): $(jstr "$2")${3-}"
}

emit_kv_num() {
    emit "    $(jstr "$1"): $(jnum "$2")${3-}"
}

# --------------------------------------------------------------------------
# Environment validation
# --------------------------------------------------------------------------

require_cmd() {
    local missing=0 cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $cmd"
            missing=1
        fi
    done
    return "$missing"
}

get_hostname() {
    if command -v hostname >/dev/null 2>&1; then
        hostname
    else
        uname -n
    fi
}

os_release_field() {
    local key="$1"
    if [[ -r /etc/os-release ]]; then
        awk -F= -v k="$key" '$1==k {gsub(/^"|"$/,"",$2); print $2; exit}' /etc/os-release
    fi
}

unit_is() {
    # unit_is <unit> <is-active|is-enabled>
    systemctl "$2" "$1" 2>/dev/null || true
}

unit_present() {
    local unit="$1"
    if systemctl list-unit-files --no-legend --no-pager 2>/dev/null |
        awk '{print $1}' | grep -qx "$unit"; then
        printf 'true'
    else
        printf 'false'
    fi
}

# --------------------------------------------------------------------------
# Collectors - each appends one top-level object to the record
# --------------------------------------------------------------------------

collect_host() {
    local hn kernel arch dist_id dist_name dist_ver patch pending
    hn=$(get_hostname)
    kernel=$(uname -r)
    arch=$(uname -m)
    dist_id=$(os_release_field "ID")
    dist_name=$(os_release_field "PRETTY_NAME")
    dist_ver=$(os_release_field "VERSION_ID")

    if [[ -r /etc/debian_version ]]; then
        patch=$(cat /etc/debian_version)
    else
        patch="$dist_ver"
    fi

    if command -v apt-get >/dev/null 2>&1; then
        pending=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null |
            grep -c '^Inst ' || true)
    else
        pending=""
        record_error "host: apt-get unavailable, pending_updates not measured"
    fi

    emit '  "host": {'
    emit_kv_str "hostname" "$hn" ","
    emit_kv_str "kernel_release" "$kernel" ","
    emit_kv_str "architecture" "$arch" ","
    emit_kv_str "distribution_id" "$dist_id" ","
    emit_kv_str "distribution_name" "$dist_name" ","
    emit_kv_str "distribution_version" "$dist_ver" ","
    emit_kv_str "patch_level" "$patch" ","
    emit_kv_num "pending_updates" "$pending"
    emit '  },'
}

collect_packages() {
    local count
    count=$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | wc -l || true)
    if [[ -z "$count" || "$count" == "0" ]]; then
        record_error "packages: dpkg-query returned no rows"
    fi

    emit '  "packages": {'
    emit_kv_str "source" "dpkg-query -W" ","
    emit_kv_num "count" "$count"
    emit '  },'
}

collect_sockets() {
    local raw line first=1
    local netid state rq sq local_ep peer_ep proc addr port pname pid

    raw=$(ss -tulnpH 2>/dev/null || true)
    if [[ -z "$raw" ]]; then
        record_error "listening_sockets: ss returned no rows"
    fi

    emit '  "listening_sockets": ['
    while IFS= read -r line; do
        if [[ -z "${line// /}" ]]; then
            continue
        fi
        read -r netid state rq sq local_ep peer_ep proc <<<"$line"
        addr=${local_ep%:*}
        port=${local_ep##*:}
        pname=$(printf '%s' "${proc-}" |
            sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p')
        pid=$(printf '%s' "${proc-}" |
            sed -n 's/.*pid=\([0-9]\{1,\}\).*/\1/p' | head -n 1)

        if [[ "$first" -eq 0 ]]; then
            emit '    ,'
        fi
        first=0
        emit '    {'
        emit "      $(jstr "protocol"): $(jstr "$netid"),"
        emit "      $(jstr "state"): $(jstr "$state"),"
        emit "      $(jstr "recv_queue"): $(jnum "$rq"),"
        emit "      $(jstr "send_queue"): $(jnum "$sq"),"
        emit "      $(jstr "local_address"): $(jstr "$addr"),"
        emit "      $(jstr "local_port"): $(jstr "$port"),"
        emit "      $(jstr "peer_address"): $(jstr "$peer_ep"),"
        emit "      $(jstr "process_name"): $(jstr "$pname"),"
        emit "      $(jstr "process_id"): $(jnum "$pid")"
        emit '    }'
    done <<<"$raw"
    emit '  ],'
}

collect_services() {
    local raw line first=1 unit load active sub running_count enabled_count
    raw=$(systemctl list-units --type=service --state=active \
        --no-legend --no-pager --plain 2>/dev/null || true)
    if [[ -z "$raw" ]]; then
        record_error "services: systemctl returned no active units"
    fi

    running_count=$(printf '%s\n' "$raw" | grep -c 'running' || true)
    enabled_count=$(systemctl list-unit-files --type=service --state=enabled \
        --no-legend --no-pager 2>/dev/null | wc -l || true)

    emit '  "services": {'
    emit_kv_num "active_count" "$(printf '%s\n' "$raw" | grep -c '\.service' || true)" ","
    emit_kv_num "running_count" "$running_count" ","
    emit_kv_num "enabled_unit_files" "$enabled_count" ","
    emit '    "units": ['
    while IFS= read -r line; do
        if [[ -z "${line// /}" ]]; then
            continue
        fi
        read -r unit load active sub _ <<<"$line"
        if [[ "$first" -eq 0 ]]; then
            emit '      ,'
        fi
        first=0
        emit '      {'
        emit "        $(jstr "unit"): $(jstr "$unit"),"
        emit "        $(jstr "load"): $(jstr "$load"),"
        emit "        $(jstr "active"): $(jstr "$active"),"
        emit "        $(jstr "sub"): $(jstr "$sub")"
        emit '      }'
    done <<<"$raw"
    emit '    ]'
    emit '  },'
}

collect_sshd_config() {
    local raw source key value first=1 sorted
    source="none"

    if command -v sshd >/dev/null 2>&1 && [[ "$PRIVILEGED" == "true" ]]; then
        raw=$(sshd -T 2>/dev/null || true)
        if [[ -n "$raw" ]]; then
            source="sshd -T (effective)"
        fi
    fi

    if [[ -z "${raw:-}" && -r /etc/ssh/sshd_config ]]; then
        raw=$(grep -vE '^\s*(#|$)' /etc/ssh/sshd_config 2>/dev/null || true)
        if [[ -n "$raw" ]]; then
            source="/etc/ssh/sshd_config (declared)"
        fi
    fi

    if [[ -z "${raw:-}" ]]; then
        record_error "sshd_config: no effective or declared configuration readable"
        raw=""
    fi

    # Normalise to "key<TAB>value", lower-case the key, fold duplicate keys
    # into one comma-joined value so the record stays a flat key-value map.
    sorted=$(printf '%s\n' "$raw" |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]\{1,\}/ /g' |
        awk 'NF>0 {k=tolower($1); $1=""; sub(/^ /,""); v[k]=(k in v)?v[k]", "$0:$0}
             END {for (k in v) print k"\t"v[k]}' |
        LC_ALL=C sort)

    emit '  "sshd_config": {'
    emit_kv_str "source" "$source" ","
    emit '    "settings": {'
    while IFS=$'\t' read -r key value; do
        if [[ -z "$key" ]]; then
            continue
        fi
        if [[ "$first" -eq 0 ]]; then
            emit '      ,'
        fi
        first=0
        emit "      $(jstr "$key"): $(jstr "$value")"
    done <<<"$sorted"
    emit '    }'
    emit '  },'
}

collect_sysctl() {
    local key value first=1
    local keys=(
        fs.protected_hardlinks
        fs.protected_symlinks
        fs.suid_dumpable
        kernel.dmesg_restrict
        kernel.kptr_restrict
        kernel.randomize_va_space
        kernel.sysrq
        kernel.unprivileged_bpf_disabled
        kernel.yama.ptrace_scope
        net.ipv4.conf.all.accept_redirects
        net.ipv4.conf.all.accept_source_route
        net.ipv4.conf.all.log_martians
        net.ipv4.conf.all.rp_filter
        net.ipv4.conf.all.send_redirects
        net.ipv4.conf.default.accept_redirects
        net.ipv4.conf.default.accept_source_route
        net.ipv4.conf.default.send_redirects
        net.ipv4.icmp_echo_ignore_broadcasts
        net.ipv4.ip_forward
        net.ipv4.tcp_syncookies
        net.ipv6.conf.all.accept_ra
        net.ipv6.conf.all.accept_redirects
        net.ipv6.conf.all.disable_ipv6
    )

    emit '  "sysctl_security": {'
    for key in "${keys[@]}"; do
        if command -v sysctl >/dev/null 2>&1; then
            value=$(sysctl -n "$key" 2>/dev/null || true)
        elif [[ -r "/proc/sys/${key//./\/}" ]]; then
            value=$(cat "/proc/sys/${key//./\/}" 2>/dev/null || true)
        else
            value=""
        fi
        if [[ "$first" -eq 0 ]]; then
            emit '    ,'
        fi
        first=0
        if [[ -z "$value" ]]; then
            emit "    $(jstr "$key"): null"
        else
            emit "    $(jstr "$key"): $(jstr "$value")"
        fi
    done
    emit '  },'
}

collect_file_permissions() {
    local suid sgid both world
    both=$(find / -perm /6000 -type f 2>/dev/null | wc -l || true)
    suid=$(find / -perm -4000 -type f 2>/dev/null | wc -l || true)
    sgid=$(find / -perm -2000 -type f 2>/dev/null | wc -l || true)
    world=$(find / -perm -0002 -type f \
        -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | wc -l || true)

    if [[ "$PRIVILEGED" != "true" ]]; then
        record_error "file_permissions: unprivileged run, counts are a lower bound"
    fi

    emit '  "file_permissions": {'
    emit_kv_str "suid_sgid_source" "find / -perm /6000 -type f" ","
    emit_kv_num "suid_sgid_count" "$both" ","
    emit_kv_num "suid_count" "$suid" ","
    emit_kv_num "sgid_count" "$sgid" ","
    emit_kv_str "world_writable_source" "find / -perm -0002 -type f (excluding /proc,/sys)" ","
    emit_kv_num "world_writable_count" "$world"
    emit '  },'
}

collect_firewall() {
    local ruleset="" bytes=0 lines=0 tables=0 backend="none" active="false"
    local iptables_rules=""

    if command -v nft >/dev/null 2>&1; then
        backend="nftables"
        ruleset=$(nft list ruleset 2>/dev/null || true)
        bytes=${#ruleset}
        if [[ -n "$ruleset" ]]; then
            lines=$(printf '%s\n' "$ruleset" | wc -l)
            tables=$(printf '%s\n' "$ruleset" | grep -c '^table ' || true)
            active="true"
        fi
        if [[ "$PRIVILEGED" != "true" ]]; then
            record_error "firewall: unprivileged run, nft ruleset may read as empty"
        fi
    else
        record_error "firewall: nft not installed"
    fi

    if command -v iptables-save >/dev/null 2>&1; then
        iptables_rules=$(iptables-save 2>/dev/null | grep -c '^-A ' || true)
    fi

    emit '  "firewall": {'
    emit_kv_str "backend" "$backend" ","
    emit "    $(jstr "active"): $(jbool "$active"),"
    emit_kv_num "ruleset_bytes" "$bytes" ","
    emit_kv_num "ruleset_lines" "$lines" ","
    emit_kv_num "table_count" "$tables" ","
    emit_kv_num "iptables_rule_count" "$iptables_rules"
    emit '  },'
}

emit_telemetry_agent() {
    # emit_telemetry_agent <json-key> <unit> <trailing-comma>
    local key="$1" unit="$2" trail="${3-}"
    local present active enabled
    present=$(unit_present "$unit")
    active=$(unit_is "$unit" is-active)
    enabled=$(unit_is "$unit" is-enabled)

    emit "    $(jstr "$key"): {"
    emit "      $(jstr "unit"): $(jstr "$unit"),"
    emit "      $(jstr "present"): $present,"
    emit "      $(jstr "running"): $(jbool "$([[ "$active" == "active" ]] && echo true || echo false)"),"
    emit "      $(jstr "active_state"): $(jstr "$active"),"
    emit "      $(jstr "enabled_state"): $(jstr "$enabled")"
    emit "    }${trail}"
}

collect_telemetry() {
    local sysmon_present="false" sysmon_version="" sysmon_config=""

    if dpkg-query -W -f='${Version}' sysmonforlinux >/dev/null 2>&1; then
        sysmon_present="true"
        sysmon_version=$(dpkg-query -W -f='${Version}' sysmonforlinux 2>/dev/null || true)
    elif command -v sysmon >/dev/null 2>&1; then
        sysmon_present="true"
    fi

    for sysmon_config in /etc/sysmon/config.xml /opt/sysmon/config.xml; do
        if [[ -r "$sysmon_config" ]]; then
            break
        fi
        sysmon_config=""
    done

    emit '  "telemetry": {'
    emit_telemetry_agent "auditd" "auditd.service" ","
    emit_telemetry_agent "rsyslog" "rsyslog.service" ","
    emit "    $(jstr "sysmon_linux"): {"
    emit "      $(jstr "present"): $(jbool "$sysmon_present"),"
    emit "      $(jstr "version"): $(jstr "$sysmon_version"),"
    emit "      $(jstr "config_path"): $(jstr "$sysmon_config"),"
    emit "      $(jstr "active_state"): $(jstr "$(unit_is sysmon.service is-active)")"
    emit '    }'
    emit '  },'

    if [[ "$(unit_is auditd.service is-active)" != "active" ]]; then
        record_error "telemetry: auditd is not active on this host"
    fi
}

collect_errors_block() {
    local i first=1
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
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local opt hn out_dir out_file collected_at

    while getopts ":o:uh" opt; do
        case "$opt" in
            o) OUTPUT_ROOT="$OPTARG" ;;
            u) ALLOW_UNPRIVILEGED=1 ;;
            h)
                usage
                exit "$EXIT_OK"
                ;;
            \?)
                log "ERROR unknown option: -$OPTARG"
                usage >&2
                exit "$EXIT_ENV"
                ;;
            :)
                log "ERROR option -$OPTARG requires an argument"
                exit "$EXIT_ENV"
                ;;
            *)
                exit "$EXIT_ENV"
                ;;
        esac
    done

    if ! require_cmd uname date find awk sed grep tr wc dpkg-query ss systemctl; then
        log "ERROR environment does not meet the minimum dependency set"
        exit "$EXIT_ENV"
    fi

    if [[ "$(id -u)" -eq 0 ]]; then
        PRIVILEGED="true"
    elif [[ "$ALLOW_UNPRIVILEGED" -eq 1 ]]; then
        record_error "run is unprivileged, record is a lower bound only"
    else
        log "ERROR must run as root; re-run with sudo, or pass -u to accept a degraded record"
        exit "$EXIT_ENV"
    fi

    hn=$(get_hostname)
    out_dir="${OUTPUT_ROOT}/${ARTIFACT_SUBDIR}/${hn}"
    out_file="${out_dir}/${RECORD_BASENAME}"

    if ! mkdir -p "$out_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $out_dir"
        exit "$EXIT_ENV"
    fi
    if [[ ! -w "$out_dir" ]]; then
        log "ERROR output directory is not writable: $out_dir"
        exit "$EXIT_ENV"
    fi

    TMP_JSON=$(mktemp "${out_dir}/.intake.XXXXXX") || {
        log "ERROR cannot create temporary file in $out_dir"
        exit "$EXIT_ENV"
    }

    collected_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    log "INFO  starting intake on $hn (privileged=$PRIVILEGED)"

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "phase"): $(jstr "$PHASE"),"
    emit "  $(jstr "platform"): $(jstr "linux"),"
    emit "  $(jstr "collected_at_utc"): $(jstr "$collected_at"),"
    emit '  "collector": {'
    emit_kv_str "script" "$SCRIPT_NAME" ","
    emit_kv_str "version" "$SCRIPT_VERSION" ","
    emit "    $(jstr "privileged"): $(jbool "$PRIVILEGED")"
    emit '  },'

    collect_host
    collect_packages
    collect_sockets
    collect_services
    collect_sshd_config
    collect_sysctl
    collect_file_permissions
    collect_firewall
    collect_telemetry
    collect_errors_block
    emit '}'

    # Atomic replace: a concurrent or repeated run never leaves a partial record.
    chmod 0640 "$TMP_JSON"
    mv -f "$TMP_JSON" "$out_file"
    TMP_JSON=""

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$out_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
    else
        record_error "integrity: sha256sum unavailable, no digest written"
    fi

    log "INFO  intake record written to $out_file"
    printf '%s\n' "$out_file"

    if [[ "${#COLLECTION_ERRORS[@]}" -gt 0 ]]; then
        log "WARN  ${#COLLECTION_ERRORS[@]} collector(s) degraded; see .collection_errors"
        exit "$EXIT_FAIL"
    fi
    exit "$EXIT_OK"
}

main "$@"
