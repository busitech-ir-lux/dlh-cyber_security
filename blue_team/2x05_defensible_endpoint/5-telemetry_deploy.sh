#!/bin/bash
#
# 5-telemetry_deploy.sh - Hawthorne capstone, Task 5 (Linux side)
#
# Deploys the auditd rule set on hawthorne-app-01, runs a controlled sequence
# of authorized test actions, verifies that each one left the expected trace,
# and exports the recent event window as structured JSON.
#
# Safety: every test action uses a run-scoped probe identity (mdprobe<run-id>)
# that cannot collide with a real account, and every action is undone by an
# EXIT trap that fires even when the script fails partway through. The script
# refuses to remove a principal it did not create.
#
# Idempotency: rule deployment writes only when the target content differs, so
# a second run reloads nothing. The test sequence is create-then-remove, so it
# is net-zero by construction: the host ends each run in the state it started.
#
# Usage:
#   sudo ./5-telemetry_deploy.sh [-o CAPSTONE_ROOT] [-r RULES_FILE] [-u UNIT]
#                                [--allow-fallback-rules] [--keep-probe] [-h]
#
#   -o CAPSTONE_ROOT        Root containing capstone/ (default: .).
#   -r RULES_FILE           Project-provided rules source. Default:
#                           /home/analyst/MedDefense_Lab/2x02/meddefense.rules
#   -u UNIT                 systemd unit used for the service-management test
#                           action (default: cron). auditd is refused: it is
#                           the daemon recording the evidence.
#   --allow-fallback-rules  If the project rules file is absent, install a
#                           documented default rule set carrying the required
#                           keys. Recorded as rules_source=fallback.
#   --keep-probe            Skip cleanup. Debugging only.
#   -h                      Show usage.
#
# Output:
#   capstone/telemetry/linux_events.json    last 30 min of auditd + syslog
#   capstone/telemetry/linux_coverage.json  per-action coverage evidence
#
# Exit codes:
#   0  every test action produced its expected record
#   1  one or more actions produced no matching record, or an action failed
#   2  environment error - not root, missing dependency, missing rules source,
#      missing or corrupt target_state.json
#
set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="5-telemetry_deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="telemetry_coverage"

readonly TELEMETRY_SUBDIR="capstone/telemetry"
readonly EVENTS_RELPATH="capstone/telemetry/linux_events.json"
readonly COVERAGE_RELPATH="capstone/telemetry/linux_coverage.json"
readonly RECORD_BASENAME="linux_coverage.json"
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly AUDIT_RULES_TARGET="/etc/audit/rules.d/meddefense.rules"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
RULES_SOURCE="${RULES_SOURCE:-/home/analyst/MedDefense_Lab/2x02/meddefense.rules}"
PROBE_UNIT="cron"
ALLOW_FALLBACK=0
KEEP_PROBE=0
TMP_JSON=""
RUN_ID=""
PROBE_USER=""
PROBE_CRON=""
PROBE_CREATED=0
CRON_CREATED=0
RULES_SOURCE_KIND="project"
RULES_CHANGED="false"
RULES_LOADED=0
COLLECTION_ERRORS=()

ACT_NAME=()
ACT_DESC=()
ACT_CMD=()
ACT_KEY=()
ACT_RC=()
ACT_COUNT=()
ACT_FIRST=()
ACT_VERIFIED=()
ACT_NOTE=()

usage() {
    sed -n '3,41p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

record_error() {
    COLLECTION_ERRORS+=("$1")
    log "WARN  $1"
}

# shellcheck disable=SC2317  # every command below runs via the EXIT trap
cleanup() {
    local rc=$?
    if [[ -n "$TMP_JSON" && -f "$TMP_JSON" ]]; then
        rm -f "$TMP_JSON"
    fi
    if [[ "$KEEP_PROBE" -eq 1 ]]; then
        return "$rc"
    fi
    if [[ "$CRON_CREATED" -eq 1 && -n "$PROBE_CRON" && -f "$PROBE_CRON" ]]; then
        rm -f "$PROBE_CRON"
        log "INFO  cleanup: removed $PROBE_CRON"
    fi
    if [[ "$PROBE_CREATED" -eq 1 && -n "$PROBE_USER" ]] && id -u "$PROBE_USER" >/dev/null 2>&1; then
        userdel "$PROBE_USER" >/dev/null 2>&1 ||
            log "WARN  cleanup: could not remove probe user $PROBE_USER"
        log "INFO  cleanup: removed probe user $PROBE_USER"
    fi
    return "$rc"
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

fallback_rules() {
    cat <<'RULES'
## MedDefense capstone auditd rules (fallback set)
## Installed by 5-telemetry_deploy.sh when the project rules file is absent.
## The keys here must match the coverage verification in the same script.

## User and group management
-w /etc/passwd -p wa -k meddefense-user-mgmt
-w /etc/shadow -p wa -k meddefense-user-mgmt
-w /etc/group -p wa -k meddefense-user-mgmt
-w /etc/gshadow -p wa -k meddefense-user-mgmt
-a always,exit -F path=/usr/sbin/useradd -F perm=x -k meddefense-user-mgmt
-a always,exit -F path=/usr/sbin/userdel -F perm=x -k meddefense-user-mgmt
-a always,exit -F path=/usr/sbin/usermod -F perm=x -k meddefense-user-mgmt

## Service management
-a always,exit -F path=/usr/bin/systemctl -F perm=x -k meddefense-svc-mgmt
-a always,exit -F path=/bin/systemctl -F perm=x -k meddefense-svc-mgmt

## Scheduled task management
-w /etc/crontab -p wa -k meddefense-cron
-w /etc/cron.d -p wa -k meddefense-cron
-w /etc/cron.daily -p wa -k meddefense-cron
-w /var/spool/cron -p wa -k meddefense-cron

## Privileged command execution
-a always,exit -F path=/usr/bin/find -F perm=x -k meddefense-priv-cmd
-a always,exit -F path=/bin/find -F perm=x -k meddefense-priv-cmd
RULES
}

deploy_rules() {
    local staged changed="false" loaded
    staged=$(mktemp)

    if [[ -r "$RULES_SOURCE" ]]; then
        cat "$RULES_SOURCE" >"$staged"
        RULES_SOURCE_KIND="project"
    else
        fallback_rules >"$staged"
        RULES_SOURCE_KIND="fallback"
        record_error "project rules file not found at ${RULES_SOURCE}; installed the documented fallback set"
    fi

    # Idempotent write: only touch the file when the content actually differs.
    if [[ -f "$AUDIT_RULES_TARGET" ]] && cmp -s "$staged" "$AUDIT_RULES_TARGET"; then
        log "INFO  audit rules already current at $AUDIT_RULES_TARGET"
    else
        install -m 0640 "$staged" "$AUDIT_RULES_TARGET"
        changed="true"
        log "INFO  installed audit rules to $AUDIT_RULES_TARGET"
    fi
    rm -f "$staged"

    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl enable --now auditd >/dev/null 2>&1 ||
            service auditd start >/dev/null 2>&1 ||
            record_error "auditd could not be started"
    fi

    # Load regardless of whether the file changed: the kernel rule set can be
    # empty after a reboot even when the file on disk is already correct.
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || record_error "augenrules --load reported a problem"
    else
        auditctl -R "$AUDIT_RULES_TARGET" >/dev/null 2>&1 ||
            record_error "auditctl -R reported a problem"
    fi

    loaded=$(auditctl -l 2>/dev/null | grep -c 'meddefense' || true)
    if [[ "$loaded" -eq 0 ]]; then
        record_error "no meddefense rules are loaded in the running kernel"
    else
        log "INFO  ${loaded} meddefense rule(s) loaded, rules_changed=${changed}"
    fi
    RULES_CHANGED="$changed"
    RULES_LOADED="$loaded"
}

record_action() {
    ACT_NAME+=("$1")
    ACT_DESC+=("$2")
    ACT_CMD+=("$3")
    ACT_KEY+=("$4")
    ACT_RC+=("$5")
    ACT_NOTE+=("${6-}")
}

run_test_sequence() {
    local rc=0 cmd

    cmd="useradd -M -s /usr/sbin/nologin ${PROBE_USER}"
    set +e
    useradd -M -s /usr/sbin/nologin "$PROBE_USER" >/dev/null 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then PROBE_CREATED=1; fi
    record_action "create_user" "create a user" "$cmd" "meddefense-user-mgmt" "$rc" ""

    cmd="userdel ${PROBE_USER}"
    set +e
    userdel "$PROBE_USER" >/dev/null 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then PROBE_CREATED=0; fi
    record_action "remove_user" "remove the user" "$cmd" "meddefense-user-mgmt" "$rc" ""

    cmd="systemctl restart ${PROBE_UNIT}"
    set +e
    systemctl restart "$PROBE_UNIT" >/dev/null 2>&1
    rc=$?
    set -e
    record_action "service_action" "run a service management action" "$cmd" \
        "meddefense-svc-mgmt" "$rc" "unit=${PROBE_UNIT}"

    cmd="write ${PROBE_CRON}"
    set +e
    printf '# MedDefense telemetry probe %s\n*/59 * * * * root /bin/true\n' "$RUN_ID" >"$PROBE_CRON" 2>/dev/null
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
        CRON_CREATED=1
        chmod 0644 "$PROBE_CRON"
    fi
    record_action "create_cron" "schedule a cron job" "$cmd" "meddefense-cron" "$rc" ""

    cmd="rm ${PROBE_CRON}"
    set +e
    rm -f "$PROBE_CRON" >/dev/null 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then CRON_CREATED=0; fi
    record_action "remove_cron" "remove it" "$cmd" "meddefense-cron" "$rc" ""

    cmd="find /etc -maxdepth 1 -name os-release -type f"
    set +e
    find /etc -maxdepth 1 -name os-release -type f >/dev/null 2>&1
    rc=$?
    set -e
    record_action "privileged_find" "run a short authorized find as root" "$cmd" \
        "meddefense-priv-cmd" "$rc" ""
}

verify_actions() {
    local i key count first raw start_date start_time

    log "INFO  waiting for auditd to flush before verification"
    sleep 3

    start_date=$(date -d '10 minutes ago' '+%m/%d/%Y' 2>/dev/null || date '+%m/%d/%Y')
    start_time=$(date -d '10 minutes ago' '+%H:%M:%S' 2>/dev/null || echo "00:00:00")

    for i in "${!ACT_NAME[@]}"; do
        key="${ACT_KEY[$i]}"
        count=0
        first=""

        raw=$(ausearch -k "$key" -ts "$start_date" "$start_time" --raw 2>/dev/null || true)
        if [[ -n "$raw" ]]; then
            count=$(printf '%s\n' "$raw" | grep -c "key=\"\?${key}" || true)
            first=$(printf '%s\n' "$raw" | grep -oE 'audit\([0-9]+\.[0-9]+' |
                head -n 1 | grep -oE '[0-9]+\.[0-9]+' || true)
            if [[ -n "$first" ]]; then
                first=$(date -u -d "@${first%%.*}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
            fi
        fi

        ACT_COUNT+=("$count")
        ACT_FIRST+=("$first")
        if [[ "${ACT_RC[$i]}" -eq 0 && "$count" -gt 0 ]]; then
            ACT_VERIFIED+=("true")
            log "INFO  ${ACT_NAME[$i]}: ${count} record(s) under key ${key}"
        else
            ACT_VERIFIED+=("false")
            if [[ "${ACT_RC[$i]}" -ne 0 ]]; then
                log "WARN  ${ACT_NAME[$i]}: action itself failed rc=${ACT_RC[$i]}"
            else
                log "WARN  ${ACT_NAME[$i]}: no auditd record found under key ${key}"
            fi
        fi
    done
}

export_events() {
    local out="$1" hn="$2" since_date since_time audit_raw="" syslog_raw=""
    since_date=$(date -d '30 minutes ago' '+%m/%d/%Y' 2>/dev/null || date '+%m/%d/%Y')
    since_time=$(date -d '30 minutes ago' '+%H:%M:%S' 2>/dev/null || echo "00:00:00")

    audit_raw=$(ausearch -ts "$since_date" "$since_time" --raw 2>/dev/null || true)

    if command -v journalctl >/dev/null 2>&1; then
        syslog_raw=$(journalctl --since '30 minutes ago' -o json --no-pager 2>/dev/null || true)
    elif [[ -r /var/log/syslog ]]; then
        syslog_raw=$(tail -n 5000 /var/log/syslog 2>/dev/null || true)
    fi

    AUDIT_RAW="$audit_raw" SYSLOG_RAW="$syslog_raw" EXPORT_HOST="$hn" \
        EXPORT_SCHEMA="$SCHEMA_VERSION" python3 - "$out" <<'PY'
import json, os, re, sys, datetime

out_path = sys.argv[1]
host = os.environ.get("EXPORT_HOST", "")
schema = os.environ.get("EXPORT_SCHEMA", "1.0")

def iso(epoch):
    return datetime.datetime.fromtimestamp(
        float(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

events = []
audit_re = re.compile(r"type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")
key_re = re.compile(r'key="?([^"\s]+)"?')

for line in os.environ.get("AUDIT_RAW", "").splitlines():
    line = line.strip()
    if not line:
        continue
    m = audit_re.search(line)
    if not m:
        continue
    k = key_re.search(line)
    events.append({
        "source": "auditd",
        "host": host,
        "timestamp": iso(m.group("epoch")),
        "event_type": m.group("type"),
        "serial": m.group("serial"),
        "key": k.group(1) if k else None,
        "raw": line[:4000],
    })

for line in os.environ.get("SYSLOG_RAW", "").splitlines():
    line = line.strip()
    if not line:
        continue
    if line.startswith("{"):
        try:
            j = json.loads(line)
        except ValueError:
            continue
        ts = j.get("__REALTIME_TIMESTAMP")
        try:
            stamp = iso(int(ts) / 1000000) if ts else None
        except (TypeError, ValueError):
            stamp = None
        events.append({
            "source": "syslog",
            "host": j.get("_HOSTNAME", host),
            "timestamp": stamp,
            "event_type": j.get("SYSLOG_IDENTIFIER") or j.get("_COMM"),
            "serial": (j.get("__CURSOR") or "")[:64] or None,
            "key": None,
            "raw": (j.get("MESSAGE") or "")[:4000],
        })
    else:
        events.append({
            "source": "syslog", "host": host, "timestamp": None,
            "event_type": None, "serial": None, "key": None, "raw": line[:4000],
        })

events.sort(key=lambda e: (e["timestamp"] or "", e["source"]))

doc = {
    "schema_version": schema,
    "record_type": "telemetry_export",
    "platform": "linux",
    "hostname": host,
    "generated_at": datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "window_minutes": 30,
    "sources": ["auditd", "syslog"],
    "event_count": len(events),
    "counts_by_source": {
        "auditd": sum(1 for e in events if e["source"] == "auditd"),
        "syslog": sum(1 for e in events if e["source"] == "syslog"),
    },
    "events": events,
}

tmp = out_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
os.replace(tmp, out_path)
print(len(events))
PY
}

main() {
    local arg hn tel_dir out_file events_file target_state dep e
    local i first=1 efirst=1 verified_count=0 failed_count=0 event_count=0

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                if [[ $# -lt 2 ]]; then log "ERROR option -o requires an argument"; exit 2; fi
                CAPSTONE_ROOT="$2"; shift 2 ;;
            -r)
                if [[ $# -lt 2 ]]; then log "ERROR option -r requires an argument"; exit 2; fi
                RULES_SOURCE="$2"; shift 2 ;;
            -u)
                if [[ $# -lt 2 ]]; then log "ERROR option -u requires an argument"; exit 2; fi
                PROBE_UNIT="$2"; shift 2 ;;
            --allow-fallback-rules) ALLOW_FALLBACK=1; shift ;;
            --keep-probe) KEEP_PROBE=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *)
                log "ERROR unknown argument: $arg"
                usage >&2
                exit 2 ;;
        esac
    done

    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR telemetry deployment must run as root; re-run with sudo"
        exit 2
    fi
    for dep in auditctl ausearch systemctl useradd userdel install cmp python3 date; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    # Restarting auditd would discard the very evidence being measured.
    if [[ "$PROBE_UNIT" == "auditd" || "$PROBE_UNIT" == "auditd.service" ]]; then
        log "ERROR auditd cannot be the probe unit: restarting it would discard the evidence"
        exit 2
    fi

    target_state="${CAPSTONE_ROOT}/${TARGET_STATE_RELPATH}"
    if [[ ! -f "$target_state" ]]; then
        log "FATAL target state contract is missing: $target_state (run 2-target_state.sh first)"
        exit 2
    fi
    if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["controls"]' \
        "$target_state" >/dev/null 2>&1; then
        log "FATAL target state contract is corrupt or declares no controls: $target_state"
        exit 2
    fi

    if [[ ! -r "$RULES_SOURCE" && "$ALLOW_FALLBACK" -eq 0 ]]; then
        log "ERROR project rules file not found: $RULES_SOURCE"
        log "ERROR pass -r with the correct path, or --allow-fallback-rules to install the default set"
        exit 2
    fi

    if ! systemctl list-unit-files --no-legend --no-pager 2>/dev/null |
        awk '{print $1}' | grep -qx "${PROBE_UNIT}.service"; then
        log "ERROR probe unit not found: ${PROBE_UNIT}.service (use -u to pick another)"
        exit 2
    fi

    hn=$(get_hostname)
    RUN_ID="$(date -u '+%y%m%d%H%M%S')"
    PROBE_USER="mdprobe${RUN_ID}"
    PROBE_CRON="/etc/cron.d/meddefense-probe-${RUN_ID}"

    if id -u "$PROBE_USER" >/dev/null 2>&1; then
        log "ERROR probe user ${PROBE_USER} already exists; refusing to reuse a real account"
        exit 2
    fi

    tel_dir="${CAPSTONE_ROOT}/${TELEMETRY_SUBDIR}"
    if ! mkdir -p "$tel_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $tel_dir"
        exit 2
    fi
    out_file="${tel_dir}/${RECORD_BASENAME}"
    events_file="${CAPSTONE_ROOT}/${EVENTS_RELPATH}"

    deploy_rules

    log "INFO  running the controlled test sequence (run_id=${RUN_ID})"
    run_test_sequence
    verify_actions

    log "INFO  exporting the last 30 minutes of auditd and syslog records"
    event_count=$(export_events "$events_file" "$hn" || echo 0)
    if [[ ! "$event_count" =~ ^[0-9]+$ ]]; then
        record_error "event export did not report a record count"
        event_count=0
    fi

    for i in "${!ACT_VERIFIED[@]}"; do
        if [[ "${ACT_VERIFIED[$i]}" == "true" ]]; then
            verified_count=$((verified_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    done

    TMP_JSON=$(mktemp "${tel_dir}/.coverage.XXXXXX") || {
        log "ERROR cannot create temporary file in $tel_dir"
        exit 2
    }

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "platform"): $(jstr "linux"),"
    emit "  $(jstr "timestamp"): $(jstr "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"),"
    emit "  $(jstr "hostname"): $(jstr "$hn"),"
    emit "  $(jstr "run_id"): $(jstr "$RUN_ID"),"
    emit '  "collector": {'
    emit "    $(jstr "script"): $(jstr "$SCRIPT_NAME"),"
    emit "    $(jstr "version"): $(jstr "$SCRIPT_VERSION")"
    emit '  },'
    emit '  "deployment": {'
    emit "    $(jstr "rules_path"): $(jstr "$AUDIT_RULES_TARGET"),"
    emit "    $(jstr "rules_source"): $(jstr "$RULES_SOURCE_KIND"),"
    emit "    $(jstr "rules_source_path"): $(jstr "$RULES_SOURCE"),"
    emit "    $(jstr "rules_changed"): ${RULES_CHANGED},"
    emit "    $(jstr "rules_loaded"): $(jnum "$RULES_LOADED"),"
    emit "    $(jstr "auditd_active"): $(systemctl is-active --quiet auditd 2>/dev/null && printf 'true' || printf 'false')"
    emit '  },'
    emit '  "actions": ['
    for i in "${!ACT_NAME[@]}"; do
        if [[ "$first" -eq 0 ]]; then
            emit '    ,'
        fi
        first=0
        emit '    {'
        emit "      $(jstr "action"): $(jstr "${ACT_NAME[$i]}"),"
        emit "      $(jstr "description"): $(jstr "${ACT_DESC[$i]}"),"
        emit "      $(jstr "command"): $(jstr "${ACT_CMD[$i]}"),"
        emit "      $(jstr "exit_code"): $(jnum "${ACT_RC[$i]}"),"
        emit "      $(jstr "expected_source"): $(jstr "auditd"),"
        emit "      $(jstr "expected_selector"): $(jstr "key=${ACT_KEY[$i]}"),"
        emit "      $(jstr "records_found"): $(jnum "${ACT_COUNT[$i]}"),"
        emit "      $(jstr "first_record_time"): $(jstr "${ACT_FIRST[$i]}"),"
        emit "      $(jstr "verified"): ${ACT_VERIFIED[$i]},"
        emit "      $(jstr "notes"): $(jstr "${ACT_NOTE[$i]}")"
        emit '    }'
    done
    emit '  ],'
    emit "  $(jstr "actions_total"): $(jnum "${#ACT_NAME[@]}"),"
    emit "  $(jstr "actions_verified"): $(jnum "$verified_count"),"
    emit "  $(jstr "actions_failed"): $(jnum "$failed_count"),"
    emit "  $(jstr "events_export_path"): $(jstr "$EVENTS_RELPATH"),"
    emit "  $(jstr "events_exported"): $(jnum "$event_count"),"
    emit "  $(jstr "coverage_path"): $(jstr "$COVERAGE_RELPATH"),"
    emit "  $(jstr "target_state_path"): $(jstr "$TARGET_STATE_RELPATH"),"
    emit "  $(jstr "result"): $(jstr "$([[ "$failed_count" -eq 0 ]] && printf 'pass' || printf 'fail')"),"
    emit '  "collection_errors": ['
    if [[ "${#COLLECTION_ERRORS[@]}" -gt 0 ]]; then
        for e in "${COLLECTION_ERRORS[@]}"; do
            if [[ "$efirst" -eq 0 ]]; then
                emit '    ,'
            fi
            efirst=0
            emit "    $(jstr "$e")"
        done
    fi
    emit '  ]'
    emit '}'

    chmod 0640 "$TMP_JSON"
    mv -f "$TMP_JSON" "$out_file"
    TMP_JSON=""

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$tel_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
    fi

    log "INFO  ${verified_count}/${#ACT_NAME[@]} action(s) verified, ${event_count} event(s) exported"
    log "INFO  coverage record written to $out_file"
    printf '%s\n' "$out_file"

    if [[ "$failed_count" -eq 0 ]]; then
        exit 0
    fi
    exit 1
}

main "$@"
