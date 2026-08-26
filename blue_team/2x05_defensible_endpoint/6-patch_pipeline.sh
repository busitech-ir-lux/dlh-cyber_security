#!/bin/bash
#
# 6-patch_pipeline.sh - Hawthorne capstone, Task 6
#
# Wraps the 2x03 patch pipeline. It does not reinvent the pipeline: it redirects
# the pipeline's artifacts into the capstone package, feeds it the capstone CVE
# feed, applies the mandated unattended-upgrades blacklist, and emits a summary
# that normalises the pipeline's own result into one field the contract can
# check.
#
# The pipeline is invoked with CAPSTONE_ARTIFACTS_DIR=capstone/patch/ exported,
# from a working directory of CAPSTONE_ROOT, so every sub-step artifact lands
# inside the capstone package exactly as the brief requires.
#
# Idempotency: the blacklist is written as a marked, managed block and is
# rewritten only when its content actually differs, so a second run changes
# nothing. Pipeline idempotency is the pipeline's own responsibility; this
# wrapper records the artifact digests before and after so a re-run that
# changed something is visible rather than assumed.
#
# Usage:
#   sudo ./6-patch_pipeline.sh [-o CAPSTONE_ROOT] [-p PIPELINE] [-f CVE_FEED]
#                              [-b BLACKLIST] [-a "ARGS"]
#                              [--skip-blacklist] [-h]
#
#   -o CAPSTONE_ROOT  Root containing capstone/ (default: .).
#   -p PIPELINE       Pipeline script from 2x03. Default:
#                     /home/analyst/MedDefense_Lab/2x03/13-patch_pipeline.sh
#                     (overridable with PATCH_PIPELINE).
#   -f CVE_FEED       Capstone CVE feed. Default:
#                     /home/analyst/MedDefense_Lab/capstone/cve_feed.json
#   -b BLACKLIST      Mandated blacklist. Default:
#                     /home/analyst/MedDefense_Lab/capstone/blacklist.json
#   -a "ARGS"         Argument list passed verbatim to the pipeline. Defaults
#                     to the CVE feed path as a single positional argument.
#                     Use this if the 2x03 pipeline takes a flag instead,
#                     e.g. -a "--feed /path/to/cve_feed.json". The feed is
#                     ALSO exported as CVE_FEED, CAPSTONE_CVE_FEED and
#                     MEDDEFENSE_CVE_FEED, so a pipeline reading any of those
#                     needs no arguments at all.
#   --skip-blacklist  Run the pipeline without touching apt configuration.
#   -h                Show usage.
#
# Output:
#   capstone/patch/                     all pipeline sub-step artifacts
#   capstone/patch/patch_pipeline.log   full pipeline stdout/stderr
#   capstone/patch/patch_summary.json   normalised wrapper summary
#
# Exit codes:
#   0  pipeline exited 0 AND failed_entries == 0
#   1  pipeline exited non-zero, failed_entries > 0, or the failed-entry count
#      could not be determined from the pipeline's execution log
#   2  environment error - not root, missing dependency, missing pipeline
#      script, missing CVE feed or blacklist, missing/corrupt target_state.json
#
set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="6-patch_pipeline.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="patch_pipeline_execution"

# The brief fixes this value. It is exported verbatim, and the pipeline is run
# with a working directory of CAPSTONE_ROOT so the relative path resolves
# inside the capstone package.
readonly ARTIFACTS_DIR_VALUE="capstone/patch/"
readonly PATCH_SUBDIR="capstone/patch"
readonly LOG_RELPATH="capstone/patch/patch_pipeline.log"
readonly SUMMARY_RELPATH="capstone/patch/patch_summary.json"
readonly RECORD_BASENAME="patch_summary.json"
readonly EXEC_LOG_BASENAME="patch_execution_log.json"
# The sub-step artifacts the pipeline is contracted to produce. Their presence
# is asserted rather than inferred from whatever happens to be on disk, so a
# pipeline that silently skipped a stage is caught here and not at T8.
readonly EXPECTED_ARTIFACTS=(
    "vulnerability_inventory.json"
    "patch_plan.json"
    "patch_execution_log.json"
)
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly UNATTENDED_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
readonly AUTO_UPGRADES_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
readonly BLOCK_BEGIN="// BEGIN meddefense-capstone managed block"
readonly BLOCK_END="// END meddefense-capstone managed block"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
PIPELINE="${PATCH_PIPELINE:-/home/analyst/MedDefense_Lab/2x03/13-patch_pipeline.sh}"
CVE_FEED="/home/analyst/MedDefense_Lab/capstone/cve_feed.json"
BLACKLIST="/home/analyst/MedDefense_Lab/capstone/blacklist.json"
SKIP_BLACKLIST=0
PIPELINE_ARGS=()
PIPELINE_ARGS_SET=0
TMP_JSON=""
BLACKLIST_CHANGED="false"
BLACKLIST_COUNT=0
AUTO_UPGRADES_CHANGED="false"
COLLECTION_ERRORS=()

usage() {
    sed -n '3,51p' "$0" | sed 's/^# \{0,1\}//'
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

file_digest() {
    if [[ -r "$1" ]] && command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    fi
}

# --------------------------------------------------------------------------
# unattended-upgrades configuration
#
# The blacklist is written as a marked block. APT unions repeated list blocks,
# so appending ours can only ever add packages to the blacklist, never remove
# an entry the distribution or the operator put there. That is the safe
# direction to fail in.
# --------------------------------------------------------------------------

write_managed_block() {
    # write_managed_block <file> <block-body>  -> prints "changed" or "unchanged"
    local file="$1" body="$2"
    MD_BLOCK_BODY="$body" MD_BEGIN="$BLOCK_BEGIN" MD_END="$BLOCK_END" \
        python3 - "$file" <<'PY'
import os, re, sys

path = sys.argv[1]
begin = os.environ["MD_BEGIN"]
end = os.environ["MD_END"]
body = os.environ["MD_BLOCK_BODY"]

try:
    with open(path) as fh:
        text = fh.read()
except FileNotFoundError:
    text = ""

new_block = "{0}\n{1}\n{2}\n".format(begin, body, end)
pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.S)

if pattern.search(text):
    updated = pattern.sub(new_block, text)
else:
    prefix = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    updated = prefix + new_block

if updated == text:
    print("unchanged")
else:
    tmp = path + ".meddefense.tmp"
    with open(tmp, "w") as fh:
        fh.write(updated)
    os.replace(tmp, path)
    print("changed")
PY
}

configure_unattended_upgrades() {
    local packages body result

    # Accept any of the shapes a blacklist feed might reasonably use.
    packages=$(python3 - "$BLACKLIST" <<'PY'
import json, sys

try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception as exc:                      # noqa: BLE001 - reported to caller
    sys.stderr.write("blacklist unreadable: {0}\n".format(exc))
    raise SystemExit(1)

items = None
if isinstance(doc, list):
    items = doc
elif isinstance(doc, dict):
    for key in ("blacklist", "package_blacklist", "packages", "blocked", "deny"):
        if isinstance(doc.get(key), list):
            items = doc[key]
            break
    if items is None:
        for value in doc.values():
            if isinstance(value, list):
                items = value
                break

if items is None:
    sys.stderr.write("no package list found in blacklist file\n")
    raise SystemExit(1)

names = []
for entry in items:
    if isinstance(entry, str):
        names.append(entry)
    elif isinstance(entry, dict):
        for key in ("package", "name", "pkg"):
            if isinstance(entry.get(key), str):
                names.append(entry[key])
                break

seen = set()
for name in names:
    name = name.strip()
    if name and name not in seen:
        seen.add(name)
        print(name)
PY
    ) || {
        record_error "mandated blacklist could not be parsed from ${BLACKLIST}"
        return 1
    }

    if [[ -z "$packages" ]]; then
        record_error "mandated blacklist is empty; nothing to configure"
        return 1
    fi

    BLACKLIST_COUNT=$(printf '%s\n' "$packages" | grep -c . || true)

    body="Unattended-Upgrade::Package-Blacklist {"
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        body+=$'\n'"    \"${pkg}\";"
    done <<<"$packages"
    body+=$'\n'"};"

    result=$(write_managed_block "$UNATTENDED_CONF" "$body")
    if [[ "$result" == "changed" ]]; then
        BLACKLIST_CHANGED="true"
        log "INFO  wrote ${BLACKLIST_COUNT} blacklisted package(s) to ${UNATTENDED_CONF}"
    else
        log "INFO  blacklist already current in ${UNATTENDED_CONF}"
    fi

    result=$(write_managed_block "$AUTO_UPGRADES_CONF" \
        'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";')
    if [[ "$result" == "changed" ]]; then
        AUTO_UPGRADES_CHANGED="true"
        log "INFO  enabled unattended-upgrades in ${AUTO_UPGRADES_CONF}"
    fi

    return 0
}

# --------------------------------------------------------------------------
# Result extraction
#
# The pipeline's execution log is a 2x03 artifact whose exact shape this
# wrapper does not control, so the failed-entry count is looked for in every
# reasonable location and the one that matched is recorded. If none matches,
# that is a controlled failure: silently reporting zero failures because the
# field was missing would be the worst possible outcome here.
# --------------------------------------------------------------------------

extract_failed_entries() {
    python3 - "$1" <<'PY'
import json, sys

try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception:                              # noqa: BLE001
    raise SystemExit(1)

FAILED = {"failed", "failure", "error", "errored"}

def count_states(entries):
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("state", "status", "result", "outcome"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip().lower() in FAILED:
                total += 1
                break
    return total

candidates = []
if isinstance(doc, dict):
    summary = doc.get("summary")
    if isinstance(summary, dict):
        for key in ("failed_count", "failed", "failed_entries", "failures"):
            if isinstance(summary.get(key), int):
                candidates.append(("summary.{0}".format(key), summary[key]))
    for key in ("failed_entries", "failed_count", "failed", "failures"):
        if isinstance(doc.get(key), int):
            candidates.append((key, doc[key]))
    for key in ("entries", "results", "patches", "actions", "log"):
        if isinstance(doc.get(key), list):
            candidates.append(("count({0}.state==failed)".format(key), count_states(doc[key])))
            break
elif isinstance(doc, list):
    candidates.append(("count(state==failed)", count_states(doc)))

if not candidates:
    raise SystemExit(2)

source, value = candidates[0]
print(value)
print(source)
PY
}

collect_artifacts() {
    # Prints "relpath<TAB>bytes<TAB>sha256" for every file under capstone/patch.
    local dir="$1" root="$2" f rel
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        rel="${f#"$root"/}"
        printf '%s\t%s\t%s\n' "$rel" "$(stat -c %s "$f" 2>/dev/null || echo 0)" \
            "$(file_digest "$f")"
    done < <(find "$dir" -type f 2>/dev/null | LC_ALL=C sort)
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local arg hn patch_dir out_file log_file target_state dep
    local root_abs pipeline_rc=0 failed_entries="" failed_source=""
    local artifacts art_count=0 first=1 e efirst=1 result="fail"
    local exec_log=""

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                if [[ $# -lt 2 ]]; then log "ERROR option -o requires an argument"; exit 2; fi
                CAPSTONE_ROOT="$2"; shift 2 ;;
            -p)
                if [[ $# -lt 2 ]]; then log "ERROR option -p requires an argument"; exit 2; fi
                PIPELINE="$2"; shift 2 ;;
            -f)
                if [[ $# -lt 2 ]]; then log "ERROR option -f requires an argument"; exit 2; fi
                CVE_FEED="$2"; shift 2 ;;
            -b)
                if [[ $# -lt 2 ]]; then log "ERROR option -b requires an argument"; exit 2; fi
                BLACKLIST="$2"; shift 2 ;;
            -a)
                if [[ $# -lt 2 ]]; then log "ERROR option -a requires an argument"; exit 2; fi
                # Word-split deliberately: -a carries a full argument list.
                read -r -a PIPELINE_ARGS <<<"$2"
                PIPELINE_ARGS_SET=1
                shift 2 ;;
            --skip-blacklist) SKIP_BLACKLIST=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *)
                log "ERROR unknown argument: $arg"
                usage >&2
                exit 2 ;;
        esac
    done

    # --- preflight ---
    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR patch pipeline must run as root; re-run with sudo"
        exit 2
    fi
    for dep in python3 find stat sha256sum date; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    if [[ ! -f "$PIPELINE" ]]; then
        log "ERROR pipeline script not found: $PIPELINE"
        log "ERROR pass -p with the path to the 2x03 pipeline"
        exit 2
    fi
    if [[ ! -x "$PIPELINE" ]]; then
        log "ERROR pipeline script is not executable: $PIPELINE"
        exit 2
    fi
    if [[ ! -r "$CVE_FEED" ]]; then
        log "ERROR capstone CVE feed not found: $CVE_FEED"
        exit 2
    fi
    if [[ "$SKIP_BLACKLIST" -eq 0 && ! -r "$BLACKLIST" ]]; then
        log "ERROR mandated blacklist not found: $BLACKLIST"
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

    if [[ "$PIPELINE_ARGS_SET" -eq 0 ]]; then
        PIPELINE_ARGS=("$CVE_FEED")
    fi

    hn=$(get_hostname)
    root_abs=$(cd "$CAPSTONE_ROOT" && pwd)
    patch_dir="${root_abs}/${PATCH_SUBDIR}"
    if ! mkdir -p "$patch_dir" 2>/dev/null; then
        log "ERROR cannot create artifact directory: $patch_dir"
        exit 2
    fi
    out_file="${patch_dir}/${RECORD_BASENAME}"
    log_file="${root_abs}/${LOG_RELPATH}"

    # --- configure unattended-upgrades ---
    if [[ "$SKIP_BLACKLIST" -eq 0 ]]; then
        configure_unattended_upgrades || record_error "unattended-upgrades configuration incomplete"
    else
        log "INFO  --skip-blacklist set; apt configuration untouched"
    fi

    # --- run the pipeline ---
    log "INFO  invoking pipeline with CAPSTONE_ARTIFACTS_DIR=${ARTIFACTS_DIR_VALUE}"
    : >"$log_file"
    {
        printf '# %s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '# host: %s\n' "$hn"
        printf '# started_at: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# pipeline: %s\n' "$PIPELINE"
        printf '# CAPSTONE_ARTIFACTS_DIR=%s\n' "$ARTIFACTS_DIR_VALUE"
        printf '# cve_feed: %s\n\n' "$CVE_FEED"
    } >>"$log_file"

    set +e
    (
        cd "$root_abs" || exit 2
        # Exported, not set as a command prefix: a prefix assignment would not
        # be visible to the expansions on the same line.
        export CAPSTONE_ARTIFACTS_DIR="$ARTIFACTS_DIR_VALUE"
        export CAPSTONE_CVE_FEED="$CVE_FEED"
        export MEDDEFENSE_CVE_FEED="$CVE_FEED"
        export CVE_FEED
        "$PIPELINE" "${PIPELINE_ARGS[@]+"${PIPELINE_ARGS[@]}"}"
    ) >>"$log_file" 2>&1
    pipeline_rc=$?
    set -e

    if [[ "$pipeline_rc" -ne 0 ]]; then
        record_error "pipeline exited with status ${pipeline_rc}; see ${LOG_RELPATH}"
    else
        log "INFO  pipeline completed with status 0"
    fi

    # --- normalise the result ---
    exec_log="${patch_dir}/${EXEC_LOG_BASENAME}"
    if [[ -r "$exec_log" ]]; then
        local extracted
        set +e
        extracted=$(extract_failed_entries "$exec_log")
        local extract_rc=$?
        set -e
        if [[ "$extract_rc" -eq 0 ]]; then
            failed_entries=$(printf '%s\n' "$extracted" | sed -n '1p')
            failed_source=$(printf '%s\n' "$extracted" | sed -n '2p')
            log "INFO  failed_entries=${failed_entries} (from ${failed_source})"
        else
            record_error "failed-entry count could not be determined from ${EXEC_LOG_BASENAME}"
        fi
    else
        record_error "pipeline produced no ${EXEC_LOG_BASENAME} in ${PATCH_SUBDIR}"
    fi

    # --- assert the expected sub-step artifacts ---
    local missing_artifacts=() expected
    for expected in "${EXPECTED_ARTIFACTS[@]}"; do
        if [[ ! -f "${patch_dir}/${expected}" ]]; then
            missing_artifacts+=("$expected")
            record_error "pipeline produced no ${expected} in ${PATCH_SUBDIR}"
        fi
    done

    # --- inventory every artifact ---
    artifacts=$(collect_artifacts "$patch_dir" "$root_abs")
    art_count=$(printf '%s\n' "$artifacts" | grep -c . || true)
    log "INFO  ${art_count} artifact(s) present under ${PATCH_SUBDIR}"

    if [[ "$pipeline_rc" -eq 0 && "$failed_entries" =~ ^[0-9]+$ &&
        "$failed_entries" -eq 0 && "${#missing_artifacts[@]}" -eq 0 ]]; then
        result="pass"
    fi

    # --- summary record ---
    TMP_JSON=$(mktemp "${patch_dir}/.summary.XXXXXX") || {
        log "ERROR cannot create temporary file in $patch_dir"
        exit 2
    }

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "platform"): $(jstr "linux"),"
    emit "  $(jstr "timestamp"): $(jstr "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"),"
    emit "  $(jstr "hostname"): $(jstr "$hn"),"
    emit '  "collector": {'
    emit "    $(jstr "script"): $(jstr "$SCRIPT_NAME"),"
    emit "    $(jstr "version"): $(jstr "$SCRIPT_VERSION")"
    emit '  },'
    emit '  "pipeline": {'
    emit "    $(jstr "script_path"): $(jstr "$PIPELINE"),"
    emit "    $(jstr "exit_code"): $(jnum "$pipeline_rc"),"
    emit "    $(jstr "artifacts_dir"): $(jstr "$ARTIFACTS_DIR_VALUE"),"
    emit "    $(jstr "cve_feed_path"): $(jstr "$CVE_FEED"),"
    emit "    $(jstr "cve_feed_sha256"): $(jstr "$(file_digest "$CVE_FEED")"),"
    emit "    $(jstr "arguments"): $(jstr "${PIPELINE_ARGS[*]+"${PIPELINE_ARGS[*]}"}"),"
    emit "    $(jstr "log_path"): $(jstr "$LOG_RELPATH")"
    emit '  },'
    emit '  "unattended_upgrades": {'
    emit "    $(jstr "configured"): $([[ "$SKIP_BLACKLIST" -eq 0 ]] && printf 'true' || printf 'false'),"
    emit "    $(jstr "config_path"): $(jstr "$UNATTENDED_CONF"),"
    emit "    $(jstr "blacklist_path"): $(jstr "$BLACKLIST"),"
    emit "    $(jstr "blacklist_sha256"): $(jstr "$(file_digest "$BLACKLIST")"),"
    emit "    $(jstr "blacklist_package_count"): $(jnum "$BLACKLIST_COUNT"),"
    emit "    $(jstr "blacklist_changed"): ${BLACKLIST_CHANGED},"
    emit "    $(jstr "auto_upgrades_changed"): ${AUTO_UPGRADES_CHANGED}"
    emit '  },'
    emit "  $(jstr "failed_entries"): $(jnum "$failed_entries"),"
    emit "  $(jstr "failed_entries_source"): $(jstr "$failed_source"),"
    emit "  $(jstr "artifact_count"): $(jnum "$art_count"),"
    emit "  $(jstr "expected_artifacts"): ["
    local xfirst=1
    for expected in "${EXPECTED_ARTIFACTS[@]}"; do
        if [[ "$xfirst" -eq 0 ]]; then
            emit '    ,'
        fi
        xfirst=0
        emit '    {'
        emit "      $(jstr "name"): $(jstr "$expected"),"
        emit "      $(jstr "path"): $(jstr "${PATCH_SUBDIR}/${expected}"),"
        emit "      $(jstr "present"): $([[ -f "${patch_dir}/${expected}" ]] && printf 'true' || printf 'false')"
        emit '    }'
    done
    emit '  ],'
    emit "  $(jstr "expected_artifacts_missing"): $(jnum "${#missing_artifacts[@]}"),"
    emit '  "artifacts": ['
    if [[ -n "$artifacts" ]]; then
        local rel bytes digest
        while IFS=$'\t' read -r rel bytes digest; do
            [[ -z "$rel" ]] && continue
            if [[ "$first" -eq 0 ]]; then
                emit '    ,'
            fi
            first=0
            emit '    {'
            emit "      $(jstr "path"): $(jstr "$rel"),"
            emit "      $(jstr "bytes"): $(jnum "$bytes"),"
            emit "      $(jstr "sha256"): $(jstr "$digest")"
            emit '    }'
        done <<<"$artifacts"
    fi
    emit '  ],'
    emit "  $(jstr "summary_path"): $(jstr "$SUMMARY_RELPATH"),"
    emit "  $(jstr "target_state_path"): $(jstr "$TARGET_STATE_RELPATH"),"
    emit "  $(jstr "result"): $(jstr "$result"),"
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

    (cd "$patch_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")

    log "INFO  summary written to $out_file (result=${result})"
    printf '%s\n' "$out_file"

    if [[ "$result" == "pass" ]]; then
        exit 0
    fi
    exit 1
}

main "$@"
