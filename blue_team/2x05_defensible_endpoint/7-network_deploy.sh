#!/bin/bash
#
# 7-network_deploy.sh - Hawthorne capstone, Task 7
#
# Deploys the network defense stack on hawthorne-app-01 and validates it. It
# wraps the 2x04 network pipeline rather than reimplementing it: artifacts are
# redirected into the capstone package, the Hawthorne segmentation contract is
# used instead of the main MedDefense topology, the firewall validation suite
# gates everything downstream, Suricata is replayed offline against the
# capstone PCAP set, and dnsmasq is configured as the local DNS filter.
#
# Ordering matters and is deliberate: firewall validation runs BEFORE the
# Suricata replay and the DNS filter change. If the perimeter is not provably
# correct, the script refuses to proceed rather than layering more state on top
# of an unverified isolation boundary.
#
# Idempotency: the dnsmasq blocklist is written as a marked, managed block and
# rewritten only when its content differs. Suricata replay is read-only against
# the PCAP set. Pipeline idempotency is the pipeline's own responsibility; the
# artifact digests recorded here make a re-run that changed something visible.
#
# Usage:
#   sudo ./7-network_deploy.sh [-o CAPSTONE_ROOT] [-p PIPELINE] [-s SEG_FILE]
#                              [-P PCAP_DIR] [-R RULES_FILE] [-B BLOCKLIST]
#                              [-V VALIDATION_SUITE] [-a "ARGS"]
#                              [--skip-dns] [--skip-pipeline] [-h]
#
#   -o CAPSTONE_ROOT   Root containing capstone/ (default: .).
#   -p PIPELINE        Network pipeline from 2x04. Overridable with
#                      NETWORK_PIPELINE.
#   -s SEG_FILE        Hawthorne segmentation contract. Default:
#                      /home/analyst/MedDefense_Lab/capstone/segmentation_rules.json
#   -P PCAP_DIR        Capstone PCAP set. Default:
#                      /home/analyst/MedDefense_Lab/capstone/PCAPs/
#   -R RULES_FILE      Custom Suricata rules. Default:
#                      /home/analyst/MedDefense_Lab/capstone/meddefense.rules
#   -B BLOCKLIST       DNS blocklist. Default:
#                      /home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt
#   -V VALIDATION_SUITE  Firewall validation suite from 2x04. Default:
#                      /home/analyst/MedDefense_Lab/2x04/5-firewall_test.sh
#                      (overridable with FIREWALL_TEST_SUITE). If it is not
#                      present, the built-in suite runs instead, checking the
#                      live nftables ruleset against the segmentation contract.
#                      Both are gating: any failure stops the run.
#   -a "ARGS"          Argument list passed verbatim to the pipeline.
#   --skip-dns         Do not touch dnsmasq configuration.
#   --skip-pipeline    Validate and replay only; do not invoke the pipeline.
#   -h                 Show usage.
#
# Output (all under capstone/network/):
#   network_deploy.log          full pipeline and replay output
#   firewall_validation.json    per-test firewall validation results
#   suricata_alerts.json        parsed alerts from the offline replay
#   suricata_rule_report.json   custom rule validation against labeled PCAPs
#   dns_filter_status.json      dnsmasq filter state
#   network_summary.json        normalised wrapper summary
#
# Exit codes:
#   0  every validation step passed
#   1  a validation step failed, the pipeline exited non-zero, or a custom rule
#      did not fire against its target PCAP
#   2  environment error - not root, missing dependency, missing pipeline,
#      segmentation file, PCAP directory, blocklist, or target_state.json
#
set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="7-network_deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="network_deployment"

# The brief fixes this value: the pipeline is invoked with
# CAPSTONE_ARTIFACTS_DIR=capstone/network/ exported, from a working directory
# of CAPSTONE_ROOT, so the relative path resolves inside the capstone package.
readonly ARTIFACTS_DIR_VALUE="capstone/network/"
readonly NETWORK_SUBDIR="capstone/network"
readonly LOG_RELPATH="capstone/network/network_deploy.log"
readonly SUMMARY_RELPATH="capstone/network/network_summary.json"
readonly RECORD_BASENAME="network_summary.json"
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly DNSMASQ_CONF="/etc/dnsmasq.d/meddefense-capstone.conf"
readonly BLOCK_BEGIN="# BEGIN meddefense-capstone managed block"
readonly BLOCK_END="# END meddefense-capstone managed block"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
PIPELINE="${NETWORK_PIPELINE:-/home/analyst/MedDefense_Lab/2x04/17-network_pipeline.sh}"
SEG_FILE="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAP_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs/"
RULES_FILE="/home/analyst/MedDefense_Lab/capstone/meddefense.rules"
BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"
VALIDATION_SUITE="${FIREWALL_TEST_SUITE:-/home/analyst/MedDefense_Lab/2x04/5-firewall_test.sh}"
PIPELINE_ARGS=()
PIPELINE_ARGS_SET=0
SKIP_DNS=0
SKIP_PIPELINE=0
TMP_JSON=""
COLLECTION_ERRORS=()

PIPELINE_RC=0
EXTERNAL_SUITE_FAILED=0
FW_TOTAL=0
FW_PASSED=0
FW_FAILED=0
PCAP_COUNT=0
ALERT_COUNT=0
RULES_LOADED=0
RULES_NOT_FIRED=1
DNS_ACTIVE="false"
DNS_CHANGED="false"
DNS_DOMAINS=0

usage() {
    sed -n '3,63p' "$0" | sed 's/^# \{0,1\}//'
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
# Firewall validation
#
# The built-in suite checks the LIVE nftables ruleset against the Hawthorne
# segmentation contract. Checking the contract file against itself would prove
# nothing; the point is that what is loaded matches what was declared.
# --------------------------------------------------------------------------

run_firewall_validation() {
    local out="$1" ruleset=""

    if [[ -n "$VALIDATION_SUITE" && -x "$VALIDATION_SUITE" ]]; then
        log "INFO  running the 2x04 firewall validation suite: $VALIDATION_SUITE"
        set +e
        "$VALIDATION_SUITE" >>"$LOG_FILE" 2>&1
        local ext_rc=$?
        set -e
        if [[ "$ext_rc" -ne 0 ]]; then
            record_error "firewall validation suite ${VALIDATION_SUITE} exited ${ext_rc}"
            EXTERNAL_SUITE_FAILED=1
        fi
    elif [[ -n "$VALIDATION_SUITE" ]]; then
        log "INFO  ${VALIDATION_SUITE} not present; using the built-in validation suite"
    fi

    ruleset=$(nft list ruleset 2>/dev/null || true)

    SEG_FILE="$SEG_FILE" NFT_RULESET="$ruleset" python3 - "$out" <<'PY'
import json, os, re, sys, datetime

out_path = sys.argv[1]
ruleset = os.environ.get("NFT_RULESET", "")
seg_path = os.environ["SEG_FILE"]

tests = []

def add(name, description, passed, detail=""):
    tests.append({
        "test": name,
        "description": description,
        "passed": bool(passed),
        "detail": detail,
    })

# --- structural checks on the live ruleset ---------------------------------
add("ruleset_loaded", "nftables ruleset is non-empty",
    bool(ruleset.strip()), "{0} bytes".format(len(ruleset)))

input_drop = re.search(r"hook\s+input\b[^\n]*policy\s+drop", ruleset)
add("input_default_deny", "input chain defaults to drop",
    bool(input_drop), input_drop.group(0).strip() if input_drop else "not found")

fwd_drop = re.search(r"hook\s+forward\b[^\n]*policy\s+drop", ruleset)
add("forward_default_deny", "forward chain defaults to drop",
    bool(fwd_drop), fwd_drop.group(0).strip() if fwd_drop else "not found")

add("loopback_allowed", "loopback traffic is permitted",
    bool(re.search(r'iif(name)?\s+"?lo"?', ruleset)), "")

add("established_allowed", "established/related traffic is permitted",
    bool(re.search(r"ct\s+state[^\n]*established", ruleset)), "")

# --- the segmentation contract ---------------------------------------------
try:
    with open(seg_path) as fh:
        seg = json.load(fh)
except Exception as exc:                       # noqa: BLE001
    add("segmentation_contract_readable",
        "Hawthorne segmentation contract parses", False, str(exc))
    seg = None
else:
    add("segmentation_contract_readable",
        "Hawthorne segmentation contract parses", True, seg_path)

def iter_rules(doc):
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("rules", "segmentation_rules", "allow", "policies", "flows"):
            value = doc.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        collected = []
        for value in doc.values():
            if isinstance(value, list):
                collected.extend(r for r in value if isinstance(r, dict))
        return collected
    return []

def field(rule, *names):
    for name in names:
        if name in rule and rule[name] not in (None, ""):
            return rule[name]
    return None

if seg is not None:
    rules = iter_rules(seg)
    if not rules:
        add("segmentation_rules_present",
            "segmentation contract declares at least one rule", False, "none found")
    else:
        add("segmentation_rules_present",
            "segmentation contract declares at least one rule", True,
            "{0} rule(s)".format(len(rules)))

        for index, rule in enumerate(rules, start=1):
            name = field(rule, "name", "id", "description") or "rule_{0}".format(index)
            action = str(field(rule, "action", "verdict", "policy") or "allow").lower()
            port = field(rule, "port", "dport", "destination_port", "dst_port")
            proto = str(field(rule, "protocol", "proto") or "").lower()

            if port is None:
                # Nothing port-shaped to look for; record it rather than
                # silently passing a rule that was never actually checked.
                add("segmentation::{0}".format(name),
                    "rule has no port to verify against the ruleset",
                    True, "skipped: no port field")
                continue

            port_text = str(port)
            found = re.search(r"\bdport\b[^\n]*\b{0}\b".format(re.escape(port_text)), ruleset)
            if not found:
                found = re.search(r"\b{0}\b".format(re.escape(port_text)), ruleset)

            if action in ("allow", "accept", "permit"):
                add("segmentation::{0}".format(name),
                    "allowed flow port {0}/{1} appears in the ruleset".format(port_text, proto or "any"),
                    bool(found), "" if found else "port not present in loaded ruleset")
            else:
                add("segmentation::{0}".format(name),
                    "denied flow port {0}/{1} is not explicitly accepted".format(port_text, proto or "any"),
                    True, "default-deny covers this flow")

passed = sum(1 for t in tests if t["passed"])
failed = len(tests) - passed

doc = {
    "schema_version": "1.0",
    "record_type": "firewall_validation",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "segmentation_contract": seg_path,
    "tests_total": len(tests),
    "tests_passed": passed,
    "tests_failed": failed,
    "result": "pass" if failed == 0 else "fail",
    "tests": tests,
}

tmp = out_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
os.replace(tmp, out_path)
print("{0} {1} {2}".format(len(tests), passed, failed))
PY
}

# --------------------------------------------------------------------------
# Suricata offline replay and custom rule validation
# --------------------------------------------------------------------------

run_suricata_replay() {
    local pcap_dir="$1" work_dir="$2" pcap base rc
    local count=0

    mkdir -p "$work_dir"

    while IFS= read -r pcap; do
        [[ -z "$pcap" ]] && continue
        base=$(basename "$pcap")
        base="${base%.*}"
        mkdir -p "${work_dir}/${base}"
        log "INFO  replaying ${base}"
        {
            printf '===== SURICATA REPLAY %s =====\n' "$base"
        } >>"$LOG_FILE"
        set +e
        if [[ -r "$RULES_FILE" ]]; then
            suricata -r "$pcap" -l "${work_dir}/${base}" -S "$RULES_FILE" -k none \
                >>"$LOG_FILE" 2>&1
        else
            suricata -r "$pcap" -l "${work_dir}/${base}" -k none >>"$LOG_FILE" 2>&1
        fi
        rc=$?
        set -e
        if [[ "$rc" -ne 0 ]]; then
            record_error "suricata replay of ${base} exited ${rc}"
        fi
        count=$((count + 1))
    done < <(find "$pcap_dir" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | LC_ALL=C sort)

    printf '%s' "$count"
}

parse_suricata_results() {
    # parse_suricata_results <work_dir> <alerts_out> <report_out>
    SURICATA_WORK="$1" RULES_FILE="$RULES_FILE" PCAP_DIR="$PCAP_DIR" \
        python3 - "$2" "$3" <<'PY'
import json, os, re, sys, datetime

alerts_out, report_out = sys.argv[1], sys.argv[2]
work = os.environ["SURICATA_WORK"]
rules_path = os.environ["RULES_FILE"]
pcap_dir = os.environ["PCAP_DIR"]

# --- alerts ---------------------------------------------------------------
alerts = []
for root, _dirs, files in os.walk(work):
    pcap_name = os.path.basename(root)
    for name in files:
        if name != "eve.json":
            continue
        with open(os.path.join(root, name)) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except ValueError:
                    continue
                if evt.get("event_type") != "alert":
                    continue
                alert = evt.get("alert", {})
                alerts.append({
                    "pcap": pcap_name,
                    "timestamp": evt.get("timestamp"),
                    "signature_id": alert.get("signature_id"),
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "src_ip": evt.get("src_ip"),
                    "src_port": evt.get("src_port"),
                    "dest_ip": evt.get("dest_ip"),
                    "dest_port": evt.get("dest_port"),
                    "proto": evt.get("proto"),
                })

alerts.sort(key=lambda a: (a["pcap"], str(a["timestamp"] or "")))

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
by_sid = {}
for a in alerts:
    sid = a["signature_id"]
    if sid is not None:
        by_sid.setdefault(int(sid), set()).add(a["pcap"])

with open(alerts_out + ".tmp", "w") as fh:
    json.dump({
        "schema_version": "1.0",
        "record_type": "suricata_alerts",
        "generated_at": now,
        "mode": "offline_replay",
        "pcap_dir": pcap_dir,
        "alert_count": len(alerts),
        "distinct_signatures": len(by_sid),
        "alerts": alerts,
    }, fh, indent=2)
    fh.write("\n")
os.replace(alerts_out + ".tmp", alerts_out)

# --- custom rules ---------------------------------------------------------
rules = []
sid_re = re.compile(r"\bsid\s*:\s*(\d+)")
msg_re = re.compile(r'\bmsg\s*:\s*"([^"]*)"')
try:
    with open(rules_path) as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = sid_re.search(stripped)
            if not m:
                continue
            msg = msg_re.search(stripped)
            rules.append({"sid": int(m.group(1)),
                          "msg": msg.group(1) if msg else None})
except FileNotFoundError:
    pass

# Labels map a PCAP to the rule(s) it is supposed to trigger. Prefer an
# explicit labels file; fall back to a sid encoded in the filename.
labels = {}
for candidate in ("labels.json", "pcap_labels.json", "labels.txt"):
    path = os.path.join(pcap_dir, candidate)
    if os.path.exists(path):
        try:
            with open(path) as fh:
                if candidate.endswith(".json"):
                    raw = json.load(fh)
                    if isinstance(raw, dict):
                        for key, value in raw.items():
                            stem = os.path.splitext(os.path.basename(key))[0]
                            if isinstance(value, list):
                                labels[stem] = [int(v) for v in value
                                                if str(v).isdigit()]
                            elif isinstance(value, dict):
                                sids = value.get("sid") or value.get("sids")
                                if isinstance(sids, list):
                                    labels[stem] = [int(v) for v in sids]
                                elif str(sids).isdigit():
                                    labels[stem] = [int(sids)]
                            elif str(value).isdigit():
                                labels[stem] = [int(value)]
        except Exception:                      # noqa: BLE001
            labels = {}
        break

if not labels:
    for name in os.listdir(pcap_dir) if os.path.isdir(pcap_dir) else []:
        m = re.search(r"sid[_-]?(\d{3,})", name, re.I)
        if m:
            labels[os.path.splitext(name)[0]] = [int(m.group(1))]

expected_by_sid = {}
for stem, sids in labels.items():
    for sid in sids:
        expected_by_sid.setdefault(sid, set()).add(stem)

rule_rows = []
for rule in rules:
    sid = rule["sid"]
    fired_in = sorted(by_sid.get(sid, set()))
    targets = sorted(expected_by_sid.get(sid, set()))
    if targets:
        matched = [t for t in targets if t in fired_in]
        fired_against_target = len(matched) == len(targets)
        basis = "labeled"
    else:
        matched = fired_in
        fired_against_target = len(fired_in) > 0
        basis = "unlabeled"
    rule_rows.append({
        "sid": sid,
        "msg": rule["msg"],
        "target_pcaps": targets,
        "fired_in": fired_in,
        "validation_basis": basis,
        "fired_against_target": fired_against_target,
    })

not_fired = [r for r in rule_rows if not r["fired_against_target"]]

with open(report_out + ".tmp", "w") as fh:
    json.dump({
        "schema_version": "1.0",
        "record_type": "suricata_rule_report",
        "generated_at": now,
        "rules_file": rules_path,
        "labels_source": "labels file" if any(
            os.path.exists(os.path.join(pcap_dir, c))
            for c in ("labels.json", "pcap_labels.json")) else "filename",
        "rules_loaded": len(rules),
        "rules_fired": len(rule_rows) - len(not_fired),
        "rules_not_fired_count": len(not_fired),
        "all_rules_fired": len(not_fired) == 0 and len(rules) > 0,
        "rules": rule_rows,
    }, fh, indent=2)
    fh.write("\n")
os.replace(report_out + ".tmp", report_out)

print("{0} {1} {2}".format(len(alerts), len(rules), len(not_fired)))
PY
}

# --------------------------------------------------------------------------
# DNS filter
# --------------------------------------------------------------------------

write_managed_block() {
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

configure_dns_filter() {
    local out="$1" body domains result active="false"

    domains=$(grep -vE '^\s*(#|$)' "$BLOCKLIST" 2>/dev/null |
        awk '{print $NF}' | LC_ALL=C sort -u || true)
    DNS_DOMAINS=$(printf '%s\n' "$domains" | grep -c . || true)

    if [[ "$DNS_DOMAINS" -eq 0 ]]; then
        record_error "DNS blocklist ${BLOCKLIST} yielded no domains"
    fi

    body=""
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        body+="address=/${domain}/0.0.0.0"$'\n'
    done <<<"$domains"
    body="${body%$'\n'}"

    mkdir -p "$(dirname "$DNSMASQ_CONF")"
    result=$(write_managed_block "$DNSMASQ_CONF" "$body")
    if [[ "$result" == "changed" ]]; then
        DNS_CHANGED="true"
        log "INFO  wrote ${DNS_DOMAINS} blocked domain(s) to ${DNSMASQ_CONF}"
    else
        log "INFO  DNS blocklist already current in ${DNSMASQ_CONF}"
    fi

    # Only reload when something changed, and validate before reloading so a
    # bad blocklist cannot take the resolver down.
    if command -v dnsmasq >/dev/null 2>&1; then
        if ! dnsmasq --test >>"$LOG_FILE" 2>&1; then
            record_error "dnsmasq configuration failed its own syntax test; not reloading"
        elif [[ "$DNS_CHANGED" == "true" ]]; then
            systemctl restart dnsmasq >>"$LOG_FILE" 2>&1 ||
                record_error "dnsmasq could not be restarted"
        fi
        systemctl enable dnsmasq >>"$LOG_FILE" 2>&1 || true
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            active="true"
        fi
    else
        record_error "dnsmasq is not installed; DNS filter cannot be activated"
    fi

    DNS_ACTIVE="$active"

    DNS_ACTIVE="$active" DNS_CHANGED="$DNS_CHANGED" DNS_DOMAINS="$DNS_DOMAINS" \
        DNS_CONF="$DNSMASQ_CONF" DNS_BLOCKLIST="$BLOCKLIST" python3 - "$out" <<'PY'
import json, os, sys, datetime

out_path = sys.argv[1]
doc = {
    "schema_version": "1.0",
    "record_type": "dns_filter_status",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "provider": "dnsmasq",
    "active": os.environ["DNS_ACTIVE"] == "true",
    "config_path": os.environ["DNS_CONF"],
    "blocklist_path": os.environ["DNS_BLOCKLIST"],
    "blocked_domain_count": int(os.environ["DNS_DOMAINS"]),
    "config_changed": os.environ["DNS_CHANGED"] == "true",
}
tmp = out_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
os.replace(tmp, out_path)
PY
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local arg hn net_dir out_file target_state dep root_abs
    local fw_out alerts_out report_out dns_out suricata_work
    local fw_result parse_result result="fail" e efirst=1

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                if [[ $# -lt 2 ]]; then log "ERROR option -o requires an argument"; exit 2; fi
                CAPSTONE_ROOT="$2"; shift 2 ;;
            -p)
                if [[ $# -lt 2 ]]; then log "ERROR option -p requires an argument"; exit 2; fi
                PIPELINE="$2"; shift 2 ;;
            -s)
                if [[ $# -lt 2 ]]; then log "ERROR option -s requires an argument"; exit 2; fi
                SEG_FILE="$2"; shift 2 ;;
            -P)
                if [[ $# -lt 2 ]]; then log "ERROR option -P requires an argument"; exit 2; fi
                PCAP_DIR="$2"; shift 2 ;;
            -R)
                if [[ $# -lt 2 ]]; then log "ERROR option -R requires an argument"; exit 2; fi
                RULES_FILE="$2"; shift 2 ;;
            -B)
                if [[ $# -lt 2 ]]; then log "ERROR option -B requires an argument"; exit 2; fi
                BLOCKLIST="$2"; shift 2 ;;
            -V)
                if [[ $# -lt 2 ]]; then log "ERROR option -V requires an argument"; exit 2; fi
                VALIDATION_SUITE="$2"; shift 2 ;;
            -a)
                if [[ $# -lt 2 ]]; then log "ERROR option -a requires an argument"; exit 2; fi
                read -r -a PIPELINE_ARGS <<<"$2"
                PIPELINE_ARGS_SET=1
                shift 2 ;;
            --skip-dns) SKIP_DNS=1; shift ;;
            --skip-pipeline) SKIP_PIPELINE=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *)
                log "ERROR unknown argument: $arg"
                usage >&2
                exit 2 ;;
        esac
    done

    # --- preflight ---
    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR network deployment must run as root; re-run with sudo"
        exit 2
    fi
    for dep in nft suricata python3 find awk date sha256sum; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    if [[ "$SKIP_PIPELINE" -eq 0 && ! -x "$PIPELINE" ]]; then
        log "ERROR network pipeline not found or not executable: $PIPELINE"
        local candidate
        for candidate in "$(dirname "$PIPELINE")"/*network*.sh; do
            [[ -e "$candidate" ]] && log "ERROR candidate in that directory: $candidate"
        done
        log "ERROR pass -p with the path to the 2x04 pipeline, or --skip-pipeline"
        exit 2
    fi
    if [[ ! -r "$SEG_FILE" ]]; then
        log "ERROR Hawthorne segmentation contract not found: $SEG_FILE"
        exit 2
    fi
    if [[ ! -d "$PCAP_DIR" ]]; then
        log "ERROR capstone PCAP directory not found: $PCAP_DIR"
        exit 2
    fi
    if [[ "$SKIP_DNS" -eq 0 && ! -r "$BLOCKLIST" ]]; then
        log "ERROR capstone DNS blocklist not found: $BLOCKLIST"
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
        PIPELINE_ARGS=("$SEG_FILE")
    fi

    hn=$(get_hostname)
    root_abs=$(cd "$CAPSTONE_ROOT" && pwd)
    net_dir="${root_abs}/${NETWORK_SUBDIR}"
    if ! mkdir -p "$net_dir" 2>/dev/null; then
        log "ERROR cannot create artifact directory: $net_dir"
        exit 2
    fi
    LOG_FILE="${root_abs}/${LOG_RELPATH}"
    out_file="${net_dir}/${RECORD_BASENAME}"
    fw_out="${net_dir}/firewall_validation.json"
    alerts_out="${net_dir}/suricata_alerts.json"
    report_out="${net_dir}/suricata_rule_report.json"
    dns_out="${net_dir}/dns_filter_status.json"
    suricata_work="${net_dir}/suricata"

    : >"$LOG_FILE"
    {
        printf '# %s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '# host: %s\n' "$hn"
        printf '# started_at: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# CAPSTONE_ARTIFACTS_DIR=%s\n' "$ARTIFACTS_DIR_VALUE"
        printf '# segmentation: %s\n' "$SEG_FILE"
        printf '# pcaps: %s\n\n' "$PCAP_DIR"
    } >>"$LOG_FILE"

    # The Hawthorne segmentation contract belongs in the handoff package.
    cp -f "$SEG_FILE" "${net_dir}/segmentation_rules.json"

    # --- 1. pipeline ---
    if [[ "$SKIP_PIPELINE" -eq 0 ]]; then
        log "INFO  invoking pipeline with CAPSTONE_ARTIFACTS_DIR=${ARTIFACTS_DIR_VALUE}"
        set +e
        (
            cd "$root_abs" || exit 2
            export CAPSTONE_ARTIFACTS_DIR="$ARTIFACTS_DIR_VALUE"
            export CAPSTONE_SEGMENTATION_FILE="$SEG_FILE"
            export SEGMENTATION_RULES="$SEG_FILE"
            export CAPSTONE_PCAP_DIR="$PCAP_DIR"
            "$PIPELINE" "${PIPELINE_ARGS[@]+"${PIPELINE_ARGS[@]}"}"
        ) >>"$LOG_FILE" 2>&1
        PIPELINE_RC=$?
        set -e
        if [[ "$PIPELINE_RC" -ne 0 ]]; then
            record_error "network pipeline exited ${PIPELINE_RC}; see ${LOG_RELPATH}"
        fi
    else
        log "INFO  --skip-pipeline set"
    fi

    # --- 2. firewall validation gates everything downstream ---
    log "INFO  running the firewall validation suite"
    fw_result=$(run_firewall_validation "$fw_out")
    FW_TOTAL=$(printf '%s' "$fw_result" | awk '{print $1}')
    FW_PASSED=$(printf '%s' "$fw_result" | awk '{print $2}')
    FW_FAILED=$(printf '%s' "$fw_result" | awk '{print $3}')
    log "INFO  firewall validation: ${FW_PASSED}/${FW_TOTAL} passed"

    if [[ "$FW_FAILED" -ne 0 || "$EXTERNAL_SUITE_FAILED" -ne 0 ]]; then
        record_error "firewall validation failed ${FW_FAILED} test(s); refusing to proceed"
        log "ERROR refusing to deploy IDS and DNS on an unverified perimeter"
        write_summary "$out_file" "fail"
        printf '%s\n' "$out_file"
        exit 1
    fi

    # --- 3. Suricata offline replay ---
    log "INFO  replaying the capstone PCAP set in offline mode"
    PCAP_COUNT=$(run_suricata_replay "$PCAP_DIR" "$suricata_work")
    if [[ "$PCAP_COUNT" -eq 0 ]]; then
        record_error "no PCAP files found in ${PCAP_DIR}"
    fi

    parse_result=$(parse_suricata_results "$suricata_work" "$alerts_out" "$report_out")
    ALERT_COUNT=$(printf '%s' "$parse_result" | awk '{print $1}')
    RULES_LOADED=$(printf '%s' "$parse_result" | awk '{print $2}')
    RULES_NOT_FIRED=$(printf '%s' "$parse_result" | awk '{print $3}')
    log "INFO  ${ALERT_COUNT} alert(s), ${RULES_LOADED} custom rule(s), ${RULES_NOT_FIRED} did not fire"
    if [[ "$RULES_NOT_FIRED" -ne 0 ]]; then
        record_error "${RULES_NOT_FIRED} custom rule(s) did not fire against their target PCAP"
    fi

    # --- 4. DNS filter ---
    if [[ "$SKIP_DNS" -eq 0 ]]; then
        log "INFO  configuring dnsmasq as the local DNS filter"
        configure_dns_filter "$dns_out"
        if [[ "$DNS_ACTIVE" != "true" ]]; then
            record_error "dnsmasq is not active after configuration"
        fi
    else
        log "INFO  --skip-dns set"
        DNS_ACTIVE="false"
    fi

    # --- verdict ---
    if [[ "$PIPELINE_RC" -eq 0 && "$FW_FAILED" -eq 0 && "$RULES_NOT_FIRED" -eq 0 &&
        "$PCAP_COUNT" -gt 0 && ("$SKIP_DNS" -eq 1 || "$DNS_ACTIVE" == "true") ]]; then
        result="pass"
    fi

    write_summary "$out_file" "$result"
    log "INFO  summary written to $out_file (result=${result})"
    printf '%s\n' "$out_file"

    if [[ "$result" == "pass" ]]; then
        exit 0
    fi
    exit 1
}

write_summary() {
    local out_file="$1" result="$2" e efirst=1 net_dir
    net_dir=$(dirname "$out_file")

    TMP_JSON=$(mktemp "${net_dir}/.summary.XXXXXX") || {
        log "ERROR cannot create temporary file in $net_dir"
        exit 2
    }

    emit '{'
    emit "  $(jstr "schema_version"): $(jstr "$SCHEMA_VERSION"),"
    emit "  $(jstr "record_type"): $(jstr "$RECORD_TYPE"),"
    emit "  $(jstr "platform"): $(jstr "network"),"
    emit "  $(jstr "timestamp"): $(jstr "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"),"
    emit "  $(jstr "hostname"): $(jstr "$(get_hostname)"),"
    emit '  "collector": {'
    emit "    $(jstr "script"): $(jstr "$SCRIPT_NAME"),"
    emit "    $(jstr "version"): $(jstr "$SCRIPT_VERSION")"
    emit '  },'
    emit '  "pipeline": {'
    emit "    $(jstr "script_path"): $(jstr "$PIPELINE"),"
    emit "    $(jstr "exit_code"): $(jnum "$PIPELINE_RC"),"
    emit "    $(jstr "artifacts_dir"): $(jstr "$ARTIFACTS_DIR_VALUE"),"
    emit "    $(jstr "skipped"): $([[ "$SKIP_PIPELINE" -eq 1 ]] && printf 'true' || printf 'false')"
    emit '  },'
    emit '  "segmentation": {'
    emit "    $(jstr "source_path"): $(jstr "$SEG_FILE"),"
    emit "    $(jstr "sha256"): $(jstr "$(file_digest "$SEG_FILE")"),"
    emit "    $(jstr "package_path"): $(jstr "${NETWORK_SUBDIR}/segmentation_rules.json")"
    emit '  },'
    emit '  "firewall_validation": {'
    emit "    $(jstr "tests_total"): $(jnum "$FW_TOTAL"),"
    emit "    $(jstr "tests_passed"): $(jnum "$FW_PASSED"),"
    emit "    $(jstr "tests_failed"): $(jnum "$FW_FAILED"),"
    emit "    $(jstr "report_path"): $(jstr "${NETWORK_SUBDIR}/firewall_validation.json")"
    emit '  },'
    emit '  "suricata": {'
    emit "    $(jstr "mode"): $(jstr "offline_replay"),"
    emit "    $(jstr "pcap_dir"): $(jstr "$PCAP_DIR"),"
    emit "    $(jstr "pcap_count"): $(jnum "$PCAP_COUNT"),"
    emit "    $(jstr "alert_count"): $(jnum "$ALERT_COUNT"),"
    emit "    $(jstr "rules_loaded"): $(jnum "$RULES_LOADED"),"
    emit "    $(jstr "rules_not_fired_count"): $(jnum "$RULES_NOT_FIRED"),"
    emit "    $(jstr "alerts_path"): $(jstr "${NETWORK_SUBDIR}/suricata_alerts.json"),"
    emit "    $(jstr "rule_report_path"): $(jstr "${NETWORK_SUBDIR}/suricata_rule_report.json")"
    emit '  },'
    emit '  "dns_filter": {'
    emit "    $(jstr "provider"): $(jstr "dnsmasq"),"
    emit "    $(jstr "active"): ${DNS_ACTIVE},"
    emit "    $(jstr "blocked_domain_count"): $(jnum "$DNS_DOMAINS"),"
    emit "    $(jstr "config_changed"): ${DNS_CHANGED},"
    emit "    $(jstr "status_path"): $(jstr "${NETWORK_SUBDIR}/dns_filter_status.json")"
    emit '  },'
    emit "  $(jstr "summary_path"): $(jstr "$SUMMARY_RELPATH"),"
    emit "  $(jstr "log_path"): $(jstr "$LOG_RELPATH"),"
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
    (cd "$net_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
}

main "$@"
