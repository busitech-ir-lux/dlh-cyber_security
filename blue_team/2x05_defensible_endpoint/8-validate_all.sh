#!/bin/bash
#
# 8-validate_all.sh - Hawthorne capstone, Task 8
#
# The single command. Loads capstone/target_state.json, walks every control,
# dispatches on check_type, records a verdict and the evidence that produced
# it, and decides whether the environment is ready for handoff.
#
# No human judgement, no partial credit: the exit code is the answer. Failing
# controls are listed with their evidence so the gap can be fixed and the suite
# re-run.
#
# This is a dispatcher, not a reimplementation of the controls. Every check
# reads either live system state or an artifact produced by T3 through T7.
#
# Idempotency: read-only with respect to system state, apart from writing its
# own report. command_exit_zero controls run whatever the contract declares,
# so the contract is responsible for keeping those commands read-only.
#
# Usage:
#   sudo ./8-validate_all.sh [-o CAPSTONE_ROOT] [--platform LIST] [--family F]
#                            [--id ID] [-w RUNNER] [--strict] [--quiet] [-h]
#
#   -o CAPSTONE_ROOT  Root containing capstone/ (default: .).
#   --platform LIST   Comma-separated platforms to evaluate live.
#                     Default: linux,network,both (plus every windows control
#                     whose check reads an artifact rather than live state).
#   --family F        Evaluate only one control family.
#   --id ID           Evaluate only one control ID.
#   -w RUNNER         Command used to execute windows command_exit_zero checks,
#                     with {} replaced by the command. For example:
#                       -w 'ssh hawthorne-adm-01 powershell -Command {}'
#                     Without this, those controls are recorded as skipped.
#   --strict          Also exit non-zero when any control was skipped.
#   --quiet           Suppress the per-control failure listing.
#   -h                Show usage.
#
# Output:
#   capstone/validation_report.json   per-control verdicts and evidence
#   a per-family summary table on stdout
#
# Exit codes:
#   0  fail_count == 0 AND error_count == 0
#   1  any control failed or errored (or, with --strict, was skipped)
#   2  environment error - missing or corrupt target_state.json, missing
#      dependency, unwritable output tree
# I should have total controls
#
set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="8-validate_all.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly REPORT_RELPATH="capstone/validation_report.json"
readonly REPORT_BASENAME="validation_report.json"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
PLATFORMS="linux,network,both"
FAMILY_FILTER=""
ID_FILTER=""
WINDOWS_RUNNER=""
STRICT=0
QUIET=0

usage() {
    sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

main() {
    local arg target_state report_file capstone_dir rc

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                if [[ $# -lt 2 ]]; then log "ERROR option -o requires an argument"; exit 2; fi
                CAPSTONE_ROOT="$2"; shift 2 ;;
            --platform)
                if [[ $# -lt 2 ]]; then log "ERROR --platform requires an argument"; exit 2; fi
                PLATFORMS="$2"; shift 2 ;;
            --family)
                if [[ $# -lt 2 ]]; then log "ERROR --family requires an argument"; exit 2; fi
                FAMILY_FILTER="$2"; shift 2 ;;
            --id)
                if [[ $# -lt 2 ]]; then log "ERROR --id requires an argument"; exit 2; fi
                ID_FILTER="$2"; shift 2 ;;
            -w)
                if [[ $# -lt 2 ]]; then log "ERROR -w requires an argument"; exit 2; fi
                WINDOWS_RUNNER="$2"; shift 2 ;;
            --strict) STRICT=1; shift ;;
            --quiet) QUIET=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *)
                log "ERROR unknown argument: $arg"
                usage >&2
                exit 2 ;;
        esac
    done

    if ! command -v python3 >/dev/null 2>&1; then
        log "ERROR python3 is required to evaluate the contract"
        exit 2
    fi

    target_state="${CAPSTONE_ROOT}/${TARGET_STATE_RELPATH}"
    capstone_dir="$(dirname "${CAPSTONE_ROOT}/${REPORT_RELPATH}")"
    report_file="${CAPSTONE_ROOT}/${REPORT_RELPATH}"

    # A missing or corrupt contract is fatal: there is nothing to validate against.
    if [[ ! -f "$target_state" ]]; then
        log "FATAL target state contract is missing: $target_state (run 2-target_state.sh first)"
        exit 2
    fi
    if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["controls"]' \
        "$target_state" >/dev/null 2>&1; then
        log "FATAL target state contract is corrupt or declares no controls: $target_state"
        exit 2
    fi
    if ! mkdir -p "$capstone_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $capstone_dir"
        exit 2
    fi

    set +e
    VALIDATE_ROOT="$CAPSTONE_ROOT" \
        VALIDATE_PLATFORMS="$PLATFORMS" \
        VALIDATE_FAMILY="$FAMILY_FILTER" \
        VALIDATE_ID="$ID_FILTER" \
        VALIDATE_WINDOWS_RUNNER="$WINDOWS_RUNNER" \
        VALIDATE_STRICT="$STRICT" \
        VALIDATE_QUIET="$QUIET" \
        VALIDATE_SCRIPT="$SCRIPT_NAME" \
        VALIDATE_VERSION="$SCRIPT_VERSION" \
        python3 - "$target_state" "$report_file" <<'PY'
import json, os, re, subprocess, sys, datetime

target_state_path, report_path = sys.argv[1], sys.argv[2]
root = os.environ["VALIDATE_ROOT"]
platforms = {p.strip() for p in os.environ["VALIDATE_PLATFORMS"].split(",") if p.strip()}
family_filter = os.environ.get("VALIDATE_FAMILY", "")
id_filter = os.environ.get("VALIDATE_ID", "")
windows_runner = os.environ.get("VALIDATE_WINDOWS_RUNNER", "")
strict = os.environ.get("VALIDATE_STRICT") == "1"
quiet = os.environ.get("VALIDATE_QUIET") == "1"

COMMAND_TIMEOUT = 60

with open(target_state_path) as fh:
    contract = json.load(fh)

def resolve(path):
    """Contract paths are relative to the capstone root unless absolute."""
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(root, path))

def split_target(target):
    """'<path>#<dot.path>' -> (path, field) with the field optional."""
    if "#" in target:
        path, field = target.split("#", 1)
        return path, field
    return target, None

FIELD_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'|([^.\[\]]+)')

def walk_field(doc, field):
    """Dotted path with quoted segments, e.g. sysctl_security."net.ipv4.ip_forward"."""
    current = doc
    for match in FIELD_RE.finditer(field):
        key = match.group(1) or match.group(2) or match.group(3)
        key = key.strip()
        if key == "":
            continue
        if isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                raise KeyError(field)
        elif isinstance(current, dict):
            if key not in current:
                raise KeyError(field)
            current = current[key]
        else:
            raise KeyError(field)
    return current

def load_json(path):
    with open(path) as fh:
        return json.load(fh)

def as_number(value):
    if isinstance(value, bool):
        raise TypeError("boolean is not a number")
    if isinstance(value, (int, float)):
        return float(value)
    return float(str(value).strip())

def values_equal(actual, expected):
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) is bool(expected)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return as_number(actual) == as_number(expected)
        except (TypeError, ValueError):
            return False
    return str(actual) == str(expected)

# --------------------------------------------------------------------------
# check_type dispatch - one handler each, all returning (verdict, evidence)
# --------------------------------------------------------------------------

def check_file_exists(control):
    path = resolve(control["check_target"])
    exists = os.path.exists(path)
    expected = control.get("expected_value", "true")
    want = str(expected).strip().lower() in ("true", "1", "yes")
    verdict = "pass" if exists == want else "fail"
    return verdict, {
        "kind": "file_exists",
        "path": path,
        "exists": exists,
        "expected_exists": want,
        "detail": "{0} {1}".format(path, "present" if exists else "absent"),
    }

def check_json_field(control, mode):
    target, field = split_target(control["check_target"])
    path = resolve(target)
    evidence = {"kind": mode, "path": path, "field": field}
    if field is None:
        evidence["detail"] = "check_target has no '#field' component"
        return "error", evidence
    if not os.path.exists(path):
        evidence["detail"] = "artifact not found: {0}".format(path)
        return "fail", evidence
    try:
        doc = load_json(path)
    except Exception as exc:                    # noqa: BLE001
        evidence["detail"] = "artifact is not valid JSON: {0}".format(exc)
        return "error", evidence
    try:
        actual = walk_field(doc, field)
    except KeyError:
        evidence["detail"] = "field '{0}' not present in {1}".format(field, path)
        return "fail", evidence

    evidence["actual_value"] = actual
    evidence["expected_value"] = control.get("expected_value")

    if mode == "json_field_equals":
        ok = values_equal(actual, control.get("expected_value"))
        evidence["detail"] = "{0} = {1!r}, expected {2!r}".format(
            field, actual, control.get("expected_value"))
        return ("pass" if ok else "fail"), evidence

    try:
        actual_num = as_number(actual)
        expected_num = as_number(control.get("expected_value"))
    except (TypeError, ValueError) as exc:
        evidence["detail"] = "non-numeric comparison: {0}".format(exc)
        return "error", evidence
    ok = actual_num >= expected_num
    evidence["detail"] = "{0} = {1}, floor {2}".format(field, actual_num, expected_num)
    return ("pass" if ok else "fail"), evidence

def check_command_exit_zero(control):
    command = control["check_target"]
    platform = control.get("platform", "")
    evidence = {"kind": "command_exit_zero", "command": command}

    if platform == "windows":
        if not windows_runner:
            evidence["detail"] = (
                "windows live check not evaluated from this host; "
                "supply -w RUNNER or run the suite on hawthorne-adm-01")
            return "skip", evidence
        shell_command = windows_runner.replace("{}", command)
        evidence["runner"] = windows_runner
    else:
        shell_command = command

    try:
        proc = subprocess.run(["bash", "-c", shell_command],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        evidence["detail"] = "command timed out after {0}s".format(COMMAND_TIMEOUT)
        return "error", evidence
    except Exception as exc:                    # noqa: BLE001
        evidence["detail"] = "command could not be executed: {0}".format(exc)
        return "error", evidence

    output = (proc.stdout or b"").decode("utf-8", "replace").strip()
    evidence["exit_code"] = proc.returncode
    evidence["output_head"] = output[:400]
    evidence["detail"] = "exit {0}".format(proc.returncode)
    return ("pass" if proc.returncode == 0 else "fail"), evidence

def check_grep_match(control):
    path = resolve(control["check_target"])
    pattern = str(control.get("expected_value", ""))
    evidence = {"kind": "grep_match", "path": path, "pattern": pattern}
    if not os.path.exists(path):
        evidence["detail"] = "file not found: {0}".format(path)
        return "fail", evidence
    try:
        proc = subprocess.run(["grep", "-E", pattern, path],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=COMMAND_TIMEOUT)
    except Exception as exc:                    # noqa: BLE001
        evidence["detail"] = "grep could not be executed: {0}".format(exc)
        return "error", evidence
    matched = (proc.returncode == 0)
    first = ""
    if matched:
        first = (proc.stdout or b"").decode("utf-8", "replace").splitlines()[0].strip()
    evidence["matched_line"] = first[:300]
    evidence["detail"] = ("matched: {0}".format(first[:200]) if matched
                          else "no line matching /{0}/".format(pattern))
    return ("pass" if matched else "fail"), evidence

DISPATCH = {
    "file_exists": check_file_exists,
    "json_field_equals": lambda c: check_json_field(c, "json_field_equals"),
    "json_field_gte": lambda c: check_json_field(c, "json_field_gte"),
    "command_exit_zero": check_command_exit_zero,
    "grep_match": check_grep_match,
}

# --------------------------------------------------------------------------
# Walk every control
# --------------------------------------------------------------------------

results = []
for control in contract.get("controls", []):
    control_id = control.get("id", "<unnamed>")
    family = control.get("family", "unknown")
    platform = control.get("platform", "unknown")
    check_type = control.get("check_type", "")

    if id_filter and control_id != id_filter:
        continue
    if family_filter and family != family_filter:
        continue

    row = {
        "id": control_id,
        "family": family,
        "platform": platform,
        "severity": control.get("severity"),
        "description": control.get("description"),
        "check_type": check_type,
        "check_target": control.get("check_target"),
        "expected_value": control.get("expected_value"),
    }

    # A windows artifact check is still evaluated here: the artifact is in the
    # package. Only windows LIVE checks need the remote host.
    selected = platform in platforms or (
        platform == "windows" and check_type != "command_exit_zero")

    if not selected:
        row["verdict"] = "skip"
        row["evidence"] = {"kind": check_type,
                           "detail": "platform '{0}' not selected".format(platform)}
        results.append(row)
        continue

    handler = DISPATCH.get(check_type)
    if handler is None:
        row["verdict"] = "error"
        row["evidence"] = {"kind": check_type,
                           "detail": "unknown check_type '{0}'".format(check_type)}
        results.append(row)
        continue

    try:
        verdict, evidence = handler(control)
    except Exception as exc:                    # noqa: BLE001
        verdict, evidence = "error", {"kind": check_type,
                                      "detail": "handler raised: {0}".format(exc)}
    row["verdict"] = verdict
    row["evidence"] = evidence
    results.append(row)

# --------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------

def count(rows, verdict):
    return sum(1 for r in rows if r["verdict"] == verdict)

total = len(results)
passed = count(results, "pass")
failed = count(results, "fail")
errored = count(results, "error")
skipped = count(results, "skip")
evaluated = total - skipped
pass_pct = round((passed / evaluated) * 100, 2) if evaluated else 0.0

families = {}
for row in results:
    fam = families.setdefault(row["family"], {
        "family": row["family"], "total": 0, "pass": 0,
        "fail": 0, "error": 0, "skip": 0})
    fam["total"] += 1
    fam[row["verdict"]] += 1
for fam in families.values():
    fam_eval = fam["total"] - fam["skip"]
    fam["pass_percent"] = round((fam["pass"] / fam_eval) * 100, 2) if fam_eval else 0.0

ready = (failed == 0 and errored == 0 and (not strict or skipped == 0))

report = {
    "schema_version": contract.get("schema_version", "1.0"),
    "record_type": "validation_report",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "validator": {
        "script": os.environ["VALIDATE_SCRIPT"],
        "version": os.environ["VALIDATE_VERSION"],
        "platforms_evaluated": sorted(platforms),
        "windows_runner": windows_runner or None,
        "strict": strict,
    },
    "target_state_path": os.path.relpath(target_state_path, root)
    if not os.path.isabs(target_state_path) else target_state_path,
    "target_state_generated_at": contract.get("generated_at"),
    "controls_total": total,
    "pass_count": passed,
    "fail_count": failed,
    "error_count": errored,
    "skip_count": skipped,
    "evaluated_count": evaluated,
    "pass_percent": pass_pct,
    "handoff_ready": ready,
    "families": [families[k] for k in sorted(families)],
    "controls": results,
}

tmp = report_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
os.replace(tmp, report_path)

# --------------------------------------------------------------------------
# Table
# --------------------------------------------------------------------------

header = "{0:<12} {1:>6} {2:>6} {3:>6} {4:>6} {5:>6} {6:>8}".format(
    "FAMILY", "TOTAL", "PASS", "FAIL", "ERROR", "SKIP", "PASS %")
print(header)
print("-" * len(header))
for key in sorted(families):
    fam = families[key]
    print("{0:<12} {1:>6} {2:>6} {3:>6} {4:>6} {5:>6} {6:>7.2f}%".format(
        fam["family"], fam["total"], fam["pass"], fam["fail"],
        fam["error"], fam["skip"], fam["pass_percent"]))
print("-" * len(header))
print("{0:<12} {1:>6} {2:>6} {3:>6} {4:>6} {5:>6} {6:>7.2f}%".format(
    "TOTAL", total, passed, failed, errored, skipped, pass_pct))
print("")
print("HANDOFF READY: {0}".format("YES" if ready else "NO"))

if not quiet:
    problems = [r for r in results if r["verdict"] in ("fail", "error")]
    if problems:
        print("")
        print("Controls requiring attention:")
        for row in problems:
            print("  [{0}] {1} ({2}/{3})".format(
                row["verdict"].upper(), row["id"], row["family"], row["severity"]))
            print("      {0}".format(row["description"]))
            print("      evidence: {0}".format(row["evidence"].get("detail", "")))
    if skipped:
        print("")
        print("Skipped ({0}) - evaluate these on the Windows host:".format(skipped))
        for row in results:
            if row["verdict"] == "skip":
                print("  [SKIP] {0}  {1}".format(row["id"], row["evidence"].get("detail", "")))

raise SystemExit(0 if ready else 1)
PY
    rc=$?
    set -e

    log "INFO  validation report written to $report_file"

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$capstone_dir" && sha256sum "$REPORT_BASENAME" >"${REPORT_BASENAME}.sha256")
    fi

    if [[ "$rc" -eq 0 ]]; then
        exit 0
    fi
    exit 1
}

main "$@"
