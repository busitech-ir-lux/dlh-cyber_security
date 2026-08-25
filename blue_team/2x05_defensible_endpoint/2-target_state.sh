#!/bin/bash
#
# 2-target_state.sh - Hawthorne capstone, Task 2
#
# Emits capstone/target_state.json: the machine-readable contract that defines
# the finish line for the whole handoff. T8 validates against it, T10 reports
# against it, and the final grille is evaluated against it.
#
# Idempotency: the contract is the source of truth. Regenerating it silently
# would let the finish line drift to match whatever was shipped, which is the
# exact failure mode this task exists to prevent. An existing target_state.json
# is therefore treated as state already in place - the script reports it and
# exits 0 without rewriting. --force overwrites deliberately and preserves the
# previous contract as *.superseded.
#
# Usage:
#   ./2-target_state.sh [-o CAPSTONE_ROOT] [--force] [--validate] [--help]
#
#   -o CAPSTONE_ROOT  Root that contains capstone/ (default: ., overridable
#                     with CAPSTONE_ROOT).
#   --force           Overwrite an existing contract.
#   --validate        Do not write anything; verify that an existing contract
#                     is present and parseable. Downstream scripts call this to
#                     satisfy "a corrupted or missing target_state.json must be
#                     fatal": it exits 2 when the contract is missing or
#                     unreadable, so callers can simply propagate the status.
#   --help            Show usage.
#
# Output:
#   capstone/target_state.json
#   capstone/target_state.json.sha256
#
# Exit codes:
#   0  success - contract written, or already present and left untouched, or
#      --validate passed
#   1  controlled failure - contract written but failed its own self-check
#   2  environment error - unwritable output tree, or --validate found the
#      contract missing or corrupt
#
set -euo pipefail

readonly SCRIPT_NAME="2-target_state.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"

readonly CONTRACT_RELPATH="capstone/target_state.json"
readonly RECORD_BASENAME="target_state.json"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
FORCE=0
VALIDATE_ONLY=0
TMP_JSON=""

usage() {
    sed -n '3,42p' "$0" | sed 's/^# \{0,1\}//'
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

# --------------------------------------------------------------------------
# JSON validation helper - uses whatever parser the host has
# --------------------------------------------------------------------------

json_is_valid() {
    local file="$1"
    if [[ ! -s "$file" ]]; then
        return 1
    fi
    if command -v jq >/dev/null 2>&1; then
        jq -e 'type == "object" and (.controls | type) == "array" and (.controls | length) > 0' \
            "$file" >/dev/null 2>&1
        return $?
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$file" <<'PY' >/dev/null 2>&1
import json, sys
with open(sys.argv[1]) as fh:
    doc = json.load(fh)
assert isinstance(doc, dict), "root is not an object"
assert isinstance(doc.get("controls"), list), "controls is not an array"
assert len(doc["controls"]) > 0, "controls is empty"
assert doc.get("schema_version"), "schema_version missing"
assert doc.get("generated_at"), "generated_at missing"
PY
        return $?
    fi
    log "WARN  neither jq nor python3 available; contract could not be parse-checked"
    return 0
}

# --------------------------------------------------------------------------
# The contract itself
#
# Check conventions, enforced by the T8 validation suite:
#   file_exists        check_target = path, expected_value = "true"
#   json_field_equals  check_target = "<path>#<dot.path>", expected_value = scalar
#   json_field_gte     check_target = "<path>#<dot.path>", expected_value = number
#   command_exit_zero  check_target = command string, expected_value = 0.
#                      Runs under bash when platform is linux or network, and
#                      under PowerShell when platform is windows.
#   grep_match         check_target = path, expected_value = ERE
# --------------------------------------------------------------------------

write_contract() {
    cat >"$TMP_JSON" <<'CONTRACT'
{
  "schema_version": "@@SCHEMA_VERSION@@",
  "record_type": "target_state",
  "generated_at": "@@GENERATED_AT@@",
  "generated_by": {
    "script": "@@SCRIPT_NAME@@",
    "version": "@@SCRIPT_VERSION@@"
  },
  "check_conventions": {
    "file_exists": "check_target is a path; expected_value is \"true\"",
    "json_field_equals": "check_target is \"<path>#<dot.path>\"; expected_value is the required scalar",
    "json_field_gte": "check_target is \"<path>#<dot.path>\"; expected_value is the numeric floor",
    "command_exit_zero": "check_target is a command; expected_value is 0; bash for linux/network, PowerShell for windows",
    "grep_match": "check_target is a path; expected_value is an extended regular expression",
    "path_base": "All relative paths resolve against the capstone root."
  },
  "controls": [
    {
      "id": "LNX-SSH-01",
      "platform": "linux",
      "family": "hardening",
      "description": "SSH must refuse direct root login",
      "check_type": "grep_match",
      "check_target": "/etc/ssh/sshd_config",
      "expected_value": "^[[:space:]]*PermitRootLogin[[:space:]]+no[[:space:]]*$",
      "source_project": "2x00",
      "severity": "critical"
    },
    {
      "id": "LNX-SSH-02",
      "platform": "linux",
      "family": "hardening",
      "description": "SSH must refuse password authentication",
      "check_type": "grep_match",
      "check_target": "/etc/ssh/sshd_config",
      "expected_value": "^[[:space:]]*PasswordAuthentication[[:space:]]+no[[:space:]]*$",
      "source_project": "2x00",
      "severity": "critical"
    },
    {
      "id": "LNX-SYS-01",
      "platform": "linux",
      "family": "hardening",
      "description": "IPv4 forwarding must be disabled on the application host",
      "check_type": "command_exit_zero",
      "check_target": "test \"$(sysctl -n net.ipv4.ip_forward)\" = \"0\"",
      "expected_value": 0,
      "source_project": "2x00",
      "severity": "high"
    },
    {
      "id": "LNX-SYS-02",
      "platform": "linux",
      "family": "hardening",
      "description": "Full address space layout randomisation must be enabled",
      "check_type": "command_exit_zero",
      "check_target": "test \"$(sysctl -n kernel.randomize_va_space)\" = \"2\"",
      "expected_value": 0,
      "source_project": "2x00",
      "severity": "high"
    },
    {
      "id": "LNX-APP-01",
      "platform": "linux",
      "family": "hardening",
      "description": "AppArmor must be loaded with at least one profile in enforce mode",
      "check_type": "command_exit_zero",
      "check_target": "test \"$(aa-status --enforced)\" -gt 0",
      "expected_value": 0,
      "source_project": "2x00",
      "severity": "high"
    },
    {
      "id": "LNX-LYN-01",
      "platform": "linux",
      "family": "hardening",
      "description": "Post-hardening Lynis hardening index must reach at least 80",
      "check_type": "json_field_gte",
      "check_target": "capstone/verify/verify_linux.json#hardening_index",
      "expected_value": 80,
      "source_project": "2x00",
      "severity": "critical"
    },
    {
      "id": "LNX-AUD-01",
      "platform": "linux",
      "family": "telemetry",
      "description": "The auditd service must be active on the application host",
      "check_type": "command_exit_zero",
      "check_target": "systemctl is-active --quiet auditd",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "critical"
    },
    {
      "id": "LNX-AUD-02",
      "platform": "linux",
      "family": "telemetry",
      "description": "The capstone auditd rules file must be present on disk",
      "check_type": "file_exists",
      "check_target": "/etc/audit/rules.d/hardening.rules",
      "expected_value": "true",
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "LNX-AUD-03",
      "platform": "linux",
      "family": "telemetry",
      "description": "The auditd rules must be loaded into the running kernel",
      "check_type": "command_exit_zero",
      "check_target": "test \"$(auditctl -l | grep -cv '^No rules$')\" -gt 0",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "LNX-TEL-01",
      "platform": "linux",
      "family": "telemetry",
      "description": "The structured Linux telemetry export must exist at the agreed path",
      "check_type": "file_exists",
      "check_target": "capstone/telemetry/linux/telemetry_export.json",
      "expected_value": "true",
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "WIN-FW-01",
      "platform": "windows",
      "family": "hardening",
      "description": "Windows Firewall must default-deny inbound on every profile",
      "check_type": "command_exit_zero",
      "check_target": "if ((Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.DefaultInboundAction -ne 'Block' -or -not $_.Enabled }).Count -eq 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x01",
      "severity": "critical"
    },
    {
      "id": "WIN-CIS-01",
      "platform": "windows",
      "family": "hardening",
      "description": "Post-hardening CIS Level 1 pass rate must reach at least 85 percent",
      "check_type": "json_field_gte",
      "check_target": "capstone/verify/verify_windows.json#pass_rate_percent",
      "expected_value": 85,
      "source_project": "2x01",
      "severity": "critical"
    },
    {
      "id": "WIN-PSL-01",
      "platform": "windows",
      "family": "telemetry",
      "description": "PowerShell Script Block Logging must be enabled by policy",
      "check_type": "command_exit_zero",
      "check_target": "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging).EnableScriptBlockLogging -eq 1) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "WIN-PSL-02",
      "platform": "windows",
      "family": "telemetry",
      "description": "The Script Block Logging event channel must have a non-zero maximum size",
      "check_type": "command_exit_zero",
      "check_target": "if ((Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes -gt 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "medium"
    },
    {
      "id": "WIN-SYS-01",
      "platform": "windows",
      "family": "telemetry",
      "description": "The Sysmon service must be installed and running",
      "check_type": "command_exit_zero",
      "check_target": "if ((Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }).Count -gt 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "critical"
    },
    {
      "id": "WIN-SYS-02",
      "platform": "windows",
      "family": "telemetry",
      "description": "Sysmon must have written at least one event in the last ten minutes",
      "check_type": "command_exit_zero",
      "check_target": "if (@(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue).Count -gt 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "WIN-AUD-01",
      "platform": "windows",
      "family": "telemetry",
      "description": "Audit policy must cover the Account Logon category",
      "check_type": "command_exit_zero",
      "check_target": "if ((auditpol /get /category:'Account Logon' /r | ConvertFrom-Csv | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' }).Count -eq 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "WIN-AUD-02",
      "platform": "windows",
      "family": "telemetry",
      "description": "Audit policy must cover the Logon/Logoff category",
      "check_type": "command_exit_zero",
      "check_target": "if ((auditpol /get /category:'Logon/Logoff' /r | ConvertFrom-Csv | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' }).Count -eq 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "high"
    },
    {
      "id": "WIN-AUD-03",
      "platform": "windows",
      "family": "telemetry",
      "description": "Audit policy must cover the Object Access category",
      "check_type": "command_exit_zero",
      "check_target": "if ((auditpol /get /category:'Object Access' /r | ConvertFrom-Csv | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' }).Count -eq 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "medium"
    },
    {
      "id": "WIN-AUD-04",
      "platform": "windows",
      "family": "telemetry",
      "description": "Audit policy must cover the Privilege Use category",
      "check_type": "command_exit_zero",
      "check_target": "if ((auditpol /get /category:'Privilege Use' /r | ConvertFrom-Csv | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' }).Count -eq 0) { exit 0 } else { exit 1 }",
      "expected_value": 0,
      "source_project": "2x02",
      "severity": "medium"
    },
    {
      "id": "PCH-INV-01",
      "platform": "both",
      "family": "patching",
      "description": "The vulnerability inventory must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/patching/vulnerability_inventory.json",
      "expected_value": "true",
      "source_project": "2x03",
      "severity": "high"
    },
    {
      "id": "PCH-PLN-01",
      "platform": "both",
      "family": "patching",
      "description": "The patch plan must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/patching/patch_plan.json",
      "expected_value": "true",
      "source_project": "2x03",
      "severity": "high"
    },
    {
      "id": "PCH-EXE-01",
      "platform": "both",
      "family": "patching",
      "description": "The patch execution log must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/patching/patch_execution_log.json",
      "expected_value": "true",
      "source_project": "2x03",
      "severity": "high"
    },
    {
      "id": "PCH-EXE-02",
      "platform": "both",
      "family": "patching",
      "description": "No patch may remain in the failed state at handoff",
      "check_type": "json_field_equals",
      "check_target": "capstone/patching/patch_execution_log.json#summary.failed_count",
      "expected_value": 0,
      "source_project": "2x03",
      "severity": "critical"
    },
    {
      "id": "PCH-UNA-01",
      "platform": "linux",
      "family": "patching",
      "description": "Unattended upgrades must be configured with the mandated package blacklist",
      "check_type": "grep_match",
      "check_target": "/etc/apt/apt.conf.d/50unattended-upgrades",
      "expected_value": "^[[:space:]]*Unattended-Upgrade::Package-Blacklist",
      "source_project": "2x03",
      "severity": "high"
    },
    {
      "id": "NET-NFT-01",
      "platform": "network",
      "family": "network",
      "description": "nftables input chain must default to drop",
      "check_type": "command_exit_zero",
      "check_target": "nft list ruleset | grep -qE 'hook input .*policy drop'",
      "expected_value": 0,
      "source_project": "2x04",
      "severity": "critical"
    },
    {
      "id": "NET-NFT-02",
      "platform": "network",
      "family": "network",
      "description": "The nftables ruleset must be persisted so it survives reboot",
      "check_type": "file_exists",
      "check_target": "/etc/nftables.conf",
      "expected_value": "true",
      "source_project": "2x04",
      "severity": "medium"
    },
    {
      "id": "NET-SEG-01",
      "platform": "network",
      "family": "network",
      "description": "The segmentation rule set must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/network/segmentation_rules.json",
      "expected_value": "true",
      "source_project": "2x04",
      "severity": "high"
    },
    {
      "id": "NET-IDS-01",
      "platform": "network",
      "family": "network",
      "description": "Suricata must load at least six custom rules from the capstone rule file",
      "check_type": "json_field_gte",
      "check_target": "capstone/network/suricata_rule_report.json#rules_loaded",
      "expected_value": 6,
      "source_project": "2x04",
      "severity": "high"
    },
    {
      "id": "NET-IDS-02",
      "platform": "network",
      "family": "network",
      "description": "Every custom Suricata rule must have fired against its target PCAP",
      "check_type": "json_field_equals",
      "check_target": "capstone/network/suricata_rule_report.json#rules_not_fired_count",
      "expected_value": 0,
      "source_project": "2x04",
      "severity": "high"
    },
    {
      "id": "NET-DNS-01",
      "platform": "network",
      "family": "network",
      "description": "The DNS filter must be active and answering on the resolver host",
      "check_type": "json_field_equals",
      "check_target": "capstone/network/dns_filter_status.json#active",
      "expected_value": true,
      "source_project": "2x04",
      "severity": "medium"
    },
    {
      "id": "HND-CMP-01",
      "platform": "both",
      "family": "handoff",
      "description": "The compliance report must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/compliance.json",
      "expected_value": "true",
      "source_project": "capstone",
      "severity": "critical"
    },
    {
      "id": "HND-MAN-01",
      "platform": "both",
      "family": "handoff",
      "description": "The handoff manifest must be present in the handoff package",
      "check_type": "file_exists",
      "check_target": "capstone/manifest.json",
      "expected_value": "true",
      "source_project": "capstone",
      "severity": "critical"
    },
    {
      "id": "HND-MAN-02",
      "platform": "both",
      "family": "handoff",
      "description": "Every file in the manifest must carry a SHA-256 digest",
      "check_type": "json_field_equals",
      "check_target": "capstone/manifest.json#summary.missing_digest_count",
      "expected_value": 0,
      "source_project": "capstone",
      "severity": "critical"
    },
    {
      "id": "HND-TEL-01",
      "platform": "both",
      "family": "handoff",
      "description": "The telemetry export package must exist as a tarball for Module 3",
      "check_type": "file_exists",
      "check_target": "capstone/telemetry/telemetry_export.tar.gz",
      "expected_value": "true",
      "source_project": "capstone",
      "severity": "high"
    },
    {
      "id": "HND-RUN-01",
      "platform": "both",
      "family": "handoff",
      "description": "The operator runbook script must be present and executable",
      "check_type": "command_exit_zero",
      "check_target": "test -x capstone/runbook.sh",
      "expected_value": 0,
      "source_project": "capstone",
      "severity": "high"
    }
  ]
}
CONTRACT

    sed -i \
        -e "s|@@SCHEMA_VERSION@@|${SCHEMA_VERSION}|" \
        -e "s|@@GENERATED_AT@@|$(date -u '+%Y-%m-%dT%H:%M:%SZ')|" \
        -e "s|@@SCRIPT_NAME@@|${SCRIPT_NAME}|" \
        -e "s|@@SCRIPT_VERSION@@|${SCRIPT_VERSION}|" \
        "$TMP_JSON"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local contract_file capstone_dir arg

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
            --force)
                FORCE=1
                shift
                ;;
            --validate)
                VALIDATE_ONLY=1
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

    contract_file="${CAPSTONE_ROOT}/${CONTRACT_RELPATH}"
    capstone_dir="$(dirname "$contract_file")"

    # --validate is the gate every downstream script calls first.
    if [[ "$VALIDATE_ONLY" -eq 1 ]]; then
        if [[ ! -f "$contract_file" ]]; then
            log "FATAL target state contract is missing: $contract_file"
            exit 2
        fi
        if ! json_is_valid "$contract_file"; then
            log "FATAL target state contract is corrupt or incomplete: $contract_file"
            exit 2
        fi
        log "INFO  target state contract is present and parseable"
        printf '%s\n' "$contract_file"
        exit 0
    fi

    if ! mkdir -p "$capstone_dir" 2>/dev/null; then
        log "ERROR cannot create output directory: $capstone_dir"
        exit 2
    fi
    if [[ ! -w "$capstone_dir" ]]; then
        log "ERROR output directory is not writable: $capstone_dir"
        exit 2
    fi

    # Idempotency gate: the contract must not drift to match what was shipped.
    if [[ -f "$contract_file" && "$FORCE" -eq 0 ]]; then
        log "INFO  contract already present at $contract_file; not rewriting (use --force)"
        printf '%s\n' "$contract_file"
        exit 0
    fi

    TMP_JSON=$(mktemp "${capstone_dir}/.target_state.XXXXXX") || {
        log "ERROR cannot create temporary file in $capstone_dir"
        exit 2
    }

    write_contract

    # Self-check before install: an unparseable contract is fatal downstream,
    # so it must never reach the agreed path in the first place.
    if ! json_is_valid "$TMP_JSON"; then
        log "ERROR generated contract failed its own parse check; not installing"
        exit 1
    fi

    if [[ -f "$contract_file" && "$FORCE" -eq 1 ]]; then
        mv -f "$contract_file" "${contract_file}.superseded"
        log "INFO  previous contract preserved as ${contract_file}.superseded"
    fi

    chmod 0644 "$TMP_JSON"
    mv -f "$TMP_JSON" "$contract_file"
    TMP_JSON=""

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$capstone_dir" && sha256sum "$RECORD_BASENAME" >"${RECORD_BASENAME}.sha256")
    else
        log "WARN  sha256sum unavailable, no digest written"
    fi

    log "INFO  target state contract written to $contract_file"
    printf '%s\n' "$contract_file"
    exit 0
}

main "$@"
