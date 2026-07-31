#!/bin/bash
#===============================================================================
# 0-baseline_snapshot.sh
#
# MedDefense - System Hardening Project
# Task 0: The Baseline Snapshot
#
# Captures the complete pre-hardening security state of a Linux host. Every
# metric recorded here is the "before" side of the delta that proves the
# hardening pipeline worked. This script is READ-ONLY: it changes no system
# state, which makes it trivially idempotent and safe to re-run at any point
# (before hardening, after hardening, or on a schedule for drift detection).
#
# Outputs:
#   <outdir>/baseline_<host>_<timestamp>.json   immutable evidence artifact
#   <outdir>/baseline_latest.json               stable path for the pipeline
#
# Usage:
#   sudo ./0-baseline_snapshot.sh [-o OUTPUT_DIR] [--with-lynis]
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
OUTPUT_DIR="${OUTPUT_DIR:-/var/log/meddefense/baseline}"
WITH_LYNIS=0
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Pseudo-filesystems are excluded from filesystem scans: they are kernel
# interfaces, not persistent storage, and their permissions are not attacker
# controlled. -xdev alone would cover them, but the exclusion is explicit
# because the audit evidence has to show the scope was deliberate.
EXCLUDE_PATHS=(/proc /sys /dev /run /snap /var/lib/docker)

#-------------------------------------------------------------------------------
# Argument parsing
#-------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --with-lynis)    WITH_LYNIS=1; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^#//' | head -20
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

#-------------------------------------------------------------------------------
# Preflight
#-------------------------------------------------------------------------------
# Root is required: process-to-socket mapping (ss -p), the effective sshd
# configuration (sshd -T) and a complete SUID sweep of root-only directories
# are all invisible to an unprivileged user. A partial baseline is worse than
# no baseline, because the delta would credit hardening that never happened.
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must be run as root (sudo $0)" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
chmod 0750 "$OUTPUT_DIR"

HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
JSON_FILE="${OUTPUT_DIR}/baseline_${HOSTNAME_SHORT}_${TIMESTAMP}.json"
LATEST_LINK="${OUTPUT_DIR}/baseline_latest.json"

#-------------------------------------------------------------------------------
# JSON helpers (no jq dependency - a hardened host may have no extra packages)
#-------------------------------------------------------------------------------
json_escape() {
    local s=${1//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/\\r}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

# Reads lines on stdin, emits a JSON array of strings.
json_array_from_stdin() {
    local first=1 line out="["
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        (( first )) && first=0 || out+=","
        out+="\"$(json_escape "$line")\""
    done
    printf '%s]' "$out"
}

#-------------------------------------------------------------------------------
# 1. System identification
#-------------------------------------------------------------------------------
# Establishes exactly which host and kernel this evidence belongs to. Kernel
# version is also the input to CVE triage - an unpatched kernel invalidates
# every userspace control layered on top of it.
. /etc/os-release 2>/dev/null || PRETTY_NAME="unknown"
OS_NAME="${PRETTY_NAME:-unknown}"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"
FQDN="$(hostname -f 2>/dev/null || hostname)"
UPTIME_PRETTY="$(uptime -p 2>/dev/null || echo 'unknown')"
BOOT_TIME="$(uptime -s 2>/dev/null || echo 'unknown')"

#-------------------------------------------------------------------------------
# 2. Running services
#-------------------------------------------------------------------------------
# Attack surface inventory. Every running service is a process that can be
# exploited; the hardening phase disables everything not clinically required.
SERVICES_RAW="$(systemctl list-units --type=service --state=running \
                --no-pager --no-legend 2>/dev/null | awk '{print $1}' || true)"
SERVICES_COUNT="$(printf '%s\n' "$SERVICES_RAW" | grep -c . || true)"

#-------------------------------------------------------------------------------
# 3. Open ports / listening sockets
#-------------------------------------------------------------------------------
# The externally reachable surface. Compared against the firewall allowlist in
# a later task: any listener not explicitly permitted is either closed or
# bound to loopback. Addresses the network-reconnaissance stage of the
# MedDefense intrusion chain.
PORTS_RAW="$(ss -tulnpH 2>/dev/null \
             | awk '{printf "%s %s %s\n", $1, $5, $7}' || true)"
PORTS_COUNT="$(printf '%s\n' "$PORTS_RAW" | grep -c . || true)"

#-------------------------------------------------------------------------------
# 4 & 5. Filesystem permission sweep
#-------------------------------------------------------------------------------
# SUID/SGID binaries run with elevated privilege regardless of who invokes
# them - the primary local privilege-escalation vector. World-writable files
# let any account (including a compromised service account) modify content
# that privileged processes trust. Both feed the lateral-movement and
# persistence stages of the MedDefense scenario.
build_prune_expr() {
    local p first=1
    printf '( '
    for p in "${EXCLUDE_PATHS[@]}"; do
        (( first )) && first=0 || printf ' -o '
        printf -- '-path %s' "$p"
    done
    printf ' ) -prune -o '
}
# shellcheck disable=SC2207
PRUNE=( $(build_prune_expr) )

SUID_RAW="$(find / -xdev "${PRUNE[@]}" -type f -perm -4000 -print 2>/dev/null | sort || true)"
SGID_RAW="$(find / -xdev "${PRUNE[@]}" -type f -perm -2000 -print 2>/dev/null | sort || true)"
WW_FILES_RAW="$(find / -xdev "${PRUNE[@]}" -type f -perm -0002 -print 2>/dev/null | sort || true)"
# Directories that are world-writable WITHOUT the sticky bit let any user
# delete or replace another user's files (classic /tmp symlink attacks).
WW_DIRS_RAW="$(find / -xdev "${PRUNE[@]}" -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sort || true)"

SUID_COUNT="$(printf '%s\n' "$SUID_RAW" | grep -c . || true)"
SGID_COUNT="$(printf '%s\n' "$SGID_RAW" | grep -c . || true)"
WW_FILES_COUNT="$(printf '%s\n' "$WW_FILES_RAW" | grep -c . || true)"
WW_DIRS_COUNT="$(printf '%s\n' "$WW_DIRS_RAW" | grep -c . || true)"

# Mount options are recorded now so the delta can prove noexec/nosuid/nodev
# were added to /tmp, /var/tmp, /dev/shm and /home.
MOUNTS_RAW="$(findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null \
              | grep -E '^(/tmp|/var/tmp|/dev/shm|/home|/var|/boot|/) ' || true)"

#-------------------------------------------------------------------------------
# 6. Security-relevant sysctl parameters
#-------------------------------------------------------------------------------
# Out-of-the-box kernel values. Each one is a control that will be flipped in
# the sysctl hardening task; recording the default is what makes the change
# auditable.
SYSCTL_KEYS=(
    net.ipv4.tcp_syncookies                      # SYN flood resilience
    net.ipv4.ip_forward                          # host must not route traffic
    net.ipv4.conf.all.accept_redirects           # ICMP redirect route poisoning
    net.ipv4.conf.default.accept_redirects
    net.ipv4.conf.all.secure_redirects
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.all.accept_source_route        # source-routed packet spoofing
    net.ipv4.conf.default.accept_source_route
    net.ipv4.conf.all.rp_filter                  # reverse-path / anti-spoofing
    net.ipv4.conf.all.log_martians
    net.ipv4.icmp_echo_ignore_broadcasts         # smurf amplification
    net.ipv4.icmp_ignore_bogus_error_responses
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.all.accept_ra
    net.ipv6.conf.all.forwarding
    kernel.randomize_va_space                    # ASLR - memory corruption exploits
    kernel.dmesg_restrict                        # kernel log info leak
    kernel.kptr_restrict                         # kernel pointer info leak
    kernel.sysrq
    kernel.yama.ptrace_scope                     # process memory scraping
    fs.suid_dumpable                             # core dumps leaking secrets
    fs.protected_hardlinks
    fs.protected_symlinks
)

#-------------------------------------------------------------------------------
# 7. SSH configuration
#-------------------------------------------------------------------------------
# 'sshd -T' is used instead of grepping sshd_config: it prints the EFFECTIVE
# configuration including compiled-in defaults and Include drop-ins. Grepping
# the file would miss any setting left at its (often insecure) default.
# Addresses the SSH lateral-movement stage of the MedDefense scenario.
SSH_KEYS=(
    permitrootlogin passwordauthentication pubkeyauthentication
    permitemptypasswords kbdinteractiveauthentication usepam
    maxauthtries logingracetime clientaliveinterval clientalivecountmax
    x11forwarding allowtcpforwarding permittunnel loglevel
    allowusers allowgroups denyusers denygroups banner
    ciphers macs kexalgorithms hostbasedauthentication ignorerhosts
)
SSHD_EFFECTIVE="$(sshd -T 2>/dev/null || true)"

#-------------------------------------------------------------------------------
# 8. Accounts and privilege
#-------------------------------------------------------------------------------
# Who exists and who can escalate. Extra UID 0 accounts, dormant logins and
# oversized sudo groups are the standing privilege that an attacker inherits
# on first compromise.
INTERACTIVE_USERS="$(awk -F: '($3>=1000 && $3<65534) || $3==0 {print $1":"$3":"$7}' /etc/passwd | sort || true)"
UID0_ACCOUNTS="$(awk -F: '$3==0 {print $1}' /etc/passwd | sort || true)"
SUDO_MEMBERS="$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep . | sort || true)"
ADMIN_MEMBERS="$(getent group admin 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep . | sort || true)"
NOPASSWD_SUDOERS="$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
EMPTY_PASSWORD_ACCTS="$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null || true)"

#-------------------------------------------------------------------------------
# Optional: Lynis hardening index
#-------------------------------------------------------------------------------
LYNIS_INDEX="null"
LYNIS_WARNINGS="null"
LYNIS_SUGGESTIONS="null"
if (( WITH_LYNIS )) && command -v lynis >/dev/null 2>&1; then
    lynis audit system --quiet --no-colors >/dev/null 2>&1 || true
    if [[ -r /var/log/lynis-report.dat ]]; then
        LYNIS_INDEX="$(awk -F= '/^hardening_index=/{print $2}' /var/log/lynis-report.dat | tail -1)"
        LYNIS_WARNINGS="$(grep -c '^warning\[\]=' /var/log/lynis-report.dat || echo 0)"
        LYNIS_SUGGESTIONS="$(grep -c '^suggestion\[\]=' /var/log/lynis-report.dat || echo 0)"
        LYNIS_INDEX="${LYNIS_INDEX:-null}"
    fi
fi

#-------------------------------------------------------------------------------
# Emit the JSON evidence artifact
#-------------------------------------------------------------------------------
{
    printf '{\n'
    printf '  "meta": {\n'
    printf '    "artifact": "baseline_snapshot",\n'
    printf '    "task": "0-baseline_snapshot.sh",\n'
    printf '    "schema_version": "1.0",\n'
    printf '    "phase": "pre-hardening",\n'
    printf '    "captured_at_utc": "%s",\n' "$TIMESTAMP"
    printf '    "captured_by": "%s"\n' "$(json_escape "${SUDO_USER:-root}")"
    printf '  },\n'

    printf '  "system": {\n'
    printf '    "hostname": "%s",\n' "$(json_escape "$HOSTNAME_SHORT")"
    printf '    "fqdn": "%s",\n' "$(json_escape "$FQDN")"
    printf '    "os": "%s",\n' "$(json_escape "$OS_NAME")"
    printf '    "kernel": "%s",\n' "$(json_escape "$KERNEL")"
    printf '    "architecture": "%s",\n' "$(json_escape "$ARCH")"
    printf '    "boot_time": "%s",\n' "$(json_escape "$BOOT_TIME")"
    printf '    "uptime": "%s"\n' "$(json_escape "$UPTIME_PRETTY")"
    printf '  },\n'

    printf '  "services": {\n'
    printf '    "running_count": %s,\n' "$SERVICES_COUNT"
    printf '    "running": '
    printf '%s\n' "$SERVICES_RAW" | json_array_from_stdin
    printf '\n  },\n'

    printf '  "network": {\n'
    printf '    "listening_count": %s,\n' "$PORTS_COUNT"
    printf '    "listening": '
    printf '%s\n' "$PORTS_RAW" | json_array_from_stdin
    printf '\n  },\n'

    printf '  "filesystem": {\n'
    printf '    "suid_count": %s,\n' "$SUID_COUNT"
    printf '    "sgid_count": %s,\n' "$SGID_COUNT"
    printf '    "world_writable_file_count": %s,\n' "$WW_FILES_COUNT"
    printf '    "world_writable_dir_no_sticky_count": %s,\n' "$WW_DIRS_COUNT"
    printf '    "excluded_paths": '
    printf '%s\n' "${EXCLUDE_PATHS[@]}" | json_array_from_stdin
    printf ',\n    "suid_binaries": '
    printf '%s\n' "$SUID_RAW" | json_array_from_stdin
    printf ',\n    "sgid_binaries": '
    printf '%s\n' "$SGID_RAW" | json_array_from_stdin
    printf ',\n    "world_writable_files": '
    printf '%s\n' "$WW_FILES_RAW" | json_array_from_stdin
    printf ',\n    "world_writable_dirs_no_sticky": '
    printf '%s\n' "$WW_DIRS_RAW" | json_array_from_stdin
    printf ',\n    "mounts": '
    printf '%s\n' "$MOUNTS_RAW" | json_array_from_stdin
    printf '\n  },\n'

    printf '  "sysctl": {\n'
    first=1
    for key in "${SYSCTL_KEYS[@]}"; do
        value="$(sysctl -n "$key" 2>/dev/null | tr '\n\t' '  ' | tr -s ' ' \
                 | sed 's/^ *//; s/ *$//' || true)"
        [[ -z "$value" ]] && value="unset"
        (( first )) && first=0 || printf ',\n'
        printf '    "%s": "%s"' "$(json_escape "$key")" "$(json_escape "$value")"
    done
    printf '\n  },\n'

    printf '  "ssh": {\n'
    first=1
    for key in "${SSH_KEYS[@]}"; do
        value="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk -v k="$key" '$1==k {$1=""; sub(/^ /,""); print; exit}')"
        [[ -z "$value" ]] && value="not_set"
        (( first )) && first=0 || printf ',\n'
        printf '    "%s": "%s"' "$(json_escape "$key")" "$(json_escape "$value")"
    done
    printf '\n  },\n'

    printf '  "accounts": {\n'
    printf '    "interactive_users": '
    printf '%s\n' "$INTERACTIVE_USERS" | json_array_from_stdin
    printf ',\n    "uid0_accounts": '
    printf '%s\n' "$UID0_ACCOUNTS" | json_array_from_stdin
    printf ',\n    "sudo_group_members": '
    printf '%s\n' "$SUDO_MEMBERS" | json_array_from_stdin
    printf ',\n    "admin_group_members": '
    printf '%s\n' "$ADMIN_MEMBERS" | json_array_from_stdin
    printf ',\n    "nopasswd_sudo_rules": '
    printf '%s\n' "$NOPASSWD_SUDOERS" | json_array_from_stdin
    printf ',\n    "empty_password_accounts": '
    printf '%s\n' "$EMPTY_PASSWORD_ACCTS" | json_array_from_stdin
    printf '\n  },\n'

    printf '  "lynis": {\n'
    printf '    "hardening_index": %s,\n' "${LYNIS_INDEX:-null}"
    printf '    "warnings": %s,\n' "${LYNIS_WARNINGS:-null}"
    printf '    "suggestions": %s\n' "${LYNIS_SUGGESTIONS:-null}"
    printf '  }\n'
    printf '}\n'
} > "$JSON_FILE"

# Evidence must not be world-readable: it is a map of every SUID binary and
# open port on the host.
chmod 0640 "$JSON_FILE"

# Stable path for the hardening pipeline. ln -sfn is idempotent by design.
ln -sfn "$JSON_FILE" "$LATEST_LINK"

#-------------------------------------------------------------------------------
# Human-readable summary
#-------------------------------------------------------------------------------
echo "Hostname: ${HOSTNAME_SHORT}"
echo "OS: ${OS_NAME}"
echo "Running services: ${SERVICES_COUNT}"
echo "Open ports: ${PORTS_COUNT}"
echo "SUID binaries: ${SUID_COUNT}"
echo "SGID binaries: ${SGID_COUNT}"
echo "World-writable files: ${WW_FILES_COUNT}"
echo ""
echo "Baseline written to: ${JSON_FILE}"

exit 0
