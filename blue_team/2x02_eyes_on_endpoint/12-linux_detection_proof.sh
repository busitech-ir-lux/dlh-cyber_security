#!/bin/bash
#
# name: 12-linux_detection_proof.sh
# Linux Detection Proof (Block 2, Task 12)
# author: Mahdi Hamidi
# purpose and description: Correlates the Task 11 ground truth against captured telemetry (auditd via
# ausearch, auth.log, syslog) and produces a detection matrix: which action was
# seen, by which source, under which audit key, with what detail level.
#
# For each action it searches a +/- 30s window around the recorded timestamp.
# Timestamps are UTC (ISO-8601 'Z'); ausearch expects LOCAL time, so we convert
# through epoch seconds to keep the window correct regardless of the host TZ.
#
# Requires: root (to read audit + auth logs). Uses ausearch if present.

set -e
set -o
set -u pipefail

INPUT_DEFAULT="linux_attack_log.json"

# ------------------------------ Setup - start ----------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Must run as root (sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="$SCRIPT_DIR/$INPUT_DEFAULT"
OUTPUT="$SCRIPT_DIR/linux_detection_matrix.json"

if [ ! -f "$INPUT" ]; then
    echo "[!] Ground truth not found: $INPUT" >&2
    exit 1
fi

# auth.log (Debian/Ubuntu) vs secure (RHEL/CentOS)
if [ -f /var/log/auth.log ]; then AUTHLOG=/var/log/auth.log; else AUTHLOG=/var/log/secure; fi

HAVE_AUSEARCH=1
command -v ausearch >/dev/null 2>&1 || { HAVE_AUSEARCH=0; echo "[!] ausearch not found - auditd rows will show as MISSED." >&2; }

# ------------------------------ Parse ground truth ---------------------------
# Field names are stable, so we extract without a jq dependency.
mapfile -t NUMS  < <(grep -oE '"action_number"[[:space:]]*:[[:space:]]*[0-9]+' "$INPUT" | grep -oE '[0-9]+')
mapfile -t TIMES < <(grep -oE '"timestamp"[[:space:]]*:[[:space:]]*"[^"]+"' "$INPUT" | sed -E 's/.*"([^"]+)"$/\1/')
TOTAL=${#NUMS[@]}

echo "[*] Loading ground truth ($TOTAL actions)..."
echo "[*] Searching telemetry..."

# ------------------------------ Helpers --------------------------------------
join_csv() { local IFS=,; echo "$*"; }

print_row() { printf '%-27s%-15s%-17s%-10s[%s]\n' "$1" "$2" "$3" "$4" "$5"; }

# Globals set by probes: DETAIL, STATUS, PRESENT[]
probe_auditd() {
    # $1 search_key ; rest = simple field tokens expected in the record
    local skey="$1"; shift
    local tokens=("$@")
    local out=""
    PRESENT=()
    if [ "$HAVE_AUSEARCH" -eq 1 ]; then
        out=$(ausearch -k "$skey" -ts "$SD" "$ST" -te "$ED" "$ET" -i 2>/dev/null)
        if [ -z "$out" ] && [ "${#FALLBACK[@]}" -gt 0 ]; then
            out=$(ausearch "${FALLBACK[@]}" -ts "$SD" "$ST" -te "$ED" "$ET" -i 2>/dev/null)
        fi
    fi
    if [ -n "$out" ]; then
        local t
        for t in "${tokens[@]}"; do
            printf '%s' "$out" | grep -qiE "$t" && PRESENT+=("$t")
        done
        if [ "${#PRESENT[@]}" -eq "${#tokens[@]}" ] && [ "${#tokens[@]}" -gt 0 ]; then
            DETAIL="Full"; else DETAIL="Partial"; fi
        STATUS="CAPTURED"
    else
        DETAIL="Missed"; STATUS="MISSED"; PRESENT=()
    fi
}

probe_log() {
    # $1 logfile ; rest = tokens that must appear (line-level)
    local file="$1"; shift
    local tokens=("$@")
    PRESENT=()
    if [ -f "$file" ]; then
        local t
        for t in "${tokens[@]}"; do
            grep -qE "$t" "$file" && PRESENT+=("$t")
        done
    fi
    if [ "${#PRESENT[@]}" -gt 0 ]; then
        if [ "${#PRESENT[@]}" -eq "${#tokens[@]}" ]; then DETAIL="Full"; else DETAIL="Partial"; fi
        STATUS="CAPTURED"
    else
        DETAIL="Missed"; STATUS="MISSED"
    fi
}

make_src_json() {
    # $1 source $2 key $3 detail $4 status ; rest = present tokens
    local s="$1" k="$2" d="$3" st="$4"; shift 4
    local arr="" f
    for f in "$@"; do arr="$arr\"$f\","; done
    arr="${arr%,}"
    printf '{"source":"%s","audit_key":"%s","detail":"%s","status":"%s","key_fields_present":[%s]}' \
        "$s" "$k" "$d" "$st" "$arr"
}

emit_source() {
    # $1 source $2 display_key  (uses ROWLABEL, DETAIL, STATUS, PRESENT globals)
    print_row "$ROWLABEL" "$1" "$2" "$DETAIL" "$STATUS"
    ROWLABEL=""
    [ "$STATUS" = "CAPTURED" ] && hits=$((hits+1))
    SRC_LIST+=("$(make_src_json "$1" "$2" "$DETAIL" "$STATUS" "${PRESENT[@]}")")
}

# ------------------------------ Correlate ------------------------------------
print_row "Action" "Source" "Key" "Detail" "Status" | sed 's/\[Status\]/Status/'
printf '%-27s%-15s%-17s%-10s%s\n' "------" "------" "---" "------" "------"

MATRIX=()
CAPTURED=0
MULTI=0

for i in "${!NUMS[@]}"; do
    num="${NUMS[$i]}"
    iso="${TIMES[$i]}"

    epoch=$(date -d "$iso" +%s 2>/dev/null)
    SD=$(date -d "@$((epoch-30))" +"%m/%d/%Y"); ST=$(date -d "@$((epoch-30))" +"%H:%M:%S")
    ED=$(date -d "@$((epoch+30))" +"%m/%d/%Y"); ET=$(date -d "@$((epoch+30))" +"%H:%M:%S")

    hits=0
    SRC_LIST=()
    FALLBACK=()

    case "$num" in
        1)  label="Create user";       ROWLABEL="$label"
            FALLBACK=(-m ADD_USER,USER_MGMT)
            probe_auditd "identity" "acct" "exe"; emit_source "auditd" "identity"
            probe_log "$AUTHLOG" "useradd" "testattacker"; emit_source "auth.log" "useradd"
            ;;
        2)  label="Modify sudoers";    ROWLABEL="$label"
            FALLBACK=(-f /etc/sudoers.d/backdoor)
            probe_auditd "sudoers" "name" "nametype"; emit_source "auditd" "sudoers"
            ;;
        3)  label="Execute from /tmp"; ROWLABEL="$label"
            FALLBACK=(-f /tmp/suspicious_bin)
            probe_auditd "process_exec" "exe" "comm"; emit_source "auditd" "process_exec"
            ;;
        4)  label="Reverse shell";     ROWLABEL="$label"
            FALLBACK=(-sc connect)
            probe_auditd "network_connect" "saddr"; emit_source "auditd" "network_connect"
            ;;
        5)  label="Cron persistence";  ROWLABEL="$label"
            FALLBACK=(-f /etc/cron.d/persistence_test)
            probe_auditd "cron_persist" "name" "nametype"; emit_source "auditd" "cron_persist"
            ;;
        6)  label="Access /etc/shadow"; ROWLABEL="$label"
            FALLBACK=(-f /etc/shadow)
            probe_auditd "identity" "name"; emit_source "auditd" "identity"
            ;;
        *)  continue ;;
    esac

    [ "$hits" -gt 0 ] && CAPTURED=$((CAPTURED+1))
    [ "$hits" -gt 1 ] && MULTI=$((MULTI+1))
    capbool=$([ "$hits" -gt 0 ] && echo true || echo false)

    MATRIX+=("$(printf '{"action_number":%d,"action":"%s","timestamp":"%s","captured":%s,"sources":[%s]}' \
        "$num" "$label" "$iso" "$capbool" "$(join_csv "${SRC_LIST[@]}")")")
done

# ------------------------------ Summary --------------------------------------
PCT=0; [ "$TOTAL" -gt 0 ] && PCT=$(( CAPTURED * 100 / TOTAL ))
echo ""
echo "Actions: $TOTAL | Captured: $CAPTURED/$TOTAL (${PCT}%) | Multi-source: $MULTI"

# ------------------------------ Save JSON ------------------------------------
{
    printf '{\n'
    printf '  "platform": "linux",\n'
    printf '  "generated_at": "%s",\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '  "total_actions": %d,\n' "$TOTAL"
    printf '  "captured": %d,\n' "$CAPTURED"
    printf '  "capture_rate": "%d%%",\n' "$PCT"
    printf '  "multi_source": %d,\n' "$MULTI"
    printf '  "matrix": [\n'
    for j in "${!MATRIX[@]}"; do
        if [ "$j" -lt $(( ${#MATRIX[@]} - 1 )) ]; then
            printf '    %s,\n' "${MATRIX[$j]}"
        else
            printf '    %s\n' "${MATRIX[$j]}"
        fi
    done
    printf '  ]\n'
    printf '}\n'
} > "$OUTPUT"

echo "Report saved to: $(basename "$OUTPUT")"
