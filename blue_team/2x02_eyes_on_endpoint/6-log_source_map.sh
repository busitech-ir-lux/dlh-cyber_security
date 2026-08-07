#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Inventory active Linux log sources and their security relevance.
# author: Mahdi Hamidi

set -e
set -u
set -o pipefail

echo "[*] Discovering log sources..."

found=0
missing=0

printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
"Source" "Path" "Format" "Rotation" "events/hr" "Relevance"

printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
"------" "----" "------" "--------" "---------" "---------"


# Get rotation information
get_rotation() {

    file="$1"
    result="unknown"

    config=$(grep -rl "$file" /etc/logrotate.conf /etc/logrotate.d 2>/dev/null | head -1 || true)

    if [ -n "$config" ]; then

        period=$(grep -E "^[[:space:]]*(daily|weekly|monthly|yearly)" "$config" |
            head -1 | xargs || true)

        rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]+[0-9]+" "$config" |
            head -1 | awk '{print $2}' || true)

        if [ -n "$period" ] && [ -n "$rotate" ]; then
            result="$period x$rotate"
        elif [ -n "$period" ]; then
            result="$period"
        fi
    fi

    echo "$result"
}


# Estimate events generated during current hour
get_events_hour() {

    file="$1"
    format="$2"

    if [ ! -s "$file" ]; then
        echo "0"
        return
    fi

    case "$format" in

        syslog)
            pattern=$(date "+%b %e %H:")
            grep -c "$pattern" "$file" 2>/dev/null || true
            ;;

        combined)
            pattern=$(date "+%d/%b/%Y:%H:")
            grep -c "$pattern" "$file" 2>/dev/null || true
            ;;

        audit)
            # Simple estimate using recent audit records
            ausearch -ts recent 2>/dev/null |
                grep -c "^type=" || true
            ;;

        *)
            # Simple estimate for custom logs
            lines=$(wc -l < "$file")
            echo $((lines / 24))
            ;;
    esac
}


check_log() {

    name="$1"
    path="$2"
    format="$3"
    relevance="$4"

    if [ -f "$path" ]; then

        rotation=$(get_rotation "$path")
        events=$(get_events_hour "$path")
        size=$(du -h "$path" 2>/dev/null | awk '{print $1}')

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
        "$name" "$path" "$format" "$rotation" "$events" "$relevance"

        echo "    Size: $size" > /dev/null

        found=$((found + 1))

        if [ ! -s "$path" ]; then
            echo "[WARNING] $path exists but is not generating events."
        fi

    else
        echo "[MISSING] $name -> $path"
        missing=$((missing + 1))
    fi
}


# Expected security-relevant logs
check_log "auth.log" \
    "/var/log/auth.log" \
    "syslog" \
    "critical"

check_log "audit.log" \
    "/var/log/audit/audit.log" \
    "audit" \
    "critical"

check_log "syslog" \
    "/var/log/syslog" \
    "syslog" \
    "high"

check_log "kern.log" \
    "/var/log/kern.log" \
    "syslog" \
    "medium"

check_log "dpkg.log" \
    "/var/log/dpkg.log" \
    "custom" \
    "medium"

check_log "apache2 access" \
    "/var/log/apache2/access.log" \
    "combined" \
    "high"

check_log "apache2 error" \
    "/var/log/apache2/error.log" \
    "custom" \
    "high"


# Discover some additional security-relevant logs
for extra in \
    /var/log/fail2ban.log \
    /var/log/ufw.log \
    /var/log/mysql/error.log
do
    if [ -f "$extra" ]; then

        name=$(basename "$extra")
        rotation=$(get_rotation "$extra")
        events=$(get_events_hour "$extra" "custom")
        size=$(du -h "$extra" | awk '{print $1}')

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
        "$name" "$extra" "custom" "$rotation" "$events" "high"

        found=$((found + 1))

        echo "    Size: $size" > /dev/null
    fi
done


echo "Sources found: $found | Missing: $missing"