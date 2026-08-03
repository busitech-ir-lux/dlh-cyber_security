#!/bin/bash
set -euo pipefail

# Remote administration
WHITELIST=(
    "ssh.service"

    # Web application
    "apache2.service"

    # Billing database
    "mysql.service"

    # Host firewall
    "ufw.service"

    # Security auditing
    "auditd.service"

    # Mandatory access control
    "apparmor.service"

    # Scheduled jobs
    "cron.service"

    # System logging
    "rsyslog.service"

    # Time synchronization
    "systemd-timesyncd.service"
)

echo "[*] Scanning enabled services..."

mapfile -t ENABLED < <(
    systemctl list-unit-files \
        --type=service \
        --state=enabled \
        --no-legend |
    awk '{print $1}'
)

BEFORE=${#ENABLED[@]}
DISABLED=0

echo "    Enabled services found: $BEFORE"
echo "[*] Comparing against MedDefense whitelist (${#WHITELIST[@]} required services)..."

# Stop and disable non-whitelisted services
for service in "${ENABLED[@]}"; do
    if [[ ! " ${WHITELIST[*]} " =~ " $service " ]]; then
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" >/dev/null 2>&1 || true

        printf "  %-28s [STOPPED] [DISABLED]\n" "$service"
        ((DISABLED+=1))
    fi
done

# Verify required services
for service in "${WHITELIST[@]}"; do
    if systemctl is-active --quiet "$service"; then
        printf "  %-28s [ACTIVE]\n" "$service"
    else
        printf "  %-28s [INACTIVE]\n" "$service"
    fi
done

AFTER=$(systemctl list-unit-files \
    --type=service \
    --state=enabled \
    --no-legend |
    wc -l)

echo "Before: $BEFORE | After: $AFTER | Disabled: $DISABLED"
