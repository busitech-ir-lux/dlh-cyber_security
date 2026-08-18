#!/bin/bash

set -e

BLOCKLIST="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST="/home/analyst/MedDefense_Lab/dns/allowlist.txt"

UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCK_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
BASE_CONF="/etc/dnsmasq.d/meddefense-base.conf"

LOG_FILE="/var/log/dnsmasq.log"


# -------------------------------------------------
# Must run as root
# -------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi


# -------------------------------------------------
# 1. Install dnsmasq if not present
# -------------------------------------------------

echo -n "[*] Ensuring dnsmasq is installed... "

if ! command -v dnsmasq >/dev/null 2>&1; then
    apt-get update
    apt-get install -y dnsmasq
fi

# dig is needed for validation
if ! command -v dig >/dev/null 2>&1; then
    apt-get update
    apt-get install -y dnsutils
fi

DNSMASQ_VERSION=$(dnsmasq --version | head -1)

echo "$DNSMASQ_VERSION"


# -------------------------------------------------
# Check required project files
# -------------------------------------------------

if [ ! -f "$BLOCKLIST" ]; then
    echo "Blocklist not found: $BLOCKLIST"
    exit 1
fi

if [ ! -f "$ALLOWLIST" ]; then
    echo "Allowlist not found: $ALLOWLIST"
    exit 1
fi

if [ ! -f "$UPSTREAM_CONF" ]; then
    echo "Upstream config not found: $UPSTREAM_CONF"
    exit 1
fi


# -------------------------------------------------
# 2. Render basic dnsmasq configuration
# -------------------------------------------------

cat > "$BASE_CONF" << 'EOF'
# MedDefense DNS filtering

# Listen only on local loopback
listen-address=127.0.0.1
bind-interfaces

# Use only the upstream configured in:
# /etc/dnsmasq.d/meddefense-upstream.conf
no-resolv

# Log every DNS query
log-queries
log-facility=/var/log/dnsmasq.log
EOF


# -------------------------------------------------
# 3. Render blocklist
#
# Each blocked domain returns 0.0.0.0
# -------------------------------------------------

echo -n "[*] Rendering blocklist... "

> "$BLOCK_CONF"

BLOCK_COUNT=0

while IFS= read -r DOMAIN
do
    # Remove spaces
    DOMAIN=$(echo "$DOMAIN" | xargs)

    # Skip empty lines
    if [ -z "$DOMAIN" ]; then
        continue
    fi

    # Skip comments
    case "$DOMAIN" in
        \#*)
            continue
            ;;
    esac

    echo "address=/$DOMAIN/0.0.0.0" >> "$BLOCK_CONF"

    BLOCK_COUNT=$((BLOCK_COUNT + 1))

done < "$BLOCKLIST"

echo "($BLOCK_COUNT domains)"


# -------------------------------------------------
# Make sure dnsmasq.d is included
# -------------------------------------------------

if ! grep -qE '^[[:space:]]*conf-dir=/etc/dnsmasq.d' /etc/dnsmasq.conf
then
    echo "conf-dir=/etc/dnsmasq.d" >> /etc/dnsmasq.conf
fi


# -------------------------------------------------
# Prepare log file
# -------------------------------------------------

touch "$LOG_FILE"


# -------------------------------------------------
# Important:
# do not rewrite /etc/resolv.conf
# -------------------------------------------------

# This task configures dnsmasq on 127.0.0.1 only.
# do not rewrite /etc/resolv.conf


# -------------------------------------------------
# Check dnsmasq configuration before restart
# -------------------------------------------------

echo "[*] Checking dnsmasq configuration..."

dnsmasq --test


# -------------------------------------------------
# 4. Restart and verify service
# -------------------------------------------------

echo -n "[*] Restarting dnsmasq.service... "

systemctl restart dnsmasq

if systemctl is-active --quiet dnsmasq
then
    echo "active"
else
    echo "failed"
    systemctl status dnsmasq --no-pager
    exit 1
fi


# -------------------------------------------------
# 5. Pick validation domains
# -------------------------------------------------

ALLOWED_DOMAIN=$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST" |
    head -1 |
    xargs)

BLOCKED_DOMAIN=$(grep -vE '^[[:space:]]*(#|$)' "$BLOCKLIST" |
    head -1 |
    xargs)

if [ -z "$ALLOWED_DOMAIN" ]; then
    echo "No allowed domain found in allowlist.txt"
    exit 1
fi

if [ -z "$BLOCKED_DOMAIN" ]; then
    echo "No blocked domain found in blocklist.txt"
    exit 1
fi


# -------------------------------------------------
# Find a domain not in either list
# -------------------------------------------------

UNKNOWN_DOMAIN="ubuntu.com"

if grep -Fxqi "$UNKNOWN_DOMAIN" "$BLOCKLIST" ||
   grep -Fxqi "$UNKNOWN_DOMAIN" "$ALLOWLIST"
then
    UNKNOWN_DOMAIN="debian.org"
fi


# -------------------------------------------------
# Validation queries using dig @127.0.0.1
# -------------------------------------------------

echo "[*] Validation queries..."


# -------------------------
# Known allowed domain
# -------------------------

ALLOWED_ANSWER=$(dig @127.0.0.1 "$ALLOWED_DOMAIN" A +short |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    head -1 || true)

echo "  dig @127.0.0.1 $ALLOWED_DOMAIN"

if [ -n "$ALLOWED_ANSWER" ] &&
   [ "$ALLOWED_ANSWER" != "0.0.0.0" ]
then
    echo "      -> $ALLOWED_ANSWER    expected allow      PASS"
    ALLOW_PASS=1
else
    echo "      -> ${ALLOWED_ANSWER:-no-answer}    expected allow      FAIL"
    ALLOW_PASS=0
fi


# -------------------------
# Known blocked domain
# -------------------------

BLOCKED_ANSWER=$(dig @127.0.0.1 "$BLOCKED_DOMAIN" A +short |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    head -1 || true)

echo "  dig @127.0.0.1 $BLOCKED_DOMAIN"

if [ "$BLOCKED_ANSWER" = "0.0.0.0" ]
then
    echo "      -> $BLOCKED_ANSWER    expected sinkhole   PASS"
    BLOCK_PASS=1
else
    echo "      -> ${BLOCKED_ANSWER:-no-answer}    expected sinkhole   FAIL"
    BLOCK_PASS=0
fi


# -------------------------
# Domain not in either list
# -------------------------

UNKNOWN_ANSWER=$(dig @127.0.0.1 "$UNKNOWN_DOMAIN" A +short |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    head -1 || true)

echo "  dig @127.0.0.1 $UNKNOWN_DOMAIN"

if [ -n "$UNKNOWN_ANSWER" ] &&
   [ "$UNKNOWN_ANSWER" != "0.0.0.0" ]
then
    echo "      -> $UNKNOWN_ANSWER    expected allow      PASS"
    UNKNOWN_PASS=1
else
    echo "      -> ${UNKNOWN_ANSWER:-no-answer}    expected allow      FAIL"
    UNKNOWN_PASS=0
fi


# -------------------------------------------------
# Output summary as JSON for audit trail
# -------------------------------------------------

echo ""
echo "[*] Generating audit summary..."

if ! command -v jq >/dev/null 2>&1; then
    apt-get update
    apt-get install -y jq
fi

SERVICE_STATUS=$(systemctl is-active dnsmasq 2>/dev/null || echo "inactive")

jq -n \
    --arg version "$DNSMASQ_VERSION" \
    --argjson domains "$BLOCK_COUNT" \
    --arg blocklist "$BLOCK_CONF" \
    --arg upstream "$UPSTREAM_CONF" \
    --arg service_status "$SERVICE_STATUS" \
    --argjson allow_pass "$ALLOW_PASS" \
    --argjson block_pass "$BLOCK_PASS" \
    --argjson unknown_pass "$UNKNOWN_PASS" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        dnsmasq_version: $version,
        blocked_domains: $domains,
        config_files: {
            blocklist: $blocklist,
            upstream: $upstream
        },
        service_status: $service_status,
        validation: {
            allowed_domain_pass: $allow_pass,
            blocked_domain_pass: $block_pass,
            upstream_domain_pass: $unknown_pass
        },
        generated_at: $timestamp
    }' > dns_filter_report.json

echo "DNS filter report written to dns_filter_report.json"


# -------------------------------------------------
# Final result
# -------------------------------------------------

if [ "$ALLOW_PASS" -eq 1 ] &&
   [ "$BLOCK_PASS" -eq 1 ] &&
   [ "$UNKNOWN_PASS" -eq 1 ]
then
    echo "DNS filtering validation passed."
    exit 0
else
    echo "DNS filtering validation failed."
    exit 1
fi
