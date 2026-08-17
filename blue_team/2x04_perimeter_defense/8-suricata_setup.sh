#!/bin/bash

set -e

RULE_SOURCE="/home/analyst/MedDefense_Lab/suricata/rules"
RULE_DEST="/var/lib/suricata/rules"

CONFIG_FILE="./suricata.yaml"
VERIFY_FILE="./setup_verification.json"

SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"
SMOKE_DIR="/tmp/suricata-smoke"


# -------------------------------------------------
# Must run as root
# -------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi


# -------------------------------------------------
# 1. Install Suricata and jq if needed
# -------------------------------------------------

echo "[*] Checking packages..."

NEED_INSTALL=0

if ! command -v suricata >/dev/null 2>&1; then
    NEED_INSTALL=1
fi

if ! command -v jq >/dev/null 2>&1; then
    NEED_INSTALL=1
fi

if [ "$NEED_INSTALL" -eq 1 ]; then
    apt-get update
    apt-get install -y suricata jq
fi

# This project uses offline replay only.
# do not start suricata.service.
systemctl stop suricata.service 2>/dev/null || true

INSTALLED_VERSION=$(suricata --version 2>&1 |
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' |
    head -1)

echo "[*] Suricata version: $INSTALLED_VERSION"


# -------------------------------------------------
# 2. Copy provided rules
# -------------------------------------------------

echo "[*] Copying rules..."

if [ ! -d "$RULE_SOURCE" ]; then
    echo "Rules directory not found: $RULE_SOURCE"
    exit 1
fi

mkdir -p "$RULE_DEST"

SOURCE_COUNT=$(find "$RULE_SOURCE" \
    -maxdepth 1 \
    -type f \
    -name "*.rules" |
    wc -l)

if [ "$SOURCE_COUNT" -eq 0 ]; then
    echo "No .rules files found."
    exit 1
fi


for FILE in "$RULE_SOURCE"/*.rules
do
    cp "$FILE" "$RULE_DEST/"
done


# Placeholder custom MedDefense rule file
touch "$RULE_DEST/meddefense.rules"


# Verify copied file count
COPIED_COUNT=0

for FILE in "$RULE_SOURCE"/*.rules
do
    NAME=$(basename "$FILE")

    if [ -f "$RULE_DEST/$NAME" ]; then
        COPIED_COUNT=$((COPIED_COUNT + 1))
    fi
done


echo "[*] Source rule files: $SOURCE_COUNT"
echo "[*] Copied rule files: $COPIED_COUNT"

if [ "$COPIED_COUNT" -ne "$SOURCE_COUNT" ]; then
    echo "Rule file count verification failed."
    exit 1
fi


# -------------------------------------------------
# Build rule file list
# -------------------------------------------------

mapfile -t RULE_FILES < <(
    find "$RULE_SOURCE" \
        -maxdepth 1 \
        -type f \
        -name "*.rules" \
        -printf "%f\n" |
    sort
)


# Add meddefense.rules if it is not already included
FOUND_MEDDEFENSE=0

for FILE in "${RULE_FILES[@]}"
do
    if [ "$FILE" = "meddefense.rules" ]; then
        FOUND_MEDDEFENSE=1
    fi
done

if [ "$FOUND_MEDDEFENSE" -eq 0 ]; then
    RULE_FILES+=("meddefense.rules")
fi


# -------------------------------------------------
# 3. Render suricata.yaml
# -------------------------------------------------

echo "[*] Creating suricata.yaml..."

cat > "$CONFIG_FILE" << 'EOF'
%YAML 1.1
---

vars:

  address-groups:
    HOME_NET: "[10.10.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544


default-rule-path: /var/lib/suricata/rules

rule-files:
EOF


# Add each rule file to YAML
for FILE in "${RULE_FILES[@]}"
do
    echo "  - $FILE" >> "$CONFIG_FILE"
done


cat >> "$CONFIG_FILE" << 'EOF'


default-log-dir: /var/log/suricata


# EVE output
# type: json
outputs:

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json

      types:
        - alert
        - http
        - dns
        - tls

        # Generates fileinfo events in eve.json
        - files:
            force-magic: no


# pcap-file: enabled
# Offline replay is activated with the -r option.
pcap-file:
  checksum-checks: no

EOF


mkdir -p /var/log/suricata


# -------------------------------------------------
# Count rules
# -------------------------------------------------

RULE_COUNT=$(awk '
    NF && $1 !~ /^#/ {
        count++
    }
    END {
        print count + 0
    }
' "$RULE_DEST"/*.rules)

echo "[*] Rules found: $RULE_COUNT"


# -------------------------------------------------
# 4. Test Suricata configuration
# -------------------------------------------------

echo "[*] Testing configuration..."

set +e

suricata -T -c ./suricata.yaml -v

CONFIG_TEST_EXIT=$?

set -e

echo "[*] Config test exit code: $CONFIG_TEST_EXIT"


# -------------------------------------------------
# 5. Smoke PCAP test
# -------------------------------------------------

SMOKE_ALERTS=0

rm -rf "$SMOKE_DIR"
mkdir -p "$SMOKE_DIR"


if [ "$CONFIG_TEST_EXIT" -eq 0 ]; then

    if [ ! -f "$SMOKE_PCAP" ]; then
        echo "Smoke PCAP not found: $SMOKE_PCAP"
    else

        echo "[*] Running smoke PCAP..."

        set +e

        suricata \
            -c ./suricata.yaml \
            -r /home/analyst/MedDefense_Lab/PCAPs/smoke.pcap \
            -l /tmp/suricata-smoke/

        SMOKE_EXIT=$?

        set -e


        if [ -f "$SMOKE_DIR/eve.json" ]; then

            SMOKE_ALERTS=$(jq -s '
                [
                    .[] |
                    select(.event_type == "alert")
                ] |
                length
            ' "$SMOKE_DIR/eve.json")

        fi

    fi

fi


echo "[*] Smoke alerts: $SMOKE_ALERTS"


# -------------------------------------------------
# 6. Create setup_verification.json
# -------------------------------------------------

RULE_FILES_JSON=$(printf '%s\n' "${RULE_FILES[@]}" |
    jq -R . |
    jq -s .)


jq -n \
    --arg version "$INSTALLED_VERSION" \
    --argjson rule_files "$RULE_FILES_JSON" \
    --argjson rule_count "$RULE_COUNT" \
    --argjson config_exit "$CONFIG_TEST_EXIT" \
    --arg smoke_pcap "$SMOKE_PCAP" \
    --argjson smoke_alerts "$SMOKE_ALERTS" \
    '{
        installed_version: $version,
        rule_files_loaded: $rule_files,
        rule_count: $rule_count,
        config_test_exit: $config_exit,
        smoke_pcap: $smoke_pcap,
        smoke_alerts: $smoke_alerts
    }' > "$VERIFY_FILE"


echo ""
echo "Suricata Offline Setup"
echo "======================"
echo "Version:          $INSTALLED_VERSION"
echo "Rule files:       ${#RULE_FILES[@]}"
echo "Rule count:       $RULE_COUNT"
echo "Config test exit: $CONFIG_TEST_EXIT"
echo "Smoke alerts:     $SMOKE_ALERTS"
echo "Output:           $VERIFY_FILE"


# Smoke test must contain at least one alert
if [ "$CONFIG_TEST_EXIT" -ne 0 ]; then
    echo "ERROR: Suricata configuration test failed."
    exit 1
fi

if [ "$SMOKE_ALERTS" -lt 1 ]; then
    echo "ERROR: smoke.pcap produced no alerts."
    exit 1
fi

echo "Suricata offline setup verified successfully."
