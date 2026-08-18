#!/bin/bash

set -e

RULE_FILE="./meddefense.rules"
RULE_DEST="/var/lib/suricata/rules/meddefense.rules"
CONFIG="./suricata.yaml"

PCAP_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
TMP_BASE="/tmp/meddefense-rule-validation"


# -------------------------------------------------
# Check root
# -------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo."
    exit 1
fi


# -------------------------------------------------
# Check required files
# -------------------------------------------------

if [ ! -f "$RULE_FILE" ]; then
    echo "meddefense.rules not found"
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "suricata.yaml not found"
    exit 1
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo "Labeled PCAP directory not found"
    exit 1
fi


# -------------------------------------------------
# Copy and load meddefense.rules
# -------------------------------------------------

cp "$RULE_FILE" "$RULE_DEST"

RULE_COUNT=$(grep -c 'sid:9000' "$RULE_FILE")

echo "[*] Loading meddefense.rules... $RULE_COUNT rules"


# Test configuration first
suricata -T -c ./suricata.yaml >/dev/null

echo "[*] Running validation against labeled PCAPs..."
echo ""


# -------------------------------------------------
# Expected rule SIDs
# -------------------------------------------------

SIDS=(
    9000001
    9000007
    9000002
    9000003
    9000004
    9000005
    9000006
)

NAMES=(
    "MEDDEV TCP to Internet"
    "MEDDEV UDP to Internet"
    "Guest to SMB"
    "Large Outbound From Server"
    "DNS Tunneling Long Label"
    "Clinical to Unauthorized DB"
    "Telnet to MEDDEV"
)

PCAPS=(
    "meddev_egress.pcap"
    "meddev_egress.pcap"
    "guest_smb.pcap"
    "large_outbound.pcap"
    "dns_tunnel.pcap"
    "clinical_wrong_db.pcap"
    "telnet_meddev.pcap"
)


PASSED=0
FAILED=0


# -------------------------------------------------
# Test each rule
# -------------------------------------------------

for ((i=0; i<${#SIDS[@]}; i++))
do

    SID="${SIDS[$i]}"
    NAME="${NAMES[$i]}"
    PCAP="$PCAP_DIR/${PCAPS[$i]}"

    TMPDIR="$TMP_BASE/$SID"

    rm -rf "$TMPDIR"
    mkdir -p "$TMPDIR"

    echo "sid $SID $NAME"
    echo "  target: ${PCAPS[$i]}"
    echo "  expected: fire"


    if [ ! -f "$PCAP" ]; then
        echo "  observed: PCAP not found     FAIL"
        echo ""

        FAILED=$((FAILED + 1))
        continue
    fi


    # Run Suricata against labeled PCAP
    suricata \
        -c ./suricata.yaml \
        -r "$PCAP" \
        -l "$TMPDIR" \
        >/dev/null 2>&1


    EVE="$TMPDIR/eve.json"


    if [ ! -f "$EVE" ]; then
        HITS=0
    else

        HITS=$(jq -s \
            --argjson sid "$SID" \
            '
            [
                .[] |
                select(
                    .event_type == "alert"
                    and
                    .alert.signature_id == $sid
                )
            ]
            | length
            ' "$EVE")

    fi


    if [ "$HITS" -gt 0 ]; then

        echo "  observed: fire ($HITS hits)     PASS"

        PASSED=$((PASSED + 1))

    else

        echo "  observed: no fire               FAIL"

        FAILED=$((FAILED + 1))

    fi

    echo ""

done


# -------------------------------------------------
# Summary
# -------------------------------------------------

echo "Rules:  $RULE_COUNT"
echo "Passed: $PASSED"
echo "Failed: $FAILED"


# Exit non-zero if any rule failed
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

exit 0
