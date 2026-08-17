#!/bin/bash

set -e

INPUT_FILE="segmentation_rules.json"
OUTPUT_FILE="nftables.conf"
EVIDENCE_FILE="nftables-after.txt"

# This endpoint is assumed to be INTERNAL unless changed.
LOCAL_ZONE="${LOCAL_ZONE:-INTERNAL}"

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
ROLLBACK_FILE="/var/backups/nftables-rollback-${TIMESTAMP}.nft"

EXPECTED_RULES=0


# -------------------------------------------------
# Basic checks
# -------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "segmentation_rules.json not found"
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "nftables is not installed"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is not installed"
    exit 1
fi


# Check that LOCAL_ZONE exists
if ! jq -e --arg zone "$LOCAL_ZONE" \
    '.zones[] | select(.name == $zone)' \
    "$INPUT_FILE" >/dev/null
then
    echo "Unknown LOCAL_ZONE: $LOCAL_ZONE"
    exit 1
fi


# -------------------------------------------------
# Small helper to convert zone names to set names
#
# DMZ      -> zone_dmz
# INTERNAL -> zone_internal
# MGMT     -> zone_mgmt
# MEDDEV   -> zone_meddev
# -------------------------------------------------

zone_set()
{
    echo "zone_$(echo "$1" | tr '[:upper:]' '[:lower:]')"
}


# -------------------------------------------------
# Helper for adding nft rules and counting them
# -------------------------------------------------

add_rule()
{
    echo "        $1" >> "$OUTPUT_FILE"
    EXPECTED_RULES=$((EXPECTED_RULES + 1))
}


# -------------------------------------------------
# Start rendering nftables.conf
# -------------------------------------------------

> "$OUTPUT_FILE"

echo "# Generated from segmentation_rules.json" >> "$OUTPUT_FILE"
echo "# Local zone: $LOCAL_ZONE" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# If our table already exists, flush only this table.
# Do not flush the complete system ruleset.
if nft list table inet meddefense >/dev/null 2>&1; then
    echo "flush table inet meddefense" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi


# Required table:
# table inet meddefense
echo "table inet meddefense {" >> "$OUTPUT_FILE"


# -------------------------------------------------
# Named set per zone
# -------------------------------------------------

while IFS=$'\t' read -r ZONE CIDR
do
    SET_NAME=$(zone_set "$ZONE")

    cat >> "$OUTPUT_FILE" <<EOF

    set $SET_NAME {
        type ipv4_addr
        flags interval
        elements = { $CIDR }
    }
EOF

done < <(
    jq -r '.zones[] | [.name, .cidr] | @tsv' "$INPUT_FILE"
)


# =================================================
# INPUT CHAIN
# =================================================

cat >> "$OUTPUT_FILE" <<'EOF'

    chain input {
        type filter hook input priority 0;
        policy drop;
EOF


# Connection tracking accept
add_rule 'ct state established,related accept'

# Loopback accept
add_rule 'iifname "lo" accept'

# Minimal ICMP
add_rule 'ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept'

# Minimal ICMPv6
add_rule 'ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded } accept'


# -------------------------------------------------
# INPUT allow rules
#
# Only flows whose dst_zone is this local host zone
# become input rules.
# -------------------------------------------------

while IFS=$'\t' read -r SRC DST PROTO DPORT JUSTIFICATION SRC_RESTRICTION SRC_IP SRC_HOST
do

    echo "        # $JUSTIFICATION" >> "$OUTPUT_FILE"

    SOURCE_MATCH=""

    if [ "$SRC" != "ALL" ]; then

        SRC_SET=$(zone_set "$SRC")

        # Special case:
        # DMZ database access must come only from named hosts.
        if [ "$SRC_RESTRICTION" = "named_dmz_application_hosts" ]; then

            RESOLVED_IP="$SRC_IP"

            # If a hostname is provided, try to resolve it.
            if [ -z "$RESOLVED_IP" ] && [ -n "$SRC_HOST" ]; then
                RESOLVED_IP=$(getent ahostsv4 "$SRC_HOST" 2>/dev/null |
                    awk 'NR==1 {print $1}')
            fi

            if [ -z "$RESOLVED_IP" ]; then
                echo "        # SKIPPED: named DMZ host has no src_ip/src_host" >> "$OUTPUT_FILE"
                continue
            fi

            SOURCE_MATCH="ip saddr $RESOLVED_IP"

        else
            SOURCE_MATCH="ip saddr @$SRC_SET"
        fi
    fi


    if [ "$PROTO" = "tcp" ]; then
        add_rule "$SOURCE_MATCH tcp dport $DPORT counter accept"

    elif [ "$PROTO" = "udp" ]; then
        add_rule "$SOURCE_MATCH udp dport $DPORT counter accept"
    fi

done < <(
    jq -r \
        --arg zone "$LOCAL_ZONE" \
        '
        .flows[]
        | select(
            .action == "allow"
            and .dst_zone == $zone
        )
        |
        [
            .src_zone,
            .dst_zone,
            .proto,
            (.dport | tostring),
            (.justification // ""),
            (.src_restriction // ""),
            (.src_ip // ""),
            (.src_host // "")
        ]
        | @tsv
        ' "$INPUT_FILE"
)


# Terminal logged drop
add_rule 'counter log prefix "MEDDEFENSE INPUT DROP: " drop'

echo "    }" >> "$OUTPUT_FILE"


# =================================================
# FORWARD CHAIN
# =================================================

cat >> "$OUTPUT_FILE" <<'EOF'

    chain forward {
        type filter hook forward priority 0;
        policy drop;
EOF


# Allow return traffic
add_rule 'ct state established,related accept'


# -------------------------------------------------
# Cross-zone allow flows
# -------------------------------------------------

while IFS=$'\t' read -r SRC DST PROTO DPORT JUSTIFICATION SRC_RESTRICTION SRC_IP SRC_HOST
do

    echo "        # $JUSTIFICATION" >> "$OUTPUT_FILE"

    DST_SET=$(zone_set "$DST")

    SOURCE_MATCH=""

    if [ "$SRC" != "ALL" ]; then

        SRC_SET=$(zone_set "$SRC")

        if [ "$SRC_RESTRICTION" = "named_dmz_application_hosts" ]; then

            RESOLVED_IP="$SRC_IP"

            if [ -z "$RESOLVED_IP" ] && [ -n "$SRC_HOST" ]; then
                RESOLVED_IP=$(getent ahostsv4 "$SRC_HOST" 2>/dev/null |
                    awk 'NR==1 {print $1}')
            fi

            if [ -z "$RESOLVED_IP" ]; then
                echo "        # SKIPPED: named DMZ application host has no IP" >> "$OUTPUT_FILE"
                continue
            fi

            SOURCE_MATCH="ip saddr $RESOLVED_IP"

        else
            SOURCE_MATCH="ip saddr @$SRC_SET"
        fi

    fi


    if [ "$PROTO" = "tcp" ]; then
        add_rule "$SOURCE_MATCH ip daddr @$DST_SET tcp dport $DPORT counter accept"

    elif [ "$PROTO" = "udp" ]; then
        add_rule "$SOURCE_MATCH ip daddr @$DST_SET udp dport $DPORT counter accept"
    fi

done < <(
    jq -r '
        .flows[]
        | select(
            .action == "allow"
            and .src_zone != .dst_zone
        )
        |
        [
            .src_zone,
            .dst_zone,
            .proto,
            (.dport | tostring),
            (.justification // ""),
            (.src_restriction // ""),
            (.src_ip // ""),
            (.src_host // "")
        ]
        | @tsv
    ' "$INPUT_FILE"
)


# -------------------------------------------------
# Explicit deny_all zone pairs
# -------------------------------------------------

while IFS=$'\t' read -r SRC DST JUSTIFICATION
do

    # Ignore a destination that is not a defined zone.
    if ! jq -e --arg zone "$DST" \
        '.zones[] | select(.name == $zone)' \
        "$INPUT_FILE" >/dev/null
    then
        continue
    fi

    SRC_SET=$(zone_set "$SRC")
    DST_SET=$(zone_set "$DST")

    echo "        # $JUSTIFICATION" >> "$OUTPUT_FILE"

    add_rule "ip saddr @$SRC_SET ip daddr @$DST_SET counter log prefix \"MEDDEFENSE DENY: \" drop"

done < <(
    jq -r '
        .flows[]
        | select(.action == "deny_all")
        |
        [
            .src_zone,
            .dst_zone,
            (.justification // "")
        ]
        | @tsv
    ' "$INPUT_FILE"
)


# Terminal logged drop
add_rule 'counter log prefix "MEDDEFENSE FORWARD DROP: " drop'

echo "    }" >> "$OUTPUT_FILE"


# =================================================
# OUTPUT CHAIN
# =================================================

cat >> "$OUTPUT_FILE" <<'EOF'

    chain output {
        type filter hook output priority 0;
        policy accept;
EOF


# Keep replies and loopback working
add_rule 'ct state established,related accept'
add_rule 'oifname "lo" accept'


# -------------------------------------------------
# Render outbound allow flows for this local zone.
#
# They become important if a restrictive zone such
# as MEDDEV gets a final outbound drop.
# -------------------------------------------------

while IFS=$'\t' read -r DST PROTO DPORT JUSTIFICATION
do

    if ! jq -e --arg zone "$DST" \
        '.zones[] | select(.name == $zone)' \
        "$INPUT_FILE" >/dev/null
    then
        continue
    fi

    DST_SET=$(zone_set "$DST")

    echo "        # $JUSTIFICATION" >> "$OUTPUT_FILE"

    if [ "$PROTO" = "tcp" ]; then
        add_rule "ip daddr @$DST_SET tcp dport $DPORT counter accept"

    elif [ "$PROTO" = "udp" ]; then
        add_rule "ip daddr @$DST_SET udp dport $DPORT counter accept"
    fi

done < <(
    jq -r \
        --arg zone "$LOCAL_ZONE" \
        '
        .flows[]
        | select(
            .action == "allow"
            and .src_zone == $zone
            and .src_zone != .dst_zone
        )
        |
        [
            .dst_zone,
            .proto,
            (.dport | tostring),
            (.justification // "")
        ]
        | @tsv
        ' "$INPUT_FILE"
)


# -------------------------------------------------
# Explicit outbound restrictions
#
# MEDDEV:
# - no DMZ access
# - no public Internet access
# -------------------------------------------------

NO_DMZ=$(jq -r \
    --arg zone "$LOCAL_ZONE" \
    '
    .zones[]
    | select(.name == $zone)
    | (.outbound_restrictions // [])
    | index("no_dmz_access") != null
    ' "$INPUT_FILE")


NO_INTERNET=$(jq -r \
    --arg zone "$LOCAL_ZONE" \
    '
    .zones[]
    | select(.name == $zone)
    | (.outbound_restrictions // [])
    | index("no_public_internet_access") != null
    ' "$INPUT_FILE")


if [ "$NO_DMZ" = "true" ]; then
    add_rule 'ip daddr @zone_dmz counter log prefix "MEDDEFENSE OUT DMZ DROP: " drop'
fi


# MEDDEV is allowed only the explicit flows above.
# Everything else, including public Internet traffic,
# is dropped.
if [ "$NO_INTERNET" = "true" ]; then
    add_rule 'counter log prefix "MEDDEFENSE OUTPUT DROP: " drop'
fi


echo "    }" >> "$OUTPUT_FILE"

echo "}" >> "$OUTPUT_FILE"


# =================================================
# TEST THE RENDERED CONFIGURATION
# =================================================

echo "Checking nftables.conf..."

# Check-only parse. This does not apply the rules.
nft -c -f nftables.conf

echo "Syntax check passed."


# =================================================
# SAVE ROLLBACK
# =================================================

mkdir -p /var/backups

# Required rollback form:
# nft list ruleset > /var/backups/nftables-rollback-<timestamp>.nft

nft list ruleset > "$ROLLBACK_FILE"

chmod 600 "$ROLLBACK_FILE"

echo "Rollback saved to:"
echo "$ROLLBACK_FILE"


# =================================================
# APPLY ATOMICALLY
# =================================================

echo "Applying nftables.conf..."

nft -f nftables.conf

echo "Ruleset applied."


# =================================================
# VERIFY
# =================================================

# Verify with nft list ruleset
nft list ruleset > "$EVIDENCE_FILE"

ACTUAL_RULES=$(nft -j list table inet meddefense |
    jq '[.nftables[] | select(has("rule"))] | length')


echo ""
echo "nftables verification"
echo "====================="
echo "Expected rules: $EXPECTED_RULES"
echo "Loaded rules:   $ACTUAL_RULES"


if [ "$ACTUAL_RULES" -ne "$EXPECTED_RULES" ]; then

    echo ""
    echo "WARNING: rule count does not match."
    echo "Rollback file:"
    echo "$ROLLBACK_FILE"

    exit 1
fi


echo "Rule count verified successfully."
echo "Evidence saved to: $EVIDENCE_FILE"
echo "Configuration saved to: $OUTPUT_FILE"
