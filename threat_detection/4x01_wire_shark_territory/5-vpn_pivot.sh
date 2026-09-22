#!/bin/bash

# Task 5 - VPN Pivot
# Usage:
#   ./5-vpn_pivot.sh full_timeline.pcap

PCAP="$1"

# VPN endpoint shown in the incident scenario
VPN_SERVER="10.10.0.1"
ACCOUNT="dmarsh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi


# =========================================================
# 1. FIND EXTERNAL VPN CONNECTION
# =========================================================

echo
echo "=== VPN CONNECTION IDENTIFIED ==="
echo "Filter:"
echo "  external IP -> $VPN_SERVER:443"
echo "  initial TCP SYN"

CANDIDATES="$TMP/vpn_candidates.tsv"

tshark -r "$PCAP" \
    -Y "ip.dst == $VPN_SERVER &&
        tcp.dstport == 443 &&
        tcp.flags.syn == 1 &&
        tcp.flags.ack == 0 &&
        !(ip.src == 10.0.0.0/8 ||
          ip.src == 172.16.0.0/12 ||
          ip.src == 192.168.0.0/16)" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport \
    -e tcp.stream 2>/dev/null > "$CANDIDATES"


if [ ! -s "$CANDIDATES" ]; then
    echo "No external HTTPS connection to $VPN_SERVER found."
    exit 1
fi


# Prefer a stream where dmarsh is visible.
VPN_LINE=""

while IFS=$'\t' read -r EPOCH TIME SRC SPORT DST DPORT STREAM; do

    if tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM" \
        -V 2>/dev/null |
        grep -qi "$ACCOUNT"; then

        VPN_LINE="$EPOCH|$TIME|$SRC|$SPORT|$DST|$DPORT|$STREAM"
        break
    fi

done < "$CANDIDATES"


# If username is encrypted/not visible,
# use the first external connection candidate.
if [ -z "$VPN_LINE" ]; then

    IFS=$'\t' read -r EPOCH TIME SRC SPORT DST DPORT STREAM \
        < "$CANDIDATES"

    VPN_LINE="$EPOCH|$TIME|$SRC|$SPORT|$DST|$DPORT|$STREAM"
fi


IFS='|' read -r \
    VPN_START \
    VPN_TIME \
    VPN_SRC \
    VPN_SPORT \
    VPN_DST \
    VPN_DPORT \
    VPN_STREAM <<< "$VPN_LINE"


echo "Timestamp: $VPN_TIME"
echo "Source: $VPN_SRC:$VPN_SPORT"
echo "Destination: $VPN_DST:$VPN_DPORT"
echo "Protocol: TCP/443 - SSL-VPN style HTTPS session"
echo "TCP stream: $VPN_STREAM"


# =========================================================
# AUTHENTICATION CONTEXT
# =========================================================

echo
echo "Authentication search:"
echo "  Search selected VPN stream for account: $ACCOUNT"

ACCOUNT_HIT=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $VPN_STREAM" \
        -V 2>/dev/null |
    grep -i -m1 "$ACCOUNT" || true
)


if [ -n "$ACCOUNT_HIT" ]; then

    echo "Authentication context: $ACCOUNT observed in VPN-related data"

else

    echo "Authentication context: username not visible in clear text"
    echo "The VPN authentication may be encrypted."
fi


# =========================================================
# 2. WHOIS / GEOIP
# =========================================================

echo
echo "=== GEOLOCATION ==="
echo "IP: $VPN_SRC"

WHOIS_FILE="$TMP/whois.txt"

if command -v whois >/dev/null 2>&1; then

    echo "Lookup method: whois $VPN_SRC"

    whois "$VPN_SRC" > "$WHOIS_FILE" 2>/dev/null || true


    COUNTRY=$(
        grep -i -m1 '^country:' "$WHOIS_FILE" |
        cut -d: -f2- |
        xargs
    )

    ASN=$(
        grep -Ei -m1 '^(origin|originas):' "$WHOIS_FILE" |
        cut -d: -f2- |
        xargs
    )

    ORG=$(
        grep -Ei -m1 \
            '^(orgname|org-name|organization|netname|descr):' \
            "$WHOIS_FILE" |
        cut -d: -f2- |
        xargs
    )


    echo "Country: ${COUNTRY:-not available}"
    echo "ASN: ${ASN:-not available}"
    echo "Organization: ${ORG:-not available}"

elif command -v geoiplookup >/dev/null 2>&1; then

    echo "Lookup method: geoiplookup"

    geoiplookup "$VPN_SRC"

else

    echo "WHOIS/GeoIP tool not installed."
    echo "Install/use a lookup tool to obtain country, ASN and organization."
fi


echo "Assessment:"
echo "  This is an external source used during the incident."
echo "  Geographic information can strengthen the finding, but location"
echo "  alone does not prove malicious activity."


# =========================================================
# 3. SESSION DURATION
# =========================================================

echo
echo "=== VPN SESSION ==="
echo "Filter: tcp.stream == $VPN_STREAM"


VPN_END=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $VPN_STREAM" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    tail -1
)


VPN_END_TIME=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $VPN_STREAM" \
        -T fields \
        -e frame.time 2>/dev/null |
    tail -1
)


DURATION_SEC=$(
    awk -v start="$VPN_START" -v end="$VPN_END" \
        'BEGIN {printf "%.2f", end-start}'
)


DURATION_MIN=$(
    awk -v sec="$DURATION_SEC" \
        'BEGIN {printf "%.2f", sec/60}'
)


echo "Connection start: $VPN_TIME"
echo "Connection close/last packet: $VPN_END_TIME"
echo "Approximate duration: $DURATION_MIN minutes"


# =========================================================
# 4. ASSIGNED INTERNAL IP
# =========================================================

echo
echo "=== ASSIGNED INTERNAL IP ==="

# Search verbose stream metadata for another 10.10.x.x address.
# If VPN assignment metadata is visible, it may appear here.

INTERNAL_IP=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $VPN_STREAM" \
        -V 2>/dev/null |
    grep -Eo '10\.10\.[0-9]+\.[0-9]+' |
    grep -v "^${VPN_SERVER}$" |
    sort -u |
    head -1 || true
)


if [ -n "$INTERNAL_IP" ]; then

    echo "Possible assigned internal IP: $INTERNAL_IP"

else

    echo "Assigned internal IP is not visible in the captured VPN metadata."
fi


# =========================================================
# 5. FIND FIRST RDP LATERAL MOVEMENT
# =========================================================

echo
echo "=== TIMELINE CORRELATION ==="

echo "RDP filter:"
echo "  tcp.dstport == 3389"
echo "  initial TCP SYN"
echo "  internal source and destination"


RDP_LINE=$(
    tshark -r "$PCAP" \
        -Y "frame.time_epoch > $VPN_START &&
            tcp.dstport == 3389 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0 &&
            ip.src == 10.10.0.0/16 &&
            ip.dst == 10.10.0.0/16" \
        -T fields \
        -e frame.time_epoch \
        -e frame.time \
        -e ip.src \
        -e ip.dst 2>/dev/null |
    head -1
)


if [ -n "$RDP_LINE" ]; then

    IFS=$'\t' read -r \
        RDP_EPOCH \
        RDP_TIME \
        RDP_SRC \
        RDP_DST <<< "$RDP_LINE"


    GAP_SEC=$(
        awk -v vpn="$VPN_START" -v rdp="$RDP_EPOCH" \
            'BEGIN {printf "%.2f", rdp-vpn}'
    )


    GAP_MIN=$(
        awk -v sec="$GAP_SEC" \
            'BEGIN {printf "%.2f", sec/60}'
    )


    echo "VPN connection:     $VPN_TIME"
    echo "First RDP movement: $RDP_TIME"
    echo "RDP path:           $RDP_SRC -> $RDP_DST"
    echo "Gap:                $GAP_MIN minutes"


    echo
    echo "=== PIVOT ASSESSMENT ==="

    echo "The VPN connection occurs before the first observed RDP"
    echo "lateral-movement session."

    echo "The timing provides a plausible network path from external"
    echo "access to later internal activity."

else

    echo "No RDP connection after the VPN session was found."
fi


# =========================================================
# 6. WHAT THE PCAP PROVES
# =========================================================

echo
echo "=== LIMITATIONS ==="

echo "The PCAP proves:"
echo "  - an external host connected to the VPN endpoint"
echo "  - the exact connection timestamp"
echo "  - the source and destination IP addresses"
echo "  - the TCP/HTTPS session duration"
echo "  - whether the VPN happened before later RDP activity"

if [ -n "$ACCOUNT_HIT" ]; then
    echo "  - the account name $ACCOUNT appears in VPN-related data"
fi

if [ -n "$INTERNAL_IP" ]; then
    echo "  - an internal address is visible in the VPN stream metadata"
fi


echo
echo "The PCAP cannot prove by itself:"
echo "  - the actual password if authentication is encrypted"
echo "  - who physically controlled the external computer"
echo "  - that geographic location alone proves malicious activity"

echo
echo "Conclusion:"
echo "The VPN session provides the network link between external"
echo "access and the later internal lateral-movement activity."
