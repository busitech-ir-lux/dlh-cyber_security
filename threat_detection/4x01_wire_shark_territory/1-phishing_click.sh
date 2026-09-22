#!/bin/bash

# Task 1 - Analyze the phishing click from packet evidence
# Usage:
# ./1-phishing_click.sh phishing_click.pcap

set -u

PCAP="${1:-}"

PHISH_DOMAIN="meddefense-portal.com"
PHISH_IP="91.234.99.107"
REAL_DOMAIN="meddefense.com"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT


# ---------------------------------------------------------
# Basic checks
# ---------------------------------------------------------

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP file not found: $PCAP"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "Error: tshark is not installed."
    exit 1
fi


# Convert epoch time to readable time.
format_time() {

    if [ -z "$1" ]; then
        echo "N/A"
        return
    fi

    date -d "@$1" '+%H:%M:%S.%3N'
}


# Convert common TLS version values to readable names.
tls_version_name() {

    case "$1" in
        0x0304|772)
            echo "TLS 1.3"
            ;;
        0x0303|771)
            echo "TLS 1.2"
            ;;
        0x0302|770)
            echo "TLS 1.1"
            ;;
        0x0301|769)
            echo "TLS 1.0"
            ;;
        *)
            echo "$1"
            ;;
    esac
}


# =========================================================
# 1. DNS RESOLUTION
# =========================================================

echo
echo "=== DNS RESOLUTION ==="
echo "Filter: dns.qry.name == \"$PHISH_DOMAIN\""

DNS_QUERY_EPOCH=""
DNS_CLIENT=""
DNS_SERVER=""

read -r DNS_QUERY_EPOCH DNS_CLIENT DNS_SERVER < <(

    tshark -r "$PCAP" \
        -Y "dns.flags.response == 0 && dns.qry.name == \"$PHISH_DOMAIN\"" \
        -T fields \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst 2>/dev/null |
    head -1
)


DNS_RESPONSE_EPOCH=""
DNS_RESPONSE_IP=""
DNS_TTL=""

read -r DNS_RESPONSE_EPOCH DNS_RESPONSE_IP DNS_TTL < <(

    tshark -r "$PCAP" \
        -Y "dns.flags.response == 1 &&
            dns.qry.name == \"$PHISH_DOMAIN\" &&
            dns.a == $PHISH_IP" \
        -T fields \
        -E occurrence=f \
        -e frame.time_epoch \
        -e dns.a \
        -e dns.resp.ttl 2>/dev/null |
    head -1
)


if [ -n "$DNS_QUERY_EPOCH" ]; then

    printf "%s  Query: %s\n" \
        "$(format_time "$DNS_QUERY_EPOCH")" \
        "$PHISH_DOMAIN"

    printf "Source: %s -> %s\n" \
        "$DNS_CLIENT" \
        "$DNS_SERVER"

else
    echo "No DNS query for $PHISH_DOMAIN found."
fi


if [ -n "$DNS_RESPONSE_EPOCH" ]; then

    printf "%s  Response: %s\n" \
        "$(format_time "$DNS_RESPONSE_EPOCH")" \
        "$DNS_RESPONSE_IP"

    printf "TTL: %s\n" \
        "${DNS_TTL:-N/A}"

else
    echo "No DNS response containing $PHISH_IP found."
fi


# =========================================================
# Find the phishing TCP session
# =========================================================

CLIENT_IP=""
CLIENT_PORT=""
STREAM=""
START_EPOCH=""

read -r CLIENT_IP CLIENT_PORT STREAM START_EPOCH < <(

    tshark -r "$PCAP" \
        -Y "ip.dst == $PHISH_IP &&
            tcp.dstport == 443 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e ip.src \
        -e tcp.srcport \
        -e tcp.stream \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


if [ -z "$STREAM" ]; then
    echo
    echo "Error: no HTTPS TCP connection to $PHISH_IP was found."
    exit 1
fi


# =========================================================
# 2. TLS HANDSHAKE
# =========================================================

echo
echo "=== TLS HANDSHAKE ==="
echo "Main session filter: tcp.stream == $STREAM"


SYNACK_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 1" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


CLIENTHELLO_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 1" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


SERVERHELLO_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 2" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


SNI=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.extensions_server_name 2>/dev/null |
    head -1
)


printf "%s  SYN -> %s:443\n" \
    "$(format_time "$START_EPOCH")" \
    "$PHISH_IP"

if [ -n "$SYNACK_EPOCH" ]; then
    printf "%s  SYN-ACK\n" \
        "$(format_time "$SYNACK_EPOCH")"
fi

if [ -n "$CLIENTHELLO_EPOCH" ]; then

    printf "%s  ClientHello\n" \
        "$(format_time "$CLIENTHELLO_EPOCH")"

    printf "  SNI: %s\n" \
        "${SNI:-Not observed}"

else
    echo "ClientHello not found."
fi


# ---------------------------------------------------------
# TLS versions offered
# ---------------------------------------------------------

echo "  TLS versions offered:"

TLS_VERSIONS=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 1" \
        -T fields \
        -E occurrence=a \
        -E aggregator=, \
        -e tls.handshake.extensions.supported_version 2>/dev/null |
    head -1
)


if [ -n "$TLS_VERSIONS" ]; then

    printf '%s\n' "$TLS_VERSIONS" |
    tr ',' '\n' |
    while read -r VERSION; do

        [ -n "$VERSION" ] &&
            printf "    %s\n" "$(tls_version_name "$VERSION")"

    done

else

    # Older TLS may not use the supported_versions extension.

    LEGACY_VERSION=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $STREAM &&
                tls.handshake.type == 1" \
            -T fields \
            -e tls.handshake.version 2>/dev/null |
        head -1
    )

    if [ -n "$LEGACY_VERSION" ]; then
        printf "    %s\n" \
            "$(tls_version_name "$LEGACY_VERSION")"
    else
        echo "    Not available"
    fi
fi


# ---------------------------------------------------------
# Cipher suites
# ---------------------------------------------------------

echo "  Cipher suites offered:"

# -V is used here because it gives readable cipher-suite names.

CIPHERS=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 1" \
        -V 2>/dev/null |
    sed -n \
        's/^[[:space:]]*Cipher Suite: \(.*\)$/\1/p' |
    head -10
)


if [ -n "$CIPHERS" ]; then

    printf '%s\n' "$CIPHERS" |
        sed 's/^/    /'

else
    echo "    Not available"
fi


if [ -n "$SERVERHELLO_EPOCH" ]; then

    echo
    printf "%s  ServerHello\n" \
        "$(format_time "$SERVERHELLO_EPOCH")"
fi


# =========================================================
# 3. SERVER CERTIFICATE
# =========================================================

echo
echo "=== SERVER CERTIFICATE ==="
echo "Filter: tcp.stream == $STREAM && tls.handshake.type == 11"


CERT_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 11" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


CERT_HEX=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            tls.handshake.type == 11" \
        -T fields \
        -E occurrence=f \
        -e tls.handshake.certificate 2>/dev/null |
    head -1
)


if [ -n "$CERT_HEX" ] &&
   command -v openssl >/dev/null 2>&1 &&
   command -v xxd >/dev/null 2>&1; then

    # Convert the certificate extracted by tshark
    # from hexadecimal into a DER certificate.

    printf '%s' "$CERT_HEX" |
        tr -d ':' |
        xxd -r -p > "$TMP_DIR/server.der"

    if openssl x509 \
        -inform DER \
        -in "$TMP_DIR/server.der" \
        -noout >/dev/null 2>&1; then

        printf "%s  Certificate\n" \
            "$(format_time "$CERT_EPOCH")"

        openssl x509 \
            -inform DER \
            -in "$TMP_DIR/server.der" \
            -noout \
            -subject \
            -issuer \
            -dates \
            -serial

    else
        echo "Certificate was detected but could not be decoded."
    fi

else

    echo "Certificate details are not visible in the capture."

    echo "This can happen when the certificate handshake is encrypted,"
    echo "for example with TLS 1.3, or when the relevant packets are missing."
fi


# =========================================================
# 4. DATA EXCHANGE
# =========================================================

echo
echo "=== DATA EXCHANGE ==="
echo "Filter: tcp.stream == $STREAM && tcp.len > 0"


CLIENT_BYTES=0
CLIENT_SEGMENTS=0

read -r CLIENT_BYTES CLIENT_SEGMENTS < <(

    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            ip.src == $CLIENT_IP &&
            tcp.len > 0" \
        -T fields \
        -e tcp.len 2>/dev/null |

    awk '
    {
        bytes += $1
        segments++
    }

    END {
        print bytes+0, segments+0
    }'
)


SERVER_BYTES=0
SERVER_SEGMENTS=0

read -r SERVER_BYTES SERVER_SEGMENTS < <(

    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            ip.src == $PHISH_IP &&
            tcp.len > 0" \
        -T fields \
        -e tcp.len 2>/dev/null |

    awk '
    {
        bytes += $1
        segments++
    }

    END {
        print bytes+0, segments+0
    }'
)


printf "Client -> Server: %d TCP payload bytes across %d segments\n" \
    "$CLIENT_BYTES" \
    "$CLIENT_SEGMENTS"

printf "Server -> Client: %d TCP payload bytes across %d segments\n" \
    "$SERVER_BYTES" \
    "$SERVER_SEGMENTS"


# ---------------------------------------------------------
# Client encrypted application-data volume
# ---------------------------------------------------------

APP_CLIENT_BYTES=0
APP_CLIENT_SEGMENTS=0

read -r APP_CLIENT_BYTES APP_CLIENT_SEGMENTS < <(

    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            ip.src == $CLIENT_IP &&
            tls.app_data &&
            tcp.len > 0" \
        -T fields \
        -e tcp.len 2>/dev/null |

    awk '
    {
        bytes += $1
        segments++
    }

    END {
        print bytes+0, segments+0
    }'
)


printf "Client encrypted application-data traffic: %d bytes across %d segments\n" \
    "$APP_CLIENT_BYTES" \
    "$APP_CLIENT_SEGMENTS"


# Largest outbound encrypted application-data packet

LARGEST_APP=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            ip.src == $CLIENT_IP &&
            tls.app_data &&
            tcp.len > 0" \
        -T fields \
        -e frame.time_epoch \
        -e tcp.len 2>/dev/null |
    sort -t $'\t' -k2,2nr |
    head -1
)


if [ -n "$LARGEST_APP" ]; then

    LARGEST_EPOCH=$(printf '%s\n' "$LARGEST_APP" | cut -f1)
    LARGEST_BYTES=$(printf '%s\n' "$LARGEST_APP" | cut -f2)

    printf "Largest client encrypted-data packet: %s bytes at %s\n" \
        "$LARGEST_BYTES" \
        "$(format_time "$LARGEST_EPOCH")"
fi


# =========================================================
# 5. EXACT SESSION TIMESTAMPS
# =========================================================

echo
echo "=== SESSION TIMELINE ==="


DATA_START_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM && tls.app_data" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    head -1
)


DATA_END_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM && tls.app_data" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    tail -1
)


# If tshark cannot identify TLS application data,
# use TCP payload packets after the ClientHello as a fallback.

if [ -z "$DATA_START_EPOCH" ]; then

    DATA_START_EPOCH=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $STREAM &&
                tcp.len > 0 &&
                frame.time_epoch >= $CLIENTHELLO_EPOCH" \
            -T fields \
            -e frame.time_epoch 2>/dev/null |
        head -1
    )
fi


if [ -z "$DATA_END_EPOCH" ]; then

    DATA_END_EPOCH=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $STREAM &&
                tcp.len > 0" \
            -T fields \
            -e frame.time_epoch 2>/dev/null |
        tail -1
    )
fi


# Use the final FIN/RST as the observed close.

CLOSE_EPOCH=$(
    tshark -r "$PCAP" \
        -Y "tcp.stream == $STREAM &&
            (tcp.flags.fin == 1 || tcp.flags.reset == 1)" \
        -T fields \
        -e frame.time_epoch 2>/dev/null |
    tail -1
)


if [ -z "$CLOSE_EPOCH" ]; then

    CLOSE_EPOCH=$(
        tshark -r "$PCAP" \
            -Y "tcp.stream == $STREAM" \
            -T fields \
            -e frame.time_epoch 2>/dev/null |
        tail -1
    )

    CLOSE_NOTE="No FIN/RST observed; using last captured packet."

else
    CLOSE_NOTE="TCP FIN/RST observed."
fi


DURATION=$(
    awk -v start="$START_EPOCH" -v end="$CLOSE_EPOCH" \
        'BEGIN {printf "%.3f", end-start}'
)


printf "Connection start:    %s\n" \
    "$(format_time "$START_EPOCH")"

printf "Data transfer start: %s\n" \
    "$(format_time "$DATA_START_EPOCH")"

printf "Data transfer end:   %s\n" \
    "$(format_time "$DATA_END_EPOCH")"

printf "Connection close:    %s\n" \
    "$(format_time "$CLOSE_EPOCH")"

printf "Session duration:    %s seconds\n" \
    "$DURATION"

echo "$CLOSE_NOTE"


# =========================================================
# 6. CREDENTIAL-SUBMISSION ASSESSMENT
# =========================================================

echo
echo "[*] Analysis:"

echo "    The HTTPS contents are encrypted, so usernames or passwords"
echo "    cannot be claimed from packet contents alone."


if [ "$APP_CLIENT_BYTES" -gt 0 ] &&
   [ "$APP_CLIENT_BYTES" -le 20000 ]; then

    echo "    The client sent a relatively small amount of encrypted"
    echo "    application data to the phishing server."

    echo "    This is consistent with a small HTTPS request such as a"
    echo "    credential form submission, but it is NOT proof that"
    echo "    credentials were actually submitted."

elif [ "$APP_CLIENT_BYTES" -gt 20000 ]; then

    echo "    A larger encrypted outbound transfer was observed."

    echo "    The traffic confirms data was sent to the server, but volume"
    echo "    alone is not enough to identify it as credential submission."

else

    echo "    No client TLS application-data traffic was identified."

    echo "    The capture therefore does not provide metadata evidence"
    echo "    of a credential submission."
fi


# =========================================================
# 7. POST-CLICK REAL PORTAL CHECK
# =========================================================

echo
echo "=== POST-CLICK BEHAVIOR ==="

POST_END=$(
    awk -v start="$CLOSE_EPOCH" \
        'BEGIN {printf "%.6f", start+120}'
)


echo "Filter: DNS query for $REAL_DOMAIN within 120 seconds after session"


REAL_QUERY_EPOCH=""
REAL_DNS_CLIENT=""
REAL_DNS_SERVER=""

read -r REAL_QUERY_EPOCH REAL_DNS_CLIENT REAL_DNS_SERVER < <(

    tshark -r "$PCAP" \
        -Y "frame.time_epoch > $CLOSE_EPOCH &&
            frame.time_epoch <= $POST_END &&
            dns.flags.response == 0 &&
            dns.qry.name == \"$REAL_DOMAIN\"" \
        -T fields \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst 2>/dev/null |
    head -1
)


if [ -n "$REAL_QUERY_EPOCH" ]; then

    printf "%s  DNS query: %s\n" \
        "$(format_time "$REAL_QUERY_EPOCH")" \
        "$REAL_DOMAIN"


    REAL_RESPONSE_EPOCH=""
    REAL_IP=""

    read -r REAL_RESPONSE_EPOCH REAL_IP < <(

        tshark -r "$PCAP" \
            -Y "frame.time_epoch >= $REAL_QUERY_EPOCH &&
                frame.time_epoch <= $POST_END &&
                dns.flags.response == 1 &&
                dns.qry.name == \"$REAL_DOMAIN\"" \
            -T fields \
            -E occurrence=f \
            -e frame.time_epoch \
            -e dns.a 2>/dev/null |
        head -1
    )


    if [ -n "$REAL_RESPONSE_EPOCH" ]; then

        printf "%s  DNS response: %s\n" \
            "$(format_time "$REAL_RESPONSE_EPOCH")" \
            "${REAL_IP:-No A record}"
    fi


    # If DNS returned an IPv4 address, look for HTTPS to it.

    if [ -n "$REAL_IP" ]; then

        REAL_HTTPS_EPOCH=$(
            tshark -r "$PCAP" \
                -Y "frame.time_epoch >= $REAL_QUERY_EPOCH &&
                    frame.time_epoch <= $POST_END &&
                    ip.dst == $REAL_IP &&
                    tcp.dstport == 443 &&
                    tcp.flags.syn == 1 &&
                    tcp.flags.ack == 0" \
                -T fields \
                -e frame.time_epoch 2>/dev/null |
            head -1
        )


        if [ -n "$REAL_HTTPS_EPOCH" ]; then

            printf "%s  HTTPS connection to %s:443\n" \
                "$(format_time "$REAL_HTTPS_EPOCH")" \
                "$REAL_IP"
        fi
    fi


    echo
    echo "[*] Possible interpretation:"
    echo "    The real MedDefense portal was queried shortly after"
    echo "    the phishing session."

    echo "    This could be caused by a redirect or by the user manually"
    echo "    visiting the legitimate portal."

    echo "    The PCAP alone does not prove which explanation is correct."

else

    echo "No DNS query for $REAL_DOMAIN was found within"
    echo "120 seconds after the phishing session."
fi


# =========================================================
# 8. 4x00 CORRELATION
# =========================================================

echo
echo "=== 4x00 CORRELATION ==="


if [ -n "$DNS_QUERY_EPOCH" ] || [ "$SNI" = "$PHISH_DOMAIN" ]; then
    echo "IOC domain match: $PHISH_DOMAIN"
else
    echo "IOC domain match: NOT CONFIRMED"
fi


if [ "$PHISH_IP" = "$DNS_RESPONSE_IP" ] ||
   [ -n "$STREAM" ]; then
    echo "IOC IP match: $PHISH_IP"
else
    echo "IOC IP match: NOT CONFIRMED"
fi


echo
echo "Conclusion:"

echo "The PCAP confirms that $CLIENT_IP established an HTTPS"
echo "connection to the known phishing infrastructure at $PHISH_IP."

if [ -n "$SNI" ]; then
    echo "The TLS SNI identifies the requested hostname as $SNI."
fi

echo "This strengthens the 4x00 phishing investigation by adding"
echo "direct network evidence of the workstation contacting the"
echo "identified phishing infrastructure."

echo "The encrypted traffic metadata may be consistent with credential"
echo "submission, but the actual credentials cannot be confirmed from"
echo "encrypted HTTPS traffic alone."
