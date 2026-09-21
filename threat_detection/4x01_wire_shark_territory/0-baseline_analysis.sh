#!/bin/bash

# Task 0 - Establish the normal MedDefense traffic baseline
# Usage:
# ./0-baseline_analysis.sh normal_baseline_clinical.pcap

set -u

PCAP="${1:-}"
OUTPUT_JSON="baseline_clinical.json"

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

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT


# Count packets matching a tshark filter.
count_filter() {
    tshark -r "$PCAP" -Y "$1" \
        -T fields -e frame.number 2>/dev/null |
        wc -l
}


# Calculate percentage safely.
percent() {
    awk -v part="$1" -v total="$2" 'BEGIN {
        if (total == 0)
            printf "0.0"
        else
            printf "%.1f", (part * 100) / total
    }'
}


# ---------------------------------------------------------
# Basic capture information
# ---------------------------------------------------------

TOTAL_PACKETS=$(
    tshark -r "$PCAP" \
        -T fields -e frame.number 2>/dev/null |
        wc -l
)

if [ "$TOTAL_PACKETS" -eq 0 ]; then
    echo "Error: PCAP contains no packets."
    exit 1
fi

read -r START_EPOCH END_EPOCH < <(
    tshark -r "$PCAP" \
        -T fields -e frame.time_epoch 2>/dev/null |
    awk '
        NR == 1 { first=$1 }
        { last=$1 }
        END { print first, last }
    '
)

DURATION_MIN=$(
    awk -v start="$START_EPOCH" -v end="$END_EPOCH" 'BEGIN {
        d=(end-start)/60

        if (d <= 0)
            d=1

        printf "%.2f", d
    }'
)


# =========================================================
# 1. PROTOCOL DISTRIBUTION
# =========================================================

echo
echo "=== PROTOCOL DISTRIBUTION ==="
echo "Filters: tcp | udp | icmp || icmpv6"

TCP_COUNT=$(count_filter 'tcp')
UDP_COUNT=$(count_filter 'udp')
ICMP_COUNT=$(count_filter 'icmp || icmpv6')

OTHER_COUNT=$((TOTAL_PACKETS - TCP_COUNT - UDP_COUNT - ICMP_COUNT))

if [ "$OTHER_COUNT" -lt 0 ]; then
    OTHER_COUNT=0
fi

printf "TCP:   %6s%% (%d packets)\n" \
    "$(percent "$TCP_COUNT" "$TOTAL_PACKETS")" "$TCP_COUNT"

printf "UDP:   %6s%% (%d packets)\n" \
    "$(percent "$UDP_COUNT" "$TOTAL_PACKETS")" "$UDP_COUNT"

printf "ICMP:  %6s%% (%d packets)\n" \
    "$(percent "$ICMP_COUNT" "$TOTAL_PACKETS")" "$ICMP_COUNT"

printf "Other: %6s%% (%d packets)\n" \
    "$(percent "$OTHER_COUNT" "$TOTAL_PACKETS")" "$OTHER_COUNT"


# =========================================================
# 2. APPLICATION BREAKDOWN
# =========================================================

echo
echo "=== APPLICATION BREAKDOWN ==="
echo "Filters: ports 80, 443, 53, 88, 389/636, 445, 123, 9100"

HTTP_COUNT=$(count_filter 'tcp.port == 80')
HTTPS_COUNT=$(count_filter 'tcp.port == 443')
DNS_PORT_COUNT=$(count_filter 'tcp.port == 53 || udp.port == 53')
KERBEROS_COUNT=$(count_filter 'tcp.port == 88 || udp.port == 88')
LDAP_COUNT=$(count_filter 'tcp.port == 389 || tcp.port == 636 || udp.port == 389')
SMB_COUNT=$(count_filter 'tcp.port == 445')
NTP_COUNT=$(count_filter 'udp.port == 123')
PRINT_COUNT=$(count_filter 'tcp.port == 9100')


# The project does not define which port represents agent traffic.
# If we discover it later, we can run:
#
# AGENT_FILTER='tcp.port == PORT' ./0-baseline_analysis.sh file.pcap

AGENT_FILTER="${AGENT_FILTER:-}"

if [ -n "$AGENT_FILTER" ]; then
    AGENT_COUNT=$(count_filter "$AGENT_FILTER")
else
    AGENT_COUNT=0
fi


KNOWN_APP_COUNT=$(( \
    HTTP_COUNT + \
    HTTPS_COUNT + \
    DNS_PORT_COUNT + \
    KERBEROS_COUNT + \
    LDAP_COUNT + \
    SMB_COUNT + \
    NTP_COUNT + \
    PRINT_COUNT + \
    AGENT_COUNT \
))

OTHER_APP_COUNT=$((TOTAL_PACKETS - KNOWN_APP_COUNT))

if [ "$OTHER_APP_COUNT" -lt 0 ]; then
    OTHER_APP_COUNT=0
fi


printf "%-22s %6s%% (%d packets)\n" \
    "HTTP (80):" \
    "$(percent "$HTTP_COUNT" "$TOTAL_PACKETS")" \
    "$HTTP_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "HTTPS (443):" \
    "$(percent "$HTTPS_COUNT" "$TOTAL_PACKETS")" \
    "$HTTPS_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "DNS (53):" \
    "$(percent "$DNS_PORT_COUNT" "$TOTAL_PACKETS")" \
    "$DNS_PORT_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "Kerberos (88):" \
    "$(percent "$KERBEROS_COUNT" "$TOTAL_PACKETS")" \
    "$KERBEROS_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "LDAP (389/636):" \
    "$(percent "$LDAP_COUNT" "$TOTAL_PACKETS")" \
    "$LDAP_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "SMB (445):" \
    "$(percent "$SMB_COUNT" "$TOTAL_PACKETS")" \
    "$SMB_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "NTP (123):" \
    "$(percent "$NTP_COUNT" "$TOTAL_PACKETS")" \
    "$NTP_COUNT"

printf "%-22s %6s%% (%d packets)\n" \
    "Printing (9100):" \
    "$(percent "$PRINT_COUNT" "$TOTAL_PACKETS")" \
    "$PRINT_COUNT"

if [ -n "$AGENT_FILTER" ]; then

    printf "%-22s %6s%% (%d packets)\n" \
        "Agent traffic:" \
        "$(percent "$AGENT_COUNT" "$TOTAL_PACKETS")" \
        "$AGENT_COUNT"

else
    printf "%-22s %s\n" \
        "Agent traffic:" \
        "not separately classified"
fi

printf "%-22s %6s%% (%d packets)\n" \
    "Other:" \
    "$(percent "$OTHER_APP_COUNT" "$TOTAL_PACKETS")" \
    "$OTHER_APP_COUNT"


echo
echo "Other observed destination ports (top 10):"

tshark -r "$PCAP" \
    -Y 'tcp || udp' \
    -T fields \
    -e tcp.dstport \
    -e udp.dstport 2>/dev/null |
awk -F '\t' '
{
    if ($1 != "")
        print $1
    else if ($2 != "")
        print $2
}' |
sort |
uniq -c |
sort -nr |
head -10 |
awk '{
    printf "  port %-6s %d packets\n", $2, $1
}'


# =========================================================
# 3. TOP 10 SOURCE IPS BY BYTES
# =========================================================

echo
echo "=== TOP 10 SOURCE IPS ==="
echo "Command fields: ip.src + frame.len"

tshark -r "$PCAP" \
    -Y 'ip.src' \
    -T fields \
    -e ip.src \
    -e frame.len 2>/dev/null |
awk -F '\t' '
$1 != "" && $2 != "" {
    bytes[$1]+=$2
}

END {
    for (ip in bytes)
        printf "%s\t%d\n", ip, bytes[ip]
}' |
sort -t $'\t' -k2,2nr |
head -10 |
awk -F '\t' '{
    printf "  %-15s %.2f MB\n", $1, $2/1024/1024
}'


# =========================================================
# 4. TOP 10 DESTINATIONS BY CONNECTIONS
# =========================================================

echo
echo "=== TOP 10 DESTINATION IPS ==="
echo "Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0"

# Count each TCP stream only once so SYN retransmissions
# do not become extra connections.

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst' \
    -T fields \
    -e ip.dst \
    -e tcp.stream 2>/dev/null |
sort -u |
awk -F '\t' '$1 != "" {print $1}' |
sort |
uniq -c |
sort -nr |
head -10 |
awk '{
    printf "  %-15s %d connections\n", $2, $1
}'


# =========================================================
# 5. DNS QUERY PROFILE
# =========================================================

echo
echo "=== DNS QUERY PROFILE ==="
echo "Filter: dns.flags.response == 0 && dns.qry.name"

DNS_QUERIES=$(count_filter 'dns.flags.response == 0 && dns.qry.name')

DNS_AVG=$(
    awk -v q="$DNS_QUERIES" -v m="$DURATION_MIN" \
        'BEGIN {printf "%.2f", q/m}'
)

printf "Total queries: %d (%s/min average)\n" \
    "$DNS_QUERIES" "$DNS_AVG"


echo
echo "Top 20 queried domains:"

tshark -r "$PCAP" \
    -Y 'dns.flags.response == 0 && dns.qry.name' \
    -T fields \
    -e dns.qry.name 2>/dev/null |
tr '[:upper:]' '[:lower:]' |
sort |
uniq -c |
sort -nr |
head -20 |
awk '{
    printf "  %-45s %d queries\n", $2, $1
}'


A_COUNT=$(count_filter 'dns.flags.response == 0 && dns.qry.type == 1')
AAAA_COUNT=$(count_filter 'dns.flags.response == 0 && dns.qry.type == 28')
TXT_COUNT=$(count_filter 'dns.flags.response == 0 && dns.qry.type == 16')
MX_COUNT=$(count_filter 'dns.flags.response == 0 && dns.qry.type == 15')

TXT_AVG=$(
    awk -v q="$TXT_COUNT" -v m="$DURATION_MIN" \
        'BEGIN {printf "%.2f", q/m}'
)


echo
printf "Query types: A %s%%, AAAA %s%%, TXT %s%%, MX %s%%\n" \
    "$(percent "$A_COUNT" "$DNS_QUERIES")" \
    "$(percent "$AAAA_COUNT" "$DNS_QUERIES")" \
    "$(percent "$TXT_COUNT" "$DNS_QUERIES")" \
    "$(percent "$MX_COUNT" "$DNS_QUERIES")"

printf "TXT queries: %d (%s/min)\n" \
    "$TXT_COUNT" "$TXT_AVG"


# =========================================================
# 6. CONNECTION DURATION DISTRIBUTION
# =========================================================

echo
echo "=== CONNECTION DURATION DISTRIBUTION ==="
echo "Fields: tcp.stream + frame.time_epoch"

read -r STREAM_TOTAL SHORT_COUNT MEDIUM_COUNT LONG_COUNT < <(

    tshark -r "$PCAP" \
        -Y 'tcp' \
        -T fields \
        -e tcp.stream \
        -e frame.time_epoch 2>/dev/null |

    awk -F '\t' '

    $1 != "" && $2 != "" {

        if (!($1 in first) || $2 < first[$1])
            first[$1]=$2

        if (!($1 in last) || $2 > last[$1])
            last[$1]=$2
    }

    END {

        short=0
        medium=0
        long=0
        total=0

        for (stream in first) {

            duration=last[stream]-first[stream]
            total++

            if (duration < 1)
                short++
            else if (duration <= 30)
                medium++
            else
                long++
        }

        print total, short, medium, long
    }'
)


printf "Short (<1s):     %6s%% (%d streams)\n" \
    "$(percent "$SHORT_COUNT" "$STREAM_TOTAL")" \
    "$SHORT_COUNT"

printf "Medium (1-30s): %6s%% (%d streams)\n" \
    "$(percent "$MEDIUM_COUNT" "$STREAM_TOTAL")" \
    "$MEDIUM_COUNT"

printf "Long (>30s):    %6s%% (%d streams)\n" \
    "$(percent "$LONG_COUNT" "$STREAM_TOTAL")" \
    "$LONG_COUNT"


# =========================================================
# 7. TLS ANALYSIS
# =========================================================

echo
echo "=== TLS ANALYSIS ==="
echo "SNI filter: tls.handshake.extensions_server_name"


echo "Observed SNI values:"

SNI_VALUES=$(
    tshark -r "$PCAP" \
        -Y 'tls.handshake.extensions_server_name' \
        -T fields \
        -e tls.handshake.extensions_server_name 2>/dev/null |
    sort -u
)

if [ -n "$SNI_VALUES" ]; then
    printf '%s\n' "$SNI_VALUES" |
        sed 's/^/  /'
else
    echo "  None observed"
fi


echo
echo "Observed TLS versions:"

TLS_VERSIONS=$(
    tshark -r "$PCAP" \
        -Y 'tls.handshake.type == 1 || tls.handshake.type == 2' \
        -T fields \
        -E occurrence=a \
        -E aggregator=, \
        -e tls.handshake.version \
        -e tls.handshake.extensions.supported_version 2>/dev/null |
    tr '\t,' '\n\n' |
    awk 'NF' |
    sort -u |
    awk '
        $0 == "0x0301" || $0 == "769" {
            print "TLS 1.0"
            next
        }

        $0 == "0x0302" || $0 == "770" {
            print "TLS 1.1"
            next
        }

        $0 == "0x0303" || $0 == "771" {
            print "TLS 1.2 / TLS 1.3 legacy value"
            next
        }

        $0 == "0x0304" || $0 == "772" {
            print "TLS 1.3"
            next
        }
    ' |
    sort -u
)

if [ -n "$TLS_VERSIONS" ]; then
    printf '%s\n' "$TLS_VERSIONS" |
        sed 's/^/  /'
else
    echo "  None observed"
fi


echo
echo "Observed certificate issuer names (where available):"

ISSUERS=$(
    tshark -r "$PCAP" \
        -Y 'tls.handshake.type == 11' \
        -V 2>/dev/null |

    awk '
    {
        lower=tolower($0)

        if (lower ~ /issuer: rdnsequence/) {
            inside=1
            next
        }

        if (lower ~ /subject: rdnsequence/)
            inside=0

        if (inside && lower ~ /commonname:/) {
            sub(/^.*[Cc]ommon[Nn]ame:[[:space:]]*/, "")
            print
        }
    }' |

    sort -u
)

if [ -n "$ISSUERS" ]; then
    printf '%s\n' "$ISSUERS" |
        sed 's/^/  /'
else
    echo "  Not available in the capture"
fi


# =========================================================
# 8. TEMPORAL PATTERN
# =========================================================

echo
echo "=== TEMPORAL PATTERN ==="
echo "Fields: frame.time_epoch + frame.len"
echo "Grouping: 60-second bins"


tshark -r "$PCAP" \
    -T fields \
    -e frame.time_epoch \
    -e frame.len 2>/dev/null |

awk -F '\t' '

$1 != "" {

    minute=int($1/60)

    packets[minute]++
    bytes[minute]+=$2
}

END {

    for (minute in packets)
        print minute, packets[minute], bytes[minute]
}' |

sort -n > "$TMP_DIR/minute_bins.txt"


while read -r MINUTE PACKETS BYTES; do

    TIME_LABEL=$(date -d "@$((MINUTE * 60))" '+%H:%M')

    KB=$(
        awk -v bytes="$BYTES" \
            'BEGIN {printf "%.2f", bytes/1024}'
    )

    printf "%s  %6d packets  %8s KB\n" \
        "$TIME_LABEL" "$PACKETS" "$KB"

done < "$TMP_DIR/minute_bins.txt"


# Find normal minimum, average and maximum packets/minute.

read -r PPM_MIN PPM_AVG PPM_MAX < <(

    awk '

    NR == 1 {
        min=$2
        max=$2
    }

    {
        sum+=$2
        count++

        if ($2 < min)
            min=$2

        if ($2 > max)
            max=$2
    }

    END {

        if (count == 0)
            print 0, 0, 0
        else
            printf "%d %.2f %d\n", min, sum/count, max
    }

    ' "$TMP_DIR/minute_bins.txt"
)


# ---------------------------------------------------------
# Normal external connection rhythm
# ---------------------------------------------------------

# Count outbound TCP connections from private addresses
# to public addresses per minute.

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src && ip.dst' \
    -T fields \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e tcp.stream 2>/dev/null |

sort -u -t $'\t' -k4,4 |

awk -F '\t' '

function private_ip(ip, a) {

    split(ip, a, ".")

    if (a[1] == 10)
        return 1

    if (a[1] == 192 && a[2] == 168)
        return 1

    if (a[1] == 172 && a[2] >= 16 && a[2] <= 31)
        return 1

    return 0
}

$1 != "" && private_ip($2) && !private_ip($3) {

    minute=int($1/60)

    count[minute]++
}

END {

    for (minute in count)
        print minute, count[minute]
}

' |

sort -n > "$TMP_DIR/external_active.txt"


# Add zero for minutes where there were no external connections.

awk '

NR == FNR {
    external[$1]=$2
    next
}

{
    if ($1 in external)
        print $1, external[$1]
    else
        print $1, 0
}

' \
"$TMP_DIR/external_active.txt" \
"$TMP_DIR/minute_bins.txt" \
> "$TMP_DIR/external_connections.txt"


read -r EXT_MIN EXT_AVG EXT_MAX < <(

    awk '

    NR == 1 {
        min=$2
        max=$2
    }

    {
        sum+=$2
        count++

        if ($2 < min)
            min=$2

        if ($2 > max)
            max=$2
    }

    END {

        if (count == 0)
            print 0, 0, 0
        else
            printf "%d %.2f %d\n", min, sum/count, max
    }

    ' "$TMP_DIR/external_connections.txt"
)


# =========================================================
# 9. BASELINE SIGNATURES
# =========================================================

echo
echo "=== BASELINE SIGNATURES ==="

printf "Normal DNS rate: %.2f queries/min\n" \
    "$DNS_AVG"

printf "Normal TXT query rate: %.2f queries/min (%d total)\n" \
    "$TXT_AVG" "$TXT_COUNT"

printf "Normal external connection rhythm: min %d, avg %.2f, max %d new TCP connections/min\n" \
    "$EXT_MIN" "$EXT_AVG" "$EXT_MAX"

printf "Normal packet volume range: %d-%d packets/min (avg %.2f)\n" \
    "$PPM_MIN" "$PPM_MAX" "$PPM_AVG"


echo
echo "Known-good services observed in this baseline:"

[ "$HTTP_COUNT" -gt 0 ] && echo "  HTTP (80)"
[ "$HTTPS_COUNT" -gt 0 ] && echo "  HTTPS (443)"
[ "$DNS_PORT_COUNT" -gt 0 ] && echo "  DNS (53)"
[ "$KERBEROS_COUNT" -gt 0 ] && echo "  Kerberos (88)"
[ "$LDAP_COUNT" -gt 0 ] && echo "  LDAP/LDAPS (389/636)"
[ "$SMB_COUNT" -gt 0 ] && echo "  SMB (445)"
[ "$NTP_COUNT" -gt 0 ] && echo "  NTP (123)"
[ "$PRINT_COUNT" -gt 0 ] && echo "  Printing (9100)"

if [ "$AGENT_COUNT" -gt 0 ]; then
    echo "  Endpoint agent traffic ($AGENT_FILTER)"
fi


if [ -n "$SNI_VALUES" ]; then

    echo
    echo "Known-good TLS destinations observed in baseline:"

    printf '%s\n' "$SNI_VALUES" |
        head -20 |
        sed 's/^/  /'
fi


# =========================================================
# SAVE BASELINE JSON
# =========================================================

cat > "$OUTPUT_JSON" <<EOF
{
  "pcap": "$(basename "$PCAP")",
  "capture_duration_minutes": $DURATION_MIN,
  "total_packets": $TOTAL_PACKETS,
  "normal_dns_queries_per_minute": $DNS_AVG,
  "normal_txt_queries_per_minute": $TXT_AVG,
  "external_tcp_connections_per_minute": {
    "min": $EXT_MIN,
    "average": $EXT_AVG,
    "max": $EXT_MAX
  },
  "packet_volume_per_minute": {
    "min": $PPM_MIN,
    "average": $PPM_AVG,
    "max": $PPM_MAX
  },
  "observed_service_packet_counts": {
    "http": $HTTP_COUNT,
    "https": $HTTPS_COUNT,
    "dns": $DNS_PORT_COUNT,
    "kerberos": $KERBEROS_COUNT,
    "ldap": $LDAP_COUNT,
    "smb": $SMB_COUNT,
    "ntp": $NTP_COUNT,
    "printing": $PRINT_COUNT,
    "agent": $AGENT_COUNT
  }
}
EOF


echo
echo "BASELINE SAVED: $OUTPUT_JSON"
