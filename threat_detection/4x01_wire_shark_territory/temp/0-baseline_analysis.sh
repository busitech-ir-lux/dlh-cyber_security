#!/bin/bash

# Task 0 - Normal traffic baseline
# Usage: ./0-baseline_analysis.sh normal_baseline_clinical.pcap

PCAP="$1"
OUT="baseline_clinical.json"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi

# Total packets and capture duration
TOTAL=$(tshark -r "$PCAP" -T fields -e frame.number 2>/dev/null | wc -l)

read START END < <(
    tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null |
    awk 'NR==1 {first=$1} {last=$1} END {print first,last}'
)

MINUTES=$(awk -v s="$START" -v e="$END" \
    'BEGIN {printf "%.2f",(e-s)/60}')


# =========================================================
# 1. PROTOCOL DISTRIBUTION
# =========================================================

echo
echo "=== PROTOCOL DISTRIBUTION ==="
echo "Filters: tcp | udp | icmp || icmpv6"

TCP=$(tshark -r "$PCAP" -Y 'tcp' -T fields -e frame.number 2>/dev/null | wc -l)
UDP=$(tshark -r "$PCAP" -Y 'udp' -T fields -e frame.number 2>/dev/null | wc -l)
ICMP=$(tshark -r "$PCAP" -Y 'icmp || icmpv6' -T fields -e frame.number 2>/dev/null | wc -l)
OTHER=$((TOTAL-TCP-UDP-ICMP))

awk -v tcp="$TCP" -v udp="$UDP" -v icmp="$ICMP" \
    -v other="$OTHER" -v total="$TOTAL" 'BEGIN {
    printf "TCP:   %.1f%% (%d packets)\n", tcp/total*100, tcp
    printf "UDP:   %.1f%% (%d packets)\n", udp/total*100, udp
    printf "ICMP:  %.1f%% (%d packets)\n", icmp/total*100, icmp
    printf "Other: %.1f%% (%d packets)\n", other/total*100, other
}'


# =========================================================
# 2. APPLICATION BREAKDOWN
# =========================================================

echo
echo "=== APPLICATION BREAKDOWN ==="
echo "Filters use tcp.port / udp.port so both directions are counted."

for ITEM in \
    "HTTPS|tcp.port==443" \
    "HTTP|tcp.port==80" \
    "DNS|tcp.port==53 || udp.port==53" \
    "Kerberos|tcp.port==88 || udp.port==88" \
    "LDAP|tcp.port==389 || tcp.port==636 || udp.port==389" \
    "SMB|tcp.port==445" \
    "NTP|udp.port==123" \
    "Printing|tcp.port==9100"
do
    NAME="${ITEM%%|*}"
    FILTER="${ITEM#*|}"

    COUNT=$(tshark -r "$PCAP" -Y "$FILTER" \
        -T fields -e frame.number 2>/dev/null | wc -l)

    awk -v name="$NAME" -v n="$COUNT" -v total="$TOTAL" \
        'BEGIN {printf "%-12s %.1f%% (%d packets)\n",
        name, n/total*100, n}'
done

echo "Agent traffic: not classified unless a dedicated agent port is identified."


# =========================================================
# 3. TOP 10 SOURCE IPS
# =========================================================

echo
echo "=== TOP 10 SOURCE IPS ==="
echo "Fields: ip.src + frame.len"

tshark -r "$PCAP" -Y 'ip.src' \
    -T fields -e ip.src -e frame.len 2>/dev/null |
awk -F '\t' '{bytes[$1]+=$2}
END {
    for (ip in bytes)
        print bytes[ip],ip
}' |
sort -nr |
head -10 |
awk '{printf "%2d. %-16s %.2f MB\n",
      NR,$2,$1/1048576}'


# =========================================================
# 4. TOP 10 DESTINATIONS
# =========================================================

echo
echo "=== TOP 10 DESTINATION IPS ==="
echo "Filter: tcp.flags.syn==1 && tcp.flags.ack==0"

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
    -T fields -e tcp.stream -e ip.dst 2>/dev/null |
sort -u |
awk -F '\t' '{count[$2]++}
END {
    for (ip in count)
        print count[ip],ip
}' |
sort -nr |
head -10 |
awk '{printf "%2d. %-16s %d connections\n",
      NR,$2,$1}'


# =========================================================
# 5. DNS PROFILE
# =========================================================

echo
echo "=== DNS QUERY PROFILE ==="
echo "Filter: dns.flags.response==0"

DNS_FILE=$(mktemp)
trap 'rm -f "$DNS_FILE"' EXIT

tshark -r "$PCAP" \
    -Y 'dns.flags.response==0 && dns.qry.name' \
    -T fields -e dns.qry.name -e dns.qry.type 2>/dev/null \
    > "$DNS_FILE"

DNS_TOTAL=$(wc -l < "$DNS_FILE")
DNS_RATE=$(awk -v n="$DNS_TOTAL" -v m="$MINUTES" \
    'BEGIN {printf "%.2f",n/m}')

echo "Total queries: $DNS_TOTAL ($DNS_RATE/min average)"

echo "Top 20 domains:"
cut -f1 "$DNS_FILE" |
tr '[:upper:]' '[:lower:]' |
sort |
uniq -c |
sort -nr |
head -20

A=$(awk -F '\t' '$2==1 {n++} END {print n+0}' "$DNS_FILE")
AAAA=$(awk -F '\t' '$2==28 {n++} END {print n+0}' "$DNS_FILE")
TXT=$(awk -F '\t' '$2==16 {n++} END {print n+0}' "$DNS_FILE")
MX=$(awk -F '\t' '$2==15 {n++} END {print n+0}' "$DNS_FILE")

awk -v a="$A" -v aaaa="$AAAA" -v txt="$TXT" \
    -v mx="$MX" -v total="$DNS_TOTAL" 'BEGIN {
    printf "A: %.1f%% | AAAA: %.1f%% | TXT: %.1f%% | MX: %.1f%%\n",
    a/total*100, aaaa/total*100, txt/total*100, mx/total*100
}'

TXT_RATE=$(awk -v n="$TXT" -v m="$MINUTES" \
    'BEGIN {printf "%.2f",n/m}')

echo "TXT queries: $TXT ($TXT_RATE/min)"


# =========================================================
# 6. CONNECTION DURATIONS
# =========================================================

echo
echo "=== CONNECTION DURATION DISTRIBUTION ==="
echo "Fields: tcp.stream + frame.time_epoch"

tshark -r "$PCAP" -Y 'tcp' \
    -T fields -e tcp.stream -e frame.time_epoch 2>/dev/null |
awk -F '\t' '
$1!="" {
    if (!($1 in first)) first[$1]=$2
    last[$1]=$2
}
END {
    for (s in first) {
        d=last[s]-first[s]
        total++

        if (d<1) short++
        else if (d<=30) medium++
        else long++
    }

    printf "Short (<1s):      %.1f%%\n", short/total*100
    printf "Medium (1-30s):   %.1f%%\n", medium/total*100
    printf "Long (>30s):      %.1f%%\n", long/total*100
}'


# =========================================================
# 7. TLS
# =========================================================

echo
echo "=== TLS ANALYSIS ==="

echo "SNI values:"
echo "Filter: tls.handshake.extensions_server_name"

tshark -r "$PCAP" \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields \
    -e tls.handshake.extensions_server_name 2>/dev/null |
sort -u |
sed 's/^/  /'


echo "TLS versions:"
echo "Filter: tls.handshake.type==2"

tshark -r "$PCAP" \
    -Y 'tls.handshake.type==2' \
    -T fields \
    -e tls.handshake.version \
    -e tls.handshake.extensions.supported_version 2>/dev/null |
sort -u |
sed 's/^/  /'


echo "Certificate details where available:"
echo "Filter: tls.handshake.type==11"

tshark -r "$PCAP" \
    -Y 'tls.handshake.type==11' \
    -V 2>/dev/null |
grep -Ei 'Issuer:|CommonName:' |
head -20 |
sed 's/^/  /'


# =========================================================
# 8. TEMPORAL PATTERN
# =========================================================

echo
echo "=== TEMPORAL PATTERN ==="
echo "Per-minute packet counts"

tshark -r "$PCAP" \
    -T fields -e frame.time_epoch 2>/dev/null |
awk -v start="$START" '
{
    bin=int(($1-start)/60)
    packets[bin]++
}
END {
    for (b in packets)
        print b,packets[b]
}' |
sort -n |
awk '{printf "+%02d min: %d packets\n",$1,$2}'


# =========================================================
# 9. BASELINE SIGNATURES
# =========================================================

echo
echo "=== BASELINE SIGNATURES ==="

echo "Normal DNS rate: $DNS_RATE queries/min"
echo "Normal TXT query rate: $TXT_RATE queries/min"


EXT_FILE=$(mktemp)
trap 'rm -f "$DNS_FILE" "$EXT_FILE"' EXIT

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 &&
        !(ip.dst==10.0.0.0/8 ||
          ip.dst==172.16.0.0/12 ||
          ip.dst==192.168.0.0/16)' \
    -T fields -e frame.time_epoch 2>/dev/null |
awk -v start="$START" '
{
    bin=int(($1-start)/60)
    count[bin]++
}
END {
    for (b in count)
        print count[b]
}' > "$EXT_FILE"

awk '
NR==1 {min=$1; max=$1}
{
    sum+=$1
    n++
    if ($1<min) min=$1
    if ($1>max) max=$1
}
END {
    if (n)
        printf "Normal external connection rhythm: min %d, avg %.2f, max %d connections/min\n",
        min,sum/n,max
    else
        print "Normal external connection rhythm: no external TCP connections"
}' "$EXT_FILE"


PACKET_RANGE=$(
    tshark -r "$PCAP" \
        -T fields -e frame.time_epoch 2>/dev/null |
    awk -v start="$START" '
    {
        bin=int(($1-start)/60)
        count[bin]++
    }
    END {
        for (b in count)
            print count[b]
    }' |
    sort -n |
    awk 'NR==1 {min=$1} {max=$1} END {print min,max}'
)

read P_MIN P_MAX <<< "$PACKET_RANGE"

echo "Normal packet volume range: $P_MIN-$P_MAX packets/min"


# =========================================================
# SAVE SIMPLE JSON
# =========================================================

cat > "$OUT" <<EOF
{
  "pcap": "$(basename "$PCAP")",
  "duration_minutes": $MINUTES,
  "total_packets": $TOTAL,
  "dns_queries_per_minute": $DNS_RATE,
  "txt_queries_per_minute": $TXT_RATE,
  "packet_volume_min_per_minute": $P_MIN,
  "packet_volume_max_per_minute": $P_MAX
}
EOF

echo
echo "BASELINE SAVED: $OUT"
