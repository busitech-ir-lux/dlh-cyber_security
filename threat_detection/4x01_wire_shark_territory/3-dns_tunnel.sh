#!/bin/bash

# Task 3 - DNS Tunnel Analysis
# Usage:
#   ./3-dns_tunnel.sh dns_exfil.pcap
#
# Optional Task 0 comparison:
#   Put baseline_clinical.json in the same directory.

PCAP="$1"

SOURCE_IP="10.10.1.10"
TUNNEL_DOMAIN="data-sync.meddefense-portal.com"
BASELINE="baseline_clinical.json"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ALL="$TMP/all.tsv"
NORMAL="$TMP/normal.tsv"
ANOM="$TMP/anomalous.tsv"
TUNNEL="$TMP/tunnel.tsv"


# =========================================================
# 1. EXTRACT DNS QUERIES
# =========================================================

echo
echo "=== DNS QUERY CLASSIFICATION ==="
echo "Filter: ip.src == $SOURCE_IP && dns.flags.response == 0"

tshark -r "$PCAP" \
    -Y "ip.src == $SOURCE_IP && dns.flags.response == 0 && dns.qry.name" \
    -T fields \
    -e frame.time_epoch \
    -e dns.qry.name \
    -e dns.qry.type 2>/dev/null > "$ALL"


# =========================================================
# 2. NORMAL VS ANOMALOUS
# =========================================================

# Normal examples:
#   meddefense.com
#   Microsoft
#   Windows
#   Ubuntu
#   Canonical
#
# Anomalous:
#   known tunnel domain
#   TXT query to unusual domain
#   very long / encoded-looking first label

# Create the files first
: > "$NORMAL"
: > "$ANOM"

awk -F '\t' \
    -v normal="$NORMAL" \
    -v anomalous="$ANOM" \
    -v tunnel="$TUNNEL_DOMAIN" '

function endswith(text, suffix) {
    return length(text) >= length(suffix) &&
           substr(text, length(text)-length(suffix)+1) == suffix
}

{
    domain=tolower($2)

    split(domain, parts, ".")
    first=parts[1]

    known_normal = endswith(domain, "meddefense.com") || endswith(domain, "microsoft.com") || endswith(domain, "microsoftonline.com") || endswith(domain, "windows.com") || endswith(domain, "ubuntu.com") || endswith(domain, "canonical.com")

    encoded = (length(first) >= 30 && first ~ /^[a-zA-Z0-9+_=-]+$/)

    if (endswith(domain, tunnel)) {
        print > anomalous
    }
    else if (known_normal) {
        print > normal
    }
    else if ($3 == 16 || length(first) >= 30 || encoded) {
        print > anomalous
    }
    else {
        print > normal
    }
}

' "$ALL"


TOTAL=$(wc -l < "$ALL")
NORMAL_COUNT=$(wc -l < "$NORMAL")
ANOM_COUNT=$(wc -l < "$ANOM")

echo "Total DNS queries: $TOTAL"
echo "Normal queries: $NORMAL_COUNT"
echo "Anomalous queries: $ANOM_COUNT"


# Save all anomalous names for evidence.

cut -f2 "$ANOM" > anomalous_dns_queries.txt

echo "Full anomalous query list saved: anomalous_dns_queries.txt"


# =========================================================
# 3. ANALYZE TUNNEL QUERIES
# =========================================================

echo
echo "=== ANOMALOUS QUERY ANALYSIS ==="
echo "Expected suspicious base domain: $TUNNEL_DOMAIN"


: > "$TUNNEL"

awk -F '\t' -v tunnel="$TUNNEL_DOMAIN" '

{
    domain=tolower($2)
    suffix="." tunnel

    if (length(domain) > length(suffix) &&
        substr(domain, length(domain)-length(suffix)+1) == suffix) {

        payload=substr($2, 1, length($2)-length(suffix))

        print $1 "\t" $2 "\t" payload "\t" length(payload) "\t" $3
    }
}

' "$ANOM" > "$TUNNEL"


TUNNEL_COUNT=$(wc -l < "$TUNNEL")

echo "Base domain: $TUNNEL_DOMAIN"
echo "Tunnel queries: $TUNNEL_COUNT"


if [ "$TUNNEL_COUNT" -eq 0 ]; then
    echo "No queries to the expected tunnel domain were found."
    exit 0
fi


read MIN_LEN AVG_LEN MAX_LEN TOTAL_ENCODED < <(
    awk -F '\t' '

    NR==1 {
        min=$4
        max=$4
    }

    {
        sum+=$4
        count++

        if ($4 < min) min=$4
        if ($4 > max) max=$4
    }

    END {
        printf "%d %.2f %d %d\n",
            min, sum/count, max, sum
    }

    ' "$TUNNEL"
)


echo "Subdomain label length:"
echo "  Minimum: $MIN_LEN"
echo "  Average: $AVG_LEN"
echo "  Maximum: $MAX_LEN"


# Determine DNS query types.

echo "Query types:"

awk -F '\t' '

{
    if ($5 == 1) type="A"
    else if ($5 == 28) type="AAAA"
    else if ($5 == 16) type="TXT"
    else if ($5 == 15) type="MX"
    else type="Type " $5

    count[type]++
}

END {
    for (type in count)
        print "  " type ": " count[type]
}

' "$TUNNEL"


# Simple encoded-looking check.

ENCODED_COUNT=$(
    awk -F '\t' '
    $3 ~ /^[A-Za-z0-9+_=-]+$/ && length($3) >= 30 {
        count++
    }
    END {
        print count+0
    }' "$TUNNEL"
)

echo "Encoded-looking labels: $ENCODED_COUNT / $TUNNEL_COUNT"


# =========================================================
# 4. QUERY RATE AND TIMING
# =========================================================

echo
echo "=== TUNNEL TIMING ==="

read FIRST LAST < <(
    awk -F '\t' '
    NR==1 {first=$1}
    {last=$1}
    END {print first,last}
    ' "$TUNNEL"
)


SPAN_SECONDS=$(awk -v first="$FIRST" -v last="$LAST" \
    'BEGIN {printf "%.2f",last-first}')

SPAN_MIN=$(awk -v seconds="$SPAN_SECONDS" \
    'BEGIN {
        m=seconds/60
        if (m <= 0) m=1
        printf "%.2f",m
    }')

RATE=$(awk -v n="$TUNNEL_COUNT" -v m="$SPAN_MIN" \
    'BEGIN {printf "%.2f",n/m}')


echo "Total tunnel queries: $TUNNEL_COUNT"
echo "Time span: $SPAN_SECONDS seconds ($SPAN_MIN minutes)"
echo "Query rate: $RATE queries/min"


# Connection/query interval statistics.

awk -F '\t' '

NR==1 {
    previous=$1
    next
}

{
    interval=$1-previous
    previous=$1

    sum+=interval
    count++

    if (count==1 || interval<min) min=interval
    if (count==1 || interval>max) max=interval
}

END {
    if (count>0) {
        printf "Query intervals: min %.2fs, avg %.2fs, max %.2fs\n",
            min, sum/count, max
    }
}

' "$TUNNEL"


# =========================================================
# 5. TRY TO DECODE 5 LABELS
# =========================================================

echo
echo "=== SAMPLE DECODING ==="

echo "Approach:"
echo "  1. Try Base32"
echo "  2. If that fails, try Base64"
echo "  3. Do not invent content if decoding fails"


decode_label() {

    LABEL="$1"

    # -------------------------
    # Try Base32
    # -------------------------

    B32=$(echo "$LABEL" | tr '[:lower:]' '[:upper:]')

    # Add Base32 padding.
    while [ $((${#B32} % 8)) -ne 0 ]; do
        B32="${B32}="
    done

    RESULT=$(printf '%s' "$B32" |
        base32 -d 2>/dev/null || true)


    if [ -n "$RESULT" ] &&
       printf '%s' "$RESULT" |
       LC_ALL=C grep -q '^[[:print:][:space:]]*$'; then

        echo "Base32 decoded: $RESULT"
        return
    fi


    # -------------------------
    # Try Base64
    # -------------------------

    B64=$(echo "$LABEL" | tr '_-' '/+')

    while [ $((${#B64} % 4)) -ne 0 ]; do
        B64="${B64}="
    done

    RESULT=$(printf '%s' "$B64" |
        base64 -d 2>/dev/null || true)


    if [ -n "$RESULT" ] &&
       printf '%s' "$RESULT" |
       LC_ALL=C grep -q '^[[:print:][:space:]]*$'; then

        echo "Base64 decoded: $RESULT"
        return
    fi


    echo "Decoding failed or result was not readable text."
}


COUNT=0

while IFS=$'\t' read -r TIME QUERY LABEL LENGTH TYPE; do

    COUNT=$((COUNT+1))

    echo
    echo "Query $COUNT:"
    echo "  Full query: $QUERY"
    echo "  Encoded label: $LABEL"
    echo "  Length: $LENGTH"

    echo -n "  Result: "
    decode_label "$LABEL"

    [ "$COUNT" -eq 5 ] && break

done < "$TUNNEL"


# =========================================================
# 6. DNS RESPONSE ANALYSIS
# =========================================================

echo
echo "=== DNS RESPONSE ANALYSIS ==="

echo "Filter:"
echo "  dns.flags.response == 1"
echo "  dns.qry.name contains $TUNNEL_DOMAIN"


RESP="$TMP/responses.tsv"

tshark -r "$PCAP" \
    -Y "dns.flags.response == 1 &&
        dns.qry.name contains \"$TUNNEL_DOMAIN\"" \
    -T fields \
    -e frame.time_epoch \
    -e dns.qry.type \
    -e dns.txt \
    -e frame.len 2>/dev/null > "$RESP"


RESP_COUNT=$(wc -l < "$RESP")

echo "Tunnel DNS responses: $RESP_COUNT"


if [ "$RESP_COUNT" -gt 0 ]; then

    awk -F '\t' '

    {
        total_packet += $4

        if ($3 != "") {
            txt++
            txt_size += length($3)
        }
    }

    END {

        printf "Average DNS response packet size: %.1f bytes\n",
            total_packet/NR

        if (txt > 0)
            printf "Average TXT content length: %.1f bytes\n",
                txt_size/txt
    }

    ' "$RESP"


    echo
    echo "Sample TXT responses:"

    awk -F '\t' '$3 != "" {print $3}' "$RESP" |
    head -3 |
    sed 's/^/  /'

else
    echo "No matching DNS responses found."
fi


# =========================================================
# 7. ESTIMATE EXFILTRATION VOLUME
# =========================================================

echo
echo "=== EXFILTRATION VOLUME ==="

echo "Tunnel queries: $TUNNEL_COUNT"
echo "Average encoded payload: $AVG_LEN characters/query"
echo "Total encoded payload: $TOTAL_ENCODED characters"


# Base32 carries about 5 raw bits per encoded character.
RAW_BASE32=$(awk -v n="$TOTAL_ENCODED" \
    'BEGIN {printf "%.0f",n*5/8}')

# Base64 carries about 6 raw bits per encoded character.
RAW_BASE64=$(awk -v n="$TOTAL_ENCODED" \
    'BEGIN {printf "%.0f",n*3/4}')


echo "Estimated raw payload:"
echo "  If Base32: about $RAW_BASE32 bytes"
echo "  If Base64: about $RAW_BASE64 bytes"

echo
echo "Because the exact encoding is not confirmed, this is an estimate."


# =========================================================
# 8. EXFILTRATION RATE
# =========================================================

RATE_B32=$(awk -v bytes="$RAW_BASE32" -v min="$SPAN_MIN" \
    'BEGIN {printf "%.2f",bytes/min}')

RATE_B64=$(awk -v bytes="$RAW_BASE64" -v min="$SPAN_MIN" \
    'BEGIN {printf "%.2f",bytes/min}')


echo
echo "Estimated exfiltration rate:"

echo "  Base32 estimate: $RATE_B32 bytes/min"
echo "  Base64 estimate: $RATE_B64 bytes/min"


# =========================================================
# 9. COMPARE WITH TASK 0 BASELINE
# =========================================================

echo
echo "=== DETECTION COMPARISON ==="

if [ -f "$BASELINE" ] && command -v jq >/dev/null 2>&1; then

    BASE_DNS=$(jq -r \
        '.dns_queries_per_minute //
         .dns.queries_per_minute //
         empty' "$BASELINE")

    BASE_TXT=$(jq -r \
        '.txt_queries_per_minute //
         .dns.txt_queries_per_minute //
         empty' "$BASELINE")


    echo "Task 0 baseline DNS rate: ${BASE_DNS:-not stored} queries/min"
    echo "Task 0 baseline TXT rate: ${BASE_TXT:-not stored} queries/min"

else

    echo "baseline_clinical.json not found."
    echo "Numeric Task 0 comparison cannot be calculated."

fi


echo
echo "Tunnel DNS:"
echo "  Query type: mostly TXT if shown above"
echo "  Subdomain length: $MIN_LEN-$MAX_LEN characters"
echo "  Encoded-looking labels: $ENCODED_COUNT/$TUNNEL_COUNT"
echo "  Query rate: $RATE queries/min"
echo "  Destination domain: $TUNNEL_DOMAIN"


# =========================================================
# CONCLUSION
# =========================================================

echo
echo "=== CONCLUSION ==="

if [ "$ENCODED_COUNT" -gt 0 ] && [ "$TUNNEL_COUNT" -gt 0 ]; then

    echo "billing-srv-01 generated repeated DNS queries to"
    echo "$TUNNEL_DOMAIN with long encoded-looking labels."

    echo
    echo "The combination of the unusual domain, repeated queries,"
    echo "long encoded labels and DNS payload volume is consistent"
    echo "with DNS tunneling."

    echo
    echo "The traffic can support a data-exfiltration conclusion,"
    echo "but decoded content is only claimed where decoding"
    echo "actually succeeded."

else

    echo "The available DNS evidence is not enough to confirm"
    echo "DNS tunneling."

fi
