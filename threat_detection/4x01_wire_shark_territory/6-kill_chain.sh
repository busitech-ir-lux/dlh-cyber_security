#!/bin/bash

# Task 6 - Complete Kill Chain Reconstruction
# Usage:
#   ./6-kill_chain.sh
#
# Required files:
#   phishing_click.pcap
#   c2_beaconing.pcap
#   dns_exfil.pcap
#   lateral_movement.pcap
#   full_timeline.pcap
#
# 4x00 email information is context only because it is not PCAP evidence.

PHISH="phishing_click.pcap"
C2="c2_beaconing.pcap"
DNS="dns_exfil.pcap"
LATERAL="lateral_movement.pcap"
FULL="full_timeline.pcap"

NURSE="10.10.2.15"
BILLING="10.10.1.10"
PHISH_IP="91.234.99.107"
PHISH_DOMAIN="meddefense-portal.com"
TUNNEL_DOMAIN="data-sync.meddefense-portal.com"
VPN_SERVER="10.10.0.1"
ACCOUNT="dmarsh"

# Optional:
# If you know the exact phishing-email timestamp from 4x00,
# you can put it here. Otherwise dwell time starts from
# the first packet-confirmed phishing activity.
EMAIL_TIME="Not available in these PCAPs"


# =========================================================
# CHECK FILES
# =========================================================

for FILE in "$PHISH" "$C2" "$DNS" "$LATERAL" "$FULL"; do

    if [ ! -f "$FILE" ]; then
        echo "Error: missing $FILE"
        exit 1
    fi

done


# =========================================================
# PHASE 2 - PHISHING CLICK
# =========================================================

echo "Filter for phishing click:"
echo "  dns.qry.name == \"$PHISH_DOMAIN\""

CLICK_LINE=$(
    tshark -r "$PHISH" \
        -Y "dns.flags.response == 0 &&
            dns.qry.name == \"$PHISH_DOMAIN\"" \
        -T fields \
        -e frame.time_epoch \
        -e frame.time \
        -e ip.src \
        -e ip.dst 2>/dev/null |
    head -1
)

IFS=$'\t' read -r \
    CLICK_EPOCH CLICK_TIME CLICK_SRC CLICK_DNS <<< "$CLICK_LINE"


PHISH_RESPONSE=$(
    tshark -r "$PHISH" \
        -Y "dns.flags.response == 1 &&
            dns.qry.name == \"$PHISH_DOMAIN\"" \
        -T fields \
        -e dns.a 2>/dev/null |
    head -1
)


# Find HTTPS connection to phishing infrastructure.

CLICK_STREAM=$(
    tshark -r "$PHISH" \
        -Y "ip.dst == $PHISH_IP &&
            tcp.dstport == 443 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e tcp.stream 2>/dev/null |
    head -1
)


CLICK_END=""

if [ -n "$CLICK_STREAM" ]; then

    CLICK_END=$(
        tshark -r "$PHISH" \
            -Y "tcp.stream == $CLICK_STREAM" \
            -T fields \
            -e frame.time 2>/dev/null |
        tail -1
    )

fi


# =========================================================
# PHASE 3 - C2 BEACONING
# =========================================================

echo "Filter for C2:"
echo "  $NURSE -> $PHISH_IP:443 initial SYN packets"

C2_FILE="/tmp/c2_timeline_$$.txt"

tshark -r "$C2" \
    -Y "ip.src == $NURSE &&
        ip.dst == $PHISH_IP &&
        tcp.dstport == 443 &&
        tcp.flags.syn == 1 &&
        tcp.flags.ack == 0" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time 2>/dev/null > "$C2_FILE"


C2_COUNT=$(wc -l < "$C2_FILE")

C2_FIRST_EPOCH=$(head -1 "$C2_FILE" | cut -f1)
C2_FIRST_TIME=$(head -1 "$C2_FILE" | cut -f2)
C2_LAST_TIME=$(tail -1 "$C2_FILE" | cut -f2)


C2_INTERVAL=$(
    awk -F '\t' '

    NR==1 {
        previous=$1
        next
    }

    {
        total += $1-previous
        previous=$1
        count++
    }

    END {
        if (count>0)
            printf "%.1f", total/count
        else
            print "N/A"
    }

    ' "$C2_FILE"
)


# =========================================================
# PHASE 4 - VPN PIVOT
# =========================================================

echo "Filter for VPN:"
echo "  external IP -> $VPN_SERVER:443"

VPN_LINE=$(
    tshark -r "$FULL" \
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
        -e tcp.stream 2>/dev/null |
    head -1
)


IFS=$'\t' read -r \
    VPN_EPOCH VPN_TIME VPN_SRC VPN_PORT VPN_STREAM <<< "$VPN_LINE"


VPN_ACCOUNT="not visible"

if [ -n "$VPN_STREAM" ]; then

    if tshark -r "$FULL" \
        -Y "tcp.stream == $VPN_STREAM" \
        -V 2>/dev/null |
        grep -qi "$ACCOUNT"; then

        VPN_ACCOUNT="$ACCOUNT"
    fi

fi


# =========================================================
# PHASE 5 - FIRST RDP MOVEMENT
# =========================================================

echo "Filter for lateral RDP:"
echo "  $NURSE -> $BILLING:3389"

RDP_LINE=$(
    tshark -r "$LATERAL" \
        -Y "ip.src == $NURSE &&
            ip.dst == $BILLING &&
            tcp.dstport == 3389 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e frame.time_epoch \
        -e frame.time \
        -e ip.src \
        -e ip.dst 2>/dev/null |
    head -1
)


IFS=$'\t' read -r \
    RDP_EPOCH RDP_TIME RDP_SRC RDP_DST <<< "$RDP_LINE"


RDP_ACCOUNT=$(
    tshark -r "$LATERAL" \
        -Y 'ntlmssp.auth.username' \
        -T fields \
        -e ntlmssp.auth.username 2>/dev/null |
    grep -i -m1 "$ACCOUNT" || true
)


if [ -z "$RDP_ACCOUNT" ]; then
    RDP_ACCOUNT="not visible"
fi


# =========================================================
# PHASE 6 - SMB ENUMERATION
# =========================================================

echo "Filter for SMB:"
echo "  $BILLING -> internal systems on TCP/445"

SMB_FIRST=$(
    tshark -r "$LATERAL" \
        -Y "ip.src == $BILLING &&
            tcp.dstport == 445 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e frame.time \
        -e ip.dst 2>/dev/null |
    head -1
)


SMB_DESTINATIONS=$(
    tshark -r "$LATERAL" \
        -Y "ip.src == $BILLING &&
            tcp.dstport == 445 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e ip.dst 2>/dev/null |
    sort -u
)


SMB_DENIED=$(
    tshark -r "$LATERAL" \
        -Y 'smb2.nt_status == 0xc0000022' \
        -T fields \
        -e frame.number 2>/dev/null |
    wc -l
)


SMB_RST=$(
    tshark -r "$LATERAL" \
        -Y "tcp.flags.reset == 1 &&
            ip.addr == $BILLING" \
        -T fields \
        -e frame.number 2>/dev/null |
    wc -l
)


DIR_COUNT=$(
    tshark -r "$LATERAL" \
        -Y 'smb2.cmd == 14' \
        -T fields \
        -e frame.number 2>/dev/null |
    wc -l
)


# =========================================================
# PHASE 7 - DNS EXFILTRATION
# =========================================================

echo "Filter for DNS tunnel:"
echo "  $BILLING TXT queries containing $TUNNEL_DOMAIN"

DNS_TUNNEL="/tmp/dns_tunnel_$$.txt"

tshark -r "$DNS" \
    -Y "ip.src == $BILLING &&
        dns.flags.response == 0 &&
        dns.qry.type == 16 &&
        dns.qry.name contains \"$TUNNEL_DOMAIN\"" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e dns.qry.name 2>/dev/null > "$DNS_TUNNEL"


DNS_COUNT=$(wc -l < "$DNS_TUNNEL")

DNS_FIRST_EPOCH=$(head -1 "$DNS_TUNNEL" | cut -f1)
DNS_FIRST_TIME=$(head -1 "$DNS_TUNNEL" | cut -f2)

DNS_LAST_EPOCH=$(tail -1 "$DNS_TUNNEL" | cut -f1)
DNS_LAST_TIME=$(tail -1 "$DNS_TUNNEL" | cut -f2)

DNS_SRC=$(head -1 "$DNS_TUNNEL" | cut -f3)
DNS_DST=$(head -1 "$DNS_TUNNEL" | cut -f4)


# Average encoded label length.

AVG_LABEL=$(
    awk -F '\t' -v domain="$TUNNEL_DOMAIN" '

    {
        name=$5
        suffix="." domain

        if (length(name) > length(suffix)) {
            label=substr(name,1,length(name)-length(suffix))
            total+=length(label)
            count++
        }
    }

    END {
        if (count>0)
            printf "%.1f",total/count
        else
            print "0"
    }

    ' "$DNS_TUNNEL"
)


TOTAL_ENCODED=$(
    awk -F '\t' -v domain="$TUNNEL_DOMAIN" '

    {
        name=$5
        suffix="." domain

        if (length(name) > length(suffix)) {
            label=substr(name,1,length(name)-length(suffix))
            total+=length(label)
        }
    }

    END {
        print total+0
    }

    ' "$DNS_TUNNEL"
)


# Raw size estimates depending on encoding.
RAW_B32=$(
    awk -v n="$TOTAL_ENCODED" \
        'BEGIN {printf "%.0f",n*5/8}'
)

RAW_B64=$(
    awk -v n="$TOTAL_ENCODED" \
        'BEGIN {printf "%.0f",n*3/4}'
)


# =========================================================
# DWELL TIME
# =========================================================

# Since the exact email timestamp is not present in these PCAPs,
# calculate packet-confirmed dwell time from phishing click
# to the final DNS exfiltration query.

DWELL_SECONDS=$(
    awk -v start="$CLICK_EPOCH" -v end="$DNS_LAST_EPOCH" \
        'BEGIN {printf "%.0f",end-start}'
)

DWELL_HOURS=$((DWELL_SECONDS / 3600))
DWELL_MINUTES=$(((DWELL_SECONDS % 3600) / 60))


# VPN -> RDP gap

VPN_RDP_GAP="N/A"

if [ -n "$VPN_EPOCH" ] && [ -n "$RDP_EPOCH" ]; then

    VPN_RDP_GAP=$(
        awk -v vpn="$VPN_EPOCH" -v rdp="$RDP_EPOCH" \
            'BEGIN {printf "%.1f",(rdp-vpn)/60}'
    )

fi


# =========================================================
# PRINT MASTER TIMELINE
# =========================================================

echo
echo "================================================================"
echo "   COMPLETE KILL CHAIN RECONSTRUCTION"
echo "   Incident: Phishing -> Network Compromise -> DNS Exfiltration"
echo "   Packet-confirmed dwell time: ${DWELL_HOURS}h ${DWELL_MINUTES}m"
echo "================================================================"


echo
echo "PHASE 1: INITIAL ACCESS"
echo "MITRE ATT&CK: T1566.002 - Spearphishing Link"
echo "Time: $EMAIL_TIME"
echo "Evidence: 4x00 phishing investigation"
echo "Action: Phishing email targeted the MedDefense user."
echo "Status: CONTEXT - not packet evidence in this project."


echo
echo "PHASE 2: CREDENTIAL HARVESTING SESSION"
echo "MITRE ATT&CK: T1056.003 - Web Portal Capture"
echo "Time: $CLICK_TIME to ${CLICK_END:-unknown}"
echo "PCAP: $PHISH"
echo "Source: ${CLICK_SRC:-unknown}"
echo "DNS server: ${CLICK_DNS:-unknown}"
echo "DNS: $PHISH_DOMAIN -> ${PHISH_RESPONSE:-unknown}"
echo "HTTPS destination: $PHISH_IP"
echo "Evidence: DNS lookup followed by TLS/HTTPS traffic."
echo "Assessment: CONFIRMED contact with phishing infrastructure."
echo "Inference: encrypted outbound data may be consistent with"
echo "credential submission, but plaintext credentials are not proven."


echo
echo "PHASE 3: COMMAND AND CONTROL BEACONING"
echo "MITRE ATT&CK: T1071.001 - Web Protocols"
echo "Time: ${C2_FIRST_TIME:-unknown} to ${C2_LAST_TIME:-unknown}"
echo "PCAP: $C2"
echo "Source/Destination: $NURSE -> $PHISH_IP:443"
echo "Connections: $C2_COUNT"
echo "Average interval: $C2_INTERVAL seconds"
echo "Evidence: repeated HTTPS connections to the same external IP."
echo "Assessment: timing pattern is consistent with automated beaconing."


echo
echo "PHASE 4: VPN PIVOT"
echo "MITRE ATT&CK: T1133 - External Remote Services"
echo "MITRE ATT&CK: T1078.002 - Valid Accounts: Domain Accounts"
echo "Time: ${VPN_TIME:-unknown}"
echo "PCAP: $FULL"
echo "Source: ${VPN_SRC:-unknown}:${VPN_PORT:-unknown}"
echo "Destination: $VPN_SERVER:443"
echo "Account visible: $VPN_ACCOUNT"
echo "Evidence: external HTTPS/VPN-style connection before RDP activity."
echo "VPN -> first RDP gap: $VPN_RDP_GAP minutes"


echo
echo "PHASE 5: LATERAL MOVEMENT"
echo "MITRE ATT&CK: T1021.001 - Remote Desktop Protocol"
echo "Time: ${RDP_TIME:-unknown}"
echo "PCAP: $LATERAL"
echo "Source/Destination: ${RDP_SRC:-unknown} -> ${RDP_DST:-unknown}:3389"
echo "Account visible: $RDP_ACCOUNT"
echo "Evidence: RDP connection attempt from clinical workstation"
echo "to billing server."


echo
echo "PHASE 6: SMB DISCOVERY / ENUMERATION"
echo "MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares"
echo "MITRE ATT&CK: T1135 - Network Share Discovery"
echo "MITRE ATT&CK: T1083 - File and Directory Discovery"
echo "PCAP: $LATERAL"
echo "First SMB activity: ${SMB_FIRST:-not observed}"

echo "SMB destinations:"
if [ -n "$SMB_DESTINATIONS" ]; then
    echo "$SMB_DESTINATIONS" | sed 's/^/  /'
else
    echo "  None observed"
fi

echo "ACCESS DENIED responses: $SMB_DENIED"
echo "TCP resets involving billing server: $SMB_RST"
echo "Directory-query packets: $DIR_COUNT"


echo
echo "PHASE 7: DNS EXFILTRATION"
echo "MITRE ATT&CK: T1048.003 - Exfiltration Over Alternative Protocol"
echo "Time: ${DNS_FIRST_TIME:-unknown} to ${DNS_LAST_TIME:-unknown}"
echo "PCAP: $DNS"
echo "Source/Destination: ${DNS_SRC:-unknown} -> ${DNS_DST:-unknown}"
echo "Domain: $TUNNEL_DOMAIN"
echo "TXT tunnel queries: $DNS_COUNT"
echo "Average encoded label length: $AVG_LABEL characters"
echo "Estimated raw payload if Base32: ~$RAW_B32 bytes"
echo "Estimated raw payload if Base64: ~$RAW_B64 bytes"
echo "Assessment: traffic is consistent with DNS tunneling."
echo "Exact exfiltrated plaintext is not confirmed."


# =========================================================
# VISIBILITY / DEFENSE LAYERS
# =========================================================

echo
echo "=== VISIBILITY / DEFENSE LAYERS ==="

echo "Email authentication/policy:"
echo "  Tested during phishing delivery."
echo "  Result must come from 4x00; PCAPs here do not prove email controls."

echo
echo "User click:"
echo "  CONFIRMED by DNS/TLS contact with $PHISH_DOMAIN."

echo
echo "TLS encryption:"
echo "  HTTPS protected application content from passive inspection."
echo "  Network metadata remained visible."

echo
echo "Beaconing visibility:"
echo "  Repeated connections were visible through timing analysis."

echo
echo "VPN authentication:"
if [ "$VPN_ACCOUNT" = "$ACCOUNT" ]; then
    echo "  Account $ACCOUNT is visible in VPN-related metadata."
else
    echo "  Account authentication is not visible in plaintext."
fi

echo
echo "RDP access:"
echo "  RDP traffic between the clinical and billing networks is visible."

echo
echo "SMB enumeration:"
echo "  SMB activity and directory-query behavior are visible."

echo
echo "DNS exfiltration:"
echo "  Long repeated TXT queries are visible in packet evidence."


# =========================================================
# CRITICAL PIVOT POINTS
# =========================================================

echo
echo "=== CRITICAL PIVOT POINTS ==="

echo "1. Phishing delivery"
echo "   Blocking the phishing message or domain could have stopped"
echo "   the chain before the user reached the fake portal."

echo
echo "2. Phishing click - $CLICK_TIME"
echo "   Blocking $PHISH_DOMAIN or $PHISH_IP could have stopped"
echo "   communication with the phishing infrastructure."

echo
echo "3. C2 beaconing - ${C2_FIRST_TIME:-unknown}"
echo "   Detecting the repeated HTTPS timing pattern could have"
echo "   triggered investigation before later movement."

echo
echo "4. VPN pivot - ${VPN_TIME:-unknown}"
echo "   Detecting or rejecting the suspicious external VPN access"
echo "   could have prevented internal lateral movement."

echo
echo "5. RDP pivot - ${RDP_TIME:-unknown}"
echo "   Restricting unexpected workstation-to-server RDP could have"
echo "   limited movement to the billing system."

echo
echo "6. SMB enumeration"
echo "   Access controls did resist some requests, shown by denied/reset traffic."

echo
echo "7. DNS tunnel - ${DNS_FIRST_TIME:-unknown}"
echo "   Detecting abnormal TXT queries could have interrupted exfiltration."


# =========================================================
# IMPACT
# =========================================================

echo
echo "=== IMPACT ASSESSMENT ==="

echo "Confirmed packet evidence:"
echo "  - Workstation contacted phishing infrastructure."
echo "  - Repeated HTTPS beaconing occurred."
echo "  - External VPN-style access occurred."
echo "  - RDP movement toward billing-srv-01 occurred."
echo "  - billing-srv-01 contacted internal systems over SMB."
echo "  - SMB access-denied/reset activity occurred."
echo "  - DNS TXT tunneling activity occurred."


echo
echo "Likely / inferred:"
echo "  - Credentials may have been submitted through the phishing page."
echo "  - VPN activity may represent use of the stolen credentials."
echo "  - DNS tunnel traffic is consistent with data exfiltration."
echo "  - Estimated raw tunneled data: $RAW_B32-$RAW_B64 bytes."


echo
echo "Not confirmed from packet evidence alone:"
echo "  - Exact plaintext password"
echo "  - Exact full contents of encrypted HTTPS traffic"
echo "  - Exact plaintext contents of all exfiltrated data"
echo "  - Whether endpoint malware executed"
echo "  - Whether MFA was enabled"
echo "  - Whether SIEM/EDR alerts fired"
echo "  - Identity of the person controlling the external system"


echo
echo "================================================================"
echo "Packet-confirmed incident window:"
echo "  Start: $CLICK_TIME"
echo "  End:   $DNS_LAST_TIME"
echo "  Dwell: ${DWELL_HOURS} hours ${DWELL_MINUTES} minutes"
echo "================================================================"


rm -f "$C2_FILE" "$DNS_TUNNEL"
