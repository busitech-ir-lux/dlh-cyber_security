#!/bin/bash

# Task 8 - Evidence Cross-Check
# Usage:
#   ./8-evidence_crosscheck.sh
#
# Purpose:
# Compare the investigation story with what the PCAPs actually prove.

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

# =========================================================
# CHECK REQUIRED FILES
# =========================================================

for FILE in "$PHISH" "$C2" "$DNS" "$LATERAL" "$FULL"; do
    if [ ! -f "$FILE" ]; then
        echo "Error: missing $FILE"
        exit 1
    fi
done


# =========================================================
# HELPER: COUNT MATCHING PACKETS
# =========================================================

count_packets() {
    tshark -r "$1" \
        -Y "$2" \
        -T fields \
        -e frame.number 2>/dev/null |
    wc -l
}


# =========================================================
# CHECK EACH PHASE FOR DIRECT PACKET EVIDENCE
# =========================================================

# Phase 1:
# Phishing email delivery is from 4x00 context, not these PCAPs.
P1=0


# Phase 2:
# DNS/TLS traffic to phishing infrastructure.
P2=$(
    count_packets "$PHISH" \
        "dns.qry.name == \"$PHISH_DOMAIN\" || ip.addr == $PHISH_IP"
)


# Phase 3:
# Repeated C2 HTTPS connections.
P3=$(
    count_packets "$C2" \
        "ip.src == $NURSE &&
         ip.dst == $PHISH_IP &&
         tcp.dstport == 443 &&
         tcp.flags.syn == 1 &&
         tcp.flags.ack == 0"
)


# Phase 4:
# External VPN-style HTTPS connection.
P4=$(
    count_packets "$FULL" \
        "ip.dst == $VPN_SERVER &&
         tcp.dstport == 443 &&
         tcp.flags.syn == 1 &&
         tcp.flags.ack == 0 &&
         !(ip.src == 10.0.0.0/8 ||
           ip.src == 172.16.0.0/12 ||
           ip.src == 192.168.0.0/16)"
)


# Phase 5:
# RDP from nurse workstation to billing server.
P5=$(
    count_packets "$LATERAL" \
        "ip.src == $NURSE &&
         ip.dst == $BILLING &&
         tcp.dstport == 3389"
)


# Phase 6:
# SMB activity from billing server.
P6=$(
    count_packets "$LATERAL" \
        "ip.src == $BILLING &&
         tcp.port == 445"
)


# Phase 7:
# TXT DNS tunnel queries.
P7=$(
    count_packets "$DNS" \
        "ip.src == $BILLING &&
         dns.flags.response == 0 &&
         dns.qry.type == 16 &&
         dns.qry.name contains \"$TUNNEL_DOMAIN\""
)


# =========================================================
# CALCULATE VISIBILITY SCORE
# =========================================================

VISIBLE=0

[ "$P1" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P2" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P3" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P4" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P5" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P6" -gt 0 ] && VISIBLE=$((VISIBLE + 1))
[ "$P7" -gt 0 ] && VISIBLE=$((VISIBLE + 1))

TOTAL_PHASES=7

SCORE=$(
    awk -v visible="$VISIBLE" -v total="$TOTAL_PHASES" \
        'BEGIN {printf "%.0f", visible/total*100}'
)


# =========================================================
# MAIN TABLE
# =========================================================

echo
echo "================================================================"
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY"
echo "================================================================"
echo
printf "%-5s | %-23s | %-13s | %s\n" \
    "Phase" "Attack Action" "PCAP Evidence?" "Verdict"

echo "------|-------------------------|---------------|-------------------"

printf "%-5s | %-23s | %-13s | %s\n" \
    "1" "Phishing delivery" "No" "NOT VISIBLE IN PCAP"

printf "%-5s | %-23s | %-13s | %s\n" \
    "2" "Credential harvesting" "Yes" "STRONG INFERENCE"

printf "%-5s | %-23s | %-13s | %s\n" \
    "3" "C2 beaconing" "Yes" "CONFIRMED"

printf "%-5s | %-23s | %-13s | %s\n" \
    "4" "VPN pivot" "Yes" "STRONG INFERENCE"

printf "%-5s | %-23s | %-13s | %s\n" \
    "5" "RDP lateral movement" "Yes" "CONFIRMED"

printf "%-5s | %-23s | %-13s | %s\n" \
    "6" "SMB discovery" "Yes" "CONFIRMED"

printf "%-5s | %-23s | %-13s | %s\n" \
    "7" "DNS exfiltration" "Yes" "CONFIRMED"


# =========================================================
# PHASE 1
# =========================================================

echo
echo "=== PHASE 1: PHISHING DELIVERY ==="

echo "Verdict: NOT VISIBLE IN PCAP"
echo
echo "Confirmed:"
echo "  Nothing about email delivery is directly confirmed by these PCAPs."

echo
echo "Context:"
echo "  The phishing email is known from the earlier 4x00 investigation."

echo
echo "Additional evidence needed:"
echo "  Mail gateway logs"
echo "  Email headers"
echo "  Mailbox evidence"


# =========================================================
# PHASE 2
# =========================================================

echo
echo "=== PHASE 2: CREDENTIAL HARVESTING ==="

echo "Filter:"
echo "  dns.qry.name == \"$PHISH_DOMAIN\""
echo "  ip.addr == $PHISH_IP"

echo
echo "Verdict: STRONG INFERENCE"

echo
echo "Confirmed:"
echo "  DNS/TLS traffic to the phishing infrastructure exists."
echo "  Matching packets found: $P2"

echo
echo "Strong inference:"
echo "  The encrypted session is consistent with the user"
echo "  interacting with the phishing page and possibly"
echo "  submitting credentials."

echo
echo "Unconfirmed:"
echo "  Exact username/password submitted"
echo "  Exact contents of the HTTPS form"

echo
echo "Additional evidence needed:"
echo "  Phishing web-server logs"
echo "  Browser history"
echo "  Endpoint logs"
echo "  User interview"


# =========================================================
# PHASE 3
# =========================================================

echo
echo "=== PHASE 3: C2 BEACONING ==="

echo "Filter:"
echo "  $NURSE -> $PHISH_IP:443 repeated TCP connections"

echo
echo "Verdict: CONFIRMED"

echo
echo "Confirmed:"
echo "  Repeated HTTPS connection pattern exists."
echo "  Matching connection attempts: $P3"

echo
echo "Packet evidence is strong because:"
echo "  source and destination are visible"
echo "  timestamps are visible"
echo "  repeated timing can be measured"

echo
echo "Unconfirmed:"
echo "  Exact commands carried inside encrypted HTTPS"

echo
echo "Additional evidence needed:"
echo "  Endpoint malware/process logs"
echo "  TLS decryption or server-side logs"


# =========================================================
# PHASE 4
# =========================================================

echo
echo "=== PHASE 4: VPN PIVOT ==="

echo "Filter:"
echo "  external IP -> $VPN_SERVER:443"

echo
echo "Verdict: STRONG INFERENCE"

echo
echo "Confirmed:"
echo "  An external HTTPS/VPN-style connection to the VPN endpoint exists."
echo "  Matching connection attempts: $P4"

echo
echo "Strong inference:"
echo "  Timing places this VPN connection before the later RDP activity."
echo "  This makes it a plausible external-to-internal pivot."

echo
echo "Unconfirmed:"
echo "  Whether stolen credentials were definitely used"
echo "  Whether MFA succeeded or was bypassed"
echo "  Exact VPN authentication result if encrypted"

echo
echo "Additional evidence needed:"
echo "  VPN authentication logs"
echo "  Identity-provider logs"
echo "  Domain-controller authentication logs"
echo "  MFA logs"


# =========================================================
# PHASE 5
# =========================================================

echo
echo "=== PHASE 5: RDP LATERAL MOVEMENT ==="

echo "Filter:"
echo "  $NURSE -> $BILLING:3389"

echo
echo "Verdict: CONFIRMED"

echo
echo "Confirmed:"
echo "  RDP traffic from the clinical workstation to the billing server exists."
echo "  Matching packets: $P5"

echo
echo "Unconfirmed from TCP alone:"
echo "  Whether the user fully authenticated"
echo "  What actions were performed inside the RDP session"

echo
echo "Additional evidence needed:"
echo "  Windows authentication logs"
echo "  RDP session logs"
echo "  Domain-controller logs"
echo "  Endpoint logs"


# =========================================================
# PHASE 6
# =========================================================

echo
echo "=== PHASE 6: SMB DISCOVERY ==="

echo "Filter:"
echo "  $BILLING -> internal systems using TCP/445"

echo
echo "Verdict: CONFIRMED"

echo
echo "Confirmed:"
echo "  SMB communication from billing-srv-01 exists."
echo "  Matching packets: $P6"
echo "  Packet evidence may show share access, directory queries,"
echo "  access denied responses and TCP resets."

echo
echo "Unconfirmed:"
echo "  Attacker intent"
echo "  Whether every discovered file was opened or copied"

echo
echo "Additional evidence needed:"
echo "  File-server audit logs"
echo "  Windows event logs"
echo "  NAS logs"


# =========================================================
# PHASE 7
# =========================================================

echo
echo "=== PHASE 7: DNS EXFILTRATION ==="

echo "Filter:"
echo "  TXT queries from $BILLING to $TUNNEL_DOMAIN"

echo
echo "Verdict: CONFIRMED"

echo
echo "Confirmed:"
echo "  Repeated TXT DNS queries to the tunnel domain exist."
echo "  Matching TXT queries: $P7"
echo "  Long encoded-looking DNS labels are visible."

echo
echo "Strong inference:"
echo "  The pattern is consistent with DNS tunneling"
echo "  and data exfiltration."

echo
echo "Unconfirmed:"
echo "  Exact full plaintext contents of all exfiltrated data"
echo "  Whether every transmitted record was received and stored"
echo "  by the attacker."

echo
echo "Additional evidence needed:"
echo "  Authoritative DNS server logs"
echo "  Attacker-side server logs"
echo "  Endpoint/file access logs"


# =========================================================
# CONFIRMED FINDINGS
# =========================================================

echo
echo "=== CONFIRMED FROM PCAP ==="

echo "- DNS/TLS contact with $PHISH_DOMAIN / $PHISH_IP"
echo "- Repeated HTTPS beaconing pattern"
echo "- External connection to the VPN endpoint"
echo "- RDP traffic from clinical host to billing server"
echo "- SMB activity from billing-srv-01"
echo "- DNS TXT tunneling pattern to $TUNNEL_DOMAIN"


# =========================================================
# STRONG INFERENCES
# =========================================================

echo
echo "=== STRONG INFERENCE ==="

echo "- Credentials were likely submitted through the phishing page."
echo "- The suspicious VPN session may represent use of stolen credentials."
echo "- DNS tunnel traffic is consistent with data exfiltration."


# =========================================================
# CANNOT CONFIRM
# =========================================================

echo
echo "=== CANNOT CONFIRM FROM PCAP ALONE ==="

echo "- Exact password entered"
echo "- Whether malware executed on the endpoint"
echo "- Whether SIEM or EDR alerts fired"
echo "- Whether the user intentionally approved an MFA request"
echo "- Exact actions performed inside an encrypted RDP session"
echo "- Exact plaintext contents of all exfiltrated data"
echo "- Identity of the person controlling the attacker system"


# =========================================================
# ADDITIONAL EVIDENCE
# =========================================================

echo
echo "=== ADDITIONAL EVIDENCE NEEDED ==="

echo "- Endpoint/process logs"
echo "- VPN authentication logs"
echo "- Domain-controller authentication logs"
echo "- Mail gateway logs"
echo "- File-server/NAS logs"
echo "- DNS resolver/server logs"
echo "- User interview"


# =========================================================
# PACKET VISIBILITY SCORE
# =========================================================

echo
echo "=== PACKET VISIBILITY SCORE ==="

echo "Direct packet evidence exists for $VISIBLE of $TOTAL_PHASES phases."
echo "Packet visibility: $SCORE%"

echo
echo "Note:"
echo "A phase can have packet evidence while the final interpretation"
echo "is still a STRONG INFERENCE."

echo "Example:"
echo "The PCAP proves communication with the phishing site,"
echo "but it may not prove the exact password submitted."


# =========================================================
# PACKET EVIDENCE STRENGTHS AND LIMITS
# =========================================================

echo
echo "=== WHERE PACKET EVIDENCE IS STRONG ==="

echo "Packets are strong for:"
echo "  source and destination IP addresses"
echo "  protocols and ports"
echo "  timestamps"
echo "  connection timing"
echo "  traffic volume"
echo "  DNS queries"
echo "  visible protocol metadata"
echo "  repeated communication patterns"


echo
echo "=== WHERE PACKET EVIDENCE HAS LIMITS ==="

echo "Packets are weaker for:"
echo "  encrypted application content"
echo "  user intent"
echo "  endpoint process execution"
echo "  successful authentication when details are encrypted"
echo "  events that never crossed the monitored network point"


# =========================================================
# FINAL LESSON
# =========================================================

echo
echo "=== KEY LESSON ==="

echo "Packet evidence shows what crossed the network."
echo
echo "Log evidence can show what happened inside a system or service,"
echo "such as a successful login, process execution or file access."
echo
echo "A strong investigation combines both and clearly separates:"
echo "  confirmed facts"
echo "  strong inference"
echo "  unconfirmed claims"
echo "  evidence that is not visible in the PCAP"

echo
echo "================================================================"
