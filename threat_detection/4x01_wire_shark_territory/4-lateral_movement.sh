#!/bin/bash

# Task 4 - Lateral Movement Analysis
# Usage:
#   ./4-lateral_movement.sh lateral_movement.pcap
#
# If normal_baseline_clinical.pcap is in the same directory,
# the script also compares important traffic with Task 0.

PCAP="$1"
BASELINE="normal_baseline_clinical.pcap"

NURSE="10.10.2.15"
BILLING="10.10.1.10"
NAS="10.10.1.60"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi


# =========================================================
# 1. CROSS-SUBNET / INTERNAL MOVEMENT
# =========================================================

echo
echo "=== CROSS-SUBNET TRAFFIC ==="
echo "Filter: internal TCP connection attempts between 10.10.x.x systems"

CROSS=$(mktemp)
trap 'rm -f "$CROSS"' EXIT

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn == 1 &&
        tcp.flags.ack == 0 &&
        ip.src == 10.10.0.0/16 &&
        ip.dst == 10.10.0.0/16' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e tcp.stream 2>/dev/null > "$CROSS"


TOTAL_CONNECTIONS=$(wc -l < "$CROSS")

UNIQUE_PAIRS=$(
    cut -f2,3 "$CROSS" |
    sort -u |
    wc -l
)

NURSE_CONNECTIONS=$(
    awk -F '\t' -v ip="$NURSE" '$2==ip {n++} END {print n+0}' "$CROSS"
)

echo "Total internal connection attempts: $TOTAL_CONNECTIONS"
echo "Unique source-destination pairs: $UNIQUE_PAIRS"
echo "Connections involving WS-NURSE-04 ($NURSE): $NURSE_CONNECTIONS"

echo
echo "Observed RDP/SMB connection attempts:"

awk -F '\t' '
$4==3389 || $4==445 {
    proto=($4==3389 ? "RDP" : "SMB")

    printf "%s | %-15s -> %-15s | %s\n",
        $1,$2,$3,proto
}' "$CROSS"


# =========================================================
# 2. AUTHENTICATION EVENTS
# =========================================================

echo
echo "=== AUTHENTICATION EVENTS ==="


# ---------------------------------------------------------
# Kerberos
# ---------------------------------------------------------

echo
echo "--- Kerberos ---"
echo "Filter: kerberos"

tshark -r "$PCAP" \
    -Y 'kerberos' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e _ws.col.Info 2>/dev/null |
head -20


# ---------------------------------------------------------
# NTLM authentication
# ---------------------------------------------------------

echo
echo "--- NTLM ---"
echo "Filter: ntlmssp"

tshark -r "$PCAP" \
    -Y 'ntlmssp' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ntlmssp.auth.username \
    -e _ws.col.Info 2>/dev/null |
head -30


# ---------------------------------------------------------
# RDP
# ---------------------------------------------------------

echo
echo "--- RDP / NLA related connections ---"
echo "Filter: tcp.port == 3389"

tshark -r "$PCAP" \
    -Y 'tcp.port == 3389 &&
        (tcp.flags.syn == 1 || tcp.flags.reset == 1)' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.flags.syn \
    -e tcp.flags.ack \
    -e tcp.flags.reset 2>/dev/null |
awk -F '\t' '
{
    result=""

    if ($6=="1")
        result="TCP RST / refused"

    else if ($4=="1" && $5=="0")
        result="Connection attempt"

    else if ($4=="1" && $5=="1")
        result="TCP accepted"

    printf "%s | %-15s -> %-15s | RDP | %s\n",
        $1,$2,$3,result
}'


# ---------------------------------------------------------
# SMB Session Setup
# ---------------------------------------------------------

echo
echo "--- SMB Session Setup ---"
echo "Filter: smb2.cmd == 1"

tshark -r "$PCAP" \
    -Y 'smb2.cmd == 1' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ntlmssp.auth.username \
    -e smb2.nt_status \
    -e _ws.col.Info 2>/dev/null |
head -40


# =========================================================
# 3. FAILED CONNECTIONS
# =========================================================

echo
echo "=== FAILED CONNECTIONS ==="

echo "TCP reset filter:"
echo "  tcp.flags.reset == 1"

tshark -r "$PCAP" \
    -Y 'tcp.flags.reset == 1 &&
        ip.src == 10.10.0.0/16 &&
        ip.dst == 10.10.0.0/16' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport 2>/dev/null |
awk -F '\t' '
{
    printf "%s | %s -> %s | ports %s -> %s | TCP RST\n",
        $1,$2,$3,$4,$5
}'


echo
echo "SMB access-denied responses:"
echo "Filter: smb2.nt_status == 0xc0000022"

tshark -r "$PCAP" \
    -Y 'smb2.nt_status == 0xc0000022' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.nt_status \
    -e _ws.col.Info 2>/dev/null


echo
echo "[*] Interpretation:"
echo "A TCP RST proves that the TCP connection was reset or refused."
echo "An SMB ACCESS DENIED response proves the requested SMB operation"
echo "was rejected."
echo "These packets do not by themselves explain why access was denied."


# =========================================================
# 4. ATTACK PATH
# =========================================================

echo
echo "=== ATTACK PATH RECONSTRUCTION ==="


# Nurse -> Billing RDP

RDP_COUNT=$(
    tshark -r "$PCAP" \
        -Y "ip.src == $NURSE &&
            ip.dst == $BILLING &&
            tcp.dstport == 3389 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields -e frame.number 2>/dev/null |
    wc -l
)


if [ "$RDP_COUNT" -gt 0 ]; then

    echo
    echo "Step: WS-NURSE-04 -> billing-srv-01"
    echo "  $NURSE -> $BILLING"
    echo "  Protocol: RDP"
    echo "  ATT&CK: T1021.001 Remote Desktop Protocol"

    tshark -r "$PCAP" \
        -Y "ip.src == $NURSE &&
            ip.dst == $BILLING &&
            tcp.dstport == 3389 &&
            tcp.flags.syn == 1 &&
            tcp.flags.ack == 0" \
        -T fields \
        -e frame.time 2>/dev/null |
    head -1 |
    sed 's/^/  First attempt: /'
fi


# Billing -> SMB systems

echo
echo "SMB systems contacted by billing-srv-01:"
echo "Filter: source=$BILLING, destination port 445"

tshark -r "$PCAP" \
    -Y "ip.src == $BILLING &&
        tcp.dstport == 445 &&
        tcp.flags.syn == 1 &&
        tcp.flags.ack == 0" \
    -T fields \
    -e frame.time \
    -e ip.dst 2>/dev/null |
sort -u -k2,2 |
awk -F '\t' '{
    printf "  %s -> %s at %s\n",
        "10.10.1.10",$2,$1
}'


# =========================================================
# 5. SMB ENUMERATION
# =========================================================

echo
echo "=== SMB ENUMERATION ==="


echo
echo "SMB Tree Connect activity:"
echo "Filter: smb2.cmd == 3"

tshark -r "$PCAP" \
    -Y 'smb2.cmd == 3' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e _ws.col.Info 2>/dev/null |
head -30


echo
echo "Directory listing activity:"
echo "Filter: smb2.cmd == 14"

DIR_COUNT=$(
    tshark -r "$PCAP" \
        -Y 'smb2.cmd == 14' \
        -T fields \
        -e frame.number 2>/dev/null |
    wc -l
)

echo "SMB Query Directory packets: $DIR_COUNT"

tshark -r "$PCAP" \
    -Y 'smb2.cmd == 14' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e _ws.col.Info 2>/dev/null |
head -30


echo
echo "SMB file activity:"
echo "Filter: smb2.filename"

tshark -r "$PCAP" \
    -Y 'smb2.filename' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.filename 2>/dev/null |
head -30


# =========================================================
# 6. SUCCESS / FAILURE SUMMARY
# =========================================================

echo
echo "=== ACCESS EFFECTIVENESS ==="

echo "Successful TCP handshakes to RDP/SMB:"
echo "Filter: SYN-ACK on ports 3389 or 445"

tshark -r "$PCAP" \
    -Y 'tcp.flags.syn == 1 &&
        tcp.flags.ack == 1 &&
        (tcp.srcport == 3389 || tcp.srcport == 445)' \
    -T fields \
    -e frame.time \
    -e ip.dst \
    -e ip.src \
    -e tcp.srcport 2>/dev/null |
awk -F '\t' '
{
    proto=($4==3389 ? "RDP" : "SMB")

    printf "  %s -> %s | %s | TCP connection accepted | %s\n",
        $2,$3,proto,$1
}'


echo
echo "Important:"
echo "A completed TCP handshake proves the service accepted the TCP connection."
echo "It does NOT automatically prove that user authentication succeeded."


# =========================================================
# 7. BASELINE COMPARISON
# =========================================================

echo
echo "=== BASELINE COMPARISON ==="


if [ -f "$BASELINE" ]; then

    echo "Using: $BASELINE"


    # WS-NURSE-04 -> billing RDP baseline

    BASE_RDP=$(
        tshark -r "$BASELINE" \
            -Y "ip.src == $NURSE &&
                ip.dst == $BILLING &&
                tcp.dstport == 3389 &&
                tcp.flags.syn == 1 &&
                tcp.flags.ack == 0" \
            -T fields -e frame.number 2>/dev/null |
        wc -l
    )


    if [ "$BASE_RDP" -eq 0 ]; then
        echo "Does WS-NURSE-04 normally RDP to billing-srv-01? NO"
    else
        echo "Does WS-NURSE-04 normally RDP to billing-srv-01? YES ($BASE_RDP attempts)"
    fi


    # Billing SMB activity baseline

    BASE_SMB=$(
        tshark -r "$BASELINE" \
            -Y "ip.src == $BILLING &&
                tcp.dstport == 445 &&
                tcp.flags.syn == 1 &&
                tcp.flags.ack == 0" \
            -T fields -e frame.number 2>/dev/null |
        wc -l
    )


    if [ "$BASE_SMB" -eq 0 ]; then
        echo "Does billing-srv-01 normally initiate SMB connections? NO"
    else
        echo "Does billing-srv-01 normally initiate SMB connections? YES ($BASE_SMB attempts)"
    fi


    # Billing -> NAS baseline

    BASE_NAS=$(
        tshark -r "$BASELINE" \
            -Y "ip.src == $BILLING &&
                ip.dst == $NAS &&
                tcp.dstport == 445 &&
                tcp.flags.syn == 1 &&
                tcp.flags.ack == 0" \
            -T fields -e frame.number 2>/dev/null |
        wc -l
    )


    if [ "$BASE_NAS" -eq 0 ]; then
        echo "Does billing-srv-01 normally access NAS-01 via SMB? NO"
    else
        echo "Does billing-srv-01 normally access NAS-01 via SMB? YES ($BASE_NAS attempts)"
    fi

else

    echo "$BASELINE not found."
    echo "Exact Task 0 comparison cannot be made."
    echo "Do not claim that traffic is absent from the baseline without checking it."

fi


# =========================================================
# 8. MITRE ATT&CK MAPPING
# =========================================================

echo
echo "=== MITRE ATT&CK MAPPING ==="


RDP_ANY=$(
    tshark -r "$PCAP" \
        -Y 'tcp.port == 3389' \
        -T fields -e frame.number 2>/dev/null |
    wc -l
)

SMB_ANY=$(
    tshark -r "$PCAP" \
        -Y 'tcp.port == 445' \
        -T fields -e frame.number 2>/dev/null |
    wc -l
)


if [ "$RDP_ANY" -gt 0 ]; then
    echo "T1021.001  Remote Desktop Protocol"
fi


if [ "$SMB_ANY" -gt 0 ]; then
    echo "T1021.002  SMB/Windows Admin Shares"
fi


if [ "$DIR_COUNT" -gt 0 ]; then
    echo "T1135      Network Share Discovery"
    echo "T1083      File and Directory Discovery"
fi


NTLM_USERS=$(
    tshark -r "$PCAP" \
        -Y 'ntlmssp.auth.username' \
        -T fields \
        -e ntlmssp.auth.username 2>/dev/null |
    sort -u |
    sed '/^$/d'
)


if [ -n "$NTLM_USERS" ]; then

    echo
    echo "Accounts visible in NTLM authentication:"

    echo "$NTLM_USERS" |
    sed 's/^/  /'

    echo
    echo "If packet evidence also shows successful authentication,"
    echo "this supports T1078.002 Valid Accounts: Domain Accounts."
fi


# =========================================================
# CONCLUSION
# =========================================================

echo
echo "=== CONCLUSION ==="

echo "The PCAP shows the internal RDP/SMB connection path above."
echo "Successful TCP handshakes show which services accepted connections."
echo "TCP resets and SMB status responses show which attempts failed."
echo "SMB directory and file activity shows whether enumeration occurred."
echo
echo "Authentication success is only claimed when the protocol evidence"
echo "clearly shows it; a TCP connection alone is not proof of login success."
