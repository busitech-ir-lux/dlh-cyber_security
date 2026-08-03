#!/bin/bash
set -euo pipefail

CONFIG="/etc/sysctl.conf"
BACKUP="/etc/sysctl.conf.bak"

PARAMETERS=(
"net.ipv4.ip_forward=0"
"net.ipv4.conf.all.accept_redirects=0"
"net.ipv4.conf.default.accept_redirects=0"
"net.ipv4.conf.all.send_redirects=0"
"net.ipv4.conf.all.accept_source_route=0"
"net.ipv4.conf.all.log_martians=1"
"net.ipv4.tcp_syncookies=1"
"net.ipv4.icmp_echo_ignore_broadcasts=1"
"net.ipv6.conf.all.disable_ipv6=1"
"net.ipv6.conf.default.disable_ipv6=1"
"kernel.randomize_va_space=2"
"fs.suid_dumpable=0"
"kernel.dmesg_restrict=1"
"kernel.kptr_restrict=2"
)

echo "[*] Backing up $CONFIG"

touch "$CONFIG"
cp "$CONFIG" "$BACKUP"

echo "[*] Applying kernel hardening parameters..."

printf "%s\n" "${PARAMETERS[@]}" > "$CONFIG"
sysctl -p "$CONFIG" > /dev/null

PASS=0
FAIL=0

for item in "${PARAMETERS[@]}"; do
    key="${item%%=*}"
    expected="${item#*=}"
    path="/proc/sys/${key//./\/}"
    actual=$(cat "$path")

    if [[ "$actual" == "$expected" ]]; then
        printf "%-47s [PASS]\n" "$key = $actual"
        ((PASS+=1))
    else
        printf "%-47s [FAIL]\n" "$key = $actual"
        ((FAIL+=1))
    fi
done

echo "Parameters applied: ${#PARAMETERS[@]}"
echo "Verified PASS: $PASS"
echo "Verified FAIL: $FAIL"
