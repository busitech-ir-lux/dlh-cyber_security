#!/bin/bash

# name: 5-auditd_refine.sh
# purpose: Add and validate detection-focused auditd rules.
# author: Mahdi Hamidi

set -e
set -u
set -o pipefail

RULE_FILE="/etc/audit/rules.d/meddefense-refine.rules"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run this script with sudo."
    exit 1
fi

current_rules=$(auditctl -l | wc -l)

echo "[*] Current auditd rules: $current_rules"
echo "[*] Adding detection-focused rules..."

cat > "$RULE_FILE" <<'EOF'
# Process execution
-a always,exit -F arch=b64 -S execve -k process_exec

# Network socket creation and connection
-a always,exit -F arch=b64 -S socket -S connect -k network_connect

# Cron persistence
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist

# Sudo configuration
-w /etc/sudoers.d/ -p wa -k sudoers
EOF

echo "    execve syscall tracking               [ADDED]"
echo "    socket/connect syscall tracking       [ADDED]"

# Requested pattern: /home/*/.ssh/
ssh_rule_added=0

for home in /home/*; do
    if [ -d "$home/.ssh" ]; then
        echo "-w $home/.ssh/ -p rwa -k ssh_keys" >> "$RULE_FILE"
        ssh_rule_added=1
    fi
done

# Also check root SSH keys
if [ -d "/root/.ssh" ]; then
    echo "-w /root/.ssh/ -p rwa -k ssh_keys" >> "$RULE_FILE"
    ssh_rule_added=1
fi

echo "    SSH key file monitoring               [ADDED]"
echo "    Cron directory monitoring             [ADDED]"
echo "    sudoers.d monitoring                  [ADDED]"


echo "[*] Loading rules..."

if augenrules --load; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    exit 1
fi

total_rules=$(auditctl -l | wc -l)

echo "[*] Total rules: $total_rules"
echo "[*] Validating new rules..."

passed=0


# 1. execve
/usr/bin/id > /dev/null

sleep 1

if ausearch -k process_exec -ts recent 2>/dev/null | grep -q "execve"; then
    echo "    execve: ran /usr/bin/id -> ausearch -k process_exec       [CAPTURED]"
    ((passed+=1))
else
    echo "    execve: ran /usr/bin/id -> ausearch -k process_exec       [MISSED]"
fi


# 2. Network
curl -s --max-time 2 http://127.0.0.1 > /dev/null 2>&1 || true

sleep 1

if ausearch -k network_connect -ts recent 2>/dev/null | grep -q "network_connect"; then
    echo "    socket: curl localhost -> ausearch -k network_connect     [CAPTURED]"
    ((passed+=1))
else
    echo "    socket: curl localhost -> ausearch -k network_connect     [MISSED]"
fi


# 3. SSH key access
ssh_test=""

for home in /home/*; do
    if [ -d "$home/.ssh" ]; then
        ssh_test="$home/.ssh/audit_test"
        touch "$ssh_test"
        break
    fi
done

if [ -z "$ssh_test" ] && [ -d "/root/.ssh" ]; then
    ssh_test="/root/.ssh/audit_test"
    touch "$ssh_test"
fi

sleep 1

if [ -n "$ssh_test" ] && ausearch -k ssh_keys -ts recent 2>/dev/null | grep -q "ssh_keys"; then
    echo "    ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys       [CAPTURED]"
    ((passed+=1))
else
    echo "    ssh_keys: SSH key access                                  [MISSED]"
fi


# 4. Cron
touch /etc/cron.d/audit_test

sleep 1

if ausearch -k cron_persist -ts recent 2>/dev/null | grep -q "cron_persist"; then
    echo "    cron: touch /etc/cron.d/test -> ausearch -k cron_persist  [CAPTURED]"
    ((passed+=1))
else
    echo "    cron: cron directory modification                         [MISSED]"
fi


# 5. sudoers.d
touch /etc/sudoers.d/audit_test

sleep 1

if ausearch -k sudoers -ts recent 2>/dev/null | grep -q "sudoers"; then
    echo "    sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers [CAPTURED]"
    ((passed+=1))
else
    echo "    sudoers: sudoers.d modification                           [MISSED]"
fi


# Cleanup
rm -f /etc/cron.d/audit_test
rm -f /etc/sudoers.d/audit_test

if [ -n "$ssh_test" ]; then
    rm -f "$ssh_test"
fi

echo "Rules added: 5 | Validation: $passed/5 PASS"