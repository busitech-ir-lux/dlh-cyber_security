#!/bin/bash

set -euo pipefail

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
RESET="\e[0m"

echo -e "${YELLOW}[*] Backing up SSH configuration....${RESET}"

CONFIG="/etc/ssh/sshd_config"
BAK="/etc/ssh/sshd_config.bak"

cp -p "$CONFIG" "$BAK"

cat > /etc/issue.net <<'EOF'
WARNING: Authorized access only.
All activities may be monitored and recorded.
EOF

TEMP=$(mktemp)

echo -e "${YELLOW}[*] Applying SSH hardening settings...${RESET}"

cat > "$TEMP" <<'EOF'
# Prevent direct brute-force attacks against the root account
PermitRootLogin no

# Prevent password brute-force and credential-stuffing attacks
PasswordAuthentication no

# Prevent access to accounts with empty passwords
PermitEmptyPasswords no

# Prevent X11 tunneling and unnecessary attack surface
X11Forwarding no

# Limit repeated authentication attempts
MaxAuthTries 3

# Disconnect abandoned sessions after approximately 10 minutes
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict SSH access to approved administrator accounts
AllowUsers medadmin sysadmin

# Disable the obsolete SSH version 1 protocol
Protocol 2

# Limit the time available for unauthenticated login attempts
LoginGraceTime 60

# Display an authorized-use warning before login
Banner /etc/issue.net

EOF

echo "    PermitRootLogin no"
echo "    PasswordAuthentication no"
echo "    PermitEmptyPasswords no"
echo "    X11Forwarding no"
echo "    MaxAuthTries 3"
echo "    ClientAliveInterval 300"
echo "    ClientAliveCountMax 2"
echo "    AllowUsers medadmin sysadmin"
echo "    Protocol 2"
echo "    LoginGraceTime 60"
echo "    Banner /etc/issue.net"


cat "$CONFIG" >> "$TEMP"
cat "$TEMP" > "$CONFIG"
rm "$TEMP"

if sshd -t; then
    echo -e "    sshd -t: ${GREEN}OK${RESET}"
else
    echo -e "    ${RED}sshd -t: FAILED${RESET}"
    echo -e "${RED}[*] restore backup...${RESET}"
    cp -p "$BAK" "$CONFIG"
    exit 1
fi

echo -e "${YELLOW}[*] Restarting SSH service...${RESET}"

if systemctl restart ssh; then
    STATUS=$(systemctl is-active ssh)
    echo -e "    ssh.service: ${GREEN}${STATUS} (running)${RESET}"
else
    echo -e "    ${RED}SSH restart failed.${RESET}"
    echo -e "${RED}[*] Restoring SSH configuration...${RESET}"

    cp -p "$BAK" "$CONFIG"
    systemctl restart ssh

    exit 1
fi

echo -e "${GREEN}Settings applied: 11${RESET}"
