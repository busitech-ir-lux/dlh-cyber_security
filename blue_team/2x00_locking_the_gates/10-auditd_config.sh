#!/bin/bash
set -euo pipefail

# File where MedDefense audit rules will be saved
RULES="/etc/audit/rules.d/meddefense.rules"

echo "[*] Enabling auditd service..."

# Install auditd if it is not already installed
if ! dpkg -s auditd >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y auditd
fi

# Enable auditd at boot and start it now
systemctl enable --now auditd >/dev/null

# Check whether auditd is running
if systemctl is-active --quiet auditd; then
    echo "    auditd.service: active (running)"
else
    echo "    auditd.service: inactive [FAIL]"
    exit 1
fi


# ---------------------------------------------------------
# Create the MedDefense audit rules
# ---------------------------------------------------------

echo "[*] Deploying MedDefense audit rules..."

cat > "$RULES" <<'EOF'
# Monitor changes to user and group identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Monitor changes to authentication configuration
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor execution of privilege escalation tools
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc

# Monitor changes to sudo permissions
-w /etc/sudoers -p wa -k sudoers

# Monitor execution of common download tools
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download

# Monitor execution of Netcat
-w /usr/bin/nc -p x -k suspicious_netcat

# Monitor MedDefense database and web configuration
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web

# Monitor startup scripts
-w /etc/init.d/ -p wa -k startup_scripts
EOF

# Display each rule followed by [ADDED]
while IFS= read -r rule; do
    # Ignore empty lines and comment lines
    if [[ -n "$rule" && "$rule" != \#* ]]; then
        printf "    %-58s [ADDED]\n" "$rule"
    fi
done < "$RULES"


# ---------------------------------------------------------
# Load the rules
# ---------------------------------------------------------

echo "[*] Loading rules..."

# augenrules combines files from /etc/audit/rules.d/
# and loads the rules into the kernel
if augenrules --load >/dev/null; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    exit 1
fi


# ---------------------------------------------------------
# Verify that the rules are active
# ---------------------------------------------------------

echo "[*] Verifying..."

# auditctl -l lists the rules currently loaded in the kernel
LOADED=$(auditctl -l | grep -E \
    'identity|pam_config|sshd_config|priv_esc|sudoers|suspicious_download|suspicious_netcat|meddefense_db|meddefense_web|startup_scripts' |
    wc -l)

echo "    auditctl -l: $LOADED rules loaded"


# ---------------------------------------------------------
# Trigger and find a test event
# ---------------------------------------------------------

echo "[*] Test: changing metadata on /etc/passwd..."

# The identity rule watches writes and attribute changes.
# touch changes the file timestamp without changing its contents.
touch /etc/passwd

# Give auditd a moment to write the event to its log
sleep 1

# Search recent audit events with the key "identity"
EVENTS=$(ausearch -ts recent -k identity 2>/dev/null |
    grep -c "type=SYSCALL" || true)

if [[ "$EVENTS" -gt 0 ]]; then
    echo "    ausearch -ts recent -k identity: $EVENTS event found [PASS]"
else
    echo "    ausearch -ts recent -k identity: no event found [FAIL]"
fi
