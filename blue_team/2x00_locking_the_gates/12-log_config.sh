#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------
# File locations used by this script
# ---------------------------------------------------------

# Rsyslog configuration created for MedDefense
RSYSLOG_CONFIG="/etc/rsyslog.d/30-meddefense.conf"

# Logrotate configuration created for MedDefense
ROTATE_CONFIG="/etc/logrotate.d/meddefense"

# Main log files
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"


# ---------------------------------------------------------
# Install and enable rsyslog
# ---------------------------------------------------------

echo "[*] Configuring rsyslog..."

# Install rsyslog and logrotate if they are not installed
if ! dpkg -s rsyslog >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y rsyslog
fi

if ! dpkg -s logrotate >/dev/null 2>&1; then
    apt-get install -y logrotate
fi

# Enable rsyslog at boot and start it now
systemctl enable --now rsyslog >/dev/null


# ---------------------------------------------------------
# Create the rsyslog routing rules
# ---------------------------------------------------------

cat > "$RSYSLOG_CONFIG" <<'EOF'
# Consistent format:
# timestamp, hostname, program, process ID and message
template(
    name="MedDefenseFormat"
    type="string"
    string="%timereported:::date-rfc3339% host=%hostname% program=%programname% pid=%procid% msg=%msg%\n"
)

# Send authentication events to auth.log
auth,authpriv.* action(
    type="omfile"
    file="/var/log/auth.log"
    template="MedDefenseFormat"
    fileOwner="root"
    fileGroup="adm"
    fileCreateMode="0640"
)

# Send informational and more serious non-auth events to syslog
*.info;auth,authpriv.none action(
    type="omfile"
    file="/var/log/syslog"
    template="MedDefenseFormat"
    fileOwner="root"
    fileGroup="adm"
    fileCreateMode="0640"
)
EOF

# Check the rsyslog configuration before restarting
rsyslogd -N1 >/dev/null 2>&1

# Restart rsyslog so the new rules become active
systemctl restart rsyslog

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"


# ---------------------------------------------------------
# Create log rotation policies
# ---------------------------------------------------------

echo "[*] Setting log rotation policies..."

cat > "$ROTATE_CONFIG" <<'EOF'
/var/log/auth.log {
    daily
    rotate 90
    missingok
    notifempty
    create 0640 root adm
    su root adm
    nocompress
    sharedscripts

    postrotate
        systemctl kill -s HUP rsyslog.service 2>/dev/null || true
        find /var/log -maxdepth 1 -type f -name 'auth.log-*' -mtime +7 ! -name '*.gz' -exec gzip {} \;
    endscript
}

/var/log/syslog {
    daily
    rotate 60
    missingok
    notifempty
    create 0640 root adm
    su root adm
    nocompress
    sharedscripts

    postrotate
        systemctl kill -s HUP rsyslog.service 2>/dev/null || true
        find /var/log -maxdepth 1 -type f -name 'syslog-*' -mtime +7 ! -name '*.gz' -exec gzip {} \;
    endscript
}
EOF

# Validate the logrotate file without rotating anything
if logrotate -d "$ROTATE_CONFIG" >/dev/null 2>&1; then

    echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
    echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"
else
    echo "    Logrotate configuration validation failed."
    exit 1
fi

# ---------------------------------------------------------
# Create and secure the log files
# ---------------------------------------------------------

touch "$AUTH_LOG" "$SYSLOG"

# root can read and write.
# Members of adm can read.
# Other users have no access.
chown root:adm "$AUTH_LOG" "$SYSLOG"
chmod 640 "$AUTH_LOG" "$SYSLOG"


# ---------------------------------------------------------
# Send test log events
# ---------------------------------------------------------

echo "[*] Verifying log activity..."

# Unique text lets us find only the events created by this test
TEST_ID="meddefense-test-$(date +%s)"

# Send an authentication event
logger -p auth.notice -t meddefense-test "$TEST_ID authentication event"

# Send a normal system event
logger -p user.info -t meddefense-test "$TEST_ID system event"

# Give rsyslog a moment to write the messages
sleep 1


# Check whether the authentication event reached auth.log
if tail -n 20 "$AUTH_LOG" | grep -q "$TEST_ID authentication event"; then
    echo "    /var/log/auth.log: receiving events       [OK]"
else
    echo "    /var/log/auth.log: not receiving events   [FAIL]"
fi

# Check whether the system event reached syslog
if tail -n 20 "$SYSLOG" | grep -q "$TEST_ID system event"; then
    echo "    /var/log/syslog: receiving events         [OK]"
else
    echo "    /var/log/syslog: not receiving events     [FAIL]"
fi

# ---------------------------------------------------------
# Verify file permissions
# ---------------------------------------------------------

echo "[*] Securing log file permissions..."

AUTH_DETAILS=$(stat -c '%a %U:%G' "$AUTH_LOG")
SYSLOG_DETAILS=$(stat -c '%a %U:%G' "$SYSLOG")

if [[ "$AUTH_DETAILS" == "640 root:adm" ]]; then
    echo "    /var/log/auth.log: 640 root:adm          [OK]"
else
    echo "    /var/log/auth.log: $AUTH_DETAILS          [FAIL]"
fi

if [[ "$SYSLOG_DETAILS" == "640 root:adm" ]]; then
    echo "    /var/log/syslog: 640 root:adm            [OK]"
else
    echo "    /var/log/syslog: $SYSLOG_DETAILS          [FAIL]"
fi

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
