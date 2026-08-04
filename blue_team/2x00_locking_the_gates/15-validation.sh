#!/bin/bash

# 15-validation.sh - Post-Hardening Validator
# Read-only validation of security controls from Tasks 4-13.
#
# This script does not change the system.
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed
#
# Usage:
#   sudo ./15-validation.sh
# ============================================================================

set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0


# ---------------------------------------------------------
# Print a PASS result
# ---------------------------------------------------------

pass() {
    echo "[PASS] $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}


# ---------------------------------------------------------
# Print a FAIL result
# ---------------------------------------------------------

fail() {
    echo "[FAIL] $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}


# ---------------------------------------------------------
# Compare an actual value with an expected value
# ---------------------------------------------------------

check_value() {
    local name="$1"
    local actual="$2"
    local expected="$3"

    if [[ "$actual" == "$expected" ]]; then
        pass "$name = $actual"
    else
        fail "$name = ${actual:-not found} (expected: $expected)"
    fi
}


# ---------------------------------------------------------
# Read the effective SSH setting
# ---------------------------------------------------------

get_sshd_setting() {
    local setting="$1"

    sshd -T 2>/dev/null |
        awk -v key="$setting" '
            tolower($1) == tolower(key) {
                print $2
                exit
            }
        '
}


# ---------------------------------------------------------
# Read a sysctl value
# ---------------------------------------------------------

get_sysctl_value() {
    local key="$1"

    sysctl -n "$key" 2>/dev/null || echo "not found"
}


# ---------------------------------------------------------
# Check whether a service is active
# ---------------------------------------------------------

check_service_active() {
    local service="$1"
    local state

    state=$(systemctl is-active "$service" 2>/dev/null || true)

    check_value "$service" "$state" "active"
}


# ---------------------------------------------------------
# Check file ownership and permissions
# ---------------------------------------------------------

check_file_permissions() {
    local file="$1"
    local expected="$2"
    local actual

    if [[ ! -e "$file" ]]; then
        fail "$file = missing (expected: $expected)"
        return
    fi

    actual=$(stat -c '%a %U:%G' "$file" 2>/dev/null || echo "unknown")

    check_value "$file permissions" "$actual" "$expected"
}


# ---------------------------------------------------------
# Check whether a UFW rule exists
# ---------------------------------------------------------

check_ufw_rule() {
    local description="$1"
    local pattern="$2"

    if ufw status 2>/dev/null | grep -Eq "$pattern"; then
        pass "$description"
    else
        fail "$description (expected rule not found)"
    fi
}


echo "============================================================"
echo "MedDefense Post-Hardening Validation"
echo "============================================================"


# =========================================================
# Task 4 - SSH hardening
# =========================================================

echo
echo "[*] Validating SSH hardening..."

check_value \
    "PermitRootLogin" \
    "$(get_sshd_setting permitrootlogin)" \
    "no"

check_value \
    "PasswordAuthentication" \
    "$(get_sshd_setting passwordauthentication)" \
    "no"

check_value \
    "PermitEmptyPasswords" \
    "$(get_sshd_setting permitemptypasswords)" \
    "no"

check_value \
    "X11Forwarding" \
    "$(get_sshd_setting x11forwarding)" \
    "no"

check_value \
    "MaxAuthTries" \
    "$(get_sshd_setting maxauthtries)" \
    "3"

check_value \
    "ClientAliveInterval" \
    "$(get_sshd_setting clientaliveinterval)" \
    "300"

check_value \
    "ClientAliveCountMax" \
    "$(get_sshd_setting clientalivecountmax)" \
    "2"

check_value \
    "LoginGraceTime" \
    "$(get_sshd_setting logingracetime)" \
    "60"

check_value \
    "Banner" \
    "$(get_sshd_setting banner)" \
    "/etc/issue.net"

check_value \
    "AllowUsers" \
    "$(get_sshd_setting allowusers)" \
    "medadmin sysadmin"


# =========================================================
# Task 5 - sysctl hardening
# =========================================================

echo
echo "[*] Validating kernel and network hardening..."

check_value \
    "net.ipv4.ip_forward" \
    "$(get_sysctl_value net.ipv4.ip_forward)" \
    "0"

check_value \
    "net.ipv4.conf.all.send_redirects" \
    "$(get_sysctl_value net.ipv4.conf.all.send_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.default.send_redirects" \
    "$(get_sysctl_value net.ipv4.conf.default.send_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.all.accept_redirects" \
    "$(get_sysctl_value net.ipv4.conf.all.accept_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.default.accept_redirects" \
    "$(get_sysctl_value net.ipv4.conf.default.accept_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.all.secure_redirects" \
    "$(get_sysctl_value net.ipv4.conf.all.secure_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.default.secure_redirects" \
    "$(get_sysctl_value net.ipv4.conf.default.secure_redirects)" \
    "0"

check_value \
    "net.ipv4.conf.all.accept_source_route" \
    "$(get_sysctl_value net.ipv4.conf.all.accept_source_route)" \
    "0"

check_value \
    "net.ipv4.conf.default.accept_source_route" \
    "$(get_sysctl_value net.ipv4.conf.default.accept_source_route)" \
    "0"

check_value \
    "net.ipv4.conf.all.log_martians" \
    "$(get_sysctl_value net.ipv4.conf.all.log_martians)" \
    "1"

check_value \
    "net.ipv4.conf.default.log_martians" \
    "$(get_sysctl_value net.ipv4.conf.default.log_martians)" \
    "1"

check_value \
    "net.ipv4.icmp_echo_ignore_broadcasts" \
    "$(get_sysctl_value net.ipv4.icmp_echo_ignore_broadcasts)" \
    "1"

check_value \
    "net.ipv4.icmp_ignore_bogus_error_responses" \
    "$(get_sysctl_value net.ipv4.icmp_ignore_bogus_error_responses)" \
    "1"

check_value \
    "net.ipv4.tcp_syncookies" \
    "$(get_sysctl_value net.ipv4.tcp_syncookies)" \
    "1"

check_value \
    "kernel.randomize_va_space" \
    "$(get_sysctl_value kernel.randomize_va_space)" \
    "2"

check_value \
    "fs.suid_dumpable" \
    "$(get_sysctl_value fs.suid_dumpable)" \
    "0"


# =========================================================
# Task 6 - Filesystem hardening
# =========================================================

echo
echo "[*] Validating filesystem hardening..."

for mount_point in /tmp /var/tmp /dev/shm; do

    mount_options=$(findmnt -n -o OPTIONS "$mount_point" 2>/dev/null || true)

    if [[ -z "$mount_options" ]]; then
        fail "$mount_point mount options = not found"
        continue
    fi

    for required_option in nodev nosuid noexec; do
        if echo "$mount_options" |
            tr ',' '\n' |
            grep -qx "$required_option"; then

            pass "$mount_point contains $required_option"
        else
            fail "$mount_point missing $required_option"
        fi
    done
done

check_file_permissions "/etc/crontab" "600 root:root"

for cron_directory in \
    /etc/cron.hourly \
    /etc/cron.daily \
    /etc/cron.weekly \
    /etc/cron.monthly \
    /etc/cron.d
do
    check_file_permissions "$cron_directory" "700 root:root"
done


# =========================================================
# Task 7 - Service minimization
# =========================================================

echo
echo "[*] Validating unnecessary services..."

UNWANTED_SERVICES=(
    avahi-daemon
    cups
    rpcbind
    telnet
    rsh
    rexec
    vsftpd
)

for service in "${UNWANTED_SERVICES[@]}"; do

    state=$(systemctl is-enabled "$service" 2>/dev/null || true)

    if [[ "$state" == "enabled" ]]; then
        fail "$service = enabled (expected: disabled or absent)"
    else
        pass "$service = disabled or absent"
    fi
done


# =========================================================
# Task 8 - PAM hardening
# =========================================================

echo
echo "[*] Validating PAM hardening..."

if grep -Rqs "pam_pwquality.so" \
    /etc/pam.d/common-password \
    /etc/pam.d 2>/dev/null; then

    pass "pam_pwquality.so = configured"
else
    fail "pam_pwquality.so = not configured"
fi

if grep -Rqs "pam_faillock.so" /etc/pam.d 2>/dev/null; then
    pass "pam_faillock.so = configured"
else
    fail "pam_faillock.so = not configured"
fi

if [[ -f /etc/security/pwquality.conf ]]; then

    MINLEN=$(
        awk -F= '
            /^[[:space:]]*minlen[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                print $2
                exit
            }
        ' /etc/security/pwquality.conf
    )

    check_value "Password minimum length" "$MINLEN" "14"
else
    fail "/etc/security/pwquality.conf = missing"
fi


# =========================================================
# Task 9 - AppArmor
# =========================================================

echo
echo "[*] Validating AppArmor..."

check_service_active "apparmor.service"

if command -v aa-status >/dev/null 2>&1; then

    if aa-status --enabled >/dev/null 2>&1; then
        pass "AppArmor = enabled"
    else
        fail "AppArmor = disabled"
    fi
else
    fail "aa-status command = missing"
fi


# =========================================================
# Task 10 and 11 - Auditd
# =========================================================

echo
echo "[*] Validating auditd..."

check_service_active "auditd.service"

AUDIT_RULES_FILE="/etc/audit/rules.d/meddefense.rules"

if [[ -f "$AUDIT_RULES_FILE" ]]; then
    pass "$AUDIT_RULES_FILE = present"
else
    fail "$AUDIT_RULES_FILE = missing"
fi

AUDIT_PATTERNS=(
    "/etc/passwd"
    "/etc/group"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/cron.d"
)

for pattern in "${AUDIT_PATTERNS[@]}"; do

    if auditctl -l 2>/dev/null |
        grep -Fq "$pattern"; then

        pass "Audit rule for $pattern = loaded"
    else
        fail "Audit rule for $pattern = not loaded"
    fi
done


# =========================================================
# Task 12 - rsyslog and log rotation
# =========================================================

echo
echo "[*] Validating logging..."

check_service_active "rsyslog.service"

check_file_permissions "/var/log/auth.log" "640 root:adm"
check_file_permissions "/var/log/syslog" "640 root:adm"

if grep -RqsE 'auth,authpriv\.\*.*\/var\/log\/auth\.log' \
    /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then

    pass "auth events route to /var/log/auth.log"
else
    fail "auth events route to /var/log/auth.log = missing"
fi

if grep -RqsE '\*\.info;.*auth.*none.*\/var\/log\/syslog' \
    /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then

    pass "system events route to /var/log/syslog"
else
    fail "system events route to /var/log/syslog = missing"
fi

LOGROTATE_FILE="/etc/logrotate.d/meddefense"

if [[ -f "$LOGROTATE_FILE" ]]; then
    pass "$LOGROTATE_FILE = present"
else
    fail "$LOGROTATE_FILE = missing"
fi

if grep -A12 "/var/log/auth.log" "$LOGROTATE_FILE" 2>/dev/null |
    grep -Eq '^[[:space:]]*rotate[[:space:]]+90'; then

    pass "auth.log retention = 90 rotations"
else
    fail "auth.log retention (expected: 90 rotations)"
fi

if grep -A12 "/var/log/syslog" "$LOGROTATE_FILE" 2>/dev/null |
    grep -Eq '^[[:space:]]*rotate[[:space:]]+60'; then

    pass "syslog retention = 60 rotations"
else
    fail "syslog retention (expected: 60 rotations)"
fi


# =========================================================
# Task 13 - UFW firewall
# =========================================================

echo
echo "[*] Validating firewall..."

UFW_STATUS=$(ufw status 2>/dev/null |
    awk -F': ' '/^Status:/ {print $2}')

check_value "UFW status" "$UFW_STATUS" "active"

DEFAULT_INCOMING=$(
    ufw status verbose 2>/dev/null |
    awk '
        /^Default:/ {
            value=$2
            gsub(/[(),]/, "", value)
            print value
            exit
        }
    '
)

check_value "Default incoming" "$DEFAULT_INCOMING" "deny"

DEFAULT_OUTGOING=$(
    ufw status verbose 2>/dev/null |
    awk '
        /^Default:/ {
            value=$3
            gsub(/[(),]/, "", value)
            print value
            exit
        }
    '
)

check_value "Default outgoing" "$DEFAULT_OUTGOING" "allow"

LOGGING_STATUS=$(
    ufw status verbose 2>/dev/null |
    awk -F': ' '/^Logging:/ {print $2}' |
    awk '{print $1}'
)

check_value "UFW logging" "$LOGGING_STATUS" "on"

check_ufw_rule \
    "SSH from 10.10.1.0/24 = allowed" \
    '22/tcp.*ALLOW.*10\.10\.1\.0/24'

check_ufw_rule \
    "HTTP port 80 = allowed" \
    '80/tcp.*ALLOW'

check_ufw_rule \
    "HTTPS port 443 = allowed" \
    '443/tcp.*ALLOW'

check_ufw_rule \
    "MySQL from 10.10.2.0/24 = allowed" \
    '3306/tcp.*ALLOW.*10\.10\.2\.0/24'


# =========================================================
# Final result
# =========================================================

echo
echo "============================================================"
echo "Validation Summary"
echo "============================================================"
echo "Controls passed: $PASS_COUNT"
echo "Controls failed: $FAIL_COUNT"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "Overall result: PASS"
    exit 0
else
    echo "Overall result: FAIL"
    exit 1
fi
