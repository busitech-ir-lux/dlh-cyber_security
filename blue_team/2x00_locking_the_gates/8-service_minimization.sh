#!/bin/bash

# 8-pam_hardening.sh - Safe PAM Fortress
#
# Configures:
#   - Password quality
#   - Account lockout
#   - Password history
#
# Designed for Ubuntu Server.
# Creates backups before modifying PAM files.
#
# Usage:
#   sudo ./8-pam_hardening.sh
# ============================================================================

set -euo pipefail

BACKUP_DIR="/root/pam-backup-$(date +%Y%m%d-%H%M%S)"

PWQUALITY_FILE="/etc/security/pwquality.conf"
FAILLOCK_FILE="/etc/security/faillock.conf"
PWHISTORY_FILE="/etc/security/pwhistory.conf"

COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"
COMMON_PASSWORD="/etc/pam.d/common-password"


# ---------------------------------------------------------
# Check root
# ---------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi


# ---------------------------------------------------------
# Install libpam-pwquality
# ---------------------------------------------------------

echo "[*] Checking libpam-pwquality..."

if dpkg -s libpam-pwquality >/dev/null 2>&1; then
    VERSION=$(dpkg-query -W -f='${Version}' libpam-pwquality)
    echo "    Already installed: libpam-pwquality $VERSION"
else
    apt-get update -qq
    apt-get install -y libpam-pwquality
    echo "    Installed: libpam-pwquality"
fi


# ---------------------------------------------------------
# Backup PAM configuration
# ---------------------------------------------------------

echo "[*] Creating PAM backup..."

mkdir -p "$BACKUP_DIR"

cp -a /etc/pam.d "$BACKUP_DIR/"
cp -a /etc/security "$BACKUP_DIR/"

echo "    Backup saved: $BACKUP_DIR"


# ---------------------------------------------------------
# Password quality
# ---------------------------------------------------------

echo "[*] Configuring password quality (/etc/security/pwquality.conf)..."

# Remove old values first so rerunning the script is safe
sed -i \
    -e '/^[[:space:]]*minlen[[:space:]]*=/d' \
    -e '/^[[:space:]]*dcredit[[:space:]]*=/d' \
    -e '/^[[:space:]]*ucredit[[:space:]]*=/d' \
    -e '/^[[:space:]]*lcredit[[:space:]]*=/d' \
    -e '/^[[:space:]]*ocredit[[:space:]]*=/d' \
    -e '/^[[:space:]]*maxrepeat[[:space:]]*=/d' \
    -e '/^[[:space:]]*usercheck[[:space:]]*=/d' \
    "$PWQUALITY_FILE"

cat >> "$PWQUALITY_FILE" <<'EOF'

# MedDefense password policy
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
EOF

echo "    minlen = 14                      [SET]"
echo "    dcredit = -1                     [SET]"
echo "    ucredit = -1                     [SET]"
echo "    lcredit = -1                     [SET]"
echo "    ocredit = -1                     [SET]"
echo "    maxrepeat = 3                    [SET]"
echo "    reject_username                  [SET]"

# ---------------------------------------------------------
# Account lockout
# ---------------------------------------------------------

echo "[*] Configuring account lockout (pam_faillock)..."

touch "$FAILLOCK_FILE"

sed -i \
    -e '/^[[:space:]]*deny[[:space:]]*=/d' \
    -e '/^[[:space:]]*unlock_time[[:space:]]*=/d' \
    -e '/^[[:space:]]*fail_interval[[:space:]]*=/d' \
    -e '/^[[:space:]]*even_deny_root/d' \
    "$FAILLOCK_FILE"

cat >> "$FAILLOCK_FILE" <<'EOF'

# MedDefense account lockout
deny = 5
unlock_time = 900
fail_interval = 900
EOF

echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"


# ---------------------------------------------------------
# Integrate pam_faillock only if not already present
# ---------------------------------------------------------

if ! grep -q "pam_faillock.so.*preauth" "$COMMON_AUTH"; then

    # Insert preauth before pam_unix authentication
    sed -i \
        '/pam_unix.so/i auth required pam_faillock.so preauth' \
        "$COMMON_AUTH"
fi


if ! grep -q "pam_faillock.so.*authfail" "$COMMON_AUTH"; then

    # Insert authfail after pam_unix
    sed -i \
        '/pam_unix.so/a auth [default=die] pam_faillock.so authfail' \
        "$COMMON_AUTH"
fi


if ! grep -q "pam_faillock.so" "$COMMON_ACCOUNT"; then

    echo "account required pam_faillock.so" >> "$COMMON_ACCOUNT"
fi

# ---------------------------------------------------------
# Password history
# ---------------------------------------------------------

echo "[*] Configuring password history..."

touch "$PWHISTORY_FILE"

sed -i \
    '/^[[:space:]]*remember[[:space:]]*=/d' \
    "$PWHISTORY_FILE"

echo "remember = 12" >> "$PWHISTORY_FILE"


# Add pam_pwhistory only if it is not already configured
if ! grep -q "pam_pwhistory.so" "$COMMON_PASSWORD"; then

    # Put history checking before pam_unix changes the password
    sed -i \
        '/pam_unix.so/i password required pam_pwhistory.so use_authtok' \
        "$COMMON_PASSWORD"
fi

echo "    remember = 12                    [SET]"

# ---------------------------------------------------------
# Validate configuration
# ---------------------------------------------------------

echo "[*] Validating PAM configuration..."

FAILED=0


# Check pwquality
grep -Eq '^minlen[[:space:]]*=[[:space:]]*14' \
    "$PWQUALITY_FILE" || FAILED=1

grep -Eq '^dcredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE" || FAILED=1

grep -Eq '^ucredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE" || FAILED=1

grep -Eq '^lcredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE" || FAILED=1

grep -Eq '^ocredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE" || FAILED=1


# Check faillock settings
grep -Eq '^deny[[:space:]]*=[[:space:]]*5' \
    "$FAILLOCK_FILE" || FAILED=1

grep -Eq '^unlock_time[[:space:]]*=[[:space:]]*900' \
    "$FAILLOCK_FILE" || FAILED=1

grep -Eq '^fail_interval[[:space:]]*=[[:space:]]*900' \
    "$FAILLOCK_FILE" || FAILED=1


# Check PAM integration
grep -q "pam_faillock.so.*preauth" \
    "$COMMON_AUTH" || FAILED=1

grep -q "pam_faillock.so.*authfail" \
    "$COMMON_AUTH" || FAILED=1

grep -q "pam_faillock.so" \
    "$COMMON_ACCOUNT" || FAILED=1


# Check password history
grep -Eq '^remember[[:space:]]*=[[:space:]]*12' \
    "$PWHISTORY_FILE" || FAILED=1

grep -q "pam_pwhistory.so" \
    "$COMMON_PASSWORD" || FAILED=1


# Make sure root lockout was NOT enabled
if grep -Eq '^[[:space:]]*even_deny_root' "$FAILLOCK_FILE"; then
    echo "    even_deny_root detected           [FAIL]"
    FAILED=1
fi


# ---------------------------------------------------------
# Roll back automatically if validation fails
# ---------------------------------------------------------

if [[ "$FAILED" -ne 0 ]]; then

    echo
    echo "[!] PAM validation failed."
    echo "[!] Restoring original configuration..."

    rm -rf /etc/pam.d
    cp -a "$BACKUP_DIR/pam.d" /etc/

    rm -rf /etc/security
    cp -a "$BACKUP_DIR/security" /etc/

    echo "[*] Rollback complete."
    exit 1
fi


echo
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
echo "Backup saved to: $BACKUP_DIR"


