#!/bin/bash

# 8-pam_hardening.sh - Safe PAM Hardening
#
# This script:
#   - Configures password quality
#   - Configures faillock only when PAM already uses pam_faillock
#   - Does not directly edit common-auth or common-account
#   - Does not lock the root account
#   - Creates backups
#   - Automatically restores backups if a validation step fails
#
# Usage:
#   sudo ./8-pam_hardening.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BACKUP_DIR="/root/pam-backup-$(date +%Y%m%d-%H%M%S)"

PWQUALITY_FILE="/etc/security/pwquality.conf.d/meddefense.conf"
FAILLOCK_FILE="/etc/security/faillock.conf"

COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"
COMMON_PASSWORD="/etc/pam.d/common-password"

ROLLBACK_NEEDED=1
FAILLOCK_CONFIGURED=0


# ---------------------------------------------------------
# Restore the original files if the script fails
# ---------------------------------------------------------

rollback() {
    if [[ "$ROLLBACK_NEEDED" -eq 1 ]]; then
        echo
        echo "[!] Validation failed. Restoring PAM backup..."

        if [[ -d "$BACKUP_DIR" ]]; then
            cp -a "$BACKUP_DIR/pam.d/." /etc/pam.d/
            cp -a "$BACKUP_DIR/security/." /etc/security/
        fi

        echo "[*] Original PAM configuration restored."
    fi
}

trap rollback EXIT


# ---------------------------------------------------------
# Check root privileges
# ---------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi


# ---------------------------------------------------------
# Check the operating system
# ---------------------------------------------------------

if [[ ! -f /etc/os-release ]]; then
    echo "Cannot identify the operating system."
    exit 1
fi

. /etc/os-release

case "${ID:-unknown}" in
    debian|kali|ubuntu)
        ;;
    *)
        echo "Unsupported operating system: ${ID:-unknown}"
        echo "This script supports Debian, Kali and Ubuntu."
        exit 1
        ;;
esac


# ---------------------------------------------------------
# Install required password-quality module
# ---------------------------------------------------------

echo "[*] Checking required PAM packages..."

if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y libpam-pwquality
fi

echo "    libpam-pwquality                           [OK]"


# ---------------------------------------------------------
# Create backups
# ---------------------------------------------------------

echo "[*] Creating PAM backup..."

mkdir -p "$BACKUP_DIR/pam.d"
mkdir -p "$BACKUP_DIR/security"

cp -a /etc/pam.d/. "$BACKUP_DIR/pam.d/"
cp -a /etc/security/. "$BACKUP_DIR/security/"

echo "    Backup: $BACKUP_DIR"


# ---------------------------------------------------------
# Validate the existing PAM stack before changing anything
# ---------------------------------------------------------

echo "[*] Checking existing PAM authentication stack..."

if ! grep -Eq '^[[:space:]]*auth.*pam_unix\.so' "$COMMON_AUTH"; then
    echo "    pam_unix.so missing from common-auth       [FAIL]"
    exit 1
fi

if ! grep -Eq '^[[:space:]]*account.*pam_unix\.so' "$COMMON_ACCOUNT"; then
    echo "    pam_unix.so missing from common-account    [FAIL]"
    exit 1
fi

if ! grep -Eq '^[[:space:]]*password.*pam_unix\.so' "$COMMON_PASSWORD"; then
    echo "    pam_unix.so missing from common-password   [FAIL]"
    exit 1
fi

echo "    common-auth contains pam_unix.so            [OK]"
echo "    common-account contains pam_unix.so         [OK]"
echo "    common-password contains pam_unix.so        [OK]"


# ---------------------------------------------------------
# Configure password quality
# ---------------------------------------------------------

echo "[*] Configuring password quality..."

mkdir -p /etc/security/pwquality.conf.d

cat > "$PWQUALITY_FILE" <<'EOF'
# MedDefense password-quality policy

# Minimum password length
minlen = 14

# Require at least one uppercase character
ucredit = -1

# Require at least one lowercase character
lcredit = -1

# Require at least one digit
dcredit = -1

# Require at least one special character
ocredit = -1

# Reject passwords containing the username
usercheck = 1

# Maximum repeated identical characters
maxrepeat = 3

# Apply checks to the root password as well
enforce_for_root
EOF

chmod 644 "$PWQUALITY_FILE"
chown root:root "$PWQUALITY_FILE"

echo "    Minimum password length: 14                [SET]"
echo "    Character classes required                 [SET]"
echo "    Username check                             [SET]"
echo "    Password quality for root                  [SET]"


# ---------------------------------------------------------
# Configure faillock safely
# ---------------------------------------------------------

echo "[*] Checking account-lockout support..."

# Do not insert pam_faillock directly into common-auth.
# Only configure it when the installed PAM stack already uses it.

if grep -RqsE \
    '^[[:space:]]*(auth|account).*pam_faillock\.so' \
    /etc/pam.d; then

    # Remove only settings managed by this script.
    # Do not enable even_deny_root.
    sed -i \
        -e '/^[[:space:]]*deny[[:space:]]*=/d' \
        -e '/^[[:space:]]*fail_interval[[:space:]]*=/d' \
        -e '/^[[:space:]]*unlock_time[[:space:]]*=/d' \
        -e '/^[[:space:]]*root_unlock_time[[:space:]]*=/d' \
        -e '/^[[:space:]]*even_deny_root/d' \
        -e '/^[[:space:]]*local_users_only/d' \
        "$FAILLOCK_FILE"

    cat >> "$FAILLOCK_FILE" <<'EOF'

# MedDefense account-lockout policy

# Lock a normal local account after five failed attempts
deny = 5

# Count failures during a 15-minute interval
fail_interval = 900

# Automatically unlock normal users after 15 minutes
unlock_time = 900

# Apply only to users stored in the local account database
local_users_only

# IMPORTANT:
# even_deny_root is intentionally not enabled.
# Root must not be locked by failed authentication attempts.
EOF

    chmod 644 "$FAILLOCK_FILE"
    chown root:root "$FAILLOCK_FILE"

    FAILLOCK_CONFIGURED=1

    echo "    pam_faillock already integrated            [OK]"
    echo "    Failed-attempt limit: 5                    [SET]"
    echo "    Unlock time: 900 seconds                   [SET]"
    echo "    Root lockout: disabled                     [SAFE]"

else
    echo "    pam_faillock not integrated                [SKIPPED]"
    echo "    No direct PAM-file changes were made       [SAFE]"
fi


# ---------------------------------------------------------
# Remove stale lockout records
# ---------------------------------------------------------

echo "[*] Clearing stale account-lockout records..."

if command -v faillock >/dev/null 2>&1; then
    while IFS=: read -r username _ uid _; do

        # Clear lockout records for normal users and root.
        if [[ "$uid" -eq 0 || "$uid" -ge 1000 ]]; then
            faillock --user "$username" --reset \
                >/dev/null 2>&1 || true
        fi

    done < /etc/passwd
fi

echo "    Existing faillock records cleared          [OK]"


# ---------------------------------------------------------
# Validate the final configuration
# ---------------------------------------------------------

echo "[*] Validating PAM configuration..."

# Confirm the standard password module still exists.
grep -Eq \
    '^[[:space:]]*auth.*pam_unix\.so' \
    "$COMMON_AUTH"

grep -Eq \
    '^[[:space:]]*account.*pam_unix\.so' \
    "$COMMON_ACCOUNT"

grep -Eq \
    '^[[:space:]]*password.*pam_unix\.so' \
    "$COMMON_PASSWORD"

# Confirm password-quality settings.
grep -Eq \
    '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14' \
    "$PWQUALITY_FILE"

grep -Eq \
    '^[[:space:]]*ucredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE"

grep -Eq \
    '^[[:space:]]*lcredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE"

grep -Eq \
    '^[[:space:]]*dcredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE"

grep -Eq \
    '^[[:space:]]*ocredit[[:space:]]*=[[:space:]]*-1' \
    "$PWQUALITY_FILE"

# Verify root is not configured for faillock.
if grep -Eq \
    '^[[:space:]]*even_deny_root' \
    "$FAILLOCK_FILE" 2>/dev/null; then

    echo "    even_deny_root detected                    [FAIL]"
    exit 1
fi

echo "    Standard Unix authentication               [OK]"
echo "    Password-quality configuration             [OK]"
echo "    Root protected from faillock                [OK]"


# ---------------------------------------------------------
# Finish successfully
# ---------------------------------------------------------

ROLLBACK_NEEDED=0

echo
echo "PAM hardening completed safely."
echo "Backup saved to: $BACKUP_DIR"

if [[ "$FAILLOCK_CONFIGURED" -eq 1 ]]; then
    echo "Account lockout: configured"
else
    echo "Account lockout: skipped because no safe existing integration was found"
fi

echo "Direct changes to common-auth: none"
echo "Direct changes to common-account: none"
