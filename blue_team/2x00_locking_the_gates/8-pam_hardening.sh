#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------
# File locations used by PAM on Ubuntu
# ---------------------------------------------------------

# Password quality settings
PWQUALITY="/etc/security/pwquality.conf"

# Account lockout settings
FAILLOCK="/etc/security/faillock.conf"

# PAM authentication rules
AUTH="/etc/pam.d/common-auth"

# PAM account rules
ACCOUNT="/etc/pam.d/common-account"

# PAM password-change rules
PASSWORD="/etc/pam.d/common-password"


# ---------------------------------------------------------
# Check whether libpam-pwquality is installed
# ---------------------------------------------------------

echo "[*] Checking libpam-pwquality..."

# dpkg -s checks whether the package is installed.
# Output is hidden because we only need the exit status.
if dpkg -s libpam-pwquality >/dev/null 2>&1; then

    # Get the installed package version.
    VERSION=$(dpkg-query -W -f='${Version}' libpam-pwquality)

    echo "    Already installed: libpam-pwquality $VERSION"
else
    # Update the package list quietly.
    apt-get update -qq

    # Install the password-quality PAM module.
    apt-get install -y libpam-pwquality

    echo "    Installed: libpam-pwquality"
fi


# ---------------------------------------------------------
# Configure password quality requirements
# ---------------------------------------------------------

echo "[*] Configuring password quality ($PWQUALITY)..."

# Remove old copies of these settings first.
# This prevents duplicate or conflicting lines.
sed -i '
    /^\s*minlen\s*=/d
    /^\s*dcredit\s*=/d
    /^\s*ucredit\s*=/d
    /^\s*lcredit\s*=/d
    /^\s*ocredit\s*=/d
    /^\s*maxrepeat\s*=/d
    /^\s*reject_username/d
' "$PWQUALITY"

# Add the new password-quality settings.
cat >> "$PWQUALITY" <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
reject_username
EOF

# Print the settings that were applied.
echo "    minlen = 14                      [SET]"
echo "    dcredit = -1                     [SET]"
echo "    ucredit = -1                     [SET]"
echo "    lcredit = -1                     [SET]"
echo "    ocredit = -1                     [SET]"
echo "    maxrepeat = 3                    [SET]"
echo "    reject_username                  [SET]"


# ---------------------------------------------------------
# Configure account lockout with pam_faillock
# ---------------------------------------------------------

echo "[*] Configuring account lockout (pam_faillock)..."

# Remove previous faillock values to avoid duplicates.
sed -i '
    /^\s*deny\s*=/d
    /^\s*unlock_time\s*=/d
    /^\s*fail_interval\s*=/d
' "$FAILLOCK"

# Add the new lockout settings.
cat >> "$FAILLOCK" <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Add the pre-authentication faillock rule if it is missing.
# This checks whether the account is already locked.
grep -q "pam_faillock.so preauth" "$AUTH" ||
sed -i '/pam_unix.so/i auth required pam_faillock.so preauth silent' "$AUTH"

# Add the failed-authentication rule if it is missing.
# This records a failed login attempt.
grep -q "pam_faillock.so authfail" "$AUTH" ||
sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail' "$AUTH"

# Add the account-checking rule if it is missing.
# This makes PAM enforce the lockout during account checks.
grep -q "pam_faillock.so" "$ACCOUNT" ||
echo "account required pam_faillock.so" >> "$ACCOUNT"

echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"


# ---------------------------------------------------------
# Configure password history
# ---------------------------------------------------------

echo "[*] Configuring password history..."

# Add pam_pwhistory before pam_unix if it is not already present.
# remember=12 prevents reuse of the previous 12 passwords.
# use_authtok passes the new password to the next PAM module.
grep -q "pam_pwhistory.so" "$PASSWORD" ||
sed -i \
    '/pam_unix.so/i password required pam_pwhistory.so remember=12 use_authtok' \
    "$PASSWORD"

echo "    remember = 12                    [SET]"


# ---------------------------------------------------------
# Validate that the expected settings exist
# ---------------------------------------------------------

# Each grep command checks for one required configuration.
# Because set -e is active, the script stops if a check fails.

grep -q "^minlen = 14" "$PWQUALITY"
grep -q "^deny = 5" "$FAILLOCK"
grep -q "pam_faillock.so" "$AUTH"
grep -q "pam_faillock.so" "$ACCOUNT"
grep -q "pam_pwhistory.so remember=12" "$PASSWORD"


# ---------------------------------------------------------
# Print the final summary
# ---------------------------------------------------------

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
