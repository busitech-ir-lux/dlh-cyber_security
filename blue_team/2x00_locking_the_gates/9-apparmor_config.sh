#!/bin/bash
set -euo pipefail

# AppArmor profile directory
PROFILE_DIR="/etc/apparmor.d"

# Custom MedDefense application
APP="/opt/meddefense/billing-app"
CUSTOM_PROFILE="$PROFILE_DIR/opt.meddefense.billing-app"

echo "[*] Checking AppArmor status..."

# Check that AppArmor commands are installed
if ! command -v aa-status >/dev/null 2>&1; then
    echo "    AppArmor is not installed."
    exit 1
fi

# Check whether the AppArmor kernel module is loaded
if [[ -d /sys/module/apparmor ]]; then
    echo "    AppArmor module: loaded"
else
    echo "    AppArmor module: not loaded"
    exit 1
fi

# Check whether the AppArmor service is running
if systemctl is-active --quiet apparmor; then
    echo "    AppArmor service: active"
else
    echo "    AppArmor service: inactive"
    exit 1
fi


# ---------------------------------------------------------
# List current AppArmor profiles and their status
# ---------------------------------------------------------

echo "[*] Current AppArmor profiles:"

# aa-status displays loaded profiles and their modes
aa-status


# ---------------------------------------------------------
# Change Apache and MySQL profiles to enforce mode
# ---------------------------------------------------------

echo "[*] Profile enforcement:"

# Apache profile normally uses this filename
APACHE_PROFILE="$PROFILE_DIR/usr.sbin.apache2"

if [[ -f "$APACHE_PROFILE" ]]; then
    aa-enforce "$APACHE_PROFILE" >/dev/null
    printf "    %-28s [ENFORCED]\n" "/usr/sbin/apache2"
else
    printf "    %-28s [PROFILE NOT FOUND]\n" "/usr/sbin/apache2"
fi

# MySQL profile normally uses this filename
MYSQL_PROFILE="$PROFILE_DIR/usr.sbin.mysqld"

if [[ -f "$MYSQL_PROFILE" ]]; then
    aa-enforce "$MYSQL_PROFILE" >/dev/null
    printf "    %-28s [ENFORCED]\n" "/usr/sbin/mysqld"
else
    printf "    %-28s [PROFILE NOT FOUND]\n" "/usr/sbin/mysqld"
fi


# ---------------------------------------------------------
# Create directories required by the MedDefense application
# ---------------------------------------------------------

mkdir -p /opt/meddefense
mkdir -p /var/log/meddefense
mkdir -p /run/meddefense


# ---------------------------------------------------------
# Create a custom AppArmor profile
# ---------------------------------------------------------

echo "[*] Creating custom MedDefense profile..."

cat > "$CUSTOM_PROFILE" <<'EOF'
#include <tunables/global>

/opt/meddefense/billing-app {
    # Basic files required by most Linux applications
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # Allow the application itself to run
    /opt/meddefense/billing-app rix,

    # Allow read-only access to application files
    /opt/meddefense/** r,

    # Allow the application to write its own logs
    /var/log/meddefense/ rw,
    /var/log/meddefense/** rw,

    # Allow runtime files such as PID and socket files
    /run/meddefense/ rw,
    /run/meddefense/** rw,

    # Allow IPv4 and IPv6 network connections
    network inet stream,
    network inet6 stream,
}
EOF


# ---------------------------------------------------------
# Load the custom profile into AppArmor
# ---------------------------------------------------------

# -r means replace the profile if it is already loaded
apparmor_parser -r "$CUSTOM_PROFILE"

# Make sure the custom profile is in enforce mode
aa-enforce "$CUSTOM_PROFILE" >/dev/null

printf "    %-38s [CREATED] [ENFORCED]\n" "$APP"


# ---------------------------------------------------------
# Report unconfined processes
# ---------------------------------------------------------

echo "[*] Unconfined processes:"

# aa-unconfined lists running processes that are not
# protected by an AppArmor profile
if command -v aa-unconfined >/dev/null 2>&1; then
    aa-unconfined 2>/dev/null || true
else
    echo "    aa-unconfined command is not installed"
fi


# ---------------------------------------------------------
# Count profile modes
# ---------------------------------------------------------

# aa-status --json is not available on every Ubuntu version,
# so this reads the normal aa-status summary.

ENFORCE=$(aa-status | awk '/profiles are in enforce mode/ {print $1}')
COMPLAIN=$(aa-status | awk '/profiles are in complain mode/ {print $1}')

# Use zero if no number was returned
ENFORCE=${ENFORCE:-0}
COMPLAIN=${COMPLAIN:-0}

# Count lines reported by aa-unconfined
if command -v aa-unconfined >/dev/null 2>&1; then
    UNCONFINED=$(aa-unconfined 2>/dev/null | grep -c . || true)
else
    UNCONFINED=0
fi

echo "Profiles in enforce: $ENFORCE | Complain: $COMPLAIN | Unconfined: $UNCONFINED"
