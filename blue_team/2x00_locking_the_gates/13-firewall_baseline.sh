#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------
# Network ranges allowed to access restricted services
# ---------------------------------------------------------

# Only administrators from this network may use SSH
MANAGEMENT_NET="10.10.1.0/24"

# Only application servers from this network may use MySQL
APPLICATION_NET="10.10.2.0/24"


# ---------------------------------------------------------
# Install UFW if it is missing
# ---------------------------------------------------------

echo "[*] Configuring UFW..."

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y ufw
fi


# ---------------------------------------------------------
# Remove existing UFW rules
# ---------------------------------------------------------

# Reset removes old rules so the final ruleset is predictable.
# --force prevents UFW from asking for confirmation.
ufw --force reset >/dev/null


# ---------------------------------------------------------
# Configure default firewall policies
# ---------------------------------------------------------

# Block all incoming connections unless a rule allows them.
ufw default deny incoming >/dev/null

# Allow the server to make outgoing connections.
ufw default allow outgoing >/dev/null

echo "    Default incoming: deny"
echo "    Default outgoing: allow"


# ---------------------------------------------------------
# Add required allow rules
# ---------------------------------------------------------

echo "[*] Adding allow rules..."

# Allow SSH only from the management network.
ufw allow from "$MANAGEMENT_NET" to any port 22 proto tcp >/dev/null
echo "    22/tcp from $MANAGEMENT_NET   [ADDED] SSH - management only"

# Allow public web traffic.
ufw allow 80/tcp >/dev/null
echo "    80/tcp                     [ADDED] HTTP"

ufw allow 443/tcp >/dev/null
echo "    443/tcp                    [ADDED] HTTPS"

# Allow MySQL only from the application network.
ufw allow from "$APPLICATION_NET" to any port 3306 proto tcp >/dev/null
echo "    3306/tcp from $APPLICATION_NET [ADDED] MySQL - app network only"


# ---------------------------------------------------------
# Enable firewall logging
# ---------------------------------------------------------

echo "[*] Enabling logging..."

# Low logging records blocked connections without excessive noise.
ufw logging low >/dev/null

echo "    Logging: on (low)"


# ---------------------------------------------------------
# Activate UFW
# ---------------------------------------------------------

echo "[*] Activating firewall..."

# --force enables UFW without asking for confirmation.
ufw --force enable >/dev/null


# ---------------------------------------------------------
# Verify firewall status and rules
# ---------------------------------------------------------

if ufw status | grep -q "Status: active"; then
    echo "    UFW: active"
else
    echo "    UFW: inactive [FAIL]"
    exit 1
fi

# Count only ALLOW rules from the active ruleset.
RULE_COUNT=$(ufw status numbered | grep -c "ALLOW" || true)

echo "    Rules: $RULE_COUNT allow, default deny"

# Display the complete active ruleset.
echo
ufw status verbose
