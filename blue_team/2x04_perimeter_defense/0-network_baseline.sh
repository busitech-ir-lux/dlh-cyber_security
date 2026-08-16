#!/bin/bash

# Output file
OUTPUT="network_baseline.json"

# Temporary folder
TMP="/tmp/network_baseline_$$"
mkdir -p "$TMP"

# jq is needed to create JSON
if ! command -v jq >/dev/null 2>&1; then
    echo "jq is not installed."
    echo "Install it with: sudo apt install jq"
    exit 1
fi

# Basic system information
TIMESTAMP=$(date -Iseconds)
HOSTNAME=$(hostname)


# -------------------------------------------------
# 1. Network interfaces
# -------------------------------------------------

ip -j addr show | jq '
[
    .[] |
    {
        name: .ifname,
        mac: (.address // ""),
        state: (.operstate // ""),
        addresses: [
            .addr_info[]? |
            {
                family: .family,
                address: .local,
                prefixlen: .prefixlen,
                scope: .scope
            }
        ]
    }
]
' > "$TMP/interfaces.json"


# -------------------------------------------------
# 2. Routing table
# -------------------------------------------------

ip -j route show > "$TMP/routes.json"


# -------------------------------------------------
# 3. ARP / neighbor table
# -------------------------------------------------

ip -j neigh show | jq '
[
    .[] |
    {
        ip: .dst,
        mac: (.lladdr // ""),
        state: (.state // [])
    }
]
' > "$TMP/neighbors.json"


# -------------------------------------------------
# 4. Listening TCP and UDP sockets
# -------------------------------------------------

ss -tulnpH > "$TMP/listening.txt"

# Create an empty file for JSON objects
> "$TMP/listening_objects.json"

while IFS= read -r LINE
do
    # Try to get process name from ss output
    PROCESS=$(echo "$LINE" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')

    # Try to get PID from ss output
    PID=$(echo "$LINE" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')

    jq -n \
        --arg socket "$LINE" \
        --arg process "$PROCESS" \
        --arg pid "$PID" \
        '{
            socket: $socket,
            process: $process,
            pid: $pid
        }' >> "$TMP/listening_objects.json"

done < "$TMP/listening.txt"

# Convert individual JSON objects into one JSON array
jq -s '.' "$TMP/listening_objects.json" > "$TMP/listening.json"


# -------------------------------------------------
# 5. Established TCP connections
# -------------------------------------------------

ss -tnpH state established > "$TMP/established.txt"

> "$TMP/established_objects.json"

while IFS= read -r LINE
do
    PROCESS=$(echo "$LINE" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')

    PID=$(echo "$LINE" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')

    jq -n \
        --arg connection "$LINE" \
        --arg process "$PROCESS" \
        --arg pid "$PID" \
        '{
            connection: $connection,
            process: $process,
            pid: $pid
        }' >> "$TMP/established_objects.json"

done < "$TMP/established.txt"

jq -s '.' "$TMP/established_objects.json" > "$TMP/established.json"


# -------------------------------------------------
# 6. DNS resolver configuration
# -------------------------------------------------

cat /etc/resolv.conf > "$TMP/resolv.conf.txt"

# Check if systemd-resolved is active
if systemctl is-active --quiet systemd-resolved
then
    resolvectl status --no-pager > "$TMP/resolvectl.txt"
else
    echo "systemd-resolved is not active" > "$TMP/resolvectl.txt"
fi


# -------------------------------------------------
# 7. Create final network_baseline.json
# -------------------------------------------------

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME" \
    --slurpfile interfaces "$TMP/interfaces.json" \
    --slurpfile routes "$TMP/routes.json" \
    --slurpfile neighbors "$TMP/neighbors.json" \
    --slurpfile listening "$TMP/listening.json" \
    --slurpfile established "$TMP/established.json" \
    --rawfile resolv_conf "$TMP/resolv.conf.txt" \
    --rawfile resolvectl "$TMP/resolvectl.txt" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        interfaces: $interfaces[0],
        routes: $routes[0],
        neighbors: $neighbors[0],
        listening_sockets: $listening[0],
        established_connections: $established[0],
        dns_resolvers: {
            resolv_conf: $resolv_conf,
            resolvectl: $resolvectl
        }
    }' > "$OUTPUT"


# Remove temporary files
rm -rf "$TMP"

echo "Network baseline saved to $OUTPUT"
