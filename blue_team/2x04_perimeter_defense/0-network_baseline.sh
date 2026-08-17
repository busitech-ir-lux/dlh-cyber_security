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
        MAC: (.address // ""),
        link state: (.operstate // ""),
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
# 2. Routing table - Also returns default route
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
        MAC: (.lladdr // ""),
        state: (.state // [])
    }
]
' > "$TMP/neighbors.json"


# -------------------------------------------------
# 4. Listening TCP and UDP sockets
# -------------------------------------------------

ss -tulnpH > "$TMP/listening.txt"

> "$TMP/listening_objects.json"

while IFS= read -r LINE
do
    # Get protocol (tcp or udp)
    PROTO=$(echo "$LINE" | awk '{print $1}')

    # Get local address and port
    LOCAL=$(echo "$LINE" | awk '{print $5}')

    LOCAL_ADDR="${LOCAL%:*}"
    LOCAL_PORT="${LOCAL##*:}"

    # Get process name
    PROCESS=$(echo "$LINE" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')

    # Get PID
    PID=$(echo "$LINE" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')

    # If port is missing, use 0
    if [ -z "$LOCAL_PORT" ]; then
        LOCAL_PORT=0
    fi

    # If PID is missing, use 0
    if [ -z "$PID" ]; then
        PID=0
    fi

    jq -n \
        --arg proto "$PROTO" \
        --arg local_addr "$LOCAL_ADDR" \
        --argjson local_port "$LOCAL_PORT" \
        --arg process "$PROCESS" \
        --argjson pid "$PID" \
        '{
            proto: $proto,
            local_addr: $local_addr,
            local_port: $local_port,
            process: $process,
            pid: $pid
        }' >> "$TMP/listening_objects.json"

done < "$TMP/listening.txt"

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
