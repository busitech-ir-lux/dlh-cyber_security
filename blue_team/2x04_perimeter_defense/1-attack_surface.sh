#!/bin/bash

set -e

INPUT="network_baseline.json"
CATALOG="service_catalog.json"
CRITICALITY="service_criticality.json"
OUTPUT="attack_surface.json"

TMP="/tmp/attack_surface_$$"

mkdir -p "$TMP"
> "$TMP/sockets.json"


# -------------------------------------------------
# Check input files
# -------------------------------------------------

if [ ! -f "$INPUT" ]; then
    echo "network_baseline.json not found"
    exit 1
fi

if [ ! -f "$CATALOG" ]; then
    echo "service_catalog.json not found"
    exit 1
fi

if [ ! -f "$CRITICALITY" ]; then
    echo "service_criticality.json not found"
    exit 1
fi


# -------------------------------------------------
# Process every listening socket
# -------------------------------------------------

COUNT=$(jq '.listening_sockets | length' "$INPUT")

for ((i=0; i<COUNT; i++))
do

    PROTO=$(jq -r ".listening_sockets[$i].proto // \"unknown\"" "$INPUT")
    PORT=$(jq -r ".listening_sockets[$i].local_port // 0" "$INPUT")
    BIND_ADDR=$(jq -r ".listening_sockets[$i].local_addr // \"unknown\"" "$INPUT")
    PROCESS=$(jq -r ".listening_sockets[$i].process // \"unknown\"" "$INPUT")
    PID=$(jq -r ".listening_sockets[$i].pid // 0" "$INPUT")


    # -------------------------------------------------
    # Find binary
    # -------------------------------------------------

    BINARY=""

    if [ "$PID" != "0" ] && [ -e "/proc/$PID/exe" ]; then
        BINARY=$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)
    fi


    # -------------------------------------------------
    # Find package
    # -------------------------------------------------

    PACKAGE="unknown"

    if [ -n "$BINARY" ]; then

        PACKAGE=$(dpkg -S "$BINARY" 2>/dev/null |
            head -1 |
            cut -d: -f1 || true)

        if [ -z "$PACKAGE" ]; then
            PACKAGE="unknown"
        fi

    fi


    # -------------------------------------------------
    # Find systemd service
    # -------------------------------------------------

    SERVICE_UNIT=""

    if [ "$PID" != "0" ] && [ -f "/proc/$PID/cgroup" ]; then

        SERVICE_UNIT=$(grep -o '[^/]*\.service' "/proc/$PID/cgroup" 2>/dev/null |
            head -1 || true)

        if [ -n "$SERVICE_UNIT" ]; then
            SERVICE_UNIT=$(systemctl show "$SERVICE_UNIT" \
                -p Id --value 2>/dev/null || true)
        fi

    fi


    # -------------------------------------------------
    # Find function in service_catalog.json
    #
    # Supports both:
    #   { "sshd": "ssh" }
    #
    # and arrays such as:
    #   [
    #     {"process":"sshd","function":"ssh"},
    #     {"port":3306,"function":"database"}
    #   ]
    # -------------------------------------------------

    FUNCTION=$(jq -r \
        --arg process "$PROCESS" \
        --arg port "$PORT" \
        --arg unit "$SERVICE_UNIT" \
        --arg package "$PACKAGE" \
        '

        if type == "object" then

            (
                .[$process]
                // .[$port]
                // .[$unit]
                // .[$package]
                // "unknown"
            )
            |
            if type == "object" then
                (.function // .label // .category // "unknown")
            else
                .
            end

        elif type == "array" then

            (
                [
                    .[] |

                    select(
                        ((.process? // .name? // "") | tostring) == $process
                        or
                        ((.port? // "") | tostring) == $port
                        or
                        ((.service_unit? // .unit? // "") | tostring) == $unit
                        or
                        ((.package? // "") | tostring) == $package
                    )

                    |

                    (
                        .function?
                        // .label?
                        // .category?
                        // empty
                    )

                ][0] // "unknown"
            )

        else
            "unknown"
        end

        ' "$CATALOG")


    # -------------------------------------------------
    # Find criticality
    # -------------------------------------------------

    LEVEL=$(jq -r \
        --arg process "$PROCESS" \
        --arg port "$PORT" \
        --arg function "$FUNCTION" \
        --arg unit "$SERVICE_UNIT" \
        --arg package "$PACKAGE" \
        '

        if type == "object" then

            (
                .[$process]
                // .[$port]
                // .[$function]
                // .[$unit]
                // .[$package]
                // "low"
            )
            |
            if type == "object" then
                (.criticality // .level // "low")
            else
                .
            end

        elif type == "array" then

            (
                [
                    .[] |

                    select(
                        ((.process? // .name? // "") | tostring) == $process
                        or
                        ((.port? // "") | tostring) == $port
                        or
                        ((.function? // "") | tostring) == $function
                        or
                        ((.service_unit? // .unit? // "") | tostring) == $unit
                        or
                        ((.package? // "") | tostring) == $package
                    )

                    |

                    (
                        .criticality?
                        // .level?
                        // empty
                    )

                ][0] // "low"
            )

        else
            "low"
        end

        ' "$CRITICALITY")


    # -------------------------------------------------
    # Build socket JSON
    # -------------------------------------------------

    jq -n \
        --arg proto "$PROTO" \
        --argjson port "$PORT" \
        --arg bind "$BIND_ADDR" \
        --arg process "$PROCESS" \
        --arg binary "$BINARY" \
        --arg package "$PACKAGE" \
        --arg unit "$SERVICE_UNIT" \
        --arg function "$FUNCTION" \
        --arg criticality "$LEVEL" \
        '
        {
            proto: $proto,
            port: $port,
            bind_addr: $bind,
            process: $process,
            binary: $binary,
            package: $package,
            service_unit: $unit,
            function: $function,
            criticality: $criticality,

            exposure_flags:
            (
                []

                +

                if $bind == "0.0.0.0"
                   and $function == "database"
                then
                    [
                        "bound_0.0.0.0",
                        "database_exposed"
                    ]
                else
                    []
                end

                +

                if $bind == "0.0.0.0"
                   and $function == "rpc"
                then
                    [
                        "bound_0.0.0.0",
                        "rpc_exposed"
                    ]
                else
                    []
                end

                +

                if (
                    $function == "telnet"
                    or $function == "ftp"
                    or $function == "snmpv1"
                    or $function == "snmpv2c"
                    or $function == "rlogin"
                    or $function == "nfs v2/v3"
                )
                then
                    [
                        "insecure_protocol_" +
                        ($function | gsub("[ /]"; "_"))
                    ]
                else
                    []
                end
            )
        }
        ' >> "$TMP/sockets.json"

done


# -------------------------------------------------
# Put socket objects into an array
# -------------------------------------------------

jq -s '.' "$TMP/sockets.json" > "$TMP/socket_array.json"


# -------------------------------------------------
# Final report
# -------------------------------------------------

GENERATED=$(date -Iseconds)
HOSTNAME=$(jq -r '.hostname' "$INPUT")

jq \
    --arg generated "$GENERATED" \
    --arg hostname "$HOSTNAME" \
    '
    {
        generated_at: $generated,

        hostname: $hostname,

        sockets: .,

        summary: {

            total_sockets:
                length,

            flagged_total:
                (
                    [
                        .[] |
                        select(.exposure_flags | length > 0)
                    ] | length
                ),

            flagged_critical:
                (
                    [
                        .[] |
                        select(
                            (.exposure_flags | length > 0)
                            and
                            .criticality == "critical"
                        )
                    ] | length
                ),

            flagged_high:
                (
                    [
                        .[] |
                        select(
                            (.exposure_flags | length > 0)
                            and
                            .criticality == "high"
                        )
                    ] | length
                ),

            flagged_medium:
                (
                    [
                        .[] |
                        select(
                            (.exposure_flags | length > 0)
                            and
                            .criticality == "medium"
                        )
                    ] | length
                ),

            flagged_low:
                (
                    [
                        .[] |
                        select(
                            (.exposure_flags | length > 0)
                            and
                            .criticality == "low"
                        )
                    ] | length
                ),

            unknown_functions:
                (
                    [
                        .[] |
                        select(.function == "unknown")
                    ] | length
                )
        }
    }
    ' "$TMP/socket_array.json" > "$OUTPUT"


rm -rf "$TMP"

echo "Attack surface report saved to $OUTPUT"
