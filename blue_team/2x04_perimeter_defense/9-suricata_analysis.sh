#!/bin/bash

set -e

DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap"
PCAP="${1:-$DEFAULT_PCAP}"

CONFIG="./suricata.yaml"
CATEGORY_FILE="./signature_categories.json"
OUTPUT="./suricata_alerts.json"

TMPDIR="/tmp/suricata-analysis-$$"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# -------------------------------------------------
# Check files
# -------------------------------------------------

if [ ! -f "$PCAP" ]; then
    echo "PCAP not found: $PCAP"
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "suricata.yaml not found"
    exit 1
fi

if [ ! -f "$CATEGORY_FILE" ]; then
    echo "signature_categories.json not found"
    exit 1
fi


# -------------------------------------------------
# Run Suricata replay
# -------------------------------------------------

rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

echo "[*] Replaying PCAP..."
echo "[*] PCAP: $PCAP"

suricata \
    -c ./suricata.yaml \
    -r "$PCAP" \
    -l "$TMPDIR"

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

EVE_FILE="$TMPDIR/eve.json"


if [ ! -f "$EVE_FILE" ]; then
    echo "eve.json was not created"
    exit 1
fi


# -------------------------------------------------
# Keep only alert records
# -------------------------------------------------

jq -c '
    select(.event_type == "alert")
' "$EVE_FILE" > "$TMPDIR/alerts_only.jsonl"


# -------------------------------------------------
# Build clean alert array
# -------------------------------------------------

jq -s '
[
    .[] |
    {
        timestamp: (.timestamp // ""),
        src_ip: (.src_ip // ""),
        src_port: (.src_port // 0),
        dst_ip: (.dest_ip // ""),
        dst_port: (.dest_port // 0),
        proto: (.proto // ""),
        signature: (.alert.signature // ""),
        signature_id: (.alert.signature_id // 0),
        category: (.alert.category // ""),
        severity: (.alert.severity // 0)
    }
]
' "$TMPDIR/alerts_only.jsonl" > "$TMPDIR/alerts.json"


# -------------------------------------------------
# Add classification from signature_categories.json
#
# Allowed categories:
# reconnaissance
# exploit
# lateral_movement
# exfiltration
# malware_c2
# policy_violation
# other
#
# No custom detection logic is used.
# The provided signature_categories.json is authoritative.
# -------------------------------------------------

jq \
    --slurpfile categories "$CATEGORY_FILE" \
    '
    map(
        . as $alert |

        . + {
            classification:

                (
                    if ($categories[0] | type) == "object" then

                        (
                            $categories[0][$alert.signature]
                            //
                            $categories[0][($alert.signature_id | tostring)]
                            //
                            "other"
                        )

                    elif ($categories[0] | type) == "array" then

                        (
                            [
                                $categories[0][] |

                                select(
                                    ((.signature? // "") == $alert.signature)
                                    or
                                    ((.signature_id? // 0 | tostring)
                                        == ($alert.signature_id | tostring))
                                )

                                |

                                (
                                    .category?
                                    // .classification?
                                    // "other"
                                )
                            ][0]
                            // "other"
                        )

                    else
                        "other"
                    end
                )
        }
    )
    ' "$TMPDIR/alerts.json" > "$TMPDIR/classified_alerts.json"


# -------------------------------------------------
# Statistics
# -------------------------------------------------

TOTAL_ALERTS=$(jq 'length' "$TMPDIR/classified_alerts.json")

UNIQUE_SIGNATURES=$(jq '
    [.[].signature] |
    unique |
    length
' "$TMPDIR/classified_alerts.json")


SEVERITY_DISTRIBUTION=$(jq '
    group_by(.severity)
    |
    map({
        severity: .[0].severity,
        count: length
    })
' "$TMPDIR/classified_alerts.json")


BY_SIGNATURE=$(jq '
    group_by(.signature)
    |
    map({
        signature: .[0].signature,
        count: length
    })
    |
    sort_by(-.count)
' "$TMPDIR/classified_alerts.json")


BY_CATEGORY=$(jq '
    group_by(.classification)
    |
    map({
        category: .[0].classification,
        count: length
    })
    |
    sort_by(-.count)
' "$TMPDIR/classified_alerts.json")


TOP_SOURCES=$(jq '
    group_by(.src_ip)
    |
    map({
        src_ip: .[0].src_ip,
        count: length
    })
    |
    sort_by(-.count)
' "$TMPDIR/classified_alerts.json")


TOP_DESTINATIONS=$(jq '
    group_by(.dst_ip)
    |
    map({
        dst_ip: .[0].dst_ip,
        count: length
    })
    |
    sort_by(-.count)
' "$TMPDIR/classified_alerts.json")


# -------------------------------------------------
# Create final suricata_alerts.json
# -------------------------------------------------

jq -n \
    --arg pcap "$PCAP" \
    --arg started "$STARTED_AT" \
    --arg finished "$FINISHED_AT" \
    --argjson total "$TOTAL_ALERTS" \
    --argjson unique "$UNIQUE_SIGNATURES" \
    --argjson severity "$SEVERITY_DISTRIBUTION" \
    --argjson by_signature "$BY_SIGNATURE" \
    --argjson by_category "$BY_CATEGORY" \
    --argjson top_sources "$TOP_SOURCES" \
    --argjson top_destinations "$TOP_DESTINATIONS" \
    --slurpfile alerts "$TMPDIR/classified_alerts.json" \
    '{
        pcap: $pcap,
        started_at: $started,
        finished_at: $finished,
        total_alerts: $total,
        unique_signatures: $unique,
        severity_distribution: $severity,
        by_signature: $by_signature,
        by_category: $by_category,
        top_sources: $top_sources,
        top_destinations: $top_destinations,
        alerts: $alerts[0]
    }' > "$OUTPUT"


# -------------------------------------------------
# Done
# -------------------------------------------------

echo ""
echo "Suricata Replay Analysis"
echo "========================"
echo "PCAP:              $PCAP"
echo "Total alerts:      $TOTAL_ALERTS"
echo "Unique signatures: $UNIQUE_SIGNATURES"
echo "Output:            $OUTPUT"
