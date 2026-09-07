#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# 0-detection_matrix.sh
#
# Analyze each source_type in the 3x00 enriched evidence and
# decide which detection types it can reasonably support.
#
# Output:
#   detection_matrix.json
# ------------------------------------------------------------


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
SCHEMA_FILE="$HANDOFF_DIR/schema/event_schema.json"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"

OUTPUT="detection_matrix.json"


# ------------------------------------------------------------
# Dependency and input checks
# ------------------------------------------------------------

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required" >&2
    exit 1
}

for file in "$EVENTS_FILE" "$SCHEMA_FILE" "$BASELINE_FILE"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: required file not found: $file" >&2
        exit 1
    fi
done

# The schema and baseline must contain valid JSON.
jq empty "$SCHEMA_FILE" >/dev/null
jq empty "$BASELINE_FILE" >/dev/null


# ------------------------------------------------------------
# Temporary working directory
# ------------------------------------------------------------

TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT


# ------------------------------------------------------------
# Normalize enriched_events.json
#
# The handoff may contain either:
#   - one JSON array
#   - newline-delimited JSON objects
#
# Convert either representation into one JSON array so the
# remaining analysis is deterministic.
# ------------------------------------------------------------

jq -s '
    if length == 1 and (.[0] | type) == "array" then
        .[0]
    else
        .
    end
' "$EVENTS_FILE" > "$TMP_DIR/events.json"


# ------------------------------------------------------------
# Build detection matrix
# ------------------------------------------------------------

jq \
    --slurpfile events "$TMP_DIR/events.json" \
    --slurpfile schema "$SCHEMA_FILE" \
    --slurpfile baseline "$BASELINE_FILE" \
'
# ------------------------------------------------------------
# Extract top-level fields declared by the unified schema.
#
# Different project versions may represent schema fields in
# slightly different ways, so support the common forms.
# ------------------------------------------------------------
def schema_fields:
    if ($schema[0] | type) != "object" then
        []
    elif ($schema[0].properties? | type) == "object" then
        ($schema[0].properties | keys)
    elif ($schema[0].fields? | type) == "array" then
        [
            $schema[0].fields[]
            | if type == "string" then
                  .
              elif type == "object" then
                  (.name? // empty)
              else
                  empty
              end
        ]
    else
        []
    end;


# ------------------------------------------------------------
# A valid baseline is required for anomaly/behavioral analysis.
# ------------------------------------------------------------
def baseline_ready:
    (($baseline | length) > 0)
    and
    (($baseline[0] | type) == "object"
     or ($baseline[0] | type) == "array");


# ------------------------------------------------------------
# Detection capability policy
#
# These decisions are based on what each source represents,
# not simply whether arbitrary text happens to exist in it.
# ------------------------------------------------------------
def policy($source; $has_baseline):

    if $source == "windows_json" then
        {
            types:
                (
                    ["signature"]
                    + (if $has_baseline then
                           ["anomaly", "behavioral"]
                       else
                           []
                       end)
                    + ["correlation"]
                ),

            rationale:
                (
                    {
                        signature:
                            "stable_structured_event_fields_support_exact_predicates",
                        correlation:
                            "timestamps_hosts_users_and_event_identifiers_support_cross_source_joining"
                    }
                    +
                    (if $has_baseline then
                        {
                            anomaly:
                                "seven_day_baseline_supports_frequency_and_value_deviation_detection",
                            behavioral:
                                "ordered_endpoint_activity_supports_behavior_sequence_detection"
                        }
                     else
                        {}
                     end)
                ),

            tactics: [
                "TA0002",
                "TA0003",
                "TA0004",
                "TA0005",
                "TA0006",
                "TA0007",
                "TA0008",
                "TA0009"
            ]
        }

    elif $source == "linux_text" then
        {
            types:
                (
                    ["signature"]
                    + (if $has_baseline then
                           ["anomaly", "behavioral"]
                       else
                           []
                       end)
                    + ["correlation"]
                ),

            rationale:
                (
                    {
                        signature:
                            "normalized_linux_fields_support_exact_event_predicates",
                        correlation:
                            "timestamps_hosts_users_processes_and_network_fields_support_cross_source_joining"
                    }
                    +
                    (if $has_baseline then
                        {
                            anomaly:
                                "seven_day_baseline_supports_frequency_and_value_deviation_detection",
                            behavioral:
                                "authentication_process_and_system_activity_support_behavior_sequences"
                        }
                     else
                        {}
                     end)
                ),

            tactics: [
                "TA0002",
                "TA0003",
                "TA0004",
                "TA0005",
                "TA0006",
                "TA0007",
                "TA0008"
            ]
        }

    elif $source == "suricata_alert" then
        {
            types: [
                "signature",
                "correlation"
            ],

            rationale: {
                signature:
                    "suricata_alerts_are_generated_from_explicit_network_signatures",
                correlation:
                    "network_endpoints_timestamps_and_alert_metadata_can_be_correlated_with_other_sources"
            },

            tactics: [
                "TA0001",
                "TA0011",
                "TA0010"
            ]
        }

    elif $source == "firewall" then
        {
            types:
                (
                    (if $has_baseline then
                         ["anomaly"]
                     else
                         []
                     end)
                    + ["correlation"]
                ),

            rationale:
                (
                    {
                        correlation:
                            "source_destination_port_action_and_timestamp_fields_support_cross_source_joining"
                    }
                    +
                    (if $has_baseline then
                        {
                            anomaly:
                                "connection_volume_destinations_ports_and_actions_can_be_compared_with_baseline"
                        }
                     else
                        {}
                     end)
                ),

            tactics: [
                "TA0008",
                "TA0011",
                "TA0010"
            ]
        }

    elif $source == "pcap_flow" then
        {
            types:
                (
                    if $has_baseline then
                        ["anomaly", "behavioral"]
                    else
                        []
                    end
                ),

            rationale:
                (
                    if $has_baseline then
                        {
                            anomaly:
                                "flow_volume_duration_peers_and_ports_can_be_compared_with_baseline",
                            behavioral:
                                "flow_sequences_and_communication_patterns_support_behavior_detection"
                        }
                    else
                        {}
                    end
                ),

            tactics: [
                "TA0007",
                "TA0008",
                "TA0011",
                "TA0010"
            ]
        }

    else
        {
            types: [],
            rationale: {},
            tactics: []
        }
    end;


# ------------------------------------------------------------
# Determine whether the baseline package is usable.
# ------------------------------------------------------------

(baseline_ready) as $has_baseline


# ------------------------------------------------------------
# Find every source_type represented in the handoff.
# ------------------------------------------------------------

| (
    $events[0]
    | map(.source_type? // empty)
    | map(select(type == "string" and length > 0))
    | unique
  ) as $source_types


# ------------------------------------------------------------
# Analyze each source independently.
# ------------------------------------------------------------

| [
    $source_types[] as $source

    | (
        $events[0]
        | map(select(.source_type? == $source))
      ) as $records

    | ($records | length) as $record_count

    # Candidate fields are the union of:
    #   - fields actually observed in the events
    #   - fields declared in the unified schema
    |
      (
        (
            [$records[] | select(type == "object") | keys[]]
            + schema_fields
        )
        | unique
      ) as $candidate_fields

    | policy($source; $has_baseline) as $policy

    | {
        source_type: $source,

        record_count: $record_count,

        # A stable field must contain a non-null value in at least
        # 95 percent of this source's records.
        stable_fields:
            [
                $candidate_fields[] as $field

                | (
                    [
                        $records[]
                        | select(
                            type == "object"
                            and has($field)
                            and .[$field] != null
                        )
                    ]
                    | length
                  ) as $present_count

                | select(
                    $present_count
                    >= ($record_count * 0.95)
                  )

                | $field
            ],

        # A high-cardinality field has more unique non-null
        # values than half of the records for this source.
        high_cardinality_fields:
            [
                $candidate_fields[] as $field

                | (
                    [
                        $records[]
                        | select(
                            type == "object"
                            and has($field)
                            and .[$field] != null
                        )
                        | .[$field]
                        | tojson
                    ]
                    | unique
                    | length
                  ) as $distinct_count

                | select(
                    $distinct_count
                    > ($record_count * 0.5)
                  )

                | $field
            ],

        supported_detection_types: $policy.types,

        rationale: $policy.rationale,

        recommended_attack_tactics: $policy.tactics
      }
]
' > "$OUTPUT"


# ------------------------------------------------------------
# Print human-readable summary
# ------------------------------------------------------------

jq -r '
    .[]
    | "\(.source_type)\t\(.supported_detection_types | length) types  [\(.supported_detection_types | join(" "))]"
' "$OUTPUT"

SOURCE_COUNT="$(jq 'length' "$OUTPUT")"

echo "$SOURCE_COUNT source types analyzed"
echo "$OUTPUT written"
