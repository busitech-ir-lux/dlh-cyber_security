#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

QUEUE="enriched_queue.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
OUTPUT="incidents.json"
TMP="${OUTPUT}.tmp"

# ------------------------------------------------------------
# Check inputs
# ------------------------------------------------------------

for file in "$QUEUE" "$EVENTS" "$ASSETS"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# Find every ticket from batches 1-7.
shopt -s nullglob
ticket_files=(tickets/batch[1-7]_*.json)
shopt -u nullglob

if (( ${#ticket_files[@]} == 0 )); then
    echo "ERROR: no batch 1-7 tickets found" >&2
    exit 1
fi

# Load all tickets into one array.
TICKETS="$(
    jq -s '
      [
        .[]
        | if type == "array"
          then .[]
          else .
          end
      ]
    ' "${ticket_files[@]}"
)"

# ------------------------------------------------------------
# Build incidents
# ------------------------------------------------------------

jq \
    --argjson tickets "$TICKETS" \
    --slurpfile events "$EVENTS" \
    --slurpfile assets "$ASSETS" '

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def pad4($number):
    ("0000" + ($number | tostring))[-4:];

# Support an event array or NDJSON.
def event_list:
    if (
      ($events | length) == 1
      and ($events[0] | type) == "array"
    )
    then $events[0]
    else $events
    end;

# Support array or hostname-keyed asset inventory.
def asset_list:
    $assets[0]
    | if type == "array" then
        .
      else
        to_entries
        | map(
            .value
            + {
                hostname:
                  (.value.hostname // .key)
              }
          )
      end;

def find_alert($id):
    [
      .[]
      | select(.alert_id == $id)
    ][0] // {};

def find_event($ref):
    [
      event_list[]
      | select(
          (.record_id // .event_ref // .id) == $ref
        )
    ][0] // empty;

def find_asset($host):
    [
      asset_list[]
      | select(
          (.hostname // .host // .asset_id) == $host
        )
    ][0] // {};

# Short readable description for timeline.
def event_description($event):
    $event.description
    // $event.message
    // $event.event_type
    // $event.action
    // (
        ($event.event_category // "security")
        + " event"
      );

# Extract IOC-like values from referenced events.
def extract_iocs($event_records):
    [
      $event_records[]

      | (
          .src_ip?
          // empty
          | select(type == "string" and length > 0)
          | {
              type: "ip",
              value: .
            }
        ),

        (
          .dst_ip?
          // empty
          | select(type == "string" and length > 0)
          | {
              type: "ip",
              value: .
            }
        ),

        (
          .domain?
          // .dst_host?
          // .dns_query?
          // .query_name?
          // empty
          | select(type == "string" and length > 0)
          | {
              type: "domain",
              value: .
            }
        ),

        (
          .user?
          // .username?
          // .target_user?
          // empty
          | select(type == "string" and length > 0)
          | {
              type: "user",
              value: .
            }
        ),

        (
          .process_name?
          // empty
          | select(type == "string" and length > 0)
          | {
              type: "process",
              value: .
            }
        )
    ]
    | unique_by(.type, .value);

# ------------------------------------------------------------
# Fixed containment table
# ------------------------------------------------------------

def containment($rule):
    if (
      $rule == "credential_theft_chain"
      or $rule == "interpreter_abuse"
      or $rule == "recon_tool_execution"
    )
    then "isolate_host"

    elif (
      $rule == "patient_data_access"
      or $rule == "privileged_shift_violation"
      or $rule == "windows_offhours_priv_logon"
    )
    then "disable_account"

    elif (
      $rule == "medical_segment_egress"
      or $rule == "unknown_outbound_destination"
      or $rule == "uncommon_port_outbound"
    )
    then "block_ip_at_egress"

    elif $rule == "ssh_brute_force"
    then "block_source_ip"

    else "isolate_host"
    end;

# Keys used to find related incidents.
def relation_keys:
    (
      [
        .affected_assets[].hostname?
        | select(. != null)
        | "host:" + .
      ]
      +
      [
        .iocs[]
        | "ioc:" + .type + ":" + (.value | tostring)
      ]
    )
    | unique;

# ------------------------------------------------------------
# Build the initial incident list
# ------------------------------------------------------------

. as $queue

| [
    $tickets[]

    # Only TP tickets that require escalation or monitoring.
    | select(.classification == "true_positive")

    | select(
        .recommended_action == "escalate_tier2"
        or .recommended_action == "monitor"
      )

    | . as $ticket

    | ($queue | find_alert($ticket.alert_id)) as $alert

    # Dereference all ticket evidence.
    | (
        [
          $ticket.evidence_refs[]?
          | find_event(.)
        ]
        | sort_by(.timestamp)
      ) as $event_records

    | (
        $alert.rule_name
        // $alert.rule_title
        // $alert.rule.name
        // "unknown_rule"
      ) as $rule

    | (
        $alert.event_summary.hostname
        // $alert.event_record.hostname
        // $event_records[0].hostname
        // "unknown"
      ) as $host

    # Every affected hostname.
    | (
        [
          $host,
          $event_records[].hostname?
        ]
        | map(
            select(
              . != null
              and . != ""
            )
          )
        | unique
      ) as $hosts

    | (
        [
          $hosts[] as $hostname
          | find_asset($hostname) as $asset

          | {
              hostname: $hostname,
              criticality:
                ($asset.criticality // null),
              data_classification:
                ($asset.data_classification // null),
              network_zone:
                ($asset.network_zone // null)
            }
        ]
      ) as $affected_assets

    | extract_iocs($event_records) as $incident_iocs

    | {
        # Helper fields removed before final output.
        _ticket_id: $ticket.ticket_id,
        _rule_title: $rule,
        _target_host: $host,

        _sort_time: (
          $ticket.created_at
          // $event_records[0].timestamp
          // "0000-00-00T00:00:00Z"
        ),

        summary: (
          $rule
          + " detected suspicious activity on "
          + $host
          + "."
        ),

        timeline: (
          [
            $event_records[]
            | {
                timestamp: .timestamp,
                hostname: .hostname,
                event_category: .event_category,
                description: event_description(.)
              }
          ]
          | sort_by(.timestamp)
        ),

        affected_assets: $affected_assets,

        iocs: $incident_iocs,

        attack_techniques: (
          [
            $ticket.attack_techniques[]?,
            (
              $alert.attack_techniques
              // $alert.rule.attack_techniques
              // []
            )[]?
          ]
          | unique
        ),

        recommended_containment:
          containment($rule),

        related_incidents: []
      }
  ]

# ------------------------------------------------------------
# Assign deterministic incident IDs
# ------------------------------------------------------------

| sort_by(._sort_time, ._ticket_id)

| to_entries

| map(
    .key as $index
    | .value as $incident

    | (
        ($incident._sort_time[0:10])
        | gsub("-"; "")
      ) as $date

    | $incident
      + {
          incident_id: (
            "INC-"
            + $date
            + "-"
            + pad4($index + 1)
          )
        }
  )

# ------------------------------------------------------------
# Find incidents sharing a hostname or IOC
# ------------------------------------------------------------

| . as $all

| map(
    . as $current

    | ($current | relation_keys) as $current_keys

    | .related_incidents = [
        $all[]

        | select(
            .incident_id != $current.incident_id
          )

        | . as $other
        | ($other | relation_keys) as $other_keys

        | select(
            any(
              $current_keys[] as $key;
              ($other_keys | index($key)) != null
            )
          )

        | .incident_id
      ]
  )

' "$QUEUE" > "$TMP"

# ------------------------------------------------------------
# Print compact incident list
# ------------------------------------------------------------

echo "incidents assembled"

jq -r '
  .[]
  | [
      .incident_id,
      ._target_host,
      ._rule_title,
      .recommended_containment
    ]
  | @tsv
' "$TMP" |
while IFS=$'\t' read -r incident host rule action; do
    printf "  %-20s %-16s %-30s %s\n" \
        "$incident" \
        "$host" \
        "$rule" \
        "$action"
done

# ------------------------------------------------------------
# Remove helper fields and write final output
# ------------------------------------------------------------

jq '
  map(
    del(
      ._ticket_id,
      ._rule_title,
      ._target_host,
      ._sort_time
    )
  )
' "$TMP" > "$OUTPUT"

rm -f "$TMP"

COUNT="$(jq 'length' "$OUTPUT")"

printf "total incidents         : %s\n" "$COUNT"
echo "$OUTPUT written"
