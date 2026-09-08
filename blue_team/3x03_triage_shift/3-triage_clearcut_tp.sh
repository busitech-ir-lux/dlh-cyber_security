#!/bin/bash
set -euo pipefail

INPUT="enriched_queue.json"
OUTPUT="tickets/batch1_clearcut_tp.json"

mkdir -p tickets

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

jq '
# ------------------------------------------------------------
# Get the rule category.
# Use the alert field first, then known 3x02 rule groups.
# ------------------------------------------------------------
def rule_category:
    .rule_category // .category // .rule.category //
    (
      if (.rule_id == "001" or .rule_id == "002"
          or .rule_id == "009" or .rule_id == "013")
      then "auth"

      elif (.rule_id == "003" or .rule_id == "004"
            or .rule_id == "005")
      then "process"

      elif (.rule_id == "006" or .rule_id == "011")
      then "file"

      elif (.rule_id == "007" or .rule_id == "008"
            or .rule_id == "012")
      then "network"

      elif .rule_id == "010"
      then "correlation"

      else "unknown"
      end
    );

# ------------------------------------------------------------
# Check whether a value exists anywhere in the host baseline.
# ------------------------------------------------------------
def baseline_has($profile; $value):
    if $value == null or $profile == null then
      true
    else
      [$profile | .. | scalars] | index($value) != null
    end;

# ------------------------------------------------------------
# Find the first relevant field that violates the baseline.
# ------------------------------------------------------------
def baseline_violation:
    . as $alert
    | .event_record as $event
    | .baseline_host_profile as $base
    | (rule_category) as $category

    | (
        if $category == "auth" then
          [
            {field: "user", value: $event.user},
            {field: "src_ip", value: $event.src_ip}
          ]

        elif $category == "process" then
          [
            {field: "process_name", value: $event.process_name}
          ]

        elif $category == "network" then
          [
            {field: "dst_ip", value: $event.dst_ip},
            {field: "dst_port", value: $event.dst_port}
          ]

        elif $category == "file" then
          [
            {
              field: "file_path",
              value: ($event.file_path // $event.path)
            }
          ]

        elif $category == "correlation" then
          [
            {field: "user", value: $event.user},
            {field: "src_ip", value: $event.src_ip},
            {field: "process_name", value: $event.process_name},
            {field: "dst_ip", value: $event.dst_ip},
            {
              field: "file_path",
              value: ($event.file_path // $event.path)
            }
          ]

        else
          []
        end
      )

    | [
        .[]
        | select(.value != null)
        | select(
            baseline_has($base; .value) | not
          )
      ][0] // null;

# ------------------------------------------------------------
# Event refs for the ticket.
# Includes the main event and correlation-linked events.
# ------------------------------------------------------------
def evidence_refs:
    [
      .event_ref,

      (.linked_event_refs[]?),

      (
        .correlation_primitives[]?
        | if type == "string"
          then .
          else .event_ref?
          end
      ),

      (.correlation.event_refs[]?)
    ]
    | map(select(. != null and . != ""))
    | unique;

# ------------------------------------------------------------
# Build tickets for alerts matching ALL three predicates.
# ------------------------------------------------------------
[
  .[] as $alert

  | ($alert.ioc_hits
      | map(select(.reputation == "malicious"))
    ) as $malicious

  | ($alert | baseline_violation) as $violation

  | select($alert.priority_band == "critical")
  | select(($malicious | length) > 0)
  | select($violation != null)

  | (
      $malicious
      | map(.categories[]?)
      | unique
      | join(", ")
    ) as $ioc_categories

  | {
      ticket_id: ("ticket_" + $alert.alert_id),
      alert_id: $alert.alert_id,
      classification: "true_positive",

      justification:
        (
          "Malicious IOC category "
          + ($ioc_categories // "unknown")
          + " matched; baseline field "
          + $violation.field
          + " does not contain observed value "
          + ($violation.value | tostring)
          + "."
        ),

      evidence_refs: ($alert | evidence_refs),

      ioc_hits: $alert.ioc_hits,

      attack_techniques:
        (
          $alert.attack_techniques
          // $alert.rule.attack_techniques
          // []
        ),

      recommended_action: "escalate_tier2",

      analyst_time_seconds:
        (
          $alert.analyst_time_seconds
          // $alert.runner_metadata.analyst_time_seconds
          // 60
        ),

      created_at:
        (
          $alert.runner_metadata.created_at
          // $alert.event_summary.timestamp
          // $alert.event_record.timestamp
        )
    }
]
' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

echo "batch 1 clear-cut true positives"

jq -r --slurpfile queue "$INPUT" '
  .[] as $ticket
  | (
      $queue[0][]
      | select(.alert_id == $ticket.alert_id)
    ) as $alert

  | [
      $ticket.alert_id,
      ($alert.rule_id // "-"),
      ($alert.rule_name // $alert.rule_title // "-"),
      ($alert.event_summary.hostname
         // $alert.event_record.hostname
         // "-"),
      "malicious",
      "ESCALATE"
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r alert_id rule_id rule_name host reputation action; do
    printf "  %-12s %-4s %-28s %-16s %-10s %s\n" \
        "$alert_id" \
        "$rule_id" \
        "$rule_name" \
        "$host" \
        "$reputation" \
        "$action"
done

COUNT="$(jq 'length' "$OUTPUT")"

printf "batch size               : %s\n" "$COUNT"
printf "tickets written          : %s\n" "$COUNT"
echo "$OUTPUT"
