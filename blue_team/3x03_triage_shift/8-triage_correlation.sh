#!/bin/bash
set -euo pipefail

INPUT="enriched_queue.json"
OUTPUT="tickets/batch6_incidents.json"

mkdir -p tickets

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

# ------------------------------------------------------------
# Load tickets from batches 1-5.
# ------------------------------------------------------------

shopt -s nullglob
previous_files=(tickets/batch[1-5]_*.json)
shopt -u nullglob

if (( ${#previous_files[@]} > 0 )); then
    PREVIOUS="$(jq -s '[.[][]]' "${previous_files[@]}")"
else
    PREVIOUS='[]'
fi

# ------------------------------------------------------------
# Build correlated incidents.
# ------------------------------------------------------------

jq --argjson previous "$PREVIOUS" '

def hostname:
    .event_summary.hostname
    // .event_record.hostname
    // "unknown";

def timestamp:
    .event_summary.timestamp
    // .event_record.timestamp;

def epoch:
    try fromdateiso8601 catch null;

# Collect evidence references from all contributing alerts.
def refs($group):
    [
      $group[]
      | .event_ref,
        .linked_event_refs[]?,
        (
          .correlation_primitives[]?
          | if type == "string"
            then .
            else .event_ref?
            end
        )
    ]
    | map(select(. != null and . != ""))
    | unique;

# Group alerts on the same host where consecutive
# alerts are no more than 600 seconds apart.
def make_incidents:
    group_by(hostname)

    | map(
        sort_by(timestamp)

        | reduce .[] as $alert
            ([];
             if length == 0 then
               [[$alert]]
             else
               (.[-1][-1] | timestamp | epoch) as $last
               | ($alert | timestamp | epoch) as $current

               | if (
                   $last != null
                   and $current != null
                   and ($current - $last) <= 600
                 )
                 then
                   .[-1] += [$alert]
                 else
                   . += [[$alert]]
                 end
             end
            )
      )

    | add

    # Correlation requires at least two alerts.
    | map(select(length >= 2));

make_incidents[] as $group

| ($group | sort_by(timestamp)) as $group
| $group[0] as $first
| $group[-1] as $last

| [$group[].alert_id] as $alert_ids

| (
    $group
    | max_by(.priority_score // 0)
  ) as $highest

| (
    [
      $previous[]
      | .alert_id as $id
      | select(
          ($alert_ids | index($id)) != null
          and .classification == "true_positive"
        )
    ]
    | length > 0
  ) as $previous_tp

| (
    if ($group | length) >= 3
    then "high_confidence"
    else "medium_confidence"
    end
  ) as $confidence

| (
    (
      $first.asset.criticality
      // $highest.asset.criticality
      // "low"
    )
    | ascii_downcase
  ) as $criticality

| (
    if $previous_tp then
      "true_positive"
    elif ($highest.priority_score // 0) >= 10 then
      "true_positive"
    else
      "benign"
    end
  ) as $classification

| (
    if (
      $confidence == "high_confidence"
      and (
        $criticality == "critical"
        or $criticality == "high"
      )
    )
    then "escalate_tier2"
    else "monitor"
    end
  ) as $action

| {
    ticket_id: (
      "incident_"
      + ($first | hostname)
      + "_"
      + ($first | timestamp)
    ),

    # Highest-priority alert is the primary alert.
    alert_id: $highest.alert_id,

    classification: $classification,

    justification: (
      ($group | length | tostring)
      + " related alerts occurred on hostname="
      + ($first | hostname)
      + " within the 600-second correlation window; "
      + "highest priority_score="
      + (($highest.priority_score // 0) | tostring)
      + ", confidence="
      + $confidence
      + ", asset.criticality="
      + $criticality
      + "."
    ),

    evidence_refs: refs($group),

    ioc_hits: (
      [
        $group[]
        | .ioc_hits[]?
      ]
      | unique_by(
          .indicator,
          .reputation
        )
    ),

    attack_techniques: (
      [
        $group[]
        | (
            .attack_techniques
            // .rule.attack_techniques
            // []
          )[]
      ]
      | unique
    ),

    recommended_action: $action,

    analyst_time_seconds: (
      [
        $group[]
        | (
            .analyst_time_seconds
            // .runner_metadata.analyst_time_seconds
            // 60
          )
      ]
      | add
    ),

    created_at: ($first | timestamp),

    contributing_alerts: $alert_ids,

    incident_window: {
      start: ($first | timestamp),
      end: ($last | timestamp)
    },

    confidence: $confidence,

    highest_priority_score:
      ($highest.priority_score // 0),

    asset_criticality: $criticality
  }

' "$INPUT" | jq -s '.' > "$OUTPUT"

# ------------------------------------------------------------
# Get every alert that was grouped into an incident.
# ------------------------------------------------------------

GROUPED_IDS="$(
    jq '
      [
        .[].contributing_alerts[]
      ]
      | unique
    ' "$OUTPUT"
)"

# ------------------------------------------------------------
# Mark grouped alerts in their individual tickets.
# ------------------------------------------------------------

for file in "${previous_files[@]}"; do

    jq --argjson ids "$GROUPED_IDS" '
      map(
        .alert_id as $id

        | if ($ids | index($id)) != null
          then . + {grouped: true}
          else .
          end
      )
    ' "$file" > "$file.tmp"

    mv "$file.tmp" "$file"
done

# ------------------------------------------------------------
# Compact summary.
# ------------------------------------------------------------

echo "batch 6 correlated incidents"

jq -r '
  .[]
  | [
      .ticket_id,
      (.contributing_alerts | length | tostring),
      .confidence,
      (
        if .recommended_action == "escalate_tier2"
        then "escalate"
        else .recommended_action
        end
      )
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r ticket_id count confidence action; do
    printf "  %-48s alerts=%-2s %-18s %s\n" \
        "$ticket_id" \
        "$count" \
        "$confidence" \
        "$action"
done

INCIDENTS="$(jq 'length' "$OUTPUT")"

ALERTS="$(
    jq '
      [
        .[].contributing_alerts[]
      ]
      | unique
      | length
    ' "$OUTPUT"
)"

printf "incidents assembled      : %s\n" "$INCIDENTS"
printf "alerts regrouped         : %s\n" "$ALERTS"
echo "$OUTPUT"
