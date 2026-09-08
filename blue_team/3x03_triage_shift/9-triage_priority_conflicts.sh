#!/bin/bash
set -euo pipefail

INPUT="enriched_queue.json"
OUTPUT="tickets/batch7_overrides.json"

mkdir -p tickets

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

# ------------------------------------------------------------
# Load tickets from batches 1-6
# ------------------------------------------------------------

shopt -s nullglob
ticket_files=(tickets/batch[1-6]_*.json)
shopt -u nullglob

if (( ${#ticket_files[@]} > 0 )); then
    PREVIOUS="$(
        jq -s '
          [
            .[][]
          ]
        ' "${ticket_files[@]}"
    )"
else
    PREVIOUS='[]'
fi

# ------------------------------------------------------------
# Build override and carry-forward tickets
# ------------------------------------------------------------

jq --argjson previous "$PREVIOUS" '

# Alert was handled if it has an individual ticket
# or belongs to a correlated incident.
def already_handled($id):
    any(
      $previous[];
      (
        .alert_id == $id
        or
        (
          (.contributing_alerts // [])
          | index($id)
        ) != null
      )
    );

# Was the individual ticket marked as grouped?
def was_grouped($id):
    any(
      $previous[];
      .alert_id == $id
      and .grouped == true
    );

# Required evidence references.
def evidence_refs:
    [
      .event_ref,
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

# Build the common ticket fields.
def base_ticket($alert):
    {
      ticket_id:
        ("ticket_" + $alert.alert_id),

      alert_id:
        $alert.alert_id,

      evidence_refs:
        ($alert | evidence_refs),

      ioc_hits:
        ($alert.ioc_hits // []),

      attack_techniques: (
        $alert.attack_techniques
        // $alert.rule.attack_techniques
        // []
      ),

      analyst_time_seconds: (
        $alert.analyst_time_seconds
        // $alert.runner_metadata.analyst_time_seconds
        // 60
      ),

      created_at: (
        $alert.runner_metadata.created_at
        // $alert.event_summary.timestamp
        // $alert.event_record.timestamp
      )
    }
    +
    if was_grouped($alert.alert_id)
    then {grouped: true}
    else {}
    end;

[
  .[] as $alert

  | (
      ($alert.asset.criticality // "")
      | ascii_downcase
    ) as $criticality

  | (
      ($alert.asset.data_classification // "")
      | ascii_downcase
    ) as $data_class

  | (
      ($alert.asset.role // "")
      | ascii_downcase
    ) as $role

  | (
      ($alert.asset.network_zone // "")
      | ascii_downcase
    ) as $zone

  | ($alert.ioc_hits // []) as $iocs

  # ----------------------------------------------------------
  # Conflict 1:
  # low/medium priority on critical regulated-data asset
  # ----------------------------------------------------------

  | (
      if (
        (
          $alert.priority_band == "low"
          or $alert.priority_band == "medium"
        )
        and $criticality == "critical"
        and (
          $data_class == "phi"
          or $data_class == "pci"
          or $data_class == "confidential"
        )
      ) then
        {
          matched: true,
          class: "true_positive",
          action: "escalate_tier2",
          reason: "critical_data_asset",

          text: (
            "Priority override: priority_band="
            + $alert.priority_band
            + ", asset.criticality=critical and "
            + "asset.data_classification="
            + $data_class
            + " require Tier 2 escalation."
          )
        }

      # --------------------------------------------------------
      # Conflict 2:
      # critical alert on low-criticality test asset
      # --------------------------------------------------------

      elif (
        $alert.priority_band == "critical"
        and $criticality == "low"
        and $role == "test"
      ) then
        {
          matched: true,
          class: "false_positive",
          action: "monitor",
          reason: "test_asset_not_production",

          text: (
            "Priority override: priority_band=critical, "
            + "but asset.criticality=low and asset.role=test."
          )
        }

      # --------------------------------------------------------
      # Conflict 3:
      # unknown IOC reputation in regulated zone
      # --------------------------------------------------------

      elif (
        ($iocs | length) > 0
        and all(
          $iocs[];
          .reputation == "unknown"
        )
        and (
          $zone == "phi"
          or $zone == "medical_devices"
        )
      ) then
        {
          matched: true,
          class: "true_positive",
          action: "monitor",
          reason: "regulated_zone_unknown_reputation",

          text: (
            "Priority override: all IOC hits have "
            + "reputation=unknown and asset.network_zone="
            + $zone
            + ", so the alert requires monitoring."
          )
        }

      else
        {
          matched: false
        }
      end
    ) as $decision

  # ----------------------------------------------------------
  # Emit every priority conflict, even if an earlier batch
  # already classified the alert.
  # ----------------------------------------------------------

  | if $decision.matched then

      base_ticket($alert)
      + {
          classification:
            $decision.class,

          justification:
            $decision.text,

          recommended_action:
            $decision.action,

          override_reason:
            $decision.reason
        }

    # --------------------------------------------------------
    # Anything still unclassified after batches 1-6
    # --------------------------------------------------------

    elif (
      already_handled($alert.alert_id) | not
    ) then

      base_ticket($alert)
      + {
          classification:
            "true_positive",

          justification: (
            "Alert fell through batches 1-6 and requires "
            + "human review; priority_band="
            + ($alert.priority_band // "unknown")
            + " and rule_id="
            + ($alert.rule_id // "unknown")
            + "."
          ),

          recommended_action:
            "monitor",

          override_reason:
            "unclassified_human_review"
        }

    else
      empty
    end
]
' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

echo "batch 7 priority conflicts"

jq -r --slurpfile queue "$INPUT" '
  .[]
  | select(
      .override_reason != "unclassified_human_review"
    ) as $ticket

  | (
      $queue[0][]
      | select(.alert_id == $ticket.alert_id)
    ) as $alert

  | [
      $ticket.alert_id,
      ($alert.priority_band // "-"),
      (
        if $ticket.override_reason ==
           "regulated_zone_unknown_reputation"
        then "monitor"
        else $ticket.classification
        end
      ),
      $ticket.override_reason
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r alert_id priority result reason; do
    printf "  %-12s %-8s -> %-16s %s\n" \
        "$alert_id" \
        "$priority" \
        "$result" \
        "$reason"
done

CARRIED="$(
    jq '
      [
        .[]
        | select(
            .override_reason ==
            "unclassified_human_review"
          )
      ]
      | length
    ' "$OUTPUT"
)"

COUNT="$(jq 'length' "$OUTPUT")"

printf "unclassified carried forward : %s\n" "$CARRIED"
printf "tickets written              : %s\n" "$COUNT"
echo "$OUTPUT"
