#!/bin/bash
set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

QUEUE="enriched_queue.json"
ASSESSMENT="queue_assessment.json"
OUTPUT="shift_metrics.json"

# Methodology may still be in the project root before T14.
METHODOLOGY="triage_methodology.md"

if [[ ! -f "$METHODOLOGY" &&
      -f "$TRIAGE_PKG/spec/triage_methodology.md" ]]; then
    METHODOLOGY="$TRIAGE_PKG/spec/triage_methodology.md"
fi

for file in "$QUEUE" "$ASSESSMENT" "$METHODOLOGY"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Find all batch tickets
# ------------------------------------------------------------

shopt -s nullglob
ticket_files=(tickets/batch[1-7]_*.json)
shopt -u nullglob

if (( ${#ticket_files[@]} == 0 )); then
    echo "ERROR: no batch tickets found" >&2
    exit 1
fi

ALL_TICKETS="$(
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
# Read SLA values from triage_methodology.md
# ------------------------------------------------------------

sla_minutes() {
    local band="$1"

    awk -v band="$band" '
        $0 ~ "- `" band "`:" {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9]+$/) {
                    print $i
                    exit
                }
            }
        }
    ' "$METHODOLOGY"
}

CRITICAL_MIN="$(sla_minutes critical)"
HIGH_MIN="$(sla_minutes high)"
MEDIUM_MIN="$(sla_minutes medium)"

[[ -n "$CRITICAL_MIN" ]] || CRITICAL_MIN=15
[[ -n "$HIGH_MIN" ]] || HIGH_MIN=30
[[ -n "$MEDIUM_MIN" ]] || MEDIUM_MIN=60

# "same day" for low priority = 24 hours.
SLA_JSON="$(
    jq -n \
        --argjson critical "$((CRITICAL_MIN * 60))" \
        --argjson high "$((HIGH_MIN * 60))" \
        --argjson medium "$((MEDIUM_MIN * 60))" \
        '{
            critical: $critical,
            high: $high,
            medium: $medium,
            low: 86400
        }'
)"

# ------------------------------------------------------------
# Calculate metrics
# ------------------------------------------------------------

jq \
    --argjson tickets "$ALL_TICKETS" \
    --argjson sla "$SLA_JSON" \
    --slurpfile assessment "$ASSESSMENT" '

# Convert ISO timestamp to epoch.
def epoch:
    if . == null then
        null
    else
        try (
            sub("\\.[0-9]+Z$"; "Z")
            | fromdateiso8601
        ) catch null
    end;

# Median of a numeric array.
def median:
    sort as $values
    | ($values | length) as $count

    | if $count == 0 then
        null

      elif ($count % 2) == 1 then
        $values[($count / 2 | floor)]

      else
        (
          $values[($count / 2) - 1]
          + $values[$count / 2]
        ) / 2
      end;

# Find alert from enriched queue.
def find_alert($queue; $id):
    [
      $queue[]
      | select(.alert_id == $id)
    ][0] // {};

. as $queue

# ------------------------------------------------------------
# Individual alert tickets only.
#
# Correlated incident tickets contain contributing_alerts.
# They are excluded so alerts are not counted twice.
# ------------------------------------------------------------

| [
    $tickets[]
    | select(
        (.contributing_alerts? | type) != "array"
      )
  ] as $individual

# ------------------------------------------------------------
# Batch 7 overrides replace an earlier ticket for the same alert.
# ------------------------------------------------------------

| (
    reduce $individual[] as $ticket
      ({};

       $ticket.alert_id as $id

       | if (
           .[$id] == null
           or $ticket.override_reason? != null
         )
         then .[$id] = $ticket
         else .
         end
      )

    | [.[]]
  ) as $final_tickets

# Join every final ticket back to its source alert.
| [
    $final_tickets[]
    | . as $ticket
    | find_alert($queue; $ticket.alert_id) as $alert

    | {
        ticket: $ticket,
        alert: $alert,
        rule_id: ($alert.rule_id // "unknown"),

        rule_title: (
          $alert.rule_name
          // $alert.rule_title
          // $alert.rule.name
          // "unknown_rule"
        )
      }
  ] as $joined

| ($joined | length) as $total

# ------------------------------------------------------------
# Classification counts
# ------------------------------------------------------------

| (
    [$joined[]
     | select(.ticket.classification == "true_positive")]
    | length
  ) as $tp

| (
    [$joined[]
     | select(.ticket.classification == "false_positive")]
    | length
  ) as $fp

| (
    [$joined[]
     | select(.ticket.classification == "benign")]
    | length
  ) as $benign

| (
    [$joined[]
     | select(.ticket.classification == "escalated")]
    | length
  ) as $escalated

# Number of tickets actually sent to Tier 2.
| (
    [
      $joined[]
      | select(
          .ticket.recommended_action == "escalate_tier2"
        )
    ]
    | length
  ) as $escalation_count

# ------------------------------------------------------------
# MTTD
#
# alert.generated_at - event_record.timestamp
# for true positives only.
# ------------------------------------------------------------

| (
    [
      $joined[]

      | select(
          .ticket.classification == "true_positive"
        )

      | (.alert.event_record.timestamp | epoch) as $event_time
      | (.alert.generated_at | epoch) as $generated

      | select(
          $event_time != null
          and $generated != null
          and $generated >= $event_time
        )

      | ($generated - $event_time)
    ]
    | median
  ) as $mttd

# ------------------------------------------------------------
# MTTR
#
# ticket.created_at - alert.generated_at
# ------------------------------------------------------------

| (
    [
      $joined[]

      | (.alert.generated_at | epoch) as $generated
      | (.ticket.created_at | epoch) as $closed

      | select(
          $generated != null
          and $closed != null
          and $closed >= $generated
        )

      | ($closed - $generated)
    ]
    | median
  ) as $mttr

# ------------------------------------------------------------
# SLA compliance
# ------------------------------------------------------------

| (
    [
      $joined[]

      | (.alert.priority_band // "low") as $band
      | ($sla[$band] // null) as $budget

      | select(
          $budget != null
          and (.ticket.analyst_time_seconds | type) == "number"
          and .ticket.analyst_time_seconds <= $budget
        )
    ]
    | length
  ) as $within_sla

# ------------------------------------------------------------
# Per-rule metrics
# ------------------------------------------------------------

| (
    $joined
    | sort_by(.rule_id)
    | group_by(.rule_id)

    | map(
        . as $group

        | ($group | length) as $matches

        | (
            [
              $group[]
              | select(
                  .ticket.classification == "true_positive"
                )
            ]
            | length
          ) as $rule_tp

        | (
            [
              $group[]
              | select(
                  .ticket.classification == "false_positive"
                )
            ]
            | length
          ) as $rule_fp

        | {
            key: $group[0].rule_id,

            value: {
              rule_title: $group[0].rule_title,
              matches: $matches,
              true_positive: $rule_tp,
              false_positive: $rule_fp,

              fp_rate:
                (
                  if $matches == 0
                  then 0
                  else ($rule_fp / $matches)
                  end
                )
            }
          }
      )

    | from_entries
  ) as $per_rule

# ------------------------------------------------------------
# Final metrics object
# ------------------------------------------------------------

| {
    shift_start:
      $assessment[0].time_span.first,

    shift_end:
      $assessment[0].time_span.last,

    queue_size:
      $assessment[0].queue_size,

    tickets_total:
      $total,

    tickets_by_classification: {
      true_positive: $tp,
      false_positive: $fp,
      benign: $benign,
      escalated: $escalated
    },

    fp_rate:
      (
        if $total == 0
        then 0
        else ($fp / $total)
        end
      ),

    escalation_ratio:
      (
        if $total == 0
        then 0
        else ($escalation_count / $total)
        end
      ),

    mttd_seconds:
      $mttd,

    mttr_seconds:
      $mttr,

    sla_compliance:
      (
        if $total == 0
        then 0
        else (($within_sla / $total) * 100)
        end
      ),

    per_rule_metrics:
      $per_rule
  }

' "$QUEUE" > "$OUTPUT"

# ------------------------------------------------------------
# Human-readable formatting
# ------------------------------------------------------------

format_time() {
    local seconds="$1"

    if [[ "$seconds" == "null" ]]; then
        echo "n/a"
        return
    fi

    # Median can theoretically contain .5, so round to integer.
    seconds="${seconds%.*}"

    printf "%02d:%02d:%02d" \
        "$((seconds / 3600))" \
        "$(((seconds % 3600) / 60))" \
        "$((seconds % 60))"
}

DATE="$(jq -r '.shift_start[0:10]' "$OUTPUT")"

TOTAL="$(jq -r '.tickets_total' "$OUTPUT")"
TP="$(jq -r '.tickets_by_classification.true_positive' "$OUTPUT")"
FP="$(jq -r '.tickets_by_classification.false_positive' "$OUTPUT")"
BENIGN="$(jq -r '.tickets_by_classification.benign' "$OUTPUT")"
ESCALATED="$(jq -r '.tickets_by_classification.escalated' "$OUTPUT")"

FP_RATE="$(jq -r '.fp_rate' "$OUTPUT")"
ESC_RATIO="$(jq -r '.escalation_ratio' "$OUTPUT")"

MTTD="$(jq -r '.mttd_seconds' "$OUTPUT")"
MTTR="$(jq -r '.mttr_seconds' "$OUTPUT")"

SLA="$(jq -r '.sla_compliance' "$OUTPUT")"

echo "=== SHIFT METRICS $DATE ==="

printf "tickets total         : %s\n" "$TOTAL"
printf "  true_positive       : %2s\n" "$TP"
printf "  false_positive      : %2s\n" "$FP"
printf "  benign              : %2s\n" "$BENIGN"
printf "  escalated           : %2s\n" "$ESCALATED"

printf "fp_rate               : %.3f\n" "$FP_RATE"
printf "escalation_ratio      : %.3f\n" "$ESC_RATIO"

printf "mttd                  : %s\n" \
    "$(format_time "$MTTD")"

printf "mttr                  : %s\n" \
    "$(format_time "$MTTR")"

printf "sla compliance        : %.1f %%\n" "$SLA"

echo "$OUTPUT written"
