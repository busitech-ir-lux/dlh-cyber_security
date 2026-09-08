#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

INPUT="enriched_queue.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
OUTPUT="tickets/batch3_benign.json"

mkdir -p tickets

for file in "$INPUT" "$EVENTS"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Alerts already handled in batches 1 and 2
# ------------------------------------------------------------

shopt -s nullglob
handled_files=(tickets/batch1_*.json tickets/batch2_*.json)
shopt -u nullglob

if (( ${#handled_files[@]} > 0 )); then
    HANDLED="$(jq -s '[.[][] | .alert_id] | unique' "${handled_files[@]}")"
else
    HANDLED='[]'
fi

# ------------------------------------------------------------
# Find benign alerts and create tickets
# ------------------------------------------------------------

jq \
    --argjson handled "$HANDLED" \
    --slurpfile events "$EVENTS" '

# Support JSON array or NDJSON event store.
def event_list:
    if (
      ($events | length) == 1
      and ($events[0] | type) == "array"
    )
    then $events[0]
    else $events
    end;

def epoch:
    try fromdateiso8601 catch null;

# Get the taxonomy/event label.
def event_label:
    .event_label
    // .event_type
    // .taxonomy
    // .label
    // .event_name
    // "";

# ------------------------------------------------------------
# Benign pattern 1:
# one failed login followed by success within 60 seconds
# ------------------------------------------------------------

def fail_then_success($alert):
    ($alert.event_record.user
      // $alert.event_summary.user) as $user

    | ($alert.event_record.hostname
      // $alert.event_summary.hostname) as $host

    | ($alert.event_record.timestamp
      // $alert.event_summary.timestamp) as $time

    | ($time | epoch) as $start

    | (
        ($alert.event_record | event_label)
        == "login_failure"
      )

    and

    any(
      event_list[];

      (
        (event_label == "login_success")
        and (.user == $user)
        and (.hostname == $host)

        and

        ((.timestamp | epoch) as $success
         | $start != null
         and $success != null
         and $success >= $start
         and ($success - $start) <= 60)
      )
    );

# ------------------------------------------------------------
# Benign pattern 2: DHCP renewal
# ------------------------------------------------------------

def dhcp_renewal($alert):
    $alert.event_record as $event

    | (
        (($event.protocol // "") | ascii_downcase) == "dhcp"
        and
        (
          (($event.action // "") | ascii_downcase)
          | test("renew")
        )
      )

      or

      (
        (($event.message // $event.raw_message // "")
          | ascii_downcase)
        | test("dhcp.*renew|renew.*dhcp")
      );

# ------------------------------------------------------------
# Benign pattern 3: NTP drift below 500 ms
# ------------------------------------------------------------

def ntp_drift($alert):
    $alert.event_record as $event

    | (
        (($event.protocol // $event.event_type // "")
          | ascii_downcase)
        | contains("ntp")
      )

    and

    (
      ($event.delta_ms // $event.delta // null) as $delta
      | $delta != null
      and $delta < 500
    );

# ------------------------------------------------------------
# Benign pattern 4:
# external SMB scan blocked by firewall
# ------------------------------------------------------------

def perimeter_smb_block($alert):
    $alert.event_record as $event

    | (
        ($event.dst_port // 0) == 445
      )

    and

    (
      (($event.action
        // $event.firewall_action
        // "")
        | ascii_downcase)
      | test("block|blocked|drop|dropped|deny|denied")
    )

    and

    (
      (($event.src_zone
        // $event.source_zone
        // "")
        | ascii_downcase)
      | test("external|perimeter|internet")
    );

# Evidence refs required by the project.
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

[
  .[] as $alert

  # Do not process tickets already handled.
  | select(
      ($handled | index($alert.alert_id)) == null
    )

  # Work out which benign pattern matched.
  | (
      if fail_then_success($alert) then
        "single_fail_then_success"

      elif dhcp_renewal($alert) then
        "dhcp_renewal"

      elif ntp_drift($alert) then
        "ntp_drift_under_threshold"

      elif perimeter_smb_block($alert) then
        "perimeter_smb_block"

      elif $alert.priority_band == "low" then
        "low_priority_activity"

      else
        null
      end
    ) as $reason

  | select($reason != null)

  | {
      ticket_id:
        ("ticket_" + $alert.alert_id),

      alert_id:
        $alert.alert_id,

      classification:
        "benign",

      justification:
        (
          if $reason == "single_fail_then_success" then
            "Benign pattern single_fail_then_success: login_failure was followed by login_success for the same user and host within 60 seconds."

          elif $reason == "dhcp_renewal" then
            "Benign pattern dhcp_renewal: the event is a normal DHCP renewal."

          elif $reason == "ntp_drift_under_threshold" then
            "Benign pattern ntp_drift_under_threshold: NTP delta is below 500 ms."

          elif $reason == "perimeter_smb_block" then
            "Benign pattern perimeter_smb_block: external SMB traffic to dst_port=445 was blocked by the firewall."

          else
            "Benign low-priority activity: priority_band=low."
          end
        ),

      evidence_refs:
        ($alert | evidence_refs),

      ioc_hits:
        ($alert.ioc_hits // []),

      attack_techniques: (
        $alert.attack_techniques
        // $alert.rule.attack_techniques
        // []
      ),

      recommended_action:
        "close",

      analyst_time_seconds: (
        $alert.analyst_time_seconds
        // $alert.runner_metadata.analyst_time_seconds
        // 30
      ),

      created_at: (
        $alert.runner_metadata.created_at
        // $alert.event_summary.timestamp
        // $alert.event_record.timestamp
      ),

      benign_reason:
        $reason
    }
]
' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

echo "batch 3 benign"

jq -r --slurpfile queue "$INPUT" '
  .[] as $ticket

  | (
      $queue[0][]
      | select(.alert_id == $ticket.alert_id)
    ) as $alert

  | [
      $ticket.alert_id,
      ($alert.priority_band // "-"),
      $ticket.benign_reason
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r alert_id priority reason; do
    printf "  %-12s %-5s %s\n" \
        "$alert_id" \
        "$priority" \
        "$reason"
done

COUNT="$(jq 'length' "$OUTPUT")"

printf "batch size               : %s\n" "$COUNT"
printf "tickets written          : %s\n" "$COUNT"
echo "$OUTPUT"
