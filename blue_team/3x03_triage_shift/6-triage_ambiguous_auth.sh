#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

INPUT="enriched_queue.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
OUTPUT="tickets/batch4_auth.json"

mkdir -p tickets

for file in "$INPUT" "$BASELINE" "$EVENTS"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# Alerts already processed in batches 1-3.
shopt -s nullglob
handled_files=(tickets/batch1_*.json tickets/batch2_*.json tickets/batch3_*.json)
shopt -u nullglob

if (( ${#handled_files[@]} > 0 )); then
    HANDLED="$(jq -s '[.[][] | .alert_id] | unique' "${handled_files[@]}")"
else
    HANDLED='[]'
fi

jq \
    --argjson handled "$HANDLED" \
    --slurpfile baseline "$BASELINE" \
    --slurpfile events "$EVENTS" '

# Support JSON array or NDJSON events.
def all_events:
    if (($events | length) == 1 and ($events[0] | type) == "array")
    then $events[0]
    else $events
    end;

# Find this users authentication baseline.
def user_profile($user):
    $baseline[0].authentication.users[$user]
    // (
        [
          $baseline[0]
          | .. | objects
          | select((.user? // .username? // "") == $user)
        ][0]
      )
    // {};

def recent_auth($user; $time):
    [
      all_events[]
      | select(.event_category == "authentication")
      | select(.user == $user)
      | select((.timestamp // "") <= $time)
    ]
    | sort_by(.timestamp)
    | reverse
    | .[:20];

def auth_failure:
    ((.event_id // "") | tostring) == "4625"
    or (
      (.raw_message // "")
      | test("failed password|authentication failure|res=failed"; "i")
    );

def epoch($time):
    try ($time | fromdateiso8601) catch null;

def auth_rule:
    (.rule_category? == "auth")
    or (.rule_category? == "authentication")
    or (.category? == "auth")
    or (.category? == "authentication")
    or (
      .rule_id as $id
      | ["001", "002", "009", "013"]
      | index($id) != null
    );

[
  .[] as $alert

  # Skip alerts already processed.
  | select(($handled | index($alert.alert_id)) == null)
  | select($alert | auth_rule)

  | (
      $alert.event_record.user
      // $alert.event_summary.user
      // null
    ) as $user

  | (
      $alert.event_record.src_ip
      // $alert.event_summary.src_ip
      // null
    ) as $src_ip

  | (
      $alert.event_summary.hostname
      // $alert.event_record.hostname
      // null
    ) as $host

  | (
      $alert.event_summary.timestamp
      // $alert.event_record.timestamp
    ) as $time

  | (($alert.asset.criticality // "low") | ascii_downcase) as $criticality

  # Historical user context.
  | user_profile($user) as $profile
  | ($profile.source_ips // $profile.known_source_ips // []) as $known_ips
  | ($profile.hosts // $profile.host_set // $profile.known_hosts // []) as $known_hosts
  | ($profile.login_times // []) as $login_times

  # Last twenty authentication events.
  | recent_auth($user; $time) as $recent

  | ($src_ip != null and (($known_ips | index($src_ip)) == null)) as $unknown_ip
  | ($src_ip != null and (($known_ips | index($src_ip)) != null)) as $known_ip
  | ($host != null and (($known_hosts | index($host)) != null)) as $host_seen

  # Baseline threshold.
  | (
      $alert.baseline_host_profile.authentication.max_failures_1h_window
      // $alert.baseline_host_profile.max_failures_1h_window
      // $profile.max_failures_1h_window
      // null
    ) as $max_failures

  # Failed authentications during the previous hour.
  | epoch($time) as $end
  | (
      [
        $recent[]
        | select(auth_failure)
        | epoch(.timestamp) as $t
        | select(
            $end != null
            and $t != null
            and $t >= ($end - 3600)
            and $t <= $end
          )
      ]
      | length
    ) as $burst

  | ($alert.ioc_hits // []) as $iocs

  # ----------------------------------------------------------
  # Decision tree
  # ----------------------------------------------------------

  | (
      if (
        $unknown_ip
        and ($criticality == "critical" or $criticality == "high")
        and ($host_seen | not)
      ) then
        {
          class: "true_positive",
          action: "escalate_tier2",
          reason: null,
          text: (
            "src_ip=" + ($src_ip | tostring)
            + " is unknown, hostname=" + ($host | tostring)
            + " is not in the user host baseline, and asset.criticality="
            + $criticality + "."
          )
        }

      elif (
        $unknown_ip
        and ($criticality == "medium" or $criticality == "low")
        and (($iocs | length) == 0)
      ) then
        {
          class: "false_positive",
          action: "tune_rule",
          reason: "unknown_ip_low_asset",
          text: (
            "src_ip=" + ($src_ip | tostring)
            + " is unknown, but asset.criticality="
            + $criticality + " and ioc_hits=0."
          )
        }

      elif (
        $known_ip
        and $max_failures != null
        and $burst >= $max_failures
        and $burst <= ($max_failures * 2)
      ) then
        {
          class: "false_positive",
          action: "tune_rule",
          reason: "baseline_edge_burst",
          text: (
            "src_ip=" + ($src_ip | tostring)
            + " is known and failure_burst=" + ($burst | tostring)
            + " is between max_failures_1h_window="
            + ($max_failures | tostring)
            + " and twice that value."
          )
        }

      else
        {
          class: "true_positive",
          action: "monitor",
          reason: null,
          text: (
            "Ambiguous authentication: src_ip=" + ($src_ip | tostring)
            + ", source_ip_known=" + ($known_ip | tostring)
            + ", hostname=" + ($host | tostring)
            + ", host_seen=" + ($host_seen | tostring)
            + ", failure_burst=" + ($burst | tostring)
            + ", max_failures_1h_window=" + ($max_failures | tostring)
            + ", ioc_hits=" + (($iocs | length) | tostring)
            + ", historical_login_times="
            + (($login_times | length) | tostring) + "."
          )
        }
      end
    ) as $decision

  # ----------------------------------------------------------
  # Ticket
  # ----------------------------------------------------------

  | {
      ticket_id: ("ticket_" + $alert.alert_id),
      alert_id: $alert.alert_id,
      classification: $decision.class,
      justification: $decision.text,

      evidence_refs: (
        [
          $alert.event_ref,
          ($recent[] | .record_id // .event_ref // empty)
        ]
        | map(select(. != null and . != ""))
        | unique
      ),

      ioc_hits: $iocs,

      attack_techniques: (
        $alert.attack_techniques
        // $alert.rule.attack_techniques
        // []
      ),

      recommended_action: $decision.action,

      analyst_time_seconds: (
        $alert.analyst_time_seconds
        // $alert.runner_metadata.analyst_time_seconds
        // 120
      ),

      created_at: (
        $alert.runner_metadata.created_at
        // $time
      )
    }

    + if $decision.reason != null
      then {fp_reason: $decision.reason}
      else {}
      end
]
' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

echo "batch 4 ambiguous authentication"

jq -r --slurpfile queue "$INPUT" '
  .[] as $ticket
  | ($queue[0][] | select(.alert_id == $ticket.alert_id)) as $alert
  | [
      $ticket.alert_id,
      ($alert.rule_id // "-"),
      ($alert.rule_name // $alert.rule_title // "-"),
      $ticket.classification,
      (
        if $ticket.recommended_action == "escalate_tier2"
        then "escalate"
        else $ticket.recommended_action
        end
      )
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r alert_id rule_id rule_name classification action; do
    printf "  %-12s %-4s %-32s %-16s %s\n" \
        "$alert_id" \
        "$rule_id" \
        "$rule_name" \
        "$classification" \
        "$action"
done

COUNT="$(jq 'length' "$OUTPUT")"

printf "batch size               : %s\n" "$COUNT"
printf "tickets written          : %s\n" "$COUNT"
echo "$OUTPUT"
