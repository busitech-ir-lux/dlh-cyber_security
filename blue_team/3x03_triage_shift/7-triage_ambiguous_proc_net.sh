#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

INPUT="enriched_queue.json"
IOCS="$ASSETS_DIR/ioc_context.json"
OUTPUT="tickets/batch5_proc_net.json"

mkdir -p tickets

for file in "$INPUT" "$IOCS"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Get alerts already handled in batches 1-4.
# ------------------------------------------------------------

shopt -s nullglob
handled_files=(
    tickets/batch1_*.json
    tickets/batch2_*.json
    tickets/batch3_*.json
    tickets/batch4_*.json
)
shopt -u nullglob

if (( ${#handled_files[@]} > 0 )); then
    HANDLED="$(jq -s '[.[][] | .alert_id] | unique' "${handled_files[@]}")"
else
    HANDLED='[]'
fi

# ------------------------------------------------------------
# Triage process and network alerts.
# ------------------------------------------------------------

jq \
    --argjson handled "$HANDLED" \
    --slurpfile iocs "$IOCS" '

# Turn a value into an array.
def values($v):
    if $v == null then []
    elif ($v | type) == "array" then $v
    else [$v]
    end;

# Determine the rule category.
def rule_category:
    .rule_category
    // .category
    // .rule.category
    // (
        if (.rule_id == "003"
            or .rule_id == "004"
            or .rule_id == "005")
        then "process"

        elif (.rule_id == "007"
              or .rule_id == "008"
              or .rule_id == "012")
        then "network"

        else "unknown"
        end
    );

# Does a value appear in a baseline profile?
def baseline_has($profile; $value):
    if $profile == null or $value == null then
        false
    else
        (
          [$profile | .. | scalars]
          | index($value)
        ) != null
    end;

# Check whether the value is normal on another host.
def known_elsewhere($queue; $current_host; $value):
    any(
        $queue[];
        (
          (
            .event_summary.hostname
            // .event_record.hostname
            // ""
          ) != $current_host

          and

          baseline_has(
              .baseline_host_profile;
              $value
          )
        )
    );

# Create IOC records directly from ioc_context.json.
def lookup_iocs($indicators):
    [
      $indicators[] as $indicator

      | select($iocs[0][$indicator]? != null)

      | {
          indicator: $indicator
        }
        + $iocs[0][$indicator]
        + {
            ioc_flag:
              ($iocs[0][$indicator].reputation != "clean")
          }
    ];

# Build evidence reference list.
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
      )
    ]
    | map(select(. != null and . != ""))
    | unique;

. as $queue

| [
    .[] as $alert

    # Skip alerts already processed.
    | select(($handled | index($alert.alert_id)) == null)

    | ($alert | rule_category) as $category
    | select(
        $category == "process"
        or $category == "network"
      )

    | (
        $alert.event_summary.hostname
        // $alert.event_record.hostname
        // ""
      ) as $host

    | (
        ($alert.asset.criticality // "low")
        | ascii_downcase
      ) as $criticality

    # --------------------------------------------------------
    # Process information
    # --------------------------------------------------------

    | ($alert.event_record.process_name // null) as $process
    | ($alert.event_record.parent_process // null) as $parent
    | ($alert.event_record.command_line // null) as $command

    # --------------------------------------------------------
    # Network destination information
    # --------------------------------------------------------

    | (
        values(
          $alert.event_record.dst_ip
          // $alert.event_summary.dst_ip
        )
      ) as $dst_ips

    | (
        values(
          $alert.event_record.dst_host
          // $alert.event_summary.dst_host
        )
      ) as $dst_hosts

    | (
        values(
          $alert.event_record.dst_port
          // $alert.event_summary.dst_port
        )
      ) as $dst_ports

    | ($dst_ips + $dst_hosts) as $indicators

    # Network alerts explicitly look destinations up
    # in ioc_context.json.
    | (
        if $category == "network" then
          (
            ($alert.ioc_hits // [])
            + lookup_iocs($indicators)
          )
          | unique_by(.indicator)
        else
          ($alert.ioc_hits // [])
        end
      ) as $ioc_hits

    # --------------------------------------------------------
    # Baseline checks
    # --------------------------------------------------------

    | (
        if $category == "process" then
          baseline_has(
              $alert.baseline_host_profile;
              $process
          )

        else
          (
            ($dst_ips + $dst_hosts + $dst_ports) as $destinations

            | ($destinations | length) > 0
              and
              all(
                  $destinations[];
                  baseline_has(
                      $alert.baseline_host_profile;
                      .
                  )
              )
          )
        end
      ) as $baseline_match

    # Check whether process/destination is known on another host.
    | (
        if $category == "process" then
          known_elsewhere(
              $queue;
              $host;
              $process
          )

        else
          any(
              ($dst_ips + $dst_hosts)[];
              known_elsewhere(
                  $queue;
                  $host;
                  .
              )
          )
        end
      ) as $known_elsewhere

    | any(
        $ioc_hits[];
        .reputation == "malicious"
      ) as $malicious

    | any(
        $ioc_hits[];
        .reputation == "suspicious"
      ) as $suspicious

    | (
        ($ioc_hits | length) > 0
        and
        all(
            $ioc_hits[];
            .reputation == "clean"
        )
      ) as $all_clean

    # --------------------------------------------------------
    # Decision tree
    # --------------------------------------------------------

    | (
        if $malicious then
          {
            class: "true_positive",
            action: "escalate_tier2",
            reason: null,
            text:
              "At least one IOC has reputation=malicious."
          }

        elif (
          $suspicious
          and (
            $criticality == "critical"
            or $criticality == "high"
          )
        ) then
          {
            class: "true_positive",
            action: "monitor",
            reason: null,
            text: (
              "IOC reputation=suspicious and "
              + "asset.criticality="
              + $criticality
              + "."
            )
          }

        elif (
          $suspicious
          and (
            $criticality == "medium"
            or $criticality == "low"
          )
          and $known_elsewhere
        ) then
          {
            class: "false_positive",
            action: "tune_rule",
            reason:
              "suspicious_but_baseline_known_elsewhere",
            text: (
              "IOC reputation=suspicious, "
              + "asset.criticality="
              + $criticality
              + ", and the process or destination "
              + "appears in another host baseline."
            )
          }

        elif (
          $all_clean
          and $baseline_match
        ) then
          {
            class: "false_positive",
            action: "tune_rule",
            reason: "clean_ioc_no_deviation",
            text:
              "All IOC hits have reputation=clean and the event matches the host baseline."
          }

        else
          {
            class: "true_positive",
            action: "monitor",
            reason: null,

            text: (
              if $category == "process" then
                "Ambiguous process alert: process_name="
                + ($process // "null")
                + ", parent_process="
                + ($parent // "null")
                + ", command_line="
                + ($command // "null")
                + ", asset.criticality="
                + $criticality
                + ", baseline_match="
                + ($baseline_match | tostring)
                + ", ioc_hits="
                + (($ioc_hits | length) | tostring)
                + "."

              else
                "Ambiguous network alert: dst_ip="
                + ($dst_ips | join(","))
                + ", dst_host="
                + ($dst_hosts | join(","))
                + ", dst_port="
                + ($dst_ports | map(tostring) | join(","))
                + ", asset.criticality="
                + $criticality
                + ", baseline_match="
                + ($baseline_match | tostring)
                + ", ioc_hits="
                + (($ioc_hits | length) | tostring)
                + "."
              end
            )
          }
        end
      ) as $decision

    # --------------------------------------------------------
    # Ticket
    # --------------------------------------------------------

    | {
        ticket_id:
          ("ticket_" + $alert.alert_id),

        alert_id:
          $alert.alert_id,

        classification:
          $decision.class,

        justification:
          $decision.text,

        evidence_refs:
          ($alert | evidence_refs),

        ioc_hits:
          $ioc_hits,

        attack_techniques: (
          $alert.attack_techniques
          // $alert.rule.attack_techniques
          // []
        ),

        recommended_action:
          $decision.action,

        analyst_time_seconds: (
          $alert.analyst_time_seconds
          // $alert.runner_metadata.analyst_time_seconds
          // 120
        ),

        created_at: (
          $alert.runner_metadata.created_at
          // $alert.event_summary.timestamp
          // $alert.event_record.timestamp
        )
      }

      + if $decision.reason != null
        then {
          fp_reason: $decision.reason
        }
        else {}
        end
  ]
' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

echo "batch 5 ambiguous process and network"

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
