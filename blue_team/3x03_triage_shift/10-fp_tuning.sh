#!/bin/bash
set -euo pipefail

INPUT="enriched_queue.json"
OUTPUT="tuning_recommendations.json"

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

# ------------------------------------------------------------
# Find all batch ticket files
# ------------------------------------------------------------

shopt -s nullglob
ticket_files=(tickets/batch[1-7]_*.json)
shopt -u nullglob

if (( ${#ticket_files[@]} == 0 )); then
    echo "ERROR: no batch ticket files found" >&2
    exit 1
fi

# Load every ticket into one array.
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
# Aggregate false positives and build recommendations
# ------------------------------------------------------------

jq --argjson tickets "$TICKETS" '

# Format values as YAML list items.
def yaml_values($values):
    $values
    | map(select(. != null and . != ""))
    | unique
    | map("    - " + (. | @json))
    | join("\n");

def nonempty($values):
    $values
    | map(select(. != null and . != ""))
    | unique;

def first_or($values; $fallback):
    nonempty($values) as $values
    | if ($values | length) > 0
      then $values[0]
      else $fallback
      end;

# owner may be an object or a plain value.
def owner_metadata($asset):
    if (($asset.owner? // null) | type) == "object"
    then $asset.owner
    else {}
    end;

def as_array($value):
    if $value == null then []
    elif ($value | type) == "array" then $value
    else [$value]
    end;

# ------------------------------------------------------------
# Sigma change for each known FP reason
# ------------------------------------------------------------

def proposed_change($reason; $group):

    if $reason == "service_account_activity" then
      nonempty(
        [$group[].service_prefix]
      ) as $values

      | "filter_service_accounts:\n"
        + "  user|startswith:\n"
        + yaml_values($values)
        + "\ncondition: selection and not filter_service_accounts"

    elif $reason == "management_subnet" then
      nonempty(
        [$group[].management_subnets[]?]
      ) as $values

      | "filter_management_subnet:\n"
        + "  src_ip|cidr:\n"
        + yaml_values($values)
        + "\ncondition: selection and not filter_management_subnet"

    elif $reason == "baseline_match" then
      nonempty(
        [$group[].process_name]
      ) as $values

      | "filter_expected_process:\n"
        + "  process_name:\n"
        + yaml_values($values)
        + "\ncondition: selection and not filter_expected_process"

    elif $reason == "unknown_ip_low_asset" then
      "filter_low_asset_hosts:\n"
      + "  hostname:\n"
      + yaml_values(
          nonempty([$group[].hostname])
        )
      + "\ncondition: selection and not filter_low_asset_hosts"

    elif $reason == "baseline_edge_burst" then
      nonempty([$group[].src_ip]) as $ips
      | nonempty([$group[].user]) as $users

      | "filter_baseline_edge_burst:\n"
        + "  src_ip:\n"
        + yaml_values($ips)

        + (
            if ($users | length) > 0
            then
              "\n  user:\n"
              + yaml_values($users)
            else
              ""
            end
          )

        + "\ncondition: selection and not filter_baseline_edge_burst"

    elif $reason ==
         "suspicious_but_baseline_known_elsewhere" then

      nonempty([$group[].process_name]) as $processes
      | nonempty([$group[].dst_ip]) as $ips
      | nonempty([$group[].dst_host]) as $domains

      | if ($processes | length) > 0 then
          "filter_known_elsewhere_process:\n"
          + "  process_name:\n"
          + yaml_values($processes)
          + "\ncondition: selection and not filter_known_elsewhere_process"

        elif ($ips | length) > 0 then
          "filter_known_elsewhere_ip:\n"
          + "  dst_ip:\n"
          + yaml_values($ips)
          + "\ncondition: selection and not filter_known_elsewhere_ip"

        else
          "filter_known_elsewhere_domain:\n"
          + "  dst_host:\n"
          + yaml_values($domains)
          + "\ncondition: selection and not filter_known_elsewhere_domain"
        end

    elif $reason == "test_asset_not_production" then
      "filter_test_assets:\n"
      + "  hostname:\n"
      + yaml_values(
          nonempty([$group[].hostname])
        )
      + "\ncondition: selection and not filter_test_assets"

    elif $reason == "clean_ioc_no_deviation" then

      nonempty([
        $group[].ioc_hits[]?
        | (.indicator // .value // empty)
        | select(
            test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")
          )
      ]) as $ips

      | nonempty([
          $group[].ioc_hits[]?
          | (.indicator // .value // empty)
          | select(
              test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")
              | not
            )
        ]) as $domains

      | if (
          ($ips | length) > 0
          and ($domains | length) > 0
        ) then

          "filter_clean_ip:\n"
          + "  dst_ip:\n"
          + yaml_values($ips)
          + "\nfilter_clean_domain:\n"
          + "  dst_host:\n"
          + yaml_values($domains)
          + "\ncondition: selection and not 1 of filter_clean_*"

        elif ($ips | length) > 0 then

          "filter_clean_ip:\n"
          + "  dst_ip:\n"
          + yaml_values($ips)
          + "\ncondition: selection and not filter_clean_ip"

        else

          "filter_clean_domain:\n"
          + "  dst_host:\n"
          + yaml_values($domains)
          + "\ncondition: selection and not filter_clean_domain"
        end

    else
      "filter_observed_fp_hosts:\n"
      + "  hostname:\n"
      + yaml_values(
          nonempty([$group[].hostname])
        )
      + "\ncondition: selection and not filter_observed_fp_hosts"
    end;

# ------------------------------------------------------------
# False-negative risk note
# ------------------------------------------------------------

def risk_note($reason; $group):

    if $reason == "service_account_activity" then
      first_or(
        [$group[].user];
        "a service account"
      ) as $value

      | "Risk: excluding this pattern could miss a compromised service account such as "
        + $value + "."

    elif $reason == "management_subnet" then
      first_or(
        [$group[].management_subnets[]?];
        "the management subnet"
      ) as $value

      | "Risk: an attacker on a compromised management host inside "
        + $value + " could be suppressed."

    elif $reason == "baseline_match" then
      first_or(
        [$group[].process_name];
        "the expected process"
      ) as $value

      | "Risk: malicious use of the normally expected process "
        + $value + " could become a false negative."

    elif $reason == "baseline_edge_burst" then
      first_or(
        [$group[].src_ip];
        "a known source IP"
      ) as $value

      | "Risk: brute-force activity from a compromised trusted source such as "
        + $value + " could be missed."

    elif $reason ==
         "suspicious_but_baseline_known_elsewhere" then

      first_or(
        [
          $group[].process_name,
          $group[].dst_ip,
          $group[].dst_host
        ];
        "the known value"
      ) as $value

      | "Risk: malicious reuse of "
        + $value
        + " on this host could be hidden because it is normal elsewhere."

    elif $reason == "test_asset_not_production" then
      first_or(
        [$group[].hostname];
        "the test host"
      ) as $value

      | "Risk: a real compromise of test system "
        + $value + " could be suppressed."

    elif $reason == "unknown_ip_low_asset" then
      first_or(
        [$group[].hostname];
        "the low-criticality host"
      ) as $value

      | "Risk: a real compromise of low-criticality host "
        + $value + " could be hidden by this exclusion."

    elif $reason == "clean_ioc_no_deviation" then
      first_or(
        [
          $group[].ioc_hits[]?
          | (.indicator // .value // empty)
        ];
        "the clean IOC"
      ) as $value

      | "Risk: "
        + $value
        + " could later become malicious or be incorrectly reputation-scored as clean."

    else
      "Risk: this exclusion could hide a real attack matching the same observed pattern."
    end;

# ------------------------------------------------------------
# Join FP tickets back to their alerts
# ------------------------------------------------------------

. as $queue

| [
    $tickets[]

    | select(
        .classification == "false_positive"
      )

    | . as $ticket

    | (
        $queue[]
        | select(
            .alert_id == $ticket.alert_id
          )
      ) as $alert

    | owner_metadata(
        $alert.asset // {}
      ) as $owner

    | {
        alert_id:
          $ticket.alert_id,

        fp_reason: (
          $ticket.fp_reason
          // $ticket.override_reason
          // "unspecified"
        ),

        rule_id:
          ($alert.rule_id // "unknown"),

        rule_title: (
          $alert.rule_name
          // $alert.rule_title
          // $alert.rule.name
          // "unknown_rule"
        ),

        service_prefix: (
          $owner.service_account_prefix
          // $alert.asset.service_account_prefix
          // null
        ),

        management_subnets:
          as_array(
            $owner.management_subnets
            // $alert.asset.management_subnets
            // null
          ),

        hostname: (
          $alert.event_summary.hostname
          // $alert.event_record.hostname
          // null
        ),

        user: (
          $alert.event_record.user
          // $alert.event_record.target_user
          // $alert.event_summary.user
          // null
        ),

        process_name:
          ($alert.event_record.process_name // null),

        src_ip: (
          $alert.event_record.src_ip
          // $alert.event_summary.src_ip
          // null
        ),

        dst_ip: (
          $alert.event_record.dst_ip
          // $alert.event_summary.dst_ip
          // null
        ),

        dst_host: (
          $alert.event_record.dst_host
          // $alert.event_summary.dst_host
          // null
        ),

        ioc_hits: (
          $ticket.ioc_hits
          // $alert.ioc_hits
          // []
        )
      }
  ]

# ------------------------------------------------------------
# Group by rule + root cause
# ------------------------------------------------------------

| sort_by(
    .rule_id,
    .fp_reason,
    .alert_id
  )

| group_by(
    .rule_id + "|" + .fp_reason
  )

| map(

    # Avoid counting the same alert twice in one group.
    unique_by(.alert_id)

    # Only systemic patterns: two or more FPs.
    | select(length >= 2)

    | . as $group

    | {
        rule_id:
          $group[0].rule_id,

        rule_title:
          $group[0].rule_title,

        fp_count:
          ($group | length),

        fp_reason:
          $group[0].fp_reason,

        sample_alert_ids: (
          $group
          | map(.alert_id)
          | .[:5]
        ),

        proposed_change:
          proposed_change(
            $group[0].fp_reason;
            $group
          ),

        expected_fp_reduction:
          ($group | length),

        tp_risk_note:
          risk_note(
            $group[0].fp_reason;
            $group
          )
      }
  )

| sort_by(
    -.fp_count,
    .rule_id,
    .fp_reason
  )

' "$INPUT" > "$OUTPUT"

# ------------------------------------------------------------
# Compact summary
# ------------------------------------------------------------

echo "tuning recommendations"

jq -r '
  .[]
  | [
      .rule_id,
      .rule_title,
      (.fp_count | tostring),
      .fp_reason
    ]
  | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r rule_id rule_title count reason; do
    printf "  %-4s %-32s fp=%-2s reason=%s\n" \
        "$rule_id" \
        "$rule_title" \
        "$count" \
        "$reason"
done

COUNT="$(jq 'length' "$OUTPUT")"

printf "recommendations written : %s\n" "$COUNT"
echo "$OUTPUT"
