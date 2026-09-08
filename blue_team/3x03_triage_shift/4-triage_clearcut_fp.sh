#!/bin/bash
set -euo pipefail

INPUT="enriched_queue.json"
OUTPUT="tickets/batch2_clearcut_fp.json"

mkdir -p tickets

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

# ------------------------------------------------------------
# Check whether an IPv4 address belongs to a CIDR subnet.
# Example: ip_in_subnet 10.10.1.5 10.10.1.0/24
# ------------------------------------------------------------
ip_to_int() {
    local ip="$1"
    local a b c d

    IFS=. read -r a b c d <<< "$ip"

    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_in_subnet() {
    local ip="$1"
    local cidr="$2"
    local network="${cidr%/*}"
    local bits="${cidr#*/}"

    local ip_int
    local net_int
    local mask

    ip_int="$(ip_to_int "$ip")"
    net_int="$(ip_to_int "$network")"

    if (( bits == 0 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    fi

    (( (ip_int & mask) == (net_int & mask) ))
}

# Start with an empty JSON array.
echo '[]' > "$OUTPUT"

echo "batch 2 clear-cut false positives"

# ------------------------------------------------------------
# Process alerts one by one.
# ------------------------------------------------------------
while IFS= read -r alert; do

    alert_id="$(jq -r '.alert_id' <<< "$alert")"
    rule_id="$(jq -r '.rule_id // "-"' <<< "$alert")"
    rule_name="$(jq -r '.rule_name // .rule_title // "-"' <<< "$alert")"

    # Determine rule category.
    category="$(jq -r '
        .rule_category
        // .category
        // .rule.category
        // empty
    ' <<< "$alert")"

    if [[ -z "$category" ]]; then
        case "$rule_id" in
            001|002|009|013) category="auth" ;;
            003|004|005)     category="process" ;;
            006|011)         category="file" ;;
            007|008|012)     category="network" ;;
            010)             category="correlation" ;;
            *)               category="unknown" ;;
        esac
    fi

    user="$(jq -r '
        .event_record.user
        // .event_record.target_user
        // .event_record.username
        // empty
    ' <<< "$alert")"

    process_name="$(jq -r '
        .event_record.process_name // empty
    ' <<< "$alert")"

    src_ip="$(jq -r '
        .event_record.src_ip
        // .event_summary.src_ip
        // empty
    ' <<< "$alert")"

    service_prefix="$(jq -r '
        .asset.owner.service_account_prefix
        // .asset.service_account_prefix
        // empty
    ' <<< "$alert" 2>/dev/null || true)"

    reason=""
    justification=""

    # --------------------------------------------------------
    # 1. Authorized service-account activity
    # --------------------------------------------------------
    if [[ -n "$service_prefix" &&
          -n "$user" &&
          "$user" == "$service_prefix"* &&
          ( "$category" == "auth" || "$category" == "process" ) ]]; then

        reason="service_account_activity"
        justification="user=$user matches authorized service account prefix=$service_prefix."

    fi

    # --------------------------------------------------------
    # 2. Source IP belongs to a management subnet
    # --------------------------------------------------------
    if [[ -z "$reason" && "$category" == "network" && -n "$src_ip" ]]; then

        while IFS= read -r subnet; do
            [[ -z "$subnet" ]] && continue

            if ip_in_subnet "$src_ip" "$subnet"; then
                reason="management_subnet"
                justification="src_ip=$src_ip is inside authorized management_subnets range=$subnet."
                break
            fi

        done < <(
            jq -r '
                (
                    .asset.owner.management_subnets
                    // .asset.management_subnets
                    // []
                )[]
            ' <<< "$alert" 2>/dev/null
        )
    fi

    # --------------------------------------------------------
    # 3. Process exists in process.expected baseline
    # --------------------------------------------------------
    if [[ -z "$reason" && -n "$process_name" ]]; then

        if jq -e --arg process "$process_name" '
            (
                .baseline_host_profile.process.expected
                // .baseline_host_profile.expected
                // []
            )
            | index($process) != null
        ' <<< "$alert" >/dev/null; then

            reason="baseline_match"
            justification="process_name=$process_name appears in baseline_host_profile.process.expected."
        fi
    fi

    # --------------------------------------------------------
    # 4. Every IOC is clean and there is no baseline deviation
    # --------------------------------------------------------
    if [[ -z "$reason" ]]; then

        if jq -e '
            def category:
                .rule_category
                // .category
                // .rule.category
                // (
                    if (.rule_id == "001" or
                        .rule_id == "002" or
                        .rule_id == "009" or
                        .rule_id == "013")
                    then "auth"

                    elif (.rule_id == "003" or
                          .rule_id == "004" or
                          .rule_id == "005")
                    then "process"

                    elif (.rule_id == "006" or
                          .rule_id == "011")
                    then "file"

                    elif (.rule_id == "007" or
                          .rule_id == "008" or
                          .rule_id == "012")
                    then "network"

                    else "unknown"
                    end
                );

            def baseline_has($value):
                [
                    .baseline_host_profile
                    | .. | scalars
                ]
                | index($value) != null;

            (.ioc_hits | length) > 0

            and

            all(
                .ioc_hits[];
                .reputation == "clean"
            )

            and

            (
                category as $cat

                | if $cat == "auth" then
                    (
                        (.event_record.user // null) as $user
                        | (.event_record.src_ip // null) as $ip
                        | ($user == null or baseline_has($user))
                        and
                          ($ip == null or baseline_has($ip))
                    )

                  elif $cat == "process" then
                    (
                        (.event_record.process_name // null) as $process
                        | $process != null
                        and baseline_has($process)
                    )

                  elif $cat == "network" then
                    (
                        (.event_record.dst_ip // null) as $ip
                        | (.event_record.dst_port // null) as $port
                        | ($ip == null or baseline_has($ip))
                        and
                          ($port == null or baseline_has($port))
                    )

                  elif $cat == "file" then
                    (
                        (
                            .event_record.file_path
                            // .event_record.path
                            // null
                        ) as $path
                        | $path != null
                        and baseline_has($path)
                    )

                  else
                    false
                  end
            )
        ' <<< "$alert" >/dev/null; then

            indicator="$(jq -r '
                .ioc_hits[0].indicator // "matched IOC"
            ' <<< "$alert")"

            reason="clean_ioc_no_deviation"
            justification="IOC=$indicator has reputation=clean and the event matches the host baseline."
        fi
    fi

    # Alert did not match any clear FP signature.
    [[ -z "$reason" ]] && continue

    # --------------------------------------------------------
    # Build ticket
    # --------------------------------------------------------
    ticket="$(jq \
        --arg reason "$reason" \
        --arg justification "$justification" '
        {
            ticket_id: ("ticket_" + .alert_id),
            alert_id: .alert_id,
            classification: "false_positive",
            justification: $justification,

            evidence_refs: (
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
                | map(select(. != null))
                | unique
            ),

            ioc_hits: (.ioc_hits // []),

            attack_techniques: (
                .attack_techniques
                // .rule.attack_techniques
                // []
            ),

            recommended_action: "tune_rule",

            analyst_time_seconds: (
                .analyst_time_seconds
                // .runner_metadata.analyst_time_seconds
                // 60
            ),

            created_at: (
                .runner_metadata.created_at
                // .event_summary.timestamp
                // .event_record.timestamp
            ),

            fp_reason: $reason
        }
    ' <<< "$alert")"

    # Append ticket to output array.
    jq --argjson ticket "$ticket" \
        '. + [$ticket]' "$OUTPUT" > "$OUTPUT.tmp"

    mv "$OUTPUT.tmp" "$OUTPUT"

    printf "  %-12s %-4s %-30s CLOSE  %s\n" \
        "$alert_id" \
        "$rule_id" \
        "$rule_name" \
        "$reason"

done < <(jq -c '.[]' "$INPUT")

# ------------------------------------------------------------
# Final summary
# ------------------------------------------------------------

COUNT="$(jq 'length' "$OUTPUT")"

printf "batch size               : %s\n" "$COUNT"
printf "tickets written          : %s\n" "$COUNT"
echo "$OUTPUT"
