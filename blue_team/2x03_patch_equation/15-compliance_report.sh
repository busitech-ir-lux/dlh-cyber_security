#!/bin/bash
#
# Name:        15-compliance_report.sh
# Purpose:     Produce a canonical change log from apt history logs and prior
#              task artifacts, enriched with maintenance window and CVE data
# Author:      Mahdi Hamidi
# Date:        August 11, 2026
#

set -euo pipefail

readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly INVENTORY="${BASE_DIR}/vulnerability_inventory.json"
readonly CHANGE_LOG="${BASE_DIR}/patch_change_log.json"
readonly HOLD_MANAGEMENT="${BASE_DIR}/hold_management.json"
readonly PIPELINE_RUN="${BASE_DIR}/pipeline_run.json"
readonly HISTORY_DIR="${BASE_DIR}/history"
readonly OUTPUT_FILE="${BASE_DIR}/patch_compliance.json"
readonly TARGET_SCORE="95.00"
readonly OVERDUE_DAYS=7
readonly OVERDUE_SECONDS=$((OVERDUE_DAYS * 24 * 60 * 60))

TMP_DIR=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_command() {
    local command_name="$1"
    command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
}

validate_json_file() {
    local file="$1"
    [[ -s "$file" ]] || fail "required JSON file missing or empty: $file"
    jq empty "$file" >/dev/null 2>&1 || fail "invalid JSON: $file"
}


main() {
    local generated_at hostname_value kernel_value clock_timestamp clock_epoch
    local resolved_count open_count held_count window_count overdue_count
    local total_ch resolved_ch score score_display verdict_exit
    local inventory_file first_seen first_seen_epoch state severity
    local -a inventory_files

    for cmd in jq date hostname uname find sort mktemp awk mv; do
        require_command "$cmd"
    done

    validate_json_file "$INVENTORY"
    validate_json_file "$CHANGE_LOG"
    validate_json_file "$HOLD_MANAGEMENT"
    validate_json_file "$PIPELINE_RUN"

    jq -e '(.generated_at | type == "string") and (.packages | type == "array")' \
        "$INVENTORY" >/dev/null 2>&1 || fail "unexpected vulnerability_inventory.json schema"
    jq -e '(.events | type == "array") and ((.period_end == null) or (.period_end | type == "string"))' \
        "$CHANGE_LOG" >/dev/null 2>&1 || fail "unexpected patch_change_log.json schema"
    jq -e '(.applied | type == "array")' \
        "$HOLD_MANAGEMENT" >/dev/null 2>&1 || fail "unexpected hold_management.json schema"
    jq -e '(.pipeline_status | type == "string")' \
        "$PIPELINE_RUN" >/dev/null 2>&1 || fail "unexpected pipeline_run.json schema"

    TMP_DIR=$(mktemp -d)

    # Current inventory is authoritative for whether a CVE still affects the host.
    # Historical snapshots are used to discover CVEs that have disappeared from
    # the current inventory and to establish first_seen.
    inventory_files=("$INVENTORY")
    if [[ -d "$HISTORY_DIR" ]]; then
        while IFS= read -r inventory_file; do
            [[ "$inventory_file" == "$INVENTORY" ]] && continue
            validate_json_file "$inventory_file"
            jq -e '(.generated_at | type == "string") and (.packages | type == "array")' \
                "$inventory_file" >/dev/null 2>&1 || \
                fail "historical inventory has an unexpected schema: $inventory_file"
            inventory_files+=("$inventory_file")
        done < <(
            find "$HISTORY_DIR" -type f \
                \( -name 'vulnerability_inventory*.json' -o -name 'vulnerability_inventory.json.*' \) \
                -print | sort
        )
    fi

    # Build one record per unique CVE ever observed. Because the upstream
    # inventory is package-centric, package is a comma-separated string if the
    # same CVE is associated with multiple packages in its latest/current view.
    cat > "${TMP_DIR}/build_cves.jq" <<'JQ'
def severity_rank:
  (ascii_downcase) as $s |
  if $s == "critical" then 4
  elif $s == "high" then 3
  elif $s == "medium" then 2
  elif $s == "low" then 1
  else 0
  end;

def current_packages($id):
  [$current[0].packages[]? |
   select(any(.cves[]?; . == $id)) |
   .package] | unique | sort;

[ .[] as $inv |
  $inv.packages[]? as $pkg |
  $pkg.cves[]? |
  {
    id: .,
    package: ($pkg.package // "unknown"),
    severity: (($pkg.severity // "none") | ascii_downcase),
    seen_at: ($inv.generated_at // null)
  }
]
| sort_by(.id)
| group_by(.id)
| map(
    . as $obs |
    ($obs[0].id) as $id |
    (current_packages($id)) as $current_pkgs |
    ([$obs[] | select(.seen_at != null) | .seen_at] | min // null) as $first_seen |
    ([$obs[] | select(.seen_at != null) | .seen_at] | max // null) as $last_seen |
    ([$obs[] | . + {rank: (.severity | severity_rank)}]
      | sort_by(.rank)
      | last) as $highest |
    ([$obs[] | select(.seen_at == $last_seen) | .package] | unique | sort) as $latest_pkgs |
    {
      id: $id,
      package: ((if ($current_pkgs | length) > 0 then $current_pkgs else $latest_pkgs end) | join(", ")),
      current_packages: $current_pkgs,
      severity: ($highest.severity // "none"),
      first_seen: $first_seen,
      last_seen: $last_seen,
      in_current: (($current_pkgs | length) > 0)
    }
  )
| sort_by(.id)
JQ

    jq -s \
        --slurpfile current "$INVENTORY" \
        -f "${TMP_DIR}/build_cves.jq" \
        "${inventory_files[@]}" > "${TMP_DIR}/cve_base.json"

    # Resolve state from the current inventory, active holds, the latest
    # pipeline result, and historical patch events.
    jq \
        --slurpfile holds "$HOLD_MANAGEMENT" \
        --slurpfile pipeline "$PIPELINE_RUN" \
        --slurpfile changes "$CHANGE_LOG" \
        '
        def package_base:
          split(":")[0];

        def hold_for($pkg):
          [$holds[0].applied[]?
           | select(.package == $pkg or ((.package | package_base) == ($pkg | package_base)))];

        def resolved_at_for($id):
          [ $changes[0].events[]?
            | select(any(.cves_resolved[]?; . == $id))
            | (.ended // .started // empty)
          ] | last // null;

        def hold_reasons($packages):
          [ $packages[] as $p
            | hold_for($p)[]?
            | (($p + ": " + (.reason // "held by version policy")))
          ] | unique;

        map(
          . as $cve |
          (hold_reasons($cve.current_packages)) as $hold_reasons |
          ([ $cve.current_packages[] as $p |
             {package: $p, held: ((hold_for($p) | length) > 0)}
           ]) as $hold_state |
          (($hold_state | length) > 0 and ($hold_state | all(.held == true))) as $all_held |
          ($pipeline[0].pipeline_status // "failed") as $pipeline_status |

          if ($cve.in_current | not) then
            (resolved_at_for($cve.id)) as $resolved_at |
            $cve + {
              state: "resolved",
              resolved_at: $resolved_at,
              justification: (if $resolved_at != null
                              then "no longer present in current vulnerability inventory; resolution recorded in patch change log"
                              else "no longer present in current vulnerability inventory; no matching resolution timestamp in patch change log"
                              end)
            }
          elif $all_held then
            $cve + {
              state: "deferred_held",
              resolved_at: null,
              justification: (if ($hold_reasons | length) > 0
                              then ("active package hold: " + ($hold_reasons | join("; ")))
                              else "active package hold"
                              end)
            }
          elif $pipeline_status == "deferred" then
            $cve + {
              state: "deferred_window",
              resolved_at: null,
              justification: "pipeline deferred until the next maintenance window"
            }
          else
            $cve + {
              state: "open",
              resolved_at: null,
              justification: "present in current vulnerability inventory"
            }
          end
          | {id, package, severity, state, first_seen, resolved_at, justification}
        )
        ' "${TMP_DIR}/cve_base.json" > "${TMP_DIR}/cves.json"

    generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    hostname_value=$(jq -r '.hostname // empty' "$PIPELINE_RUN")
    if [[ -z "$hostname_value" ]]; then
        hostname_value=$(hostname)
    fi
    kernel_value=$(uname -r)

    # The task specifies patch_change_log.json as the overdue clock. period_end
    # is therefore the reference instant; if the log has no events yet, fall
    # back to this report's generation time so a clean host is still reportable.
    clock_timestamp=$(jq -r '.period_end // empty' "$CHANGE_LOG")
    if [[ -z "$clock_timestamp" ]]; then
        clock_timestamp="$generated_at"
    fi
    clock_epoch=$(date -d "$clock_timestamp" '+%s' 2>/dev/null || true)
    [[ "$clock_epoch" =~ ^[0-9]+$ ]] || fail "cannot parse change-log clock: $clock_timestamp"

    overdue_count=0
    while IFS=$'\t' read -r state severity first_seen; do
        [[ "$state" == "open" ]] || continue
        [[ "$severity" == "critical" || "$severity" == "high" ]] || continue
        [[ -n "$first_seen" && "$first_seen" != "null" ]] || continue

        first_seen_epoch=$(date -d "$first_seen" '+%s' 2>/dev/null || true)
        [[ "$first_seen_epoch" =~ ^[0-9]+$ ]] || continue

        if (( clock_epoch - first_seen_epoch > OVERDUE_SECONDS )); then
            overdue_count=$((overdue_count + 1))
        fi
    done < <(jq -r '.[] | [.state, .severity, (.first_seen // "")] | @tsv' "${TMP_DIR}/cves.json")

    resolved_count=$(jq '[.[] | select(.state == "resolved")] | length' "${TMP_DIR}/cves.json")
    open_count=$(jq '[.[] | select(.state == "open")] | length' "${TMP_DIR}/cves.json")
    held_count=$(jq '[.[] | select(.state == "deferred_held")] | length' "${TMP_DIR}/cves.json")
    window_count=$(jq '[.[] | select(.state == "deferred_window")] | length' "${TMP_DIR}/cves.json")

    total_ch=$(jq '[.[] | select(.severity == "critical" or .severity == "high")] | length' "${TMP_DIR}/cves.json")
    resolved_ch=$(jq '[.[] | select((.severity == "critical" or .severity == "high") and .state == "resolved")] | length' "${TMP_DIR}/cves.json")

    if (( total_ch == 0 )); then
        score="100.00"
    else
        score=$(awk -v r="$resolved_ch" -v t="$total_ch" 'BEGIN { printf "%.2f", (r * 100) / t }')
    fi
    score_display="$score"

    # jq keeps score numeric for machine use; JSON numeric values do not retain
    # insignificant trailing zeroes, so 87.50 may serialize as 87.5.
    jq -n \
        --arg generated_at "$generated_at" \
        --arg hostname "$hostname_value" \
        --arg kernel "$kernel_value" \
        --argjson resolved "$resolved_count" \
        --argjson open "$open_count" \
        --argjson deferred_held "$held_count" \
        --argjson deferred_window "$window_count" \
        --argjson score "$score_display" \
        --argjson target_score "$TARGET_SCORE" \
        --argjson overdue "$overdue_count" \
        --slurpfile cves "${TMP_DIR}/cves.json" \
        '{
          generated_at: $generated_at,
          hostname: $hostname,
          kernel: $kernel,
          summary: {
            resolved: $resolved,
            open: $open,
            deferred_held: $deferred_held,
            deferred_window: $deferred_window,
            score: $score,
            target_score: $target_score,
            overdue: $overdue
          },
          cves: $cves[0]
        }' > "${TMP_DIR}/patch_compliance.json"

    # Atomic replacement avoids leaving a partial compliance artifact.
    mv "${TMP_DIR}/patch_compliance.json" "$OUTPUT_FILE"

    echo "Compliance artifact saved to: $OUTPUT_FILE"
    echo "Score: ${score}% (target: ${TARGET_SCORE}%)"
    echo "Overdue critical/high CVEs: $overdue_count"

    verdict_exit=$(awk -v s="$score" -v t="$TARGET_SCORE" 'BEGIN { print (s + 0 >= t + 0) ? 0 : 1 }')
    exit "$verdict_exit"
}

main "$@"

# ./history
