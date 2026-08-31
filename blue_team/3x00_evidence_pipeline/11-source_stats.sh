#!/bin/bash
set -euo pipefail

INPUT="${1:-enriched_events.json}"
OUTPUT="${2:-source_stats.json}"

[[ -f "$INPUT" ]] || {
    echo "ERROR: $INPUT not found" >&2
    exit 1
}

jq -s '
# Convert ISO 8601 timestamp to epoch.
def epoch:
  try fromdateiso8601 catch null;

# Calculate statistics for one group of events.
def stats:
  . as $events

  # Keep only valid timestamps.
  | (
      $events
      | map({
          raw: .timestamp,
          time: (.timestamp | epoch)
        })
      | map(select(.time != null))
      | sort_by(.time)
    ) as $times

  | {
      record_count: ($events | length),

      first_event:
        (if ($times | length) > 0
         then $times[0].raw
         else null
         end),

      last_event:
        (if ($times | length) > 0
         then $times[-1].raw
         else null
         end),

      unique_hosts:
        ($events
         | map(.hostname)
         | map(select(. != null and . != ""))
         | unique
         | length),

      top_event_categories:
        ($events
         | map(.event_category // "unknown")
         | group_by(.)
         | map({
             category: .[0],
             count: length
           })
         | sort_by(.count)
         | reverse
         | .[0:5]),

      events_per_hour:
        (if ($times | length) > 1
            and ($times[-1].time - $times[0].time) > 0
         then
           (
             ($events | length)
             /
             (($times[-1].time - $times[0].time) / 3600)
             | round
           )
         else 0
         end),

      coverage_gap:
        (if ($times | length) > 1
         then
           (
             [
               range(1; $times | length) as $i
               | (
                   ($times[$i].time - $times[$i - 1].time)
                   / 60
                 )
             ]
             | max
             | round
           )
         else 0
         end)
    };

# Save the complete dataset before grouping.
. as $all

# Produce one section for each source_type.
| (
    $all
    | sort_by(.source_type // "unknown")
    | group_by(.source_type // "unknown")
    | map({
        key: (.[0].source_type // "unknown"),
        value: stats
      })
    | from_entries
  ) as $sources

# Add global statistics.
| $sources + {
    overall: ($all | stats)
  }
' "$INPUT" > "$OUTPUT"


# ------------------------------------------------------------
# Human-readable summary
# ------------------------------------------------------------

printf "%-18s %10s %8s %10s %14s\n" \
    "source" "records" "hosts" "ev/hour" "max_gap(min)"

jq -r '
to_entries[]
| [
    .key,
    .value.record_count,
    .value.unique_hosts,
    .value.events_per_hour,
    .value.coverage_gap
  ]
| @tsv
' "$OUTPUT" |
awk -F'\t' '{
    printf "%-18s %10s %8s %10s %14s\n",
           $1, $2, $3, $4, $5
}'

echo "source_stats.json written"
