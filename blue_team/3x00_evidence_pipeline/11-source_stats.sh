#!/bin/bash
set -euo pipefail

INPUT="enriched_events.json"
OUTPUT="source_stats.json"

[[ -f "$INPUT" ]] || { echo "ERROR: $INPUT not found"; exit 1; }

jq -s '
def stats:
  . as $e
  | ($e | map(.timestamp | try fromdateiso8601 catch null)
        | map(select(. != null))
        | sort) as $t
  | {
      record_count: ($e | length),

      first_event:
        ($e | map(.timestamp) | min),

      last_event:
        ($e | map(.timestamp) | max),

      unique_hosts:
        ($e
         | map(.hostname)
         | map(select(. != null and . != ""))
         | unique
         | length),

      top_event_categories:
        ($e
         | map(.event_category // "unknown")
         | group_by(.)
         | map({
             category: .[0],
             count: length
           })
         | sort_by(-.count)
         | .[0:5]),

      events_per_hour:
        (if ($t | length) > 1 and ($t[-1] - $t[0]) > 0
         then (($e | length) / (($t[-1] - $t[0]) / 3600) | round)
         else ($e | length)
         end),

      coverage_gap:
        (if ($t | length) > 1
         then
           ([range(1; $t|length) as $i
             | (($t[$i] - $t[$i-1]) / 60)]
            | max
            | round)
         else 0
         end)
    };

group_by(.source_type)
| map({
    key: (.[0].source_type // "unknown"),
    value: stats
  })
| from_entries as $sources

| . as $all
| $sources + {
    overall: ($all | stats)
  }
' "$INPUT" > "$OUTPUT"


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
