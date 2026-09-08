#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

QUEUE="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA="$CATALOG_DIR/alerts/alert_queue_schema.json"
OUTPUT="queue_assessment.json"

[[ -f "$QUEUE" ]] || {
    echo "ERROR: $QUEUE not found" >&2
    exit 1
}

[[ -f "$SCHEMA" ]] || {
    echo "ERROR: $SCHEMA not found" >&2
    exit 1
}

# ------------------------------------------------------------
# Build queue assessment
# ------------------------------------------------------------

jq --slurpfile schema "$SCHEMA" '

  # Check JSON Schema data types.
  def type_ok($v; $t):
    if ($t | type) == "array" then
      any($t[]; type_ok($v; .))
    elif $t == "object" then
      ($v | type) == "object"
    elif $t == "array" then
      ($v | type) == "array"
    elif $t == "string" then
      ($v | type) == "string"
    elif $t == "number" then
      ($v | type) == "number"
    elif $t == "integer" then
      (($v | type) == "number" and ($v == ($v | floor)))
    elif $t == "boolean" then
      ($v | type) == "boolean"
    elif $t == "null" then
      $v == null
    else
      true
    end;

  # Validate one alert against the supplied schema.
  def validate($v; $s; $path):
    [
      if ($s.type? != null)
         and (type_ok($v; $s.type) | not)
      then
        "\($path): wrong type"
      else
        empty
      end,

      if ($s.enum? != null)
         and (($s.enum | index($v)) == null)
      then
        "\($path): value not allowed"
      else
        empty
      end,

      if ($v | type) == "object" then
        ($s.required? // [])[] as $key
        | if ($v | has($key) | not) then
            "\($path).\($key): missing required field"
          else
            empty
          end
      else
        empty
      end,

      if (($v | type) == "object")
         and ($s.properties? != null)
      then
        $s.properties
        | to_entries[] as $p
        | if ($v | has($p.key)) then
            validate(
              $v[$p.key];
              $p.value;
              ($path + "." + $p.key)
            )[]
          else
            empty
          end
      else
        empty
      end,

      if (($v | type) == "array")
         and ($s.items? != null)
      then
        range(0; $v | length) as $i
        | validate(
            $v[$i];
            $s.items;
            ($path + "[" + ($i | tostring) + "]")
          )[]
      else
        empty
      end,

      if (($v | type) == "number")
         and ($s.minimum? != null)
         and ($v < $s.minimum)
      then
        "\($path): below minimum"
      else
        empty
      end,

      if (($v | type) == "number")
         and ($s.maximum? != null)
         and ($v > $s.maximum)
      then
        "\($path): above maximum"
      else
        empty
      end
    ];

  # Count values and sort highest count first.
  def counts($name):
    group_by(.)
    | map({
        ($name): .[0],
        count: length
      })
    | sort_by(-.count, .[$name]);

  # Get tactic name from rule tags.
  def tactic:
    sub("^attack_tactic[:=.]"; "")
    | sub("^tactic[:=.]"; "");

  . as $alerts

  # The queue schema normally describes an array,
  # so .items is the schema for one alert.
  | ($schema[0].items // $schema[0]) as $alert_schema

  | {
      queue_size: ($alerts | length),

      validation_errors: [
        $alerts[] as $alert
        | (validate(
            $alert;
            $alert_schema;
            "$"
          )) as $errors

        | select(($errors | length) > 0)

        | {
            alert_id: ($alert.alert_id // "unknown"),
            errors: $errors
          }
      ],

      by_priority_band: {
        critical: (
          [$alerts[]
           | select(.priority_score >= 20)]
          | length
        ),

        high: (
          [$alerts[]
           | select(
               .priority_score >= 10
               and .priority_score <= 19
             )]
          | length
        ),

        medium: (
          [$alerts[]
           | select(
               .priority_score >= 5
               and .priority_score <= 9
             )]
          | length
        ),

        low: (
          [$alerts[]
           | select(
               .priority_score >= 1
               and .priority_score <= 4
             )]
          | length
        )
      },

      by_rule: (
        $alerts
        | group_by(.rule_id)
        | map({
            rule_id: .[0].rule_id,
            rule_name: (.[0].rule_name // ""),
            count: length
          })
        | sort_by(-.count, .rule_id)
      ),

      by_hostname: (
        [$alerts[] | .event_summary.hostname]
        | counts("hostname")
      ),

      by_attack_tactic: (
        [
          $alerts[]
          | (.rule_tags // .tags // [])[]
          | select(
              test("^(attack_tactic|tactic)[:=.]")
            )
          | tactic
        ]
        | counts("tactic")
      ),

      time_span: {
        first: (
          [$alerts[].event_summary.timestamp]
          | sort
          | first
        ),

        last: (
          [$alerts[].event_summary.timestamp]
          | sort
          | last
        )
      },

      top_targets: (
        $alerts
        | group_by(.event_summary.hostname)

        | map({
            hostname: .[0].event_summary.hostname,

            cumulative_priority_score: (
              map(.priority_score)
              | add
            )
          })

        | sort_by(
            -.cumulative_priority_score,
            .hostname
          )

        | .[:3]
      )
    }

' "$QUEUE" > "$OUTPUT"

# ------------------------------------------------------------
# Human-readable shift briefing
# ------------------------------------------------------------

DATE="$(date -u +%F)"

echo "=== SHIFT BRIEFING $DATE ==="

printf "queue size           : %s alerts\n" \
    "$(jq -r '.queue_size' "$OUTPUT")"

printf "validation errors    : %s\n" \
    "$(jq -r '.validation_errors | length' "$OUTPUT")"

printf "time span            : %s -> %s\n" \
    "$(jq -r '.time_span.first' "$OUTPUT")" \
    "$(jq -r '.time_span.last' "$OUTPUT")"

echo "priority bands"

printf "  critical  : %2s\n" \
    "$(jq -r '.by_priority_band.critical' "$OUTPUT")"

printf "  high      : %2s\n" \
    "$(jq -r '.by_priority_band.high' "$OUTPUT")"

printf "  medium    : %2s\n" \
    "$(jq -r '.by_priority_band.medium' "$OUTPUT")"

printf "  low       : %2s\n" \
    "$(jq -r '.by_priority_band.low' "$OUTPUT")"

echo "top rules (5)"

jq -r '
  .by_rule[:5][]
  | "  \(.rule_id) \(.rule_name) \(.count)"
' "$OUTPUT"

echo "top hosts (3 by cumulative score)"

jq -r '
  .top_targets[]
  | "  \(.hostname)   score \(.cumulative_priority_score)"
' "$OUTPUT"

printf "attack tactics covered : %s\n" \
    "$(jq -r '.by_attack_tactic | length' "$OUTPUT")"

echo "$OUTPUT written"
