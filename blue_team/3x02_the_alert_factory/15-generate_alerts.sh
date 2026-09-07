#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

RULES_DIR="rules/sigma"
RUNNER="./3-sigma_runner.sh"
PRIORITY="rule_prioritization.json"

EVENTS="$HANDOFF_DIR/data/normalized_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

OUTPUT="alert_queue.json"
SCHEMA="alert_queue_schema.json"

for cmd in jq sha256sum uuidgen; do
    command -v "$cmd" >/dev/null || {
        echo "ERROR: $cmd not found" >&2
        exit 1
    }
done

for file in "$RUNNER" "$PRIORITY" "$EVENTS" "$ASSETS" "$SUMMARY"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------
# Evaluation window
# ------------------------------------------------------------

EVAL_START="$(jq -r '.evaluation_window.start' "$SUMMARY")"
EVAL_END="$(jq -r '.evaluation_window.end' "$SUMMARY")"

# Keep generated_at deterministic.
GENERATED_AT="$EVAL_END"

# Convert normalized events to NDJSON once.
jq -c 'if type == "array" then .[] else . end' "$EVENTS" > "$TMP/events.jsonl"

# ------------------------------------------------------------
# Active rules:
# tuned version if present, otherwise original
# ------------------------------------------------------------

mapfile -t BASE_RULES < <(
    find "$RULES_DIR" -maxdepth 1 -type f -name '*.yml' | sort
)

ACTIVE_RULES=()

for rule in "${BASE_RULES[@]}"; do
    prefix="$(basename "$rule" | cut -c1-3)"

    tuned="$(
        find "$RULES_DIR/tuned" \
            -maxdepth 1 \
            -type f \
            -name "${prefix}_*.yml" \
            2>/dev/null |
        sort |
        head -1
    )"

    if [[ -n "$tuned" ]]; then
        ACTIVE_RULES+=("$tuned")
    else
        ACTIVE_RULES+=("$rule")
    fi
done

RULE_COUNT="${#ACTIVE_RULES[@]}"
RAW_FILE="$TMP/raw_alerts.jsonl"

# ------------------------------------------------------------
# Run rules
# ------------------------------------------------------------

for rule in "${ACTIVE_RULES[@]}"; do

    result="$(
        "$RUNNER" "$rule" \
            --window "$EVAL_START,$EVAL_END"
    )"

    rule_id="$(jq -r '.rule_id' <<<"$result")"
    rule_title="$(jq -r '.rule_title' <<<"$result")"
    rule_level="$(jq -r '.level' <<<"$result")"

    priority="$(
        jq -r --arg id "$rule_id" '
            (.rules // .)[]
            | select(.rule_id == $id)
            | .priority_score
        ' "$PRIORITY" | head -1
    )"

    priority="${priority:-0}"

    # ATT&CK technique tags from Sigma rule.
    techniques="$(
        grep -oE 'attack\.t[0-9]+(\.[0-9]+)?' "$rule" 2>/dev/null |
        sort -u |
        sed 's/attack\.//' |
        tr '[:lower:]' '[:upper:]' |
        jq -R . |
        jq -s .
    )"

    rule_name="$(basename "$rule" .yml)"

    # Process every match.
    jq -c '.matches[]' <<<"$result" |
    while IFS= read -r match; do

        event_ref="$(jq -r '.event_ref' <<<"$match")"

        # Find original normalized event.
        if [[ "$event_ref" == index:* ]]; then
            index="${event_ref#index:}"
            event="$(
                sed -n "$((index + 1))p" "$TMP/events.jsonl"
            )"
        else
            event="$(
                jq -c \
                    --arg ref "$event_ref" '
                    select(
                        ((.event_ref // .record_id // .id // "") | tostring)
                        == $ref
                    )
                ' "$TMP/events.jsonl" |
                head -1
            )"
        fi

        [[ -n "$event" ]] || continue

        hostname="$(jq -r '.hostname // .host.name // ""' <<<"$event")"
        user="$(jq -r '.user // ""' <<<"$event")"

        # Deterministic UUID5.
        alert_id="$(
            uuidgen \
                --sha1 \
                --namespace @url \
                --name "$rule_id:$event_ref"
        )"

        # SHA256 of the matched normalized record.
        evidence_hash="$(
            printf '%s\n' "$event" |
            sha256sum |
            awk '{print $1}'
        )"

        # Asset information for the event host.
        asset_context="$(
            jq -c --arg host "$hostname" '
                (.assets // .) |
                if type == "array" then
                    (
                        map(
                            select(
                                (.hostname // .name // .host // "")
                                == $host
                            )
                        )[0] // {}
                    )
                else
                    .[$host] // {}
                end
            ' "$ASSETS"
        )"

        # Build alert.
        jq -n \
            --arg alert_id "$alert_id" \
            --arg generated_at "$GENERATED_AT" \
            --arg rule_id "$rule_id" \
            --arg rule_title "$rule_title" \
            --arg rule_level "$rule_level" \
            --arg rule_name "$rule_name" \
            --argjson priority "$priority" \
            --arg event_ref "$event_ref" \
            --arg hash "$evidence_hash" \
            --argjson event "$event" \
            --argjson asset "$asset_context" \
            --argjson techniques "$techniques" '
            {
                alert_id: $alert_id,
                generated_at: $generated_at,
                rule_id: $rule_id,
                rule_title: $rule_title,
                rule_level: $rule_level,
                priority_score: $priority,
                event_ref: $event_ref,

                event_summary: {
                    timestamp: $event.timestamp,
                    hostname: ($event.hostname // $event.host.name // null),
                    user: ($event.user // null),
                    src_ip: ($event.src_ip // null),
                    dst_ip: ($event.dst_ip // null),
                    process_name: ($event.process_name // null),
                    canonical_label: ($event.canonical_label // null),
                    event_category: ($event.event_category // null)
                },

                asset_context: $asset,
                attack_techniques: $techniques,
                status: "new",
                evidence_hash: $hash,

                _rule_name: $rule_name
            }
        ' >> "$RAW_FILE"

    done
done

RAW_COUNT="$(wc -l < "$RAW_FILE")"

# ------------------------------------------------------------
# Deduplicate within 60 seconds on:
# rule_id + hostname + user
# ------------------------------------------------------------

jq -s '
    def epoch:
        try (.event_summary.timestamp | fromdateiso8601)
        catch 0;

    sort_by(
        .rule_id,
        (.event_summary.hostname // ""),
        (.event_summary.user // ""),
        .event_summary.timestamp
    )

    | reduce .[] as $a (
        {last: {}, alerts: []};

        (
            $a.rule_id + "|" +
            ($a.event_summary.hostname // "") + "|" +
            ($a.event_summary.user // "")
        ) as $key

        | ($a | epoch) as $time

        | if (
            .last[$key] == null
            or ($time - .last[$key]) > 60
          )
          then
            .alerts += [$a]
            | .last[$key] = $time
          else
            .
          end
    )

    | .alerts
    | sort_by(
        -.priority_score,
        .event_summary.timestamp
    )
' "$RAW_FILE" > "$TMP/ranked.json"

DEDUP_COUNT="$(jq 'length' "$TMP/ranked.json")"

# Remove temporary display field.
jq 'map(del(._rule_name))' "$TMP/ranked.json" > "$OUTPUT"

# ------------------------------------------------------------
# Queue schema
# ------------------------------------------------------------

cat > "$SCHEMA" <<'EOF'
{
  "type": "array",
  "items": {
    "type": "object",
    "required": [
      "alert_id",
      "generated_at",
      "rule_id",
      "rule_title",
      "rule_level",
      "priority_score",
      "event_ref",
      "event_summary",
      "asset_context",
      "attack_techniques",
      "status",
      "evidence_hash"
    ],
    "properties": {
      "alert_id": {"type": "string"},
      "generated_at": {"type": "string"},
      "rule_id": {"type": "string"},
      "rule_title": {"type": "string"},
      "rule_level": {"type": "string"},
      "priority_score": {"type": "number"},
      "event_ref": {"type": "string"},
      "event_summary": {
        "type": "object",
        "properties": {
          "timestamp": {},
          "hostname": {},
          "user": {},
          "src_ip": {},
          "dst_ip": {},
          "process_name": {},
          "canonical_label": {},
          "event_category": {}
        }
      },
      "asset_context": {"type": "object"},
      "attack_techniques": {"type": "array"},
      "status": {"type": "string"},
      "evidence_hash": {"type": "string"}
    }
  }
}
EOF

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

echo "rules executed            : $RULE_COUNT"
echo "raw matches               : $RAW_COUNT"
echo "after deduplication       : $DEDUP_COUNT"
echo "top 5 alerts"

jq -r '
    .[:5]
    | to_entries[]
    | [
        (.key + 1),
        .value.priority_score,
        .value.rule_level,
        .value._rule_name,
        (.value.event_summary.hostname // "-")
      ]
    | @tsv
' "$TMP/ranked.json" |
while IFS=$'\t' read -r rank score level rule host; do
    printf "%2d  %5.1f  %-9s %-32s %s\n" \
        "$rank" "$score" "$level" "$rule" "$host"
done

echo "alert_queue.json        : $DEDUP_COUNT alerts"
echo "alert_queue_schema.json : written"
