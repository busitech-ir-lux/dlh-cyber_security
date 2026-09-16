#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[baseline] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE BASELINE_BIN
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
BASELINE_OUT="$SHIFT_WORKSPACE/enriched/baseline.json"
BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
BASELINE_LOG="$SHIFT_WORKSPACE/runtime/baseline_run.log"


# --------------------------------------------------
# 1. Check Task 1
# --------------------------------------------------

if [[ ! -s "$PIPELINE_RUN" ]]; then
    fail "pipeline_run.json is missing or empty"
fi

if ! jq empty "$PIPELINE_RUN" >/dev/null 2>&1; then
    fail "pipeline_run.json is not valid JSON"
fi

PIPELINE_STATUS=$(jq -r '.exit_status // -1' "$PIPELINE_RUN")

if [[ "$PIPELINE_STATUS" != "0" ]]; then
    fail "pipeline did not complete successfully"
fi

echo "[baseline] pipeline check: OK"


# --------------------------------------------------
# Find enriched events file
# --------------------------------------------------

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"

elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.json"

else
    fail "enriched events file is missing"
fi


# --------------------------------------------------
# Check baseline executable
# --------------------------------------------------

if [[ ! -x "$BASELINE_BIN" ]]; then
    fail "BASELINE_BIN missing or not executable: $BASELINE_BIN"
fi


# --------------------------------------------------
# Try to read baseline version
# --------------------------------------------------

BASELINE_VERSION="unknown"

set +e

VERSION_OUTPUT=$("$BASELINE_BIN" --version 2>/dev/null)
VERSION_STATUS=$?

set -e

if [[ "$VERSION_STATUS" -eq 0 && -n "$VERSION_OUTPUT" ]]; then
    BASELINE_VERSION=$(printf '%s\n' "$VERSION_OUTPUT" | head -1)
fi


# --------------------------------------------------
# 2. Run baseline
# --------------------------------------------------

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[baseline] invoking $BASELINE_BIN"
echo "[baseline] input: $EVENTS_FILE"
echo "[baseline] output: $BASELINE_OUT"


# Pass both paths as positional arguments.
# Environment variables are also provided for compatibility
# with previous project scripts.

set +e

BASELINE_INPUT="$EVENTS_FILE" \
BASELINE_OUTPUT="$BASELINE_OUT" \
"$BASELINE_BIN" "$EVENTS_FILE" "$BASELINE_OUT" \
    >"$BASELINE_LOG" 2>&1

BASELINE_STATUS=$?

set -e


if [[ "$BASELINE_STATUS" -ne 0 ]]; then
    cat "$BASELINE_LOG"
    fail "baseline script exited with status $BASELINE_STATUS"
fi


ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------
# 3. Verify baseline.json
# --------------------------------------------------

if [[ ! -s "$BASELINE_OUT" ]]; then
    fail "baseline.json is missing or empty"
fi

if ! jq empty "$BASELINE_OUT" >/dev/null 2>&1; then
    fail "baseline.json is not valid JSON"
fi


# --------------------------------------------------
# 4. Extract deviation markers
# --------------------------------------------------
#
# Supports:
#
# 1. .deviation_markers[]
# 2. .markers[]
# 3. .hosts[].deviations[]
# 4. .per_host.<hostname>.deviations[]
#
# The result is converted to the locked capstone format.
# --------------------------------------------------

MARKERS_JSON=$(
jq '
[
    if (.deviation_markers | type?) == "array" then

        .deviation_markers[]

    elif (.markers | type?) == "array" then

        .markers[]

    elif (.hosts | type?) == "array" then

        .hosts[] as $host
        |
        (
            $host.deviation_markers //
            $host.deviations //
            []
        )[]
        |
        . + {
            host: (
                .host //
                $host.host //
                $host.hostname //
                "unknown"
            )
        }

    elif (.per_host | type?) == "object" then

        .per_host
        | to_entries[]
        | .key as $hostname
        |
        (
            .value.deviation_markers //
            .value.deviations //
            []
        )[]
        |
        . + {
            host: (.host // $hostname)
        }

    else

        empty

    end
]
|
map(
    {
        host: (.host // .hostname // "unknown"),

        marker: (
            .marker //
            .type //
            .deviation_type //
            "unknown"
        ),

        field: (
            .field //
            .field_name //
            ""
        ),

        observed_value: (
            .observed_value //
            .observed //
            .value //
            ""
            | tostring
        ),

        baseline_reference: (
            .baseline_reference //
            .expected //
            .baseline //
            ""
            | tostring
        ),

        deviation_score: (
            .deviation_score //
            .score //
            0
            | tonumber? // 0
        )
    }
)
' "$BASELINE_OUT"
)


# --------------------------------------------------
# Count hosts from baseline.json
# --------------------------------------------------

HOSTS_TOTAL=$(
jq '
[
    if (.hosts | type?) == "array" then

        .hosts[]
        | (
            .host //
            .hostname //
            empty
        )

    elif (.per_host | type?) == "object" then

        .per_host
        | keys[]

    elif (.host_profiles | type?) == "object" then

        .host_profiles
        | keys[]

    else
        empty
    end
]
|
unique
|
length
' "$BASELINE_OUT"
)


# --------------------------------------------------
# Fallback: if baseline has no explicit host list,
# count hosts from enriched events
# --------------------------------------------------

if [[ "$HOSTS_TOTAL" -eq 0 ]]; then

    if [[ "$EVENTS_FILE" == *.jsonl ]]; then

        HOSTS_TOTAL=$(
            jq -r '
                .hostname //
                .host //
                empty
            ' "$EVENTS_FILE" |
            sort -u |
            grep -c . || true
        )

    else

        HOSTS_TOTAL=$(
            jq '
                [
                    .[]
                    | (
                        .hostname //
                        .host //
                        empty
                    )
                ]
                | unique
                | length
            ' "$EVENTS_FILE"
        )

    fi
fi


if [[ "$HOSTS_TOTAL" -eq 0 ]]; then
    fail "hosts_total is zero"
fi


# --------------------------------------------------
# Hosts with at least one deviation
# --------------------------------------------------

HOSTS_WITH_DEVIATIONS=$(
    jq '
        [
            .[]
            | select(.host != "unknown")
            | .host
        ]
        | unique
        | length
    ' <<< "$MARKERS_JSON"
)


# --------------------------------------------------
# Five hottest hosts
# --------------------------------------------------

HOT_HOSTS_JSON=$(
    jq '
        group_by(.host)

        | map(
            {
                host: .[0].host,

                total_score: (
                    map(.deviation_score)
                    | add
                )
            }
        )

        | sort_by(-.total_score)

        | .[0:5]

        | map(.host)
    ' <<< "$MARKERS_JSON"
)


# --------------------------------------------------
# Print hot-host summaries
# --------------------------------------------------

echo "[baseline] hosts processed: $HOSTS_TOTAL"
echo "[baseline] hosts with deviations: $HOSTS_WITH_DEVIATIONS"


HOT_HOST_COUNT=$(jq 'length' <<< "$HOT_HOSTS_JSON")

if [[ "$HOT_HOST_COUNT" -gt 0 ]]; then

    echo "[baseline] hot hosts:"

    jq -r '
        group_by(.host)

        | map(
            {
                host: .[0].host,

                score: (
                    map(.deviation_score)
                    | add
                ),

                markers: length
            }
        )

        | sort_by(-.score)

        | .[0:5][]

        | "[baseline] hot host \(.host) score=\(.score) markers=\(.markers)"
    ' <<< "$MARKERS_JSON"

else

    echo "[baseline] hot hosts: none"

fi


# --------------------------------------------------
# Marker statistics
# --------------------------------------------------

MARKER_TOTAL=$(jq 'length' <<< "$MARKERS_JSON")

echo "[baseline] markers: $MARKER_TOTAL total"


# Print count for each marker type.

jq -r '
    group_by(.marker)

    | map({
        marker: .[0].marker,
        count: length
    })

    | .[]

    | "[baseline] marker \(.marker)=\(.count)"
' <<< "$MARKERS_JSON"


# --------------------------------------------------
# 5. Write baseline_run.json
# --------------------------------------------------

jq -n \
    --arg baseline_version "$BASELINE_VERSION" \
    --argjson hosts_total "$HOSTS_TOTAL" \
    --argjson hosts_with_deviations "$HOSTS_WITH_DEVIATIONS" \
    --argjson deviation_markers "$MARKERS_JSON" \
    --argjson hot_hosts "$HOT_HOSTS_JSON" \
    --arg started_at "$STARTED_AT" \
    --arg ended_at "$ENDED_AT" \
    '
    {
        baseline_version: $baseline_version,

        hosts_total: $hosts_total,

        hosts_with_deviations: $hosts_with_deviations,

        deviation_markers: $deviation_markers,

        hot_hosts: $hot_hosts,

        started_at: $started_at,

        ended_at: $ended_at,

        exit_status: 0
    }
    ' > "$BASELINE_RUN"


echo "[baseline] baseline_run.json written"
