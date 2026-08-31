#!/bin/bash
set -uo pipefail

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKDIR"

SECONDARY_PACK="${SECONDARY_PACK:-$HOME/evidence_pack_secondary}"

PIPELINE="./evidence_pipeline.sh"
RUN_LOG="$WORKDIR/pipeline_run.log"
REPORT="$WORKDIR/pipeline_test_report.json"

CAPTURE_FILE=$(mktemp)
STAGE_FILE=$(mktemp)

trap 'rm -f "$CAPTURE_FILE" "$STAGE_FILE"' EXIT


# ------------------------------------------------------------
# Check required input
# ------------------------------------------------------------

if [[ ! -d "$SECONDARY_PACK" ]]; then
    echo "ERROR: Secondary evidence pack not found"
    exit 1
fi

if [[ ! -x "$PIPELINE" ]]; then
    echo "ERROR: evidence_pipeline.sh not found or not executable"
    exit 1
fi


# ------------------------------------------------------------
# Remove old final outputs so stale primary results cannot
# accidentally make this test pass.
# ------------------------------------------------------------

rm -f \
    "$WORKDIR/enriched_events.json" \
    "$WORKDIR/timeline_index.json" \
    "$RUN_LOG"


# ------------------------------------------------------------
# Run pipeline and capture stdout + stderr
# ------------------------------------------------------------

echo "running pipeline against $SECONDARY_PACK"

START=$(date +%s)

if "$PIPELINE" "$SECONDARY_PACK" >"$CAPTURE_FILE" 2>&1; then
    PIPELINE_RC=0
else
    PIPELINE_RC=$?
fi

END=$(date +%s)
RUNTIME=$((END - START))


# ------------------------------------------------------------
# Expected stages
# ------------------------------------------------------------

STAGES="
0 source_inventory
1 telemetry_import
2 windows_parse
3 linux_parse
5 normalize
6 network_normalize
7 schema_validate
8 data_quality
9 enrich
10 timeline
11 source_stats
"


# ------------------------------------------------------------
# Parse pipeline_run.log
#
# Each stage becomes:
#   pass
#   fail
#   not_run
# ------------------------------------------------------------

PASS_COUNT=0

while read -r number name
do
    [[ -z "$number" ]] && continue

    result="not_run"

    if [[ -f "$RUN_LOG" ]]; then

        if grep -q \
            "FINISH stage $number $name OK" \
            "$RUN_LOG"
        then
            result="pass"
            PASS_COUNT=$((PASS_COUNT + 1))

        elif grep -q \
            "FINISH stage $number $name FAILED" \
            "$RUN_LOG"
        then
            result="fail"
        fi
    fi

    printf "%s\t%s\t%s\n" \
        "$number" "$name" "$result" \
        >> "$STAGE_FILE"

done <<< "$STAGES"


# ------------------------------------------------------------
# Verify final output files
# ------------------------------------------------------------

OUTPUT_OK=true
EVENT_COUNT=0

if [[ -s "$WORKDIR/enriched_events.json" ]] &&
   [[ -s "$WORKDIR/timeline_index.json" ]]
then
    EVENT_COUNT=$(
        wc -l < "$WORKDIR/enriched_events.json"
    )
else
    OUTPUT_OK=false
fi


# ------------------------------------------------------------
# Final verdict
# ------------------------------------------------------------

if [[ "$PIPELINE_RC" -eq 0 ]] &&
   [[ "$PASS_COUNT" -eq 11 ]] &&
   [[ "$OUTPUT_OK" == true ]]
then
    VERDICT="pass"
else
    VERDICT="fail"
fi


# ------------------------------------------------------------
# Convert stage results to JSON
# ------------------------------------------------------------

STAGES_JSON=$(
    jq -Rn '
        [
          inputs
          | split("\t")
          | {
              stage: (.[0] | tonumber),
              name: .[1],
              result: .[2]
            }
        ]
    ' < "$STAGE_FILE"
)


# ------------------------------------------------------------
# Write machine-readable report
# ------------------------------------------------------------

jq -n \
    --arg pack "$SECONDARY_PACK" \
    --arg verdict "$VERDICT" \
    --argjson stages "$STAGES_JSON" \
    --argjson count "$EVENT_COUNT" \
    --argjson runtime "$RUNTIME" \
    '{
        pack_path: $pack,
        stages: $stages,
        final_event_count: $count,
        runtime_seconds: $runtime,
        verdict: $verdict
    }' > "$REPORT"


# ------------------------------------------------------------
# Human-readable result
# ------------------------------------------------------------

if [[ "$VERDICT" == "pass" ]]; then
    echo "all 11 stages passed"
else
    echo "$PASS_COUNT/11 stages passed"

    # Show captured pipeline error/output on failure.
    cat "$CAPTURE_FILE"
fi

echo "enriched events: $EVENT_COUNT"
echo "runtime: ${RUNTIME}s"
echo "verdict: $VERDICT"
echo "pipeline_test_report.json written"


# ------------------------------------------------------------
# Required exit status
# ------------------------------------------------------------

if [[ "$VERDICT" == "pass" ]]; then
    exit 0
else
    exit 1
fi
