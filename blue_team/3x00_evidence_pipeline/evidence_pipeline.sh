#!/bin/bash
set -uo pipefail

# ============================================================
# TASK 12 - END-TO-END EVIDENCE PIPELINE
# ============================================================

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <evidence_pack>"
    exit 1
fi

EVIDENCE_PACK="$(realpath "$1")"
export EVIDENCE_PACK

# Run from the directory containing this script.
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
export WORKDIR
cd "$WORKDIR"

LOG_FILE="$WORKDIR/pipeline_run.log"
: > "$LOG_FILE"

START_TIME=$(date +%s)


# ------------------------------------------------------------
# Validate evidence pack
# ------------------------------------------------------------

if [[ ! -d "$EVIDENCE_PACK" ]]; then
    echo "ERROR: Evidence pack not found: $EVIDENCE_PACK"
    exit 1
fi

for dir in windows linux network context student_telemetry
do
    if [[ ! -d "$EVIDENCE_PACK/$dir" ]]; then
        echo "ERROR: Missing directory: $dir/"
        exit 1
    fi
done

if [[ ! -f "$WORKDIR/event_schema.json" ]]; then
    echo "ERROR: event_schema.json not found"
    exit 1
fi


# ------------------------------------------------------------
# Run one pipeline stage
# ------------------------------------------------------------

run_stage() {
    number="$1"
    name="$2"
    script="$3"

    stage_start=$(date +%s)

    printf "[%s] stage %s %-20s ... " \
        "$(date +%H:%M:%S)" \
        "$number" \
        "$name"

    echo "[$(date +%H:%M:%S)] START stage $number $name" \
        >> "$LOG_FILE"

    if "./$script" >> "$LOG_FILE" 2>&1; then

        stage_end=$(date +%s)
        runtime=$((stage_end - stage_start))

        echo "ok (${runtime}s)"

        echo "[$(date +%H:%M:%S)] FINISH stage $number $name OK (${runtime}s)" \
            >> "$LOG_FILE"

    else
        stage_end=$(date +%s)
        runtime=$((stage_end - stage_start))

        echo "FAILED (${runtime}s)"

        echo "[$(date +%H:%M:%S)] FINISH stage $number $name FAILED" \
            >> "$LOG_FILE"

        echo "Pipeline stopped at stage $number"
        echo "See: $LOG_FILE"
        exit 1
    fi
}


# ------------------------------------------------------------
# Run stages in required order
# ------------------------------------------------------------

run_stage 0  "source_inventory"    "0-source_inventory.sh"
run_stage 1  "telemetry_import"    "1-telemetry_import.sh"
run_stage 2  "windows_parse"       "2-windows_parse.sh"
run_stage 3  "linux_parse"         "3-linux_parse.sh"
run_stage 5  "normalize"           "5-normalize.sh"
run_stage 6  "network_normalize"   "6-network_normalize.sh"
run_stage 7  "schema_validate"     "7-schema_validate.sh"
run_stage 8  "data_quality"        "8-data_quality.sh"
run_stage 9  "enrich"              "9-enrich.sh"
run_stage 10 "timeline"            "10-timeline.sh"
run_stage 11 "source_stats"        "11-source_stats.sh"


# ------------------------------------------------------------
# Final summary
# ------------------------------------------------------------

END_TIME=$(date +%s)
TOTAL_RUNTIME=$((END_TIME - START_TIME))

FINAL_FILE="$WORKDIR/enriched_events.json"

if [[ -f "$FINAL_FILE" ]]; then
    EVENT_COUNT=$(wc -l < "$FINAL_FILE")
else
    EVENT_COUNT=0
fi

echo
echo "pipeline ok. $EVENT_COUNT enriched events in ${TOTAL_RUNTIME}s"
echo "output: $FINAL_FILE"
echo "log:    $LOG_FILE"
