#!/bin/bash

# Stop immediately if a command fails,
# an undefined variable is used,
# or a pipeline fails.
set -euo pipefail


# --------------------------------------------------
# Helper function for failures
# --------------------------------------------------

fail() {
    echo "[intake] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Check required environment variables
# --------------------------------------------------

for var in \
    CAPSTONE_PACK \
    ASSETS_DIR \
    WAZUH_EXPORTS \
    SHIFT_WORKSPACE \
    PIPELINE_BIN \
    BASELINE_BIN \
    CATALOG_DIR \
    TRIAGE_BIN
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


# --------------------------------------------------
# 1. Check required tools
# --------------------------------------------------

for tool in jq python3 yq sigma-cli sha256sum
do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool is missing"
    fi
done


# Get simple version numbers.

JQ_VERSION=$(jq --version | sed 's/^jq-//')
PYTHON_VERSION=$(python3 --version | awk '{print $2}')

YQ_VERSION=$(
    yq --version |
    grep -oE 'v?[0-9]+(\.[0-9]+)+' |
    tail -1 |
    sed 's/^v//'
)

SIGMA_VERSION=$(
    sigma-cli --version 2>&1 |
    grep -oE '[0-9]+(\.[0-9]+)+' |
    head -1
)

echo "[intake] jq $JQ_VERSION OK"
echo "[intake] python3 $PYTHON_VERSION OK"
echo "[intake] yq $YQ_VERSION OK"
echo "[intake] sigma-cli $SIGMA_VERSION OK"
echo "[intake] sha256sum OK"


# --------------------------------------------------
# 2. Check previous-project components
# --------------------------------------------------

if [[ ! -f "$PIPELINE_BIN" || ! -x "$PIPELINE_BIN" ]]; then
    fail "PIPELINE_BIN missing or not executable"
fi
echo "[intake] PIPELINE_BIN OK"


if [[ ! -f "$BASELINE_BIN" || ! -x "$BASELINE_BIN" ]]; then
    fail "BASELINE_BIN missing or not executable"
fi
echo "[intake] BASELINE_BIN OK"


if [[ ! -d "$CATALOG_DIR" || ! -r "$CATALOG_DIR" ]]; then
    fail "CATALOG_DIR missing or not readable"
fi

RULE_COUNT=$(find "$CATALOG_DIR" -type f -name '*.yml' | wc -l)

if [[ "$RULE_COUNT" -eq 0 ]]; then
    fail "CATALOG_DIR contains no .yml rules"
fi

echo "[intake] CATALOG_DIR OK ($RULE_COUNT rules)"


if [[ ! -f "$TRIAGE_BIN" || ! -x "$TRIAGE_BIN" ]]; then
    fail "TRIAGE_BIN missing or not executable"
fi
echo "[intake] TRIAGE_BIN OK"


# --------------------------------------------------
# 3. Check CAPSTONE_PACK
# --------------------------------------------------

if [[ ! -d "$CAPSTONE_PACK" || ! -r "$CAPSTONE_PACK" || ! -x "$CAPSTONE_PACK" ]]; then
    fail "CAPSTONE_PACK is missing or inaccessible"
fi

FIRST_ENTRY=$(find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -print -quit)

if [[ -z "$FIRST_ENTRY" ]]; then
    fail "CAPSTONE_PACK is empty"
fi

echo "[intake] CAPSTONE_PACK OK"
echo "[intake] top-level subdirectories:"

find "$CAPSTONE_PACK" \
    -mindepth 1 \
    -maxdepth 1 \
    -type d \
    -printf '  %f\n' |
    sort


# --------------------------------------------------
# 4. Check required context files
# --------------------------------------------------

ASSET_FILES=(
    "assets.json"
    "ioc_feed.json"
    "hc_red7_advisory.md"
    "change_tickets.json"
    "prior_shift_notes.md"
)

for file in "${ASSET_FILES[@]}"
do
    if [[ ! -f "$ASSETS_DIR/$file" ]]; then
        fail "missing context file: $file"
    fi
done

echo "[intake] ASSETS_DIR: 5 meta files OK"


# --------------------------------------------------
# 5. Check Wazuh exports
# --------------------------------------------------

WAZUH_FILES=(
    "incident_A_search_results.json"
    "incident_B_search_results.json"
    "incident_C_search_results.json"
    "campaign_dashboard_summary.md"
)

for file in "${WAZUH_FILES[@]}"
do
    if [[ ! -f "$WAZUH_EXPORTS/$file" ]]; then
        fail "missing Wazuh export: $file"
    fi
done

echo "[intake] WAZUH_EXPORTS: 4 export files OK"


# --------------------------------------------------
# 6. Read IOC count and HC-RED7 cluster
# --------------------------------------------------

IOC_COUNT=$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")

echo "[intake] ioc_feed.json OK ($IOC_COUNT entries)"


CLUSTER_ID=$(
    grep -m1 -o 'HC-RED7' \
        "$ASSETS_DIR/hc_red7_advisory.md" || true
)

if [[ "$CLUSTER_ID" != "HC-RED7" ]]; then
    fail "HC-RED7 not found in advisory"
fi

echo "[intake] advisory $CLUSTER_ID loaded"


# --------------------------------------------------
# 7. Create locked workspace layout
# --------------------------------------------------

mkdir -p \
    "$SHIFT_WORKSPACE/runtime" \
    "$SHIFT_WORKSPACE/enriched" \
    "$SHIFT_WORKSPACE/alerts" \
    "$SHIFT_WORKSPACE/investigations" \
    "$SHIFT_WORKSPACE/campaign" \
    "$SHIFT_WORKSPACE/reports" \
    "$SHIFT_WORKSPACE/response" \
    "$SHIFT_WORKSPACE/handoff"


# Create required stub files.

touch \
    "$SHIFT_WORKSPACE/MANIFEST.json" \
    "$SHIFT_WORKSPACE/runtime/shift_start.json" \
    "$SHIFT_WORKSPACE/runtime/pipeline_run.json" \
    "$SHIFT_WORKSPACE/runtime/baseline_run.json" \
    "$SHIFT_WORKSPACE/runtime/catalog_run.json" \
    "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" \
    "$SHIFT_WORKSPACE/enriched/timeline.jsonl" \
    "$SHIFT_WORKSPACE/enriched/baseline.json" \
    "$SHIFT_WORKSPACE/enriched/source_stats.json" \
    "$SHIFT_WORKSPACE/alerts/alert_queue.json" \
    "$SHIFT_WORKSPACE/alerts/shift_briefing.json" \
    "$SHIFT_WORKSPACE/alerts/triage_log.jsonl" \
    "$SHIFT_WORKSPACE/alerts/incidents.json" \
    "$SHIFT_WORKSPACE/investigations/incident_A.json" \
    "$SHIFT_WORKSPACE/investigations/incident_B.json" \
    "$SHIFT_WORKSPACE/investigations/incident_C_cli.json" \
    "$SHIFT_WORKSPACE/investigations/incident_C_export.json" \
    "$SHIFT_WORKSPACE/campaign/campaign_assessment.json" \
    "$SHIFT_WORKSPACE/reports/incident_A.md" \
    "$SHIFT_WORKSPACE/reports/incident_B.md" \
    "$SHIFT_WORKSPACE/reports/incident_C.md" \
    "$SHIFT_WORKSPACE/response/tuning_recommendations.json" \
    "$SHIFT_WORKSPACE/response/containment.json" \
    "$SHIFT_WORKSPACE/response/ioc_package.json" \
    "$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"


# --------------------------------------------------
# 8. Create shift_start.json
# --------------------------------------------------

NOW_EPOCH=$(date -u +%s)

STARTED_AT=$(
    date -u -d "@$NOW_EPOCH" +"%Y-%m-%dT%H:%M:%SZ"
)

SHIFT_ID=$(
    date -u -d "@$NOW_EPOCH" +"SHIFT-%Y%m%d-%H%M"
)

ANALYST_HOST=$(hostname)

RESOLVED_PACK=$(readlink -f "$CAPSTONE_PACK")


jq -n \
    --arg shift_id "$SHIFT_ID" \
    --arg analyst_host "$ANALYST_HOST" \
    --arg started_at "$STARTED_AT" \
    --arg jq_version "$JQ_VERSION" \
    --arg python_version "$PYTHON_VERSION" \
    --arg yq_version "$YQ_VERSION" \
    --arg sigma_version "$SIGMA_VERSION" \
    --arg capstone_pack "$RESOLVED_PACK" \
    --argjson ioc_count "$IOC_COUNT" \
    --arg cluster_id "$CLUSTER_ID" \
    '
    {
        shift_id: $shift_id,
        analyst_host: $analyst_host,
        started_at: $started_at,
        tools: {
            jq: $jq_version,
            python3: $python_version,
            yq: $yq_version,
            "sigma-cli": $sigma_version,
            sha256sum: "present"
        },
        prior_project_bins: {
            pipeline: true,
            baseline: true,
            catalog: true,
            triage: true
        },
        capstone_pack: $capstone_pack,
        ioc_feed_count: $ioc_count,
        advisory_cluster_id: $cluster_id,
        wazuh_exports_verified: true
    }
    ' > "$SHIFT_WORKSPACE/runtime/shift_start.json"


echo "[intake] shift_start.json written"
