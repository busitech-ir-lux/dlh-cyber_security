#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[handoff] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variable
# --------------------------------------------------

if [[ -z "${SHIFT_WORKSPACE:-}" ]]; then
    fail "SHIFT_WORKSPACE is not set"
fi


# --------------------------------------------------
# Important files
# --------------------------------------------------

SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
BRIEFING="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
CAMPAIGN="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"

FINDING_A="$SHIFT_WORKSPACE/investigations/incident_A.json"
FINDING_B="$SHIFT_WORKSPACE/investigations/incident_B.json"
FINDING_C="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"

MANIFEST="$SHIFT_WORKSPACE/MANIFEST.json"
HANDOFF="$SHIFT_WORKSPACE/handoff/shift_handoff.md"


# --------------------------------------------------
# 1. Locked workspace layout
# --------------------------------------------------

REQUIRED_FILES=(

    "runtime/shift_start.json"
    "runtime/pipeline_run.json"
    "runtime/baseline_run.json"
    "runtime/catalog_run.json"

    "enriched/enriched_events.jsonl"
    "enriched/timeline.jsonl"
    "enriched/baseline.json"
    "enriched/source_stats.json"

    "alerts/alert_queue.json"
    "alerts/shift_briefing.json"
    "alerts/triage_log.jsonl"
    "alerts/incidents.json"

    "investigations/incident_A.json"
    "investigations/incident_B.json"
    "investigations/incident_C_cli.json"
    "investigations/incident_C_export.json"

    "campaign/campaign_assessment.json"

    "reports/incident_A.md"
    "reports/incident_B.md"
    "reports/incident_C.md"

    "response/tuning_recommendations.json"
    "response/containment.json"
    "response/ioc_package.json"
)


echo "[handoff] checking workspace layout..."


CHECKED=0


for relative in "${REQUIRED_FILES[@]}"
do

    file="$SHIFT_WORKSPACE/$relative"

    if [[ ! -f "$file" ]]; then
        fail "missing file: $relative"
    fi

    if [[ ! -s "$file" ]]; then
        fail "empty file: $relative"
    fi

    echo "[handoff] OK $relative"

    CHECKED=$((CHECKED + 1))

done


echo "[handoff] checking workspace layout... $CHECKED source files OK"


# --------------------------------------------------
# Validate core JSON
# --------------------------------------------------

for file in \
    "$SHIFT_START" \
    "$INCIDENTS" \
    "$BRIEFING" \
    "$CAMPAIGN" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C"
do

    if ! jq empty "$file" >/dev/null 2>&1; then
        fail "invalid JSON: $file"
    fi

done


# --------------------------------------------------
# 2. Shift information
# --------------------------------------------------

SHIFT_ID=$(jq -r '.shift_id // empty' "$SHIFT_START")
ANALYST_HOST=$(jq -r '.analyst_host // empty' "$SHIFT_START")
STARTED_AT=$(jq -r '.started_at // empty' "$SHIFT_START")

ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


if [[ -z "$SHIFT_ID" ]]; then
    fail "shift_id missing from shift_start.json"
fi


if [[ -z "$STARTED_AT" ]]; then
    fail "started_at missing from shift_start.json"
fi


DURATION_HOURS=$(
python3 - "$STARTED_AT" "$ENDED_AT" <<'PY'
import sys
from datetime import datetime

start = sys.argv[1].replace("Z", "+00:00")
end = sys.argv[2].replace("Z", "+00:00")

start_dt = datetime.fromisoformat(start)
end_dt = datetime.fromisoformat(end)

hours = (end_dt - start_dt).total_seconds() / 3600

print(f"{hours:.2f}")
PY
)


echo "[handoff] shift_id: $SHIFT_ID"
echo "[handoff] duration: $DURATION_HOURS hours"


# --------------------------------------------------
# 3. Incident IDs
# --------------------------------------------------

mapfile -t INCIDENT_IDS < <(
    jq -r '.incidents[].incident_id' "$INCIDENTS"
)


if [[ "${#INCIDENT_IDS[@]}" -eq 0 ]]; then
    fail "no incidents found"
fi


# --------------------------------------------------
# 4. Campaign information
# --------------------------------------------------

CAMPAIGN_LINKED=$(jq -r '.campaign_linked' "$CAMPAIGN")
CLUSTER_ID=$(jq -r '.cluster_id // "unknown"' "$CAMPAIGN")
CAMPAIGN_CONFIDENCE=$(jq -r '.confidence // "low"' "$CAMPAIGN")


# --------------------------------------------------
# Additional briefing information
# --------------------------------------------------

IOC_COUNT=$(jq -r '.ioc_count // 0' "$BRIEFING")


# Get overall incident observation period.

PACK_START=$(
    jq -r '
        [.incidents[].first_seen]
        | map(select(. != null and . != ""))
        | min // "unknown"
    ' "$INCIDENTS"
)


PACK_END=$(
    jq -r '
        [.incidents[].last_seen]
        | map(select(. != null and . != ""))
        | max // "unknown"
    ' "$INCIDENTS"
)


# --------------------------------------------------
# Temporary workspace
# --------------------------------------------------

TMP_DIR=$(mktemp -d)

trap 'rm -rf "$TMP_DIR"' EXIT


ARTIFACT_JSON="$TMP_DIR/artifacts.json"
OPEN_ITEMS="$TMP_DIR/open_items.txt"
HANDOFF_DRAFT="$TMP_DIR/shift_handoff.md"


# --------------------------------------------------
# Build artifact hashes
#
# MANIFEST.json and shift_handoff.md are excluded
# because they are self-referential control files.
# --------------------------------------------------

python3 - "$SHIFT_WORKSPACE" "$ARTIFACT_JSON" <<'PY'

import hashlib
import json
import os
import sys


workspace = os.path.abspath(sys.argv[1])
output = sys.argv[2]


skip = {
    "MANIFEST.json",
    "handoff/shift_handoff.md",
}


files = []


for root, dirs, names in os.walk(workspace):

    dirs.sort()
    names.sort()

    for name in names:

        full = os.path.join(root, name)

        relative = os.path.relpath(
            full,
            workspace
        ).replace(os.sep, "/")


        if relative in skip:
            continue


        if not os.path.isfile(full):
            continue


        sha = hashlib.sha256()


        with open(full, "rb") as f:

            for block in iter(
                lambda: f.read(65536),
                b""
            ):

                sha.update(block)


        files.append({

            "path": relative,

            "sha256": sha.hexdigest(),

            "size": os.path.getsize(full),
        })


with open(
    output,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        files,
        f,
        indent=2
    )

    f.write("\n")

PY


# --------------------------------------------------
# Build open items
#
# Use ambiguity_notes from findings where confidence
# is not high.
# --------------------------------------------------

: > "$OPEN_ITEMS"


for finding in \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C"
do

    CONFIDENCE=$(jq -r '.confidence // "low"' "$finding")

    NOTES=$(jq -r '.ambiguity_notes // empty' "$finding")


    if [[ "$CONFIDENCE" != "high" && -n "$NOTES" ]]; then

        echo "$NOTES" >> "$OPEN_ITEMS"

    fi

done


# Add prior shift open items only if we have room.

jq -r '
    .prior_shift_open_items[]?
' "$BRIEFING" >> "$OPEN_ITEMS"


# Remove duplicates and limit to 8.

sort -u "$OPEN_ITEMS" |
head -8 > "$TMP_DIR/open_items_final.txt"


# --------------------------------------------------
# Create handoff document
# --------------------------------------------------

python3 - \
    "$SHIFT_ID" \
    "$ANALYST_HOST" \
    "$STARTED_AT" \
    "$ENDED_AT" \
    "$DURATION_HOURS" \
    "$IOC_COUNT" \
    "$PACK_START" \
    "$PACK_END" \
    "$INCIDENTS" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$CAMPAIGN_LINKED" \
    "$CLUSTER_ID" \
    "$CAMPAIGN_CONFIDENCE" \
    "$ARTIFACT_JSON" \
    "$TMP_DIR/open_items_final.txt" \
    "$HANDOFF_DRAFT" <<'PY'

import json
import sys


(
    shift_id,
    analyst_host,
    started_at,
    ended_at,
    duration_hours,
    ioc_count,
    pack_start,
    pack_end,
    incidents_path,
    finding_a,
    finding_b,
    finding_c,
    campaign_linked,
    cluster_id,
    campaign_confidence,
    artifacts_path,
    open_items_path,
    output_path,
) = sys.argv[1:]


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def clean(value):

    if value is None:
        return ""

    return " ".join(
        str(value).split()
    )


# --------------------------------------------------
# Data
# --------------------------------------------------

incidents_data = load_json(
    incidents_path
)


findings = {
    "A": load_json(finding_a),
    "B": load_json(finding_b),
    "C": load_json(finding_c),
}


artifacts = load_json(
    artifacts_path
)


incident_map = {}


for incident in incidents_data.get(
    "incidents",
    []
):

    iid = clean(
        incident.get("incident_id")
    )

    if iid.endswith("-A"):
        incident_map["A"] = incident

    elif iid.endswith("-B"):
        incident_map["B"] = incident

    elif iid.endswith("-C"):
        incident_map["C"] = incident


# --------------------------------------------------
# Open items
# --------------------------------------------------

with open(
    open_items_path,
    "r",
    encoding="utf-8"
) as f:

    open_items = [
        clean(line)
        for line in f
        if clean(line)
    ]


# --------------------------------------------------
# Handoff sections
# --------------------------------------------------

lines = []


# ==================================================
# 1. Shift Identifier
# ==================================================

lines.append("## Shift Identifier")

lines.append(
    f"Shift ID: {shift_id}  "
)

lines.append(
    f"Analyst host: {analyst_host}  "
)

lines.append(
    f"Started: {started_at}  "
)

lines.append(
    f"Ended: {ended_at}  "
)

lines.append(
    f"Duration: {duration_hours} hours"
)

lines.append("")


# ==================================================
# 2. Situation
# 4 sentences
# ==================================================

lines.append("## Situation")

lines.append(
    "The shift operated under heightened monitoring "
    f"for the {cluster_id if cluster_id != 'unknown' else 'HC-RED7'} "
    "healthcare threat advisory. "
    f"The shift briefing contained {ioc_count} IOC values. "
    f"The investigated activity occurred between {pack_start} "
    f"and {pack_end}. "
    f"The shift produced {len(incident_map)} candidate incidents "
    "for investigation and handoff."
)

lines.append("")


# ==================================================
# 3. Incidents
# ==================================================

lines.append("## Incidents")


for letter in ("A", "B", "C"):

    incident = incident_map.get(letter)

    finding = findings.get(letter, {})


    if not incident:
        continue


    iid = clean(
        incident.get("incident_id")
    )


    confidence = clean(
        finding.get(
            "confidence"
        )
    ).lower()


    if confidence == "high":
        verdict = "TP"
    else:
        verdict = "ambiguous"


    techniques = finding.get(
        "attack_techniques",
        []
    )


    primary = (
        techniques[0]
        if techniques
        else "not mapped"
    )


    report_path = (
        f"reports/incident_{letter}.md"
    )


    lines.append(
        f"{iid} is classified as {verdict}. "
        f"The primary ATT&CK technique is {primary}. "
        f"The complete incident report is available at "
        f"`{report_path}`."
    )


    lines.append("")


# ==================================================
# 4. Campaign Assessment
# ==================================================

lines.append(
    "## Campaign Assessment"
)


linked_text = (
    "campaign-linked"
    if campaign_linked.lower() == "true"
    else "not currently campaign-linked"
)


lines.append(
    f"The incidents are {linked_text}. "
    f"The assessed cluster is {cluster_id} with "
    f"{campaign_confidence} confidence. "
    "The counted IOC, tactic, temporal, host and user "
    "correlation evidence is recorded in "
    "`campaign/campaign_assessment.json`."
)

lines.append("")


# ==================================================
# 5. Open Items
# ==================================================

lines.append(
    "## Open Items for Next Shift"
)


if open_items:

    for item in open_items[:8]:

        # Force one physical line per item.
        item = item.replace(
            "\n",
            " "
        ).strip()

        lines.append(
            f"- {item}"
        )

else:

    lines.append(
        "- No unresolved investigation ambiguity was recorded; "
        "continue monitoring the enriched telemetry and IOC matches."
    )


lines.append("")


# ==================================================
# 6. Artifact Index
# ==================================================

lines.append(
    "## Artifact Index"
)

lines.append(
    "| PATH | SHA256 | SIZE |"
)

lines.append(
    "|---|---|---:|"
)


for artifact in artifacts:

    lines.append(
        f"| `{artifact['path']}` | "
        f"`{artifact['sha256']}` | "
        f"{artifact['size']} |"
    )


# Explain the two control artifacts without
# pretending they can hash themselves.

lines.append(
    "| `handoff/shift_handoff.md` | "
    "`self-referential-control-artifact` | - |"
)

lines.append(
    "| `MANIFEST.json` | "
    "`self-referential-control-artifact` | - |"
)


lines.append("")


with open(
    output_path,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "\n".join(lines)
    )

    f.write("\n")

PY


# --------------------------------------------------
# Install completed handoff
# --------------------------------------------------

cp "$HANDOFF_DRAFT" "$HANDOFF"


# --------------------------------------------------
# 5. Word count <= 900
# --------------------------------------------------

WORD_COUNT=$(wc -w < "$HANDOFF")


if [[ "$WORD_COUNT" -gt 900 ]]; then
    fail "shift_handoff.md exceeds 900 words ($WORD_COUNT)"
fi


# --------------------------------------------------
# 6. Verify exact required headings
# --------------------------------------------------

REQUIRED_HEADINGS=(

    "## Shift Identifier"
    "## Situation"
    "## Incidents"
    "## Campaign Assessment"
    "## Open Items for Next Shift"
    "## Artifact Index"
)


for heading in "${REQUIRED_HEADINGS[@]}"
do

    if ! grep -Fxq "$heading" "$HANDOFF"; then
        fail "handoff missing heading: $heading"
    fi

done


HEADING_COUNT=$(grep -c '^## ' "$HANDOFF")


if [[ "$HEADING_COUNT" -ne 6 ]]; then
    fail "handoff must contain exactly 6 level-2 sections; found $HEADING_COUNT"
fi


echo "[handoff] shift_handoff.md: $WORD_COUNT words, 6 sections OK"


# --------------------------------------------------
# 7. Hash final handoff itself for MANIFEST
# --------------------------------------------------

HANDOFF_HASH=$(sha256sum "$HANDOFF" | awk '{print $1}')
HANDOFF_SIZE=$(stat -c '%s' "$HANDOFF")


# --------------------------------------------------
# Artifact counts
#
# Count completed files by top-level directory.
# --------------------------------------------------

RUNTIME_COUNT=$(find "$SHIFT_WORKSPACE/runtime" -type f -size +0c | wc -l)
ENRICHED_COUNT=$(find "$SHIFT_WORKSPACE/enriched" -type f -size +0c | wc -l)
ALERTS_COUNT=$(find "$SHIFT_WORKSPACE/alerts" -type f -size +0c | wc -l)
INVESTIGATIONS_COUNT=$(find "$SHIFT_WORKSPACE/investigations" -type f -size +0c | wc -l)
CAMPAIGN_COUNT=$(find "$SHIFT_WORKSPACE/campaign" -type f -size +0c | wc -l)
REPORTS_COUNT=$(find "$SHIFT_WORKSPACE/reports" -type f -size +0c | wc -l)
RESPONSE_COUNT=$(find "$SHIFT_WORKSPACE/response" -type f -size +0c | wc -l)
HANDOFF_COUNT=$(find "$SHIFT_WORKSPACE/handoff" -type f -size +0c | wc -l)


# --------------------------------------------------
# Incident IDs JSON
# --------------------------------------------------

INCIDENT_IDS_JSON=$(
    jq '[.incidents[].incident_id]' "$INCIDENTS"
)


# --------------------------------------------------
# Add final handoff hash into manifest file list
# --------------------------------------------------

FINAL_FILES=$(
    jq \
        --arg path "handoff/shift_handoff.md" \
        --arg hash "$HANDOFF_HASH" \
        --argjson size "$HANDOFF_SIZE" \
    '
        . + [
            {
                path: $path,
                sha256: $hash,
                size: $size
            }
        ]
        | sort_by(.path)
    ' "$ARTIFACT_JSON"
)


# --------------------------------------------------
# 8. Write MANIFEST.json
# --------------------------------------------------

jq -n \
    --arg shift_id "$SHIFT_ID" \
    --arg analyst_host "$ANALYST_HOST" \
    --arg started_at "$STARTED_AT" \
    --arg ended_at "$ENDED_AT" \
    --argjson duration_hours "$DURATION_HOURS" \
    --argjson files "$FINAL_FILES" \
    --argjson runtime "$RUNTIME_COUNT" \
    --argjson enriched "$ENRICHED_COUNT" \
    --argjson alerts "$ALERTS_COUNT" \
    --argjson investigations "$INVESTIGATIONS_COUNT" \
    --argjson campaign "$CAMPAIGN_COUNT" \
    --argjson reports "$REPORTS_COUNT" \
    --argjson response "$RESPONSE_COUNT" \
    --argjson handoff "$HANDOFF_COUNT" \
    --argjson incident_ids "$INCIDENT_IDS_JSON" \
    --argjson campaign_linked "$CAMPAIGN_LINKED" \
    --arg cluster_id "$CLUSTER_ID" \
'
{
    shift_id: $shift_id,

    analyst_host: $analyst_host,

    started_at: $started_at,

    ended_at: $ended_at,

    duration_hours: $duration_hours,

    files: $files,

    artifact_counts: {
        runtime: $runtime,
        enriched: $enriched,
        alerts: $alerts,
        investigations: $investigations,
        campaign: $campaign,
        reports: $reports,
        response: $response,
        handoff: $handoff
    },

    incident_ids: $incident_ids,

    campaign_linked: $campaign_linked,

    cluster_id: $cluster_id
}
' > "$MANIFEST"


# --------------------------------------------------
# MANIFEST must be valid and non-empty
# --------------------------------------------------

if [[ ! -s "$MANIFEST" ]]; then
    fail "MANIFEST.json is missing or empty"
fi


if ! jq empty "$MANIFEST" >/dev/null 2>&1; then
    fail "MANIFEST.json is invalid JSON"
fi


# --------------------------------------------------
# 9. Verify incident IDs used in handoff
# --------------------------------------------------

mapfile -t HANDOFF_IDS < <(
    grep -oE 'INC-[0-9]{8}-[A-Z]' "$HANDOFF" |
    sort -u
)


for iid in "${HANDOFF_IDS[@]}"
do

    if ! jq -e \
        --arg id "$iid" \
        '.incidents[] | select(.incident_id == $id)' \
        "$INCIDENTS" >/dev/null
    then

        fail "handoff contains unknown incident ID: $iid"

    fi

done


echo -n "[handoff] incident IDs in handoff: "

printf '%s ' "${HANDOFF_IDS[@]}"

echo "(all in incidents.json: OK)"


# --------------------------------------------------
# Final workspace completeness check
# --------------------------------------------------

FINAL_REQUIRED=(

    "MANIFEST.json"

    "${REQUIRED_FILES[@]}"

    "handoff/shift_handoff.md"
)


FINAL_COUNT=0


for relative in "${FINAL_REQUIRED[@]}"
do

    file="$SHIFT_WORKSPACE/$relative"

    if [[ ! -f "$file" ]]; then
        fail "final workspace missing: $relative"
    fi

    if [[ ! -s "$file" ]]; then
        fail "final workspace file empty: $relative"
    fi

    FINAL_COUNT=$((FINAL_COUNT + 1))

done


# --------------------------------------------------
# Manifest statistics
# --------------------------------------------------

MANIFEST_FILES=$(jq '.files | length' "$MANIFEST")

TOTAL_BYTES=$(
    jq '[.files[].size] | add // 0' "$MANIFEST"
)

TOTAL_KB=$(
    python3 - "$TOTAL_BYTES" <<'PY'
import sys

size = int(sys.argv[1])

print(f"{size / 1024:.1f}")
PY
)


echo "[handoff] MANIFEST.json: $MANIFEST_FILES hashed files, ${TOTAL_KB} KB total"

echo "[handoff] final workspace: $FINAL_COUNT required files OK"

echo "[handoff] campaign_linked=$CAMPAIGN_LINKED cluster=$CLUSTER_ID"

echo "[handoff] handoff package complete"
