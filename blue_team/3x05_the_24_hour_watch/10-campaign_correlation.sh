#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[campaign] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR WAZUH_EXPORTS
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


# --------------------------------------------------
# Files
# --------------------------------------------------

FINDING_A="$SHIFT_WORKSPACE/investigations/incident_A.json"
FINDING_B="$SHIFT_WORKSPACE/investigations/incident_B.json"
FINDING_C="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"

INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"

CAMPAIGN_SUMMARY="$WAZUH_EXPORTS/campaign_dashboard_summary.md"
WORKFLOW="$WAZUH_EXPORTS/exported_dashboard_workflow.json"

OUTPUT="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"


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
# Check all required files
# --------------------------------------------------

for file in \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$INCIDENTS" \
    "$IOC_FILE" \
    "$CAMPAIGN_SUMMARY" \
    "$WORKFLOW"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# Validate JSON files.

for file in \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$INCIDENTS" \
    "$IOC_FILE" \
    "$WORKFLOW"
do
    if ! jq empty "$file" >/dev/null 2>&1; then
        fail "invalid JSON: $file"
    fi
done


echo "[campaign] loading 3 incident findings"


# --------------------------------------------------
# IOC count
# --------------------------------------------------

IOC_COUNT=$(jq '.iocs | length' "$IOC_FILE")

echo "[campaign] ioc feed: $IOC_COUNT IOCs loaded"


# --------------------------------------------------
# Run correlation
# --------------------------------------------------

mkdir -p "$SHIFT_WORKSPACE/campaign"


python3 - \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$INCIDENTS" \
    "$IOC_FILE" \
    "$EVENTS_FILE" \
    "$CAMPAIGN_SUMMARY" \
    "$WORKFLOW" \
    "$OUTPUT" <<'PY'

import json
import sys
import re
from datetime import datetime


finding_paths = {
    "A": sys.argv[1],
    "B": sys.argv[2],
    "C": sys.argv[3],
}

incidents_path = sys.argv[4]
ioc_path = sys.argv[5]
events_path = sys.argv[6]
summary_path = sys.argv[7]
workflow_path = sys.argv[8]
output_path = sys.argv[9]


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_time(value):

    if not value:
        return None

    value = str(value).strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def event_id(event):
    return str(
        event.get("event_id")
        or event.get("id")
        or event.get("event_uid")
        or (
            event.get("event", {}).get("id")
            if isinstance(event.get("event"), dict)
            else ""
        )
        or ""
    )


def extract_event_iocs(event):
    """
    Extract IP addresses and user/account values
    from one enriched event.
    """

    values = set()

    # IP fields

    candidates = [
        event.get("src_ip"),
        event.get("dst_ip"),
    ]

    source = event.get("source")
    destination = event.get("destination")
    src = event.get("src")
    dst = event.get("dst")

    if isinstance(source, dict):
        candidates.append(source.get("ip"))

    if isinstance(destination, dict):
        candidates.append(destination.get("ip"))

    if isinstance(src, dict):
        candidates.append(src.get("ip"))

    if isinstance(dst, dict):
        candidates.append(dst.get("ip"))

    # User/account fields

    candidates.extend([
        event.get("user"),
        event.get("username"),
        event.get("account"),
    ])

    user_obj = event.get("user")

    if isinstance(user_obj, dict):
        candidates.extend([
            user_obj.get("name"),
            user_obj.get("id"),
        ])

    for value in candidates:

        if value is None:
            continue

        if isinstance(value, (str, int)):
            values.add(str(value))

    return values


# --------------------------------------------------
# Load findings
# --------------------------------------------------

findings = {
    name: load_json(path)
    for name, path in finding_paths.items()
}


# --------------------------------------------------
# Load correlated incident records
# --------------------------------------------------

incident_data = load_json(incidents_path)

incident_records = {}

for incident in incident_data.get("incidents", []):

    iid = str(incident.get("incident_id", ""))

    if iid.endswith("-A"):
        incident_records["A"] = incident

    elif iid.endswith("-B"):
        incident_records["B"] = incident

    elif iid.endswith("-C"):
        incident_records["C"] = incident


for name in ("A", "B", "C"):

    if name not in incident_records:
        raise SystemExit(
            f"Incident {name} missing from incidents.json"
        )


# --------------------------------------------------
# Load IOC feed
# --------------------------------------------------

ioc_data = load_json(ioc_path)

feed_values = set()

for item in ioc_data.get("iocs", []):

    value = (
        item.get("value")
        or item.get("indicator")
        or item.get("ioc")
    )

    if value is not None:
        feed_values.add(str(value))


# --------------------------------------------------
# Load enriched events
# --------------------------------------------------

events = []

if events_path.endswith(".jsonl"):

    with open(events_path, "r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if line:
                events.append(json.loads(line))

else:

    data = load_json(events_path)

    if isinstance(data, list):
        events = data
    else:
        events = [data]


events_by_id = {}

for event in events:

    eid = event_id(event)

    if eid:
        events_by_id[eid] = event


# --------------------------------------------------
# 3. Count direct IOC-feed matches per incident
#
# Only event_refs from each finding are checked.
# --------------------------------------------------

feed_match_counts = {}


for name in ("A", "B", "C"):

    finding = findings[name]

    matched_values = set()

    for ref in finding.get("event_refs", []):

        event = events_by_id.get(str(ref))

        if not event:
            continue

        event_values = extract_event_iocs(event)

        matched_values.update(
            event_values.intersection(feed_values)
        )

    feed_match_counts[name] = len(matched_values)


# --------------------------------------------------
# Pairwise matrices
# --------------------------------------------------

pairs = [
    ("A", "B"),
    ("A", "C"),
    ("B", "C"),
]


ioc_overlap_matrix = {}
tactic_overlap_matrix = {}
temporal_matrix = {}

linked_pairs = []
link_reasons = {}


for left, right in pairs:

    key = f"{left}-{right}"

    left_inc = incident_records[left]
    right_inc = incident_records[right]

    left_finding = findings[left]
    right_finding = findings[right]


    # --------------------------------------------------
    # IOC overlap
    # --------------------------------------------------

    left_iocs = set(
        str(x)
        for x in left_inc.get("ioc_list", [])
        if x
    )

    right_iocs = set(
        str(x)
        for x in right_inc.get("ioc_list", [])
        if x
    )

    shared_iocs = left_iocs.intersection(right_iocs)

    ioc_overlap = len(shared_iocs)

    ioc_overlap_matrix[key] = ioc_overlap


    # --------------------------------------------------
    # ATT&CK technique overlap
    # --------------------------------------------------

    left_techniques = set(
        left_finding.get("attack_techniques", [])
    )

    right_techniques = set(
        right_finding.get("attack_techniques", [])
    )

    tactic_overlap = len(
        left_techniques.intersection(right_techniques)
    )

    tactic_overlap_matrix[key] = tactic_overlap


    # --------------------------------------------------
    # Temporal distance
    # --------------------------------------------------

    left_first = parse_time(
        left_inc.get("first_seen")
    )

    left_last = parse_time(
        left_inc.get("last_seen")
    )

    right_first = parse_time(
        right_inc.get("first_seen")
    )

    right_last = parse_time(
        right_inc.get("last_seen")
    )


    temporal_minutes = 0


    if all([
        left_first,
        left_last,
        right_first,
        right_last,
    ]):

        # Determine which incident happened first.

        if left_first <= right_first:

            earlier_last = left_last
            later_first = right_first

        else:

            earlier_last = right_last
            later_first = left_first


        difference = (
            later_first - earlier_last
        ).total_seconds() / 60


        # If incidents overlap in time, distance is zero.

        temporal_minutes = max(
            0,
            int(round(difference))
        )


    temporal_matrix[key] = temporal_minutes


    # --------------------------------------------------
    # Shared hosts
    # --------------------------------------------------

    left_hosts = {
        str(x).lower()
        for x in left_inc.get("host_list", [])
        if x
    }

    right_hosts = {
        str(x).lower()
        for x in right_inc.get("host_list", [])
        if x
    }

    shared_host = bool(
        left_hosts.intersection(right_hosts)
    )


    # --------------------------------------------------
    # Shared users
    # --------------------------------------------------

    left_users = {
        str(x).lower()
        for x in left_inc.get("user_list", [])
        if x
    }

    right_users = {
        str(x).lower()
        for x in right_inc.get("user_list", [])
        if x
    }

    shared_user = bool(
        left_users.intersection(right_users)
    )


    # --------------------------------------------------
    # Mechanical linkage rules
    # --------------------------------------------------

    reasons = []


    # Rule 1:
    # Shared IOC + direct feed match for at least
    # one incident.

    if (
        ioc_overlap >= 1
        and
        (
            feed_match_counts[left] > 0
            or
            feed_match_counts[right] > 0
        )
    ):
        reasons.append("shared_ioc")


    # Rule 2:
    # At least 2 shared ATT&CK techniques and
    # no more than 6 hours apart.

    if (
        tactic_overlap >= 2
        and
        temporal_minutes <= 360
    ):
        reasons.append("tactical_temporal")


    # Rule 3:
    # Shared user.

    if shared_user:
        reasons.append("shared_user")


    # Rule 4:
    # Shared host.

    if shared_host:
        reasons.append("shared_host")


    if reasons:

        linked_pairs.append(key)
        link_reasons[key] = reasons


# --------------------------------------------------
# Campaign verdict
#
# One linked pair means at least two incidents
# are mechanically connected.
# --------------------------------------------------

campaign_linked = len(linked_pairs) >= 1


# --------------------------------------------------
# HC-RED7 assignment
#
# At least one incident participating in a linked
# pair must have a direct feed match.
# --------------------------------------------------

linked_incidents = set()

for pair in linked_pairs:

    left, right = pair.split("-")

    linked_incidents.add(left)
    linked_incidents.add(right)


has_linked_feed_match = any(
    feed_match_counts[name] > 0
    for name in linked_incidents
)


if campaign_linked and has_linked_feed_match:
    cluster_id = "HC-RED7"
else:
    cluster_id = "unknown"


# --------------------------------------------------
# Read Wazuh campaign summary
# --------------------------------------------------

with open(
    summary_path,
    "r",
    encoding="utf-8"
) as f:
    summary_text = f.read()


# Verify workflow JSON is readable.

workflow = load_json(workflow_path)


# --------------------------------------------------
# Extract useful export-view verdict
# --------------------------------------------------

linked_match = re.search(
    r'campaign[_ ]linked\s*[:=]\s*(true|false)',
    summary_text,
    flags=re.IGNORECASE,
)

cluster_match = re.search(
    r'cluster(?:_id)?\s*[:=]\s*(HC-RED7|unknown)',
    summary_text,
    flags=re.IGNORECASE,
)


export_campaign = None
export_cluster = None


if linked_match:
    export_campaign = (
        linked_match.group(1).lower() == "true"
    )


if cluster_match:
    export_cluster = cluster_match.group(1)


if export_campaign is not None:

    export_view_verdict = (
        f"campaign_linked="
        f"{str(export_campaign).lower()}"
    )

    if export_cluster:
        export_view_verdict += (
            f" cluster={export_cluster}"
        )

else:

    # If the markdown uses prose rather than
    # machine-style key/value text, preserve a
    # short non-empty line as the export verdict.

    meaningful_lines = [
        line.strip()
        for line in summary_text.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
    ]

    if meaningful_lines:
        export_view_verdict = meaningful_lines[0][:200]
    else:
        export_view_verdict = "not stated"


# --------------------------------------------------
# Supporting totals
# --------------------------------------------------

shared_iocs_total = sum(
    ioc_overlap_matrix.values()
)

shared_tactics_total = sum(
    tactic_overlap_matrix.values()
)


# --------------------------------------------------
# Confidence
# --------------------------------------------------
#
# High:
# mechanical link + HC-RED7 feed evidence +
# export view supports campaign link.
#
# Medium:
# campaign mechanically linked, but export view
# is missing or does not clearly agree.
#
# Low:
# no mechanical campaign link.
# --------------------------------------------------

if (
    campaign_linked
    and
    cluster_id == "HC-RED7"
    and
    export_campaign is True
):

    confidence = "high"

elif campaign_linked:

    confidence = "medium"

else:

    confidence = "low"


# --------------------------------------------------
# Output
# --------------------------------------------------

result = {

    "incidents": [
        findings["A"].get("incident_id", ""),
        findings["B"].get("incident_id", ""),
        findings["C"].get("incident_id", ""),
    ],

    "ioc_overlap_matrix":
        ioc_overlap_matrix,

    "tactic_overlap_matrix":
        tactic_overlap_matrix,

    "temporal_distance_minutes":
        temporal_matrix,

    "ioc_feed_matches":
        feed_match_counts,

    "linked_pairs":
        linked_pairs,

    "campaign_linked":
        campaign_linked,

    "cluster_id":
        cluster_id,

    "confidence":
        confidence,

    "export_view_verdict":
        export_view_verdict,

    "supporting_counts": {
        "shared_iocs_total":
            shared_iocs_total,

        "shared_tactics_total":
            shared_tactics_total,
    },
}


with open(
    output_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        result,
        f,
        indent=2,
    )

    f.write("\n")


# --------------------------------------------------
# Human-readable output
# --------------------------------------------------

for left, right in pairs:

    key = f"{left}-{right}"

    print(
        f"[campaign] {key}: "
        f"ioc_overlap={ioc_overlap_matrix[key]} "
        f"tactic_overlap={tactic_overlap_matrix[key]} "
        f"temporal_dist={temporal_matrix[key]}min"
    )


print(
    "[campaign] feed matches: "
    f"A={feed_match_counts['A']} "
    f"B={feed_match_counts['B']} "
    f"C={feed_match_counts['C']}"
)


if linked_pairs:

    pair_text = []

    for pair in linked_pairs:

        reasons = "+".join(
            link_reasons.get(pair, [])
        )

        pair_text.append(
            f"{pair} ({reasons})"
        )

    print(
        "[campaign] linked pairs: "
        + ", ".join(pair_text)
    )

else:

    print("[campaign] linked pairs: none")


print(
    f"[campaign] export view: "
    f"{export_view_verdict}"
)


print(
    "[campaign] verdict: "
    f"campaign_linked={str(campaign_linked).lower()} "
    f"cluster={cluster_id} "
    f"confidence={confidence}"
)

PY


# --------------------------------------------------
# Verify output
# --------------------------------------------------

if [[ ! -s "$OUTPUT" ]]; then
    fail "campaign_assessment.json was not created"
fi


if ! jq empty "$OUTPUT" >/dev/null 2>&1; then
    fail "campaign_assessment.json is invalid JSON"
fi


echo "[campaign] campaign_assessment.json written"
