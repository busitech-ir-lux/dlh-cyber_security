#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[report] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
ASSETS="$ASSETS_DIR/assets.json"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"

FINDING_A="$SHIFT_WORKSPACE/investigations/incident_A.json"
FINDING_B="$SHIFT_WORKSPACE/investigations/incident_B.json"

FINDING_C="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"

if [[ ! -s "$FINDING_C" ]]; then
    FINDING_C="$SHIFT_WORKSPACE/investigations/incident_C_export.json"
fi


REPORT_DIR="$SHIFT_WORKSPACE/reports"

mkdir -p "$REPORT_DIR"


# --------------------------------------------------
# Find enriched events
# --------------------------------------------------

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"

elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.json"

else

    fail "enriched events file is missing"

fi


# --------------------------------------------------
# Check required files
# --------------------------------------------------

for file in \
    "$INCIDENTS" \
    "$ASSETS" \
    "$IOC_FILE" \
    "$ALERT_QUEUE" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# --------------------------------------------------
# Generate all three reports
# --------------------------------------------------

python3 - \
    "$INCIDENTS" \
    "$ASSETS" \
    "$IOC_FILE" \
    "$ALERT_QUEUE" \
    "$EVENTS_FILE" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$REPORT_DIR" <<'PY'

import json
import re
import sys
from pathlib import Path


incidents_path = sys.argv[1]
assets_path = sys.argv[2]
ioc_path = sys.argv[3]
alerts_path = sys.argv[4]
events_path = sys.argv[5]

finding_paths = {
    "A": sys.argv[6],
    "B": sys.argv[7],
    "C": sys.argv[8],
}

report_dir = Path(sys.argv[9])


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def clean_text(value):
    if value is None:
        return ""

    value = str(value)
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    value = re.sub(r"\s+", " ", value)

    return value.strip()


def table_text(value):
    """Prevent values from breaking Markdown tables."""

    value = clean_text(value)
    value = value.replace("|", "/")

    return value


def defang_ips(text):
    """Defang normal IPv4 addresses throughout report."""

    pattern = re.compile(
        r'(?<![\d\[])'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)'
        r'(?:\.'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}'
        r'(?![\d\]])'
    )

    def replace(match):
        return match.group(0).replace(".", "[.]")

    return pattern.sub(replace, text)


def event_ref(event):

    return str(
        event.get("event_ref")
        or event.get("event_id")
        or event.get("id")
        or event.get("event_uid")
        or (
            event.get("event", {}).get("id")
            if isinstance(event.get("event"), dict)
            else ""
        )
        or ""
    )


def event_timestamp(event):

    return clean_text(
        event.get("timestamp")
        or event.get("@timestamp")
        or event.get("event_time")
        or event.get("time")
        or ""
    )


def event_host(event):

    host = (
        event.get("host")
        or event.get("hostname")
        or ""
    )

    if isinstance(host, dict):
        host = host.get("name", "")

    return clean_text(host).lower()


def event_description(event):

    description = (
        event.get("raw_message")
        or event.get("message")
        or event.get("event_description")
        or event.get("description")
        or event.get("event_category")
        or event.get("category")
        or "event"
    )

    description = clean_text(description)

    return description[:160]


def extract_event_values(event):

    values = set()

    candidates = [
        event.get("src_ip"),
        event.get("dst_ip"),
        event.get("user"),
        event.get("username"),
        event.get("account"),
    ]

    for key in ("source", "destination", "src", "dst"):

        obj = event.get(key)

        if isinstance(obj, dict):
            candidates.append(obj.get("ip"))


    user_obj = event.get("user")

    if isinstance(user_obj, dict):

        candidates.extend([
            user_obj.get("name"),
            user_obj.get("id"),
        ])


    for value in candidates:

        if value is not None and not isinstance(value, dict):

            values.add(str(value))

    return values


def normalize_alerts(data):

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        if isinstance(data.get("alerts"), list):
            return data["alerts"]

    return []


def alert_id(alert):

    return str(
        alert.get("alert_id")
        or alert.get("id")
        or ""
    )


def rule_id(alert):

    rule = alert.get("rule")

    if not isinstance(rule, dict):
        rule = {}

    return clean_text(
        alert.get("rule_id")
        or rule.get("id")
        or alert.get("detection_id")
        or "unknown"
    )


# --------------------------------------------------
# ATT&CK names
#
# Generic lookup, not incident-specific.
# --------------------------------------------------

attack_names = {
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1543.003": "Windows Service",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1059.001": "PowerShell",
    "T1053.005": "Scheduled Task",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1041": "Exfiltration Over C2 Channel",
}


# --------------------------------------------------
# Load source data
# --------------------------------------------------

incidents_data = load_json(incidents_path)
assets_data = load_json(assets_path)
ioc_data = load_json(ioc_path)
alert_data = load_json(alerts_path)

alerts = normalize_alerts(alert_data)


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


events_by_ref = {}

for event in events:

    ref = event_ref(event)

    if ref:
        events_by_ref[ref] = event


# --------------------------------------------------
# Normalize assets
# --------------------------------------------------

if isinstance(assets_data, list):

    assets = assets_data

elif isinstance(assets_data, dict):

    assets = assets_data.get("assets", [])

else:

    assets = []


# --------------------------------------------------
# Normalize IOC feed
# --------------------------------------------------

ioc_items = ioc_data.get("iocs", [])

ioc_lookup = {}


for item in ioc_items:

    value = clean_text(
        item.get("value")
        or item.get("indicator")
        or item.get("ioc")
    )

    if not value:
        continue

    ioc_lookup[value] = {
        "type": clean_text(
            item.get("type") or "unknown"
        ),

        "confidence": clean_text(
            item.get("confidence") or "unknown"
        ),

        "source": "ioc_feed",
    }


# --------------------------------------------------
# Incident lookup
# --------------------------------------------------

incident_lookup = {}


for incident in incidents_data.get("incidents", []):

    iid = clean_text(
        incident.get("incident_id")
    )

    if iid.endswith("-A"):
        incident_lookup["A"] = incident

    elif iid.endswith("-B"):
        incident_lookup["B"] = incident

    elif iid.endswith("-C"):
        incident_lookup["C"] = incident


# --------------------------------------------------
# Report generation
# --------------------------------------------------

total_verified_refs = 0


for letter in ("A", "B", "C"):

    report_name = f"incident_{letter}.md"

    print(
        f"[report] generating {report_name}"
    )


    if letter not in incident_lookup:

        raise SystemExit(
            f"[report] ERROR: Incident {letter} "
            f"missing from incidents.json"
        )


    incident = incident_lookup[letter]
    finding = load_json(
        finding_paths[letter]
    )


    incident_id = clean_text(
        incident.get("incident_id")
    )


    # --------------------------------------------------
    # Evidence References
    # --------------------------------------------------

    finding_refs = []

    for ref in finding.get("event_refs", []):

        ref = clean_text(ref)

        if ref and ref not in finding_refs:
            finding_refs.append(ref)


    # Hard cap = 12

    evidence_refs = finding_refs[:12]


    # Every report reference must exist.

    missing_refs = [
        ref
        for ref in evidence_refs
        if ref not in events_by_ref
    ]


    if missing_refs:

        raise SystemExit(
            "[report] ERROR: "
            f"{letter} missing event refs in enriched data: "
            + ", ".join(missing_refs)
        )


    total_verified_refs += len(
        evidence_refs
    )


    referenced_events = [
        events_by_ref[ref]
        for ref in evidence_refs
    ]


    # --------------------------------------------------
    # Timeline
    #
    # Maximum 15; because refs are capped to 12,
    # this automatically remains below the limit.
    # --------------------------------------------------

    timeline = sorted(
        referenced_events,
        key=lambda e: event_timestamp(e),
    )[:15]


    # --------------------------------------------------
    # Affected Assets
    # --------------------------------------------------

    host_list = []

    for host in incident.get("host_list", []):

        host = clean_text(host).lower()

        if host and host not in host_list:
            host_list.append(host)


    affected_assets = []


    for hostname in host_list:

        match = None


        for asset in assets:

            asset_host = clean_text(
                asset.get("host")
                or asset.get("hostname")
                or asset.get("name")
            ).lower()


            if asset_host == hostname:
                match = asset
                break


        if match:

            affected_assets.append({
                "host": hostname,

                "criticality": clean_text(
                    match.get("criticality")
                    or "unknown"
                ),

                "data_class": clean_text(
                    match.get("data_classification")
                    or match.get("data_class")
                    or "unknown"
                ),

                "zone": clean_text(
                    match.get("zone")
                    or "unknown"
                ),
            })

        else:

            affected_assets.append({
                "host": hostname,
                "criticality": "unknown",
                "data_class": "unknown",
                "zone": "unknown",
            })


    affected_assets = (
        affected_assets[:10]
    )


    # --------------------------------------------------
    # IOC section
    #
    # Start with IOCs from incidents.json.
    # Also find IOC feed matches in referenced events.
    # --------------------------------------------------

    observed_iocs = []


    for value in incident.get(
        "ioc_list", []
    ):

        value = clean_text(value)

        if value and value not in observed_iocs:
            observed_iocs.append(value)


    # Find feed IOC values in evidence events.

    for event in referenced_events:

        values = extract_event_values(event)

        for value in values:

            if (
                value in ioc_lookup
                and
                value not in observed_iocs
            ):
                observed_iocs.append(value)


    ioc_rows = []


    for value in observed_iocs[:15]:

        metadata = ioc_lookup.get(
            value,
            {
                "type": "unknown",
                "confidence": "unknown",
                "source": "incident_correlation",
            }
        )


        ioc_rows.append({
            "type": metadata["type"],
            "value": value,
            "confidence": metadata[
                "confidence"
            ],
            "source": metadata["source"],
        })


    # --------------------------------------------------
    # ATT&CK mapping
    # --------------------------------------------------

    techniques = []

    for technique in finding.get(
        "attack_techniques", []
    ):

        technique = clean_text(
            technique
        )

        if (
            technique
            and
            technique not in techniques
        ):
            techniques.append(technique)


    techniques = techniques[:8]


    hypothesis = clean_text(
        finding.get("hypothesis")
        or "Investigation finding recorded."
    )


    attack_rows = []


    for technique in techniques:

        attack_rows.append({
            "technique": technique,

            "name": attack_names.get(
                technique,
                "ATT&CK technique"
            ),

            "evidence": hypothesis[:160],
        })


    # --------------------------------------------------
    # Detection Performance
    # --------------------------------------------------

    incident_alert_ids = {
        clean_text(x)
        for x in incident.get(
            "alert_ids", []
        )
        if clean_text(x)
    }


    fired_rule_counts = {}


    for alert in alerts:

        aid = alert_id(alert)

        if aid not in incident_alert_ids:
            continue

        rid = rule_id(alert)

        fired_rule_counts[rid] = (
            fired_rule_counts.get(
                rid, 0
            ) + 1
        )


    detection_lines = []


    for rid, count in sorted(
        fired_rule_counts.items()
    ):

        detection_lines.append(
            f"- {rid} | fired | "
            f"{count} alert(s)"
        )


    # Support optional gap fields if a finding
    # contains them.

    missed_rules = (
        finding.get("missed_rules")
        or finding.get(
            "rules_should_have_fired"
        )
        or finding.get(
            "detection_gaps"
        )
        or []
    )


    for item in missed_rules:

        if isinstance(item, dict):

            rid = clean_text(
                item.get("rule_id")
                or item.get("id")
                or "unknown"
            )

        else:

            rid = clean_text(item)


        if rid:

            detection_lines.append(
                f"- {rid} | should have "
                f"fired but did not"
            )


    if not detection_lines:

        detection_lines.append(
            "- No detection rule information "
            "was available for this incident."
        )


    # --------------------------------------------------
    # Recommended Actions
    #
    # Use explicit finding recommendations if present.
    # Otherwise derive bounded actions mechanically
    # from the incident evidence.
    # --------------------------------------------------

    recommendations = []


    explicit_actions = finding.get(
        "recommended_actions"
    )


    if isinstance(
        explicit_actions, list
    ):

        for action in explicit_actions:

            action = clean_text(action)

            if action:
                recommendations.append(
                    action
                )


    if not recommendations:

        if host_list:

            recommendations.append(
                "Contain and review the affected "
                "host(s): "
                + ", ".join(host_list)
                + "."
            )


        user_list = [
            clean_text(x)
            for x in incident.get(
                "user_list", []
            )
            if clean_text(x)
        ]


        if user_list:

            recommendations.append(
                "Review and secure the affected "
                "account(s): "
                + ", ".join(user_list)
                + "."
            )


        if observed_iocs:

            recommendations.append(
                "Block or monitor the confirmed "
                "IOC values at relevant security "
                "controls."
            )


        if techniques:

            recommendations.append(
                "Hunt for the observed ATT&CK "
                "techniques on other systems."
            )


        recommendations.append(
            "Preserve the referenced logs and "
            "events for continued investigation."
        )


        confidence = clean_text(
            finding.get("confidence")
        ).lower()


        ambiguity = clean_text(
            finding.get(
                "ambiguity_notes"
            )
        )


        if (
            confidence != "high"
            and
            ambiguity
        ):

            recommendations.append(
                "Resolve the documented ambiguity: "
                + ambiguity
            )


    recommendations = recommendations[:6]


    # --------------------------------------------------
    # Executive Summary
    #
    # Exactly four controlled sentences.
    # --------------------------------------------------

    first_seen = clean_text(
        incident.get("first_seen")
        or "unknown time"
    )

    last_seen = clean_text(
        incident.get("last_seen")
        or "unknown time"
    )


    host_summary = (
        ", ".join(host_list)
        if host_list
        else "unknown hosts"
    )


    # Remove internal full stops so hypothesis
    # remains one sentence.

    hypothesis_summary = re.sub(
        r"[.!?]+",
        ",",
        hypothesis
    ).strip(" ,")


    confidence = clean_text(
        finding.get("confidence")
        or "unknown"
    )


    executive_sentences = [
        (
            f"{incident_id} affected "
            f"{host_summary} between "
            f"{first_seen} and {last_seen}."
        ),

        (
            f"The investigation hypothesis is "
            f"{hypothesis_summary}."
        ),

        (
            f"The finding has {confidence} "
            f"confidence and maps to "
            f"{len(techniques)} ATT&CK "
            f"technique(s)."
        ),

        (
            f"The incident contains "
            f"{len(incident_alert_ids)} correlated "
            f"alert(s) and "
            f"{len(evidence_refs)} reportable "
            f"evidence reference(s)."
        ),
    ]


    # --------------------------------------------------
    # Cap validation BEFORE writing
    # --------------------------------------------------

    counts = {
        "executive":
            len(executive_sentences),

        "timeline":
            len(timeline),

        "assets":
            len(affected_assets),

        "iocs":
            len(ioc_rows),

        "techniques":
            len(attack_rows),

        "actions":
            len(recommendations),

        "refs":
            len(evidence_refs),
    }


    if not (
        3 <= counts["executive"] <= 5
    ):

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "Executive Summary cap violated"
        )


    if counts["timeline"] > 15:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "timeline exceeds 15 events"
        )


    if counts["assets"] > 10:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "assets exceed 10 rows"
        )


    if counts["iocs"] > 15:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "IOCs exceed 15 rows"
        )


    if counts["techniques"] > 8:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "ATT&CK mapping exceeds 8 rows"
        )


    if counts["actions"] > 6:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "actions exceed 6"
        )


    if counts["refs"] > 12:

        raise SystemExit(
            f"[report] ERROR: {letter} "
            "evidence references exceed 12"
        )


    # --------------------------------------------------
    # Build exact locked report structure
    # --------------------------------------------------

    lines = []


    # 1
    lines.append(
        "## Incident Identifier"
    )

    lines.append(
        incident_id
    )

    lines.append("")


    # 2
    lines.append(
        "## Executive Summary"
    )

    lines.append(
        " ".join(
            executive_sentences
        )
    )

    lines.append("")


    # 3
    lines.append(
        "## Timeline"
    )


    for event in timeline:

        lines.append(
            f"{event_timestamp(event)} | "
            f"{table_text(event_host(event))} | "
            f"{table_text(event_description(event))}"
        )


    lines.append("")


    # 4
    lines.append(
        "## Affected Assets"
    )

    lines.append(
        "| HOST | CRITICALITY | "
        "DATA_CLASS | ZONE |"
    )

    lines.append(
        "|---|---|---|---|"
    )


    for asset in affected_assets:

        lines.append(
            "| "
            + table_text(asset["host"])
            + " | "
            + table_text(
                asset["criticality"]
            )
            + " | "
            + table_text(
                asset["data_class"]
            )
            + " | "
            + table_text(
                asset["zone"]
            )
            + " |"
        )


    lines.append("")


    # 5
    lines.append(
        "## Indicators of Compromise"
    )

    lines.append(
        "| TYPE | VALUE | CONFIDENCE | SOURCE |"
    )

    lines.append(
        "|---|---|---|---|"
    )


    for row in ioc_rows:

        lines.append(
            "| "
            + table_text(row["type"])
            + " | "
            + table_text(row["value"])
            + " | "
            + table_text(
                row["confidence"]
            )
            + " | "
            + table_text(row["source"])
            + " |"
        )


    lines.append("")


    # 6
    lines.append(
        "## ATT&CK Mapping"
    )

    lines.append(
        "| TECHNIQUE | NAME | EVIDENCE |"
    )

    lines.append(
        "|---|---|---|"
    )


    for row in attack_rows:

        lines.append(
            "| "
            + table_text(
                row["technique"]
            )
            + " | "
            + table_text(row["name"])
            + " | "
            + table_text(
                row["evidence"]
            )
            + " |"
        )


    lines.append("")


    # 7
    lines.append(
        "## Detection Performance"
    )

    lines.extend(
        detection_lines
    )

    lines.append("")


    # 8
    lines.append(
        "## Recommended Actions"
    )


    for number, action in enumerate(
        recommendations,
        start=1,
    ):

        lines.append(
            f"{number}. {action}"
        )


    lines.append("")


    # 9
    lines.append(
        "## Evidence References"
    )


    for ref in evidence_refs:

        lines.append(
            f"- {ref}"
        )


    # --------------------------------------------------
    # Defang ALL IPv4 addresses in report body
    # --------------------------------------------------

    report_text = "\n".join(lines)
    report_text = defang_ips(
        report_text
    )

    report_text += "\n"


    # --------------------------------------------------
    # Write report
    # --------------------------------------------------

    report_path = (
        report_dir / report_name
    )


    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report_text)


    print(
        f"[report] {letter}: "
        f"timeline={counts['timeline']} "
        f"assets={counts['assets']} "
        f"IOCs={counts['iocs']} "
        f"techniques={counts['techniques']} "
        f"actions={counts['actions']} "
        f"refs={counts['refs']}"
    )


    print(
        f"[report] {letter}: "
        "section caps respected"
    )


# --------------------------------------------------
# Final result
# --------------------------------------------------

print(
    f"[report] {total_verified_refs} "
    "event references verified against "
    "enriched events"
)

print("[report] reports written")

PY
