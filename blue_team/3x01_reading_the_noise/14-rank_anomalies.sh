#!/bin/bash

# ============================================================
# Task 14 - Anomaly Priority Ranking
#
# Reads:
#   anomalies_auth.json
#   anomalies_process.json
#   anomalies_network.json
#   correlated_anomalies.json
#
# Produces:
#   ranked_anomalies.json
#
# Priority score:
#
#   (severity value * asset criticality multiplier)
#   + cross-source correlation bonus
#   + off-hours bonus
#   + high-risk category bonus
#
# The output preserves every original anomaly field and adds:
#   - priority_score
#   - score_breakdown
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff/}"

AUTH_FILE="anomalies_auth.json"
PROCESS_FILE="anomalies_process.json"
NETWORK_FILE="anomalies_network.json"
CORRELATED_FILE="correlated_anomalies.json"

OUTPUT_FILE="ranked_anomalies.json"


# ------------------------------------------------------------
# Business hours
#
# Keep this consistent with Task 8.
#
# If an anomaly already contains an off_hours/is_off_hours
# boolean, that value is preferred.
#
# Otherwise:
#   business hours = 08:00 inclusive to 18:00 exclusive
# ------------------------------------------------------------

BUSINESS_START_HOUR="${BUSINESS_START_HOUR:-8}"
BUSINESS_END_HOUR="${BUSINESS_END_HOUR:-18}"


# ============================================================
# 2. Optional HANDOFF_DIR fallback
#
# Normally these files are produced in the project directory.
# ============================================================

find_input_file() {
    local filename="$1"

    if [ -f "$filename" ]; then
        printf '%s\n' "$filename"
        return
    fi

    if [ -f "${HANDOFF_DIR%/}/data/$filename" ]; then
        printf '%s\n' "${HANDOFF_DIR%/}/data/$filename"
        return
    fi

    echo "Error: $filename not found" >&2
    exit 1
}


AUTH_FILE="$(find_input_file "$AUTH_FILE")"
PROCESS_FILE="$(find_input_file "$PROCESS_FILE")"
NETWORK_FILE="$(find_input_file "$NETWORK_FILE")"
CORRELATED_FILE="$(find_input_file "$CORRELATED_FILE")"


# ============================================================
# 3. Validate business-hour configuration
# ============================================================

case "$BUSINESS_START_HOUR" in
    ''|*[!0-9]*)
        echo "Error: BUSINESS_START_HOUR must be 0-23" >&2
        exit 1
        ;;
esac

case "$BUSINESS_END_HOUR" in
    ''|*[!0-9]*)
        echo "Error: BUSINESS_END_HOUR must be 1-24" >&2
        exit 1
        ;;
esac

if [ "$BUSINESS_START_HOUR" -gt 23 ]; then
    echo "Error: BUSINESS_START_HOUR must be 0-23" >&2
    exit 1
fi

if [ "$BUSINESS_END_HOUR" -lt 1 ] || \
   [ "$BUSINESS_END_HOUR" -gt 24 ]; then
    echo "Error: BUSINESS_END_HOUR must be 1-24" >&2
    exit 1
fi

if [ "$BUSINESS_START_HOUR" -ge "$BUSINESS_END_HOUR" ]; then
    echo "Error: business start hour must be before end hour" >&2
    exit 1
fi


# ============================================================
# 4. Rank anomalies
# ============================================================

python3 -W error - \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$CORRELATED_FILE" \
    "$OUTPUT_FILE" \
    "$BUSINESS_START_HOUR" \
    "$BUSINESS_END_HOUR" <<'PYTHON'

import json
import os
import sys
from datetime import datetime, timezone


auth_file = sys.argv[1]
process_file = sys.argv[2]
network_file = sys.argv[3]
correlated_file = sys.argv[4]

output_file = sys.argv[5]

business_start = int(sys.argv[6])
business_end = int(sys.argv[7])


# ============================================================
# Required scoring values from the task
# ============================================================

SEVERITY_VALUES = {
    "low": 1,
    "medium": 3,
    "high": 5,
    "critical": 8,
}


ASSET_MULTIPLIERS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


HIGH_RISK_TYPES = {
    "high_risk_process",
    "privilege_escalation_surge",
    "external_destination_new",
}


# ============================================================
# 5. Load JSON array or NDJSON
# ============================================================

def load_records(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    if not text:
        return []

    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        records = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}: invalid JSON on line "
                    f"{line_number}: {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"{path}: line {line_number} "
                    "is not a JSON object"
                )

            records.append(record)

        return records


    if isinstance(data, list):

        if not all(
            isinstance(record, dict)
            for record in data
        ):
            raise ValueError(
                f"{path}: JSON array contains "
                "a non-object item"
            )

        return data


    if isinstance(data, dict):
        return [data]


    raise ValueError(
        f"{path}: expected JSON objects"
    )


# ============================================================
# 6. General helpers
# ============================================================

def present(value):
    if value is None:
        return False

    if isinstance(value, str) and not value.strip():
        return False

    return True


def normal_text(value):
    if not present(value):
        return None

    return str(value).strip().lower()


# ============================================================
# 7. Severity score
# ============================================================

def severity_details(record, source_name, item_number):

    severity = normal_text(
        record.get("severity")
    )

    if severity not in SEVERITY_VALUES:
        raise ValueError(
            f"{source_name} item {item_number}: "
            "missing or unsupported severity"
        )

    return (
        severity,
        SEVERITY_VALUES[severity]
    )


# ============================================================
# 8. Asset criticality
#
# Accept a few reasonable representations because enrichment
# may have been preserved differently by upstream scripts.
#
# Preferred:
#   asset_criticality
#
# Also accepted:
#   criticality
#   asset.criticality
#
# If no criticality survived into the anomaly record, use
# multiplier 1. This is a neutral multiplier: missing context
# receives no extra priority boost.
# ============================================================

def asset_details(record):

    value = record.get(
        "asset_criticality"
    )


    if not present(value):
        value = record.get(
            "criticality"
        )


    asset = record.get(
        "asset"
    )

    if (
        not present(value)
        and isinstance(asset, dict)
    ):
        value = asset.get(
            "criticality"
        )


    criticality = normal_text(
        value
    )


    if criticality in ASSET_MULTIPLIERS:

        return (
            criticality,
            ASSET_MULTIPLIERS[
                criticality
            ],
            False,
        )


    # Missing asset context receives no multiplier boost.
    return (
        "unknown",
        1,
        True,
    )


# ============================================================
# 9. Determine whether the anomaly is off-hours
# ============================================================

def parse_timestamp(value):

    if not isinstance(value, str):
        return None

    text = value.strip()

    if not text:
        return None


    if text.endswith("Z"):
        text = (
            text[:-1]
            + "+00:00"
        )


    try:
        timestamp = datetime.fromisoformat(
            text
        )

    except ValueError:
        return None


    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )


    return timestamp.astimezone(
        timezone.utc
    )


def is_off_hours(record):

    # --------------------------------------------------------
    # Prefer an explicit upstream classification.
    # --------------------------------------------------------

    for field in (
        "off_hours",
        "is_off_hours",
    ):

        value = record.get(field)

        if isinstance(value, bool):
            return value


    # --------------------------------------------------------
    # Otherwise derive it from the anomaly timestamp.
    # --------------------------------------------------------

    timestamp = parse_timestamp(
        record.get("timestamp")
    )


    if timestamp is None:
        # Do not award a bonus when the timestamp cannot
        # establish that the event was off-hours.
        return False


    hour = timestamp.hour


    return not (
        business_start
        <= hour
        < business_end
    )


# ============================================================
# 10. Count unique source types
# ============================================================

def source_name_from_item(item):

    if isinstance(item, str):

        value = item.strip()

        if value:
            return value

        return None


    if isinstance(item, dict):

        for field in (
            "source_type",
            "source",
            "type",
            "name",
        ):

            value = item.get(field)

            if present(value):
                return str(value).strip()


    return None


def source_count(record, is_correlated):

    # --------------------------------------------------------
    # An upstream correlation task may already store a count.
    # --------------------------------------------------------

    value = record.get(
        "source_count"
    )

    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    ):
        return value


    # --------------------------------------------------------
    # Try common list fields.
    # --------------------------------------------------------

    for field in (
        "source_types",
        "sources",
        "evidence_sources",
    ):

        value = record.get(field)

        if not isinstance(value, list):
            continue


        unique_sources = set()


        for item in value:

            source = source_name_from_item(
                item
            )

            if source is not None:
                unique_sources.add(
                    source
                )


        if unique_sources:
            return len(
                unique_sources
            )


    # --------------------------------------------------------
    # A normal single-source anomaly.
    # --------------------------------------------------------

    source_type = record.get(
        "source_type"
    )

    if present(source_type):
        return 1


    # --------------------------------------------------------
    # correlated_anomalies.json represents correlations.
    #
    # If its explicit source list was not preserved, the
    # minimum cross-source correlation is two sources.
    # --------------------------------------------------------

    if is_correlated:
        return 2


    return 1


# ============================================================
# 11. High-risk category bonus
# ============================================================

def is_high_risk(record):

    anomaly_type = normal_text(
        record.get("anomaly_type")
    )


    if anomaly_type in HIGH_RISK_TYPES:
        return True


    # Correlated records may preserve several contributing
    # anomaly types.
    anomaly_types = record.get(
        "anomaly_types"
    )


    if isinstance(
        anomaly_types,
        list
    ):

        for value in anomaly_types:

            if normal_text(
                value
            ) in HIGH_RISK_TYPES:

                return True


    return False


# ============================================================
# 12. Produce one ranked record
# ============================================================

def score_record(
    original,
    source_name,
    item_number,
    is_correlated
):

    # Preserve the full original record.
    record = dict(original)


    severity, severity_value = (
        severity_details(
            record,
            source_name,
            item_number,
        )
    )


    (
        criticality,
        asset_multiplier,
        criticality_missing,
    ) = asset_details(
        record
    )


    sources = source_count(
        record,
        is_correlated
    )


    # +2 for every source beyond the first.
    additional_sources = max(
        sources - 1,
        0
    )

    correlation_bonus = (
        additional_sources * 2
    )


    off_hours = is_off_hours(
        record
    )

    offhours_bonus = (
        1
        if off_hours
        else 0
    )


    high_risk = is_high_risk(
        record
    )

    high_risk_bonus = (
        2
        if high_risk
        else 0
    )


    severity_asset_score = (
        severity_value
        * asset_multiplier
    )


    priority_score = (
        severity_asset_score
        + correlation_bonus
        + offhours_bonus
        + high_risk_bonus
    )


    # --------------------------------------------------------
    # Explain every part of the result.
    # --------------------------------------------------------

    record[
        "score_breakdown"
    ] = {

        "severity": severity,

        "severity_value":
            severity_value,

        "asset_criticality":
            criticality,

        "asset_criticality_multiplier":
            asset_multiplier,

        "asset_criticality_missing":
            criticality_missing,

        "severity_asset_score":
            severity_asset_score,

        "source_count":
            sources,

        "additional_sources":
            additional_sources,

        "cross_source_bonus":
            correlation_bonus,

        "off_hours":
            off_hours,

        "offhours_bonus":
            offhours_bonus,

        "high_risk_category":
            high_risk,

        "high_risk_bonus":
            high_risk_bonus,
    }


    record[
        "priority_score"
    ] = int(
        priority_score
    )


    return record


# ============================================================
# 13. Read all four anomaly files
# ============================================================

inputs = [
    (
        "anomalies_auth.json",
        auth_file,
        False,
    ),
    (
        "anomalies_process.json",
        process_file,
        False,
    ),
    (
        "anomalies_network.json",
        network_file,
        False,
    ),
    (
        "correlated_anomalies.json",
        correlated_file,
        True,
    ),
]


ranked_internal = []


for file_order, (
    source_name,
    path,
    correlated,
) in enumerate(inputs):

    records = load_records(
        path
    )


    for item_number, record in enumerate(
        records,
        start=1
    ):

        scored = score_record(
            record,
            source_name,
            item_number,
            correlated,
        )


        # Internal metadata is used only as a stable tie-breaker.
        # It is not written to the output.
        ranked_internal.append(
            (
                scored,
                file_order,
                item_number,
            )
        )


# ============================================================
# 14. Deterministic sorting
#
# Primary:
#   priority_score descending
#
# Stable tie-breakers:
#   timestamp
#   host
#   anomaly_type
#   input file order
#   original item number
# ============================================================

def sort_key(item):

    record = item[0]
    file_order = item[1]
    item_number = item[2]


    timestamp = str(
        record.get(
            "timestamp"
        )
        or ""
    )


    host = str(
        record.get(
            "host"
        )
        or record.get(
            "hostname"
        )
        or ""
    )


    anomaly_type = str(
        record.get(
            "anomaly_type"
        )
        or "correlated_anomaly"
    )


    return (
        -record[
            "priority_score"
        ],
        timestamp,
        host,
        anomaly_type,
        file_order,
        item_number,
    )


ranked_internal.sort(
    key=sort_key
)


ranked = [
    item[0]
    for item in ranked_internal
]


# ============================================================
# 15. Write output atomically
# ============================================================

temporary_file = (
    output_file + ".tmp"
)


with open(
    temporary_file,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        ranked,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Project requirement:
    # every file ends with a newline.
    handle.write("\n")


os.replace(
    temporary_file,
    output_file
)


# ============================================================
# 16. Human-readable top-five table
# ============================================================

print(
    f"ranked anomalies total : {len(ranked)}"
)

print(
    "top 5:"
)


for position, record in enumerate(
    ranked[:5],
    start=1
):

    host = (
        record.get("host")
        or record.get("hostname")
        or "-"
    )


    anomaly_type = (
        record.get("anomaly_type")
        or "correlated_anomaly"
    )


    score = record[
        "priority_score"
    ]


    print(
        f" {position:<2} "
        f"score {score:<4} "
        f"{str(host):<20} "
        f"{anomaly_type}"
    )


print(
    f"{output_file} written"
)

PYTHON
