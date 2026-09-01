#!/bin/bash

# ============================================================
# Task 12 - Network Anomalies
#
# Reads:
#   baseline_summary.json
#   labeled_events.json
#
# Produces:
#   anomalies_network.json
#
# Detects:
#   - unknown_destination_for_host
#   - unknown_port_for_host
#   - unexpected_zone_flow
#   - volume_burst
#   - external_destination_new
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff/}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

BASELINE_FILE="baseline_summary.json"
EVENTS_FILE="labeled_events.json"
OUTPUT_FILE="anomalies_network.json"


# ============================================================
# 2. Find input files
# ============================================================

# baseline_summary.json may later live inside BASELINE_PKG.
if [ ! -f "$BASELINE_FILE" ] && \
   [ -n "${BASELINE_PKG:-}" ] && \
   [ -f "${BASELINE_PKG%/}/baseline_summary.json" ]; then

    BASELINE_FILE="${BASELINE_PKG%/}/baseline_summary.json"
fi


# labeled_events.json normally comes from an earlier project task.
if [ ! -f "$EVENTS_FILE" ] && \
   [ -f "${HANDOFF_DIR%/}/data/labeled_events.json" ]; then

    EVENTS_FILE="${HANDOFF_DIR%/}/data/labeled_events.json"
fi


if [ ! -f "$BASELINE_FILE" ]; then
    echo "Error: baseline_summary.json not found" >&2
    exit 1
fi

if [ ! -f "$EVENTS_FILE" ]; then
    echo "Error: labeled_events.json not found" >&2
    exit 1
fi


# ============================================================
# 3. Validate BASELINE_DAYS
# ============================================================

case "$BASELINE_DAYS" in
    ''|*[!0-9]*)
        echo "Error: BASELINE_DAYS must be a positive integer" >&2
        exit 1
        ;;
esac

if [ "$BASELINE_DAYS" -lt 1 ]; then
    echo "Error: BASELINE_DAYS must be at least 1" >&2
    exit 1
fi


# ============================================================
# 4. Detect network anomalies
# ============================================================

python3 -W error - \
    "$BASELINE_FILE" \
    "$EVENTS_FILE" \
    "$OUTPUT_FILE" \
    "$BASELINE_DAYS" <<'PYTHON'

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


baseline_file = sys.argv[1]
events_file = sys.argv[2]
output_file = sys.argv[3]
baseline_days_env = int(sys.argv[4])


ANOMALY_TYPES = (
    "unknown_destination_for_host",
    "unknown_port_for_host",
    "unexpected_zone_flow",
    "volume_burst",
    "external_destination_new",
)


# ============================================================
# Helper: load a normal JSON file
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


# ============================================================
# Helper: load JSON array or NDJSON
# ============================================================

def load_events(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    if not text:
        return []

    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        events = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {line_number}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"record on line {line_number} "
                    "is not a JSON object"
                )

            events.append(event)

        return events

    if isinstance(data, list):
        if not all(isinstance(event, dict) for event in data):
            raise ValueError(
                "JSON array contains a non-object record"
            )

        return data

    if isinstance(data, dict):
        return [data]

    raise ValueError(
        "labeled_events.json must contain JSON objects"
    )


# ============================================================
# General helpers
# ============================================================

def present(value):
    if value is None:
        return False

    if isinstance(value, str) and not value.strip():
        return False

    return True


def parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "event has a missing timestamp"
        )

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)

    except ValueError as exc:
        raise ValueError(
            f"invalid timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def iso_utc(value):
    return (
        value
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# Get network section from baseline_summary.json
#
# This accepts:
#
# {
#   "network": { ... }
# }
#
# or:
#
# {
#   "baseline_network": { ... }
# }
#
# It also works if the network baseline is directly at the
# top level.
# ============================================================

def get_network_section(summary):
    for key in (
        "network",
        "baseline_network",
        "network_baseline",
    ):
        value = summary.get(key)

        if isinstance(value, dict):
            return value

    return summary


# ============================================================
# Extract a set from baseline values
#
# Our Task 6 structure is:
#
# "host1": {
#     "10.10.1.10": 42,
#     "10.10.1.53": 10
# }
#
# Therefore the dictionary keys are the observed values.
# ============================================================

def observed_values(value):
    if isinstance(value, dict):
        return {
            str(item)
            for item in value
        }

    if isinstance(value, list):
        return {
            str(item)
            for item in value
            if present(item)
        }

    return set()


# ============================================================
# Count all baseline connections for one host
# ============================================================

def total_count(value):
    if not isinstance(value, dict):
        return 0.0

    total = 0.0

    for entry in value.values():

        if isinstance(entry, bool):
            continue

        if isinstance(entry, (int, float)):
            total += entry

        elif isinstance(entry, dict):
            count = entry.get("count")

            if (
                isinstance(count, (int, float))
                and not isinstance(count, bool)
            ):
                total += count

    return total


# ============================================================
# Get the volume-burst multiplier
#
# IMPORTANT:
# The project forbids hardcoding anomaly thresholds.
#
# Therefore the multiplier MUST already exist in
# baseline_summary.json.
# ============================================================

def get_volume_multiplier(summary, network):
    candidates = []

    network_thresholds = network.get("thresholds")

    if isinstance(network_thresholds, dict):
        candidates.extend(
            [
                network_thresholds.get(
                    "volume_burst_multiplier"
                ),
                network_thresholds.get(
                    "volume_burst_threshold"
                ),
            ]
        )

    summary_thresholds = summary.get("thresholds")

    if isinstance(summary_thresholds, dict):
        candidates.extend(
            [
                summary_thresholds.get(
                    "volume_burst_multiplier"
                ),
                summary_thresholds.get(
                    "volume_burst_threshold"
                ),
            ]
        )

    candidates.extend(
        [
            network.get("volume_burst_multiplier"),
            network.get("volume_burst_threshold"),
        ]
    )

    for value in candidates:

        if isinstance(value, bool):
            continue

        if (
            isinstance(value, (int, float))
            and value > 0
        ):
            return float(value)

    raise ValueError(
        "baseline_summary.json does not contain a "
        "volume-burst multiplier; the anomaly script "
        "must not hardcode one"
    )


# ============================================================
# Build the set of known zone pairs
#
# Task 6 used keys such as:
#
#   INTERNAL->EXTERNAL
# ============================================================

def get_zone_pairs(zone_flows):
    pairs = set()

    if not isinstance(zone_flows, dict):
        return pairs

    for key in zone_flows:

        text = str(key).strip()

        if "->" not in text:
            continue

        src_zone, dst_zone = text.split(
            "->",
            1
        )

        pairs.add(
            (
                src_zone.strip(),
                dst_zone.strip(),
            )
        )

    return pairs


# ============================================================
# Host identity
#
# Prefer hostname.
#
# Network-only telemetry may not have a hostname, so src_ip is
# used as a stable fallback.
# ============================================================

def get_host(event):
    hostname = event.get("hostname")

    if present(hostname):
        return str(hostname).strip()

    src_ip = event.get("src_ip")

    if present(src_ip):
        return str(src_ip).strip()

    return None


# ============================================================
# Event reference
# ============================================================

def get_event_ref(event, record_number):
    value = event.get("event_ref")

    if present(value):
        return str(value)

    return f"record:{record_number}"


# ============================================================
# Severity
#
# The task does not define a separate anomaly severity model,
# so preserve the severity of the event instead of inventing
# another threshold.
# ============================================================

def get_severity(event):
    severity = event.get("severity")

    if not present(severity):
        return "unknown"

    return str(severity).strip().lower()


SEVERITY_ORDER = {
    "unknown": -1,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def highest_severity(events):
    if not events:
        return "unknown"

    severities = [
        get_severity(event)
        for event in events
    ]

    return max(
        severities,
        key=lambda value: SEVERITY_ORDER.get(
            value,
            -1
        )
    )


# ============================================================
# Return a field only when all events in a volume burst have
# the same value.
# ============================================================

def common_value(events, field):
    values = {
        str(event[field]).strip()
        for event in events
        if field in event
        and present(event[field])
    }

    if len(values) == 1:
        return next(iter(values))

    return None


# ============================================================
# Create a normal single-event anomaly
# ============================================================

def make_anomaly(
    event,
    record_number,
    anomaly_type
):
    return {
        "timestamp": event.get("timestamp"),
        "host": get_host(event),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "dst_port": event.get("dst_port"),
        "src_zone": event.get("src_zone"),
        "dst_zone": event.get("dst_zone"),
        "anomaly_type": anomaly_type,
        "severity": get_severity(event),
        "event_refs": [
            get_event_ref(
                event,
                record_number
            )
        ],
    }


# ============================================================
# 5. Read baseline_summary.json
# ============================================================

baseline_summary = load_json(
    baseline_file
)

if not isinstance(
    baseline_summary,
    dict
):
    raise ValueError(
        "baseline_summary.json must be a JSON object"
    )


network = get_network_section(
    baseline_summary
)


# ============================================================
# 6. Get baseline window information
# ============================================================

baseline_window = network.get(
    "baseline_window"
)

if not isinstance(
    baseline_window,
    dict
):
    baseline_window = baseline_summary.get(
        "baseline_window",
        {}
    )


stored_days = baseline_window.get(
    "baseline_days"
)


if (
    isinstance(stored_days, int)
    and stored_days > 0
):
    # A baseline generated with seven days should not be used
    # while Task 12 is told to use five days.
    if stored_days != baseline_days_env:
        raise ValueError(
            "BASELINE_DAYS does not match "
            "baseline_summary.json"
        )

    baseline_days = stored_days

else:
    baseline_days = baseline_days_env


# ============================================================
# 7. Read network baseline
# ============================================================

per_host_destinations = network.get(
    "per_host_destinations",
    {}
)

per_host_ports = network.get(
    "per_host_ports",
    {}
)

zone_flows = network.get(
    "zone_flows",
    {}
)

known_external_data = network.get(
    "known_external_ips",
    {}
)


if not isinstance(
    per_host_destinations,
    dict
):
    raise ValueError(
        "per_host_destinations is missing "
        "from the network baseline"
    )


if not isinstance(
    per_host_ports,
    dict
):
    raise ValueError(
        "per_host_ports is missing "
        "from the network baseline"
    )


# ============================================================
# 8. Convert baseline into lookup sets
# ============================================================

baseline_destinations = {
    str(host): observed_values(values)
    for host, values
    in per_host_destinations.items()
}


baseline_ports = {
    str(host): observed_values(values)
    for host, values
    in per_host_ports.items()
}


known_zone_pairs = get_zone_pairs(
    zone_flows
)


known_external_ips = observed_values(
    known_external_data
)


# ============================================================
# 9. Read the volume-burst threshold FROM THE BASELINE
# ============================================================

volume_multiplier = get_volume_multiplier(
    baseline_summary,
    network
)


# ============================================================
# 10. Calculate baseline hourly connection mean per host
#
# If baseline_summary.json already contains
# per_host_hourly_mean, use it.
#
# Otherwise derive it from the baseline connection counts:
#
# total baseline connections / baseline hours
#
# This means the mean is still derived entirely from baseline
# data rather than being hardcoded.
# ============================================================

host_hourly_mean = {}


explicit_means = network.get(
    "per_host_hourly_mean"
)


if isinstance(explicit_means, dict):

    for host, value in explicit_means.items():

        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
        ):
            host_hourly_mean[
                str(host)
            ] = float(value)


baseline_hours = (
    baseline_days * 24
)


for host, destinations in (
    per_host_destinations.items()
):

    host = str(host)

    if host in host_hourly_mean:
        continue

    connections = total_count(
        destinations
    )

    host_hourly_mean[host] = (
        connections / baseline_hours
    )


# ============================================================
# 11. Load labeled events
# ============================================================

events = load_events(
    events_file
)

if not events:
    raise ValueError(
        "labeled_events.json contains no events"
    )


parsed_events = []


for record_number, event in enumerate(events):

    timestamp = parse_timestamp(
        event.get("timestamp")
    )

    parsed_events.append(
        (
            timestamp,
            record_number,
            event,
        )
    )


# ============================================================
# 12. Derive evaluation window
#
# Baseline:
#   dataset_start -> dataset_start + BASELINE_DAYS
#
# Evaluation:
#   following 24 hours
# ============================================================

dataset_start = min(
    timestamp
    for timestamp, _, _
    in parsed_events
)


evaluation_start = (
    dataset_start
    + timedelta(
        days=baseline_days
    )
)


evaluation_end = (
    evaluation_start
    + timedelta(days=1)
)


evaluation_events = [
    (
        timestamp,
        record_number,
        event,
    )

    for (
        timestamp,
        record_number,
        event,
    ) in parsed_events

    if (
        evaluation_start
        <= timestamp
        < evaluation_end
    )
]


# ============================================================
# 13. Detect anomalies
# ============================================================

anomalies = []

counts = Counter({
    anomaly_type: 0
    for anomaly_type
    in ANOMALY_TYPES
})


# Used later for volume-burst detection.
hourly_connections = defaultdict(list)


for (
    timestamp,
    record_number,
    event,
) in evaluation_events:

    host = get_host(event)

    dst_ip = event.get("dst_ip")
    dst_port = event.get("dst_port")

    src_zone = event.get("src_zone")
    dst_zone = event.get("dst_zone")


    has_dst_ip = present(dst_ip)
    has_dst_port = present(dst_port)


    # Ignore records that do not contain network destination data.
    if (
        not has_dst_ip
        and not has_dst_port
    ):
        continue


    # --------------------------------------------------------
    # unknown_destination_for_host
    # --------------------------------------------------------

    if (
        host is not None
        and has_dst_ip
    ):

        destination = str(
            dst_ip
        ).strip()

        known_destinations = (
            baseline_destinations.get(
                host,
                set()
            )
        )

        if (
            destination
            not in known_destinations
        ):

            anomalies.append(
                make_anomaly(
                    event,
                    record_number,
                    "unknown_destination_for_host"
                )
            )

            counts[
                "unknown_destination_for_host"
            ] += 1


    # --------------------------------------------------------
    # unknown_port_for_host
    # --------------------------------------------------------

    if (
        host is not None
        and has_dst_port
    ):

        port = str(
            dst_port
        ).strip()

        known_ports = baseline_ports.get(
            host,
            set()
        )

        if port not in known_ports:

            anomalies.append(
                make_anomaly(
                    event,
                    record_number,
                    "unknown_port_for_host"
                )
            )

            counts[
                "unknown_port_for_host"
            ] += 1


    # --------------------------------------------------------
    # unexpected_zone_flow
    # --------------------------------------------------------

    if (
        present(src_zone)
        and present(dst_zone)
    ):

        zone_pair = (
            str(src_zone).strip(),
            str(dst_zone).strip(),
        )

        if zone_pair not in known_zone_pairs:

            anomalies.append(
                make_anomaly(
                    event,
                    record_number,
                    "unexpected_zone_flow"
                )
            )

            counts[
                "unexpected_zone_flow"
            ] += 1


    # --------------------------------------------------------
    # external_destination_new
    #
    # Do not guess whether an IP is external.
    # Use the dst_zone enrichment.
    # --------------------------------------------------------

    if (
        has_dst_ip
        and present(dst_zone)
        and str(
            dst_zone
        ).strip().lower() == "external"
    ):

        destination = str(
            dst_ip
        ).strip()

        if (
            destination
            not in known_external_ips
        ):

            anomalies.append(
                make_anomaly(
                    event,
                    record_number,
                    "external_destination_new"
                )
            )

            counts[
                "external_destination_new"
            ] += 1


    # --------------------------------------------------------
    # Collect connections for volume_burst
    #
    # A connection must have:
    #   - a host identity
    #   - a destination IP
    # --------------------------------------------------------

    if (
        host is not None
        and has_dst_ip
    ):

        hour_start = timestamp.replace(
            minute=0,
            second=0,
            microsecond=0
        )

        hourly_connections[
            (
                host,
                hour_start,
            )
        ].append(
            (
                record_number,
                event,
            )
        )


# ============================================================
# 14. Detect volume bursts
# ============================================================

for (
    host,
    hour_start,
), bucket in sorted(
    hourly_connections.items(),
    key=lambda item: (
        item[0][1],
        item[0][0],
    )
):

    baseline_mean = (
        host_hourly_mean.get(
            host
        )
    )


    # No valid baseline means we cannot make a meaningful
    # volume comparison for this host.
    if (
        baseline_mean is None
        or baseline_mean <= 0
    ):
        continue


    observed_count = len(
        bucket
    )


    threshold_count = (
        baseline_mean
        * volume_multiplier
    )


    # Requirement says "exceeds", so use > rather than >=.
    if (
        observed_count
        <= threshold_count
    ):
        continue


    bucket_events = [
        event
        for _, event
        in bucket
    ]


    refs = [
        get_event_ref(
            event,
            record_number
        )

        for (
            record_number,
            event,
        ) in bucket
    ]


    anomalies.append(
        {
            "timestamp":
                iso_utc(hour_start),

            "host":
                host,

            "src_ip":
                common_value(
                    bucket_events,
                    "src_ip"
                ),

            "dst_ip":
                common_value(
                    bucket_events,
                    "dst_ip"
                ),

            "dst_port":
                common_value(
                    bucket_events,
                    "dst_port"
                ),

            "src_zone":
                common_value(
                    bucket_events,
                    "src_zone"
                ),

            "dst_zone":
                common_value(
                    bucket_events,
                    "dst_zone"
                ),

            "anomaly_type":
                "volume_burst",

            "severity":
                highest_severity(
                    bucket_events
                ),

            "event_refs":
                refs,
        }
    )


    counts[
        "volume_burst"
    ] += 1


# ============================================================
# 15. Sort output deterministically
# ============================================================

anomalies.sort(
    key=lambda item: (
        str(
            item.get(
                "timestamp"
            ) or ""
        ),
        str(
            item.get(
                "host"
            ) or ""
        ),
        str(
            item.get(
                "anomaly_type"
            ) or ""
        ),
        str(
            item.get(
                "dst_ip"
            ) or ""
        ),
        str(
            item.get(
                "dst_port"
            ) or ""
        ),
    )
)


# ============================================================
# 16. Write anomalies_network.json atomically
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
        anomalies,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Every project file ends with a newline.
    handle.write("\n")


os.replace(
    temporary_file,
    output_file
)


# ============================================================
# 17. Human-readable summary
# ============================================================

print(
    "evaluation window : "
    f"{iso_utc(evaluation_start)} "
    "-> "
    f"{iso_utc(evaluation_end)}"
)


for anomaly_type in ANOMALY_TYPES:

    print(
        f"{anomaly_type:<29}: "
        f"{counts[anomaly_type]}"
    )


print(
    "total anomalies              : "
    f"{len(anomalies)}"
)

print(
    f"{output_file} written"
)

PYTHON
