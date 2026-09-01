#!/bin/bash

# ============================================================
# Task 6 - Network Connection Baseline
#
# Reads:
#   labeled_events.json
#
# Produces:
#   baseline_network.json
#
# The baseline contains:
#   - destinations used by each host
#   - destination ports used by each host
#   - source-zone to destination-zone flow counts
#   - known external destination IPs
#   - hosts normally using each destination port
#
# The baseline window is the first BASELINE_DAYS days of the
# dataset. BASELINE_DAYS defaults to 7.
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff/}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

INPUT_FILE="labeled_events.json"
OUTPUT_FILE="baseline_network.json"


# ============================================================
# 2. Find labeled_events.json
#
# Normally this file comes from an earlier task and is in the
# current project directory.
#
# The HANDOFF_DIR check also makes the script portable if the
# labeled file is stored with the handoff data later.
# ============================================================

if [ ! -f "$INPUT_FILE" ] && \
   [ -f "${HANDOFF_DIR%/}/data/labeled_events.json" ]; then

    INPUT_FILE="${HANDOFF_DIR%/}/data/labeled_events.json"
fi


# ============================================================
# 3. Validate input
# ============================================================

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: labeled_events.json not found" >&2
    exit 1
fi


# BASELINE_DAYS must contain only digits.
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
# 4. Build the network baseline
# ============================================================

python3 -W error - \
    "$INPUT_FILE" \
    "$OUTPUT_FILE" \
    "$BASELINE_DAYS" <<'PYTHON'

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


input_file = sys.argv[1]
output_file = sys.argv[2]
baseline_days = int(sys.argv[3])


# ============================================================
# Load either JSON array or NDJSON
# ============================================================

def load_events(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    if not text:
        return []

    # First try a normal JSON document.
    try:
        data = json.loads(text)

    except json.JSONDecodeError:

        # If that fails, treat the input as NDJSON.
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


    # Normal JSON array.
    if isinstance(data, list):

        if not all(isinstance(event, dict) for event in data):
            raise ValueError(
                "JSON array contains a non-object record"
            )

        return data


    # Also allow a single JSON event.
    if isinstance(data, dict):
        return [data]


    raise ValueError(
        "input must be a JSON array, object, or NDJSON"
    )


# ============================================================
# Timestamp helpers
# ============================================================

def parse_timestamp(value):
    """
    Parse normalized ISO 8601 timestamps.

    The 3x00 pipeline produces normalized timestamps, so this
    script uses them to calculate the baseline boundary.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "event has a missing or empty timestamp"
        )

    text = value.strip()

    # Python understands +00:00 directly.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)

    except ValueError as exc:
        raise ValueError(
            f"unparseable timestamp: {value}"
        ) from exc


    # Normalized events should contain timezone information.
    # If it is absent, treat the value as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


def iso_utc(value):
    """
    Produce deterministic UTC timestamps ending in Z.
    """

    return (
        value
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# Field helpers
# ============================================================

def present(value):
    """
    Return True when a field contains a useful value.

    None and empty strings are treated as absent.
    """

    if value is None:
        return False

    if isinstance(value, str) and not value.strip():
        return False

    return True


def port_key(value):
    """
    JSON object keys must be strings, so normalize ports to
    stable string values.
    """

    if isinstance(value, bool):
        return str(value).lower()

    return str(value).strip()


def port_sort_key(value):
    """
    Sort normal numeric ports numerically.
    """

    if value.isdigit():
        return (0, int(value))

    return (1, value)


# ============================================================
# 5. Load dataset
# ============================================================

events = load_events(input_file)


if not events:
    raise ValueError(
        "labeled_events.json contains no events"
    )


# ============================================================
# 6. Parse timestamps
#
# We calculate the boundary from the actual dataset rather than
# using hardcoded dates.
# ============================================================

parsed_events = []


for event in events:

    timestamp = parse_timestamp(
        event.get("timestamp")
    )

    parsed_events.append(
        (timestamp, event)
    )


first_timestamp = min(
    timestamp
    for timestamp, _ in parsed_events
)


# First N days belong to the baseline.
baseline_end = (
    first_timestamp
    + timedelta(days=baseline_days)
)


# The end boundary is exclusive:
#
#     start <= timestamp < baseline_end
#
# This prevents the first event of the evaluation window from
# accidentally becoming part of the baseline.
baseline_events = [
    event
    for timestamp, event in parsed_events
    if first_timestamp <= timestamp < baseline_end
]


if not baseline_events:
    raise ValueError(
        "no events fall inside the baseline window"
    )


# ============================================================
# 7. Baseline counters
# ============================================================

# hostname -> destination IP -> count
per_host_destinations = defaultdict(Counter)

# hostname -> destination port -> count
per_host_ports = defaultdict(Counter)

# "SRC_ZONE->DST_ZONE" -> count
zone_flow_counts = Counter()

# external destination IP -> count
external_ip_counts = Counter()

# destination port -> set of hosts
service_hosts = defaultdict(set)


# Values used for the stdout summary.
all_hosts = set()
all_dst_ips = set()
all_dst_ports = set()


# ============================================================
# 8. Process baseline events
#
# Do not hardcode source_type values.
#
# If an event contains useful network fields, it can contribute
# to the network baseline regardless of which telemetry source
# originally produced it.
# ============================================================

for event in baseline_events:

    hostname = event.get("hostname")
    dst_ip = event.get("dst_ip")
    dst_port = event.get("dst_port")
    src_zone = event.get("src_zone")
    dst_zone = event.get("dst_zone")


    has_host = present(hostname)
    has_dst_ip = present(dst_ip)
    has_dst_port = present(dst_port)
    has_src_zone = present(src_zone)
    has_dst_zone = present(dst_zone)


    # --------------------------------------------------------
    # Normalize values
    # --------------------------------------------------------

    if has_host:
        hostname = str(hostname).strip()

    if has_dst_ip:
        dst_ip = str(dst_ip).strip()
        all_dst_ips.add(dst_ip)

    if has_dst_port:
        dst_port = port_key(dst_port)
        all_dst_ports.add(dst_port)


    # --------------------------------------------------------
    # Per-host destinations
    # --------------------------------------------------------

    if has_host and has_dst_ip:

        per_host_destinations[
            hostname
        ][dst_ip] += 1

        all_hosts.add(hostname)


    # --------------------------------------------------------
    # Per-host ports
    # --------------------------------------------------------

    if has_host and has_dst_port:

        per_host_ports[
            hostname
        ][dst_port] += 1

        all_hosts.add(hostname)


        # The service profile records which hosts normally use
        # each destination port.
        service_hosts[
            dst_port
        ].add(hostname)


    # --------------------------------------------------------
    # Zone flow counts
    #
    # JSON cannot have a real Python tuple as an object key.
    # Therefore:
    #
    #   INTERNAL->DMZ
    #
    # represents:
    #
    #   (INTERNAL, DMZ)
    # --------------------------------------------------------

    if has_src_zone and has_dst_zone:

        src_zone = str(src_zone).strip()
        dst_zone = str(dst_zone).strip()

        zone_key = (
            f"{src_zone}->{dst_zone}"
        )

        zone_flow_counts[
            zone_key
        ] += 1


    # --------------------------------------------------------
    # Known external destinations
    #
    # Use the enrichment result rather than trying to guess
    # whether an address is external from the IP itself.
    # --------------------------------------------------------

    if has_dst_ip and has_dst_zone:

        if (
            str(dst_zone)
            .strip()
            .lower()
            == "external"
        ):

            external_ip_counts[
                dst_ip
            ] += 1


# ============================================================
# 9. Build deterministic output structures
# ============================================================

per_host_destinations_output = {}


for host in sorted(per_host_destinations):

    per_host_destinations_output[
        host
    ] = {

        destination:
            per_host_destinations[
                host
            ][destination]

        for destination in sorted(
            per_host_destinations[host]
        )
    }


per_host_ports_output = {}


for host in sorted(per_host_ports):

    per_host_ports_output[
        host
    ] = {

        port:
            per_host_ports[
                host
            ][port]

        for port in sorted(
            per_host_ports[host],
            key=port_sort_key
        )
    }


zone_flows_output = {

    flow: zone_flow_counts[flow]

    for flow in sorted(
        zone_flow_counts
    )
}


known_external_ips_output = {

    address:
        external_ip_counts[address]

    for address in sorted(
        external_ip_counts
    )
}


service_profiles_output = {}


for port in sorted(
    service_hosts,
    key=port_sort_key
):

    service_profiles_output[
        port
    ] = sorted(
        service_hosts[port]
    )


# ============================================================
# 10. Final machine-readable baseline
# ============================================================

result = {

    "baseline_window": {
        "start": iso_utc(
            first_timestamp
        ),
        "end_exclusive": iso_utc(
            baseline_end
        ),
        "baseline_days": baseline_days,
        "record_count": len(
            baseline_events
        )
    },

    "per_host_destinations":
        per_host_destinations_output,

    "per_host_ports":
        per_host_ports_output,

    "zone_flows":
        zone_flows_output,

    "known_external_ips":
        known_external_ips_output,

    "service_profiles":
        service_profiles_output
}


# ============================================================
# 11. Write output atomically
#
# Writing to a temporary file first prevents a partially written
# baseline_network.json if the process fails.
#
# os.replace() also ensures repeated runs replace the old result
# instead of appending to it.
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
        result,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Project requirement:
    # every file must end with a newline.
    handle.write("\n")


os.replace(
    temporary_file,
    output_file
)


# ============================================================
# 12. Human-readable summary
# ============================================================

print(
    "baseline window   : "
    f"{iso_utc(first_timestamp)} "
    "-> "
    f"{iso_utc(baseline_end)}"
)

print(
    "hosts with network activity : "
    f"{len(all_hosts)}"
)

print(
    "distinct dst_ip           : "
    f"{len(all_dst_ips)}"
)

print(
    "distinct dst_port         : "
    f"{len(all_dst_ports)}"
)

print(
    "zone flows recorded       : "
    f"{len(zone_flow_counts)}"
)

print(
    "known external IPs        : "
    f"{len(external_ip_counts)}"
)

print(
    f"{output_file} written"
)

PYTHON
