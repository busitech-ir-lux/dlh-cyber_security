#!/bin/bash

# ============================================================
# TASK 6 - NETWORK ARTIFACT NORMALIZATION
#
# Reads:
#   firewall.csv
#   suricata_eve.json
#   pcap_summary.json
#
# Writes:
#   network_events.json
#
# Also appends all network records to:
#   normalized_events.json
# ============================================================

set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
NETWORK_DIR="$EVIDENCE_PACK/network"

WORKDIR="${WORKDIR:-$(pwd)}"

FIREWALL_FILE="$NETWORK_DIR/firewall.csv"
SURICATA_FILE="$NETWORK_DIR/suricata_eve.json"
PCAP_FILE="$NETWORK_DIR/pcap_summary.json"

NETWORK_OUTPUT="$WORKDIR/network_events.json"
NORMALIZED_OUTPUT="$WORKDIR/normalized_events.json"


# ============================================================
# CHECK REQUIRED FILES
# ============================================================

for file in "$FIREWALL_FILE" "$SURICATA_FILE" "$PCAP_FILE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file: $file" >&2
        exit 1
    fi
done


# ============================================================
# RUN PYTHON NORMALIZER
# ============================================================

python3 - \
    "$FIREWALL_FILE" \
    "$SURICATA_FILE" \
    "$PCAP_FILE" \
    "$NETWORK_OUTPUT" \
    "$NORMALIZED_OUTPUT" <<'PYTHON_EOF'

import csv
import json
import sys
from datetime import datetime, timezone


firewall_file = sys.argv[1]
suricata_file = sys.argv[2]
pcap_file = sys.argv[3]
network_output = sys.argv[4]
normalized_output = sys.argv[5]


# ============================================================
# TIMESTAMP HELPERS
# ============================================================

def epoch_to_utc(value):
    """Convert Unix epoch seconds to ISO 8601 UTC."""

    try:
        dt = datetime.fromtimestamp(
            float(value),
            timezone.utc
        )

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except (ValueError, TypeError, OverflowError):
        return None


def iso_to_utc(value):
    """Convert Suricata ISO timestamp to UTC."""

    if not value:
        return None

    try:
        value = value.strip()

        # Example:
        # 2026-03-18T00:00:31.026524+0000
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        if len(value) >= 5:
            if value[-5] in ("+", "-") and value[-3] != ":":
                value = value[:-2] + ":" + value[-2:]

        dt = datetime.fromisoformat(value)

        dt = dt.astimezone(timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        return None


def pcap_time_to_utc(value):
    """Convert PCAP MM/DD/YYYY HH:MM:SS AM/PM timestamp."""

    if not value:
        return None

    try:
        dt = datetime.strptime(
            value,
            "%m/%d/%Y %I:%M:%S %p"
        )

        dt = dt.replace(tzinfo=timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        return None


# ============================================================
# SAFE INTEGER CONVERSION
#
# Ports and byte counts should be integers when possible.
# ============================================================

def to_int(value):

    if value in (None, ""):
        return None

    try:
        return int(value)

    except (ValueError, TypeError):
        return None


# ============================================================
# BASE NETWORK RECORD
#
# Using a common base keeps the three network sources
# consistent.
#
# Missing optional fields are explicitly null.
# ============================================================

def base_record():

    return {
        "timestamp": None,
        "hostname": None,
        "source_type": None,
        "source_origin": "evidence_pack",
        "event_category": None,
        "event_id": None,
        "severity": None,
        "user": None,
        "process_name": None,
        "process_id": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "action": None,
        "signature": None,
        "raw_message": None,
        "source_fields": {}
    }


# ============================================================
# FIREWALL CSV
#
# Header:
#
# timestamp,src_ip,src_port,dst_ip,dst_port,
# protocol,action,interface,rule_id,bytes_in,bytes_out
# ============================================================

def parse_firewall(filepath):

    records = []

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            record = base_record()

            record["timestamp"] = epoch_to_utc(
                row.get("timestamp")
            )

            record["source_type"] = "firewall"

            record["event_category"] = "network"

            record["src_ip"] = row.get("src_ip")

            record["src_port"] = to_int(
                row.get("src_port")
            )

            record["dst_ip"] = row.get("dst_ip")

            record["dst_port"] = to_int(
                row.get("dst_port")
            )

            record["protocol"] = row.get("protocol")

            # Preserve ALLOW or BLOCK exactly.
            record["action"] = row.get("action")

            record["event_id"] = row.get("rule_id")

            record["raw_message"] = ",".join(
                row.get(name, "")
                for name in reader.fieldnames
            )

            record["source_fields"] = dict(row)

            records.append(record)

    return records


# ============================================================
# SURICATA EVE JSON
#
# Suricata EVE is NDJSON.
#
# Important fields include:
#
#   timestamp
#   src_ip
#   src_port
#   dest_ip
#   dest_port
#   proto
#   alert.signature
#   alert.severity
# ============================================================

def parse_suricata(filepath):

    records = []

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue


            record = base_record()

            alert = event.get("alert") or {}


            record["timestamp"] = iso_to_utc(
                event.get("timestamp")
            )

            record["source_type"] = "suricata"

            record["event_category"] = "network_alert"

            record["event_id"] = alert.get(
                "signature_id"
            )

            record["severity"] = alert.get(
                "severity"
            )

            record["signature"] = alert.get(
                "signature"
            )

            record["src_ip"] = event.get("src_ip")

            record["src_port"] = to_int(
                event.get("src_port")
            )

            record["dst_ip"] = event.get("dest_ip")

            record["dst_port"] = to_int(
                event.get("dest_port")
            )

            record["protocol"] = (
                event.get("app_proto")
                or event.get("proto")
            )

            record["raw_message"] = line

            record["source_fields"] = event

            records.append(record)

    return records


# ============================================================
# PCAP SUMMARY
#
# PCAP summary is also NDJSON.
#
# start_time is used as the normalized event timestamp.
# end_time is preserved inside source_fields.
# ============================================================

def parse_pcap(filepath):

    records = []

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue


            record = base_record()

            record["timestamp"] = pcap_time_to_utc(
                event.get("start_time")
            )

            record["source_type"] = "pcap"

            record["event_category"] = "network_flow"

            record["src_ip"] = (
                event.get("src_ip")
                or event.get("source_ip")
            )

            record["src_port"] = to_int(
                event.get("src_port")
                or event.get("source_port")
            )

            record["dst_ip"] = (
                event.get("dst_ip")
                or event.get("dest_ip")
                or event.get("destination_ip")
            )

            record["dst_port"] = to_int(
                event.get("dst_port")
                or event.get("dest_port")
                or event.get("destination_port")
            )

            record["protocol"] = (
                event.get("protocol")
                or event.get("proto")
            )

            record["raw_message"] = line

            record["source_fields"] = event

            records.append(record)

    return records


# ============================================================
# PARSE ALL THREE SOURCES
# ============================================================

firewall_records = parse_firewall(
    firewall_file
)

suricata_records = parse_suricata(
    suricata_file
)

pcap_records = parse_pcap(
    pcap_file
)


all_network_records = (
    firewall_records
    + suricata_records
    + pcap_records
)


# ============================================================
# WRITE STANDALONE NETWORK OUTPUT
#
# Opening with "w" makes the standalone output idempotent.
# ============================================================

with open(
    network_output,
    "w",
    encoding="utf-8"
) as f:

    for record in all_network_records:

        json.dump(
            record,
            f,
            separators=(",", ":")
        )

        f.write("\n")


# ============================================================
# APPEND TO NORMALIZED DATASET
#
# Task 6 specifically asks to append network events to the
# normalized endpoint dataset created in Task 5.
# ============================================================

with open(
    normalized_output,
    "a",
    encoding="utf-8"
) as f:

    for record in all_network_records:

        json.dump(
            record,
            f,
            separators=(",", ":")
        )

        f.write("\n")


# ============================================================
# SUMMARY
# ============================================================

print(
    f"firewall.csv        : "
    f"{len(firewall_records):6d} records normalized"
)

print(
    f"suricata_eve.json   : "
    f"{len(suricata_records):6d} records normalized"
)

print(
    f"pcap_summary.json   : "
    f"{len(pcap_records):6d} records normalized"
)

print("appended to normalized_events.json")
print("network_events.json written")

PYTHON_EOF
