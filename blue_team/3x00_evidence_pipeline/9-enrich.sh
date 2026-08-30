#!/bin/bash

# ============================================================
# TASK 9 - CONTEXT ENRICHMENT
#
# Reads:
#   cleaned_events.json
#   context/asset_inventory.json
#   context/network_zones.json
#
# Writes:
#   enriched_events.json
#
# Adds:
#   asset
#   src_zone
#   dst_zone
# ============================================================

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"

INPUT_FILE="$WORKDIR/cleaned_events.json"
ASSET_FILE="$EVIDENCE_PACK/context/asset_inventory.json"
ZONE_FILE="$EVIDENCE_PACK/context/network_zones.json"
OUTPUT_FILE="$WORKDIR/enriched_events.json"


# ============================================================
# CHECK REQUIRED FILES
# ============================================================

for file in "$INPUT_FILE" "$ASSET_FILE" "$ZONE_FILE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file: $file" >&2
        exit 1
    fi
done


# ============================================================
# RUN ENRICHMENT
# ============================================================

python3 - \
    "$INPUT_FILE" \
    "$ASSET_FILE" \
    "$ZONE_FILE" \
    "$OUTPUT_FILE" <<'PYTHON_EOF'

import ipaddress
import json
import sys


input_file = sys.argv[1]
asset_file = sys.argv[2]
zone_file = sys.argv[3]
output_file = sys.argv[4]


# ============================================================
# LOAD ASSET INVENTORY
# ============================================================

with open(asset_file, "r", encoding="utf-8") as f:
    asset_data = json.load(f)


# ============================================================
# BUILD HOSTNAME LOOKUP
#
# Support either:
#
# [
#   {"hostname": "srv-dc-01", ...}
# ]
#
# or:
#
# {
#   "assets": [
#       {"hostname": "srv-dc-01", ...}
#   ]
# }
# ============================================================

if isinstance(asset_data, dict):
    assets = asset_data.get("assets", [])
else:
    assets = asset_data


asset_lookup = {}

for asset in assets:

    if not isinstance(asset, dict):
        continue

    hostname = asset.get("hostname")

    if hostname:
        asset_lookup[hostname.lower()] = asset


# ============================================================
# LOAD NETWORK ZONES
# ============================================================

with open(zone_file, "r", encoding="utf-8") as f:
    zone_data = json.load(f)


# ============================================================
# BUILD CIDR LOOKUP LIST
#
# Support either:
#
# [
#   {"zone": "DMZ", "cidr": "10.10.2.0/24"}
# ]
#
# or:
#
# {
#   "zones": [
#       {"zone": "DMZ", "cidr": "10.10.2.0/24"}
#   ]
# }
# ============================================================

if isinstance(zone_data, dict):
    zones = zone_data.get("zones", [])
else:
    zones = zone_data


network_lookup = []

for zone in zones:

    if not isinstance(zone, dict):
        continue

    zone_name = (
        zone.get("zone")
        or zone.get("name")
    )

    cidr = (
        zone.get("cidr")
        or zone.get("network")
    )

    if not zone_name or not cidr:
        continue

    try:
        network = ipaddress.ip_network(
            cidr,
            strict=False
        )

        network_lookup.append(
            (network, zone_name)
        )

    except ValueError:
        continue


# ============================================================
# LOOK UP NETWORK ZONE
# ============================================================

def find_zone(ip_value):

    if not ip_value:
        return "unknown"

    try:
        ip = ipaddress.ip_address(ip_value)

    except ValueError:
        return "unknown"

    for network, zone_name in network_lookup:

        if ip in network:
            return zone_name

    return "unknown"


# ============================================================
# COUNTERS
# ============================================================

total = 0
asset_added = 0
src_resolved = 0
dst_resolved = 0
unknown_hosts = 0


# ============================================================
# PROCESS EVENTS
# ============================================================

with open(
    input_file,
    "r",
    encoding="utf-8",
    errors="replace"
) as source, open(
    output_file,
    "w",
    encoding="utf-8"
) as output:

    for line in source:

        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)

        except json.JSONDecodeError:
            continue

        if not isinstance(event, dict):
            continue


        total += 1


        # ====================================================
        # ASSET ENRICHMENT
        # ====================================================

        hostname = event.get("hostname")

        asset = None

        if isinstance(hostname, str):
            asset = asset_lookup.get(
                hostname.lower()
            )


        if asset:

            event["asset"] = {
                "role": asset.get("role"),
                "criticality": asset.get("criticality"),
                "os": asset.get("os"),
                "owner": asset.get("owner"),
                "zone": asset.get("zone")
            }

            asset_added += 1

        else:

            event["asset"] = None

            if hostname:
                unknown_hosts += 1


        # ====================================================
        # SOURCE IP ZONE
        # ====================================================

        src_ip = event.get("src_ip")

        if src_ip:

            src_zone = find_zone(src_ip)

            event["src_zone"] = src_zone

            if src_zone != "unknown":
                src_resolved += 1

        else:

            event["src_zone"] = "unknown"


        # ====================================================
        # DESTINATION IP ZONE
        # ====================================================

        dst_ip = event.get("dst_ip")

        if dst_ip:

            dst_zone = find_zone(dst_ip)

            event["dst_zone"] = dst_zone

            if dst_zone != "unknown":
                dst_resolved += 1

        else:

            event["dst_zone"] = "unknown"


        # ====================================================
        # WRITE ENRICHED RECORD
        # ====================================================

        json.dump(
            event,
            output,
            separators=(",", ":")
        )

        output.write("\n")


# ============================================================
# COVERAGE PERCENTAGES
# ============================================================

def percent(value):

    if total == 0:
        return 0.0

    return (value / total) * 100


# ============================================================
# SUMMARY
# ============================================================

print(f"events processed    : {total}")

print(
    f"asset context added : "
    f"{asset_added} ({percent(asset_added):.1f}%)"
)

print(
    f"src_zone resolved   : "
    f"{src_resolved} ({percent(src_resolved):.1f}%)"
)

print(
    f"dst_zone resolved   : "
    f"{dst_resolved} ({percent(dst_resolved):.1f}%)"
)

print(f"unknown hosts       : {unknown_hosts}")

print("enriched_events.json written")

PYTHON_EOF
