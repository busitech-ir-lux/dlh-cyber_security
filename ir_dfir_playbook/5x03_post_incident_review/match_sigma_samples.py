#!/usr/bin/env python3
"""Small Sigma-subset matcher for the supplied normalized Sysmon JSONL samples.

Supports only the modifiers and condition form used by our two supplied rules.
This is NOT a general Sigma-to-SIEM conversion engine.
"""
import argparse
import ipaddress
import json
import pathlib
import yaml

FIELD_MAP = {
    "Image": "image",
    "ParentImage": "parent_image",
    "Initiated": "initiated",
    "DestinationIp": "dst_ip",
    "DestinationHostname": "dst_hostname",
}
EVENT_IDS = {"process_creation": 1, "network_connection": 3}

def matches_field(event, field_expr, expected):
    parts = field_expr.split("|")
    raw = event.get(FIELD_MAP.get(parts[0], parts[0]))
    if raw is None:
        return False
    options = expected if isinstance(expected, list) else [expected]
    modifier = parts[1] if len(parts) > 1 else ""
    for option in options:
        if modifier == "cidr":
            try:
                if ipaddress.ip_address(str(raw)) in ipaddress.ip_network(option, strict=False):
                    return True
            except ValueError:
                pass
        elif modifier == "endswith" and str(raw).lower().endswith(str(option).lower()):
            return True
        elif modifier == "startswith" and str(raw).lower().startswith(str(option).lower()):
            return True
        elif not modifier and (raw == option or str(raw).lower() == str(option).lower()):
            return True
    return False

def matches_selection(event, fields):
    return all(matches_field(event, key, value) for key, value in fields.items())

def match(event, rule):
    cat = rule["logsource"]["category"]
    if event.get("event_id") != EVENT_IDS[cat]:
        return False
    detection = rule["detection"]
    if "selection_parent" in detection:
        return (matches_selection(event, detection["selection_parent"])
                and matches_selection(event, detection["selection_child"]))
    if not matches_selection(event, detection["selection"]):
        return False
    for key, values in detection.items():
        if key.startswith("filter_") and matches_selection(event, values):
            return False
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rule")
    parser.add_argument("logfile")
    args = parser.parse_args()
    rule = yaml.safe_load(pathlib.Path(args.rule).read_text())
    total = 0
    hits = []
    for line in pathlib.Path(args.logfile).read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        total += 1
        if match(event, rule):
            hits.append(event)
    percent = 100 * len(hits) / total if total else 0
    print(f"Rule: {pathlib.Path(args.rule).name}")
    print(f"Sample: {pathlib.Path(args.logfile).name}")
    print(f"Total events: {total}")
    print(f"Matches: {len(hits)}")
    print(f"Match rate: {percent:.3f}%")
    for hit in hits:
        print("MATCH: " + " | ".join(str(hit.get(k, "")) for k in
              ("ts", "host", "event_id", "pid", "image", "parent_image", "dst_ip", "dst_hostname")))
    print()

if __name__ == "__main__":
    main()
