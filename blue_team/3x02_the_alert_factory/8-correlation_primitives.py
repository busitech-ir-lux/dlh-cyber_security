#!/usr/bin/env python3

import json
import os
from datetime import datetime
from pathlib import Path

handoff = Path(
    os.environ.get(
        "HANDOFF_DIR",
        Path.home() / "3x00_handoff/evidence_handoff"
    )
)

source = handoff / "data/normalized_events.json"
output = Path("correlation_primitives.json")


def load_events():
    text = source.read_text(encoding="utf-8").strip()

    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def time_value(event):
    value = event.get("timestamp", "").replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def ref(event):
    return str(
        event.get("event_ref")
        or event.get("record_id")
        or event.get("id")
        or ""
    )


events = sorted(load_events(), key=time_value)
primitives = []

for success in events:
    if success.get("canonical_label") != "login_success":
        continue

    user = success.get("user")
    success_time = time_value(success)
    success_ip = success.get("src_ip")

    failures = [
        e for e in events
        if e.get("canonical_label") == "login_failure"
        and e.get("user") == user
        and e.get("src_ip") != success_ip
        and 0 <= (success_time - time_value(e)).total_seconds() <= 300
    ]

    if len(failures) < 3:
        continue

    privileges = [
        e for e in events
        if e.get("canonical_label") == "privilege_escalation"
        and e.get("hostname") == success.get("hostname")
        and 0 <= (time_value(e) - success_time).total_seconds() <= 600
    ]

    if not privileges:
        continue

    primitives.append({
        "timestamp": success.get("timestamp"),
        "hostname": success.get("hostname"),
        "user": user,
        "event_ref": ref(success),
        "correlation_primitive": "credential_compromise_chain",
        "failure_refs": [ref(e) for e in failures],
        "success_ref": ref(success),
        "privilege_ref": ref(privileges[0])
    })

with output.open("w", encoding="utf-8") as f:
    json.dump(primitives, f, indent=2)
    f.write("\n")

print(f"credential_compromise_chain primitives : {len(primitives)}")
print("correlation_primitives.json written")
