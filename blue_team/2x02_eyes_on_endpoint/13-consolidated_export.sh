#!/bin/bash
#
# name: 13-consolidated_export.sh
# Consolidated Telemetry Export (Block 3 handoff)
#
# purpose: Combines Windows (Task 3) and Linux (Task 7) telemetry exports plus the
# attacker ground truth (Tasks 9 & 11) into a single SOC handoff package with
# timestamps normalized to UTC ISO 8601 across both platforms.
#
# Output structure:
#   telemetry_handoff/
#     windows_events.json
#     linux_events.json
#     attack_ground_truth.json   (combined Windows + Linux)
#
# JSON parsing / timestamp normalization is done in embedded Python3 for
# correctness on multi-thousand-event files and mixed input formats.
# author: Mahdi Hamidi

set -e
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

command -v python3 >/dev/null 2>&1 || { echo "[!] python3 is required." >&2; exit 1; }

python3 - "$SCRIPT_DIR" <<'PYEOF'
import json, os, sys
from datetime import datetime, timezone

base = sys.argv[1]
HANDOFF = os.path.join(base, "telemetry_handoff")

WIN_EVENTS_IN = os.path.join(base, "windows_events_export.json")
LIN_EVENTS_IN = os.path.join(base, "linux_events_export.json")
WIN_GT_IN     = os.path.join(base, "windows_attack_log.json")
LIN_GT_IN     = os.path.join(base, "linux_attack_log.json")

REQUIRED = ("timestamp", "hostname", "source_type", "event_category")
TS_KEYS  = ("timestamp", "@timestamp", "TimeCreated", "time", "event_time", "EventTime")

def die(msg):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)

def load_json(path):
    if not os.path.exists(path):
        die(f"missing input file: {os.path.basename(path)}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read().strip()
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # NDJSON fallback (one object per line)
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

def as_events(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("events", "records", "data"):
            if isinstance(obj.get(k), list):
                return obj[k]
    return []

def as_actions(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("actions", "matrix"):
            if isinstance(obj.get(k), list):
                return obj[k]
    return []

def to_utc_iso(v):
    """Return (normalized_iso, ok)."""
    if v is None:
        return None, False
    # epoch numeric
    if isinstance(v, (int, float)):
        ts = v / 1000.0 if v > 1e11 else float(v)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), True
    s = str(v).strip()
    if s.isdigit():
        n = int(s); ts = n / 1000.0 if n > 1e11 else float(n)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), True
    # ISO 8601 (accept trailing Z)
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), True
    except ValueError:
        pass
    for fmt in ('%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%b %d %H:%M:%S'):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ'), True
        except ValueError:
            continue
    return s, False

def normalize(events):
    ok = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        src_key = next((k for k in TS_KEYS if k in e), None)
        if src_key is not None:
            norm, good = to_utc_iso(e[src_key])
            e["timestamp"] = norm
            if good:
                ok += 1
    return ok

def check_fields(events):
    missing = {f: 0 for f in REQUIRED}
    for e in events:
        if not isinstance(e, dict):
            continue
        for f in REQUIRED:
            if f not in e or e[f] in (None, ""):
                missing[f] += 1
    return missing

# ---------------- Load ----------------
win_events = as_events(load_json(WIN_EVENTS_IN))
print(f"[*] Loading Windows events ({len(win_events):,})...")
lin_events = as_events(load_json(LIN_EVENTS_IN))
print(f"[*] Loading Linux events ({len(lin_events):,})...")

# ---------------- Normalize ----------------
print("[*] Normalizing timestamps to UTC...")
win_ok = normalize(win_events)
print(f"    Windows: {win_ok:,} events normalized")
lin_ok = normalize(lin_events)
print(f"    Linux: {lin_ok:,} events normalized")

# ---------------- Verify field consistency ----------------
print("[*] Verifying field consistency...")
miss = check_fields(win_events)
miss_l = check_fields(lin_events)
total_missing = sum(miss.values()) + sum(miss_l.values())
if total_missing == 0:
    print("    Required fields present in all events    [OK]")
else:
    print("    Required fields MISSING in some events   [WARN]")
    for f in REQUIRED:
        c = miss[f] + miss_l[f]
        if c:
            print(f"      - {f}: {c:,} event(s) missing")

# ---------------- Combine ground truth ----------------
print("[*] Combining ground truth...")
win_actions = as_actions(load_json(WIN_GT_IN))
lin_actions = as_actions(load_json(LIN_GT_IN))
for a in win_actions:
    if isinstance(a, dict):
        a.setdefault("platform", "windows")
        ts = a.get("timestamp")
        if ts is not None:
            a["timestamp"], _ = to_utc_iso(ts)
for a in lin_actions:
    if isinstance(a, dict):
        a.setdefault("platform", "linux")
        ts = a.get("timestamp")
        if ts is not None:
            a["timestamp"], _ = to_utc_iso(ts)
combined_actions = list(win_actions) + list(lin_actions)
print(f"    Windows actions: {len(win_actions)} | Linux actions: {len(lin_actions)} | Total: {len(combined_actions)}")

ground_truth = {
    "generated_at": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    "total_actions": len(combined_actions),
    "windows_actions": len(win_actions),
    "linux_actions": len(lin_actions),
    "actions": combined_actions,
}

# ---------------- Build handoff ----------------
print("[*] Building handoff directory...")
os.makedirs(HANDOFF, exist_ok=True)

win_path = os.path.join(HANDOFF, "windows_events.json")
lin_path = os.path.join(HANDOFF, "linux_events.json")
gt_path  = os.path.join(HANDOFF, "attack_ground_truth.json")

with open(win_path, "w", encoding="utf-8") as f:
    json.dump(win_events, f, indent=2)
with open(lin_path, "w", encoding="utf-8") as f:
    json.dump(lin_events, f, indent=2)
with open(gt_path, "w", encoding="utf-8") as f:
    json.dump(ground_truth, f, indent=2)

def mb(path):
    return os.path.getsize(path) / (1024 * 1024)

print("telemetry_handoff/")
print(f"  {'windows_events.json':<24} ({len(win_events):,} events, {mb(win_path):.1f} MB)")
print(f"  {'linux_events.json':<24} ({len(lin_events):,} events, {mb(lin_path):.1f} MB)")
print(f"  {'attack_ground_truth.json':<24} ({len(combined_actions)} actions)")
print(f"Total: {len(win_events) + len(lin_events):,} events across 2 platforms")
PYEOF
