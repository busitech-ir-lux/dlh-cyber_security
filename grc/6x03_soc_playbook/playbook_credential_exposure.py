#!/usr/bin/env python3
"""Credential triage with a human-authorization queue. Never isolates a host."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import case_manager
from enrich_ioc import utc_now
from playbook_common import (add_note, audit_line, fail_execution, linked_iocs,
                             load_alert, queue_isolation, safe_enrich, set_status)

MITRE_TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
}


def decide(ip_verdict: str, is_da: bool, is_sa: bool) -> tuple[str, str, str, bool]:
    if ip_verdict == "BLOCK" or (ip_verdict == "INVESTIGATE" and is_da):
        return "ESCALATE", "Critical", "escalated", True
    if ip_verdict == "ALLOW" and is_da:
        return "ESCALATE", "High", "escalated", False
    return "MANUAL_REVIEW", "High" if ip_verdict == "INVESTIGATE" else "Medium", "open", False


def run(alert_path: str) -> dict:
    alert = load_alert(alert_path)
    raw = alert["raw_log"]
    for field in ("source_ip", "username", "host", "mitre_technique"):
        if not isinstance(raw.get(field), str) or not raw[field].strip():
            raise ValueError("Missing required credential field: " + field)
        if any(char in raw[field] for char in ("\n", "\r", "\t", "|")):
            raise ValueError("Invalid control or separator in credential field: " + field)
    inventory = json.loads(Path("privileged_accounts.json").read_text(encoding="utf-8-sig"))
    if not isinstance(inventory, dict):
        raise ValueError("Invalid privileged-account inventory")
    for key in ("domain_admins", "server_admins"):
        if not isinstance(inventory.get(key), list) or not all(isinstance(item, str) for item in inventory[key]):
            raise ValueError("Invalid privilege list: " + key)
    user = raw["username"].casefold()
    is_da = user in {name.casefold() for name in inventory["domain_admins"]}
    is_sa = user in {name.casefold() for name in inventory["server_admins"]}
    privilege = "Domain Admin" if is_da else "Server Admin" if is_sa else "Standard user"
    result = safe_enrich(raw["source_ip"])
    verdict, severity, status, isolate = decide(result["verdict"], is_da, is_sa)
    technique = MITRE_TECHNIQUES.get(raw["mitre_technique"], "Unknown technique; analyst verification required")
    reason = "{} on {} from {} ({}) by {} {}".format(
        technique, raw["host"], raw["source_ip"], result["verdict"], privilege, raw["username"])
    case_id = case_manager.create_case(alert["alert_id"], severity, "Credential exposure: " + raw["host"], reason, linked_iocs([result]))
    if status == "escalated":
        set_status(case_id, status)
    add_note(case_id, json.dumps({"playbook_verdict": verdict, "reason": reason,
                                  "enrichment": result, "privilege": privilege,
                                  "mitre_technique": raw["mitre_technique"], "technique_name": technique,
                                  "source_event_time": alert.get("timestamp"),
                                  "inventory_exported_at": inventory.get("metadata", {}).get("exported_at"),
                                  "human_authorization_required": isolate}, sort_keys=True))
    if isolate:
        queue_isolation({"queued_at": utc_now(), "host": raw["host"], "alert_id": alert["alert_id"],
                         "case_id": case_id, "reason": reason,
                         "action_required": "Analyst must authorize isolation via EDR console before execution",
                         "status": "pending_authorization"})
    audit_line(["CREDENTIAL_EXPOSURE", alert["alert_id"], "Host:" + raw["host"], "User:" + raw["username"],
                "IPVerdict:" + result["verdict"], "Privilege:" + privilege, "Case:" + case_id,
                "Severity:" + severity, "IsolationQueued:" + ("yes" if isolate else "no")])
    print("[{}] CREDENTIAL EXPOSURE PLAYBOOK".format(utc_now()))
    print("Alert      : " + alert["alert_id"])
    print("Host       : " + raw["host"])
    print("User       : {}  Privilege: {}".format(raw["username"], privilege))
    print("Source IP  : {}  Verdict: {}  Score: {}".format(raw["source_ip"], result["verdict"], result["score"]))
    print("MITRE      : {} {}".format(raw["mitre_technique"], technique))
    print("Verdict    : " + verdict)
    print("Case       : {}  Severity: {}  Status: {}".format(case_id, severity, status))
    print("Action     : " + ("Host written to isolation_queue.json for analyst authorization" if isolate
                             else "Case recorded for analyst review; no isolation queued"))
    return {"case_id": case_id, "verdict": verdict, "severity": severity, "status": status, "isolation_queued": isolate}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert_path")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        run(args.alert_path)
        return 0
    except Exception as exc:
        return fail_execution("CREDENTIAL_EXPOSURE", args.alert_path, exc)


if __name__ == "__main__":
    raise SystemExit(main())
