#!/usr/bin/env python3
"""Shared validation and evidence helpers; no response integrations."""
from __future__ import annotations

import json
import logging
from pathlib import Path
import re

import case_manager
from enrich_ioc import detect_ioc_type, enrich_ioc, utc_now

LOGGER = logging.getLogger("meddefense.playbook")


def load_alert(path: str) -> dict:
    alert = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(alert, dict):
        raise ValueError("Alert must be an object")
    if not isinstance(alert.get("alert_id"), str) or not re.fullmatch(r"[A-Za-z0-9._-]+", alert["alert_id"]):
        raise ValueError("Missing or invalid alert_id")
    if not isinstance(alert.get("raw_log"), dict):
        raise ValueError("Missing raw_log object")
    if not isinstance(alert.get("rule_name"), str) or not alert["rule_name"].strip():
        raise ValueError("Missing rule_name")
    return alert


def audit_line(parts: list[str]) -> None:
    # One physical line per execution, including untrusted alert-derived text.
    safe = [str(value).replace("\r", "\\r").replace("\n", "\\n").replace("|", "/") for value in parts]
    with Path("playbook_audit.log").open("a", encoding="utf-8") as handle:
        handle.write(utc_now() + " | " + " | ".join(safe) + "\n")


def safe_enrich(value: str) -> dict:
    try:
        result = enrich_ioc(value)
        if result.get("verdict") not in {"BLOCK", "INVESTIGATE", "ALLOW"}:
            raise ValueError("Unknown enrichment verdict")
        if result.get("error"):
            LOGGER.warning("Enrichment requires review for %r: %s", value, result.get("note"))
        return result
    except Exception as exc:
        # Task explicitly requires an enrichment exception to become review,
        # not closure or abandonment of the rest of the alert.
        LOGGER.warning("Enrichment failed for %r: %s", value, exc)
        try:
            kind = detect_ioc_type(value)
        except ValueError:
            kind = "domain"
        return {"ioc": value, "type": kind, "ip_class": "N/A", "reverse_dns": "N/A",
                "feed_result": {"in_malicious_feed": False, "in_benign_list": False},
                "score": 30, "verdict": "INVESTIGATE", "enriched_at": utc_now(),
                "error": "enrichment_exception", "note": str(exc)}


def linked_iocs(results: list[dict]) -> list[dict]:
    return [{"ioc_value": item["ioc"], "ioc_type": item["type"],
             "verdict": item["verdict"], "score": item["score"]} for item in results]


def set_status(case_id: str, status: str) -> None:
    if not case_manager.update_case_status(case_id, status):
        raise ValueError("Could not update case status")


def add_note(case_id: str, note: str) -> None:
    if not case_manager.add_case_note(case_id, note):
        raise ValueError("Could not append case note")


def queue_isolation(entry: dict) -> None:
    path = Path("isolation_queue.json")
    queue = json.loads(path.read_text()) if path.exists() else []
    if not isinstance(queue, list):
        raise ValueError("Isolation queue is not a JSON list; preserving it unchanged")
    queue.append(entry)
    # Atomic replacement prevents a half-written JSON file for a single writer.
    # A multi-worker durable queue/outbox is a separate production requirement.
    temporary = path.with_suffix(".json.tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(queue, indent=2) + "\n")
    temporary.replace(path)


def fail_execution(playbook: str, alert_path: str, exc: Exception) -> int:
    LOGGER.error("%s failed for %s: %s", playbook, alert_path, exc)
    try:
        audit_line([playbook, "ERROR", "Input:" + alert_path, "Reason:" + str(exc)])
    except OSError as audit_error:
        LOGGER.error("Audit append also failed: %s", audit_error)
    return 1
