#!/usr/bin/env python3
"""Simulated phishing triage. No quarantine, sender block or message delivery."""
from __future__ import annotations

import argparse
import json
import logging
from urllib.parse import urlsplit

import case_manager
from enrich_ioc import normalize_ioc, utc_now
from playbook_common import (LOGGER, add_note, audit_line, fail_execution,
                             linked_iocs, load_alert, safe_enrich, set_status)


def extract_iocs(alert: dict) -> tuple[list[str], int, list[str]]:
    raw = alert["raw_log"]
    candidates = []
    warnings = []
    if isinstance(raw.get("from_ip"), str) and raw["from_ip"].strip():
        candidates.append(raw["from_ip"].strip())
    else:
        warnings.append("Missing from_ip; skipped")
    sender = raw.get("from")
    if isinstance(sender, str) and "@" in sender and sender.rsplit("@", 1)[1].strip():
        candidates.append(sender.rsplit("@", 1)[1].strip())
    else:
        warnings.append("Missing or malformed sender email domain; skipped")
    urls = raw.get("body_urls", [])
    if not isinstance(urls, list):
        warnings.append("body_urls is not a list; skipped")
        urls = []
    for value in urls:
        try:
            if not isinstance(value, str):
                raise ValueError("URL is not text")
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                raise ValueError("URL lacks HTTP(S) scheme or hostname")
            _ = parsed.port
            # Validate the entire URL before preserving just the hostname.
            normalize_ioc(value)
            candidates.append(parsed.hostname)
        except (ValueError, UnicodeError) as exc:
            warnings.append("Malformed body URL skipped: " + str(exc))
    unique = []
    seen = set()
    for value in candidates:
        try:
            normalized = normalize_ioc(value)
        except (ValueError, UnicodeError):
            normalized = value.strip().lower()
        if normalized not in seen:
            unique.append(normalized)
            seen.add(normalized)
    return unique, len(candidates), warnings


def run(alert_path: str) -> dict:
    alert = load_alert(alert_path)
    values, extracted, warnings = extract_iocs(alert)
    for warning in warnings:
        LOGGER.warning("%s: %s", alert["alert_id"], warning)
    results = [safe_enrich(value) for value in values]
    counts = {key: sum(item["verdict"] == key for item in results) for key in ("BLOCK", "INVESTIGATE", "ALLOW")}
    if counts["BLOCK"]:
        verdict, severity, status = "ESCALATE", "Critical", "escalated"
    elif counts["INVESTIGATE"] or warnings or not results:
        verdict, severity, status = "REVIEW", "High", "open"
    else:
        verdict, severity, status = "CLOSE", "Low", "closed"
    case_id = case_manager.create_case(
        alert["alert_id"], severity, "Phishing: " + {"ESCALATE": "Known indicator escalated", "REVIEW": "Sender review", "CLOSE": "Benign simulation"}[verdict],
        "Simulated triage for rule " + alert["rule_name"] + "; source event time " + str(alert.get("timestamp", "unknown")),
        linked_iocs(results))
    if status == "closed":
        if not case_manager.close_case(case_id, "no_indicators_of_compromise"):
            raise ValueError("Could not close simulated benign case")
    elif status == "escalated":
        set_status(case_id, status)
    add_note(case_id, json.dumps({"playbook_verdict": verdict, "enrichment": results,
                                  "warnings": warnings, "extracted": extracted,
                                  "deduplicated": len(results), "simulation_only": True}, sort_keys=True))
    if verdict == "ESCALATE":
        add_note(case_id, "Escalation triggered by: " + ", ".join(item["ioc"] for item in results if item["verdict"] == "BLOCK")
                 + ". On-call notification delivery is not integrated; analyst must review escalated cases.")
    audit_line(["PHISHING_TRIAGE", alert["alert_id"], "IOCs:" + str(len(results)),
                "BLOCK:{},INVESTIGATE:{},ALLOW:{}".format(counts["BLOCK"], counts["INVESTIGATE"], counts["ALLOW"]),
                "Verdict:" + verdict, "Case:" + case_id, "Severity:" + severity])
    print("[{}] PHISHING TRIAGE PLAYBOOK".format(utc_now()))
    print("Alert      : " + alert["alert_id"])
    print("Rule       : " + alert["rule_name"])
    print("IOCs       : {} extracted, {} enriched, {} dedup skipped".format(extracted, len(results), extracted - len(results)))
    for item in results:
        feed = item["feed_result"]
        context = ", ".join([str(feed.get("category", "unknown"))] + list(feed.get("tags", [])))
        print("  {:<24} {:<7} {:<11} score={} ({})".format(item["ioc"], item["type"], item["verdict"], item["score"], context))
    print("Verdict    : " + verdict)
    print("Case       : {}  Severity: {}  Status: {}".format(case_id, severity, status))
    action = {"ESCALATE": "Escalation recorded; on-call notification delivery is not integrated",
              "REVIEW": "Case recorded for analyst review; no mail action taken",
              "CLOSE": "Simulated benign case closed; production auto-close is not approved"}[verdict]
    print("Action     : " + action)
    return {"case_id": case_id, "verdict": verdict, "severity": severity, "status": status}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert_path")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        run(args.alert_path)
        return 0
    except Exception as exc:
        return fail_execution("PHISHING_TRIAGE", args.alert_path, exc)


if __name__ == "__main__":
    raise SystemExit(main())
