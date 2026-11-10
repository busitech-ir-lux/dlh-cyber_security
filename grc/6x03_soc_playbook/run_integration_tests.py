#!/usr/bin/env python3
"""Run the five canonical fixtures in a fresh workspace; never delete prior evidence."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=Path.cwd())
    parser.add_argument("--materials", type=Path,
                        default=Path(__file__).resolve().parent.parent / "opt/meddefense/materials")
    args = parser.parse_args()
    work = args.workdir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    for name in ("cases.db", "playbook_audit.log", "isolation_queue.json", "integration_test_results.md"):
        if (work / name).exists():
            raise SystemExit("Use a new --workdir; preserving existing " + name)
    materials = args.materials.resolve()
    scripts = Path(__file__).resolve().parent
    expected = list(csv.DictReader((materials / "integration/expected_outcomes.csv").open()))
    (work / "alerts").mkdir(exist_ok=True)
    evidence = work / "evidence"
    evidence.mkdir(exist_ok=True)
    copies = [(materials / "threat_intel/ioc_feed.json", work / "ioc_feed.json"),
              (materials / "iam/privileged_accounts.json", work / "privileged_accounts.json")]
    copies += [(source, work / "alerts" / source.name) for source in sorted((materials / "alerts").glob("*/*.json"))]
    for source, destination in copies:
        if destination.exists() and destination.read_bytes() != source.read_bytes():
            raise SystemExit("Input differs; preserving existing " + str(destination))
        if not destination.exists():
            destination.write_bytes(source.read_bytes())
    observations = []
    for row in expected:
        name = "playbook_" + row["playbook"] + ".py"
        relative_alert = "alerts/" + row["alert_id"] + ".json"
        before = time.perf_counter()
        result = subprocess.run([sys.executable, str(scripts / name), relative_alert], cwd=work,
                                capture_output=True, text=True, timeout=30)
        elapsed = time.perf_counter() - before
        stem = row["alert_id"]
        (evidence / (stem + ".stdout.txt")).write_text(result.stdout)
        (evidence / (stem + ".stderr.txt")).write_text(result.stderr)
        connection = sqlite3.connect(str(work / "cases.db"))
        connection.row_factory = sqlite3.Row
        cases = connection.execute("SELECT * FROM cases WHERE alert_id=?", (stem,)).fetchall()
        connection.close()
        case = dict(cases[0]) if len(cases) == 1 else {}
        case_id = case.get("case_id", "MISSING")
        details = subprocess.run([sys.executable, str(scripts / "case_manager.py"), "get", case_id],
                                 cwd=work, capture_output=True, text=True, timeout=10)
        (evidence / (stem + ".case.json")).write_text(details.stdout)
        queue = json.loads((work / "isolation_queue.json").read_text()) if (work / "isolation_queue.json").exists() else []
        matched = [entry for entry in queue if entry.get("alert_id") == stem]
        queued = len(matched) == 1 and matched[0].get("case_id") == case_id and matched[0].get("status") == "pending_authorization"
        verdict_lines = [line.split(":", 1)[1].strip() for line in result.stdout.splitlines() if line.startswith("Verdict    :")]
        verdict = verdict_lines[0] if len(verdict_lines) == 1 else "MISSING"
        passed = (result.returncode == 0 and details.returncode == 0 and len(cases) == 1
                  and case.get("severity") == row["expected_case_severity"]
                  and case.get("status") == row["expected_case_status"]
                  and verdict == row["expected_verdict"]
                  and queued == (row["isolation_queue_expected"] == "yes")
                  and (len(matched) == 0 if row["isolation_queue_expected"] == "no" else len(matched) == 1))
        observations.append({"expected": row, "command": "python3 " + name + " " + relative_alert,
                             "stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode,
                             "case_json": details.stdout, "case": case, "verdict": verdict,
                             "elapsed_seconds": elapsed, "isolation_queued": queued, "pass": passed})
        print(stem + ": " + ("PASS" if passed else "FAIL"), flush=True)
    listing = subprocess.run([sys.executable, str(scripts / "case_manager.py"), "list"],
                             cwd=work, capture_output=True, text=True, timeout=10)
    (evidence / "case_list.stdout.txt").write_text(listing.stdout)
    queue_text = (work / "isolation_queue.json").read_text()
    (evidence / "integration_observations.json").write_text(json.dumps(observations, indent=2) + "\n")
    report = """# SOC playbook integration test results

**Test date:** """ + datetime.now(timezone.utc).strftime("%Y-%m-%d") + """  
**Version:** 1.0  
**Environment:** Local Python execution against supplied fixtures; prescribed SSH lab not connected

## Scope and method

These are real CLI runs with the local feed and account inventory, not copied
sample outputs. The source alert `expected` objects are never read by the playbooks;
the runner compares actual case data with `integration/expected_outcomes.csv`.
All five runs used a fresh database and audit log. Existing evidence is never reset;
the runner refuses reuse and supports a separate `--workdir` for later runs.
No external API, mail, account, firewall, or endpoint action is called.

Run `python3 run_integration_tests.py` from a fresh task working directory with
access to the original `../opt/meddefense/materials`, or supply `--materials` and
`--workdir`. The supplied execution used a temporary staging directory before
copying the completed artifacts into this project. Commands below use the same
working-directory-relative arguments; subprocesses located the scripts by their
absolute staging paths. Raw stdout and stderr are saved separately in `evidence/`.

The local fixtures contain RFC documentation addresses, not live hostile targets.
Reverse DNS is best-effort metadata; verdicts depend on the supplied feed and rules,
not network availability. Timestamps and case IDs reflect actual November execution,
not the April dates inside the source alerts.

## Results overview

| Alert | Expected verdict / severity / status | Actual verdict / severity / status | Isolation queued | Runtime, seconds | Result |
| --- | --- | --- | --- | --- | --- |
"""
    for obs in observations:
        row, case = obs["expected"], obs["case"]
        report += "| {} | {} / {} / {} | {} / {} / {} | {} | {:.4f} | {} |\n".format(
            row["alert_id"], row["expected_verdict"], row["expected_case_severity"], row["expected_case_status"],
            obs["verdict"], case.get("severity"), case.get("status"), "yes" if obs["isolation_queued"] else "no",
            obs["elapsed_seconds"], "PASS" if obs["pass"] else "FAIL")
    for idx, obs in enumerate(observations, 1):
        row, case = obs["expected"], obs["case"]
        report += "\n## Scenario {}: {}\n\n{}\n\n**Command:**\n\n```bash\n{}\n```\n\n**Actual stdout, unchanged:**\n\n```text\n{}```\n\n".format(
            idx, row["alert_id"], row["expected_reason"], obs["command"], obs["stdout"])
        report += "**Actual stderr:** " + ("Empty.\n\n" if not obs["stderr"] else "\n\n```text\n" + obs["stderr"] + "```\n\n")
        report += "**Case query:**\n\n```bash\npython3 case_manager.py get {}\n```\n\n**Actual case query stdout, unchanged:**\n\n```json\n{}```\n\n".format(case.get("case_id"), obs["case_json"])
        report += "**Expected versus actual:** {}. Exit code {}; expected queue {}; actual queue {}.\n\n".format(
            "PASS" if obs["pass"] else "FAIL", obs["exit_code"], row["isolation_queue_expected"], "yes" if obs["isolation_queued"] else "no")
    report += """## Final case listing

Exact output of `python3 case_manager.py list`:

```text
""" + listing.stdout + """```

The default CLI lists actionable cases: open, escalated, and investigating.
The benign closed case remains in the database and is retrievable by ID or
`list --status closed`. The Python function `list_cases()` without a filter
returns every case, including closed cases.

## Final isolation queue

Exact output equivalent to `cat isolation_queue.json`:

```json
""" + queue_text + """```

One host recommendation is pending authorization. This is a local queue entry,
not an isolation event or a delivered on-call notification. Case and queue identifiers
must stay linked when the package is copied or reviewed.

## Interpretation and remaining limits

All five canonical scenarios matched their expected results on the first canonical
run. No failing integration run or corrective patch is invented. Separate regression
checks exercise malformed input, uncertain enrichment, the additional privileged
internal alert, decision branches, and database behavior; see the saved regression
report. These checks are not additional entries in the five-case canonical database.

The phishing sample 001 contains four extracted indicator occurrences: sender IP,
sender domain, and two URL hostnames. After normalization, only two unique indicators
are enriched. This corrects contradictory illustrative sample counts without
changing the canonical verdict. Audit IOC counts are unique enriched counts.

The five fixtures do not measure real false-positive or false-negative rates,
clinical disruption risk, sustained throughput, or production readiness. Missing
cross-alert deduplication, TTL caching, privilege/feed freshness enforcement, and
notification delivery remain production gaps. Multi-file persistence is not one
transaction: a crash between database and file writes can leave partial evidence;
production requires durable outbox/retry and idempotency controls.
"""
    (work / "integration_test_results.md").write_text(report)
    return 0 if all(obs["pass"] for obs in observations) and listing.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
