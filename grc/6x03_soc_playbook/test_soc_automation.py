#!/usr/bin/env python3
"""Regression checks in temporary directories; canonical integration evidence is preserved."""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
MATERIALS = ROOT.parent / "opt/meddefense/materials"


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.original = Path.cwd()
        self.temp = tempfile.TemporaryDirectory(prefix="meddefense_regression_")
        self.work = Path(self.temp.name)
        os.chdir(self.work)
        for name in ("ioc_feed.json", "privileged_accounts.json"):
            Path(name).write_bytes((ROOT / name).read_bytes())
        import case_manager
        import enrich_ioc
        import playbook_common
        import playbook_phishing_triage
        import playbook_credential_exposure
        self.cm = case_manager
        self.en = enrich_ioc
        self.common = playbook_common
        self.phish = playbook_phishing_triage
        self.cred = playbook_credential_exposure
        self.cm.init_db()
        self.dns = mock.patch.object(self.en, "reverse_dns", return_value="NXDOMAIN")
        self.dns.start()

    def tearDown(self):
        self.dns.stop()
        os.chdir(self.original)
        self.temp.cleanup()

    def alert(self, name):
        return json.loads((ROOT / "alerts" / name).read_text())

    def save_alert(self, alert):
        Path("input.json").write_text(json.dumps(alert))
        return "input.json"

    def invoke(self, module, alert):
        with contextlib.redirect_stdout(io.StringIO()):
            return module.run(self.save_alert(alert))

    def test_validation_csv_all_ten_rows(self):
        import csv
        with (MATERIALS / "threat_intel/enrichment_validation_set.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            with self.subTest(ioc=row["ioc"]):
                result = self.en.enrich_ioc(row["ioc"])
                for key in ("type", "ip_class", "score", "verdict"):
                    self.assertEqual(str(result[key]), row["expected_" + key])

    def test_ip_categories_and_normalization(self):
        for ip, expected in {"127.0.0.1": "loopback", "::1": "loopback", "169.254.1.1": "link_local",
                             "224.0.0.1": "multicast", "192.0.2.1": "documentation",
                             "2001:db8::1": "documentation", "fc00::1": "private", "8.8.4.4": "public"}.items():
            self.assertEqual(self.en.classify_ip(ip), expected)
        self.assertEqual(self.en.normalize_ioc("HTTPS://MEDDEFENSE-SECURE.NET./reset"), "meddefense-secure.net")
        self.assertEqual(self.en.detect_ioc_type("https://[2001:db8::1]/x"), "url")

    def test_scoring_boundary_and_private_precedence(self):
        for confidence, expected in [(79, "INVESTIGATE"), (80, "BLOCK")]:
            self.assertEqual(self.en.score_ioc({"in_malicious_feed": True, "confidence": confidence}, "public")[1], expected)
        self.assertEqual(self.en.score_ioc({"in_malicious_feed": True, "confidence": 99}, "private"), (0, "ALLOW"))
        self.assertEqual(self.en.score_ioc({"in_benign_list": True}, "public"), (0, "ALLOW"))

    def test_malformed_and_feed_failure_require_review(self):
        for value in ("", "999.999.999.999", "not a domain", "http:///missing", "http://example.com:99999"):
            self.assertEqual(self.en.enrich_ioc(value)["verdict"], "INVESTIGATE")
        self.assertEqual(self.en.enrich_ioc("192.168.1.1", "missing.json")["verdict"], "INVESTIGATE")
        Path("ioc_feed.json").write_text('{}')
        self.assertEqual(self.en.enrich_ioc("8.8.8.8")["verdict"], "INVESTIGATE")

    def test_reverse_dns_success_error_timeout(self):
        self.dns.stop()
        import socket
        for response, expected in [(("host.example", [], []), "host.example"),
                                   (socket.herror("missing"), "NXDOMAIN"),
                                   (socket.timeout("slow"), "TIMEOUT"),
                                   (OSError("offline"), "NXDOMAIN")]:
            kwargs = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
            with mock.patch.object(socket, "gethostbyaddr", **kwargs), mock.patch.object(socket, "setdefaulttimeout") as setter:
                self.assertEqual(self.en.reverse_dns("198.51.100.42"), expected)
                setter.assert_any_call(3)

    def test_case_schema_matches_reference(self):
        actual = sqlite3.connect("cases.db")
        expected = sqlite3.connect(":memory:")
        try:
            expected.executescript((MATERIALS / "case_management/case_schema_reference.sql").read_text())
            for table in ("cases", "case_notes", "case_iocs"):
                self.assertEqual(actual.execute("PRAGMA table_info(" + table + ")").fetchall(),
                                 expected.execute("PRAGMA table_info(" + table + ")").fetchall())
                self.assertEqual(actual.execute("PRAGMA foreign_key_list(" + table + ")").fetchall(),
                                 expected.execute("PRAGMA foreign_key_list(" + table + ")").fetchall())
        finally:
            actual.close(); expected.close()

    def test_case_lifecycle_notes_and_sql_parameters(self):
        cid = self.cm.create_case("alert-1", "High", "Quote ' and ; DROP TABLE cases;", "description", [])
        cid2 = self.cm.create_case("alert-2", "Medium", "Second", "description", [])
        self.assertTrue(cid.endswith("-001")); self.assertTrue(cid2.endswith("-002"))
        self.assertTrue(self.cm.add_case_note(cid, "analyst's observation"))
        self.assertFalse(self.cm.add_case_note("missing", "note"))
        self.assertFalse(self.cm.update_case_status(cid, "bogus"))
        self.assertFalse(self.cm.update_case_status("missing", "open"))
        self.assertTrue(self.cm.update_case_status(cid, "investigating"))
        self.assertTrue(self.cm.close_case(cid, "human reviewed"))
        self.assertEqual(len(self.cm.list_cases("closed")), 1)
        self.assertEqual(self.cm.get_case(cid)["notes"][0]["note"], "analyst's observation")
        self.assertTrue(self.cm.update_case_status(cid, "open"))
        self.assertIsNone(self.cm.get_case(cid)["resolution"])
        self.assertIsNone(self.cm.get_case("missing"))

    def test_case_create_rolls_back_bad_ioc(self):
        with self.assertRaises(KeyError):
            self.cm.create_case("alert-1", "High", "title", "description", [{"ioc_value": "x"}])
        self.assertEqual(self.cm.list_cases(), [])

    def test_phishing_dedup_and_replay_limitation(self):
        alert = self.alert("ALT-20260428-001.json")
        values, occurrences, warnings = self.phish.extract_iocs(alert)
        self.assertEqual(occurrences, 4)
        self.assertEqual(values, ["198.51.100.42", "meddefense-secure.net"])
        self.assertEqual(warnings, [])
        first = self.invoke(self.phish, alert)
        second = self.invoke(self.phish, alert)
        self.assertNotEqual(first["case_id"], second["case_id"])
        self.assertEqual(len(self.cm.list_cases()), 2)  # documented cross-alert replay gap

    def test_phishing_missing_ip_and_malformed_url_never_close(self):
        alert = self.alert("ALT-20260428-003.json")
        del alert["raw_log"]["from_ip"]
        with self.assertLogs(self.common.LOGGER, level="WARNING"):
            result = self.invoke(self.phish, alert)
        self.assertEqual(result["verdict"], "REVIEW")
        alert = self.alert("ALT-20260428-003.json")
        alert["raw_log"]["body_urls"] = ["http:///bad"]
        with self.assertLogs(self.common.LOGGER, level="WARNING"):
            self.assertEqual(self.invoke(self.phish, alert)["verdict"], "REVIEW")

    def test_phishing_empty_and_exception_review(self):
        alert = self.alert("ALT-20260428-003.json")
        alert["raw_log"] = {}
        with self.assertLogs(self.common.LOGGER, level="WARNING"):
            self.assertEqual(self.invoke(self.phish, alert)["verdict"], "REVIEW")
        with mock.patch.object(self.common, "enrich_ioc", side_effect=RuntimeError("lookup failed")), self.assertLogs(self.common.LOGGER, level="WARNING"):
            self.assertEqual(self.invoke(self.phish, self.alert("ALT-20260428-003.json"))["verdict"], "REVIEW")

    def test_credential_all_branches(self):
        for verdict in ("BLOCK", "INVESTIGATE", "ALLOW"):
            for da, sa in ((True, False), (False, True), (False, False)):
                with self.subTest(verdict=verdict, da=da, sa=sa):
                    result = self.cred.decide(verdict, da, sa)
                    if verdict == "BLOCK" or (verdict == "INVESTIGATE" and da):
                        self.assertEqual(result, ("ESCALATE", "Critical", "escalated", True))
                    elif verdict == "ALLOW" and da:
                        self.assertEqual(result, ("ESCALATE", "High", "escalated", False))
                    else:
                        self.assertEqual(result, ("MANUAL_REVIEW", "High" if verdict == "INVESTIGATE" else "Medium", "open", False))

    def test_privileged_internal_alert_008(self):
        result = self.invoke(self.cred, self.alert("ALT-20260428-008.json"))
        self.assertEqual((result["verdict"], result["severity"], result["status"]), ("ESCALATE", "High", "escalated"))
        self.assertFalse(Path("isolation_queue.json").exists())

    def test_credential_queue_and_preservation(self):
        result = self.invoke(self.cred, self.alert("ALT-20260428-007.json"))
        queue = json.loads(Path("isolation_queue.json").read_text())
        self.assertEqual(queue[0]["case_id"], result["case_id"])
        self.assertEqual(queue[0]["status"], "pending_authorization")
        self.invoke(self.cred, self.alert("ALT-20260428-009.json"))
        self.assertEqual(json.loads(Path("isolation_queue.json").read_text()), queue)
        Path("isolation_queue.json").write_text('broken')
        with self.assertRaises(json.JSONDecodeError):
            self.common.queue_isolation({"host": "test"})
        self.assertEqual(Path("isolation_queue.json").read_text(), 'broken')

    def test_no_expected_fixture_dependency(self):
        alert = self.alert("ALT-20260428-007.json")
        alert["expected"] = {"case_severity": "Low", "isolation_queue": False}
        result = self.invoke(self.cred, alert)
        self.assertEqual(result["severity"], "Critical")
        self.assertTrue(result["isolation_queued"])

    def test_missing_privilege_evidence_stops(self):
        Path("privileged_accounts.json").write_text('{}')
        with self.assertRaises(ValueError):
            self.invoke(self.cred, self.alert("ALT-20260428-007.json"))
        self.assertEqual(self.cm.list_cases(), [])

    def test_cli_malformed_json_exit_and_audit(self):
        import subprocess
        import sys
        Path("bad.json").write_text("{bad")
        result = subprocess.run([sys.executable, str(ROOT / "playbook_phishing_triage.py"), "bad.json"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERROR", result.stderr)
        self.assertEqual(len(Path("playbook_audit.log").read_text().splitlines()), 1)
        self.assertEqual(self.cm.list_cases(), [])

    def test_cli_missing_credential_field_exit(self):
        import subprocess
        import sys
        alert = self.alert("ALT-20260428-007.json")
        del alert["raw_log"]["host"]
        path = self.save_alert(alert)
        result = subprocess.run([sys.executable, str(ROOT / "playbook_credential_exposure.py"), path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(Path("isolation_queue.json").exists())
        self.assertEqual(self.cm.list_cases(), [])

    def test_python38_syntax_and_core_imports(self):
        allowed = {"__future__", "json", "sqlite3", "socket", "ipaddress", "argparse", "datetime", "re", "logging", "pathlib", "urllib", "enrich_ioc", "case_manager", "playbook_common"}
        for name in ("enrich_ioc.py", "case_manager.py", "playbook_common.py", "playbook_phishing_triage.py", "playbook_credential_exposure.py"):
            tree = ast.parse((ROOT / name).read_text(), feature_version=(3, 8))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(item.name.split('.')[0] in allowed for item in node.names))
                elif isinstance(node, ast.ImportFrom):
                    self.assertIn(node.module.split('.')[0], allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
