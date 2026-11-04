"""ML Intelligence regression tests. No Docker or network required."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import tempfile
import unittest

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.demo import create_demo
from honeytrace.ml_intelligence import cluster_sessions, describe_anomalies, evaluate_session_labels, export_label_template


def session_events(name: str, ip: str, commands: list[str]) -> list[dict]:
    base = {"session": name, "sensor": "test", "src_ip": ip, "timestamp": "2026-11-03T12:00:00Z"}
    return [dict(base, eventid="cowrie.login.success")] + [dict(base, eventid="cowrie.command.input", input=cmd) for cmd in commands]


class ClusteringTests(unittest.TestCase):
    def test_groups_similar_sessions_without_using_ip_identity(self):
        events = (session_events("a", "192.0.2.1", ["whoami", "uname -a"])
                  + session_events("b", "192.0.2.2", ["whoami", "uname -a", "hostname"])
                  + session_events("c", "198.51.100.1", ["whoami", "uname -a"]))
        result = analyze_events(events)
        self.assertEqual(result["meta"]["sessions"], 3)
        self.assertTrue(result["meta"]["cluster_enabled"])
        self.assertEqual(len(result["clusters"]), 1)
        self.assertEqual(result["clusters"][0]["sessions"], 3)
        self.assertEqual(result["clusters"][0]["sources"], 3)
        self.assertEqual(len({s["ml_cluster"] for s in result["sessions"]}), 1)
        self.assertTrue(all(s["ml_cluster_size"] == 3 for s in result["sessions"]))

    def test_no_ml_disables_clustering(self):
        events = session_events("a", "192.0.2.1", ["whoami"]) + session_events("b", "192.0.2.2", ["whoami"])
        result = analyze_events(events, enable_ml=False)
        self.assertFalse(result["meta"]["cluster_enabled"])
        self.assertEqual(result["clusters"], [])
        self.assertTrue(all(row["ml_cluster"] is None for row in result["sessions"]))

    def test_cluster_membership_does_not_copy_passwords(self):
        events = session_events("a", "192.0.2.1", ["whoami"]) + session_events("b", "192.0.2.2", ["whoami"])
        events[0]["password"] = "CREDENTIAL_SHOULD_NOT_APPEAR"
        result = analyze_events(events)
        self.assertNotIn("CREDENTIAL_SHOULD_NOT_APPEAR", json.dumps(result))

    def test_feature_contrast_is_not_model_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.jsonl"
            create_demo(path, count=120)
            events, _ = load_events(path)
            result = analyze_events(events)
            flagged = [r for r in result["sessions"] if r["anomaly"]]
            self.assertTrue(flagged)
            self.assertTrue(all(r["anomaly_factors"] for r in flagged))
            self.assertTrue(all(not r["anomaly_factors"] for r in result["sessions"] if not r["anomaly"]))
            self.assertIn("not causal", result["meta"]["ml_explanation_note"])


class ManualEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        path = self.tmp / "events.jsonl"
        create_demo(path, count=35)
        events, _ = load_events(path)
        self.result = analyze_events(events)
        self.csvpath = self.tmp / "labels.csv"
        self.assertTrue(self.result["meta"]["ml_enabled"])

    def _fill_labels(self):
        export_label_template(self.result, self.csvpath)
        with self.csvpath.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        rows[0]["label"] = "review"
        rows[1]["label"] = "background"
        with self.csvpath.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["sensor", "session", "label"])
            writer.writeheader()
            writer.writerows(rows)
        return rows

    def test_template_contains_only_ids_no_passwords_and_blank_labels(self):
        count = export_label_template(self.result, self.csvpath)
        self.assertEqual(count, 35)
        content = self.csvpath.read_text(encoding="utf-8")
        self.assertEqual(content.splitlines()[0], "sensor,session,label")
        self.assertNotIn("password", content.lower())
        self.assertNotIn("src_ip", content)
        self.assertEqual(sum(1 for _ in content.splitlines()), 36)

    def test_evaluation_metrics_cover_only_reviewed_sessions(self):
        self._fill_labels()
        report = evaluate_session_labels(self.result, self.csvpath)
        self.assertEqual(report["labeled"], 2)
        self.assertEqual(report["unlabeled"], 33)
        self.assertEqual(sum(report["confusion"].values()), 2)
        self.assertIn("not held-out", report["evaluation_type"])

    def test_export_does_not_overwrite_manual_labels(self):
        self._fill_labels()
        with self.assertRaises(FileExistsError):
            export_label_template(self.result, self.csvpath)

    def test_rejects_formula_like_identifiers(self):
        result = {"sessions": [{"sensor": "=HYPERLINK(x)", "session": "valid"}]}
        with self.assertRaisesRegex(ValueError, "unsafe spreadsheet"):
            export_label_template(result, self.csvpath)

    def test_rejects_blank_and_invalid_labels(self):
        export_label_template(self.result, self.csvpath)
        with self.assertRaisesRegex(ValueError, "No adjudicated"):
            evaluate_session_labels(self.result, self.csvpath)
        self.csvpath.write_text("sensor,session,label\nx,y,review\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown session"):
            evaluate_session_labels(self.result, self.csvpath)

    def test_rejects_duplicates(self):
        rows = self._fill_labels()
        with self.csvpath.open("a", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["sensor", "session", "label"])
            writer.writerow(rows[0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate_session_labels(self.result, self.csvpath)

    def test_metrics_undefined_when_denominator_zero(self):
        export_label_template(self.result, self.csvpath)
        with self.csvpath.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        # Only label an unflagged session as background; precision is undefined.
        zero = next((r for r in rows if not next(s["anomaly"] for s in self.result["sessions"] if s["session"] == r["session"] and s["sensor"] == r["sensor"])), None)
        self.assertIsNotNone(zero)
        self.csvpath.write_text(f"sensor,session,label\n{zero['sensor']},{zero['session']},background\n", encoding="utf-8")
        report = evaluate_session_labels(self.result, self.csvpath)
        self.assertIsNone(report["precision"])
        self.assertIsNone(report["recall"])


if __name__ == "__main__":
    unittest.main()
