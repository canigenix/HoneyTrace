"""Source-disjoint holdout protocol tests; no network or Docker needed."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from honeytrace.validation import (
    _metrics, create_validation_demo, validate_holdout,
)
from honeytrace.validation_report import write_validation_html


class HoldoutValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_obj = TemporaryDirectory()
        cls.root = Path(cls.tmp_obj.name)
        cls.paths = create_validation_demo(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_obj.cleanup()

    def _run(self, **changes):
        options = {**self.paths, **changes}
        return validate_holdout(options["training_log"], options["training_labels"],
                                options["testing_log"], options["testing_labels"])

    def _copy_log(self, key: str, mutate):
        path = self.root / f"altered-{self._testMethodName}-{key}.jsonl"
        rows = [json.loads(line) for line in self.paths[key].read_text().splitlines()]
        mutate(rows)
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def _copy_labels(self, key: str, mutate):
        path = self.root / f"altered-{self._testMethodName}-{key}.csv"
        with self.paths[key].open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        mutate(rows)
        with path.open("w", newline="", encoding="utf-8") as stream:
            w = csv.DictWriter(stream, fieldnames=["sensor", "session", "label"])
            w.writeheader()
            w.writerows(rows)
        return path

    def test_genuine_holdout_fit_and_aggregate_results(self):
        report = self._run()
        protocol = report["protocol"]
        self.assertEqual(protocol["training_background_sessions"], 65)
        self.assertEqual(protocol["testing_labeled_sessions"], 45)
        self.assertEqual(protocol["source_overlap"], 0)
        self.assertTrue(protocol["training_only_fit"])
        self.assertTrue(protocol["time_forward_split"])
        self.assertEqual(sum(report["model"]["confusion"].values()), 45)
        self.assertEqual(sum(report["rules_threshold_35"]["confusion"].values()), 45)
        self.assertNotIn("SYNTHETIC_NOT_REAL", json.dumps(report))
        self.assertNotIn("192.0.2.", json.dumps(report))
        self.assertNotIn("198.51.100.", json.dumps(report))

    def test_refuses_identical_train_test_files(self):
        with self.assertRaisesRegex(ValueError, "identical"):
            self._run(testing_log=self.paths["training_log"])

    def test_refuses_overlapping_source_ips(self):
        path = self._copy_log("testing_log", lambda rows: [r.update(src_ip="192.0.2.1") for r in rows if r["session"] == "test-0000"])
        with self.assertRaisesRegex(ValueError, "share source IPs"):
            self._run(testing_log=path)

    def test_refuses_overlapping_session_ids(self):
        path = self._copy_log("testing_log", lambda rows: [r.update(session="train-0000") for r in rows if r["session"] == "test-0000"])
        with self.assertRaisesRegex(ValueError, "Overlapping sensor/session"):
            self._run(testing_log=path)

    def test_refuses_missing_source_ids(self):
        path = self._copy_log("testing_log", lambda rows: [r.pop("src_ip", None) for r in rows if r["session"] == "test-0000"])
        with self.assertRaisesRegex(ValueError, "Missing source IP"):
            self._run(testing_log=path)

    def test_requires_labeled_training_background(self):
        path = self._copy_labels("training_labels", lambda rows: [r.update(label="review") for r in rows[:50]])
        with self.assertRaisesRegex(ValueError, "at least 25"):
            self._run(training_labels=path)

    def test_refuses_no_test_labels(self):
        path = self._copy_labels("testing_labels", lambda rows: [r.update(label="") for r in rows])
        with self.assertRaisesRegex(ValueError, "No labeled testing"):
            self._run(testing_labels=path)

    def test_rejects_unknown_csv_sessions(self):
        path = self._copy_labels("testing_labels", lambda rows: rows[0].update(session="no-such-session"))
        with self.assertRaisesRegex(ValueError, "not found"):
            self._run(testing_labels=path)

    def test_rejects_invalid_labels(self):
        path = self._copy_labels("testing_labels", lambda rows: rows[0].update(label="hacked"))
        with self.assertRaisesRegex(ValueError, "review or background"):
            self._run(testing_labels=path)

    def test_rejects_duplicate_csv_rows(self):
        path = self._copy_labels("testing_labels", lambda rows: rows.append(dict(rows[0])))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._run(testing_labels=path)

    def test_rejects_bad_contamination(self):
        with self.assertRaisesRegex(ValueError, "contamination"):
            validate_holdout(*self.paths.values(), contamination=0.8)

    def test_time_overlap_warns_without_leaking_data(self):
        path = self._copy_log("testing_log", lambda rows: [r.update(timestamp=r["timestamp"].replace("2026-02-01", "2026-01-01")) for r in rows])
        report = self._run(testing_log=path)
        self.assertFalse(report["protocol"]["time_forward_split"])
        self.assertTrue(any("time-forward validation" in w for w in report["warnings"]))

    def test_label_one_class_does_not_invent_recall(self):
        path = self._copy_labels("testing_labels", lambda rows: [r.update(label="background") for r in rows])
        report = self._run(testing_labels=path)
        self.assertIsNone(report["model"]["recall"])
        self.assertIsNone(report["model"]["recall_wilson_95"])
        self.assertTrue(any("one label class" in w for w in report["warnings"]))

    def test_html_report_is_aggregate_only(self):
        report = self._run()
        target = self.root / "report.html"
        write_validation_html(report, target)
        html = target.read_text(encoding="utf-8")
        self.assertIn("Isolation Forest", html)
        self.assertIn("Fixed heuristic baseline", html)
        self.assertNotIn("SYNTHETIC_NOT_REAL", html)
        self.assertNotIn("192.0.2.", html)
        self.assertNotIn("<script", html.lower())

    def test_demo_will_not_overwrite_labels(self):
        with self.assertRaises(FileExistsError):
            create_validation_demo(self.root)

    def test_partial_labels_are_not_counted_as_negative(self):
        path = self._copy_labels("testing_labels", lambda rows: [r.update(label="") for r in rows[:8]])
        report = self._run(testing_labels=path)
        self.assertEqual(report["model"]["evaluated"], 37)
        self.assertEqual(report["protocol"]["testing_unlabeled_sessions"], 8)


class MetricTests(unittest.TestCase):
    def test_confusion_and_wilson_intervals(self):
        result = _metrics([(True, True), (True, False), (False, True), (False, False)])
        self.assertEqual(result["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["f1"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertLess(result["precision_wilson_95"][0], 0.5)
        self.assertGreater(result["precision_wilson_95"][1], 0.5)

    def test_undefined_metrics_are_null_not_zero(self):
        result = _metrics([(False, False)])
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])
        self.assertIsNone(result["f1"])
        self.assertIsNone(result["precision_wilson_95"])


if __name__ == "__main__":
    unittest.main()
