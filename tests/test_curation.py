"""Dataset-review tooling: no Docker or network required."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.curation import audit_dataset, export_review_queue
from honeytrace.demo import create_demo


class CurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.raw = self.root / "cowrie.jsonl"

    def write_events(self, events):
        self.raw.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

    def sessions(self, events):
        self.write_events(events)
        e, _ = load_events(self.raw)
        return analyze_events(e, enable_ml=False)

    def test_review_queue_remains_unlabeled_and_never_copies_secrets(self):
        result = self.sessions([
            {"sensor": "lab", "session": "a", "eventid": "cowrie.login.success", "src_ip": "192.0.2.5",
             "username": "SECRET_USER", "password": "SECRET_PASSWORD", "timestamp": "2026-11-03T03:00:00Z"},
            {"sensor": "lab", "session": "a", "eventid": "cowrie.command.input", "input": "curl https://secret.invalid/token",
             "src_ip": "192.0.2.5", "timestamp": "2026-11-03T03:00:01Z"},
        ])
        out = self.root / "labels.csv"
        self.assertEqual(export_review_queue(result, out), 1)
        text = out.read_text(encoding="utf-8")
        for forbidden in ("SECRET_USER", "SECRET_PASSWORD", "192.0.2.5", "secret.invalid", "curl", "Payload delivery indicator", "risk"):
            self.assertNotIn(forbidden, text)
        with out.open(newline="", encoding="utf-8") as stream:
            row = next(csv.DictReader(stream))
        self.assertEqual(row["label"], "")
        self.assertEqual(row["command_count"], "1")
        self.assertEqual(row["session"], "a")

    def test_does_not_overwrite_human_review(self):
        result = self.sessions([{"sensor": "test", "session": "test1", "eventid": "cowrie.login.failed"}])
        path = self.root / "review.csv"
        export_review_queue(result, path)
        path.write_text("human edited content", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            export_review_queue(result, path)
        self.assertEqual(path.read_text(encoding="utf-8"), "human edited content")

    def test_rejects_spreadsheet_formula_ids_and_controls(self):
        for invalid in ("=HYPERLINK(x)", " +10", "-100", "@SUM(1)", "normal\nfile", "x\tfoo"):
            with self.subTest(invalid=invalid):
                result = {"sessions": [{"sensor": "demo", "session": invalid, "start": "Unknown", "features": {"login_failures":0,"login_successes":0,"command_count":0,"file_transfers":0}}]}
                with self.assertRaises(ValueError):
                    export_review_queue(result, self.root / "out.csv")
                self.assertFalse((self.root / "out.csv").exists())

    def test_compatible_with_existing_validation_label_reader(self):
        from honeytrace.validation import _read_labels
        result = self.sessions([{"sensor":"test", "session":"s1", "src_ip":"192.0.2.1", "eventid":"cowrie.session.connect"}])
        path = self.root / "review.csv"
        export_review_queue(result,path)
        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        rows[0]["label"] = "background"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
        self.assertEqual(_read_labels(path,result["sessions"]),{("test","s1"):"background"})

    def test_aggregated_audit_is_private_and_flags_one_source(self):
        self.write_events([
            {"sensor":"a","session":"s1","src_ip":"172.17.0.1","eventid":"cowrie.login.success","password":"SECRET_PW","timestamp":"2026-11-03T03:00:00Z"},
            {"sensor":"a","session":"s1","src_ip":"172.17.0.1","eventid":"cowrie.command.input","input":"curl https://private.invalid","timestamp":"2026-11-03T03:00:02Z"},
            {"sensor":"a","session":"s2","src_ip":"172.17.0.1","eventid":"cowrie.login.failed","password":"OTHER_SECRET","timestamp":"2026-11-03T03:00:10Z"},
        ])
        report = audit_dataset(self.raw, origin="controlled-lab")
        self.assertEqual(report["quality"]["sessions"], 2)
        self.assertEqual(report["quality"]["distinct_source_ips"], 1)
        self.assertEqual(report["quality"]["sessions_with_commands"], 1)
        self.assertEqual(len(report["source_sha256"]),64)
        self.assertFalse(report["holdout_ready"])
        self.assertTrue(any("cross-source" in w for w in report["warnings"]))
        text = json.dumps(report)
        for secret in ("172.17.0.1", "SECRET_PW", "OTHER_SECRET", "private.invalid"):
            self.assertNotIn(secret, text)

    def test_audit_with_manual_labels_checks_coverage(self):
        self.sessions([
            {"sensor":"lab","session":"s1","eventid":"cowrie.session.connect","src_ip":"192.0.2.1"},
            {"sensor":"lab","session":"s2","eventid":"cowrie.session.connect","src_ip":"192.0.2.2"},
        ])
        labels = self.root / "labeled.csv"
        labels.write_text("sensor,session,label\nlab,s1,review\nlab,s2,\n",encoding="utf-8")
        report = audit_dataset(self.raw, labels)
        self.assertEqual(report["quality"]["labels"],{"review":1,"background":0,"unlabeled":1})
        self.assertTrue(any("selection bias" in w for w in report["warnings"]))

    def test_rejects_bad_label_ids(self):
        self.sessions([{"sensor":"lab","session":"s1","eventid":"cowrie.session.connect","src_ip":"192.0.2.1"}])
        labels = self.root / "wrong.csv"
        labels.write_text("sensor,session,label\nlab,not-s1,review\n",encoding="utf-8")
        with self.assertRaisesRegex(ValueError,"not found"):
            audit_dataset(self.raw, labels)

    def test_synthetic_log_cannot_be_called_holdout_ready(self):
        create_demo(self.raw, count=60)
        report = audit_dataset(self.raw,origin="synthetic")
        self.assertEqual(report["quality"]["sessions"],60)
        self.assertEqual(report["origin_declaration"],"synthetic")
        self.assertFalse(report["holdout_ready"])
        self.assertTrue(any("not independently" in w for w in report["warnings"]))

    def test_cli_review_queue_and_audit(self):
        create_demo(self.raw,count=4)
        entry=Path(__file__).resolve().parents[1]/"honeytrace.py"
        queue=self.root/"review.csv"
        audit=self.root/"audit.json"
        review_run=subprocess.run([sys.executable,str(entry),"review-queue",str(self.raw),"--output",str(queue)],cwd=self.root,capture_output=True,text=True,timeout=20)
        self.assertEqual(review_run.returncode,0,review_run.stderr)
        audit_run=subprocess.run([sys.executable,str(entry),"audit",str(self.raw),"--output",str(audit),"--origin","controlled-lab"],cwd=self.root,capture_output=True,text=True,timeout=20)
        self.assertEqual(audit_run.returncode,0,audit_run.stderr)
        self.assertEqual(json.loads(audit.read_text(encoding="utf-8"))["quality"]["sessions"],4)

if __name__ == "__main__":
    unittest.main()
