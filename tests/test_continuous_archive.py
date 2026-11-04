"""v0.9 localhost-only continuous archival and consistency tests."""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from honeytrace.archive import archive_check, archive_import, archive_summary
from honeytrace.live import Monitor


class ContinuousArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "cowrie.json"
        self.store = self.root / "dataset.sqlite3"
        self.labels = self.root / "review.csv"
        self.secret = "TOP_SECRET_PASSWORD_NEVER_ECHO"
        self.write_log()

    def write_log(self, *, extra=False):
        base = {"sensor": "my-sensor", "session": "sample-1", "src_ip": "198.51.100.55",
                "timestamp": "2026-11-04T01:00:00Z"}
        records = [dict(base, eventid="cowrie.session.connect"),
                   dict(base, eventid="cowrie.login.success", username="root", password=self.secret),
                   dict(base, eventid="cowrie.command.input", input="whoami")]
        if extra:
            records.append(dict(base, eventid="cowrie.command.input", input="uname -a"))
        self.log.write_text("".join(json.dumps(r)+"\n" for r in records), encoding="utf-8")

    def live(self, archive=True):
        return Monitor(input_path=self.log, source="file", enable_ml=False,
                       archive_enabled=archive, archive_store=self.store,
                       archive_origin="controlled-lab")

    def test_disabled_by_default(self):
        monitor = self.live(archive=False)
        self.assertTrue(monitor.poll_once())
        self.assertFalse(self.store.exists())
        self.assertFalse(monitor.snapshot()["archive"]["enabled"])

    def test_live_import_is_idempotent_and_new_revision_saved(self):
        monitor = self.live()
        self.assertTrue(monitor.poll_once())
        self.assertEqual(archive_summary(self.store)["versions"], 1)
        self.assertTrue(monitor.poll_once())
        self.assertEqual((archive_summary(self.store)["imports"], archive_summary(self.store)["versions"]), (1, 1))
        self.write_log(extra=True)
        self.assertTrue(monitor.poll_once())
        self.assertEqual(archive_summary(self.store)["versions"], 2)
        self.assertEqual(archive_summary(self.store)["unique_sessions"], 1)
        self.assertTrue(monitor.poll_once())
        self.assertEqual(archive_summary(self.store)["imports"], 2)
        self.assertEqual(monitor.snapshot()["archive"]["last_added_versions"], 1)

    def test_live_preserves_previously_reviewed_background_label(self):
        self.labels.write_text("sensor,session,label,analyst_note\nmy-sensor,sample-1,background,private note\n", encoding="utf-8")
        archive_import(self.log, store_path=self.store, labels_path=self.labels, origin="controlled-lab")
        monitor = self.live()
        self.assertTrue(monitor.poll_once())
        self.assertEqual(archive_summary(self.store)["latest_labels"], {"background": 1})
        self.assertEqual(archive_summary(self.store)["versions"], 1)
        self.write_log(extra=True)
        self.assertTrue(monitor.poll_once())
        self.assertEqual(archive_summary(self.store)["latest_labels"], {"background": 1})
        self.assertEqual(archive_summary(self.store)["versions"], 2)
        self.assertNotIn(self.secret.encode(), self.store.read_bytes())
        self.assertNotIn(b"private note", self.store.read_bytes())

    def test_archive_failure_does_not_stop_monitor_and_retry_succeeds(self):
        monitor = self.live()
        with patch("honeytrace.live.archive_import", side_effect=OSError("secret: " + self.secret)):
            self.assertTrue(monitor.poll_once())
        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["revision"], 1)
        self.assertEqual(snapshot["report"]["meta"]["sessions"], 1)
        self.assertIsNone(snapshot["monitor"]["error"])
        self.assertIn("retry", snapshot["archive"]["error"].lower())
        self.assertNotIn(self.secret, json.dumps(snapshot["archive"]))
        self.assertTrue(monitor.poll_once())
        self.assertEqual(monitor.snapshot()["revision"], 1)
        self.assertIsNone(monitor.snapshot()["archive"]["error"])
        self.assertEqual(archive_summary(self.store)["versions"], 1)

    def test_missing_log_does_not_create_archive(self):
        self.log.unlink()
        monitor = self.live()
        self.assertFalse(monitor.poll_once())
        self.assertFalse(self.store.exists())

    def test_bad_origin_rejected(self):
        with self.assertRaisesRegex(ValueError, "origin"):
            Monitor(input_path=self.log, source="file", archive_enabled=True, archive_origin="real verified attacker")

    def test_integrity_check_on_v08_compatible_archive(self):
        archive_import(self.log, store_path=self.store, origin="controlled-lab")
        result = archive_check(self.store)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sqlite_integrity"], "ok")
        self.assertEqual(result["versions_checked"], 1)
        self.assertEqual(result["snapshot_mismatches"], 0)

    def test_modified_feature_values_detected(self):
        archive_import(self.log, store_path=self.store)
        with closing(sqlite3.connect(self.store)) as conn, conn:
            conn.execute("UPDATE observations SET event_count = 999")
        result = archive_check(self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["snapshot_mismatches"], 1)

    def test_orphaned_import_detected(self):
        archive_import(self.log, store_path=self.store)
        with closing(sqlite3.connect(self.store)) as conn, conn:
            conn.execute("UPDATE observations SET import_id = 999999")
        self.assertFalse(archive_check(self.store)["ok"])
        self.assertEqual(archive_check(self.store)["foreign_key_violations"], 1)

    def test_key_mismatch_detected(self):
        archive_import(self.log, store_path=self.store)
        Path(str(self.store)+".key").write_bytes(b"z"*32)
        result = archive_check(self.store)
        self.assertFalse(result["ok"])
        self.assertIn("key", " ".join(result["errors"]).lower())

    def test_cli_store_check_exit_status(self):
        archive_import(self.log, store_path=self.store)
        command = [sys.executable, "honeytrace.py", "store-check", "--store", str(self.store)]
        base = Path(__file__).parent.parent
        passed = subprocess.run(command, cwd=base, capture_output=True, text=True, timeout=20)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertTrue(json.loads(passed.stdout)["ok"])
        with closing(sqlite3.connect(self.store)) as conn, conn:
            conn.execute("UPDATE observations SET event_count = 999")
        failed = subprocess.run(command, cwd=base, capture_output=True, text=True, timeout=20)
        self.assertEqual(failed.returncode, 1)
        self.assertFalse(json.loads(failed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
