"""v1.0-rc backup, restore and scheduling regression tests (offline only)."""
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

from honeytrace.archive import archive_import, archive_summary, archive_check
from honeytrace.backup import create_backup, verify_backup, restore_backup
from honeytrace.live import Monitor


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.log = self.folder / "cowrie.json"
        self.store = self.folder / "local.sqlite3"
        self.backup = self.folder / "backups" / "first"
        self.restored = self.folder / "restored.sqlite3"
        self.secret = "PRIVATE_TEST_PASSWORD_XYZ"
        self._write_log()
        self.labels = self.folder / "labels.csv"
        self.labels.write_text("sensor,session,label\nsensor-A,session-one,background\n", encoding="utf-8")
        archive_import(self.log, store_path=self.store, labels_path=self.labels, origin="controlled-lab")

    def _write_log(self, extra=False):
        base = {"sensor": "sensor-A", "session": "session-one", "src_ip": "192.0.2.19", "timestamp": "2026-11-03T10:00:00Z"}
        events = [dict(base, eventid="cowrie.session.connect"),
                  dict(base, eventid="cowrie.login.success", username="root", password=self.secret),
                  dict(base, eventid="cowrie.command.input", input="whoami")]
        if extra:
            events.append(dict(base, eventid="cowrie.command.input", input="hostname"))
        self.log.write_text("".join(json.dumps(v) + "\n" for v in events), encoding="utf-8")

    def test_create_verify_restore_preserves_private_labels(self):
        before = archive_summary(self.store)
        made = create_backup(self.store, destination=self.backup)
        self.assertTrue(made["verified"])
        self.assertTrue(verify_backup(self.backup)["ok"])
        restored = restore_backup(self.backup, target=self.restored)
        self.assertTrue(restored["verified"])
        self.assertEqual(before["latest_labels"], archive_summary(self.restored)["latest_labels"])
        self.assertEqual(before["versions"], archive_summary(self.restored)["versions"])
        self.assertTrue(archive_check(self.restored)["ok"])
        self.assertEqual((self.folder / "restored.sqlite3.key").read_bytes(), Path(str(self.store)+".key").read_bytes())

    def test_backup_does_not_contain_raw_password_or_commands(self):
        create_backup(self.store, destination=self.backup)
        for file in self.backup.iterdir():
            self.assertNotIn(self.secret.encode(), file.read_bytes())
            self.assertNotIn(b"whoami", file.read_bytes())
        self.assertNotIn("sensor-A", (self.backup / "manifest.json").read_text())

    def test_source_archive_is_never_modified(self):
        original = self.store.read_bytes()
        original_key = Path(str(self.store) + ".key").read_bytes()
        create_backup(self.store, destination=self.backup)
        restore_backup(self.backup, target=self.restored)
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(Path(str(self.store)+".key").read_bytes(), original_key)

    def test_refuse_to_replace_backup_folder(self):
        create_backup(self.store, destination=self.backup)
        with self.assertRaises(FileExistsError):
            create_backup(self.store, destination=self.backup)
        self.assertTrue(verify_backup(self.backup)["ok"])

    def test_refuse_to_restore_over_any_existing_file(self):
        create_backup(self.store, destination=self.backup)
        with self.assertRaises(FileExistsError):
            restore_backup(self.backup, target=self.store)
        self.assertTrue(archive_check(self.store)["ok"])
        self.restored.with_name(self.restored.name+".key").write_bytes(b"don't overwrite")
        with self.assertRaises(FileExistsError):
            restore_backup(self.backup, target=self.restored)
        self.assertFalse(self.restored.exists())

    def test_tampered_database_checksum_fails_closed(self):
        create_backup(self.store, destination=self.backup)
        with closing(sqlite3.connect(self.backup / "archive.sqlite3")) as conn, conn:
            conn.execute("UPDATE observations SET event_count=999")
        result = verify_backup(self.backup)
        self.assertFalse(result["ok"])
        self.assertFalse(result["checksums_match"])
        with self.assertRaises(ValueError):
            restore_backup(self.backup, target=self.restored)
        self.assertFalse(self.restored.exists())

    def test_tampered_key_checksum_fails_closed(self):
        create_backup(self.store, destination=self.backup)
        (self.backup / "archive.sqlite3.key").write_bytes(b"0" * 32)
        self.assertFalse(verify_backup(self.backup)["ok"])

    def test_missing_file_or_symlink_rejected(self):
        create_backup(self.store, destination=self.backup)
        (self.backup / "archive.sqlite3.key").unlink()
        self.assertFalse(verify_backup(self.backup)["ok"])

    def test_backup_works_when_new_versions_exist(self):
        self._write_log(extra=True)
        archive_import(self.log, store_path=self.store, origin="controlled-lab")
        self.assertEqual(archive_summary(self.store)["versions"], 2)
        create_backup(self.store, destination=self.backup)
        restore_backup(self.backup, target=self.restored)
        self.assertEqual(archive_summary(self.restored)["latest_labels"], {"background": 1})
        self.assertEqual(archive_summary(self.restored)["versions"], 2)

    def test_invalid_source_refuses_to_create_backup(self):
        with closing(sqlite3.connect(self.store)) as conn, conn:
            conn.execute("UPDATE observations SET event_count=999")
        with self.assertRaisesRegex(ValueError, "consistency"):
            create_backup(self.store, destination=self.backup)
        self.assertFalse(self.backup.exists())

    def test_cli_roundtrip(self):
        root = Path(__file__).resolve().parent.parent
        cmds = [
            ["store-backup", "--store", str(self.store), "--destination", str(self.backup)],
            ["store-verify-backup", str(self.backup)],
            ["store-restore", str(self.backup), "--target", str(self.restored)],
            ["store-check", "--store", str(self.restored)],
        ]
        for parts in cmds:
            p = subprocess.run([sys.executable, "honeytrace.py", *parts], cwd=root,
                               capture_output=True, text=True, timeout=25)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(json.loads(p.stdout).get("verified") or json.loads(p.stdout).get("ok"))

    def test_live_periodic_backup_once_until_due(self):
        backupdir = self.folder / "live-backups"
        monitor = Monitor(input_path=self.log, source="file", archive_enabled=True,
                          archive_store=self.store, archive_origin="controlled-lab",
                          backup_interval_seconds=3600, backup_dir=backupdir)
        self.assertTrue(monitor.poll_once())
        state = monitor.snapshot()["archive"]
        self.assertTrue(state["backup_enabled"])
        self.assertIsNotNone(state["last_backup"])
        self.assertEqual(len(list(backupdir.iterdir())), 1)
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(list(backupdir.iterdir())), 1)
        monitor._last_backup_at = -float("inf")
        self.assertTrue(monitor.poll_once())
        self.assertEqual(len(list(backupdir.iterdir())), 2)
        self.assertTrue(all(verify_backup(d)["ok"] for d in backupdir.iterdir()))

    def test_live_backup_failure_does_not_stop_monitoring(self):
        monitor = Monitor(input_path=self.log, source="file", archive_enabled=True,
                          archive_store=self.store, backup_interval_seconds=3600)
        with patch("honeytrace.live.create_backup", side_effect=OSError("bad")):
            self.assertTrue(monitor.poll_once())
        result = monitor.snapshot()
        self.assertEqual(result["report"]["meta"]["sessions"], 1)
        self.assertIsNone(result["monitor"]["error"])
        self.assertIn("retry", result["archive"]["backup_error"])

    def test_manifest_edit_or_missing_manifest_fails(self):
        create_backup(self.store, destination=self.backup)
        p = self.backup / "manifest.json"
        manifest = json.loads(p.read_text())
        manifest["sha256"]["archive.sqlite3"] = "a"*64
        p.write_text(json.dumps(manifest))
        self.assertFalse(verify_backup(self.backup)["ok"])
        with self.assertRaises(ValueError):
            restore_backup(self.backup, target=self.restored)
        p.unlink()
        self.assertFalse(verify_backup(self.backup)["ok"])

    def test_cli_verify_corruption_fails_with_exit_one(self):
        create_backup(self.store, destination=self.backup)
        (self.backup / "archive.sqlite3.key").write_bytes(b"1"*32)
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run([sys.executable, "honeytrace.py", "store-verify-backup", str(self.backup)],
                              cwd=root, capture_output=True, text=True, timeout=25)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(json.loads(proc.stdout)["ok"])

    def test_online_backup_in_wal_mode(self):
        with closing(sqlite3.connect(self.store)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE internal_test (value TEXT)")
            connection.execute("INSERT INTO internal_test VALUES ('committed')")
            connection.commit()
            made = create_backup(self.store, destination=self.backup)
            self.assertTrue(made["verified"])
        self.assertTrue(verify_backup(self.backup)["ok"])
        with closing(sqlite3.connect(self.backup / "archive.sqlite3")) as connection:
            self.assertEqual(connection.execute("SELECT value FROM internal_test").fetchone()[0], "committed")

    def test_invalid_live_backup_interval_requires_archive(self):
        with self.assertRaises(ValueError):
            Monitor(input_path=self.log, source="file", backup_interval_seconds=3600)


if __name__ == "__main__":
    unittest.main()
