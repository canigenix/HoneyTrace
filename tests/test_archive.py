"""v0.8 local archive regression tests (never uses Docker or network)."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from contextlib import closing
import sqlite3
import tempfile
import unittest

from honeytrace.archive import archive_import, archive_summary, archive_export
from honeytrace.demo import create_demo


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.log = self.root / "cowrie.jsonl"
        self.store = self.root / "data" / "history.sqlite3"
        self.export = self.root / "data" / "features.csv"
        self.secret_text = "RAW_PASSWORD_SHOULD_NOT_BE_IN_ARCHIVE"
        self.ip = "198.51.100.182"
        self.make_log()

    def make_log(self, *, extra_command=None):
        base = {"sensor": "lab", "session": "session-1", "src_ip": self.ip, "timestamp": "2026-11-03T19:00:00Z"}
        events = [dict(base, eventid="cowrie.session.connect"),
                  dict(base, eventid="cowrie.login.success", username="root", password=self.secret_text),
                  dict(base, eventid="cowrie.command.input", input="whoami")]
        if extra_command:
            events.append(dict(base, eventid="cowrie.command.input", input=extra_command))
        self.log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

    def import_it(self, labels=None, origin="controlled-lab"):
        return archive_import(self.log, store_path=self.store, labels_path=labels, origin=origin)

    def test_import_and_status_do_not_copy_raw_sensitive_values(self):
        result = self.import_it()
        self.assertEqual(result["added_versions"], 1)
        self.assertEqual(result["sessions_in_input"], 1)
        summary = archive_summary(self.store)
        self.assertEqual(summary["unique_sessions"], 1)
        self.assertEqual(summary["versions"], 1)
        self.assertEqual(summary["imports"], 1)
        self.assertEqual(summary["distinct_source_groups"], 1)
        text = self.store.read_bytes()
        for secret in (self.secret_text, self.ip, "whoami", "root", "session-1"):
            self.assertNotIn(secret.encode(), text)
            self.assertNotIn(secret, json.dumps(summary))

    def test_exact_repeat_does_not_duplicate(self):
        self.import_it()
        again = self.import_it()
        self.assertTrue(again["already_imported"])
        self.assertEqual(again["added_versions"], 0)
        self.assertEqual(archive_summary(self.store)["imports"], 1)

    def test_changed_log_adds_only_a_new_version(self):
        self.import_it()
        self.make_log(extra_command="uname -a")
        updated = self.import_it()
        self.assertEqual(updated["added_versions"], 1)
        s = archive_summary(self.store)
        self.assertEqual((s["imports"], s["unique_sessions"], s["versions"]), (2, 1, 2))

    def test_label_review_creates_revision_without_notes_or_secrets(self):
        self.import_it()
        csvfile = self.root / "review.csv"
        csvfile.write_text("sensor,session,label,analyst_note\nlab,session-1,background,SENSITIVE NOTE\n", encoding="utf-8")
        changed = self.import_it(labels=csvfile)
        self.assertEqual(changed["added_versions"], 1)
        status = archive_summary(self.store)
        self.assertEqual(status["latest_labels"], {"background": 1})
        self.assertEqual(status["versions"], 2)
        self.assertNotIn(b"SENSITIVE NOTE", self.store.read_bytes())
        csvfile.write_text("sensor,session,label,analyst_note\nlab,session-1,review,SENSITIVE NOTE\n", encoding="utf-8")
        self.assertEqual(self.import_it(labels=csvfile)["added_versions"], 1)
        self.assertEqual(archive_summary(self.store)["latest_labels"], {"review": 1})

    def test_invalid_label_does_not_create_archive(self):
        p = self.root / "bad.csv"
        p.write_text("sensor,session,label\nlab,session-1,attacker\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "label must be"):
            self.import_it(labels=p)
        self.assertFalse(self.store.exists())
        self.assertFalse(self.store.with_name(self.store.name + ".key").exists())

    def test_missing_key_rejected_for_existing_archive(self):
        self.import_it()
        self.store.with_name(self.store.name + ".key").unlink()
        with self.assertRaisesRegex(ValueError, "key missing"):
            self.import_it()

    def test_invalid_key_rejected(self):
        self.import_it()
        self.store.with_name(self.store.name + ".key").write_bytes(b"x" * 32)
        self.make_log(extra_command="uname -a")
        with self.assertRaisesRegex(ValueError, "key_sha256 mismatch"):
            self.import_it()

    def test_private_export_does_not_overwrite(self):
        self.import_it()
        self.assertEqual(archive_export(self.store, output=self.export), 1)
        csvtext = self.export.read_text(encoding="utf-8")
        self.assertIn("session_token,source_token,observed_day", csvtext)
        self.assertIn("2026-11-03", csvtext)
        for forbidden in (self.ip, self.secret_text, "whoami", "root", "session-1"):
            self.assertNotIn(forbidden, csvtext)
        with self.assertRaises(FileExistsError):
            archive_export(self.store, output=self.export)

    def test_export_only_latest_state(self):
        self.import_it()
        self.make_log(extra_command="uname -a")
        self.import_it()
        archive_export(self.store, output=self.export)
        with self.export.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["command_count"], "2")

    def test_distinct_source_groups_are_pseudonymized(self):
        self.import_it()
        base = {"sensor": "lab", "session": "session-2", "src_ip": "203.0.113.27", "timestamp": "2026-11-04T19:00:00Z"}
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(base, eventid="cowrie.command.input", input="whoami")) + "\n")
        self.import_it()
        status = archive_summary(self.store)
        self.assertEqual(status["unique_sessions"], 2)
        self.assertEqual(status["distinct_source_groups"], 2)
        self.assertNotIn(b"203.0.113.27", self.store.read_bytes())

    def test_schema_conflict_rejected(self):
        self.import_it()
        with closing(sqlite3.connect(self.store)) as conn, conn:
            conn.execute("UPDATE metadata SET value='999' WHERE name='schema'")
        self.make_log(extra_command="uname -a")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            self.import_it()

    def test_wrong_origin_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid origin"):
            self.import_it(origin="live-attacker")

    def test_demo_works_with_archive(self):
        create_demo(self.log, count=30)
        result = self.import_it(origin="synthetic")
        self.assertEqual(result["added_versions"], 30)
        self.assertEqual(archive_summary(self.store)["origin_declarations_by_import"], {"synthetic": 1})


if __name__ == "__main__":
    unittest.main()
