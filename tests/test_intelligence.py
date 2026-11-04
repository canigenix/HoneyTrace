"""v0.4 session intelligence regression tests; no Docker or internet required."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from honeytrace.analyzer import analyze_events
from honeytrace.live import Monitor
from honeytrace.intelligence import build_timeline, fingerprint_session, MAX_TIMELINE_EVENTS


def session_events(session: str, ip: str, commands: list[str], *, password: str = "FAKE_SECRET") -> list[dict]:
    base = {
        "session": session, "sensor": "lab", "src_ip": ip,
        "protocol": "ssh", "timestamp": "2026-11-03T00:00:00Z",
    }
    events = [
        {**base, "eventid": "cowrie.session.connect"},
        {**base, "eventid": "cowrie.login.success", "password": password, "username": "root", "message": "sensitive fixture only"},
    ]
    events.extend({**base, "eventid": "cowrie.command.input", "input": c} for c in commands)
    events.append({**base, "eventid": "cowrie.session.closed", "duration_ms": 2000})
    return events


class IntelligenceTests(unittest.TestCase):
    def test_repeated_sequence_groups_different_ips_and_arguments(self):
        events = session_events("a", "192.0.2.1", ["whoami", "uname -a", "hostname"])
        events += session_events("b", "198.51.100.5", ["whoami", "uname -r", "hostname"])
        report = analyze_events(events, enable_ml=False)
        self.assertEqual(report["meta"]["sessions"], 2)
        self.assertEqual(len(report["patterns"]), 1)
        self.assertEqual(report["patterns"][0]["sessions"], 2)
        self.assertEqual(report["patterns"][0]["sources"], 2)
        self.assertEqual(len({row["fingerprint"] for row in report["sessions"]}), 1)
        self.assertTrue(all(row["similar_sessions"] == 1 for row in report["sessions"]))
        self.assertEqual(report["sessions"][0]["timeline"][0]["label"], "SSH/Telnet connection opened")
        self.assertIn("Shell command entered", [event["label"] for event in report["sessions"][0]["timeline"]])

    def test_changed_sequence_changes_fingerprint(self):
        events = session_events("a", "192.0.2.1", ["whoami", "uname -a"])
        events += session_events("b", "198.51.100.5", ["uname -a", "whoami"])
        report = analyze_events(events, enable_ml=False)
        self.assertNotEqual(report["sessions"][0]["fingerprint"], report["sessions"][1]["fingerprint"])
        self.assertFalse(report["patterns"])

    def test_login_password_and_username_not_in_timeline_or_pattern(self):
        events = session_events("a", "192.0.2.1", ["whoami"], password="TOP_SECRET_DO_NOT_STORE")
        report = analyze_events(events, enable_ml=False)
        serialized = json.dumps(report)
        self.assertNotIn("TOP_SECRET_DO_NOT_STORE", serialized)
        self.assertNotIn("sensitive fixture only", serialized)
        self.assertNotIn("root", serialized)
        self.assertEqual(report["sessions"][0]["timeline"][1]["label"], "Login attempt succeeded")

    def test_timeline_truncation_and_escaping_will_be_text_only(self):
        events = session_events("a", "192.0.2.1", ["echo <script>alert(1)</script>"] * 100)
        report = analyze_events(events, enable_ml=False)
        timeline = report["sessions"][0]["timeline"]
        self.assertEqual(len(timeline), MAX_TIMELINE_EVENTS + 1)
        self.assertIn("omitted", timeline[-1]["label"])
        # Raw commands are retained as *data*, not executed, and rendered with textContent.
        self.assertIn("<script>", timeline[2]["command"])

    def test_live_monitor_state_has_pattern_data(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            events = session_events("a", "192.0.2.1", ["whoami"])
            events += session_events("b", "198.51.100.5", ["whoami"])
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
            monitor = Monitor(input_path=path, source="file", enable_ml=False)
            self.assertTrue(monitor.poll_once())
            state = monitor.snapshot()
            self.assertIsNone(state["monitor"]["error"])
            self.assertEqual(state["report"]["patterns"][0]["sessions"], 2)
            self.assertEqual(state["report"]["sessions"][0]["similar_sessions"], 1)


if __name__ == "__main__":
    unittest.main()
