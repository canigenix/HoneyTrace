import json
from pathlib import Path
import tempfile
import unittest

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.demo import create_demo
from honeytrace.report import write_report


class HoneyTraceTests(unittest.TestCase):
    def test_synthetic_anomaly_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.jsonl"
            create_demo(p)
            events, stats = load_events(p)
            result = analyze_events(events)
            self.assertEqual(result["meta"]["sessions"], 240)
            self.assertTrue(result["meta"]["ml_enabled"])
            self.assertGreater(sum(bool(s["anomaly"]) for s in result["sessions"]), 0)
            self.assertIn("Payload delivery indicator", result["labels"])
            self.assertIn("Credential guessing", result["labels"])
            self.assertEqual(stats["invalid"], 0)

    def test_too_few_sessions_does_not_claim_ml(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.jsonl"
            create_demo(p, count=10)
            events, _ = load_events(p)
            result = analyze_events(events)
            self.assertFalse(result["meta"]["ml_enabled"])
            self.assertTrue(all(s["anomaly"] is None for s in result["sessions"]))

    def test_ignores_invalid_and_unrelated_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.jsonl"
            p.write_text('{broken}\n{"eventid":"other","session":"x"}\n{"eventid":"cowrie.session.connect","session":"s1"}\n', encoding="utf-8")
            events, stats = load_events(p)
            self.assertEqual(len(events), 1)
            self.assertEqual(stats["invalid"], 1)
            self.assertEqual(stats["skipped"], 1)

    def test_html_script_injection_is_escaped(self):
        evil = '</script><script>alert("x")</script>'
        event = {"session":"x", "eventid":"cowrie.command.input", "input":evil, "src_ip":"192.0.2.1", "sensor":"test", "timestamp":"2026-11-03T00:00:00Z"}
        result = analyze_events([event])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report.html"
            write_report(result, p)
            html = p.read_text(encoding="utf-8")
            self.assertNotIn(evil, html)
            self.assertIn("\\u003c/script\\u003e", html)
            self.assertEqual(html.count('<script id="payload"'), 1)

    def test_session_and_sensor_isolation(self):
        events = [
            {"session":"same", "sensor":"one", "eventid":"cowrie.login.failed"},
            {"session":"same", "sensor":"two", "eventid":"cowrie.login.failed"},
        ]
        self.assertEqual(analyze_events(events)["meta"]["sessions"], 2)

    def test_passwords_never_enter_report(self):
        events = [{"session":"a", "sensor":"lab", "eventid":"cowrie.login.failed", "password":"SECRET_DO_NOT_LOG", "username":"root"}]
        result = analyze_events(events)
        self.assertNotIn("SECRET_DO_NOT_LOG", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
