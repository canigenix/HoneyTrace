"""Live monitor regression checks: no Docker needed."""
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from honeytrace.demo import create_demo
from honeytrace.live import Monitor, DashboardHandler, _docker_executable


class DockerDiscoveryTests(unittest.TestCase):
    def test_user_installed_docker_without_path(self):
        with TemporaryDirectory() as directory:
            expected = Path(directory) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
            expected.parent.mkdir(parents=True)
            expected.write_bytes(b"dummy for path discovery only")
            with patch("honeytrace.live.shutil.which", return_value=None), patch.dict("os.environ", {"LOCALAPPDATA": directory}):
                self.assertEqual(_docker_executable(), str(expected))


class LiveMonitorTests(unittest.TestCase):
    def test_reads_demo_log_and_only_reanalyzes_changes(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            create_demo(path, count=30)
            monitor = Monitor(input_path=path, source="file", enable_ml=True)
            self.assertTrue(monitor.poll_once())
            state = monitor.snapshot()
            self.assertEqual(state["report"]["meta"]["sessions"], 30)
            self.assertTrue(state["report"]["meta"]["ml_enabled"])
            self.assertIsNone(state["monitor"]["error"])
            self.assertEqual(state["revision"], 1)
            self.assertTrue(monitor.poll_once())
            self.assertEqual(monitor.snapshot()["revision"], 1)
            path.write_text(path.read_text(encoding="utf-8") + '\n', encoding="utf-8")
            self.assertTrue(monitor.poll_once())
            self.assertEqual(monitor.snapshot()["revision"], 2)

    def test_missing_file_appears_as_warning(self):
        with TemporaryDirectory() as directory:
            monitor = Monitor(input_path=Path(directory) / "missing.jsonl", source="file")
            self.assertFalse(monitor.poll_once())
            self.assertIn("not found", monitor.snapshot()["monitor"]["error"])
            self.assertEqual(monitor.snapshot()["report"]["meta"]["sessions"], 0)

    def test_alerts_do_not_include_passwords(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input.jsonl"
            ev = {"session":"s", "sensor":"a", "eventid":"cowrie.login.failed", "password":"SECRET_PASSWORD", "timestamp":"2026-11-03T00:00:00Z"}
            path.write_text(''.join(json.dumps(ev) + '\n' for _ in range(4)), encoding="utf-8")
            monitor = Monitor(input_path=path, source="file")
            self.assertTrue(monitor.poll_once())
            state = monitor.snapshot()
            self.assertEqual(state["alerts"][0]["label"], "Credential guessing")
            self.assertNotIn("SECRET_PASSWORD", json.dumps(state))

    def test_http_endpoint_read_only_local(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input.jsonl"
            create_demo(path, count=2)
            monitor = Monitor(input_path=path, source="file")
            monitor.poll_once()
            handler = type("TestHandler", (DashboardHandler,), {"monitor": monitor})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server.daemon_threads = True
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                client.request("GET", "/api/state")
                res = client.getresponse()
                self.assertEqual(res.status, 200)
                self.assertEqual(res.getheader("cache-control"), "no-store")
                data = json.loads(res.read())
                self.assertEqual(data["report"]["meta"]["sessions"], 2)
                client.request("GET", "/")
                page = client.getresponse()
                self.assertEqual(page.status, 200)
                self.assertIn(b"HONEYTRACE", page.read())
                client.request("GET", "/does-not-exist")
                missing = client.getresponse()
                self.assertEqual(missing.status, 404)
                missing.read()
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
