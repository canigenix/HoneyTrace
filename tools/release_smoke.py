"""Offline, disposable HoneyTrace release smoke test.

Run from any directory: python tools/release_smoke.py
This creates synthetic sessions ONLY in a temporary directory, tests the local
HTTP endpoint on loopback, and exercises archive -> backup -> restore. It does
not start Docker, import a user's data, or change the existing SQLite archive.
"""
from __future__ import annotations

from contextlib import closing
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
from threading import Thread

# Make the project importable when called as `python tools/release_smoke.py`.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeytrace.analyzer import analyze_events, load_events  # noqa: E402
from honeytrace.archive import archive_check, archive_import, archive_summary  # noqa: E402
from honeytrace.backup import create_backup, restore_backup, verify_backup  # noqa: E402
from honeytrace.demo import create_demo  # noqa: E402
from honeytrace.live import DashboardHandler, Monitor  # noqa: E402
from honeytrace.report import write_report  # noqa: E402


def _check(predicate: bool, message: str) -> None:
    if not predicate:
        raise AssertionError(message)


def _check_http(monitor: Monitor) -> None:
    handler = type("ReleaseSmokeHandler", (DashboardHandler,), {"monitor": monitor})
    # Ephemeral port, explicit loopback binding; never exposed on LAN.
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        port = server.server_address[1]
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as client:
                client.request("GET", "/api/state")
                response = client.getresponse()
                body = response.read()
                _check(response.status == 200, "Dashboard API did not respond with 200")
                state = json.loads(body)
                _check(state["report"]["meta"]["sessions"] == 40, "Dashboard session count incorrect")
                _check(state["archive"]["error"] is None, "Dashboard archive status reports failure")
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as client:
                client.putrequest("GET", "/api/state", skip_host=True)
                client.putheader("Host", "untrusted.invalid")
                client.endheaders()
                response = client.getresponse()
                response.read()
                _check(response.status == 403, "Dashboard accepted an untrusted Host header")
        finally:
            server.shutdown()
            worker.join(timeout=5)


def run_smoke() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="honeytrace-release-") as tmp:
        root = Path(tmp)
        log = root / "synthetic.jsonl"
        events_expected = create_demo(log, count=40)
        events, statistics = load_events(log)
        report = analyze_events(events)
        _check(report["meta"]["sessions"] == 40, "Synthetic analysis did not find 40 sessions")
        _check(report["meta"]["ml_enabled"], "Isolation Forest was not evaluated")
        _check(not statistics["truncated"], "Synthetic fixture was truncated")
        dashboard = root / "offline-report.html"
        write_report(report, dashboard, demo=True)
        _check(dashboard.is_file() and dashboard.stat().st_size > 100, "Offline report was not created")

        store = root / "history.sqlite3"
        first = archive_import(log, store_path=store, origin="synthetic")
        _check(first["added_versions"] == 40, "First archive import did not store 40 sessions")
        repeated = archive_import(log, store_path=store, origin="synthetic")
        _check(repeated["already_imported"] and repeated["added_versions"] == 0,
               "Repeated imports were not idempotent")
        initial = archive_check(store)
        _check(initial["ok"] and archive_summary(store)["unique_sessions"] == 40,
               "Archive failed integrity or unique-session check")

        backup = root / "private-backup"
        created = create_backup(store, destination=backup)
        verified = verify_backup(backup)
        _check(created["verified"] and verified["ok"], "Backup verification failed")
        restored_store = root / "restored.sqlite3"
        restored = restore_backup(backup, target=restored_store)
        restored_check = archive_check(restored_store)
        _check(restored["verified"] and restored_check["ok"], "Restore consistency check failed")
        _check(archive_summary(restored_store)["unique_sessions"] == 40,
               "Restored archive lost sessions")

        monitor = Monitor(input_path=log, source="file", archive_enabled=True,
                          archive_store=store, archive_origin="synthetic")
        _check(monitor.poll_once(), "Live file poll failed")
        state = monitor.snapshot()
        _check(state["report"]["meta"]["sessions"] == 40, "Live monitor lost sessions")
        _check(state["archive"]["last_added_versions"] == 0,
               "Live poll duplicated the archived sessions")
        _check_http(monitor)
        _check(archive_check(store)["ok"], "Live monitor damaged archive")
        return {"ok": True, "synthetic_sessions": 40,
                "archive_versions": initial["versions_checked"],
                "restore_verified": True, "live_http": "loopback-only; untrusted Host rejected",
                "note": "All data were synthetic in a disposable temporary directory; not an ML accuracy benchmark."}


if __name__ == "__main__":
    try:
        print(json.dumps(run_smoke(), indent=2))
    except Exception as exc:
        print(f"Release smoke test FAILED ({type(exc).__name__}): {exc}", file=sys.stderr)
        raise SystemExit(1) from None
