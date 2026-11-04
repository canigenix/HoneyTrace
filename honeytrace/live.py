"""Local-only Cowrie log monitor with a read-only, auto-updating dashboard.

No remote ports, shell execution, external APIs, or sample downloading.
Docker CLI is invoked with a fixed argument list (never a shell).
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Event, Lock, Thread
from typing import Any
import sqlite3
from urllib.parse import urlsplit

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.archive import ORIGINS, archive_import

DEFAULT_COWRIE_LOG = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
MAX_LIVE_FILE_BYTES = 20 * 1024 * 1024
ALERT_LABELS = {
    "Credential guessing", "System reconnaissance", "Payload delivery indicator",
    "Persistence indicator", "Privilege exploration", "Suspicious/encoded execution",
    "Destructive command indicator", "Exploit indicator",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _docker_executable() -> str:
    """Find Docker even when VS Code inherited an outdated Windows PATH.

    Docker Desktop can be installed per-user rather than in Program Files.
    The resolved executable is passed as an argv element, never to a shell.
    """
    found = shutil.which("docker") or shutil.which("docker.exe")
    if found:
        return found

    candidates: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base = Path(local_app_data)
        candidates.extend([
            base / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe",
            base / "Programs" / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
        ])
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates.append(Path(program_files) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe")

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError(
        "Docker CLI not found. On Windows, confirm Docker Desktop is running "
        "and docker.exe exists under LOCALAPPDATA/Programs/DockerDesktop/resources/bin. "
        "Restart HoneyTrace after fixing Docker access."
    )


def _hash(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def _alert_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    for row in result["sessions"]:
        for label in row["labels"]:
            if label in ALERT_LABELS:
                alerts.append({
                    "session": row["session"], "sensor": row["sensor"],
                    "source": row["src_ip"], "label": label,
                    "risk": row["risk"], "start": row["start"],
                })
    alerts.sort(key=lambda alert: alert["start"], reverse=True)
    return alerts[:30]


class Monitor:
    """Fetch logs, analyze new bytes, and expose a synchronized snapshot."""

    def __init__(
        self, *, input_path: Path, source: str = "docker", container: str = "honeytrace-cowrie",
        container_path: str = DEFAULT_COWRIE_LOG, interval: int = 5,
        enable_ml: bool = True,
        archive_enabled: bool = False,
        archive_store: Path = Path("data/honeytrace-history.sqlite3"),
        archive_origin: str = "unverified",
    ) -> None:
        if source not in ("docker", "file"):
            raise ValueError("source must be 'docker' or 'file'")
        if not 2 <= interval <= 60:
            raise ValueError("interval must be between 2 and 60 seconds")
        self.input_path = input_path
        self.source = source
        self.container = container
        self.container_path = container_path
        self.interval = interval
        self.enable_ml = enable_ml
        if archive_origin not in ORIGINS:
            raise ValueError("Invalid archive origin declaration")
        self.archive_enabled = archive_enabled
        self.archive_store = Path(archive_store)
        self.archive_origin = archive_origin
        self._archived_digest: str | None = None
        self._archive_error: str | None = None
        self._archive_checked: str | None = None
        self._archive_last_success: str | None = None
        self._archive_added_versions = 0
        self._lock = Lock()
        self._stop = Event()
        self._last_digest: str | None = None
        self._revision = 0
        self._report: dict[str, Any] = {
            "meta": {"sessions": 0, "unique_sources": 0, "events": 0, "ml_enabled": False},
            "sessions": [], "labels": {},
        }
        self._alerts: list[dict[str, Any]] = []
        self._checked: str | None = None
        self._changed: str | None = None
        self._error: str | None = "Waiting for the first successful log read"

    def _copy_docker_log(self) -> None:
        self.input_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".cowrie-", suffix=".json", dir=self.input_path.parent)
        os.close(fd)
        temp = Path(name)
        try:
            args = [_docker_executable(), "cp", f"{self.container}:{self.container_path}", str(temp)]
            completed = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
            if completed.returncode != 0:
                msg = (completed.stderr or completed.stdout or "docker cp failed").strip()
                raise RuntimeError(msg[:500])
            if not temp.is_file():
                raise RuntimeError("Docker did not produce a log file")
            if temp.stat().st_size > MAX_LIVE_FILE_BYTES:
                raise RuntimeError("Live log exceeds the 20 MB safety limit; rotate/archive it first")
            temp.replace(self.input_path)
        finally:
            temp.unlink(missing_ok=True)

    def poll_once(self) -> bool:
        """Return True if new input generated a new analysis."""
        try:
            if self.source == "docker":
                self._copy_docker_log()
            if not self.input_path.is_file():
                raise FileNotFoundError(f"Cowrie JSON log not found: {self.input_path}")
            if self.input_path.stat().st_size > MAX_LIVE_FILE_BYTES:
                raise RuntimeError("Live log exceeds the 20 MB safety limit; rotate/archive it first")
            digest = _hash(self.input_path)
            if digest != self._last_digest:
                events, stats = load_events(self.input_path)
                result = analyze_events(events, enable_ml=self.enable_ml)
                result["meta"].update({"input_name": self.input_path.name, "demo": False, "parse_stats": stats})
                alerts = _alert_rows(result)
                with self._lock:
                    self._report = result
                    self._alerts = alerts
                    self._revision += 1
                    self._changed = _utc_now()
                    self._last_digest = digest
            # Archive retries are independent from dashboard analysis. A busy,
            # unwritable, or mismatched SQLite database must not block viewing.
            # Failed snapshots retry on the next poll even if the log is unchanged.
            if self.archive_enabled and digest != self._archived_digest:
                try:
                    saved = archive_import(self.input_path, store_path=self.archive_store,
                                           origin=self.archive_origin)
                    with self._lock:
                        self._archived_digest = digest
                        self._archive_last_success = _utc_now()
                        self._archive_added_versions = saved["added_versions"]
                        self._archive_error = None
                except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError) as exc:
                    with self._lock:
                        # Avoid echoing raw log content in the HTTP error field.
                        self._archive_error = (
                            "Local archive failed; check database/key and file permissions "
                            f"({type(exc).__name__}). Retry is automatic."
                        )
            with self._lock:
                self._checked = _utc_now()
                self._error = None
                if self.archive_enabled:
                    self._archive_checked = self._checked
            return True
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            with self._lock:
                self._checked = _utc_now()
                self._error = str(exc)[:500]
            return False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            # JSON serialization is performed while locked, returning a detached object.
            payload = {
                "revision": self._revision,
                "report": self._report,
                "alerts": self._alerts,
                "archive": {
                    "enabled": self.archive_enabled,
                    "origin": self.archive_origin if self.archive_enabled else None,
                    "last_checked": self._archive_checked,
                    "last_success": self._archive_last_success,
                    "last_added_versions": self._archive_added_versions,
                    "error": self._archive_error,
                },
                "monitor": {
                    "source": self.source,
                    "interval_seconds": self.interval,
                    "last_checked": self._checked,
                    "last_changed": self._changed,
                    "error": self._error,
                },
            }
            return json.loads(json.dumps(payload))

    def loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval)

    def start(self) -> Thread:
        worker = Thread(target=self.loop, name="honeytrace-cowrie-poller", daemon=True)
        worker.start()
        return worker

    def stop(self) -> None:
        self._stop.set()


class DashboardHandler(BaseHTTPRequestHandler):
    monitor: Monitor

    def log_message(self, format: str, *args: object) -> None:
        # The browser polls every 3s; avoid spamming terminal with routine requests.
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP method name
        # Reject arbitrary Host values (e.g., DNS-rebinding attempts).
        port = self.server.server_address[1]
        valid_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "").lower() not in valid_hosts:
            self._respond(403, "text/plain; charset=utf-8", b"Invalid Host")
            return
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            html = (Path(__file__).parent / "live.html").read_bytes()
            self._respond(200, "text/html; charset=utf-8", html)
        elif path == "/api/state":
            payload = json.dumps(self.monitor.snapshot(), ensure_ascii=True).encode("utf-8")
            self._respond(200, "application/json; charset=utf-8", payload)
        else:
            self._respond(404, "text/plain; charset=utf-8", b"Not found")

    def _respond(self, status: int, mime: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; object-src 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)


def serve_dashboard(monitor: Monitor, port: int = 8765) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("port must be between 1024 and 65535")
    handler = type("HoneyTraceHandler", (DashboardHandler,), {"monitor": monitor})
    # Binding to loopback is deliberate: no --host option or public listener.
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    monitor.start()
    print(f"HoneyTrace live dashboard: http://127.0.0.1:{port}", flush=True)
    print("Local-only; press Ctrl+C to stop. Never port-forward this interface.", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Stopping HoneyTrace monitoring...", flush=True)
    finally:
        monitor.stop()
        server.server_close()
