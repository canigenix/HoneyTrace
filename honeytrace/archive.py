"""Local, append-only, privacy-minimized history for Cowrie-derived features.

Only derived numeric features, behavior labels, truncated day timestamps and
HMAC-pseudonymized session/source identifiers enter SQLite. Raw event text,
commands, addresses, usernames, passwords and reviewer notes stay out.

This is a local research archive, *not* an authenticated evidence ledger,
and a declared collection origin is not independently verified provenance.
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import csv
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3

from honeytrace.analyzer import FEATURES, analyze_events, load_events, parse_time
from honeytrace.validation import _read_labels

ORIGINS = ("unverified", "controlled-lab", "synthetic", "independent-observations")
SCHEMA_VERSION = "1"
MAX_SOURCE_BYTES = 20 * 1024 * 1024


def _digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secret_path(store: Path) -> Path:
    return store.with_name(store.name + ".key")


def _load_secret(store: Path) -> bytes:
    path = _secret_path(store)
    if path.exists():
        data = path.read_bytes()
        if len(data) != 32:
            raise ValueError("Archive key invalid; restore original 32-byte key")
        return data
    if store.exists():
        raise ValueError("Archive key missing; restore the original .key file before importing")
    store.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation, with best-effort owner-only permissions on Unix.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            key = secrets.token_bytes(32)
            output.write(key)
        return key
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _token(key: bytes, domain: str, value: str) -> str:
    return hmac.new(key, (domain + "\x00" + value).encode("utf-8"), "sha256").hexdigest()[:32]


def _connect(path: Path, key: bytes) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS imports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          log_sha256 TEXT NOT NULL,
          labels_sha256 TEXT NOT NULL,
          imported_utc TEXT NOT NULL,
          origin TEXT NOT NULL,
          events INTEGER NOT NULL,
          sessions INTEGER NOT NULL,
          invalid_lines INTEGER NOT NULL,
          skipped_lines INTEGER NOT NULL,
          UNIQUE (log_sha256, labels_sha256)
        );
        CREATE TABLE IF NOT EXISTS observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          import_id INTEGER NOT NULL REFERENCES imports(id),
          session_token TEXT NOT NULL,
          source_token TEXT NOT NULL,
          sensor_token TEXT NOT NULL,
          observed_day TEXT,
          fingerprint TEXT NOT NULL,
          features_json TEXT NOT NULL,
          indicators_json TEXT NOT NULL,
          review_label TEXT NOT NULL,
          event_count INTEGER NOT NULL,
          snapshot_sha256 TEXT NOT NULL,
          UNIQUE (session_token, snapshot_sha256)
        );
        CREATE INDEX IF NOT EXISTS idx_observation_session ON observations(session_token, id);
    """)
    expected = {"schema": SCHEMA_VERSION, "key_sha256": sha256(key).hexdigest()}
    for name, value in expected.items():
        row = conn.execute("SELECT value FROM metadata WHERE name = ?", (name,)).fetchone()
        if row and row["value"] != value:
            conn.close()
            raise ValueError(f"Archive {name} mismatch; refusing to merge incompatible history")
        if row is None:
            conn.execute("INSERT INTO metadata VALUES (?, ?)", (name, value))
    conn.commit()
    return conn


def _latest_clause() -> str:
    return """
      SELECT o.* FROM observations o
      INNER JOIN (SELECT session_token, MAX(id) AS latest_id
                  FROM observations GROUP BY session_token) newest
      ON o.id = newest.latest_id
    """


def archive_import(
    log_path: str | Path, *, store_path: str | Path = "data/honeytrace-history.sqlite3",
    labels_path: str | Path | None = None, origin: str = "unverified",
) -> dict:
    """Import one complete log snapshot; deduplicate unchanged snapshots.

    A changed session state or manually revised label adds a new *version*.
    Existing observation rows are never updated or deleted by this tool.
    """
    if origin not in ORIGINS:
        raise ValueError("Invalid origin declaration")
    log = Path(log_path)
    if log.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("Input exceeds 20 MB archive safeguard; split/rotate the log")
    events, stats = load_events(log)
    if stats["truncated"]:
        raise ValueError("Input was truncated by parser; split log before archiving")
    analyzed = analyze_events(events, enable_ml=False)
    sessions = analyzed["sessions"]
    # Validate all manual rows before opening the database or creating a key.
    labels = _read_labels(Path(labels_path), sessions) if labels_path is not None else {}
    log_sha = _digest_file(log)
    labels_sha = _digest_file(Path(labels_path)) if labels_path is not None else ""
    store = Path(store_path)
    store.parent.mkdir(parents=True, exist_ok=True)
    key = _load_secret(store)

    counts = Counter()
    for ev in events:
        sensor = str(ev.get("sensor") or "")[:120] or "default"
        counts[(sensor, str(ev["session"]))] += 1

    with closing(_connect(store, key)) as conn, conn:
        prior = conn.execute("SELECT id FROM imports WHERE log_sha256=? AND labels_sha256=?", (log_sha, labels_sha)).fetchone()
        if prior:
            return {"already_imported": True, "added_versions": 0, "sessions_in_input": len(sessions),
                    "events_in_input": len(events), "source_groups_in_input": len({s["src_ip"] for s in sessions if s["src_ip"]})}

        cur = conn.execute("INSERT INTO imports (log_sha256, labels_sha256, imported_utc, origin, events, sessions, invalid_lines, skipped_lines) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (log_sha, labels_sha, _now(), origin, len(events), len(sessions), stats["invalid"], stats["skipped"]))
        import_id = cur.lastrowid
        added = 0
        for row in sessions:
            sensor, session = str(row["sensor"]), str(row["session"])
            feature_data = {name: row["features"][name] for name in FEATURES}
            label = labels.get((sensor, session), "")
            session_token = _token(key, "session", sensor + "\x00" + session)
            # An automatic live import has no reviewed CSV. Preserve the
            # previous human judgment instead of resetting it to unlabeled.
            # An explicitly supplied CSV is authoritative, even if blank.
            if labels_path is None:
                previous = conn.execute(
                    "SELECT review_label FROM observations WHERE session_token=? ORDER BY id DESC LIMIT 1",
                    (session_token,),
                ).fetchone()
                if previous is not None:
                    label = previous["review_label"]
            day_time = parse_time(row["start"])
            day = day_time.date().isoformat() if day_time else None
            indicators = sorted(row["labels"])
            digest_payload = {"feature": feature_data, "indicators": indicators,
                              "fingerprint": row["fingerprint"], "label": label,
                              "event_count": counts[(sensor, session)], "day": day,
                              "source_token": _token(key, "source", row["src_ip"]) if row["src_ip"] else ""}
            digest = sha256(json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            cur = conn.execute("""
              INSERT OR IGNORE INTO observations (
                import_id, session_token, source_token, sensor_token, observed_day,
                fingerprint, features_json, indicators_json, review_label, event_count, snapshot_sha256
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (import_id, session_token,
                  _token(key, "source", row["src_ip"]) if row["src_ip"] else "",
                  _token(key, "sensor", sensor), day, row["fingerprint"],
                  json.dumps(feature_data, sort_keys=True), json.dumps(indicators), label,
                  counts[(sensor, session)], digest))
            added += max(0, cur.rowcount)
    return {"already_imported": False, "added_versions": added,
            "sessions_in_input": len(sessions), "events_in_input": len(events),
            "source_groups_in_input": len({s["src_ip"] for s in sessions if s["src_ip"]})}


def archive_summary(store_path: str | Path = "data/honeytrace-history.sqlite3") -> dict:
    """Aggregate-only status; never print source/session pseudonyms."""
    store = Path(store_path)
    if not store.is_file():
        raise FileNotFoundError(f"No local archive yet: {store}")
    with closing(sqlite3.connect(store)) as conn:
        conn.row_factory = sqlite3.Row
        names = {row["name"]: row["value"] for row in conn.execute("SELECT name, value FROM metadata")}
        if names.get("schema") != SCHEMA_VERSION:
            raise ValueError("Unsupported archive schema")
        count_imports = conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
        count_versions = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        latest = list(conn.execute(_latest_clause()))
        origins = {r[0]: r[1] for r in conn.execute("SELECT origin, COUNT(*) FROM imports GROUP BY origin")}
        labels = Counter(r["review_label"] or "unlabeled" for r in latest)
        sources = {r["source_token"] for r in latest if r["source_token"]}
        return {"kind": "local-private-research-archive", "schema": SCHEMA_VERSION,
                "imports": count_imports, "unique_sessions": len(latest), "versions": count_versions,
                "distinct_source_groups": len(sources), "latest_labels": dict(sorted(labels.items())),
                "origin_declarations_by_import": origins,
                "cautions": ["Source identifiers are stable local HMAC pseudonyms, not independently verified people or attackers.",
                             "An origin declaration is not third-party provenance verification.",
                             "This SQLite archive is not tamper-evident, encrypted, or an independent ML benchmark."]}


def archive_export(store_path: str | Path = "data/honeytrace-history.sqlite3",
                   *, output: str | Path = "data/honeytrace-features.csv") -> int:
    """Export latest sanitized feature rows, never raw Cowrie commands or IPs.

    The output still contains linkable opaque identifiers; keep it private.
    """
    store = Path(store_path)
    if not store.is_file():
        raise FileNotFoundError(f"No local archive yet: {store}")
    dest = Path(output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(store)) as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute(_latest_clause() + " ORDER BY o.session_token"))
    cols = ["session_token", "source_token", "observed_day", "fingerprint", "review_label", "event_count", *FEATURES]
    # Exclusive create: do not accidentally discard a curated dataset export.
    with dest.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=cols)
        writer.writeheader()
        for row in rows:
            features = json.loads(row["features_json"])
            writer.writerow({"session_token": row["session_token"], "source_token": row["source_token"],
                             "observed_day": row["observed_day"] or "", "fingerprint": row["fingerprint"],
                             "review_label": row["review_label"], "event_count": row["event_count"],
                             **features})
    return len(rows)


def archive_check(store_path: str | Path = "data/honeytrace-history.sqlite3") -> dict:
    """Read-only SQLite and stored-snapshot consistency checks for schema 1.

    These checks detect many accidental corruptions and some inconsistent edits.
    The archive is NOT tamper-proof: a person with write access can recompute
    unkeyed row digests or replace the database and .key together.
    """
    store = Path(store_path)
    if not store.is_file():
        raise FileNotFoundError(f"No local archive yet: {store}")
    keyfile = _secret_path(store)
    if not keyfile.is_file():
        raise ValueError("Archive key missing; restore the database and .key together")
    key = keyfile.read_bytes()
    if len(key) != 32:
        raise ValueError("Archive key invalid; expected the original 32-byte .key")

    errors: list[str] = []
    checked = 0
    mismatches = 0
    foreign_key_violations = 0
    sqlite_result = "not checked"
    imports = versions = 0
    # Read-only URI prevents an integrity check from creating or mutating a DB.
    with closing(sqlite3.connect(store.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        results = [r[0] for r in conn.execute("PRAGMA integrity_check(10)")]
        sqlite_result = "ok" if results == ["ok"] else "failed"
        if sqlite_result != "ok":
            errors.append("SQLite integrity_check reported structural problems")
        foreign_key_violations = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        if foreign_key_violations:
            errors.append("Orphaned SQLite foreign-key references found")
        metadata = {r["name"]: r["value"] for r in conn.execute("SELECT name, value FROM metadata")}
        if metadata.get("schema") != SCHEMA_VERSION:
            errors.append("Archive schema does not match supported version")
        if metadata.get("key_sha256") != sha256(key).hexdigest():
            errors.append("Archive key does not match the database")
        imports = conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
        versions = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

        for row in conn.execute("""SELECT features_json, indicators_json, fingerprint, review_label,
                                        event_count, observed_day, source_token, snapshot_sha256
                                 FROM observations"""):
            checked += 1
            try:
                features = json.loads(row["features_json"])
                indicators = json.loads(row["indicators_json"])
                if not isinstance(features, dict) or not isinstance(indicators, list):
                    raise ValueError("Invalid feature structure")
                payload = {"feature": features, "indicators": indicators,
                           "fingerprint": row["fingerprint"], "label": row["review_label"],
                           "event_count": row["event_count"], "day": row["observed_day"],
                           "source_token": row["source_token"]}
                digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if not hmac.compare_digest(digest, row["snapshot_sha256"]):
                    mismatches += 1
            except (ValueError, TypeError, KeyError):
                mismatches += 1
        if mismatches:
            errors.append("Stored snapshot hashes do not match stored feature values")
    return {"kind": "local-archive-consistency-check", "ok": not errors,
            "sqlite_integrity": sqlite_result, "foreign_key_violations": foreign_key_violations,
            "versions_checked": checked, "snapshot_mismatches": mismatches,
            "imports": imports, "versions": versions, "errors": errors,
            "caution": "This is a consistency check, not a cryptographic authenticity proof or a substitute for offline backups."}
