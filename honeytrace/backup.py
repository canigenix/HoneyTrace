"""Local recoverable backups of HoneyTrace's SQLite archive and HMAC key.

Uses sqlite3's online backup API for a consistent database image. Backups
include the private pseudonymization key and are NOT ENCRYPTED. Restore only
creates a new archive; it never overwrites an existing database or key.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3

from honeytrace.archive import SCHEMA_VERSION, _secret_path, archive_check

BACKUP_FORMAT = "honeytrace-local-backup-v1"
DB_FILE = "archive.sqlite3"
KEY_FILE = "archive.sqlite3.key"
MANIFEST_FILE = "manifest.json"
DEFAULT_STORE = Path("data/honeytrace-history.sqlite3")


def _digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def _bundle_paths(folder: Path) -> tuple[Path, Path, Path]:
    return folder / DB_FILE, folder / KEY_FILE, folder / MANIFEST_FILE


def _secure_folder(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700, exist_ok=False)


def _read_manifest(folder: Path) -> dict:
    db, key, manifest_path = _bundle_paths(folder)
    for file in (db, key, manifest_path):
        if file.is_symlink() or not file.is_file():
            raise ValueError("Incomplete backup or symlinked backup file")
    if manifest_path.stat().st_size > 16_384:
        raise ValueError("Invalid oversized backup manifest")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("format") != BACKUP_FORMAT or payload.get("schema") != SCHEMA_VERSION:
        raise ValueError("Unsupported backup manifest")
    sha = payload.get("sha256")
    if not isinstance(sha, dict) or set(sha) != {DB_FILE, KEY_FILE}:
        raise ValueError("Invalid backup checksums")
    if any(not isinstance(v, str) or len(v) != 64 or any(c not in "0123456789abcdef" for c in v) for v in sha.values()):
        raise ValueError("Malformed backup checksums")
    return payload


def verify_backup(folder: str | Path) -> dict:
    """Return an aggregate validation result; never reveal stored IDs or values."""
    directory = Path(folder)
    result = {"kind": "honeytrace-backup-verification", "ok": False,
              "checksums_match": False, "archive_consistent": False,
              "errors": [], "caution": "Checksum and SQLite checks are not tamper-proof authenticity proofs; this backup contains a plaintext private key."}
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Backup folder not found or is a symlink")
        manifest = _read_manifest(directory)
        db, key, _ = _bundle_paths(directory)
        if _digest_file(db) != manifest["sha256"][DB_FILE] or _digest_file(key) != manifest["sha256"][KEY_FILE]:
            raise ValueError("Backup file checksum mismatch")
        result["checksums_match"] = True
        check = archive_check(db)
        if not check["ok"]:
            raise ValueError("Archive consistency check failed")
        result["archive_consistent"] = True
        result["ok"] = True
        result["imports"] = check["imports"]
        result["versions"] = check["versions"]
    except (OSError, ValueError, sqlite3.DatabaseError, json.JSONDecodeError) as exc:
        # Don't include arbitrary filesystem/SQL error messages in summaries.
        result["errors"].append(f"Backup verification failed ({type(exc).__name__}); check folder, checksums, key, and SQLite integrity")
    return result


def create_backup(store_path: str | Path = DEFAULT_STORE,
                  *, destination: str | Path | None = None) -> dict:
    """Snapshot a running SQLite database and copy its matching HMAC key.

    Uses exclusive directory creation and never overwrites an old backup.
    Errors clean up only the new, incomplete backup directory.
    """
    store = Path(store_path)
    if not store.is_file() or not _secret_path(store).is_file():
        raise FileNotFoundError("Archive database and its .key must both exist")
    source_check = archive_check(store)
    if not source_check["ok"]:
        raise ValueError("Source archive failed consistency checks; refusing backup")
    if destination is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = Path("data/backups") / f"backup-{stamp}-{secrets.token_hex(4)}"
    folder = Path(destination)
    # Avoid backing up to a path that coincides with either source file's parent.
    _secure_folder(folder)
    db, key, manifest = _bundle_paths(folder)
    try:
        with closing(sqlite3.connect(store.resolve().as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(db)) as target:
                source.backup(target, pages=64, sleep=0.1)
                target.commit()
        shutil.copyfile(_secret_path(store), key)
        if os.name != "nt":
            key.chmod(0o600)
            db.chmod(0o600)
        report = archive_check(db)
        if not report["ok"]:
            raise ValueError("Backup snapshot failed consistency check")
        payload = {
            "format": BACKUP_FORMAT, "schema": SCHEMA_VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "sha256": {DB_FILE: _digest_file(db), KEY_FILE: _digest_file(key)},
            "note": "Contains private pseudonymization key and derived history; unencrypted; keep local and access-controlled",
        }
        manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        verified = verify_backup(folder)
        if not verified["ok"]:
            raise ValueError("New backup did not pass independent verification")
        return {"created": True, "folder": str(folder.resolve()), "verified": True,
                "imports": verified["imports"], "versions": verified["versions"],
                "warning": "Backup is unencrypted. Protect the entire folder, including its .key file."}
    except BaseException:
        shutil.rmtree(folder)
        raise


def restore_backup(folder: str | Path, *, target: str | Path = "data/honeytrace-restored.sqlite3") -> dict:
    """Restore into a NEW path only; never replace an active/existing archive."""
    verification = verify_backup(folder)
    if not verification["ok"]:
        raise ValueError("Backup failed verification; nothing restored")
    destination = Path(target)
    destination_key = _secret_path(destination)
    if destination.exists() or destination_key.exists() or destination.is_symlink() or destination_key.is_symlink():
        raise FileExistsError("Target archive or key already exists; choose a new --target; nothing overwritten")
    destination.parent.mkdir(parents=True, exist_ok=True)
    db, key, _ = _bundle_paths(Path(folder))
    copied: list[Path] = []
    try:
        # 'xb' means no-overwrite even if a separate process races to create it.
        for source, output in ((db, destination), (key, destination_key)):
            with source.open("rb") as reader, output.open("xb") as writer:
                copied.append(output)
                shutil.copyfileobj(reader, writer)
            if os.name != "nt":
                output.chmod(0o600)
        check = archive_check(destination)
        if not check["ok"]:
            raise ValueError("Restored archive failed consistency check")
    except BaseException:
        for created in reversed(copied):
            created.unlink(missing_ok=True)
        raise
    return {"restored": True, "target": str(destination.resolve()),
            "imports": check["imports"], "versions": check["versions"],
            "verified": True, "note": "Restored to a separate archive; existing live database untouched"}
