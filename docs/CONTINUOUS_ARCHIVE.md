# HoneyTrace v0.9 — Continuous Archiving & Integrity Checks

The Cowrie live dashboard and the v0.8 SQLite research archive can now run together **on localhost**. This is opt-in and designed for your own authorized, isolated sensor. No remote API, upload, or external service is required.

## Quick start (Windows PowerShell)

**Keep your existing `data/` folder untouched**; it holds your archived reviewed sessions and `honeytrace-history.sqlite3.key`.

First check your existing archive:

```powershell
py honeytrace.py store-check
py honeytrace.py store-status
```

Then start live monitoring and continuous storage:

```powershell
py honeytrace.py live --archive --archive-origin controlled-lab
```

Open http://127.0.0.1:8765 and look for **Local dataset archive**. The default Docker container is `honeytrace-cowrie`; stop any prior live process first to free port 8765. If you omit `--archive`, the dashboard works as it did in v0.8, without auto-saving.

`controlled-lab` is a declaration suitable **only for your own controlled tests**. For a sensor with unverified traffic, omit `--archive-origin`; it defaults to `unverified`. The origin is **not proof of authenticity**.

For an existing local file without Docker, use:

```powershell
py honeytrace.py live --source file --input data/cowrie.json --archive --archive-origin controlled-lab
```

When the source log changes, HoneyTrace attempts to import derived features into the SQLite file. Identical snapshots do not add sessions, and changed session features produce new versions. A temporary archive failure is displayed separately in the dashboard and automatically retried; it does **not** interrupt reading the live log. Restarts are safe, because the archive checks the content hashes in SQLite.

**Your v0.8 labels are retained:** when automatic importing has no review CSV, the latest reviewed label for each known session is carried forward. To change a label on purpose, use the existing explicit `store-import --labels ...` command. This label propagation keeps the previous *judgment*, not evidence of new or verified intent.

## Integrity check

```powershell
py honeytrace.py store-check
```

This checks SQLite's built-in structural integrity (`PRAGMA integrity_check`), foreign-key references, compatibility of the key and database, and SHA-256 consistency of archived feature snapshots. It reads the archive without modifying it. If a check fails it prints `"ok": false` and exits nonzero.

**Important limitation:** These are consistency/corruption checks, *not cryptographic tamper evidence*. An attacker with access to your database can edit values and recompute the unkeyed snapshot hashes, or replace the database and key together. There is no digital signature or independent trusted checkpoint.

The archive is not encrypted. Save private backups of both:

- `data/honeytrace-history.sqlite3`
- `data/honeytrace-history.sqlite3.key`

If backups were made while HoneyTrace was running, use a SQLite-aware backup rather than blindly copying an open database. Do not commit either file, raw logs, exported features, or manual labels to public GitHub. Avoid connecting the Cowrie honeypot or dashboard to public or LAN interfaces without a separate isolation and risk review.

## What this does not do

- It does not fetch third-party attack data, label unknown attacks, or prove model accuracy.
- It does not run shell commands found in Cowrie logs, and does not collect more source IP diversity automatically.
- It does not archive unbounded log growth: the existing 20 MB per-log safety limit still applies. Use log rotation and carefully planned imports for larger datasets.
- It does not change the v0.6 independent holdout validation requirements.
