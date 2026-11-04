# HoneyTrace v0.8 — Local Dataset History

**Purpose:** Preserve *privacy-minimized, versioned summaries* of Cowrie sessions for later ML experiments. Nothing is sent to a server. The existing `live`, `audit`, `review-queue`, `validate`, and `demo` commands remain available.

## Use it with your existing controlled lab

From **Windows PowerShell in your HoneyTrace project folder**:

```powershell
py -m unittest discover -s tests -v
py honeytrace.py store-import data/cowrie.json --labels data/review-queue.csv --origin controlled-lab
py honeytrace.py store-status
```

Your first import should report **4 input sessions and 4 new stored versions** if your log and review worksheet still contain the same four sessions. If the Cowrie log has grown since you last labeled it, the review CSV may still be valid for those four entries; other sessions will be stored unlabeled. Run the import command again unchanged and it should report **0 new versions** / **Already imported: True**.

To capture a later state of the same session or new sessions, run `store-import` again after the log file grows. If you use a different review-queue CSV, pass that filename. A changed summary or manual label produces a new version; existing versions are never overwritten by the CLI.

To create a private feature table for future experiments:

```powershell
py honeytrace.py store-export
```

This creates `data/honeytrace-features.csv` with one *latest* row per session. It refuses to overwrite an existing export. Rename or move your old export before creating a new one.

## What is stored

- A local SQLite database: `data/honeytrace-history.sqlite3`
- An **essential 32-byte HMAC key**, created once: `data/honeytrace-history.sqlite3.key`
- The SHA-256 of each imported source log and optional label file, date imported, analyst-declared origin, and aggregate quality counts
- An append-only history of HMAC-pseudonymized session, sensor and source identifiers, day-resolution date, numerical behavior features, behavior indicators, deterministic fingerprint, analyst review label and event count

**Never delete or regenerate the `.key` file while preserving the database.** A key loss means future imports cannot safely link to the previous pseudonyms. Back up the **database and key together** to a secured location. The key protects the pseudonymization scheme; the SQLite database and key are **not encrypted at rest**. Keep both private.

Raw Cowrie JSON lines, passwords, usernames, source IPs, command text, and `analyst_note` **are not inserted** into this store. Your separate existing `data/cowrie.json` is still a raw log, so protect it too. The export contains stable linkable pseudonyms: do not upload it or the archive to public GitHub, and treat source groups as pseudonyms, **not verified distinct actors**.

## Research limits and provenance

- `--origin` accepts `unverified`, `controlled-lab`, `synthetic`, or `independent-observations`. This is your **declaration**, not independently verified provenance.
- The import SHA-256 is an ordinary file checksum. The archive is **not** an authenticated chain of custody, tamper-proof evidence store, or encrypted database.
- Session versions are snapshots of derived features. New raw command arguments alone may not change the derived snapshot; that is deliberate privacy minimization.
- `store-status` reports aggregates only. `store-export` emits pseudonymized feature rows with day-resolution dates, not raw events. Its output is **not** a ready-to-train ground-truth dataset.
- Missing or single source-group data and few sessions are still inadequate for reliable cross-source ML validation. Use v0.6's source-disjoint `validate` workflow only when you have ethically sourced, independently reviewed data.
- Imports are manual in v0.8, not linked to the live polling loop. There is no background archive writer.
- Files in `data/` are ignored by Git; confirm `git status` before every public push, and don't use `git add -f data/`.

## Operational cautions

- Imports are transactional for archive rows, and a repeated identical source-log/labels pair is skipped. Do not edit the database directly.
- The default import limit is 20 MB per source file (plus the existing event/parser limits). Rotate/archive larger logs or split them intentionally.
- Keep your local Cowrie Docker container and HoneyTrace Live bound to `127.0.0.1`; do not open ports to the home LAN or public internet.
- Future versions can add analyst agreement tracking, chronology validation, and source-group splits. v0.8 does **not** assert that it has solved these research problems.
