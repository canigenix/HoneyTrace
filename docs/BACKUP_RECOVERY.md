# HoneyTrace v1.0 release candidate — Backup and recovery

**Scope:** local, privacy-minimized SQLite dataset archives. This is **not** a
backup of the original Cowrie JSONL log, your review CSV, or the entire computer.
It is also **not** a cryptographically authenticated evidence chain.

## Backup the archive (Windows CMD or PowerShell)

Run inside the project directory, **outside the fake Cowrie SSH shell**:

```powershell
py honeytrace.py store-check
py honeytrace.py store-backup --destination data/backups/manual-01
py honeytrace.py store-verify-backup data/backups/manual-01
```

Pick a **new** destination folder on every run; old backups are never overwritten.
Use `py honeytrace.py store-backup` without a destination for an automatically
named folder under `data/backups/`. A valid backup directory has three files:

- `archive.sqlite3` — a consistent SQLite snapshot created with the SQLite backup API, including committed activity while live monitoring runs;
- `archive.sqlite3.key` — the original private 32-byte HMAC pseudonymization key;
- `manifest.json` — creation time and SHA-256 checksums for accidental damage detection.

The source archive and key are never modified during backup. A backup fails closed
if the source or the generated snapshot fails archive integrity checks. A backup
folder already present is left unchanged, even if incomplete.

## Verify recovery without touching the live archive

```powershell
py honeytrace.py store-restore data/backups/manual-01 --target data/recovery-check.sqlite3
py honeytrace.py store-check --store data/recovery-check.sqlite3
py honeytrace.py store-status --store data/recovery-check.sqlite3
```

The restored database and `data/recovery-check.sqlite3.key` form a **separate
archive**. These commands refuse to overwrite either existing target file.
Choose another new target path to repeat this check.

## Recover after data loss

1. **Stop HoneyTrace Live** using Ctrl+C; close any programs using the archive.
2. Preserve/move aside **both** existing `data/honeytrace-history.sqlite3` and
   `data/honeytrace-history.sqlite3.key`, if present. Do not delete your last
   recoverable copies. When both original paths are absent, use:

   ```powershell
   py honeytrace.py store-restore data/backups/manual-01 --target data/honeytrace-history.sqlite3
   py honeytrace.py store-check
   ```

3. Restart monitoring with the same command as before:
   `py honeytrace.py live --archive --archive-origin controlled-lab`.

The restore operation intentionally never has a force/replace option. It cannot
silently replace a running database. SQLite restores preserve reviewed labels,
versions and pseudonymization tokens because the database and its original key
are restored together. They **do not** recover source logs or CSVs you did not
separately back up.

## Optional periodic backups during live monitoring

```powershell
py honeytrace.py live --archive --archive-origin controlled-lab --backup-hours 24
```

The first verified backup occurs after a successful archive import, then no
more often than every 24 hours **while the live process is running**. It is
not an operating-system scheduler, and no backups occur when HoneyTrace is off.
Use `--backup-dir data/backups` to choose another directory. `--backup-hours 0`
(disabled) is the default; allowed enabled values are 1–168. Backup errors are
reported separately from monitoring; they are retried later, without stopping
the dashboard. Stopping/restarting Live restarts its in-memory backup timer.

**No automatic retention/deletion:** the number of backups grows over time.
Monitor free disk space and decide manually what to keep after verifying a
second recoverable copy. Do not delete the last good backup.

## Security, privacy, and limitations

- **Backups are unencrypted.** They include the HMAC secret and linkable,
  pseudonymized research data. The key is essential for consistent source IDs.
  Protect the backup directory with Windows filesystem permissions and secure,
  encrypted offline/off-device storage. A copy on the same disk does **not**
  protect against loss of the physical disk.
- `data/` (including `data/backups/`) is Git-ignored. Never commit, attach to an
  issue, or publicly upload your database, key, Cowrie logs or manual labels.
- A matching SHA-256 manifest and SQLite integrity result detect accidental
  damage, **not malicious tampering**. Someone who can modify the backup and
  manifest can recompute checksums.
- Restore is **not** a disaster-recovery guarantee. Test a fresh restore before
  relying on backup automation. Store backups independently of the laptop.
- The ML detector still needs source-disjoint, independently reviewed real
  observations. Backup checks do not establish detection accuracy.
