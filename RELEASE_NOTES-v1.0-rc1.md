# HoneyTrace v1.0 RC1 — Release notes

**Status:** local release candidate; not yet a stable production or public-facing service.

## New

- Verified manual backups of the privacy-minimized SQLite archive and matching
  local HMAC key (`store-backup`, `store-verify-backup`). Uses SQLite's online
  backup API so committed writes are captured consistently.
- Safe restore to **new locations only**, with post-restore consistency checks
  (`store-restore`). Never silently overwrites the active archive.
- Optional periodic verified backup while HoneyTrace Live runs (`--backup-hours
  24`), with an independent error indicator in the local dashboard. Periodic
  backups are disabled unless explicitly requested and no automatic deletion
  is performed.
- Security documentation describing unencrypted keys, private local storage,
  disaster recovery, and checksums' limitations.

## Compatibility

- Retains archive schema `1`; no database migration required from v0.9.
- Existing `demo`, `analyze`, `live`, `labels`, `evaluate`, `validate`, `audit`,
  `review-queue`, `store-import`, `store-status`, `store-check`, and `store-export`
  commands remain available.
- Backup files **are not encrypted** and must not be committed to GitHub.
- The 25-session minimum for batch Isolation Forest is unchanged; no real-world
  ML accuracy claims are made.

## Known limitations

- Backup cadence applies only while the live process runs; not a Windows Task
  Scheduler task or always-on service. Backups accumulate until manually
  managed.
- A matching checksum is not proof of origin or malicious tamper resistance.
- Backups cover derived SQLite data, **not** raw Cowrie logs or review CSV files.
- The localhost dashboard remains unauthenticated; avoid port forwarding.
- Independent real-world, source-disjoint ML validation remains future work.

Tested in an isolated local Python environment; final release awaits testing
with an actual user's existing v0.9 Windows installation and recovery exercise.
