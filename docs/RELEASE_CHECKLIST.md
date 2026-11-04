# HoneyTrace v1.0.0 — Stable-release acceptance checklist

**Status: awaiting Windows and GitHub Actions acceptance.** Passing synthetic tests is
not a certification of intrusion-detection accuracy or a production deployment.

The earlier `v1.0.0-rc1` tag should remain unchanged. Promote only an audited
commit with passing CI and the checks below; do not force-move the RC tag.

## 1. Clean installation, no existing data

Use a **separate directory** (Git clone or fresh source archive). Do not extract
into or remove your working HoneyTrace data folder for this test.

Windows PowerShell (inside the fresh source directory):

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools/release_smoke.py
```

The last command must report `"ok": true`. It uses disposable synthetic data
in the system temporary directory. It does not start Docker, contact a cloud
service, change your actual archive, or prove real-world ML accuracy.

Linux/macOS: substitute `python3` and `.venv/bin/python`.

## 2. GitHub Actions and dependency checks

Confirm **all** checks are green on the final commit and tag:

- Ubuntu: Python 3.11, 3.12, 3.13, and 3.14.
- Windows: Python 3.14 (the main user environment).
- Each: unit tests and disposable end-to-end smoke test.
- Dependency vulnerability audit (`pip-audit`), with failures investigated
  rather than ignored; weekly Dependabot updates enabled.

No CI platform has yet been independently attested as passing by this document.
Check the repository's *Actions* tab for actual results before promotion.

## 3. Existing local installation & recovery drill

On the **existing** Windows installation (where `data/` contains private logs,
SQLite history, and a pseudonymization `.key` file), in a different terminal
from your running HoneyTrace monitor:

```powershell
py honeytrace.py store-check
py honeytrace.py store-backup --destination data/backups/stable-candidate
py honeytrace.py store-verify-backup data/backups/stable-candidate
py honeytrace.py store-restore data/backups/stable-candidate --target data/stable-restore-check.sqlite3
py honeytrace.py store-check --store data/stable-restore-check.sqlite3
```

Pick unused backup and restore paths. The CLI intentionally refuses to overwrite
existing targets. Confirm record counts agree and that the original archive was
not changed. Copy a **protected/encrypted** backup off-device as a separate step;
these backups contain the unencrypted private key. The backup does not include
raw Cowrie logs or analyst CSVs; protect those separately.

## 4. Localhost security checks

- `python tools/release_smoke.py` must confirm loopback API access and rejection
  of an untrusted Host header.
- Cowrie test service and HoneyTrace dashboard must bind to `127.0.0.1` only,
  unless a separate isolated honeypot deployment has been designed.
- Do not port-forward, proxy, or expose the unauthenticated dashboard to a LAN.
- Check `git status --short` and staged filenames before commit: **never** add
  `data/`, `output/`, keys, CSV labels, raw JSONL logs, or backup directories.
- Ensure file-upload/payload events stay unexecuted; they're observation data.

## 5. Release decision and labeling

Mark as **stable local research tooling** only if clean install, tests,
recovery, and security checks are all successful. Do **not** describe the
Isolation Forest as independently validated, production-ready detection,
attacker attribution, or a calibrated attack-probability model.

After the final code is pushed and checks pass:

```powershell
git status --short
git tag -a v1.0.0 -m "HoneyTrace v1.0.0 local research release"
git push origin v1.0.0
```

Then publish a GitHub Release for tag `v1.0.0`, attaching a source archive or
release bundle and the limitations from the final release notes. A tag alone is
not a GitHub Release. Do not create or push the stable tag until checks pass.
