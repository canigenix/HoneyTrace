# HoneyTrace — Honeypot Intelligence (v0.4)

A local-first, CPU-friendly tool for analyzing Cowrie SSH/Telnet honeypot JSON logs. It combines **transparent behavioral indicators** and **Isolation Forest anomaly detection** with a standalone, offline HTML dashboard. No cloud service, GPU, external API, or public port is required.

> **Important:** Behavior *labels* are rule based. Machine learning detects *relative anomalies*, not proven malicious intent or attacker identity. Heuristic risk scores are not probabilities. Synthetic demo outcomes do not establish production accuracy.

## Start in 3 steps (Windows PowerShell)

Use Python 3.11+ and open a terminal inside this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe honeytrace.py demo
```

Open `output/report.html` in your browser (double-click). Works offline, on CPU, and produces `output/analysis.json` as well.

macOS/Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python honeytrace.py demo
```

## Analyze real Cowrie logs

Cowrie records events to `var/log/cowrie/cowrie.json` when JSON output is enabled. Copy the JSONL file into this project (for example, `data/cowrie.json`) and run:

```powershell
.\.venv\Scripts\python.exe honeytrace.py analyze data/cowrie.json
```

The dashboard/report overwrite the prior report on each run. Keep the source log private; honeypot logs may contain real IPs, usernames, typed commands, and credentials. This program **does not include passwords in the report**; still treat logs and reports as sensitive. Do not open untrusted `output/report.html` from unknown senders.

### Optional: local-only Cowrie trial with Docker Desktop

Run Cowrie **only on loopback**, not a public interface:

```powershell
docker run -d --name honeytrace-cowrie -p 127.0.0.1:2222:2222 cowrie/cowrie:latest
```

In another terminal, initiate an SSH connection: `ssh -p 2222 root@127.0.0.1`. Use test credentials only, then leave the session. Copy the captured JSON file (container layout may change by image version):

```powershell
docker cp honeytrace-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json data/cowrie.json
.\.venv\Scripts\python.exe honeytrace.py analyze data/cowrie.json
```

You can check the path with `docker exec honeytrace-cowrie pwd` or `docker logs honeytrace-cowrie` (the minimal image may not include `find`) if needed. To stop: `docker stop honeytrace-cowrie`; to delete container: `docker rm honeytrace-cowrie`.

**Security:** Local-only binding is not a complete security boundary. Use a dedicated VM or host, isolated from your home LAN; do not expose to the public internet or forward ports until properly isolated and hardened. Do not execute anything captured by a honeypot. File-download events are analyzed from metadata only—HoneyTrace does not fetch or run files.

## Detection logic

- Behaviors: credential guessing (>= 3 failures), system reconnaissance, payload-delivery indicators, persistence indicators, privilege exploration, suspicious/encoded execution, destructive-command indicators, and exploit event indicators.
- Isolation Forest (scikit-learn) uses 13 per-session behavioral features with log-scaled counts and standardized inputs. It only runs with >= 25 sessions. A fixed 8% `contamination` makes the flag rate a chosen threshold, **not an estimated attack prevalence**.
- The "ML anomaly percentile" is the session's *relative unusualness* in the supplied batch, **not confidence**. All events reaching a honeypot are worth review; an unflagged event is not necessarily safe.
- Unmatched sessions are "Unclassified interaction", **not** "legitimate" or "benign".

## Safety and privacy

- Offline analysis starts no listener. Optional live mode serves an HTTP dashboard bound to 127.0.0.1 only.
- Untrusted JSON log entries are parsed, never executed. The HTML viewer renders attacker-controlled fields as text, not executable HTML.
- Synthetic demo addresses are drawn exclusively from IANA TEST-NET ranges and demo URLs from the reserved `.invalid` domain.
- Inputs are limited to 250,000 accepted events and 128 KB per line as basic safeguards. Large data should eventually use a streaming database pipeline.

## Test

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Next milestones

1. Collect labeled real-world sessions (ethically and with permissions) and quantify false positives.
2. Train/evaluate a supervised multi-label classifier using held-out source groups and time slices.
3. Add incremental ingestion, alerting and behavioral clustering without ever exposing the dashboard publicly by default.

Not affiliated with Cowrie or StingBox. Cowrie documentation: https://docs.cowrie.org/ .

## Live monitoring (v0.3)

**No manually copying logs or refreshing the browser.** This mode uses the existing
Cowrie Docker container, analyzes changed JSON logs, and serves a read-only local
HTTP dashboard that refreshes every 3 seconds.

From **Windows PowerShell in the HoneyTrace project directory**, with Docker Desktop
running and `honeytrace-cowrie` started:

```powershell
py honeytrace.py live
```

Open **http://127.0.0.1:8765** in your browser. In another terminal, test your
localhost honeypot with `ssh -p 2222 root@127.0.0.1`. Return to the dashboard
to view new commands, behavioral labels, and alerts. Stop with **Ctrl+C**.

By default, HoneyTrace copies Cowrie's log **every 5 seconds**, then analyzes it
*only when changed*. Use `--interval 10` to poll every 10 seconds. The app binds
**only to 127.0.0.1**, does not open any public ports, and does not execute or
fetch captured command content. Browser alerts appear as in-dashboard indicators;
no email, push, or system notifications are sent.

To monitor an existing local JSONL file instead of Docker:

```powershell
py honeytrace.py live --source file --input data/cowrie.json
```

The live mode imposes a **20 MB log limit** as a safeguard. Rotate or archive
larger Cowrie logs before running it. Each refresh reanalyzes the full log;
large-scale ingestion and supervised attack-type ML remain future work.

The dashboard is **not authenticated** because it only listens on localhost;
other processes or users on the same computer may be able to access it. Never
port-forward or reverse-proxy the live dashboard. Honeypot logs can contain
credentials and identifying information, so do not commit `data/` or `output/`
files to GitHub. The browser shows selected command excerpts but does not show
captured login passwords. ML remains inactive until 25 sessions are available.

## Attacker intelligence (v0.4)

Both `analyze` and `live` now generate **session timelines** (connection, login
results, shell commands, transfers, disconnects) and **deterministic behavioral
fingerprints** based on command names, behavioral labels, and coarse login
patterns. The live dashboard displays recurring patterns and lets you filter
sessions by fingerprint. The offline report includes timelines and fingerprints.

Fingerprints intentionally exclude source IPs, usernames, passwords, command
arguments, and timestamps. **They are not attacker IDs, evidence of coordination,
ML predictions, or proof of compromise.** Similar sessions may belong to
unrelated people or test scripts. They are meant to help a human investigator.
Timelines show command input and should be handled as potentially sensitive.
A per-session timeline is capped at 80 displayed events, and only the top 20
recurring fingerprint groups are summarized. No external network ports are
opened, and no captured commands are executed.

### Local upgrade from v0.3

Stop the running HoneyTrace live server with **Ctrl+C**. Copy the v0.4 update
files into the same project folder as `honeytrace.py`, allowing existing files
to be overwritten but **preserving `.git/`, `data/`, and `output/`**.

From a Windows PowerShell or CMD terminal inside that folder:

```powershell
py -m unittest discover -s tests -v
py honeytrace.py live
```

Open http://127.0.0.1:8765. You can test fingerprint grouping with two
similar localhost SSH sessions using `whoami`, `uname -a`, and `hostname`.
The existing Cowrie container name (`honeytrace-cowrie`) and Docker settings
are unchanged. Do not port-forward the honeypot or the dashboard.


## ML Intelligence (v0.5)

**Live dashboard:** `py honeytrace.py live` now shows *ML behavioral clusters* and
*anomaly feature contrasts* alongside the v0.4 deterministic fingerprints and
timelines. The live server still binds only to `127.0.0.1` and uses the existing
Cowrie Docker container. No additional third-party dependencies are needed.

- **DBSCAN clusters** compare fixed, log-scaled command, authentication, transfer,
  and session-duration features. They can group *similar but not identical*
  sessions. A session can remain unclustered (noise). IDs such as `C001` are
  only meaningful within one analyzed batch; they are not stable attacker IDs.
  Cluster membership is exploratory, not an independent identity or threat
  assessment. Clustering operates on batches of 2–2000 sessions to limit
  DBSCAN resource use; at least two similar sessions are needed.
- **Isolation Forest feature contrasts** are displayed only for flagged sessions,
  after at least **25 sessions** are present. Contrasts highlight differences
  against the loaded batch's feature medians. They are **not** true Isolation
  Forest feature-attribution explanations or calibrated probabilities.
- **Manual label evaluation** helps develop a disciplined research workflow.
  A CSV labels sessions as `review` (analyst wants to investigate) or
  `background` (expected test/background interaction); an empty label is ignored.
  These labels do not prove real-world maliciousness.

### Optional: evaluate with manually labeled sessions

When you have 25 or more diverse sessions, use a **local** Cowrie JSONL file:

```powershell
py honeytrace.py labels data/cowrie.json --output data/session_labels.csv
```

Inspect each session in the dashboard and fill the `label` column with `review`
or `background` using a text editor or spreadsheet. The template command
refuses to overwrite an existing label file. **Do not upload this file
or your source logs to GitHub.** Then run:

```powershell
py honeytrace.py evaluate data/cowrie.json data/session_labels.csv
```

Results are written to `output/evaluation.json` with precision, recall, F1,
false-positive rate, counts, and missing-label coverage. Undefined metrics
are `null`, not zero. Evaluation uses a model fitted to the *same batch* it
scores and is only a **within-batch diagnostic**, not an independent holdout
validation or measured production detection accuracy. Anomaly flags are
unsupervised and may not align with an analyst's `review` labels.

**Security/privacy:** Only copy your own authorized Cowrie logs into `data/`.
The `.gitignore` excludes logs, manual CSV labels, and generated reports.
Sessions and command excerpts can still be sensitive; keep them local.

## Holdout ML validation (v0.6)

The new **Validation Lab** evaluates an independent, frozen anomaly model on
manually labeled sessions from *different source groups*, and compares it with
HoneyTrace's fixed rule-score baseline. It produces aggregate-only JSON and HTML
reports with confusion matrices, precision, recall, F1, false-positive rate,
and uncertainty intervals. It does not change the live dashboard's model.

For an entirely synthetic first run:

```powershell
py honeytrace.py validate-demo
start .\output\demo-holdout-validation.html
```

For your own labeled, source-disjoint logs:

```powershell
py honeytrace.py validate data/train.jsonl data/train_labels.csv data/test.jsonl data/test_labels.csv
```

**Read [docs/VALIDATION.md](docs/VALIDATION.md) before interpreting scores.**
You need at least 25 independently labeled background training sessions, and
sessions from different source IP groups for testing. Your current small
localhost Cowrie sample is insufficient. Demo metrics are not claims of accuracy.

## Dataset review and quality audit (v0.7)

HoneyTrace now supports **private review worksheets** and **aggregate-only dataset audits**. This helps you assess whether your captured Cowrie sessions are suitable for ML experiments without mistaking localhost demonstrations for independent attack data.

From a second Windows PowerShell terminal while your existing monitor runs:

```powershell
py honeytrace.py audit data/cowrie.json --origin controlled-lab
py honeytrace.py review-queue data/cowrie.json
```

The audit writes `output/dataset-audit.json` with aggregate quality metrics and warnings. The worksheet writes `data/review-queue.csv` with blank `review` / `background` labels for manual inspection. These labels must be assigned by a human; HoneyTrace does not silently turn heuristics into ground truth. Both files are excluded from Git by the existing ignore rules, but still check before publishing. The worksheet refuses to overwrite an existing file.

After manually reviewing sessions using your local dashboard or source logs:

```powershell
py honeytrace.py audit data/cowrie.json --labels data/review-queue.csv --origin controlled-lab
```

**This is not ML accuracy validation.** Your localhost sessions share a Docker source address and do not establish source-disjoint generalization. Read [docs/DATASET_REVIEW.md](docs/DATASET_REVIEW.md) for privacy, review guidance, and limitations. Use `py honeytrace.py validate ...` for separate labeled holdout datasets when you have them.

## Local session archive (v0.8)

A new **opt-in, append-only local SQLite archive** stores versioned, pseudonymized
session features, manual review labels, and checksum-based import history.
Raw Cowrie commands, usernames, passwords and source IPs are not stored in the
archive. The database and its essential HMAC key are created under `data/`.

```powershell
py honeytrace.py store-import data/cowrie.json --labels data/review-queue.csv --origin controlled-lab
py honeytrace.py store-status
py honeytrace.py store-export
```

`store-import` skips repeated identical snapshots and adds new versions when
observed features or reviewed labels change. Imports are **manual**, not yet
performed by the live poller. `store-export` creates a private features CSV;
keep it out of public GitHub. **Back up the database and `.key` together.**
A source-group pseudonym, dataset checksum, or origin declaration does not
prove real attacker identity or valid ML evaluation provenance.

For instructions and limitations, see [docs/ARCHIVE.md](docs/ARCHIVE.md).

## Continuous local archiving & integrity checks (v0.9)

HoneyTrace Live can now **optionally** archive derived Cowrie session features
and their revisions directly into the existing v0.8 SQLite database. It
preserves existing human review labels when importing changed sessions without
an explicit CSV, deduplicates unchanged snapshots, and keeps archive errors
separate from live monitoring. Everything remains local-only.

```powershell
py honeytrace.py store-check
py honeytrace.py live --archive --archive-origin controlled-lab
```

The origin shown is self-declared, not verified. Omit `--archive-origin` for
unverified sensor traffic. Without `--archive`, live monitoring behaves as
before. On the dashboard, see **Local dataset archive** for status and warnings.
The `store-check` command performs SQLite structural, foreign-key, key-binding,
and row-hash consistency checks without changing the database; **it is not
cryptographic tamper detection**, encryption, or proof of accuracy.

Read **[docs/CONTINUOUS_ARCHIVE.md](docs/CONTINUOUS_ARCHIVE.md)** before
interpreting results or making backups. Never upload your `data/` folder,
manual labels, raw logs, SQLite file, or `.key` to the public repository.
