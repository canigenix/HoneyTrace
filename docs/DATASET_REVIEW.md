# HoneyTrace v0.7 — Dataset Review & Quality Audit

This workflow gives you a **private manual-review worksheet** and an **aggregate-only dataset audit**. It complements, but does not replace, v0.6's source-disjoint holdout validation.

## Quick start: your existing Cowrie logs

Keep Cowrie and your live dashboard running as before. HoneyTrace Live already copies the current Cowrie JSONL file to `data/cowrie.json`.

In a **separate Windows PowerShell terminal** inside your project:

```powershell
py honeytrace.py audit data/cowrie.json --origin controlled-lab
py honeytrace.py review-queue data/cowrie.json
```

- Read `output/dataset-audit.json` to see aggregate counts, coverage, and limitations.
- Open `data/review-queue.csv` privately in a local text editor or spreadsheet. It starts with **blank** `label` values and has no raw passwords, source addresses, usernames, commands, or ML predictions.
- Inspect the original session timeline and commands in your **local** HoneyTrace dashboard (or a controlled raw-log viewer), then fill `label` with `review` or `background`. Leave uncertain cases blank. The `analyst_note` column is optional.
- Review labels are *operational judgments*, not verified malicious-vs-benign ground truth. A Cowrie login or command is not automatically a positive label, especially in a lab.

Once you've labeled a few sessions, run:

```powershell
py honeytrace.py audit data/cowrie.json --labels data/review-queue.csv --origin controlled-lab
```

The existing within-batch `evaluate` command also accepts the new CSV with extra columns, once enough sessions exist:

```powershell
py honeytrace.py evaluate data/cowrie.json data/review-queue.csv
```

### Important: preserving human labels

The `review-queue` command **refuses to overwrite** an existing CSV. If your Cowrie log has grown and you want a fresh blank worksheet, choose a different output path:

```powershell
py honeytrace.py review-queue data/cowrie.json --output data/review-queue-second.csv
```

Do **not** replace an annotated CSV with a new blank copy. We have not implemented automatic reconciliation between snapshots yet.

## Dataset audit fields

The audit includes:

- `source_sha256`: SHA-256 of the raw input bytes for tracking which log was evaluated. It is **not** a signature of authenticity.
- Parsing acceptance, invalid/skipped rows, and input truncation.
- Number of sessions, unique source addresses (as a **count only**), missing identifiers/timestamps, and observed command totals.
- Number of distinct behavioral fingerprints, as a **count only**.
- Counts of `review`, `background`, and unlabeled sessions, when an analyst CSV is supplied.
- Warnings about source concentration, small sample size, missing data, and unverified provenance.

The JSON report contains **no source addresses, command strings, usernames, or passwords**. Be aware that the *review CSV* still contains session and sensor identifiers, and any notes you add could be sensitive. Keep both private.

`holdout_ready` is **always false in this audit**. A single log—even one with hundreds of sessions or numerous unique IP addresses—cannot prove a valid held-out study. To validate, create separate manually labeled train/test files and run the existing `validate` command with source-disjoint groups and appropriate collection chronology.

## Dataset origins

Specify one of these declarations to document where a file came from:

- `unverified` (default): you have not attested to its provenance.
- `controlled-lab`: your own authorized Cowrie demonstrations.
- `synthetic`: entirely generated data.
- `independent-observations`: data independently obtained with suitable permissions and provenance records.

The origin flag is **your declaration**, not a verification by HoneyTrace.

## Known limitations

- Local Docker tests often share the single source `172.17.0.1`. Four such sessions are enough for the pipeline demo but not meaningful cross-source ML evaluation.
- A fingerprint is an observed pattern, not an identity. Diverse sources can still be related (NAT, proxy, coordinated lab activity).
- Counts and timing extracted from honeypot sessions do not independently establish intent.
- Reviewing only sessions that HoneyTrace alerts on can inflate apparent accuracy. Prefer predetermined, systematic review of a diverse sample, including quiet and unflagged sessions, before scoring.
- Never expose Cowrie to your home LAN or the internet without proper isolation and a considered threat model. Never run attacker-submitted shell commands or downloads from logs.
- `.gitignore` excludes `data/` and `output/`; **always check `git status`** before committing. Do not upload raw logs or your annotated review CSV to public GitHub.

## What comes after this release

Build an append-only local dataset store with privacy controls, collection provenance, reviewer agreement, and leakage-resistant train/test splits. Then acquire suitably diverse *authorized* datasets for independent evaluation, rather than creating many nearly identical localhost sessions to meet the 25-session threshold.
