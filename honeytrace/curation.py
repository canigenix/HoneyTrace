"""Private review worksheet and aggregate dataset quality auditing for Cowrie.

Never publishes source IPs, passwords, raw command text, or user names.
A review worksheet is not a ground-truth dataset until an analyst labels it.
"""
from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from honeytrace.analyzer import analyze_events, load_events, parse_time
from honeytrace.validation import _read_labels

MAX_REVIEW_SESSIONS = 20_000
REVIEW_COLUMNS = (
    "sensor", "session", "label", "analyst_note", "first_seen_utc",
    "login_failures", "login_successes", "command_count", "file_transfers",
)


def _safe_id(value: object, field: str) -> str:
    """Reject spreadsheet-formula prefixes, separators, controls and excess length."""
    identifier = str(value)
    if (not identifier or len(identifier) > 240 or identifier.lstrip().startswith(("=", "+", "-", "@"))
            or any(ord(char) < 32 or ord(char) == 127 for char in identifier)):
        raise ValueError(f"Unsafe {field} identifier for CSV review export")
    return identifier


def export_review_queue(result: dict[str, Any], output: str | Path) -> int:
    """Write one blank analyst worksheet; exclusive creation prevents lost labels.

    Extra columns are compatible with the existing labels/evaluate/validate commands
    which read only sensor/session/label. No inferred labels or risk are shown in
    the worksheet, reducing avoidable reviewer priming.
    """
    rows = sorted(result["sessions"], key=lambda row: (row["sensor"], row["session"]))
    if len(rows) > MAX_REVIEW_SESSIONS:
        raise ValueError("Review queue exceeds 20,000 sessions; split collection into batches")
    cleaned = []
    for row in rows:
        sensor = _safe_id(row["sensor"], "sensor")
        session = _safe_id(row["session"], "session")
        dt = parse_time(row.get("start", ""))
        features = row["features"]
        cleaned.append({
            "sensor": sensor, "session": session, "label": "", "analyst_note": "",
            "first_seen_utc": dt.isoformat() if dt else "",
            "login_failures": features["login_failures"],
            "login_successes": features["login_successes"],
            "command_count": features["command_count"],
            "file_transfers": features["file_transfers"],
        })
    dest = Path(output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(cleaned)
    return len(cleaned)


def audit_dataset(
    source: str | Path,
    labels: str | Path | None = None,
    *, origin: str = "unverified",
) -> dict[str, Any]:
    """Calculate aggregate-only quality indicators and honest limitations.

    No inference from source IP into a claimed independent threat dataset.
    The source hash identifies the input *bytes* for reproducibility; it is not
    an authentication signature or a privacy-preserving data release.
    """
    if origin not in {"unverified", "controlled-lab", "synthetic", "independent-observations"}:
        raise ValueError("Unknown dataset origin")
    path = Path(source)
    events, parse_stats = load_events(path)
    result = analyze_events(events, enable_ml=False)
    sessions = result["sessions"]
    source_counts = Counter(row["src_ip"] for row in sessions if row["src_ip"])
    missing_source = sum(not row["src_ip"] for row in sessions)
    missing_start = sum(row["start"] == "Unknown" for row in sessions)
    commands = sum(row["features"]["command_count"] for row in sessions)
    with_commands = sum(row["features"]["command_count"] > 0 for row in sessions)
    unique_fingerprints = len({row["fingerprint"] for row in sessions})

    # Work with aggregates only. Never emit raw addresses, commands, labels by ID,
    # or human-entered analyst notes in an audit artifact.
    label_counts = {"review": 0, "background": 0, "unlabeled": len(sessions)}
    if labels is not None:
        reviewed = _read_labels(Path(labels), sessions)
        label_counts = {
            "review": sum(x == "review" for x in reviewed.values()),
            "background": sum(x == "background" for x in reviewed.values()),
            "unlabeled": len(sessions) - len(reviewed),
        }
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    warnings = []
    if len(sessions) < 25:
        warnings.append("Fewer than 25 sessions: insufficient even for HoneyTrace's batch anomaly threshold")
    if len(source_counts) <= 1:
        warnings.append("Zero or one distinct source IP: local Docker traffic cannot demonstrate cross-source generalization")
    if missing_source:
        warnings.append(f"{missing_source} sessions lack source IP; source-disjoint holdout cannot include them")
    if missing_start:
        warnings.append(f"{missing_start} sessions lack usable timestamps; time-forward checks may be incomplete")
    if parse_stats["invalid"] or parse_stats["skipped"] or parse_stats["truncated"]:
        warnings.append("Log parser skipped, rejected or truncated events; inspect parse statistics")
    if labels is None:
        warnings.append("No analyst label CSV supplied; classification accuracy cannot be calculated")
    elif label_counts["unlabeled"]:
        warnings.append("Some sessions have no analyst label; results may be subject to selection bias")
    if origin in ("unverified", "synthetic", "controlled-lab"):
        warnings.append("Dataset is not independently established real-world attack traffic")
    if len(source_counts) >= 2:
        warnings.append("Multiple sources alone do not establish independence; check shared infrastructure and collection dates")
    return {
        "version": "0.7.0",
        "kind": "aggregate-dataset-quality-audit",
        "origin_declaration": origin,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_sha256": digest.hexdigest(),
        "parse": parse_stats,
        "quality": {
            "accepted_events": len(events),
            "sessions": len(sessions),
            "distinct_source_ips": len(source_counts),
            "largest_source_share": round(max(source_counts.values()) / len(sessions), 4) if sessions and source_counts else None,
            "missing_source_ip_sessions": missing_source,
            "missing_timestamp_sessions": missing_start,
            "sessions_with_commands": with_commands,
            "total_commands": commands,
            "distinct_behavior_fingerprints": unique_fingerprints,
            "labels": label_counts,
        },
        "holdout_ready": False,
        "holdout_note": "A single-log audit never proves held-out readiness. Use separate labeled source-disjoint train/test inputs with the validate command.",
        "warnings": warnings,
    }
