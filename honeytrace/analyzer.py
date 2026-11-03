"""Cowrie log parsing, explainable behavioral rules, and ML anomaly ranking.

The rules assign behavioral *indicators*, not proven attribution or intent.
Isolation Forest ranks unusual sessions relative to the supplied dataset.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import bisect
import json
import math
import re

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


MAX_EVENTS = 250_000
MAX_LINE_BYTES = 128_000
MIN_ML_SESSIONS = 25

# Intentionally simple, auditable detectors. False positives are expected.
RECON = re.compile(r"\b(?:uname|whoami|id|hostname|ifconfig|ip\s+addr|ip\s+route|netstat|ss\s+-|ps\s+aux|ls\s|cat\s+/etc/(?:passwd|os-release)|pwd\b|lscpu)\b", re.I)
DELIVERY = re.compile(r"\b(?:wget|curl|tftp|ftpget|scp)\b", re.I)
PERSISTENCE = re.compile(r"(?:\bcrontab\b|/etc/cron\b|authorized_keys|\bsystemctl\s+enable\b|/etc/rc\.local)", re.I)
DESTRUCTIVE = re.compile(r"(?:\brm\s+-rf\b|\bmkfs(?:\.[a-z0-9]+)?\b|\bdd\s+if=\b|\bshred\b)", re.I)
PRIV_ESC = re.compile(r"(?:\bsudo\s+-l\b|/etc/shadow|\bfind\s+/.*-perm\b|\bgetcap\b)", re.I)
OBFUSCATION = re.compile(r"(?:\bbase64\s+(?:-d|--decode)\b|\b(?:bash|python3?|perl)\s+-c\b|\beval\s+\$)", re.I)

FEATURES = (
    "login_failures", "login_successes", "command_count", "unique_commands",
    "recon_commands", "delivery_commands", "persistence_commands",
    "destructive_commands", "privilege_commands", "obfuscated_commands",
    "file_transfers", "exploit_indicators", "duration_seconds",
)


def parse_time(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def load_events(path: str | Path) -> tuple[list[dict], dict]:
    """Read untrusted JSONL without executing any content. Ignore malformed entries."""
    events: list[dict] = []
    stats = {"lines": 0, "invalid": 0, "skipped": 0, "truncated": False}
    with Path(path).open("rb") as file:
        for line in file:
            stats["lines"] += 1
            if len(events) >= MAX_EVENTS:
                stats["truncated"] = True
                break
            if len(line) > MAX_LINE_BYTES:
                stats["invalid"] += 1
                continue
            try:
                obj = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                stats["invalid"] += 1
                continue
            if not isinstance(obj, dict) or not isinstance(obj.get("session"), str) or not isinstance(obj.get("eventid"), str):
                stats["skipped"] += 1
                continue
            if not obj["session"].strip() or not obj["eventid"].startswith("cowrie."):
                stats["skipped"] += 1
                continue
            events.append(obj)
    return events, stats


def _match(pattern: re.Pattern, command: str) -> bool:
    return bool(pattern.search(command))


def _safe(value: object, limit: int = 240) -> str:
    return str(value or "")[:limit]


def _session_row(key: tuple[str, str], events: list[dict]) -> dict:
    events.sort(key=lambda event: _safe(event.get("timestamp")))
    first = events[0]
    commands = [_safe(e.get("input"), 400) for e in events if e.get("eventid") == "cowrie.command.input"]
    names = [str(e.get("eventid")) for e in events]
    times = [parse_time(e.get("timestamp", "")) for e in events]
    times = [t for t in times if t is not None]
    start = min(times) if times else None
    end = max(times) if times else None
    duration = max(0.0, (end - start).total_seconds()) if start and end else 0.0
    for event in events:
        if event.get("eventid") == "cowrie.session.closed":
            try:
                duration = max(duration, float(event.get("duration_ms", 0)) / 1000.0)
            except (ValueError, TypeError):
                pass
    feature = {
        "login_failures": names.count("cowrie.login.failed"),
        "login_successes": names.count("cowrie.login.success"),
        "command_count": len(commands),
        "unique_commands": len(set(commands)),
        "recon_commands": sum(_match(RECON, c) for c in commands),
        "delivery_commands": sum(_match(DELIVERY, c) for c in commands),
        "persistence_commands": sum(_match(PERSISTENCE, c) for c in commands),
        "destructive_commands": sum(_match(DESTRUCTIVE, c) for c in commands),
        "privilege_commands": sum(_match(PRIV_ESC, c) for c in commands),
        "obfuscated_commands": sum(_match(OBFUSCATION, c) for c in commands),
        "file_transfers": sum(n in {"cowrie.session.file_download", "cowrie.session.file_upload"} for n in names),
        "exploit_indicators": sum(n.endswith(".exploit_attempt") or n.endswith(".exploit_success") for n in names),
        "duration_seconds": round(min(duration, 86400.0), 1),
    }
    labels: list[str] = []
    evidence: list[str] = []
    if feature["login_failures"] >= 3:
        labels.append("Credential guessing")
        evidence.append(f"{feature['login_failures']} failed login attempts")
    if feature["recon_commands"]:
        labels.append("System reconnaissance")
        evidence.append(f"{feature['recon_commands']} discovery-style commands")
    if feature["delivery_commands"] or feature["file_transfers"]:
        labels.append("Payload delivery indicator")
        evidence.append(f"{feature['delivery_commands']} retrieval commands; {feature['file_transfers']} file-transfer events")
    if feature["persistence_commands"]:
        labels.append("Persistence indicator")
        evidence.append(f"{feature['persistence_commands']} persistence-related commands")
    if feature["privilege_commands"]:
        labels.append("Privilege exploration")
        evidence.append(f"{feature['privilege_commands']} privilege-related commands")
    if feature["obfuscated_commands"]:
        labels.append("Suspicious/encoded execution")
        evidence.append(f"{feature['obfuscated_commands']} obfuscated execution indicators")
    if feature["destructive_commands"]:
        labels.append("Destructive command indicator")
        evidence.append(f"{feature['destructive_commands']} potentially destructive commands")
    if feature["exploit_indicators"]:
        labels.append("Exploit indicator")
        evidence.append(f"{feature['exploit_indicators']} honeypot exploit events")
    if not labels:
        labels.append("Unclassified interaction")
        evidence.append("No defined behavioral indicators matched")

    # Human-readable heuristic severity, NOT a probability or ML confidence score.
    risk = min(100, (
        (min(30, 8 + feature["login_failures"] * 3) if feature["login_failures"] >= 3 else 0)
        + (15 if feature["recon_commands"] else 0)
        + (35 if feature["delivery_commands"] or feature["file_transfers"] else 0)
        + (38 if feature["persistence_commands"] else 0)
        + (18 if feature["privilege_commands"] else 0)
        + (22 if feature["obfuscated_commands"] else 0)
        + (60 if feature["destructive_commands"] else 0)
        + (55 if feature["exploit_indicators"] else 0)
        + (8 if feature["login_successes"] else 0)
    ))
    return {
        "session": key[1], "sensor": key[0],
        "src_ip": _safe(next((e.get("src_ip") for e in events if e.get("src_ip")), first.get("src_ip")), 80),
        "protocol": _safe(first.get("protocol", "unknown"), 16),
        "start": start.isoformat() if start else "Unknown",
        "labels": labels, "evidence": evidence,
        "commands": commands[:50],
        "features": feature,
        "risk": int(risk), "anomaly": None, "anomaly_percentile": None,
    }


def analyze_events(events: list[dict], *, enable_ml: bool = True) -> dict:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        if not isinstance(e, dict) or not isinstance(e.get("session"), str):
            continue
        if not isinstance(e.get("eventid"), str) or not e["eventid"].startswith("cowrie."):
            continue
        grouped[(_safe(e.get("sensor"), 120) or "default", e["session"])].append(e)
    sessions = [_session_row(key, group) for key, group in grouped.items()]
    ml_ready = enable_ml and len(sessions) >= MIN_ML_SESSIONS
    if ml_ready:
        # Log transform prevents large login counts from dominating the scale.
        data = [[math.log1p(row["features"][name]) for name in FEATURES] for row in sessions]
        x = StandardScaler().fit_transform(data)
        model = IsolationForest(n_estimators=150, contamination=0.08, random_state=42)
        model.fit(x)
        scores = model.score_samples(x)
        predictions = model.predict(x)
        sorted_scores = sorted(scores)
        for row, score, prediction in zip(sessions, scores, predictions):
            # Higher percentile = more atypical relative to THIS dataset.
            row["anomaly_percentile"] = round(100 * (1 - bisect.bisect_right(sorted_scores, score) / len(sorted_scores)), 1)
            row["anomaly"] = bool(prediction == -1)
            if row["anomaly"]:
                row["risk"] = min(100, row["risk"] + 15)
                row["evidence"].append("Isolation Forest flagged this session as unusual relative to the loaded dataset")
    sessions.sort(key=lambda row: (row["risk"], row["start"]), reverse=True)
    by_label = defaultdict(int)
    for row in sessions:
        for label in row["labels"]:
            by_label[label] += 1
    return {
        "meta": {
            "events": len(events), "sessions": len(sessions),
            "unique_sources": len({s["src_ip"] for s in sessions if s["src_ip"]}),
            "ml_enabled": bool(ml_ready),
            "ml_note": "Isolation Forest scores are relative to this dataset; not attack probabilities."
              if ml_ready else f"Need {MIN_ML_SESSIONS} or more sessions to run anomaly ranking.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "labels": dict(sorted(by_label.items(), key=lambda kv: (-kv[1], kv[0]))),
        "sessions": sessions,
    }
