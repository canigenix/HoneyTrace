"""Privacy-conscious session timelines and deterministic behavioral fingerprints.

These are heuristic groupings of observed activity, not identities or ML-based
attributions. Raw Cowrie credentials are intentionally never copied.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
import json
import re

MAX_TIMELINE_EVENTS = 80
MAX_PATTERN_COMMANDS = 24

EVENT_TYPES = {
    "cowrie.session.connect": ("connection", "SSH/Telnet connection opened"),
    "cowrie.login.failed": ("login", "Login attempt failed"),
    "cowrie.login.success": ("login", "Login attempt succeeded"),
    "cowrie.command.input": ("command", "Shell command entered"),
    "cowrie.session.file_download": ("transfer", "File download observed"),
    "cowrie.session.file_upload": ("transfer", "File upload observed"),
    "cowrie.session.closed": ("connection", "Session closed"),
}


def build_timeline(events: list[dict]) -> list[dict]:
    """Build a bounded, safe-to-display timeline from supported Cowrie events.

    Explicitly avoids copying usernames, passwords, URLs, and arbitrary event
    messages. Commands are shown as entered because this is an investigation
    tool; analysts should still treat command text as sensitive.
    """
    timeline: list[dict] = []
    omitted = 0
    for event in events:
        name = str(event.get("eventid", ""))
        kind, label = EVENT_TYPES.get(name, (None, None))
        if kind is None and name.endswith((".exploit_attempt", ".exploit_success")):
            kind, label = "exploit", "Honeypot exploit event observed"
        if kind is None:
            continue
        if len(timeline) >= MAX_TIMELINE_EVENTS:
            omitted += 1
            continue
        value = {"time": str(event.get("timestamp") or "Unknown")[:40], "kind": kind, "label": label}
        if kind == "command":
            value["command"] = str(event.get("input") or "")[:240]
        timeline.append(value)
    if omitted:
        timeline.append({"time": "", "kind": "notice", "label": f"{omitted} additional events omitted (display limit)"})
    return timeline


def _command_verb(command: str) -> str:
    """Return a coarse command family without copying arguments or IPs."""
    text = command.strip().lower()
    # Skip simple environment variable assignments in command prefixes.
    text = re.sub(r"^(?:[a-z_][a-z0-9_]*=\S+\s+){0,4}", "", text)
    match = re.match(r"[a-z0-9_./-]{1,80}", text)
    if not match:
        return "other"
    return match.group(0).rsplit("/", 1)[-1][:32]


def fingerprint_session(row: dict) -> str:
    """Stable deterministic grouping of *observed* behavior, not an identity.

    Never includes source IPs, usernames, passwords, command arguments, dates,
    sensor identifiers, or raw logs. Different attackers can match by design.
    """
    f = row["features"]
    failed = f["login_failures"]
    login_bucket = 0 if not failed else 1 if failed == 1 else 2 if failed <= 3 else 3
    signature = {
        "version": 1,
        "protocol": row.get("protocol", "unknown"),
        "logins": [login_bucket, bool(f["login_successes"])],
        "commands": [_command_verb(command) for command in row["commands"][:MAX_PATTERN_COMMANDS]],
        "labels": sorted(label for label in row["labels"] if label != "Unclassified interaction"),
        "transfer": bool(f["file_transfers"]),
        "exploit": bool(f["exploit_indicators"]),
    }
    canonical = json.dumps(signature, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()[:16]


def annotate_patterns(sessions: list[dict]) -> list[dict]:
    """Annotate sessions and summarize recurring fingerprints."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in sessions:
        fp = fingerprint_session(row)
        row["fingerprint"] = fp
        groups[fp].append(row)
    summaries: list[dict] = []
    for fp, members in groups.items():
        for row in members:
            row["similar_sessions"] = len(members) - 1
        if len(members) < 2:
            continue
        labels = Counter(label for m in members for label in m["labels"])
        summaries.append({
            "fingerprint": fp,
            "sessions": len(members),
            "sources": len({m["src_ip"] for m in members if m["src_ip"]}),
            "behavior": labels.most_common(1)[0][0] if labels else "Unclassified interaction",
        })
    summaries.sort(key=lambda item: (-item["sessions"], item["fingerprint"]))
    return summaries[:20]
