"""Batch-relative session clustering, descriptive anomaly contrasts and evaluation.

Clusters are groups of similar *observed features*, not attacker identities.
Feature contrasts are descriptive; they are not Isolation Forest attribution.
No credential or raw command text is used for clustering or evaluation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
import math
from pathlib import Path
from statistics import median

from sklearn.cluster import DBSCAN

MAX_CLUSTER_SESSIONS = 2000  # Protect localhost monitors from quadratic DBSCAN workloads.

# Fixed, interpretable weights avoid a per-batch StandardScaler for clusters.
# Clustering is still batch-dependent and not validated as identity attribution.
CLUSTER_FEATURES = (
    ("login_failures", 0.9),
    ("login_successes", 1.0),
    ("command_count", 0.65),
    ("unique_commands", 0.45),
    ("recon_commands", 0.9),
    ("delivery_commands", 1.5),
    ("persistence_commands", 1.6),
    ("destructive_commands", 1.8),
    ("privilege_commands", 1.2),
    ("obfuscated_commands", 1.4),
    ("file_transfers", 1.5),
    ("exploit_indicators", 1.8),
    ("duration_seconds", 0.16),
)

FEATURE_DESCRIPTIONS = {
    "login_failures": "failed logins", "login_successes": "successful logins",
    "command_count": "commands", "unique_commands": "distinct commands",
    "recon_commands": "discovery-style commands", "delivery_commands": "retrieval commands",
    "persistence_commands": "persistence indicators", "destructive_commands": "destructive indicators",
    "privilege_commands": "privilege-exploration commands", "obfuscated_commands": "encoded execution indicators",
    "file_transfers": "file transfers", "exploit_indicators": "exploit events",
    "duration_seconds": "duration (seconds)",
}


def _vector(session: dict) -> list[float]:
    features = session["features"]
    return [weight * math.log1p(max(0.0, float(features.get(key, 0)))) for key, weight in CLUSTER_FEATURES]


def cluster_sessions(sessions: list[dict], *, enabled: bool = True) -> list[dict]:
    """Group locally similar sessions with DBSCAN; expose no cross-run stable IDs.

    Epsilon is a heuristic in a fixed log-scaled feature space, not tuned on
    independently labeled data. Individual noise sessions have null cluster.
    """
    for row in sessions:
        row["ml_cluster"] = None
        row["ml_cluster_size"] = 0
    if not enabled or not 2 <= len(sessions) <= MAX_CLUSTER_SESSIONS:
        return []

    ordered = sorted(sessions, key=lambda r: (r["sensor"], r["session"]))
    predictions = DBSCAN(eps=1.25, min_samples=2, metric="euclidean").fit_predict(
        [_vector(row) for row in ordered]
    )
    members: dict[int, list[dict]] = defaultdict(list)
    for row, cluster_id in zip(ordered, predictions):
        if int(cluster_id) >= 0:
            members[int(cluster_id)].append(row)
    # Batch-relative labels. Reorders do not affect the deterministic input order.
    groups = sorted(members.values(), key=lambda items: (-len(items), items[0]["sensor"], items[0]["session"]))
    result = []
    for n, group in enumerate(groups, 1):
        name = f"C{n:03d}"
        for row in group:
            row["ml_cluster"] = name
            row["ml_cluster_size"] = len(group)
        labels = Counter(label for row in group for label in row["labels"])
        result.append({
            "id": name,
            "sessions": len(group),
            "sources": len({row["src_ip"] for row in group if row["src_ip"]}),
            "behavior": labels.most_common(1)[0][0] if labels else "Unclassified interaction",
        })
    return result[:30]


def describe_anomalies(sessions: list[dict]) -> None:
    """Add simple cohort contrasts, NOT model-derived feature importance."""
    if not sessions:
        return
    keys = [key for key, _ in CLUSTER_FEATURES]
    medians = {key: median(float(s["features"].get(key, 0)) for s in sessions) for key in keys}
    for row in sessions:
        row["anomaly_factors"] = []
        if row.get("anomaly") is not True:
            continue
        contrasts = []
        for key in keys:
            value = float(row["features"].get(key, 0))
            typical = medians[key]
            # Log-space difference reduces dominance by arbitrarily large counts.
            contrast = math.log1p(value) - math.log1p(typical)
            if abs(contrast) < 0.35:
                continue
            contrasts.append((abs(contrast), key, value, typical, "More" if contrast > 0 else "Fewer"))
        contrasts.sort(key=lambda item: (-item[0], item[1]))
        row["anomaly_factors"] = [
            f"{direction} {FEATURE_DESCRIPTIONS[key]} than batch median: {value:g} vs {typical:g}"
            for _, key, value, typical, direction in contrasts[:4]
        ]
        if not row["anomaly_factors"]:
            row["anomaly_factors"] = ["Unusual multivariate combination; no single large median contrast"]


def export_label_template(result: dict, output: str | Path) -> int:
    """Create a private CSV for manual adjudication. Does not infer labels."""
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(result["sessions"], key=lambda s: (s["sensor"], s["session"]))
    for row in rows:
        for key in ("sensor", "session"):
            identifier = str(row[key])
            if identifier.lstrip().startswith(("=", "+", "-", "@")) or "\r" in identifier or "\n" in identifier:
                raise ValueError(f"Refusing unsafe spreadsheet identifier in {key}")
    # Exclusive create: never silently discard a person's manual labels.
    with destination.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sensor", "session", "label"])
        writer.writeheader()
        writer.writerows({"sensor": s["sensor"], "session": s["session"], "label": ""} for s in rows)
    return len(rows)


def evaluate_session_labels(result: dict, labels_path: str | Path) -> dict:
    """Measure existing within-batch anomaly flags against manual review labels.

    'review' means a session deserves investigation; 'background' indicates
    expected lab/background traffic. These aren't real-world malicious labels.
    This is NOT an independent held-out validation of the fitted model.
    """
    if not result["meta"]["ml_enabled"]:
        raise ValueError("Anomaly detection did not run; need at least 25 sessions and ML enabled")
    predictions = {(row["sensor"], row["session"]): bool(row["anomaly"]) for row in result["sessions"]}
    confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    seen = set()
    with Path(labels_path).open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {"sensor", "session", "label"}.issubset(reader.fieldnames):
            raise ValueError("Label CSV requires sensor,session,label columns")
        for line, item in enumerate(reader, 2):
            label = (item.get("label") or "").strip().lower()
            if not label:
                continue
            if label not in {"review", "background"}:
                raise ValueError(f"CSV line {line}: label must be review or background")
            key = ((item.get("sensor") or "").strip(), (item.get("session") or "").strip())
            if key not in predictions:
                raise ValueError(f"CSV line {line}: unknown session/sensor key")
            if key in seen:
                raise ValueError(f"CSV line {line}: duplicate labeled session")
            seen.add(key)
            flagged, needs_review = predictions[key], label == "review"
            confusion["tp" if flagged and needs_review else "fp" if flagged else "fn" if needs_review else "tn"] += 1
    if not seen:
        raise ValueError("No adjudicated labels: fill 'review' or 'background' in the CSV")
    tp, fp, tn, fn = (confusion[k] for k in ("tp", "fp", "tn", "fn"))
    def ratio(n: int, d: int) -> float | None:
        return round(n / d, 4) if d else None
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "evaluation_type": "within-batch manual-label diagnostic (not held-out model validation)",
        "labels": {"positive": "review", "negative": "background"},
        "labeled": len(seen), "unlabeled": len(predictions) - len(seen),
        "confusion": confusion,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": ratio(fp, fp + tn),
        "limitations": "Labels are manually supplied, not verified ground truth. Isolation Forest was fitted to the batch being scored. This does not establish real-world detection performance.",
    }
