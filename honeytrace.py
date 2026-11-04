"""HoneyTrace ML CLI. Run: python honeytrace.py demo"""
from __future__ import annotations
import argparse
import json
import sqlite3
from pathlib import Path

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.demo import create_demo
from honeytrace.report import write_report
from honeytrace.live import Monitor, serve_dashboard
from honeytrace.ml_intelligence import export_label_template, evaluate_session_labels
from honeytrace.validation import create_validation_demo, validate_holdout
from honeytrace.validation_report import write_validation_html
from honeytrace.curation import audit_dataset, export_review_queue
from honeytrace.archive import ORIGINS, archive_import, archive_summary, archive_export


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline Cowrie honeypot behavior analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Generate synthetic logs and an offline HTML dashboard")
    demo.add_argument("--sessions", type=int, default=240, help="Synthetic session count, 1-240")
    analyze = sub.add_parser("analyze", help="Analyze a Cowrie JSONL log file")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--no-ml", action="store_true", help="Disable Isolation Forest")
    live = sub.add_parser("live", help="Serve an automatically updating local Cowrie dashboard")
    live.add_argument("--source", choices=("docker", "file"), default="docker")
    live.add_argument("--input", type=Path, default=Path("data/cowrie.json"))
    live.add_argument("--container", default="honeytrace-cowrie")
    live.add_argument("--container-path", default="/cowrie/cowrie-git/var/log/cowrie/cowrie.json")
    live.add_argument("--port", type=int, default=8765)
    live.add_argument("--interval", type=int, default=5, help="Polling interval (2-60 seconds)")
    live.add_argument("--no-ml", action="store_true")
    labels = sub.add_parser("labels", help="Export a blank per-session CSV for manual review labels")
    labels.add_argument("input", type=Path, help="Cowrie JSONL file")
    labels.add_argument("--output", type=Path, default=Path("data/session_labels.csv"))
    evaluate = sub.add_parser("evaluate", help="Compare batch anomaly flags against manually reviewed sessions")
    evaluate.add_argument("input", type=Path, help="Cowrie JSONL file")
    evaluate.add_argument("labels", type=Path, help="CSV with sensor,session,label (review or background)")
    evaluate.add_argument("--output", type=Path, default=Path("output/evaluation.json"))
    validation = sub.add_parser("validate", help="Evaluate a training-only anomaly model on source-disjoint, manually labeled holdout sessions")
    validation.add_argument("train_log", type=Path, help="Training Cowrie JSONL")
    validation.add_argument("train_labels", type=Path, help="Training CSV with analyst-reviewed background labels")
    validation.add_argument("test_log", type=Path, help="Independent testing Cowrie JSONL")
    validation.add_argument("test_labels", type=Path, help="Independent testing CSV with review/background labels")
    validation.add_argument("--contamination", type=float, default=0.08, help="Fixed training contamination 0.01-0.25 (default: 0.08)")
    validation.add_argument("--output", type=Path, default=Path("output/holdout-validation.json"))
    validation_demo = sub.add_parser("validate-demo", help="Generate entirely synthetic, labeled holdout fixtures and validate the pipeline")
    validation_demo.add_argument("--dir", type=Path, default=Path("data/validation-demo"), help="Must be a new/empty directory")
    validation_demo.add_argument("--output", type=Path, default=Path("output/demo-holdout-validation.json"))
    review = sub.add_parser("review-queue", help="Create a private blank analyst review CSV (does not infer labels)")
    review.add_argument("input", type=Path, help="Cowrie JSONL file")
    review.add_argument("--output", type=Path, default=Path("data/review-queue.csv"))
    audit = sub.add_parser("audit", help="Write an aggregate-only dataset quality report")
    audit.add_argument("input", type=Path, help="Cowrie JSONL file")
    audit.add_argument("--labels", type=Path, default=None, help="Optional reviewed CSV (sensor,session,label)")
    audit.add_argument("--origin", choices=("unverified", "controlled-lab", "synthetic", "independent-observations"), default="unverified")
    audit.add_argument("--output", type=Path, default=Path("output/dataset-audit.json"))
    arch = sub.add_parser("store-import", help="Archive a Cowrie log snapshot as private derived features")
    arch.add_argument("input", type=Path, help="Existing Cowrie JSONL log")
    arch.add_argument("--labels", type=Path, default=None, help="Optional reviewed CSV for matching session IDs")
    arch.add_argument("--origin", choices=ORIGINS, default="unverified")
    arch.add_argument("--store", type=Path, default=Path("data/honeytrace-history.sqlite3"))
    status = sub.add_parser("store-status", help="Show aggregate archive counts without private IDs")
    status.add_argument("--store", type=Path, default=Path("data/honeytrace-history.sqlite3"))
    export = sub.add_parser("store-export", help="Export private pseudonymized feature CSV")
    export.add_argument("--store", type=Path, default=Path("data/honeytrace-history.sqlite3"))
    export.add_argument("--output", type=Path, default=Path("data/honeytrace-features.csv"))
    args = parser.parse_args()
    if args.command in ("store-import", "store-status", "store-export"):
        try:
            if args.command == "store-import":
                result = archive_import(args.input, store_path=args.store, labels_path=args.labels, origin=args.origin)
                print(f"Input sessions: {result['sessions_in_input']} | New stored versions: {result['added_versions']} | Already imported: {result['already_imported']}")
                if result['source_groups_in_input'] <= 1:
                    print("Dataset note: One source group is insufficient for independent holdout validation.")
            elif args.command == "store-status":
                print(json.dumps(archive_summary(args.store), indent=2))
            else:
                count = archive_export(args.store, output=args.output)
                print(f"Wrote {count} privacy-minimized feature rows to {args.output}")
                print("Keep this CSV local: pseudonyms can be linked across rows.")
        except (OSError, ValueError, sqlite3.DatabaseError) as error:
            parser.error(str(error))
        return
    if args.command in ("review-queue", "audit"):
        try:
            if args.command == "review-queue":
                events, _ = load_events(args.input)
                result = analyze_events(events, enable_ml=False)
                count = export_review_queue(result, args.output)
                print(f"Created {count} blank review rows: {args.output.resolve()}")
                print("Inspect original sessions privately. Fill label with review or background; do not commit CSVs or raw logs.")
            else:
                result = audit_dataset(args.input, args.labels, origin=args.origin)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
                q = result["quality"]
                print(f"Sessions: {q['sessions']} | distinct sources: {q['distinct_source_ips']} | labeled: {q['labels']['review'] + q['labels']['background']}")
                print(f"Aggregate audit: {args.output.resolve()}")
                for warning in result["warnings"]:
                    print("Audit warning:", warning)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return
    if args.command in ("validate", "validate-demo"):
        try:
            if args.command == "validate-demo":
                paths = create_validation_demo(args.dir)
                report = validate_holdout(paths["training_log"], paths["training_labels"], paths["testing_log"], paths["testing_labels"])
                report["dataset_origin"] = "synthetic-fixture; NOT a real-world performance benchmark"
            else:
                report = validate_holdout(args.train_log, args.train_labels, args.test_log, args.test_labels, contamination=args.contamination)
                report["dataset_origin"] = "user-supplied; not independently verified"
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
            html_path = args.output.with_suffix(".html")
            write_validation_html(report, html_path)
            metrics = report["model"]
            print(f"Held-out labeled: {metrics['evaluated']} | Precision: {metrics['precision']} | Recall: {metrics['recall']} | F1: {metrics['f1']}")
            print(f"Validation report: {args.output.resolve()}")
            print(f"Offline HTML dashboard: {html_path.resolve()}")
            if args.command == "validate-demo":
                print("SYNTHETIC DEMO ONLY — no real-world accuracy has been established.")
            for warning in report["warnings"]:
                print("Validation warning:", warning)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return
    if args.command in ("labels", "evaluate"):
        try:
            events, stats = load_events(args.input)
            result = analyze_events(events, enable_ml=args.command == "evaluate")
            if args.command == "labels":
                count = export_label_template(result, args.output)
                print(f"Wrote {count} unlabeled sessions to {args.output}. Fill label=review or background after manual inspection.")
            else:
                evaluation = evaluate_session_labels(result, args.labels)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
                print(f"Labeled: {evaluation['labeled']} | Precision: {evaluation['precision']} | Recall: {evaluation['recall']} | F1: {evaluation['f1']}")
                print(f"Diagnostic only (not held-out validation). Full result: {args.output}")
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return
    if args.command == "live":
        if not 2 <= args.interval <= 60:
            parser.error("--interval must be between 2 and 60 seconds")
        if not 1024 <= args.port <= 65535:
            parser.error("--port must be between 1024 and 65535")
        monitor = Monitor(input_path=args.input, source=args.source, container=args.container,
                          container_path=args.container_path, interval=args.interval,
                          enable_ml=not args.no_ml)
        try:
            serve_dashboard(monitor, port=args.port)
        except OSError as error:
            parser.error(str(error))
        return
    output = Path("output")
    output.mkdir(exist_ok=True)
    if args.command == "demo":
        if not 1 <= args.sessions <= 240:
            parser.error("--sessions must be between 1 and 240")
        path = Path("data") / "demo-cowrie.jsonl"
        count, event_count = create_demo(path, count=args.sessions)
        print(f"Created {event_count} synthetic Cowrie events across {count} sessions: {path}")
        is_demo, ml = True, True
    else:
        path, is_demo, ml = args.input, False, not args.no_ml
    try:
        events, stats = load_events(path)
    except (OSError, PermissionError) as e:
        parser.error(str(e))
    result = analyze_events(events, enable_ml=ml)
    result["meta"]["input_name"] = path.name
    result["meta"]["demo"] = is_demo
    result["meta"]["parse_stats"] = stats
    report = output / "report.html"
    report_json = output / "analysis.json"
    write_report(result, report, demo=is_demo)
    report_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Sessions: {result['meta']['sessions']} | Unique sources: {result['meta']['unique_sources']} | ML: {'on' if result['meta']['ml_enabled'] else 'not run'}")
    print(f"Dashboard: {report.resolve()}")
    print(f"JSON analysis: {report_json.resolve()}")
    if stats["invalid"] or stats["skipped"] or stats["truncated"]:
        print("Input notices:", stats)
    print("Open output/report.html in your browser. No web server required.")


if __name__ == "__main__":
    main()
