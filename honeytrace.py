"""HoneyTrace ML CLI. Run: python honeytrace.py demo"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.demo import create_demo
from honeytrace.report import write_report
from honeytrace.live import Monitor, serve_dashboard
from honeytrace.ml_intelligence import export_label_template, evaluate_session_labels


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
    args = parser.parse_args()
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
