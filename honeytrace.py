"""HoneyTrace ML CLI. Run: python honeytrace.py demo"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from honeytrace.analyzer import analyze_events, load_events
from honeytrace.demo import create_demo
from honeytrace.report import write_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline Cowrie honeypot behavior analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Generate synthetic logs and an offline HTML dashboard")
    demo.add_argument("--sessions", type=int, default=240, help="Synthetic session count, 1-240")
    analyze = sub.add_parser("analyze", help="Analyze a Cowrie JSONL log file")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--no-ml", action="store_true", help="Disable Isolation Forest")
    args = parser.parse_args()
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
