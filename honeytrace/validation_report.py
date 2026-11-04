"""Offline, aggregate-only validation report. No client scripts or remote assets."""
from __future__ import annotations

from html import escape
from pathlib import Path


def _pct(value: float | None) -> str:
    return "Not defined" if value is None else f"{100 * value:.1f}%"


def _interval(value: list[float] | None) -> str:
    return "Not defined" if value is None else f"Approx. 95% Wilson interval: {_pct(value[0])} – {_pct(value[1])}"


def _metric(label: str, rate: float | None, interval: list[float] | None) -> str:
    caption = _interval(interval) if interval is not None else ("Not defined" if rate is None else "Interval not calculated for this metric")
    return f'<div class="stat"><div class="label">{escape(label)}</div><strong>{_pct(rate)}</strong><small>{caption}</small></div>'


def _panel(title: str, values: dict) -> str:
    c = values["confusion"]
    return f'''<section class="panel"><h2>{escape(title)}</h2><div class="stats">
      {_metric("Precision", values["precision"], values["precision_wilson_95"])}
      {_metric("Recall", values["recall"], values["recall_wilson_95"])}
      {_metric("F1", values["f1"], None)}
      {_metric("False positive rate", values["false_positive_rate"], values["fpr_wilson_95"])}
    </div><div class="counts"><span>True positives: {c["tp"]}</span><span>False positives: {c["fp"]}</span>
    <span>True negatives: {c["tn"]}</span><span>False negatives: {c["fn"]}</span></div></section>'''


def write_validation_html(report: dict, path: str | Path) -> None:
    """Render only aggregate numbers and fixed metadata; never embed source logs."""
    protocol = report["protocol"]
    warnings = "".join(f"<li>{escape(item)}</li>" for item in report["warnings"])
    limits = "".join(f"<li>{escape(item)}</li>" for item in report["limitations"])
    origin = escape(str(report.get("dataset_origin", "user-supplied, not independently verified")))
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark"><title>HoneyTrace v0.6 | ML Validation</title>
    <style>
    :root{{--bg:#08121b;--panel:#142432;--line:#304655;--txt:#eaf4fa;--mute:#a6bdc8;--accent:#f2b66a}}
    *{{box-sizing:border-box}}body{{margin:0;font:14px/1.55 system-ui,Segoe UI,sans-serif;background:radial-gradient(ellipse 750px 270px at 70% 0,#174359,transparent),var(--bg);color:var(--txt)}}
    main{{max-width:1110px;margin:auto;padding:35px 25px 65px}}h1{{font-size:clamp(29px,4vw,48px);margin:8px 0 5px;letter-spacing:-1px}}h1 b{{color:var(--accent)}}
    h2{{font-size:20px;margin:0 0 16px}}h3{{font-size:15px}}p,.note{{color:var(--mute)}}.eyebrow{{color:var(--accent);font-weight:700;letter-spacing:2px;text-transform:uppercase;font-size:11px}}
    .panel{{background:linear-gradient(130deg,#172c3a,var(--panel));border:1px solid var(--line);border-radius:16px;padding:23px;margin:19px 0}}
    .stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}.stat{{padding:15px;border:1px solid var(--line);border-radius:11px;background:#0c1a25}}
    .label{{color:var(--mute);font-size:12px}}.stat strong{{font-size:30px;display:block;margin:8px 0}}.stat small{{font-size:11px;color:var(--mute)}}
    .counts{{display:flex;flex-wrap:wrap;gap:14px;margin-top:16px;color:#c8dbe4}}.counts span{{padding:7px 10px;border:1px solid var(--line);border-radius:8px}}
    .strip{{display:flex;flex-wrap:wrap;gap:12px;margin:17px 0}}.strip span{{background:#182e3c;padding:10px 14px;border-radius:10px}}li{{margin:7px 0}}.warn{{border-left:3px solid var(--accent);padding-left:18px}}footer{{margin-top:30px;color:var(--mute);border-top:1px solid var(--line);padding-top:20px}}
    @media(max-width:780px){{.stats{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}@media(max-width:420px){{.stats{{grid-template-columns:1fr}}}}
    </style></head><body><main><div class="eyebrow">HoneyTrace / Validation Laboratory</div><h1>ML <b>holdout evaluation</b></h1>
    <p>Source-disjoint holdout with training-only model fitting. These are analyst-review labels, not independently confirmed malicious activity.</p>
    <div class="strip"><span>Background training sessions: <b>{protocol['training_background_sessions']}</b></span>
    <span>Held-out labeled sessions: <b>{protocol['testing_labeled_sessions']}</b></span>
    <span>Separate source groups: <b>{protocol['training_source_groups']} train / {protocol['testing_source_groups']} test</b></span>
    <span>Time-forward: <b>{'yes' if protocol['time_forward_split'] else 'no'}</b></span></div>
    <p>Dataset origin: {origin}</p>
    {_panel('Isolation Forest — held-out sessions',report['model'])}
    {_panel('Fixed heuristic baseline — risk ≥35',report['rules_threshold_35'])}
    <section class="panel warn"><h2>Interpretation & warnings</h2><ul>{warnings if warnings else '<li>No protocol warnings triggered.</li>'}</ul>
    <h3>Limitations</h3><ul>{limits}</ul></section><footer>HoneyTrace v0.6 • Local, offline, aggregate-only report. No raw logs, source IP addresses, credentials, or commands are embedded.</footer>
    </main></body></html>'''
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")
