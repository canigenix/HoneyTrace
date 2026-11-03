"""Generate a fully offline, self-contained HTML report. No remote scripts or APIs."""
from __future__ import annotations
from pathlib import Path
import json


def write_report(result: dict, target: str | Path, demo: bool = False) -> None:
    source = Path(__file__).parent / "template.html"
    template = source.read_text(encoding="utf-8")
    # Prevent untrusted Cowrie input from closing the data script element.
    data = json.dumps(result, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    html = template.replace("__HONEYTRACE_PAYLOAD__", data).replace("__HONEYTRACE_MODE__", "SYNTHETIC DEMO" if demo else "IMPORTED LOGS")
    Path(target).write_text(html, encoding="utf-8")
