# Security policy

HoneyTrace v0.x is experimental research software, not a certified intrusion detection system.

## Responsible use

- Run honeypots only on networks and systems you own or are authorized to test.
- Start with synthetic logs and a loopback-bound test service on an isolated VM.
- Do not expose Cowrie, generated reports, or captured files to the public internet by default.
- Real logs can include IP addresses, credentials, and attacker-controlled content. Never commit them.
- Treat all captured payloads as hostile; never execute them on your analysis machine.
- Keep your Python environment, dependencies, and honeypot container up to date.

## Reporting vulnerabilities

Please report vulnerabilities privately to the repository maintainer using GitHub's private vulnerability reporting feature if enabled. If it is unavailable, open a GitHub issue **without** publishing exploit details, credentials, or sensitive logs and request a private channel.

No guarantees of vulnerability fixes or response times are offered for this experimental project.
