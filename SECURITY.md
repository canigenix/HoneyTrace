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


## v1.0 RC local backup security

Backup directories contain a **plaintext HMAC key**, pseudonymized feature
history and checksums. They are not encrypted or signed and must not be
committed to GitHub or uploaded to public services. Protect them using access
controls, encrypted off-device storage, and regular restore verification.
The `store-restore` command refuses to overwrite an existing DB or key.
A valid backup checksum is not proof that the content was never maliciously
modified. The localhost-only dashboard still has no authentication and must
never be forwarded to a public or LAN-facing address.
