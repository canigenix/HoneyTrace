# Contributing

Contributions improving log parsing, explainable detections, and offline usability are welcome.

1. Create a feature branch and keep changes focused.
2. Use a virtual environment and install with `python -m pip install -e .`.
3. Run `python -m unittest discover -s tests -v` before proposing changes.
4. Add tests for new behavior. Never submit real victim credentials, real attacker payload binaries, or sensitive honeypot data.
5. Explain detection limitations and false-positive tradeoffs. Do not claim anomaly scores are probabilities.

By contributing, you agree your contributions may be distributed under Apache License 2.0 (see `LICENSE`).
