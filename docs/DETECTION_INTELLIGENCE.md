# HoneyTrace v1.1 — Detection Intelligence (Preview)

The v1.1 rules are **conservative syntax indicators**, not evidence of malicious intent or verified attacker attribution. This update makes the existing rule system less vulnerable to false positives from text *describing* a command rather than invoking it. It remains a shallow shell parser, **not** a shell interpreter or a malware sandbox.

## First run

On Windows PowerShell / CMD from the HoneyTrace project folder:

```powershell
py -m unittest discover -s tests -v
py honeytrace.py rules-benchmark
py honeytrace.py live --archive --archive-origin controlled-lab --backup-hours 24
```

The built-in benchmark uses **30 synthetic, intentionally constructed examples**. A perfect result means only that the implementation agrees with these known fixtures. It **does not measure sensitivity, specificity, or real-world attack-detection performance**. All raw Cowrie commands remain local, and the aggregate JSON benchmark report does not include command strings.

## Rule identifiers

| Code | Category | Interpretation |
|---|---|---|
| HT-R101 | `recon` | Command-side system discovery syntax, including `crontab -l` |
| HT-R102 | `delivery` | Retrieval tool invocation, such as `curl` and `wget` (not necessarily a malicious payload) |
| HT-R103 | `persistence` | Selected persistence-affecting commands and writes to cron or SSH-authorized-key paths |
| HT-R104 | `destructive` | Selected destructive command forms |
| HT-R105 | `privilege` | Selected privilege-related inspection syntax |
| HT-R106 | `obfuscated` | Interpreted/encoded shell invocation indicators (not conclusive obfuscation) |
| HT-R107 | `execution` | Local executable / shell script invocation, used with retrieval for session co-occurrence |

`HT-R107` contributes to the **Retrieval-and-execution pattern** label **only when retrieval and execution both appear within a session**. This does not prove the retrieved file was the executed file. The risk score remains a heuristic (0–100), not an attack probability. Credential-failure and Cowrie event indicators continue independently.

The other existing labels, numeric features, and archive schema are retained. Rule IDs are added to session investigation output; version `1.1` is recorded in analysis metadata. The SQL archive does not store raw commands, rule IDs, or proof of attribution.

## Analyst-reviewed command-category cases

You can provide a local JSONL of **syntax-category expectations**, such as:

```jsonl
{"command":"echo 'wget https://example.invalid/a'","expected":[]}
{"command":"wget https://example.invalid/a","expected":["delivery"]}
{"command":"sudo -l","expected":["privilege"]}
```

Use only your own authorized observations, and keep this JSONL private. Save it under Git-ignored `data/`, then run:

```powershell
py honeytrace.py rules-benchmark data/rule-cases.jsonl --output output/my-rule-benchmark.json
```

The output contains **aggregate category-confusion counts**, precision, recall and F1, not source IPs, credentials, or command text. The output is created exclusively: choose another output filename for a rerun. An expectation array is not a malicious/benign label, and this evaluation does **not** train or test Isolation Forest. For ML model performance on separate observed sources, use the existing `validate` workflow.

## Important limitations

- `shlex` tokenization is shallow. Shell substitutions like `$(...)`, multiline commands, encoded payloads, function aliases, redirections and complex conditional syntax can be missed or misclassified.
- Unclosed quotes fail conservatively (no match), and command strings longer than 4,096 characters are not analyzed by the v1.1 rule parser.
- Read-only commands such as `ls`, `whoami`, or `curl -I` can be normal administration; **rules describe syntax, not intent**.
- For compatibility, the numeric ML feature names and SQLite schema are unchanged. **Feature values may change** because the detection rules have improved; comparisons across engine versions need the source/engine version recorded. Previously archived historical versions are not silently rewritten.
- Existing live monitoring remains loopback-only. Do not expose the honeypot or browser dashboard beyond an isolated authorized lab, and do not execute commands found in logs.
- Collect independent, appropriately labeled authorized observations, including benign examples and missed detection candidates, before claiming empirical performance.
