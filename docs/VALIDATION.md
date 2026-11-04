# HoneyTrace v0.6 — Validation Lab

This adds a **separate experimental holdout evaluator**. The existing `demo`,
`analyze`, `live`, `labels`, and `evaluate` commands remain unchanged.

## What is new

- Train an Isolation Forest model on **manually labeled background-only** sessions.
- Score **different, source-disjoint** held-out sessions without retraining or changing the threshold.
- Compare the model with HoneyTrace's existing rule-score baseline (`risk >= 35`).
- Report confusion matrices, precision, recall, F1, false-positive rate, and approximate Wilson 95% intervals.
- Produce **aggregate-only** JSON and offline HTML reports. No IPs, commands, or passwords are included in these reports.
- Check train/test file duplication, source overlap, session overlap, missing labels, and limited sample size.

This is a *research protocol*, **not** a production accuracy certification or
an independently sourced threat-intelligence feed. A session labeled `review`
means "an analyst thinks this merits investigation," not "verified malicious".

## Quickest test — synthetic fixtures

From **Windows PowerShell inside your HoneyTrace project**:

```powershell
py -m unittest discover -s tests -v
py honeytrace.py validate-demo
start .\output\demo-holdout-validation.html
```

The demo creates synthetic logs and synthetic labels under
`data/validation-demo/` (which is Git-ignored), and writes two reports under
`output/`. It never contacts the internet or Docker.

**Expect imperfect ML results.** On the deterministic synthetic fixture,
review labels intentionally correspond to observable scripted behavior.
The heuristic rule baseline can appear unrealistically strong and Isolation
Forest can miss many sessions. Neither score is a prediction of real-world
performance. A useful experiment can demonstrate model failure.

`validate-demo` refuses to overwrite previous fixtures. To repeat it in an
empty destination, use:

```powershell
py honeytrace.py validate-demo --dir data/validation-demo-second
```

## Evaluation with your own observations

Prepare **two distinct Cowrie JSONL files** from authorized, isolated sensors
or experiments, with no overlapping source IP addresses (and ideally with
training dates earlier than testing dates). Do not use your four Docker sessions
for this evaluation: they share `172.17.0.1` and are far too few.

1. Export CSVs using the existing `labels` command:

   ```powershell
   py honeytrace.py labels data/train.jsonl --output data/train_labels.csv
   py honeytrace.py labels data/test.jsonl --output data/test_labels.csv
   ```

2. Review **every session independently of the model's predictions** using
   trusted observation/context. Fill `label` with `background` (expected
   controlled behavior), `review` (warrants investigation), or leave blank if
   undetermined. Avoid labeling by simply copying HoneyTrace's heuristic
   classifications; that would bias the evaluation. Keep labels private.

3. Run validation:

   ```powershell
   py honeytrace.py validate data/train.jsonl data/train_labels.csv data/test.jsonl data/test_labels.csv
   start .\output\holdout-validation.html
   ```

   The command needs **at least 25 labeled background training sessions**.
   Test sessions can be review or background; unreviewed rows are omitted from
   measured outcomes. If one class is absent, some metrics will correctly show
   `null`/Not defined.

### How the evaluation works

- Extract the same 13 numerical features used by the live anomaly analyzer.
- Apply `log1p` to nonnegative features.
- Fit `StandardScaler` and `IsolationForest` **only on the labeled background training sessions**.
- Keep the contamination setting fixed (default 0.08; configure before seeing test labels).
- Transform and score the held-out labeled test sessions with the frozen model.
- Compare against manually supplied `review` / `background` labels.
- Evaluate the fixed rule-score threshold `>=35` on the same held-out sessions
  **without the live model's anomaly risk bonus**.

This differs from the v0.5 `evaluate` command, which scores the same batch that
was used to fit Isolation Forest, and is only a within-batch diagnostic.

### Interpreting results

- **Precision:** fraction of alerts that correspond to sessions an analyst
  labeled `review`. Undefined if the model issued no alerts.
- **Recall:** fraction of reviewed sessions the model flagged. Undefined if
  no sessions were labeled `review`.
- **False-positive rate:** fraction of labeled `background` sessions flagged.
- **F1:** harmonic mean of precision and recall; not a replacement for FPR.
- **Wilson intervals:** approximate sampling uncertainty for rates. They do
  **not** account for biased selection, correlated sessions, distribution
  shift, or mistakes in labeling.

A local Docker honeypot may show the same source IP across many sessions.
The validator **intentionally refuses overlapping train/test sources**.
It also reports whether testing takes place strictly after training.

### Privacy and boundaries

Never commit `data/` or `output/` to GitHub. Raw Cowrie logs may contain IPs,
credentials, commands, and URLs. The aggregate report excludes those fields.
No live monitoring code is replaced by this update, and the evaluator does not
open ports, retrieve malware, execute recorded commands, or phone home.

The model's output is not proof of intent, attribution, or compromise.
