# CodeGuard Benchmark

A controlled SAST benchmark comparing **CodeGuard** (custom AI-augmented scanner) against **Semgrep Community Edition** across 7 deliberately vulnerable applications.

## Overview

The benchmark measures precision, recall, and F1 score for each tool against a manually verified ground-truth database of 45 vulnerabilities spanning 4 programming languages (Python, JavaScript/Node.js, PHP, Java).

## Structure

```
codeguard-benchmark/
  apps/
    webgoat/            git submodule — OWASP WebGoat (Java)
    nodegoat/           git submodule — OWASP NodeGoat (Node.js)
    dvwa/               git submodule — DVWA (PHP)
    flask-app/          Vulnerable Flask app (created for benchmark)
    real-app-nodejs/    Vulnerable Express task manager API
    real-app-python/    Vulnerable Flask blog REST API
    real-app-php/       Vulnerable PHP guestbook CRUD app
  ground-truth/
    webgoat.json        10 verified vulnerabilities
    nodegoat.json        6 verified vulnerabilities
    dvwa.json            5 verified vulnerabilities
    flask-app.json       7 verified vulnerabilities
    real-app-nodejs.json 6 verified vulnerabilities
    real-app-python.json 6 verified vulnerabilities
    real-app-php.json    5 verified vulnerabilities
  reports/
    codeguard/          Normalized JSON reports (CodeGuard output)
    semgrep/            Normalized JSON reports (Semgrep output)
  evaluator/
    evaluate.py         Evaluation script — computes TP/FP/FN, precision, recall, F1
    output/             CSV and JSON output files (generated)
  tools/
    convert_codeguard_to_glsast.py   Convert CodeGuard NDJSON to gl-sast-report format
    convert_semgrep_to_glsast.py     Convert Semgrep JSON to gl-sast-report format
    run_semgrep.sh                   Run Semgrep on all apps and generate reports
    run_codeguard.sh                 Run CodeGuard worker on all apps
  docs/
    format.md           gl-sast-report.json schema documentation
    report.md           Benchmark methodology and results summary
    poc/                Proof-of-concept exploits for selected vulnerabilities
  README.md
```

## Prerequisites

- **git** 2.30+ (for submodules)
- **Python** 3.10+
- **semgrep** 1.60+ (`pip install semgrep`)
- **trufflehog** 3.x (for CodeGuard secrets detection)
- **Node.js** 18+ (to run NodeGoat / real-app-nodejs locally)
- **PHP** 8.0+ (to run DVWA / real-app-php locally)
- **CodeGuard worker** at `../codeguard-worker/` relative to this repo

## Setup

### 1. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/yahiaouierwan15-cmyk/codeguard-benchmark.git
cd codeguard-benchmark
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

### 2. Install Python dependencies

```bash
pip install semgrep
```

## Running the benchmark

### Step 1 — Run Semgrep

```bash
bash tools/run_semgrep.sh
```

Reports are written to `reports/semgrep/<app>.json` in the normalized gl-sast-report format.

### Step 2 — Run CodeGuard

Ensure the CodeGuard worker is available at `../codeguard-worker/`:

```bash
bash tools/run_codeguard.sh
```

Reports are written to `reports/codeguard/<app>.json`.

### Step 3 — Evaluate

```bash
python3 evaluator/evaluate.py
```

Options:

```
--tools codeguard semgrep    Tools to include (default: both)
--line-tolerance 10          ±N lines for matching (default: 10)
--output-dir evaluator/output
```

Output:
- Printed comparison table to stdout
- `evaluator/output/<tool>_per_app.csv`
- `evaluator/output/cwe_comparison.csv`
- `evaluator/output/metrics.json`

## Ground truth

Ground truth entries document:
- File path (relative to app root)
- Line numbers (`line_start`, `line_end`) — verified with `cat -n`
- CWE identifier
- Severity
- Human description

See `docs/format.md` for the full schema.

## Vulnerability coverage

| CWE | Description | Apps affected |
|-----|-------------|---------------|
| CWE-89 | SQL Injection | flask-app, real-app-nodejs, real-app-python, real-app-php, webgoat, dvwa |
| CWE-78 | Command Injection | flask-app, real-app-nodejs, real-app-python, real-app-php, dvwa |
| CWE-918 | SSRF | flask-app, real-app-python, webgoat |
| CWE-22 | Path Traversal | flask-app, real-app-nodejs, real-app-python, real-app-php, webgoat |
| CWE-79 | XSS | real-app-nodejs, real-app-php, dvwa, webgoat |
| CWE-798 | Hardcoded Secrets | flask-app, real-app-nodejs, real-app-python, real-app-php, nodegoat, webgoat |
| CWE-95 | SSJS / eval Injection | nodegoat |
| CWE-943 | NoSQL Injection | nodegoat |
| CWE-601 | Open Redirect | real-app-nodejs, nodegoat |
| CWE-611 | XXE | webgoat |
| CWE-502 | Insecure Deserialization | webgoat |
| CWE-1333 | ReDoS | nodegoat |
| CWE-532 | Sensitive Data in Logs | nodegoat |
| CWE-328 | Weak Password Hashing | real-app-python |
| CWE-98 | File Inclusion | dvwa |

## Expected results (preliminary)

> Run the evaluator after populating reports/ to get actual numbers.

| Tool | Recall | Precision | F1 |
|------|--------|-----------|-----|
| CodeGuard | ~78% | ~71% | ~74% |
| Semgrep CE | ~65% | ~82% | ~73% |

CodeGuard advantages: SSRF detection, SSJS injection, ReDoS, secrets in non-standard locations.
Semgrep CE advantages: lower false-positive rate, faster scan time.

## License

MIT. Vulnerable apps (WebGoat, NodeGoat, DVWA) are subject to their own licenses — see each submodule for details.

The custom vulnerable apps (`flask-app`, `real-app-*`) are provided for security research and education purposes only. Do not deploy them in production environments.
