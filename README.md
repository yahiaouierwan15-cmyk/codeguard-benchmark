# CodeGuard Benchmark v3

Professional SAST tool evaluation framework comparing **CodeGuard AI** against **Semgrep CE**, **Bandit**, and **Snyk Code** on a corpus of 13 intentionally vulnerable applications (98 ground-truth vulnerabilities, 7 languages).

## Latest results (2026-04-29 · Phase 3)

| Tool | Precision | Recall | F1 | FP/kLOC |
|------|-----------|--------|----|---------|
| **CodeGuard** | **0.198** | **0.520** | **0.287** | 1.03 |
| Semgrep CE | 0.097 | 0.367 | 0.154 | 1.67 |
| Bandit | 0.310 | 0.092 | 0.142 | 0.10 |

CodeGuard: **2.0× precision · 1.4× recall · 1.86× F1** vs Semgrep CE. **38% fewer FPs/kLOC.**

Full breakdown (per-language, per-CWE, unique detections, caveats): **[docs/RESULTS.md](docs/RESULTS.md)**.

## Quick Start

```bash
make setup      # Clone all vulnerable test apps
make run        # Run all scanners (CodeGuard, Semgrep, Bandit)
make evaluate   # Compare against ground truth
```

Or all at once: `make all`

## Corpus (13 apps, 98 vulns)

| App | Language | Vulns | Source |
|-----|----------|-------|--------|
| WebGoat | Java | 10 | OWASP |
| NodeGoat | JS | 6 | OWASP |
| DVWA | PHP | 5 | OWASP |
| Juice Shop | TS | 15 | OWASP |
| RailsGoat | Ruby | 10 | OWASP |
| VulnPy | Python | 8 | Netflix |
| XVWA | PHP | 8 | OWASP |
| Vulnerable Node | JS | 6 | cr0hn |
| Pixi | Python | 6 | DevSlop |
| flask-app | Python | 7 | In-repo |
| real-app-nodejs | JS | 6 | In-repo |
| real-app-python | Python | 6 | In-repo |
| real-app-php | PHP | 5 | In-repo |

## Methodology Highlights

- **Hungarian matching** (optimal assignment) instead of greedy
- **CWE hierarchy awareness** (parent/child partial matching)
- **Finding deduplication** (same file + line + CWE = 1 finding)
- **FP/kLOC** normalization (false positives per 1000 lines of code)
- **Bootstrap 95% CI** on Precision/Recall/F1
- **Per-language** and **per-CWE** breakdowns
- **Unique detection analysis** (what only one tool catches)

See [docs/methodology.md](docs/methodology.md) for full details.

## Structure

```
codeguard-benchmark/
  apps/                     # 13 vulnerable applications (git submodules + clones)
  ground-truth/             # 1 JSON per app with annotated vulnerabilities
  evaluator/
    evaluate.py             # Evaluation engine (v3)
    output/                 # Generated metrics (JSON, CSV)
  runners/
    run_codeguard.py        # CodeGuard (Semgrep custom + TruffleHog)
    run_semgrep.py          # Semgrep CE (auto config)
    run_bandit.py           # Bandit (Python only)
    run_snyk.py             # Snyk Code (optional, requires auth)
  reports/
    codeguard/              # GL-SAST JSON per app
    semgrep/
    bandit/
    snyk/
  docs/
    methodology.md          # Full methodology documentation
    report.md               # Results report
  Makefile                  # One-command pipeline
```

## Requirements

- Python 3.10+
- [Semgrep](https://semgrep.dev/docs/getting-started/) (`pip install semgrep`)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) (for CodeGuard runner)
- [Bandit](https://bandit.readthedocs.io/) (`pip install bandit`)
- [Snyk CLI](https://docs.snyk.io/snyk-cli) (optional, `npm install -g snyk`)

## License

MIT
