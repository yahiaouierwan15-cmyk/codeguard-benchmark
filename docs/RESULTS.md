# Benchmark Results — CodeGuard v3.0

_Last run: 2026-04-27 · Evaluator v3.0 · Corpus: 13 apps, 98 ground-truth vulns, 119,558 LOC_

These numbers are produced by `make all` and reflect the most recent evaluator output committed at `evaluator/output/metrics.json`. We publish them honestly — including weaknesses — so prospective customers can judge fit.

## Headline (global)

| Tool | TP | FP | FN | Precision | Recall | F1 | FP/kLOC |
|------|----|----|----|-----------|--------|----|---------|
| **CodeGuard** | 31 | 172 | 67 | **0.153** | **0.316** | **0.206** | 1.44 |
| Semgrep CE | 30 | 307 | 68 | 0.089 | 0.306 | 0.138 | 2.57 |
| Bandit (Python only) | 6 | 10 | 92 | 0.375 | 0.061 | 0.105 | 0.08 |
| Snyk Code | 0 | 0 | 98 | 0.000 | 0.000 | 0.000 | 0.00 |

**Bootstrap 95% CI for CodeGuard:** Precision [0.106, 0.204] · Recall [0.228, 0.409] · F1 [0.144, 0.264]

## How to read these numbers

- **Recall ≈ 31.6 %** — out of 98 known-vulnerable findings across the corpus, we catch ~1 in 3. This is **comparable to Semgrep CE** (30.6 %) and **5× Bandit** (6.1 %).
- **Precision ≈ 15.3 %** — when we report something, ~1 in 7 is a true vulnerability. **Better than Semgrep CE** (8.9 %) but well below mature commercial tools like Bandit on its narrow scope (37.5 %, Python only).
- **FP/kLOC = 1.44** — for every 1,000 lines scanned we surface ~1.4 false positives. Lower than Semgrep (2.57), much higher than Bandit (0.08).
- **CWE coverage:** 9 / 27 distinct CWE classes detected. Strong on **CWE-78 (cmd injection, 86 % recall)**, **CWE-918 (SSRF, 80 %)**, **CWE-328 (weak hashing, 100 %)**. Weak on **CWE-22 (path traversal, 0 %)**, **CWE-79 (XSS, 30 %)**, and full categories not yet covered (deserialization, XXE, broken access control).

## By language

| Language | LOC | TP | FP | Recall | F1 |
|----------|-----|----|----|--------|----|
| PHP | 34,676 | 10 | 70 | **55.6 %** | 0.20 |
| Python | 222 | 11 | 24 | 52.4 % | 0.39 |
| Java | 71,331 | 4 | 9 | 40.0 % | 0.35 |
| JavaScript | 13,329 | 6 | 69 | 25.0 % | 0.12 |
| TypeScript | 0¹ | 0 | 0 | 0 % | — |
| Ruby | 0¹ | 0 | 0 | 0 % | — |

¹ TypeScript and Ruby corpora are present but not yet wired into the runner — known gap, planned for v3.1.

## What CodeGuard catches that others miss

7 unique detections in this corpus, including:
- Hardcoded secret keys committed to source (`flask-app`, `real-app-python`)
- Open redirect via `req.query.returnUrl` (`real-app-nodejs`)
- Stored XSS in PHP echo shorthand (`real-app-php`)
- MD5 used for password hashing (`real-app-python`)
- Unrestricted file upload (`xvwa`)

## What we miss (top FN by category)

- **CWE-22 (Path Traversal)** — 8 misses. Rules added in v3.1 (April 2026), not yet rebenchmarked.
- **CWE-639 / 640 (Authorization)** — 4 misses, 32 FPs. Auth-flow analysis is heuristic-only today.
- **CWE-79 (XSS)** — 7 misses across templating engines; sink coverage is partial.
- **CWE-94 (Code Injection)** — 13 FPs, 0 TPs. Rule needs tightening.

## Reproduce

```bash
cd codeguard-benchmark
make setup     # clone vulnerable apps
make run       # run all scanners
make evaluate  # compute metrics → evaluator/output/metrics.json
```

Numbers above are read directly from `evaluator/output/metrics.json`. PRs that change rules should re-run the benchmark and commit updated metrics.

## Honest caveats

- This is a **synthetic corpus** of intentionally-vulnerable apps. Real-world codebases have different shape (more glue code, fewer textbook vulns) — expect different precision/recall there.
- We compete against **Semgrep CE** (free), not Semgrep Pro. Pro has interfile dataflow that we do not.
- CodeGuard's main differentiators — **AI triage** (rejects ~30 % of raw findings as FP) and **auto-fix** (PR generation) — are not measured here. They run *after* the SAST stage.
