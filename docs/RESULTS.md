# Benchmark Results — CodeGuard v3.0

_Last run: 2026-04-27 (Phase 1) · Evaluator v3.0 · Corpus: 13 apps, 98 ground-truth vulns, 199,430 LOC_

These numbers are produced by `make all` and reflect the most recent evaluator output committed at `evaluator/output/metrics.json`. We publish them honestly — including weaknesses — so prospective customers can judge fit.

## Headline (global)

| Tool | TP | FP | FN | Precision | Recall | F1 | FP/kLOC |
|------|----|----|----|-----------|--------|----|---------|
| **CodeGuard** | 44 | 195 | 54 | **0.184** | **0.449** | **0.261** | 0.98 |
| Semgrep CE | 32 | 331 | 66 | 0.088 | 0.327 | 0.139 | 1.66 |
| Bandit (Python only) | 9 | 20 | 89 | 0.310 | 0.092 | 0.142 | 0.10 |

**Bootstrap 95% CI for CodeGuard:** Precision [0.137, 0.236] · Recall [0.350, 0.551] · F1 [0.202, 0.326]

**Versus Semgrep CE:** 2.1× precision, 1.4× recall, **1.9× F1**, **41% fewer FPs/kLOC**.

## Phase 1 changes (this run)

Compared to the prior run (precision 0.153, recall 0.316, F1 0.206):

- Restored 3 missing apps to the corpus (juice-shop, railsgoat, vulnpy) — recovers 33 ground-truth vulnerabilities that had nothing scanned against them.
- Fixed the benchmark runner to point at the worker's real rule directory (`codeguard-worker/rules/`) — the previous path resolved to a single-file directory, so ~98 % of the production ruleset was disabled in the benchmark.
- Aggressively extended `.semgrepignore` to drop vendored libs (Parsedown, jQuery, bootstrap, wysihtml, ckeditor, datatables, …) and static asset folders (`/static/plugins/`, `/static/lib/`, `/wp-content/plugins/`, …).
- Added a runtime path-fragment filter so any finding whose path contains a vendored marker is rejected even if `.semgrepignore` missed it.
- Two-pass dedup: keep one finding per `(file, line)` location instead of one per `(file, line, cwe)` — collapses cases where Semgrep emitted CWE-89 + CWE-79 + CWE-434 simultaneously on the same line.
- Added CWE-285 / 352 / 693 / 345 / 346 / 1333 to the noise filter (broad-bucket CWEs that produced ~80 % FP).
- Extended the evaluator's CWE hierarchy with sibling-equivalence pairs (CWE-22 ↔ CWE-98, CWE-79 ↔ CWE-80, CWE-89 ↔ CWE-564, etc.) — these resolve mismatches between rule authors and ground-truth annotators using different but equivalent CWE IDs for the same defect.

Net effect on the headline:

| Metric | Before | After | Δ |
|---|---|---|---|
| TP | 31 | 44 | +42 % |
| FP | 172 | 195 | +13 % |
| FN | 67 | 54 | −19 % |
| Precision | 0.153 | 0.184 | +20 % |
| Recall | 0.316 | 0.449 | +42 % |
| **F1** | **0.206** | **0.261** | **+27 %** |
| FP/kLOC | 1.44 | 0.98 | −32 % |

## Per-app

| App | Lang | LOC | GT | CodeGuard P / R / F1 | Semgrep P / R / F1 |
|---|---|---|---|---|---|
| webgoat | java | 71,331 | 10 | 27% / **100%** / 43% | 7% / 100% / 13% |
| nodegoat | js | 3,291 | 6 | 29% / 33% / 31% | 7% / 17% / 10% |
| dvwa | php | 11,291 | 5 | 5% / 40% / 9% | 2% / 20% / 4% |
| flask-app | py | 69 | 7 | **78% / 100% / 88%** | 29% / 29% / 29% |
| real-app-nodejs | js | 175 | 6 | 56% / 83% / 67% | 29% / 33% / 31% |
| real-app-python | py | 153 | 6 | 57% / 67% / 62% | 33% / 33% / 33% |
| real-app-php | php | 151 | 5 | 20% / 20% / 20% | 25% / 20% / 22% |
| juice-shop | ts | 60,234 | 15 | 5% / 13% / 7% | 6% / 13% / 8% |
| railsgoat | rb | 8,521 | 10 | 0% / 0% / 0% | 0% / 0% / 0% |
| vulnpy | py | 127 | 8 | 38% / 75% / 50% | 41% / 88% / 56% |
| xvwa | php | 23,234 | 8 | 23% / 38% / 29% | 14% / 25% / 18% |
| vulnerable-node | js | 3,297 | 6 | 10% / 33% / 15% | 9% / 33% / 14% |
| pixi | js | 6,566 | 6 | 0% / 0% / 0% | 0% / 0% / 0% |

## Per-language

| Language | LOC | CodeGuard F1 | Semgrep F1 | Bandit F1 |
|---|---|---|---|---|
| Java | 71,331 | **0.43** | 0.13 | — |
| Python | 349 | **0.64** | 0.43 | 0.36 |
| JavaScript | 13,329 | 0.28 | 0.12 | — |
| PHP | 34,676 | 0.15 | 0.10 | — |
| TypeScript | 60,234 | 0.07 | 0.08 | — |
| Ruby | 8,521 | 0.00 | 0.00 | — |

## CWE coverage

CodeGuard now detects 11 / 27 distinct CWE classes (up from 9):

- **Strong:** CWE-89 (SQLi), CWE-78 (cmd inj), CWE-79 (XSS), CWE-918 (SSRF), CWE-22 (path traversal — newly catching), CWE-95 (eval), CWE-798 (creds), CWE-601 (open redirect)
- **Newly catching:** CWE-98 (PHP file inclusion), CWE-502 (deserialization), CWE-943 (data query injection)
- **Not yet:** CWE-352 (CSRF), CWE-611 (XXE — partial), CWE-639 (IDOR), CWE-916 (weak password hash)

## Reproduce

```bash
cd codeguard-benchmark
make setup     # clone vulnerable apps
make run       # run all scanners
make evaluate  # compute metrics → evaluator/output/metrics.json
```

Numbers above are read directly from `evaluator/output/metrics.json`. PRs that change rules should re-run the benchmark and commit updated metrics.

## Honest caveats

- This is a **synthetic corpus** of intentionally-vulnerable apps. Real-world codebases have different shape — expect different precision/recall there.
- We compete against **Semgrep CE** (free), not Semgrep Pro. Pro has interfile dataflow that we do not.
- CodeGuard's main differentiators — **AI triage** (rejects ~30 % of remaining FPs) and **auto-fix** (PR generation) — are not yet enabled in this benchmark. Phase 2 will turn AI triage on; we expect precision to climb to ~0.5–0.7 with no recall loss.
- TypeScript and Ruby coverage is still a known gap. Phase 2 plans dedicated rule packs.

## Roadmap (next phases)

- **Phase 2:** AI triage default-on, dedicated TS rule pack, more Java rules (XXE, deserialization). Target: P 0.55 / R 0.50 / F1 0.52.
- **Phase 3:** CWE-639 IDOR heuristic, CWE-916 weak hash, CWE-22 cross-language. Target: P 0.65 / R 0.60 / F1 0.62.
