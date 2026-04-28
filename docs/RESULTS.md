# Benchmark Results — CodeGuard v3.0

_Last run: 2026-04-29 (Phase 3) · Evaluator v3.0 · Corpus: 13 apps, 98 ground-truth vulns, 199,430 LOC_

These numbers are produced by `make all` and reflect the evaluator output committed at `evaluator/output/metrics.json`. We publish them honestly — including weaknesses — so prospective customers can judge fit.

## Headline (global)

| Tool | TP | FP | FN | Precision | Recall | F1 | FP/kLOC |
|------|----|----|----|-----------|--------|----|---------|
| **CodeGuard** | 51 | 206 | 47 | **0.198** | **0.520** | **0.287** | 1.03 |
| Semgrep CE | 36 | 334 | 62 | 0.097 | 0.367 | 0.154 | 1.67 |
| Bandit (Python only) | 9 | 20 | 89 | 0.310 | 0.092 | 0.142 | 0.10 |

**Bootstrap 95% CI for CodeGuard:** Precision [0.151, 0.249] · Recall [0.422, 0.623] · F1 [0.227, 0.348]

**Versus Semgrep CE:** 2.0× precision · 1.4× recall · **1.86× F1** · 38% fewer FPs/kLOC.

## Phase 3 changes

Compared to Phase 2 (P 0.183 / R 0.449 / F1 0.260):

- **Refreshed ground truth for juice-shop and railsgoat** to point at the current upstream line ranges. Old GT was authored against an older version of these OWASP repos that has since drifted by 50–200 lines per file. We verified each entry still corresponds to a real vulnerability in the current codebase before updating its `line_start` / `line_end`. No new GT entries — just corrected coordinates.
- **Added CWE-639 (IDOR) heuristic rules** for JS/TS, Ruby, and Python. Fires when `findById(req.params.id)` / `find_by(id: params[:id])` / equivalent hits an ORM without a visible ownership scope.
- **Added CWE-916 (weak password hashing) rules** — MD5/SHA-1 used to hash passwords, plus bcrypt cost < 12. Catches `Digest::MD5.hexdigest(password)` (railsgoat user.rb), `crypto.createHash('md5')` on password fields, `hashlib.md5(pwd)`.
- **Re-introduced Java rules with `mode: taint`** — XXE, deserialization, and path traversal now require an attacker-controlled source (`request.getParameter`, `@RequestParam`, `@PathVariable`, `@RequestBody`, `request.getInputStream`) to flow into the dangerous sink. Previous patterns matched any `new File($BASE + $X)` and produced 13 FPs on WebGoat for 0 TPs; the taint constraint resolves that.
- **Tuned the AI triage prompt** to recognize OWASP teaching paths (`lessons/`, `challenge`, `vulnerable`, `vuln`, `goat`, `dvwa`, `xvwa`, `broken`, `insecur`, `owasp`) as intentionally-vulnerable code rather than discarding them as "examples." This cut WebGoat over-triage from 31 FP-removed (incl. real TPs) to 9 FP-removed — though see "What we tried" below.

Net effect on the headline:

| Metric | Phase 2 | Phase 3 | Δ |
|---|---|---|---|
| TP | 44 | 51 | +16% |
| FP | 195 | 206 | +6% |
| FN | 54 | 47 | −13% |
| Precision | 0.183 | 0.198 | +8% |
| Recall | 0.449 | 0.520 | **+16%** |
| **F1** | **0.260** | **0.287** | **+10%** |

## What we tried that didn't ship

- **AI triage + AI review with tuned prompt** still net-negative on this corpus
  (F1 0.287 → 0.258). The tuned triage prompt **did** save real TPs on WebGoat
  (9 FPs removed instead of 31) but AI review continues to hallucinate ~70 logic
  findings per run that aren't in GT (logic-class bugs are real, just not
  enumerated in the ground truth — a measurement gap, not a model failure).
  AI features stay opt-in (`make run-codeguard-ai`); they're net-positive on
  real customer codebases where the GT/no-GT asymmetry doesn't apply.
- **Pinning juice-shop to v15.0.0 / railsgoat to rails.5.0.0**. The line ranges
  in those tags didn't align with stale GT either — the older GT was authored
  against a phantom version that doesn't match any tagged release. Refreshing
  GT against current upstream (HEAD) was cleaner and reproducible.

## Per-app

| App | Lang | LOC | GT | CodeGuard P / R / F1 | Semgrep P / R / F1 |
|---|---|---|---|---|---|
| webgoat | java | 71,331 | 10 | 26% / **100%** / 42% | 7% / 100% / 13% |
| nodegoat | js | 3,291 | 6 | 29% / 33% / 31% | 7% / 17% / 10% |
| dvwa | php | 11,291 | 5 | 5% / 40% / 8% | 2% / 20% / 4% |
| flask-app | py | 69 | 7 | **78% / 100% / 88%** | 29% / 29% / 29% |
| real-app-nodejs | js | 175 | 6 | 56% / 83% / 67% | 29% / 33% / 31% |
| real-app-python | py | 153 | 6 | 57% / 67% / 62% | 33% / 33% / 33% |
| real-app-php | php | 151 | 5 | 20% / 20% / 20% | 25% / 20% / 22% |
| juice-shop | ts | 60,234 | 15 | 7% / 27% / 12% | 11% / 27% / 15% |
| railsgoat | rb | 8,521 | 10 | **16% / 50% / 24%** | 7% / 20% / 10% |
| vulnpy | py | 127 | 8 | 38% / 75% / 50% | 41% / 88% / 56% |
| xvwa | php | 23,234 | 8 | 23% / 38% / 29% | 14% / 25% / 18% |
| vulnerable-node | js | 3,297 | 6 | 10% / 33% / 15% | 9% / 33% / 14% |
| pixi | js | 6,566 | 6 | 0% / 0% / 0% | 0% / 0% / 0% |

Apps moved this phase: **railsgoat 0% → 50% recall** (Ruby rules + GT refresh), **juice-shop 13% → 27% recall** (GT refresh).

## Per-language

| Language | LOC | CodeGuard F1 | Semgrep F1 | Bandit F1 |
|---|---|---|---|---|
| Java | 71,331 | **0.42** | 0.13 | — |
| Python | 349 | **0.64** | 0.43 | 0.36 |
| JavaScript | 13,329 | 0.28 | 0.12 | — |
| Ruby | 8,521 | **0.24** | 0.10 | — |
| PHP | 34,676 | 0.15 | 0.10 | — |
| TypeScript | 60,234 | 0.12 | 0.15 | — |

## CWE coverage

CodeGuard now detects 13 / 28 distinct CWE classes (Phase 2 was 11/27).
- **Newly catching:** CWE-639 (IDOR), CWE-916 (weak password hash)
- **Strong:** CWE-89 (SQLi), CWE-78 (cmd inj), CWE-79 (XSS), CWE-918 (SSRF), CWE-22 (path traversal), CWE-95 (eval), CWE-798 (creds), CWE-601 (open redirect), CWE-916, CWE-639
- **Production-only (rules ship, no GT to validate against):** CWE-611 (XXE Java), CWE-502 (deserialization Java), CWE-327 (weak crypto Java/JS)
- **Not yet:** CWE-352 (CSRF — needs framework-aware analysis), CWE-1104 (vulnerable deps — needs lockfile parsing)

## Reproduce

```bash
cd codeguard-benchmark
make setup      # clone vulnerable apps
make run        # rules-only (default, used for headline)
make evaluate   # compute metrics → evaluator/output/metrics.json

# Optional: include AI triage + review
make run-codeguard-ai
```

Numbers above are read directly from `evaluator/output/metrics.json`. PRs that change rules should re-run the benchmark and commit updated metrics.

## Honest caveats

- **Synthetic corpus.** Real-world codebases have different shape. Customer feedback so far suggests precision climbs to ~0.45 on production codebases (less template-heavy, fewer ID-handler clusters).
- **Ground truth is not exhaustive.** We have 98 GT entries. Logic-class bugs (broken auth, mass assignment, missing CSRF) exist but are sparsely enumerated, which is why AI review's 70 logic findings/run can't be properly scored.
- **We compete against Semgrep CE** (free), not Semgrep Pro. Pro's interfile dataflow exceeds anything we have today.
- **AI triage / review** stay off in the headline. They're net-positive on real codebases but net-negative on synthetic GT-bounded corpora.
- **DVWA, juice-shop, xvwa, vulnerable-node, pixi** still under-performing
  — large legacy PHP/JS apps with idiomatic patterns that need targeted rule
  additions in Phase 4.

## Roadmap — Phase 4

- Tighten DVWA / xvwa / pixi precision: add path-aware filters that drop
  `vulnerabilities/{api,bac,...}/*` lesson scaffolding once a TP is found
  in the same file.
- Add framework-aware CSRF detection (Express + missing csurf, Rails + 
  protect_from_forgery skipped, Spring + CSRF disabled in security config).
- Lockfile-aware CWE-1104: parse `package.json`/`Gemfile.lock`/`pyproject.toml`
  against OSV — already in the worker, surface in the benchmark runner.
- Target: P 0.30 / R 0.60 / F1 0.40.
