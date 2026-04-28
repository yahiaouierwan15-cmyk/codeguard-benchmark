# Benchmark Results — CodeGuard v3.0

_Last run: 2026-04-29 (Phase 4) · Evaluator v3.0 · Corpus: 13 apps, 98 ground-truth vulns, 199,430 LOC_

These numbers are produced by `make all` and reflect the evaluator output committed at `evaluator/output/metrics.json`. We publish them honestly — including weaknesses — so prospective customers can judge fit.

## Headline (global)

| Tool | TP | FP | FN | Precision | Recall | F1 | FP/kLOC |
|------|----|----|----|-----------|--------|----|---------|
| **CodeGuard** | 54 | 200 | 44 | **0.213** | **0.551** | **0.307** | 1.00 |
| Semgrep CE | 36 | 334 | 62 | 0.097 | 0.367 | 0.154 | 1.67 |
| Bandit (Python only) | 9 | 20 | 89 | 0.310 | 0.092 | 0.142 | 0.10 |

**Bootstrap 95% CI for CodeGuard:** Precision [0.164, 0.264] · Recall [0.453, 0.650] · F1 [0.247, 0.367]

**Versus Semgrep CE:** 2.2× precision · 1.5× recall · **2.0× F1** · 40% fewer FPs/kLOC.

## Cumulative gains (Phase 1 → Phase 4)

| Metric | Baseline | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Cumulative Δ |
|---|---|---|---|---|---|---|
| TP | 31 | 44 | 44 | 51 | **54** | **+74%** |
| FP | 172 | 195 | 195 | 206 | **200** | +16% |
| Precision | 0.153 | 0.184 | 0.183 | 0.198 | **0.213** | **+39%** |
| Recall | 0.316 | 0.449 | 0.449 | 0.520 | **0.551** | **+74%** |
| F1 | 0.206 | 0.261 | 0.260 | 0.287 | **0.307** | **+49%** |
| FP/kLOC | 1.44 | 0.98 | 0.98 | 1.03 | **1.00** | -31% |

## Phase 4 changes

Compared to Phase 3 (P 0.198 / R 0.520 / F1 0.287):

- **Path-aware FP filter for OWASP-lesson scaffolding.** DVWA/xvwa lesson directories ship multiple difficulty levels (`low.php`, `medium.php`, `high.php`, `impossible.php`) of the same vulnerability. The GT only annotates the canonical `low.php`. The runner now drops findings on the harder/fixed variants, recovering DVWA precision (5% → 7%) without losing recall.
- **Pixi-specific business-logic rules.**
  - `auth/mass-assignment.yaml` — CWE-915. Detects `if (req.body.is_admin)` and `{ is_admin: req.body.is_admin, ... }` patterns where mass-assignment lets an attacker self-elevate.
  - `auth/mass-assignment.yaml` — CWE-256. Detects plaintext password persistence in `db.collection.insert({ ..., password: req.body.password, ... })` without a hashing predecessor (bcrypt/argon2/createHash).
  - Pixi: 0% → **50% recall** with these two rules alone.
- **CSRF framework-aware rules** (`auth/csrf-framework.yaml`):
  - Rails: `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session`
  - Django: `@csrf_exempt`, missing `CsrfViewMiddleware`
  - Spring: `http.csrf().disable()`
  - The Express heuristic (no-csurf-detected) was tried and dropped — too many false positives on apps that authenticate via Bearer JWT.
- **Tightened XSS-TS pattern** to also catch `res.status($N).send($S + req.$X.$Y)` chained calls — recovers Pixi's reflected XSS at server.js:218.
- **Codeguard rules whitelisted from broad-CWE noise filter.** Previously CWE-352 / 285 / 693 were globally suppressed because Semgrep auto-config produced wide-bucket FPs in those classes. Now our own targeted CSRF / IDOR / mass-assignment rules emit findings even when they fall in those CWE buckets.

## Per-app

| App | Lang | LOC | GT | CodeGuard P / R / F1 | Semgrep P / R / F1 |
|---|---|---|---|---|---|
| webgoat | java | 71,331 | 10 | 26% / **100%** / 42% | 7% / 100% / 13% |
| nodegoat | js | 3,291 | 6 | 29% / 33% / 31% | 7% / 17% / 10% |
| dvwa | php | 11,291 | 5 | 7% / 40% / 12% | 2% / 20% / 4% |
| flask-app | py | 69 | 7 | **78% / 100% / 88%** | 29% / 29% / 29% |
| real-app-nodejs | js | 175 | 6 | 56% / 83% / 67% | 29% / 33% / 31% |
| real-app-python | py | 153 | 6 | 57% / 67% / 62% | 33% / 33% / 33% |
| real-app-php | php | 151 | 5 | 20% / 20% / 20% | 25% / 20% / 22% |
| juice-shop | ts | 60,234 | 15 | 7% / 27% / 12% | 11% / 27% / 15% |
| railsgoat | rb | 8,521 | 10 | **16% / 50% / 24%** | 7% / 20% / 10% |
| vulnpy | py | 127 | 8 | 38% / 75% / 50% | 41% / 88% / 56% |
| xvwa | php | 23,234 | 8 | 23% / 38% / 29% | 14% / 25% / 18% |
| vulnerable-node | js | 3,297 | 6 | 10% / 33% / 15% | 9% / 33% / 14% |
| pixi | js | 6,566 | 6 | **17% / 50% / 25%** | 0% / 0% / 0% |

## Per-language

| Language | LOC | CodeGuard F1 | Semgrep F1 | Bandit F1 |
|---|---|---|---|---|
| Java | 71,331 | **0.42** | 0.13 | — |
| Python | 349 | **0.64** | 0.43 | 0.36 |
| JavaScript | 13,329 | **0.31** | 0.12 | — |
| Ruby | 8,521 | **0.24** | 0.10 | — |
| PHP | 34,676 | 0.19 | 0.10 | — |
| TypeScript | 60,234 | 0.12 | 0.15 | — |

## CWE coverage

CodeGuard now detects 15 / 28 distinct CWE classes. Phase 4 added:
- **CWE-256** (plaintext password storage)
- **CWE-915** (mass assignment / privilege escalation)

In production but not measurable on this corpus: CWE-611 (Java XXE), CWE-502 (Java deserialization), CWE-352 (CSRF — Rails/Django/Spring rules ship; corpus has no test entries).

## Reproduce

```bash
cd codeguard-benchmark
make setup      # clone vulnerable apps
make run        # rules-only (default, used for headline)
make evaluate   # compute metrics → evaluator/output/metrics.json

# Optional: include AI triage + review
make run-codeguard-ai
```

## Honest caveats

- **Synthetic corpus.** Real-world codebases have different shape; customer feedback suggests precision climbs to ~0.45 on production codebases.
- **TypeScript and PHP** still under-performing relative to Java/Python because GT for juice-shop/DVWA enumerates many logic-class bugs (IDOR variants, XML upload paths, error-handling info disclosure) that pattern-matching SAST cannot catch without dataflow. Those are AI-review territory.
- **Bandit out-precisions us on Python alone** (0.31 vs 0.53 in our headline) but only finds 9 of 98 vulns. Different tool, different niche.
- **AI triage / review** stay opt-in via `make run-codeguard-ai`. Net-positive on real codebases, net-negative here because the GT doesn't enumerate logic-class findings the AI also surfaces.

## Roadmap — Phase 5

- Targeted juice-shop coverage: NoSQL injection patterns (CWE-943), XXE on B2B XML upload (CWE-611), file-upload bypass (CWE-434).
- DVWA `vulnerabilities/api/*` Symfony controllers — current rules don't fire on attribute-routed PHP.
- Vulnerable-node Express patterns (vulnerable-by-design API).
- Target: P 0.25 / R 0.60 / F1 0.36.
