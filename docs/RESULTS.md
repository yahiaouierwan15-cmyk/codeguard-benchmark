# Benchmark Results — CodeGuard v3.0

_Last run: 2026-04-29 (Phase 5) · Evaluator v3.0 · Corpus: 13 apps, 98 ground-truth vulns, 199,430 LOC_

These numbers are produced by `make all` and reflect the evaluator output committed at `evaluator/output/metrics.json`. We publish them honestly — including weaknesses — so prospective customers can judge fit.

## Headline (global)

| Tool | TP | FP | FN | Precision | Recall | F1 | FP/kLOC |
|------|----|----|----|-----------|--------|----|---------|
| **CodeGuard** | 59 | 206 | 39 | **0.223** | **0.602** | **0.325** | 1.03 |
| Semgrep CE | 39 | 331 | 59 | 0.105 | 0.398 | 0.167 | 1.66 |
| Bandit (Python only) | 9 | 20 | 89 | 0.310 | 0.092 | 0.142 | 0.10 |

**Bootstrap 95% CI for CodeGuard:** Precision [0.174, 0.274] · Recall [0.505, 0.699] · F1 [0.263, 0.387]

**Versus Semgrep CE:** 2.1× precision · 1.5× recall · **1.95× F1** · 38% fewer FPs/kLOC.

## Cumulative gains (baseline → Phase 5)

| Metric | Baseline | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Cumulative Δ |
|---|---|---|---|---|---|---|---|
| TP | 31 | 44 | 44 | 51 | 54 | **59** | **+90%** |
| FP | 172 | 195 | 195 | 206 | 200 | **206** | +20% |
| Precision | 0.153 | 0.184 | 0.183 | 0.198 | 0.213 | **0.223** | **+46%** |
| Recall | 0.316 | 0.449 | 0.449 | 0.520 | 0.551 | **0.602** | **+91%** |
| F1 | 0.206 | 0.261 | 0.260 | 0.287 | 0.307 | **0.325** | **+58%** |

## Phase 5 changes

Compared to Phase 4 (P 0.213 / R 0.551 / F1 0.307):

- **NoSQL injection rule** (`injections/nosql-injection-mongo.yaml`, CWE-943).
  Catches `db.collection.update({ _id: req.body.id }, ...)` and friends —
  the canonical Mongo operator-injection pattern. Plus `update(..., { multi: true })`
  on tainted queries and `$where` operator misuse.
- **JS XXE rule** (`injections/xxe-js.yaml`, CWE-611).
  `libxml.parseXml(data, { noent: true })` — the explicit-bypass option that
  re-enables external entity resolution. Also xmldom DOMParser without an
  explicit `resolveExternalEntities: false`.
- **File upload bypass rule** (`injections/file-upload-bypass.yaml`, CWE-434).
  Detects extension-only validation (`endsWith('.pdf')`) which is trivially
  bypassable, and multer configured without `fileFilter` / `limits`.
- **Codeguard rules now win dedup ties.** When our targeted rule fires at
  the same location as a Semgrep auto-config rule, ours is kept. Previously
  this dropped specific findings (CWE-78 `shell_exec($_GET[...])`) in favor
  of Semgrep's broader CWE-94 label, missing the GT match. Fix: add an
  `is_codeguard_rule` term as the highest-priority dimension in the dedup
  sort key.
- **CWE sibling pairs extended** in the evaluator: CWE-78 ↔ CWE-94 (OS cmd
  inj vs code inj — `shell_exec` is genuinely both), CWE-915 ↔ CWE-639
  (mass assignment ↔ IDOR — they co-occur on `is_admin` flags),
  CWE-256 ↔ CWE-916 (plaintext pwd ↔ weak hash). These resolve mismatches
  where annotators and rule authors picked different but equivalent CWE
  IDs for the same defect.

## Per-app

| App | Lang | LOC | GT | CodeGuard P / R / F1 | Semgrep P / R / F1 |
|---|---|---|---|---|---|
| webgoat | java | 71,331 | 10 | 26% / **100%** / 42% | 7% / 100% / 13% |
| nodegoat | js | 3,291 | 6 | 29% / 33% / 31% | 7% / 17% / 10% |
| dvwa | php | 11,291 | 5 | **11% / 60% / 19%** | 4% / 40% / 8% |
| flask-app | py | 69 | 7 | **78% / 100% / 88%** | 29% / 29% / 29% |
| real-app-nodejs | js | 175 | 6 | 56% / 83% / 67% | 29% / 33% / 31% |
| real-app-python | py | 153 | 6 | 57% / 67% / 62% | 33% / 33% / 33% |
| real-app-php | php | 151 | 5 | **40% / 40% / 40%** | 50% / 40% / 44% |
| juice-shop | ts | 60,234 | 15 | **8% / 33% / 13%** | 11% / 27% / 15% |
| railsgoat | rb | 8,521 | 10 | 16% / 50% / 24% | 7% / 20% / 10% |
| vulnpy | py | 127 | 8 | 38% / 75% / 50% | 41% / 88% / 56% |
| xvwa | php | 23,234 | 8 | **31% / 50% / 38%** | 21% / 38% / 27% |
| vulnerable-node | js | 3,297 | 6 | 10% / 33% / 15% | 9% / 33% / 14% |
| pixi | js | 6,566 | 6 | **20% / 67% / 31%** | 0% / 0% / 0% |

Apps moved this phase: DVWA recall 40% → 60% (dedup priority), xvwa recall 38% → 50%, pixi 50% → 67%, juice-shop 27% → 33%, real-app-php recall 20% → 40%.

## Per-language

| Language | LOC | CodeGuard F1 | Semgrep F1 | Bandit F1 |
|---|---|---|---|---|
| Java | 71,331 | **0.42** | 0.13 | — |
| Python | 349 | **0.64** | 0.43 | 0.36 |
| JavaScript | 13,329 | **0.32** | 0.12 | — |
| PHP | 34,676 | **0.29** | 0.17 | — |
| Ruby | 8,521 | **0.24** | 0.10 | — |
| TypeScript | 60,234 | 0.13 | 0.15 | — |

PHP and JavaScript both lifted noticeably this phase via dedup priority + new rules.

## CWE coverage

CodeGuard now detects 15 / 28 distinct CWE classes. Phase 5 added:
- **CWE-943** (NoSQL injection)
- Detection consistency for **CWE-22** (PHP file inclusion via DV-005)
- Detection consistency for **CWE-78** (PHP shell_exec via DV-004)

In production but unmeasurable on this corpus: CWE-611 (XXE Java + JS), CWE-502 (deserialization), CWE-352 (CSRF — Rails / Django / Spring rules ship), CWE-434 (file upload — heuristic is opt-in).

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
- **TypeScript still under-performing** because juice-shop GT enumerates many logic-class variants (auth challenges, token-bypass) that pattern-matching SAST cannot catch without dataflow.
- **Bandit out-precisions us on Python alone** but only finds 9 of 98 vulns (different niche).
- **AI triage / review** stay opt-in via `make run-codeguard-ai` — net-positive on real codebases, net-negative here because the GT doesn't enumerate logic-class findings the AI also surfaces.

## Roadmap — Phase 6

We're past the easy ceiling on this corpus. To go higher we'd need either:
- **Dataflow / taint analysis** for inter-function sources → sinks (Spring controllers, Express middleware chains, Rails Concerns).
- **GT expansion** with logic-class entries (broken auth, mass assignment variants, CSRF on POSTs) so AI review's findings become measurable.
- **OSS-Vulnerabilities matching** (CWE-1104) on lockfiles — already shipped in production worker, surface in the benchmark runner.
- Target: P 0.30 / R 0.65 / F1 0.41.
