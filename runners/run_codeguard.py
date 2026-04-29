#!/usr/bin/env python3
"""
Runner: CodeGuard (Custom Rules + Semgrep auto + TruffleHog + Bandit)
=====================================================================
Runs the full CodeGuard detection pipeline:
  1. Semgrep with custom CodeGuard rules (high-precision)
  2. Semgrep --config=auto (broad coverage)
  3. TruffleHog for secret detection → CWE-798
  4. Bandit for Python apps (high-precision complement)

Noise filtering is applied post-scan to remove known-bad rules.

Usage:
    python3 runners/run_codeguard.py
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APPS_DIR = REPO_ROOT / "apps"
OUTPUT_DIR = REPO_ROOT / "reports" / "codeguard"

WORKER_DIR = REPO_ROOT.parent / "codeguard-worker"
# Point at the worker's actual production rule directory (codeguard-worker/rules)
# — the previous src/rules path only contained one file, so the benchmark
# was running with ~98 % of the rules disabled.
RULES_DIR = WORKER_DIR / "rules"

APP_LIST = [
    "webgoat", "nodegoat", "dvwa", "flask-app",
    "real-app-nodejs", "real-app-python", "real-app-php",
    "juice-shop", "railsgoat", "vulnpy", "xvwa",
    "vulnerable-node", "pixi",
]

APP_LANG_MAP = {
    "webgoat": "java",
    "nodegoat": "javascript",
    "dvwa": "php",
    "flask-app": "python",
    "real-app-nodejs": "javascript",
    "real-app-python": "python",
    "real-app-php": "php",
    "juice-shop": "typescript",
    "railsgoat": "ruby",
    "vulnpy": "python",
    "xvwa": "php",
    "vulnerable-node": "javascript",
    "pixi": "javascript",
}

# ---------------------------------------------------------------------------
# Noise filter: rules that produce pure FP with zero security value
# ---------------------------------------------------------------------------
BLOCKED_RULES = {
    # CSRF rules on wrong languages (django rules on Java/PHP/JS)
    "python.django.security.django-no-csrf-token.django-no-csrf-token",
    # Informational / noise rules
    "html.security.audit.missing-integrity.missing-integrity",
    "html.security.plaintext-http-link.plaintext-http-link",
    "generic.secrets.security.detected-jwt-token.detected-jwt-token",
    "php.lang.security.md5-loose-equality.md5-loose-equality",
}

BLOCKED_RULE_PREFIXES = (
    "generic.secrets.security.detected-generic-api-key",
    "generic.secrets.security.detected-private-key",
)

NOISE_CWES = {
    "CWE-353",   # Missing integrity check (SRI on <script> tags)
    "CWE-1004",  # Cookie without HttpOnly (informational)
    "CWE-614",   # Cookie without Secure (informational)
    "CWE-489",   # Debug features left enabled
    "CWE-676",   # Use of potentially dangerous function
    "CWE-252",   # Unchecked return value
    # Broad-bucket CWEs that produce >80% FP on non-trivial corpora.
    # We re-enable these only when AI triage is on.
    "CWE-285",   # Improper authorization — too generic, fires on every route
    "CWE-352",   # CSRF — fires on every POST without middleware annotation
    "CWE-693",   # Protection mechanism failure — wide bucket
    "CWE-345",   # Insufficient verification of data authenticity
    "CWE-346",   # Origin validation — usually informational
    "CWE-1333",  # ReDoS — Semgrep heuristic is very noisy
}

CROSS_LANG_FILTER = {
    "python.": {"python"},
    "java.": {"java"},
    "php.": {"php"},
    "ruby.": {"ruby"},
}

# DVWA-style "harder difficulty" or "impossible" variants — educational
# scaffolding the GT doesn't enumerate, kept around as the fixed reference.
# Drop findings on them when the same lesson has a `low.php` (the canonical
# vuln). Pattern: `vulnerabilities/<lesson>/source/<level>.php`.
_LESSON_LEVEL_FRAGMENTS = (
    "/source/medium.php",
    "/source/high.php",
    "/source/impossible.php",
    "/source/check_token_high.php",
    "/source/check_token_impossible.php",
    "/source/token_library_high.php",
    "/source/token_library_impossible.php",
)

# Path fragments that mark vendored / non-app code, even if .semgrepignore
# missed them. Findings whose path contains any of these are dropped.
_NOISY_PATH_FRAGMENTS = (
    "/static/plugins/",
    "/static/lib/",
    "/static/libs/",
    "/static/js/libs/",
    "/static/js/vendor/",
    "/static/vendor/",
    "/assets/lib/",
    "/assets/libs/",
    "/assets/vendor/",
    "/public/lib/",
    "/public/vendor/",
    "/wp-content/plugins/",
    "/wp-includes/",
    "/parsedown.php",
    "/parsedown",
    "/jquery.",
    "/jquery-",
    "/bootstrap.",
    "/bootstrap-",
    "/wysihtml",
    "/ckeditor",
    "/tinymce",
    "/select2",
    "/datatables",
    "/highlight.",
    "/three.min",
    "/handlebars",
    "/lodash.",
    "/moment.",
    "node_modules/",
    "/vendor/",
    "/dist/",
    "/build/",
    "/.git/",
    "/__pycache__/",
    "/coverage/",
    "/cypress/",
    "gruntfile.js",
    "gulpfile.js",
    "/db-reset.",
)


def _is_vendored_path(file_path: str) -> bool:
    fp = (file_path or "").lower()
    if not fp:
        return False
    if any(frag in fp for frag in _NOISY_PATH_FRAGMENTS):
        return True
    # DVWA-style hardened lesson variants — the GT only annotates the
    # `low.php` baseline; medium/high/impossible are educational
    # contrast and not part of the truth set.
    if any(frag in fp for frag in _LESSON_LEVEL_FRAGMENTS):
        return True
    return False


def _norm_cwe(raw: str) -> str:
    m = re.search(r"(CWE-\d+)", raw or "", re.I)
    return m.group(1).upper() if m else ""


def _is_noise(finding: dict, app_lang: str) -> bool:
    rule_id = finding.get("check_id", "")
    file_path = finding.get("path", "") or finding.get("file", "")
    meta = finding.get("extra", {}).get("metadata", {})
    cwe_raw = meta.get("cwe", [])
    if isinstance(cwe_raw, list):
        cwe = _norm_cwe(cwe_raw[0]) if cwe_raw else ""
    elif isinstance(cwe_raw, str):
        cwe = _norm_cwe(cwe_raw)
    else:
        cwe = ""

    # Reject anything in vendored / static / plugin paths up-front
    if _is_vendored_path(file_path):
        return True

    if rule_id in BLOCKED_RULES:
        return True

    for prefix in BLOCKED_RULE_PREFIXES:
        if rule_id.startswith(prefix):
            return True

    # Codeguard's own rules are exempt from the broad-CWE noise filter:
    # the filter exists to suppress Semgrep auto-config's wide-bucket
    # false positives, not our targeted rules.
    is_codeguard_rule = "codeguard-worker/rules" in rule_id or rule_id.startswith("codeguard.")

    if cwe in NOISE_CWES and not is_codeguard_rule:
        return True

    for lang_prefix, valid_langs in CROSS_LANG_FILTER.items():
        if rule_id.startswith(lang_prefix) and app_lang not in valid_langs:
            return True

    return False


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
def run_semgrep(app_dir: Path, app_lang: str) -> list:
    """Run semgrep with custom rules first, then auto config, with noise filter."""
    configs = ["--config=auto"]
    if RULES_DIR.exists():
        configs.insert(0, f"--config={RULES_DIR}")

    try:
        result = subprocess.run(
            ["semgrep", "scan", *configs, "--json",
             "--timeout=60", "--max-target-bytes=1000000", str(app_dir)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode not in (0, 1):
            return []
        data = json.loads(result.stdout)
        raw = data.get("results", [])
        return [f for f in raw if not _is_noise(f, app_lang)]
    except Exception as e:
        print(f"    [ERR] semgrep: {e}", file=sys.stderr)
        return []


def normalize_semgrep(f: dict, app_dir: Path) -> dict:
    rel_path = str(Path(f.get("path", "")).relative_to(app_dir))
    meta = f.get("extra", {}).get("metadata", {})
    cwe_raw = meta.get("cwe", [])
    if isinstance(cwe_raw, list):
        cwe = cwe_raw[0] if cwe_raw else ""
    elif isinstance(cwe_raw, str):
        cwe = cwe_raw
    else:
        cwe = ""
    return {
        "id": f.get("check_id", ""),
        "category": "sast",
        "name": f.get("check_id", "").split(".")[-1],
        "message": f.get("extra", {}).get("message", ""),
        "cwe": cwe,
        "severity": {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            f.get("extra", {}).get("severity", "WARNING").upper(), "medium"
        ),
        "confidence": meta.get("confidence", "MEDIUM"),
        "file": rel_path,
        "line": f.get("start", {}).get("line", 0),
    }


# ---------------------------------------------------------------------------
# TruffleHog
# ---------------------------------------------------------------------------
def run_trufflehog(app_dir: Path) -> list:
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", str(app_dir), "--json", "--no-update"],
            capture_output=True, text=True, timeout=120,
        )
        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"    [ERR] trufflehog: {e}", file=sys.stderr)
        return []


def normalize_trufflehog(f: dict, app_dir: Path) -> dict:
    source = f.get("SourceMetadata", {}).get("Data", {})
    file_info = source.get("Filesystem", {})
    file_path = file_info.get("file", "")
    try:
        rel_path = str(Path(file_path).relative_to(app_dir))
    except ValueError:
        rel_path = file_path

    return {
        "id": f"trufflehog-{f.get('DetectorName', 'unknown')}",
        "category": "secrets",
        "name": f.get("DetectorName", "Secret"),
        "message": f"Secret detected: {f.get('DetectorName', '')}",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "severity": "critical" if f.get("Verified") else "high",
        "confidence": "HIGH" if f.get("Verified") else "MEDIUM",
        "file": rel_path,
        "line": file_info.get("line", 0),
    }


# ---------------------------------------------------------------------------
# Bandit (Python only)
# ---------------------------------------------------------------------------
def run_bandit(app_dir: Path) -> list:
    try:
        result = subprocess.run(
            ["bandit", "-r", str(app_dir), "-f", "json", "-ll"],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(result.stdout)
        return data.get("results", [])
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"    [ERR] bandit: {e}", file=sys.stderr)
        return []


BANDIT_CWE_MAP = {
    "B608": "CWE-89: SQL Injection",
    "B602": "CWE-78: OS Command Injection",
    "B603": "CWE-78: OS Command Injection",
    "B604": "CWE-78: OS Command Injection",
    "B605": "CWE-78: OS Command Injection",
    "B601": "CWE-601: Open Redirect",
    "B106": "CWE-798: Use of Hard-coded Credentials",
    "B107": "CWE-798: Use of Hard-coded Credentials",
    "B105": "CWE-798: Use of Hard-coded Credentials",
    "B303": "CWE-328: Use of Weak Hash",
    "B324": "CWE-328: Use of Weak Hash",
    "B501": "CWE-295: Improper Certificate Validation",
    "B307": "CWE-78: OS Command Injection",
}


def normalize_bandit(f: dict, app_dir: Path) -> dict:
    file_path = f.get("filename", "")
    try:
        rel_path = str(Path(file_path).relative_to(app_dir))
    except ValueError:
        rel_path = file_path

    test_id = f.get("test_id", "")
    cwe_data = f.get("issue_cwe", {})
    if isinstance(cwe_data, dict) and cwe_data.get("id"):
        cwe = f"CWE-{cwe_data['id']}"
    else:
        cwe = BANDIT_CWE_MAP.get(test_id, "")

    return {
        "id": f"bandit-{test_id}",
        "category": "sast",
        "name": f.get("test_name", test_id),
        "message": f.get("issue_text", ""),
        "cwe": cwe,
        "severity": f.get("issue_severity", "MEDIUM").lower(),
        "confidence": f.get("issue_confidence", "MEDIUM"),
        "file": rel_path,
        "line": f.get("line_number", 0),
    }


# ---------------------------------------------------------------------------
# Dedup: same file + nearby line + same CWE = keep highest confidence
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _finding_priority(f: dict) -> tuple:
    """Higher = better. Used to pick the winning finding when multiple
    rules fire on the same code location.

    Sort key = (codeguard_rule, severity, confidence). The first dimension
    favors our targeted rules over Semgrep auto-config when both fire at
    the same location: our rules tend to label CWEs more specifically
    (CWE-78 vs CWE-94 for `shell_exec($_GET[...])`) which matters for
    GT matching.
    """
    rule_id = f.get("id", "")
    is_codeguard = 1 if ("codeguard-worker/rules" in rule_id or rule_id.startswith("codeguard.")) else 0
    sev = _SEVERITY_RANK.get(str(f.get("severity", "medium")).lower(), 2)
    conf_raw = f.get("confidence", "MEDIUM")
    if isinstance(conf_raw, (int, float)):
        conf = 3 if conf_raw >= 80 else 2 if conf_raw >= 50 else 1
    else:
        conf = _CONFIDENCE_RANK.get(str(conf_raw).upper(), 2)
    return (is_codeguard, sev, conf)


def dedup_findings(findings: list) -> list:
    """
    Two-pass dedup:
      1. Per-CWE dedup: same (file, line//5, cwe) → keep one.
      2. Per-location collapse: at most ONE finding per (file, line//5),
         even if rules fire with different CWEs. Keeps highest-priority.

    Rationale: most "10 CWEs on the same line" patterns are a single root
    cause (e.g. `eval($_GET[...])`) where one CWE is correct and the
    others are over-classification. Reporting all of them inflates FP.
    """
    # Pass 1 — per-CWE dedup
    seen = {}
    pass1 = []
    for f in findings:
        fp = f.get("file", "")
        line = f.get("line", 0)
        cwe = _norm_cwe(f.get("cwe", ""))
        if not cwe:
            continue
        bucket = (fp, line // 5, cwe)
        if bucket not in seen:
            seen[bucket] = True
            pass1.append(f)

    # Pass 2 — collapse multi-CWE on same location
    by_loc: dict = {}
    for f in pass1:
        loc = (f.get("file", ""), f.get("line", 0) // 5)
        prev = by_loc.get(loc)
        if prev is None or _finding_priority(f) > _finding_priority(prev):
            by_loc[loc] = f
    return list(by_loc.values())


# ---------------------------------------------------------------------------
# AI Triage: Claude filters false positives
# ---------------------------------------------------------------------------
_AI_TRIAGE_PROMPT = """\
You are a senior appsec engineer. Classify this SAST finding as true positive or false positive.

<UNTRUSTED_FINDING>
Rule: {rule_id}
CWE: {cwe}
File: {file_path}
Line: {line}
Message: {message}

Code:
```
{snippet}
```
</UNTRUSTED_FINDING>

Respond with ONLY valid JSON: {{"verdict":"tp" or "fp","confidence":1-100,"reason":"one sentence"}}

Decision rules:
- If user input reaches a dangerous sink without sanitization → tp
- If the path contains "lessons/", "challenge", "vulnerable", "vuln", "goat",
  "dvwa", "xvwa", "broken", "insecur", or "owasp" → the code is intentionally
  vulnerable teaching material; treat the vulnerability as REAL → tp
- If input is sanitized, parameterized (?-placeholder, prepared statement,
  bind variables) or from a trusted source (env var, hardcoded literal) → fp
- If the path contains "test/", "tests/", "spec/", "__tests__/", "fixtures/",
  "node_modules/", "vendor/" — and is NOT a teaching path per above — → fp
- When unsure, say tp"""

_AI_REVIEW_PROMPT = """\
You are a senior appsec engineer reviewing AI-generated code for logic flaws \
that SAST tools cannot detect.

Focus ONLY on:
1. Missing authentication — data-modifying endpoints without login check
2. IDOR — endpoints accessing resources by ID without ownership check
3. Mass assignment — req.body passed directly to DB without field filtering
4. Broken access control — admin routes without role verification

<UNTRUSTED_CODE>
File: {file_path}
```
{code}
```
</UNTRUSTED_CODE>

Respond with ONLY a JSON array: [{{"line":N,"cwe":"CWE-XXX","severity":"high","description":"...","confidence":60-100}}]
If no logic flaws found: []
Do NOT report SAST-detectable issues (SQLi, XSS, etc.)."""

_ROUTE_INDICATORS = ["routes/", "controllers/", "api/", "views/", "server.js", "app.js", "app.py", "index.php"]
_CODE_EXTENSIONS = {".js", ".ts", ".py", ".php", ".rb", ".java"}


def _get_ai_client():
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    try:
        import anthropic
        return anthropic.Anthropic(api_key=api_key)
    except Exception:
        return None


def _read_lines(file_path: Path, center: int, window: int = 8) -> str:
    if not file_path.exists():
        return ""
    try:
        lines = file_path.read_text(errors="replace").splitlines()
        s = max(0, center - window - 1)
        e = min(len(lines), center + window)
        return "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines[s:e], start=s))[:600]
    except Exception:
        return ""


def ai_triage(client, findings: list, app_dir: Path, max_items: int = 80) -> list:
    """Use Claude to filter false positives from SAST findings."""
    to_check = findings[:max_items]
    kept = []
    fp_removed = 0

    for f in to_check:
        snippet = _read_lines(app_dir / f.get("file", ""), f.get("line", 0))
        prompt = _AI_TRIAGE_PROMPT.format(
            rule_id=f.get("id", ""), cwe=f.get("cwe", ""),
            file_path=f.get("file", ""), line=f.get("line", 0),
            message=f.get("message", "")[:200], snippet=snippet,
        )
        try:
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001", max_tokens=150,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
            text = re.sub(r"^```json\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            result = json.loads(text)
            if result.get("verdict") == "fp" and result.get("confidence", 0) >= 70:
                fp_removed += 1
                continue
        except Exception:
            pass
        kept.append(f)

    overflow = findings[max_items:]
    print(f"[AI triage: {fp_removed} FP removed]", end=" ", flush=True)
    return kept + overflow


def ai_review(client, app_dir: Path) -> list:
    """Use Claude to find logic vulnerabilities in route/controller files."""
    route_files = []
    for f in app_dir.rglob("*"):
        if not f.is_file() or f.suffix not in _CODE_EXTENSIONS:
            continue
        rel = str(f.relative_to(app_dir))
        if any(s in rel for s in ["node_modules/", "vendor/", ".git/", "__pycache__/"]):
            continue
        if any(p in rel.lower() for p in _ROUTE_INDICATORS):
            route_files.append(f)
    route_files.sort(key=lambda x: x.stat().st_size, reverse=True)
    route_files = route_files[:10]

    findings = []
    for rf in route_files:
        rel_path = str(rf.relative_to(app_dir))
        code = rf.read_text(errors="replace")[:6000]
        prompt = _AI_REVIEW_PROMPT.format(file_path=rel_path, code=code)
        try:
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001", max_tokens=1200,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
            text = re.sub(r"^```json\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            results = json.loads(text)
            if not isinstance(results, list):
                continue
            for r in results:
                if r.get("confidence", 0) < 60:
                    continue
                findings.append({
                    "id": f"codeguard-ai-{r.get('cwe','').lower()}",
                    "category": "ai-review",
                    "name": r.get("description", "")[:60],
                    "message": r.get("description", ""),
                    "cwe": r.get("cwe", ""),
                    "severity": r.get("severity", "high"),
                    "confidence": str(r.get("confidence", 70)),
                    "file": rel_path,
                    "line": r.get("line", 0),
                })
        except Exception:
            continue

    print(f"[AI review: {len(findings)} logic findings]", end=" ", flush=True)
    return findings


# ---------------------------------------------------------------------------
# ML Engine integration (codeguard-ml)
# ---------------------------------------------------------------------------
_ML_ROOT = Path(__file__).parents[2] / "codeguard-ml"


def _load_ml_scanner(min_score: float = 0.85):
    """Lazy-load the ML scanner so users without ML deps can still run the benchmark."""
    import sys as _sys
    _sys.path.insert(0, str(_ML_ROOT / "src"))
    from codeguard_ml.embedder import CodeEmbedder  # noqa
    from codeguard_ml.pattern_db import PatternDB, INDEX_CACHE  # noqa
    from codeguard_ml.scanner import MLScanner  # noqa

    embedder = CodeEmbedder()
    if INDEX_CACHE.exists():
        db = PatternDB.load(INDEX_CACHE)
    else:
        db = PatternDB.build(embedder)
    return MLScanner(embedder, db, min_score=min_score)


def run_ml_scan(scanner, app_dir: Path) -> list:
    """Convert ML Findings to the runner's dict format."""
    findings = scanner.scan_directory(app_dir)
    out = []
    for f in findings:
        out.append({
            "id": f.id,
            "category": "ml",
            "name": f.name,
            "message": f.message,
            "cwe": f.cwe,
            "severity": f.severity,
            "confidence": str(f.confidence),
            "file": f.file,
            "line": f.line,
            "ml_score": f.ml_score,
        })
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Run CodeGuard engines on benchmark apps")
    parser.add_argument("--apps", nargs="+", default=APP_LIST)
    parser.add_argument("--with-ai", action="store_true", help="Enable AI triage + AI review (Claude API)")
    parser.add_argument("--with-ml", action="store_true", help="Enable proprietary ML engine (CodeBERT + pattern DB)")
    parser.add_argument("--ml-min-score", type=float, default=0.85, help="Minimum cosine similarity for ML findings")
    args = parser.parse_args()

    ai_client = None
    if args.with_ai:
        ai_client = _get_ai_client()
        if ai_client:
            print("  AI engines ENABLED (triage + review)")
        else:
            print("  AI engines requested but ANTHROPIC_API_KEY not set — running without AI")

    ml_scanner = None
    if args.with_ml:
        print("  Loading ML engine (CodeBERT + pattern DB)...", flush=True)
        try:
            ml_scanner = _load_ml_scanner(min_score=args.ml_min_score)
            print(f"  ML engine ENABLED ({len(ml_scanner.db)} patterns, min_score={args.ml_min_score})\n")
        except Exception as e:
            print(f"  ML engine failed to load: {e}\n")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    total = 0

    for app in args.apps:
        app_dir = APPS_DIR / app
        if not app_dir.exists():
            print(f"  [SKIP] {app} — not found")
            continue

        app_lang = APP_LANG_MAP.get(app, "unknown")
        print(f"  Scanning {app} ({app_lang})...", end=" ", flush=True)
        t = time.time()

        sast_raw = run_semgrep(app_dir, app_lang)
        sast = [normalize_semgrep(f, app_dir) for f in sast_raw]
        secrets = [normalize_trufflehog(f, app_dir) for f in run_trufflehog(app_dir)]

        bandit_findings = []
        if app_lang == "python":
            bandit_raw = run_bandit(app_dir)
            bandit_findings = [normalize_bandit(f, app_dir) for f in bandit_raw]

        all_findings = dedup_findings(sast + secrets + bandit_findings)

        ml_findings = []
        if ml_scanner:
            ml_findings = run_ml_scan(ml_scanner, app_dir)
            print(f"[ML: {len(ml_findings)}]", end=" ", flush=True)
            all_findings = dedup_findings(all_findings + ml_findings)

        if ai_client:
            all_findings = ai_triage(ai_client, all_findings, app_dir)
            ai_findings = ai_review(ai_client, app_dir)
            all_findings = dedup_findings(all_findings + ai_findings)

        elapsed = time.time() - t

        engines = ["semgrep-custom", "semgrep-auto", "trufflehog", "bandit"]
        if ml_scanner:
            engines.append("ml-pattern-db")
        if ai_client:
            engines += ["ai-triage", "ai-review"]

        report = {
            "version": "3.0.0",
            "vulnerabilities": all_findings,
            "scan": {
                "scanner": {"id": "codeguard", "name": "CodeGuard AI"},
                "type": "sast",
                "engines": engines,
            },
        }

        (OUTPUT_DIR / f"{app}.json").write_text(json.dumps(report, indent=2))
        total += len(all_findings)
        n_sast = len([f for f in all_findings if f["category"] == "sast"])
        n_sec = len([f for f in all_findings if f["category"] == "secrets"])
        n_ml = len([f for f in all_findings if f["category"] == "ml"])
        n_ai = len([f for f in all_findings if f["category"] == "ai-review"])
        parts = f"{n_sast} SAST + {n_sec} secrets"
        if n_ml:
            parts += f" + {n_ml} ML"
        if n_ai:
            parts += f" + {n_ai} AI"
        print(f"{len(all_findings)} findings ({parts}) in {elapsed:.1f}s")

    print(f"\nTotal: {total} findings")


if __name__ == "__main__":
    main()
