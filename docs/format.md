# gl-sast-report.json Format

This document describes the normalized report format used across all tools in the CodeGuard benchmark. Both `convert_semgrep_to_glsast.py` and `convert_codeguard_to_glsast.py` produce this format.

## Schema version

`"schema_version": "1.0.0"`

## Top-level structure

```json
{
  "schema_version": "1.0.0",
  "scanner": {
    "name": "Semgrep CE"
  },
  "vulnerabilities": [ ... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Always `"1.0.0"` for this benchmark |
| `scanner.name` | string | Human-readable tool name |
| `vulnerabilities` | array | List of vulnerability objects |

## Vulnerability object

```json
{
  "id": "SG-1",
  "cwe": "CWE-89",
  "file": "src/routes/tasks.js",
  "line": 14,
  "severity": "High",
  "message": "SQL query built with string concatenation from user-controlled input.",
  "rule_id": "javascript.lang.security.audit.sqli.node-sqlite3.node-sqlite3-sqli",
  "confidence": "HIGH"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Tool-scoped unique ID (e.g. `SG-1`, `CG-42`) |
| `cwe` | string | CWE identifier (e.g. `CWE-89`). `CWE-unknown` when unavailable |
| `file` | string | File path **relative to app root** |
| `line` | integer | Line number of the finding (0 if unknown) |
| `severity` | string | One of: `Critical`, `High`, `Medium`, `Low` |
| `message` | string | Human-readable description, max 300 characters |
| `rule_id` | string | Original rule / check ID from the tool |
| `confidence` | string | Tool-reported confidence: `HIGH`, `MEDIUM`, `LOW` |

## Severity mapping

### Semgrep CE

| Semgrep severity | Normalized severity |
|-----------------|---------------------|
| `ERROR` | `Critical` |
| `WARNING` | `High` |
| `INFO` | `Medium` |

### CodeGuard

| CodeGuard severity | Normalized severity |
|-------------------|---------------------|
| `critical` | `Critical` |
| `high` | `High` |
| `medium` | `Medium` |
| `low` | `Low` |

## Ground truth format

Ground truth files live in `ground-truth/<app>.json` and use a slightly different schema:

```json
[
  {
    "id": "FA-001",
    "file": "app.py",
    "line_start": 27,
    "line_end": 28,
    "cwe": "CWE-89",
    "severity": "High",
    "description": "SQL Injection in /users endpoint ...",
    "poc": "docs/poc/flask-app-sqli-1.md"
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique ID within the app (`<PREFIX>-NNN`) |
| `file` | string | File path relative to app root |
| `line_start` | integer | First line of the vulnerable code block |
| `line_end` | integer | Last line of the vulnerable code block |
| `cwe` | string | CWE identifier |
| `severity` | string | Expected severity |
| `description` | string | Human description of the vulnerability |
| `poc` | string or null | Path to proof-of-concept document |

## Matching rules (evaluator)

A tool finding is considered a **True Positive** when all three conditions hold:

1. **File**: the finding's `file` path ends with (or is ended by) the GT `file` path
2. **CWE**: the finding's `cwe` matches the GT `cwe` (case-insensitive)
3. **Line**: `|finding.line - gt.line_start| <= LINE_TOLERANCE` (default: 10)

If a finding matches no GT entry it is counted as a **False Positive**.
GT entries with no matching finding are counted as **False Negatives**.
