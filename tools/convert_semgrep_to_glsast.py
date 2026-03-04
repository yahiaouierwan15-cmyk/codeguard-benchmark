#!/usr/bin/env python3
"""Convert native Semgrep JSON output to gl-sast-report.json format."""
import json
import sys
import argparse
from pathlib import Path

SEVERITY_MAP = {
    "ERROR": "Critical",
    "WARNING": "High",
    "INFO": "Medium",
}

CWE_MAP = {
    "CWE-89": "CWE-89",
    "CWE-79": "CWE-79",
    "CWE-22": "CWE-22",
    "CWE-78": "CWE-78",
    "CWE-918": "CWE-918",
    "CWE-611": "CWE-611",
    "CWE-943": "CWE-943",
    "CWE-798": "CWE-798",
    "CWE-1333": "CWE-1333",
    "CWE-95": "CWE-95",
    "CWE-532": "CWE-532",
    "CWE-502": "CWE-502",
}


def extract_cwe(metadata: dict) -> str:
    """Extract and normalize CWE to 'CWE-NNN' format."""
    import re
    cwe = metadata.get("cwe", "")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    if not cwe:
        return "CWE-unknown"
    # Normalize: extract just 'CWE-NNN' from longer strings
    m = re.search(r"(CWE-\d+)", str(cwe), re.IGNORECASE)
    return m.group(1).upper() if m else str(cwe).split(":")[0].strip()


def convert(semgrep_json: dict, app_root: str, scanner_name: str = "Semgrep CE") -> dict:
    vulnerabilities = []
    for i, r in enumerate(semgrep_json.get("results", [])):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        raw_path = r.get("path", "")
        # Make path relative to app root
        if app_root and raw_path.startswith(app_root):
            rel_path = raw_path[len(app_root):].lstrip("/")
        else:
            rel_path = raw_path

        severity_raw = extra.get("severity", "INFO")
        cwe = extract_cwe(meta)
        owasp = meta.get("owasp", "")
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else ""

        vulnerabilities.append({
            "id": f"SG-{i+1}",
            "cwe": cwe,
            "file": rel_path,
            "line": r.get("start", {}).get("line", 0),
            "severity": SEVERITY_MAP.get(severity_raw, "Medium"),
            "message": extra.get("message", r.get("check_id", ""))[:300],
            "rule_id": r.get("check_id", ""),
            "confidence": meta.get("confidence", "MEDIUM"),
        })

    return {
        "schema_version": "1.0.0",
        "scanner": {"name": scanner_name},
        "vulnerabilities": vulnerabilities,
    }


def main():
    parser = argparse.ArgumentParser(description="Convert Semgrep JSON to gl-sast-report format")
    parser.add_argument("input", help="Semgrep JSON output file (- for stdin)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--app-root", default="", help="App root path to strip from file paths")
    parser.add_argument("--scanner-name", default="Semgrep CE")
    args = parser.parse_args()

    if args.input == "-":
        data = json.load(sys.stdin)
    else:
        with open(args.input) as f:
            data = json.load(f)

    result = convert(data, args.app_root, args.scanner_name)

    out = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(out)
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
