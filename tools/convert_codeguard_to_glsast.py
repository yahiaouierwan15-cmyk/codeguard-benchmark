#!/usr/bin/env python3
"""Convert CodeGuard native NDJSON output to gl-sast-report.json format."""
import json
import sys
import argparse
from pathlib import Path

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def convert(findings: list, app_root: str) -> dict:
    vulnerabilities = []
    for i, f in enumerate(findings):
        raw_path = f.get("file_path", "")
        if app_root and raw_path.startswith(app_root):
            rel_path = raw_path[len(app_root):].lstrip("/")
        else:
            rel_path = raw_path

        cwe = f.get("cwe_id", "CWE-unknown")
        if not cwe or cwe == "None":
            cwe = "CWE-unknown"

        vulnerabilities.append({
            "id": f"CG-{i+1}",
            "cwe": cwe,
            "file": rel_path,
            "line": f.get("line_start") or 0,
            "severity": SEVERITY_MAP.get(f.get("severity", "medium"), "Medium"),
            "message": f.get("title", f.get("rule_id", ""))[:300],
            "rule_id": f.get("rule_id", ""),
            "confidence": f.get("confidence", "MEDIUM"),
        })

    return {
        "schema_version": "1.0.0",
        "scanner": {"name": "CodeGuard"},
        "vulnerabilities": vulnerabilities,
    }


def main():
    parser = argparse.ArgumentParser(description="Convert CodeGuard NDJSON to gl-sast-report format")
    parser.add_argument("input", help="CodeGuard NDJSON file (- for stdin)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--app-root", default="", help="App root path to strip from file paths")
    args = parser.parse_args()

    if args.input == "-":
        lines = sys.stdin.read().strip().splitlines()
    else:
        lines = Path(args.input).read_text().strip().splitlines()

    findings = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    result = convert(findings, args.app_root)
    out = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(out)
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
