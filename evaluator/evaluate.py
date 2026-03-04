#!/usr/bin/env python3
"""
CodeGuard Benchmark Evaluator
==============================
Compares SAST tool reports (CodeGuard, Semgrep CE) against ground-truth
vulnerability data and computes per-app, per-language, per-CWE, and global
precision / recall / F1 metrics.

Usage:
    python3 evaluator/evaluate.py
    python3 evaluator/evaluate.py --line-tolerance 15
    python3 evaluator/evaluate.py --tools codeguard semgrep
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

GROUND_TRUTH_DIR = REPO_ROOT / "ground-truth"
REPORTS_BASE_DIR = REPO_ROOT / "reports"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"

APP_LANG_MAP = {
    "webgoat": "java",
    "nodegoat": "javascript",
    "dvwa": "php",
    "flask-app": "python",
    "real-app-nodejs": "javascript",
    "real-app-python": "python",
    "real-app-php": "php",
}

ALL_APPS = list(APP_LANG_MAP.keys())
ALL_TOOLS = ["codeguard", "semgrep"]

LINE_TOLERANCE = 10  # lines ± to accept a finding as matching a GT entry


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def load_ground_truth(app: str) -> list:
    """Load ground-truth entries for a given app. Returns [] if file missing."""
    gt_file = GROUND_TRUTH_DIR / f"{app}.json"
    if not gt_file.exists():
        print(f"  [WARN] Ground truth not found: {gt_file}", file=sys.stderr)
        return []
    with open(gt_file) as f:
        return json.load(f)


def load_report(tool: str, app: str) -> list:
    """Load normalized gl-sast-report findings for a tool+app. Returns [] if missing."""
    report_file = REPORTS_BASE_DIR / tool / f"{app}.json"
    if not report_file.exists():
        return []
    with open(report_file) as f:
        data = json.load(f)
    return data.get("vulnerabilities", [])


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def normalize_path(path: str) -> str:
    """Normalize a file path for comparison (lowercase, strip leading slashes)."""
    return path.lstrip("/").lower()


def finding_matches_gt(finding: dict, gt_entry: dict, line_tolerance: int) -> bool:
    """
    Return True if a finding matches a ground-truth entry using 3 criteria:
      1. File path match (suffix / endswith check)
      2. CWE match
      3. Line number within ±line_tolerance of gt line_start
    """
    gt_file = normalize_path(gt_entry.get("file", ""))
    f_file = normalize_path(finding.get("file", ""))

    # File: one must be a suffix of the other (handles relative vs absolute)
    if not (f_file.endswith(gt_file) or gt_file.endswith(f_file)):
        return False

    # CWE
    gt_cwe = gt_entry.get("cwe", "")
    f_cwe = finding.get("cwe", "")
    if gt_cwe and f_cwe and gt_cwe.upper() != f_cwe.upper():
        return False

    # Line number
    gt_line = gt_entry.get("line_start", 0)
    f_line = finding.get("line", 0)
    if gt_line and f_line:
        if abs(f_line - gt_line) > line_tolerance:
            return False

    return True


def match_findings(findings: list, gt_entries: list, line_tolerance: int) -> tuple:
    """
    Match findings against GT entries.
    Returns:
        (tp_findings, fp_findings, fn_gt_entries, tp_gt_ids)
    """
    matched_gt = set()  # indices of matched GT entries
    tp_findings = []
    fp_findings = []

    for finding in findings:
        matched = False
        for j, gt_entry in enumerate(gt_entries):
            if j in matched_gt:
                continue
            if finding_matches_gt(finding, gt_entry, line_tolerance):
                matched_gt.add(j)
                matched = True
                tp_findings.append({"finding": finding, "gt": gt_entry})
                break
        if not matched:
            fp_findings.append(finding)

    fn_gt_entries = [gt_entries[j] for j in range(len(gt_entries)) if j not in matched_gt]
    return tp_findings, fp_findings, fn_gt_entries, {gt_entries[j]["id"] for j in matched_gt}


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(tp: int, fp: int, fn: int) -> dict:
    """Compute precision, recall, F1 from TP/FP/FN counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def evaluate(tools: list, line_tolerance: int) -> dict:
    """
    Run full evaluation across all apps and tools.
    Returns a nested dict: results[tool][app] = {metrics, tp_findings, fp_findings, fn_gt}
    """
    results = {}

    for tool in tools:
        results[tool] = {}
        for app in ALL_APPS:
            gt_entries = load_ground_truth(app)
            findings = load_report(tool, app)

            tp_findings, fp_findings, fn_gt_entries, _ = match_findings(
                findings, gt_entries, line_tolerance
            )

            tp = len(tp_findings)
            fp = len(fp_findings)
            fn = len(fn_gt_entries)

            results[tool][app] = {
                "metrics": compute_metrics(tp, fp, fn),
                "tp_findings": tp_findings,
                "fp_findings": fp_findings,
                "fn_gt": fn_gt_entries,
                "gt_total": len(gt_entries),
                "findings_total": len(findings),
            }

    return results


def aggregate_by_language(results: dict) -> dict:
    """Aggregate TP/FP/FN by language for each tool."""
    lang_agg = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))

    for tool, apps in results.items():
        for app, data in apps.items():
            lang = APP_LANG_MAP.get(app, "unknown")
            m = data["metrics"]
            lang_agg[tool][lang]["tp"] += m["tp"]
            lang_agg[tool][lang]["fp"] += m["fp"]
            lang_agg[tool][lang]["fn"] += m["fn"]

    # Compute derived metrics
    out = {}
    for tool, langs in lang_agg.items():
        out[tool] = {}
        for lang, counts in langs.items():
            out[tool][lang] = compute_metrics(counts["tp"], counts["fp"], counts["fn"])
    return out


def aggregate_by_cwe(results: dict, all_tools: list) -> dict:
    """Aggregate TP/FP/FN by CWE for each tool using GT data for FN CWE lookup."""
    cwe_agg = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))

    for tool, apps in results.items():
        for app, data in apps.items():
            for tp in data["tp_findings"]:
                cwe = tp["gt"].get("cwe", "CWE-unknown")
                cwe_agg[tool][cwe]["tp"] += 1
            for fp in data["fp_findings"]:
                cwe = fp.get("cwe", "CWE-unknown")
                cwe_agg[tool][cwe]["fp"] += 1
            for fn_gt in data["fn_gt"]:
                cwe = fn_gt.get("cwe", "CWE-unknown")
                cwe_agg[tool][cwe]["fn"] += 1

    out = {}
    for tool, cwes in cwe_agg.items():
        out[tool] = {}
        for cwe, counts in cwes.items():
            out[tool][cwe] = compute_metrics(counts["tp"], counts["fp"], counts["fn"])
    return out


def aggregate_global(results: dict) -> dict:
    """Compute global TP/FP/FN totals for each tool."""
    out = {}
    for tool, apps in results.items():
        total_tp = sum(d["metrics"]["tp"] for d in apps.values())
        total_fp = sum(d["metrics"]["fp"] for d in apps.values())
        total_fn = sum(d["metrics"]["fn"] for d in apps.values())
        out[tool] = compute_metrics(total_tp, total_fp, total_fn)
    return out


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_comparison_table(results: dict, global_agg: dict, lang_agg: dict) -> None:
    """Print a formatted comparison table to stdout."""
    tools = list(results.keys())
    col_w = 14

    def row(*cells):
        print("  ".join(str(c).ljust(col_w) for c in cells))

    def separator(n_cols):
        print("-" * (col_w * n_cols + 2 * (n_cols - 1)))

    print()
    print("=" * 70)
    print("  CODEGUARD BENCHMARK — EVALUATION RESULTS")
    print("=" * 70)

    # Per-app table
    print()
    print("PER-APP RESULTS")
    separator(1 + len(tools) * 3)
    row("App", *[f"{t.upper()} P/R/F1" for t in tools])
    separator(1 + len(tools) * 3)
    for app in ALL_APPS:
        cells = [app]
        for tool in tools:
            m = results[tool][app]["metrics"]
            cells.append(
                f"{m['precision']:.0%} / {m['recall']:.0%} / {m['f1']:.0%}"
            )
        row(*cells)
    separator(1 + len(tools) * 3)

    # Per-language table
    print()
    print("PER-LANGUAGE RESULTS")
    langs = sorted(set(APP_LANG_MAP.values()))
    separator(1 + len(tools) * 3)
    row("Language", *[f"{t.upper()} P/R/F1" for t in tools])
    separator(1 + len(tools) * 3)
    for lang in langs:
        cells = [lang]
        for tool in tools:
            m = lang_agg.get(tool, {}).get(lang, {"precision": 0, "recall": 0, "f1": 0})
            cells.append(
                f"{m['precision']:.0%} / {m['recall']:.0%} / {m['f1']:.0%}"
            )
        row(*cells)
    separator(1 + len(tools) * 3)

    # Global totals
    print()
    print("GLOBAL TOTALS")
    separator(1 + len(tools) * 4)
    row("Tool", "TP", "FP", "FN", "Precision", "Recall", "F1")
    separator(1 + len(tools) * 4)
    for tool in tools:
        m = global_agg[tool]
        row(tool.upper(), m["tp"], m["fp"], m["fn"],
            f"{m['precision']:.1%}", f"{m['recall']:.1%}", f"{m['f1']:.1%}")
    separator(1 + len(tools) * 4)
    print()


def write_csv_per_app(results: dict, output_dir: Path) -> None:
    """Write per-app metrics CSV for each tool."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for tool, apps in results.items():
        csv_path = output_dir / f"{tool}_per_app.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["app", "language", "gt_total", "findings_total",
                               "tp", "fp", "fn", "precision", "recall", "f1"]
            )
            writer.writeheader()
            for app, data in apps.items():
                m = data["metrics"]
                writer.writerow({
                    "app": app,
                    "language": APP_LANG_MAP.get(app, "unknown"),
                    "gt_total": data["gt_total"],
                    "findings_total": data["findings_total"],
                    **m,
                })
        print(f"  Written: {csv_path}")


def write_csv_by_cwe(cwe_agg: dict, output_dir: Path) -> None:
    """Write per-CWE metrics CSV."""
    output_dir.mkdir(parents=True, exist_ok=True)
    # Collect all CWEs across tools
    all_cwes = set()
    for tool_data in cwe_agg.values():
        all_cwes.update(tool_data.keys())

    csv_path = output_dir / "cwe_comparison.csv"
    with open(csv_path, "w", newline="") as f:
        fieldnames = ["cwe"]
        for tool in cwe_agg:
            fieldnames += [f"{tool}_tp", f"{tool}_fp", f"{tool}_fn",
                           f"{tool}_precision", f"{tool}_recall", f"{tool}_f1"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for cwe in sorted(all_cwes):
            row = {"cwe": cwe}
            for tool, data in cwe_agg.items():
                m = data.get(cwe, {"tp": 0, "fp": 0, "fn": 0, "precision": 0, "recall": 0, "f1": 0})
                row[f"{tool}_tp"] = m["tp"]
                row[f"{tool}_fp"] = m["fp"]
                row[f"{tool}_fn"] = m["fn"]
                row[f"{tool}_precision"] = m["precision"]
                row[f"{tool}_recall"] = m["recall"]
                row[f"{tool}_f1"] = m["f1"]
            writer.writerow(row)
    print(f"  Written: {csv_path}")


def write_metrics_json(global_agg: dict, lang_agg: dict, cwe_agg: dict, output_dir: Path) -> None:
    """Write a consolidated metrics.json with all aggregations."""
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics = {
        "global": global_agg,
        "by_language": lang_agg,
        "by_cwe": cwe_agg,
    }
    json_path = output_dir / "metrics.json"
    json_path.write_text(json.dumps(metrics, indent=2))
    print(f"  Written: {json_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate SAST tools against benchmark ground truth"
    )
    parser.add_argument(
        "--tools", nargs="+", default=ALL_TOOLS,
        help=f"Tools to evaluate (default: {' '.join(ALL_TOOLS)})"
    )
    parser.add_argument(
        "--line-tolerance", type=int, default=LINE_TOLERANCE,
        help=f"Line number tolerance for matching (default: {LINE_TOLERANCE})"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=OUTPUT_DIR,
        help="Directory for CSV and JSON output"
    )
    args = parser.parse_args()

    print(f"Evaluating tools: {', '.join(args.tools)}")
    print(f"Line tolerance: ±{args.line_tolerance}")
    print(f"Output dir: {args.output_dir}")
    print()

    results = evaluate(args.tools, args.line_tolerance)
    global_agg = aggregate_global(results)
    lang_agg = aggregate_by_language(results)
    cwe_agg = aggregate_by_cwe(results, args.tools)

    print_comparison_table(results, global_agg, lang_agg)

    print("Writing output files...")
    write_csv_per_app(results, args.output_dir)
    write_csv_by_cwe(cwe_agg, args.output_dir)
    write_metrics_json(global_agg, lang_agg, cwe_agg, args.output_dir)

    print()
    print("Evaluation complete.")


if __name__ == "__main__":
    main()
