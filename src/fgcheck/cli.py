from __future__ import annotations
import argparse
from collections import Counter
from pathlib import Path

from rich.console import Console

from .parse import parse_fortios_text
from .rules import run
from .report import finding_to_dict, findings_to_json, findings_to_markdown, scan_to_json
from .versioning import resolve_target_fortios

def main():
    ap = argparse.ArgumentParser(prog="fgcheck")
    ap.add_argument("config", help="FortiOS text config .conf or folder containing .conf files")
    ap.add_argument("--rules", nargs="+", default=[
        "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        "rules/builtin/FGT-ADMIN-EDGE-HTTPS.yaml",
        "rules/builtin/FGT-POLICY-LOG-001.yaml",
    ])
    ap.add_argument("--format", choices=["json", "md"], default="md")
    ap.add_argument("--vdom", action="append", default=None, help="Specify vdom(s). Can repeat.")
    ap.add_argument("--fortios", default=None, help="Target FortiOS version (e.g. 7.4, 7.6, 7.6.6).")
    args = ap.parse_args()

    config_path = Path(args.config)
    if config_path.is_dir():
        files = sorted(config_path.rglob("*.conf"))
    else:
        files = [config_path]

    console = Console()
    if not config_path.is_dir():
        text = config_path.read_text(encoding="utf-8", errors="replace")
        model, warnings = parse_fortios_text(text, file_id=config_path.name)
        target_fortios, version_warnings = resolve_target_fortios(model, explicit_version=args.fortios)
        model.meta["target_fortios"] = target_fortios
        findings = run(model, vdoms=args.vdom, rule_files=args.rules, fortios_version=target_fortios)

        if version_warnings:
            for vw in version_warnings:
                if vw == "version_defaulted":
                    console.print("[yellow]Warning:[/yellow] version_defaulted (using 7.4)")
                else:
                    console.print(f"[yellow]Warning:[/yellow] {vw}")
        if warnings:
            console.print(f"[yellow]Parse warnings:[/yellow] {len(warnings)}")
            for w in warnings[:30]:
                console.print(f"  - {w.code} line {w.line_no}: {w.message}")
            if len(warnings) > 30:
                console.print(f"  ... {len(warnings)-30} more")

        if args.format == "json":
            print(findings_to_json(findings))
        else:
            print(findings_to_markdown(findings))
        return

    file_reports = []
    total_warnings = 0
    total_findings = 0
    severity_counts = Counter()
    confidence_counts = Counter()
    for file_path in files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        model, warnings = parse_fortios_text(text, file_id=file_path.name)
        target_fortios, version_warnings = resolve_target_fortios(model, explicit_version=args.fortios)
        model.meta["target_fortios"] = target_fortios
        findings = run(model, vdoms=args.vdom, rule_files=args.rules, fortios_version=target_fortios)
        total_warnings += len(warnings)
        total_findings += len(findings)
        for f in findings:
            severity_counts[f.severity] += 1
            confidence_counts[f.confidence] += 1

        file_reports.append(
            {
                "file": str(file_path),
                "target_fortios": target_fortios,
                "version_warnings": version_warnings,
                "parse_warnings": [{"code": w.code, "line_no": w.line_no, "message": w.message} for w in warnings],
                "findings": [finding_to_dict(f) for f in findings],
            }
        )

    summary = {
        "files": len(files),
        "findings": total_findings,
        "parse_warnings": total_warnings,
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
        "certain": confidence_counts.get("certain", 0),
        "likely": confidence_counts.get("likely", 0),
        "heuristic": confidence_counts.get("heuristic", 0),
    }

    if args.format == "json":
        print(scan_to_json(file_reports, summary))
    else:
        out = ["# FortiGate Config Check Folder Report\n\n"]
        out.append(f"Scanned {summary['files']} file(s), findings={summary['findings']}, parse_warnings={summary['parse_warnings']}.\n\n")
        for report in file_reports:
            out.append(f"## {Path(str(report['file'])).name}\n\n")
            out.append(f"- target_fortios: `{report['target_fortios']}`\n")
            out.append(f"- parse_warnings: `{len(report['parse_warnings'])}`\n")
            out.append(f"- findings: `{len(report['findings'])}`\n\n")
        print("".join(out))
