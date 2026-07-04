from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from collections import Counter
from pathlib import Path

from rich.console import Console

from .authority import lookup_authority, render_authority_human, render_authority_json
from .baseline import (
    finding_to_record,
    load_baseline_matchers,
    matches_record,
    merge_baseline_records,
    write_baseline_records,
)
from .parse import parse_fortios_text
from .report import (
    finding_to_dict,
    findings_to_html,
    findings_to_human,
    findings_to_json,
    findings_to_markdown,
    scan_to_html,
    scan_to_human,
    scan_to_json,
    write_pdf_from_html,
)
from .rules import run
from .sarif import findings_to_sarif
from .versioning import resolve_target_fortios

DEFAULT_RULE_FILES = sorted(str(p).replace("\\", "/") for p in (Path("rules") / "builtin").glob("*.yaml"))

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 99)


def _highest_severity(findings) -> str:
    if not findings:
        return "none"
    ranked = sorted((str(f.severity) for f in findings), key=_severity_rank)
    return ranked[0] if ranked else "none"


def _should_fail_on_severity(findings, threshold: str | None) -> bool:
    if not threshold:
        return False
    threshold_rank = _severity_rank(threshold)
    return any(_severity_rank(str(f.severity)) <= threshold_rank for f in findings)


def authority_main(argv: list[str]) -> None:
    command = argv[0]
    ap = argparse.ArgumentParser(prog=f"fgcheck {command}")
    ap.add_argument("query", help="FortiOS table, command, or field to validate.")
    ap.add_argument("--fortios", default="7.6", help="Target FortiOS version, for example 7.4, 7.6, or 7.6.6.")
    ap.add_argument("--format", choices=["json", "human"], default="human")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero unless validation is fully validated.")
    args = ap.parse_args(argv[1:])

    result = lookup_authority(args.query, fortios=args.fortios, base_dir=Path("."))
    if command == "schema" and result.matched_table is None:
        result.warnings = (result.warnings or []) + ["schema_command_expected_table_match"]
    if command == "docs" and result.source_url is None:
        result.warnings = (result.warnings or []) + ["docs_command_found_no_source_url"]

    if args.format == "json":
        print(render_authority_json(result), end="")
    else:
        print(render_authority_human(result), end="")

    if args.strict and result.validation_result != "VALIDATED":
        raise SystemExit(2)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"lookup", "schema", "docs"}:
        return authority_main(sys.argv[1:])
    if len(sys.argv) > 1 and sys.argv[1] == "compliance":
        from .compliance import compliance_main

        return compliance_main(sys.argv[2:])

    ap = argparse.ArgumentParser(prog="fgcheck")
    ap.add_argument("config", help="FortiOS text config .conf or folder containing .conf files")
    ap.add_argument("--rules", nargs="+", default=DEFAULT_RULE_FILES)
    ap.add_argument("--format", choices=["json", "md", "human", "html", "sarif"], default="md")
    ap.add_argument("--output", default=None, help="Write report output to a file path.")
    ap.add_argument("--pdf-output", default=None, help="Write rendered HTML report to PDF (requires weasyprint).")
    ap.add_argument("--summary-output", default=None, help="Write run summary JSON to a file path.")
    ap.add_argument("--findings-csv-output", default=None, help="Write unsuppressed findings to CSV.")
    ap.add_argument("--report-title", default=None, help="Override report title for human/html outputs.")
    ap.add_argument("--quiet", action="store_true", help="Do not print report output to stdout.")
    ap.add_argument("--baseline", default=None, help="JSON baseline matcher file to suppress known findings.")
    ap.add_argument("--write-baseline", default=None, help="Write current finding signatures to a JSON baseline file.")
    ap.add_argument("--baseline-update", action="store_true", help="Merge current findings into the --baseline file.")
    ap.add_argument("--new-findings-output", default=None, help="Write unsuppressed finding signatures to JSON.")
    ap.add_argument("--baseline-strict", action="store_true", help="Exit non-zero if unsuppressed findings remain.")
    ap.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Exit non-zero if unsuppressed findings are at or above the severity threshold.",
    )
    ap.add_argument("--vdom", action="append", default=None, help="Specify vdom(s). Can repeat.")
    ap.add_argument("--fortios", default=None, help="Target FortiOS version (e.g. 7.4, 7.6, 7.6.6).")
    ap.add_argument(
        "--max-size",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum config file size in bytes (default: 10485760 = 10 MB). Files exceeding this limit are skipped.",
    )
    args = ap.parse_args()
    if args.baseline_strict and not args.baseline:
        ap.error("--baseline-strict requires --baseline")
    if args.baseline_update and not args.baseline:
        ap.error("--baseline-update requires --baseline")
    if args.pdf_output and args.format != "html":
        ap.error("--pdf-output requires --format html")

    config_path = Path(args.config)
    if config_path.is_dir():
        files = sorted(config_path.rglob("*.conf"))
    else:
        files = [config_path]
    baseline_matchers = load_baseline_matchers(args.baseline) if args.baseline else []

    def emit(text: str) -> None:
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
        if not args.quiet:
            print(text)

    def write_json(path: str, payload: object) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def write_csv(path: str, records: list[dict]) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = ["rule_id", "severity", "confidence", "vdom", "message", "file_id", "line_start", "line_end"]
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                writer.writerow({k: rec.get(k, "") for k in fieldnames})

    console = Console()
    _log = logging.getLogger("fgcheck")

    def _check_file_size(file_path: Path) -> str | None:
        """Return None if file is within --max-size; otherwise log and return a skip reason."""
        try:
            size = file_path.stat().st_size
        except OSError as exc:
            return f"cannot stat file: {exc}"
        if size > args.max_size:
            return f"{file_path.name} is {size:,} bytes which exceeds --max-size limit of {args.max_size:,} bytes"
        if size > args.max_size * 0.8:
            _log.warning(
                "%s is %d bytes (%.0f%% of --max-size limit)",
                file_path.name,
                size,
                100 * size / args.max_size,
            )
        return None

    if not config_path.is_dir():
        skip_reason = _check_file_size(config_path)
        if skip_reason:
            console.print(f"[yellow]Skipping {config_path.name}:[/yellow] {skip_reason}")
            return
        text = config_path.read_text(encoding="utf-8", errors="replace")
        model, warnings = parse_fortios_text(text, file_id=config_path.name)
        target_fortios, version_warnings = resolve_target_fortios(model, explicit_version=args.fortios)
        model.meta["target_fortios"] = target_fortios
        findings = run(model, vdoms=args.vdom, rule_files=args.rules, fortios_version=target_fortios)
        finding_records = [finding_to_record(f) for f in findings]
        suppressed = 0
        if args.write_baseline:
            write_baseline_records(args.write_baseline, finding_records)
        if args.baseline_update and args.baseline:
            merge_baseline_records(args.baseline, finding_records)
        if baseline_matchers:
            filtered_findings = []
            for f, rec in zip(findings, finding_records, strict=False):
                if any(matches_record(rec, m) for m in baseline_matchers):
                    suppressed += 1
                    continue
                filtered_findings.append(f)
            findings = filtered_findings
        if args.new_findings_output:
            write_json(args.new_findings_output, [finding_to_record(f) for f in findings])
        if args.findings_csv_output:
            write_csv(args.findings_csv_output, [finding_to_record(f) for f in findings])

        single_summary = {
            "files": 1,
            "findings_total": len(findings) + suppressed,
            "findings": len(findings),
            "parse_warnings": len(warnings),
            "suppressed": suppressed,
            "highest_severity": _highest_severity(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
            "certain": sum(1 for f in findings if f.confidence == "certain"),
            "likely": sum(1 for f in findings if f.confidence == "likely"),
            "heuristic": sum(1 for f in findings if f.confidence == "heuristic"),
        }
        if args.summary_output:
            write_json(
                args.summary_output,
                {
                    "summary": single_summary,
                    "file": str(config_path),
                    "target_fortios": target_fortios,
                },
            )

        if version_warnings:
            for vw in version_warnings:
                if vw == "version_defaulted":
                    console.print("[yellow]Warning:[/yellow] version_defaulted (using 7.4)")
                else:
                    console.print(f"[yellow]Warning:[/yellow] {vw}")
        if model.meta.get("fortimanager_config"):
            console.print(
                "[yellow]Warning:[/yellow] Config appears to be managed by FortiManager. "
                "The exported configuration may not reflect the effective running "
                "configuration on the device."
            )
        if warnings:
            console.print(f"[yellow]Parse warnings:[/yellow] {len(warnings)}")
            for w in warnings[:30]:
                console.print(f"  - {w.code} line {w.line_no}: {w.message}")
            if len(warnings) > 30:
                console.print(f"  ... {len(warnings) - 30} more")

        if args.format == "json":
            rendered = findings_to_json(findings)
        elif args.format == "human":
            rendered = findings_to_human(
                findings,
                title=args.report_title or f"FortiGate Findings: {config_path.name}",
                suppressed=suppressed,
            )
        elif args.format == "html":
            rendered = findings_to_html(
                findings,
                title=args.report_title or f"FortiGate Findings: {config_path.name}",
                suppressed=suppressed,
            )
        elif args.format == "sarif":
            rendered = findings_to_sarif(findings)
        else:
            rendered = findings_to_markdown(findings)
        emit(rendered)
        if args.pdf_output:
            write_pdf_from_html(rendered, args.pdf_output)
        if args.baseline_strict and findings:
            raise SystemExit(2)
        if _should_fail_on_severity(findings, args.fail_on_severity):
            raise SystemExit(3)
        return

    file_reports = []
    total_warnings = 0
    total_findings = 0
    total_suppressed = 0
    severity_counts = Counter()
    confidence_counts = Counter()
    baseline_records = []
    new_records = []
    for file_path in files:
        skip_reason = _check_file_size(file_path)
        if skip_reason:
            console.print(f"[yellow]Skipping {file_path.name}:[/yellow] {skip_reason}")
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        model, warnings = parse_fortios_text(text, file_id=file_path.name)
        if model.meta.get("fortimanager_config"):
            console.print(
                f"[yellow]Warning:[/yellow] {file_path.name}: Config appears to be managed by "
                f"FortiManager. The exported configuration may not reflect the effective "
                f"running configuration on the device."
            )
        target_fortios, version_warnings = resolve_target_fortios(model, explicit_version=args.fortios)
        model.meta["target_fortios"] = target_fortios
        findings = run(model, vdoms=args.vdom, rule_files=args.rules, fortios_version=target_fortios)
        finding_records = [finding_to_record(f) for f in findings]
        baseline_records.extend(finding_records)
        if baseline_matchers:
            filtered_findings = []
            suppressed_for_file = 0
            for f, rec in zip(findings, finding_records, strict=False):
                if any(matches_record(rec, m) for m in baseline_matchers):
                    suppressed_for_file += 1
                    continue
                filtered_findings.append(f)
            findings = filtered_findings
            total_suppressed += suppressed_for_file
        new_records.extend(finding_to_record(f) for f in findings)
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
    if args.write_baseline:
        write_baseline_records(args.write_baseline, baseline_records)
    if args.baseline_update and args.baseline:
        merge_baseline_records(args.baseline, baseline_records)
    if args.new_findings_output:
        write_json(args.new_findings_output, new_records)
    if args.findings_csv_output:
        write_csv(args.findings_csv_output, new_records)

    summary = {
        "files": len(files),
        "findings_total": total_findings + total_suppressed,
        "findings": total_findings,
        "parse_warnings": total_warnings,
        "suppressed": total_suppressed,
        "highest_severity": (
            next(
                (sev for sev in ["critical", "high", "medium", "low", "info"] if severity_counts.get(sev, 0) > 0),
                "none",
            )
        ),
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
        "certain": confidence_counts.get("certain", 0),
        "likely": confidence_counts.get("likely", 0),
        "heuristic": confidence_counts.get("heuristic", 0),
    }
    if args.summary_output:
        write_json(args.summary_output, {"summary": summary})

    if args.format == "json":
        rendered = scan_to_json(file_reports, summary)
    elif args.format == "human":
        rendered = scan_to_human(file_reports, summary, title=args.report_title or "FortiGate Folder Scan")
    elif args.format == "html":
        rendered = scan_to_html(file_reports, summary, title=args.report_title or "FortiGate Folder Scan")
    elif args.format == "sarif":
        # For folder scans, flatten all findings from all files into one SARIF run.
        all_findings = []
        for report in file_reports:
            for fd in report.get("findings", []):
                from .model import Evidence as _Evidence
                from .rules import Finding as _Finding

                evts = []
                for ev_dict in fd.get("evidence", []):
                    evts.append(
                        _Evidence(
                            file_id=str(ev_dict.get("file_id", "")),
                            line_range=tuple(ev_dict.get("line_range", [1, 1])),
                            path=tuple(ev_dict.get("path", [])),
                            raw_lines=list(ev_dict.get("raw_lines", [])),
                        )
                    )
                all_findings.append(
                    _Finding(
                        rule_id=str(fd.get("rule_id", "")),
                        title=str(fd.get("title", "")),
                        severity=str(fd.get("severity", "")),
                        confidence=str(fd.get("confidence", "")),
                        vdom=str(fd.get("vdom", "")),
                        message=str(fd.get("message", "")),
                        evidence=evts,
                    )
                )
        rendered = findings_to_sarif(all_findings)
    else:
        out = ["# FortiGate Config Check Folder Report\n\n"]
        out.append(
            "Scanned "
            f"{summary['files']} file(s), findings={summary['findings']}, "
            f"findings_total={summary['findings_total']}, suppressed={summary['suppressed']}, "
            f"parse_warnings={summary['parse_warnings']}.\n\n"
        )
        for report in file_reports:
            out.append(f"## {Path(str(report['file'])).name}\n\n")
            out.append(f"- target_fortios: `{report['target_fortios']}`\n")
            out.append(f"- parse_warnings: `{len(report['parse_warnings'])}`\n")
            out.append(f"- findings: `{len(report['findings'])}`\n\n")
        rendered = "".join(out)
    emit(rendered)
    if args.pdf_output:
        write_pdf_from_html(rendered, args.pdf_output)
    if args.baseline_strict and summary["findings"] > 0:
        raise SystemExit(2)
    if args.fail_on_severity and summary["highest_severity"] != "none":
        if _severity_rank(summary["highest_severity"]) <= _severity_rank(args.fail_on_severity):
            raise SystemExit(3)


if __name__ == "__main__":
    main()
