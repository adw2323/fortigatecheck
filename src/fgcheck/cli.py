from __future__ import annotations
import argparse
from pathlib import Path

from rich.console import Console

from .parse import parse_fortios_text
from .rules import run
from .report import findings_to_json, findings_to_markdown

def main():
    ap = argparse.ArgumentParser(prog="fgcheck")
    ap.add_argument("config", help="FortiOS text config .conf")
    ap.add_argument("--rules", nargs="+", default=[
        "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        "rules/builtin/FGT-ADMIN-EDGE-HTTPS.yaml",
        "rules/builtin/FGT-POLICY-LOG-001.yaml",
    ])
    ap.add_argument("--format", choices=["json", "md"], default="md")
    ap.add_argument("--vdom", action="append", default=None, help="Specify vdom(s). Can repeat.")
    args = ap.parse_args()

    text = Path(args.config).read_text(encoding="utf-8", errors="replace")
    model, warnings = parse_fortios_text(text, file_id=Path(args.config).name)

    findings = run(model, vdoms=args.vdom, rule_files=args.rules)

    console = Console()
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
