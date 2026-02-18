from __future__ import annotations
import json
from typing import Dict, List
from .rules import Finding

def finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "vdom": f.vdom,
        "message": f.message,
        "evidence": [
            {
                "file_id": e.file_id,
                "line_range": list(e.line_range),
                "path": list(e.path),
                "raw_lines": e.raw_lines,
            } for e in f.evidence
        ],
    }


def findings_to_json(findings: List[Finding]) -> str:
    payload = [finding_to_dict(f) for f in findings]
    return json.dumps(payload, indent=2)


def scan_to_json(files: List[Dict[str, object]], summary: Dict[str, int]) -> str:
    return json.dumps({"summary": summary, "files": files}, indent=2)

def findings_to_markdown(findings: List[Finding]) -> str:
    if not findings:
        return "# FortiGate Config Check Report\n\nNo findings.\n"
    sev_order = ["critical", "high", "medium", "low", "info"]
    out = ["# FortiGate Config Check Report\n\n"]
    for sev in sev_order:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out.append(f"## {sev.upper()} ({len(group)})\n\n")
        for f in group:
            out.append(f"- **{f.rule_id}**: {f.title} (vdom `{f.vdom}`, confidence `{f.confidence}`)\n")
            out.append(f"  - {f.message}\n")
            for ev in f.evidence:
                out.append(f"  - Evidence: `{ev.file_id}` lines {ev.line_range[0]}-{ev.line_range[1]}\n")
                if ev.raw_lines:
                    out.append("    ```\n")
                    for rl in ev.raw_lines:
                        out.append(f"    {rl}\n")
                    out.append("    ```\n")
        out.append("\n")
    return "".join(out)
