from __future__ import annotations

import html
import json
from pathlib import Path

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


def findings_to_json(findings: list[Finding]) -> str:
    payload = [finding_to_dict(f) for f in findings]
    return json.dumps(payload, indent=2)


def scan_to_json(files: list[dict[str, object]], summary: dict[str, int]) -> str:
    return json.dumps({"summary": summary, "files": files}, indent=2)

def findings_to_markdown(findings: list[Finding]) -> str:
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


_RULE_EXPLANATIONS = {
    "FGT-ADMIN-EDGE-SSH": "SSH management is reachable from an internet-facing edge interface.",
    "FGT-ADMIN-EDGE-HTTPS": "HTTPS management is reachable from an internet-facing edge interface.",
    "FGT-ADMIN-EDGE-ALLACCESS": "Multiple management protocols are exposed on an edge interface.",
    "FGT-ADMIN-NO-TRUSTED-HOSTS": "Administrator login is not restricted to trusted source hosts.",
    "FGT-ADMIN-TRUSTHOST-UNRESTRICTED": "A super-admin account is effectively open to any source host.",
    "FGT-ADMIN-SUPER-NO-2FA": "A super-admin account does not enforce two-factor authentication.",
    "FGT-ADMIN-NO-IDLE-TIMEOUT": "Administrator idle timeout is disabled or exceeds recommended limits.",
    "FGT-LOCAL-IN-PERMISSIVE": "Local-in policy accepts broad traffic directly to the FortiGate.",
    "FGT-LOCALIN-NO-PROTECTION": "No enabled local-in deny protection is present.",
    "FGT-POLICY-LOG-001": "A permit firewall policy is not logging traffic.",
    "FGT-POLICY-ANY-ANY-ALL": "A firewall policy allows any source to any destination for any service.",
    "FGT-SSLVPN-MIN-TLS": "SSL-VPN minimum TLS version allows legacy protocol versions.",
    "FGT-SSLVPN-SRCINTF-ANY": "SSL-VPN is listening on interface any instead of a restricted interface list.",
    "FGT-SSLVPN-SRCADDR-ALL": "SSL-VPN source-address is all instead of a restricted source scope.",
    "FGT-IPSEC-WEAK-DH": "IPsec phase1 uses weak Diffie-Hellman groups.",
    "FGT-NO-REMOTE-LOGGING": "No remote logging destination is enabled.",
}


def _severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev, 99)


def _rule_explanation(rule_id: str, fallback: str) -> str:
    return _RULE_EXPLANATIONS.get(rule_id, fallback)


def _top_risks_lines(records: list[dict[str, object]]) -> list[str]:
    by_rule: dict[str, dict[str, object]] = {}
    for rec in records:
        rule_id = str(rec.get("rule_id", ""))
        severity = str(rec.get("severity", "info"))
        file_name = str(rec.get("file", ""))
        if rule_id not in by_rule:
            by_rule[rule_id] = {
                "severity": severity,
                "count": 0,
                "files": set(),
            }
        by_rule[rule_id]["count"] = int(by_rule[rule_id]["count"]) + 1
        if file_name:
            cast_files = by_rule[rule_id]["files"]
            if isinstance(cast_files, set):
                cast_files.add(file_name)

    ranked = sorted(
        by_rule.items(),
        key=lambda x: (
            _severity_rank(str(x[1]["severity"])),
            -int(x[1]["count"]),
            x[0],
        ),
    )
    lines: list[str] = ["Top Risks First\n"]
    if not ranked:
        lines.append("- none\n")
    else:
        for rule_id, data in ranked[:10]:
            sev = str(data["severity"]).upper()
            count = int(data["count"])
            files = data.get("files", set())
            file_count = len(files) if isinstance(files, set) else 0
            if file_count:
                lines.append(f"- [{sev}] {rule_id}: {count} finding(s), files={file_count}\n")
            else:
                lines.append(f"- [{sev}] {rule_id}: {count} finding(s)\n")
    lines.append("\n")
    return lines


def findings_to_human(
    findings: list[Finding],
    *,
    title: str = "FortiGate Findings",
    suppressed: int = 0,
) -> str:
    out: list[str] = [f"{title}\n", "=" * len(title) + "\n\n"]
    if not findings:
        if suppressed:
            out.append("Summary\n")
            out.append("- Findings: 0\n")
            out.append(f"- Suppressed by baseline: {suppressed}\n\n")
        out.append("No findings were detected.\n")
        return "".join(out)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    conf_counts = {"certain": 0, "likely": 0, "heuristic": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
        if f.confidence in conf_counts:
            conf_counts[f.confidence] += 1

    out.append("Summary\n")
    out.append(f"- Findings: {len(findings)}\n")
    out.append(
        "- Severity: "
        f"critical={sev_counts['critical']}, high={sev_counts['high']}, "
        f"medium={sev_counts['medium']}, low={sev_counts['low']}, info={sev_counts['info']}\n"
    )
    out.append(
        "- Confidence: "
        f"certain={conf_counts['certain']}, likely={conf_counts['likely']}, heuristic={conf_counts['heuristic']}\n\n"
    )
    if suppressed:
        out.append(f"- Suppressed by baseline: {suppressed}\n\n")
    out.extend(
        _top_risks_lines(
            [
                {"rule_id": f.rule_id, "severity": f.severity, "file": ""}
                for f in findings
            ]
        )
    )

    out.append("Findings\n")
    sorted_findings = sorted(findings, key=lambda f: (_severity_rank(f.severity), f.vdom, f.rule_id))
    for i, f in enumerate(sorted_findings, start=1):
        expl = _rule_explanation(f.rule_id, f.message)
        out.append(f"{i}. [{f.severity.upper()}] {f.rule_id} ({f.vdom}, {f.confidence})\n")
        out.append(f"   - What it means: {expl}\n")
        out.append(f"   - Why flagged: {f.message}\n")
        if f.evidence:
            ev = f.evidence[0]
            out.append(f"   - Evidence: {ev.file_id} lines {ev.line_range[0]}-{ev.line_range[1]}\n")
        out.append("\n")
    return "".join(out)


def scan_to_human(files: list[dict[str, object]], summary: dict[str, int], *, title: str = "FortiGate Folder Scan") -> str:
    out: list[str] = [f"{title}\n", "=" * len(title) + "\n\n"]
    out.append(
        "Summary\n"
        f"- Files scanned: {summary['files']}\n"
        f"- Findings: {summary['findings']}\n"
        f"- Parse warnings: {summary['parse_warnings']}\n"
        f"- Severity: critical={summary['critical']}, high={summary['high']}, "
        f"medium={summary['medium']}, low={summary['low']}, info={summary['info']}\n"
    )
    if "findings_total" in summary:
        out.append(f"- Findings before suppression: {summary['findings_total']}\n")
    if "highest_severity" in summary:
        out.append(f"- Highest severity: {summary['highest_severity']}\n")
    if "suppressed" in summary:
        out.append(f"- Suppressed by baseline: {summary['suppressed']}\n")
    out.append("\n")
    risk_records: list[dict[str, object]] = []
    for fr in files:
        file_name = str(fr.get("file", ""))
        for finding in fr.get("findings", []):
            if isinstance(finding, dict):
                risk_records.append(
                    {
                        "rule_id": str(finding.get("rule_id", "")),
                        "severity": str(finding.get("severity", "info")),
                        "file": file_name,
                    }
                )
    out.extend(_top_risks_lines(risk_records))

    out.append("Per-file\n")
    for fr in files:
        file_name = str(fr.get("file", ""))
        findings = fr.get("findings", [])
        parse_warnings = fr.get("parse_warnings", [])
        out.append(f"- {file_name}: findings={len(findings)}, parse_warnings={len(parse_warnings)}\n")
        sorted_findings = sorted(
            [f for f in findings if isinstance(f, dict)],
            key=lambda f: (_severity_rank(str(f.get("severity", ""))), str(f.get("rule_id", ""))),
        )
        for i, f in enumerate(sorted_findings, start=1):
            rule_id = str(f.get("rule_id", ""))
            severity = str(f.get("severity", "unknown")).upper()
            confidence = str(f.get("confidence", "unknown"))
            message = str(f.get("message", ""))
            expl = _rule_explanation(rule_id, message)
            out.append(f"  {i}. [{severity}] {rule_id} ({confidence})\n")
            out.append(f"     - What it means: {expl}\n")
            out.append(f"     - Why flagged: {message}\n")
            evidence = f.get("evidence", [])
            if isinstance(evidence, list) and evidence:
                ev0 = evidence[0]
                if isinstance(ev0, dict):
                    file_id = str(ev0.get("file_id", file_name))
                    line_range = ev0.get("line_range", [])
                    if isinstance(line_range, list) and len(line_range) >= 2:
                        out.append(f"     - Evidence: {file_id} lines {line_range[0]}-{line_range[1]}\n")
        if sorted_findings:
            out.append("\n")
    out.append("\n")
    return "".join(out)


def _top_risks_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    by_rule: dict[str, dict[str, object]] = {}
    for rec in records:
        rule_id = str(rec.get("rule_id", ""))
        severity = str(rec.get("severity", "info"))
        file_name = str(rec.get("file", ""))
        if rule_id not in by_rule:
            by_rule[rule_id] = {"rule_id": rule_id, "severity": severity, "count": 0, "files": set()}
        by_rule[rule_id]["count"] = int(by_rule[rule_id]["count"]) + 1
        files = by_rule[rule_id]["files"]
        if file_name and isinstance(files, set):
            files.add(file_name)
    ranked = sorted(
        by_rule.values(),
        key=lambda item: (
            _severity_rank(str(item["severity"])),
            -int(item["count"]),
            str(item["rule_id"]),
        ),
    )
    return ranked[:10]


def _severity_class(sev: str) -> str:
    s = sev.lower()
    if s == "critical":
        return "sev-critical"
    if s == "high":
        return "sev-high"
    if s == "medium":
        return "sev-medium"
    if s == "low":
        return "sev-low"
    return "sev-info"


def _html_doc(title: str, body: str) -> str:
    safe_title = html.escape(title)
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\" />\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
        f"  <title>{safe_title}</title>\n"
        "  <style>\n"
        "    :root { --bg:#f7f8fb; --card:#ffffff; --ink:#1a1f2b; --muted:#556074; --line:#d9dfeb; }\n"
        "    body { margin:0; font-family:'Segoe UI',Tahoma,Arial,sans-serif; background:var(--bg); color:var(--ink); }\n"
        "    .wrap { max-width:1100px; margin:24px auto; padding:0 16px 32px; }\n"
        "    .hero { background:linear-gradient(120deg,#133a72,#1b6ca8); color:#fff; border-radius:14px; padding:18px 20px; }\n"
        "    .hero h1 { margin:0; font-size:24px; }\n"
        "    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin:14px 0 0; }\n"
        "    .kpi { background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.22); border-radius:10px; padding:10px; }\n"
        "    .kpi .k { font-size:12px; opacity:.9; }\n"
        "    .kpi .v { font-size:20px; font-weight:700; margin-top:4px; }\n"
        "    .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; margin-top:14px; }\n"
        "    h2 { margin:0 0 10px; font-size:18px; }\n"
        "    h3 { margin:0 0 8px; font-size:15px; }\n"
        "    ul { margin:8px 0 0 18px; }\n"
        "    li { margin:4px 0; }\n"
        "    .finding { border-top:1px solid var(--line); padding-top:10px; margin-top:10px; }\n"
        "    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; text-transform:uppercase; }\n"
        "    .sev-critical { background:#7f1d1d; color:#fff; }\n"
        "    .sev-high { background:#991b1b; color:#fff; }\n"
        "    .sev-medium { background:#92400e; color:#fff; }\n"
        "    .sev-low { background:#1e3a8a; color:#fff; }\n"
        "    .sev-info { background:#374151; color:#fff; }\n"
        "    .meta { color:var(--muted); font-size:12px; }\n"
        "    code, pre { font-family:Consolas,'Courier New',monospace; }\n"
        "    pre { background:#f3f5fa; border:1px solid var(--line); border-radius:8px; padding:10px; overflow:auto; }\n"
        "    @media print { body { background:#fff; } .wrap { margin:0; max-width:none; } }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        f"  <div class=\"wrap\">{body}</div>\n"
        "</body>\n"
        "</html>\n"
    )


def findings_to_html(findings: list[Finding], *, title: str = "FortiGate Findings", suppressed: int = 0) -> str:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    conf_counts = {"certain": 0, "likely": 0, "heuristic": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        conf_counts[f.confidence] = conf_counts.get(f.confidence, 0) + 1
    risk_rows = _top_risks_records([{"rule_id": f.rule_id, "severity": f.severity, "file": ""} for f in findings])

    body: list[str] = []
    body.append(f"<section class=\"hero\"><h1>{html.escape(title)}</h1>")
    body.append("<div class=\"grid\">")
    body.append(f"<div class=\"kpi\"><div class=\"k\">Findings</div><div class=\"v\">{len(findings)}</div></div>")
    body.append(f"<div class=\"kpi\"><div class=\"k\">Suppressed</div><div class=\"v\">{suppressed}</div></div>")
    body.append(f"<div class=\"kpi\"><div class=\"k\">Critical</div><div class=\"v\">{sev_counts.get('critical', 0)}</div></div>")
    body.append(f"<div class=\"kpi\"><div class=\"k\">High</div><div class=\"v\">{sev_counts.get('high', 0)}</div></div>")
    body.append("</div></section>")

    body.append("<section class=\"card\"><h2>Top Risks First</h2><ul>")
    if not risk_rows:
        body.append("<li>none</li>")
    else:
        for row in risk_rows:
            body.append(
                f"<li><span class=\"badge {_severity_class(str(row['severity']))}\">{html.escape(str(row['severity']))}</span> "
                f"{html.escape(str(row['rule_id']))}: {int(row['count'])} finding(s)</li>"
            )
    body.append("</ul></section>")

    body.append("<section class=\"card\"><h2>Findings</h2>")
    if not findings:
        body.append("<p>No findings were detected.</p>")
    else:
        sorted_findings = sorted(findings, key=lambda f: (_severity_rank(f.severity), f.vdom, f.rule_id))
        for f in sorted_findings:
            expl = _rule_explanation(f.rule_id, f.message)
            body.append("<article class=\"finding\">")
            body.append(
                f"<h3><span class=\"badge {_severity_class(f.severity)}\">{html.escape(f.severity)}</span> "
                f"{html.escape(f.rule_id)}</h3>"
            )
            body.append(
                f"<p class=\"meta\">vdom={html.escape(f.vdom)} | confidence={html.escape(f.confidence)}</p>"
            )
            body.append(f"<p><strong>What it means:</strong> {html.escape(expl)}</p>")
            body.append(f"<p><strong>Why flagged:</strong> {html.escape(f.message)}</p>")
            if f.evidence:
                ev = f.evidence[0]
                body.append(
                    f"<p><strong>Evidence:</strong> {html.escape(ev.file_id)} lines "
                    f"{ev.line_range[0]}-{ev.line_range[1]}</p>"
                )
                if ev.raw_lines:
                    body.append(f"<pre>{html.escape(chr(10).join(ev.raw_lines))}</pre>")
            body.append("</article>")
    body.append("</section>")
    return _html_doc(title, "".join(body))


def scan_to_html(
    files: list[dict[str, object]],
    summary: dict[str, int],
    *,
    title: str = "FortiGate Folder Scan",
) -> str:
    risk_records: list[dict[str, object]] = []
    for fr in files:
        file_name = str(fr.get("file", ""))
        for finding in fr.get("findings", []):
            if isinstance(finding, dict):
                risk_records.append(
                    {
                        "rule_id": str(finding.get("rule_id", "")),
                        "severity": str(finding.get("severity", "info")),
                        "file": file_name,
                    }
                )
    risk_rows = _top_risks_records(risk_records)

    body: list[str] = []
    body.append(f"<section class=\"hero\"><h1>{html.escape(title)}</h1>")
    body.append("<div class=\"grid\">")
    body.append(f"<div class=\"kpi\"><div class=\"k\">Files</div><div class=\"v\">{summary.get('files', 0)}</div></div>")
    body.append(f"<div class=\"kpi\"><div class=\"k\">Findings</div><div class=\"v\">{summary.get('findings', 0)}</div></div>")
    body.append(
        f"<div class=\"kpi\"><div class=\"k\">Suppressed</div><div class=\"v\">{summary.get('suppressed', 0)}</div></div>"
    )
    body.append(
        f"<div class=\"kpi\"><div class=\"k\">Highest</div><div class=\"v\">{html.escape(str(summary.get('highest_severity', 'none')))}</div></div>"
    )
    body.append("</div></section>")

    body.append("<section class=\"card\"><h2>Top Risks First</h2><ul>")
    if not risk_rows:
        body.append("<li>none</li>")
    else:
        for row in risk_rows:
            files_count = row["files"]
            nfiles = len(files_count) if isinstance(files_count, set) else 0
            body.append(
                f"<li><span class=\"badge {_severity_class(str(row['severity']))}\">{html.escape(str(row['severity']))}</span> "
                f"{html.escape(str(row['rule_id']))}: {int(row['count'])} finding(s), files={nfiles}</li>"
            )
    body.append("</ul></section>")

    body.append("<section class=\"card\"><h2>Per-file</h2>")
    for fr in files:
        file_name = str(fr.get("file", ""))
        findings = fr.get("findings", [])
        parse_warnings = fr.get("parse_warnings", [])
        body.append(
            f"<article class=\"finding\"><h3>{html.escape(file_name)}</h3>"
            f"<p class=\"meta\">findings={len(findings)}, parse_warnings={len(parse_warnings)}</p>"
        )
        sorted_findings = sorted(
            [f for f in findings if isinstance(f, dict)],
            key=lambda f: (_severity_rank(str(f.get("severity", ""))), str(f.get("rule_id", ""))),
        )
        for f in sorted_findings:
            rule_id = str(f.get("rule_id", ""))
            sev = str(f.get("severity", "info"))
            conf = str(f.get("confidence", "unknown"))
            msg = str(f.get("message", ""))
            expl = _rule_explanation(rule_id, msg)
            body.append(
                f"<p><span class=\"badge {_severity_class(sev)}\">{html.escape(sev)}</span> "
                f"<strong>{html.escape(rule_id)}</strong> "
                f"<span class=\"meta\">({html.escape(conf)})</span><br/>"
                f"<strong>What it means:</strong> {html.escape(expl)}<br/>"
                f"<strong>Why flagged:</strong> {html.escape(msg)}</p>"
            )
        body.append("</article>")
    body.append("</section>")
    return _html_doc(title, "".join(body))


def write_pdf_from_html(html_text: str, output_path: str) -> None:
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "PDF export requires the optional 'weasyprint' package. "
            "Install with: pip install weasyprint"
        ) from exc
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_text).write_pdf(str(out))
