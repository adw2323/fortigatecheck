from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .rules import Finding

_MATCHABLE_KEYS = (
    "rule_id",
    "severity",
    "confidence",
    "vdom",
    "message",
    "file_id",
    "line_start",
    "line_end",
)


def finding_to_record(finding: Finding) -> dict[str, Any]:
    record: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "vdom": finding.vdom,
        "message": finding.message,
        "file_id": "",
        "line_start": 0,
        "line_end": 0,
    }
    if finding.evidence:
        ev = finding.evidence[0]
        record["file_id"] = ev.file_id
        record["line_start"] = ev.line_range[0]
        record["line_end"] = ev.line_range[1]
    return record


def finding_dict_to_record(finding: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "rule_id": str(finding.get("rule_id", "")),
        "severity": str(finding.get("severity", "")),
        "confidence": str(finding.get("confidence", "")),
        "vdom": str(finding.get("vdom", "")),
        "message": str(finding.get("message", "")),
        "file_id": "",
        "line_start": 0,
        "line_end": 0,
    }
    evidence = finding.get("evidence", [])
    if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict):
        ev0 = evidence[0]
        record["file_id"] = str(ev0.get("file_id", ""))
        line_range = ev0.get("line_range", [])
        if isinstance(line_range, list) and len(line_range) >= 2:
            record["line_start"] = int(line_range[0])
            record["line_end"] = int(line_range[1])
    return record


def _normalize_matcher(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in _MATCHABLE_KEYS:
        if key in raw:
            out[key] = raw[key]
    return out


def load_baseline_matchers(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        items = payload.get("matchers", [])
    else:
        items = payload
    if not isinstance(items, list):
        raise ValueError("Baseline file must contain a JSON list or {\"matchers\": [...]}.")
    return [_normalize_matcher(x) for x in items if isinstance(x, dict)]


def matches_record(record: dict[str, Any], matcher: dict[str, Any]) -> bool:
    for key, value in matcher.items():
        if key not in _MATCHABLE_KEYS:
            continue
        if record.get(key) != value:
            return False
    return bool(matcher)


def filter_finding_records(
    records: Sequence[dict[str, Any]],
    matchers: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    kept: list[dict[str, Any]] = []
    suppressed = 0
    for rec in records:
        if any(matches_record(rec, m) for m in matchers):
            suppressed += 1
            continue
        kept.append(rec)
    return kept, suppressed


def write_baseline_records(path: str, records: Sequence[dict[str, Any]]) -> None:
    unique = sorted(
        {
            json.dumps(_normalize_matcher(dict(rec)), sort_keys=True)
            for rec in records
        }
    )
    payload = [json.loads(item) for item in unique]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def merge_baseline_records(path: str, new_records: Sequence[dict[str, Any]]) -> None:
    existing: list[dict[str, Any]] = []
    p = Path(path)
    if p.exists():
        existing = load_baseline_matchers(path)
    combined: list[dict[str, Any]] = []
    combined.extend(existing)
    combined.extend(dict(r) for r in new_records)
    write_baseline_records(path, combined)
