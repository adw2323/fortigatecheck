"""Convert fgcheck findings to SARIF 2.1.0 format for GitHub Security tab."""
from __future__ import annotations

import json
from typing import List

from .rules import Finding

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "fgcheck"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/adw2323/fortigatecheck"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


def findings_to_sarif(findings: List[Finding]) -> str:
    """Return a SARIF 2.1.0 JSON string for the given findings."""
    # Build de-duplicated rules list (keyed by rule_id).
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        # Collect rule metadata once per unique rule_id.
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {
                    "level": _severity_to_level(f.severity),
                },
            }

        # Build locations from evidence.
        locations: list[dict] = []
        for ev in f.evidence:
            artifact_uri = f"file:///{ev.file_id}"
            start_line = ev.line_range[0] if ev.line_range else 1
            loc: dict = {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": start_line},
                }
            }
            locations.append(loc)

        result: dict = {
            "ruleId": f.rule_id,
            "message": {"text": f.message},
            "level": _severity_to_level(f.severity),
        }
        if locations:
            result["locations"] = locations

        results.append(result)

    sarif: dict = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)
