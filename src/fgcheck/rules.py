from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import yaml

from .facts import build_facts
from .model import ConfigModel, Evidence
from .schema import SchemaView, load_schema
from .versioning import resolve_target_fortios


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    vdom: str
    message: str
    evidence: list[Evidence]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    confidence: str
    entrypoint: str


def _import_callable(dotted: str) -> Callable[..., list[Finding]]:
    mod, fn = dotted.rsplit(":", 1)
    # Security: only allow fgcheck.* modules to prevent arbitrary code execution
    if not mod.startswith("fgcheck."):
        raise ValueError(f"Only fgcheck.* modules allowed, got: {mod}")
    m = __import__(mod, fromlist=[fn])
    return getattr(m, fn)


def load_rules(rule_files: list[str]) -> list[Rule]:
    rules: list[Rule] = []
    for p in rule_files:
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules.append(
            Rule(
                id=data["id"],
                title=data["title"],
                severity=data["severity"],
                confidence=data["confidence"],
                entrypoint=data["entrypoint"],
            )
        )
    return rules


def run(
    model: ConfigModel,
    *,
    vdoms: list[str] | None = None,
    rule_files: list[str] | None = None,
    fortios_version: str | None = None,
    schema_base_dir: str = ".",
) -> list[Finding]:
    vdoms = vdoms or list(model.vdoms.keys())
    rules = load_rules(rule_files or [])
    resolved_version, _ = resolve_target_fortios(model, explicit_version=fortios_version)
    model.meta["target_fortios"] = resolved_version
    schema: SchemaView = load_schema(resolved_version, base_dir=schema_base_dir)
    findings: list[Finding] = []
    for vdom in vdoms:
        facts = build_facts(model, vdom=vdom)
        for r in rules:
            impl = _import_callable(r.entrypoint)
            findings.extend(impl(model=model, facts=facts, vdom=vdom, rule=r, schema=schema))
    findings.sort(
        key=lambda f: (
            f.vdom,
            f.rule_id,
            f.evidence[0].line_range[0] if f.evidence else 0,
            f.message,
        )
    )
    return findings
