from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, List, Optional

import yaml

from .model import ConfigModel, Evidence
from .facts import Facts, build_facts

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    vdom: str
    message: str
    evidence: List[Evidence]

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    confidence: str
    entrypoint: str

def _import_callable(dotted: str) -> Callable[..., List[Finding]]:
    mod, fn = dotted.rsplit(":", 1)
    m = __import__(mod, fromlist=[fn])
    return getattr(m, fn)

def load_rules(rule_files: List[str]) -> List[Rule]:
    rules: List[Rule] = []
    for p in rule_files:
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules.append(Rule(
            id=data["id"],
            title=data["title"],
            severity=data["severity"],
            confidence=data["confidence"],
            entrypoint=data["entrypoint"],
        ))
    return rules

def run(model: ConfigModel, *, vdoms: Optional[List[str]] = None, rule_files: Optional[List[str]] = None) -> List[Finding]:
    vdoms = vdoms or list(model.vdoms.keys())
    rules = load_rules(rule_files or [])
    findings: List[Finding] = []
    for vdom in vdoms:
        facts = build_facts(model, vdom=vdom)
        for r in rules:
            impl = _import_callable(r.entrypoint)
            findings.extend(impl(model=model, facts=facts, vdom=vdom, rule=r))
    return findings
