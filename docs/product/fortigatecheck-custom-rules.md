# Custom Rule Authoring Guide

**Tags:** #fortigatecheck #rules #custom

---

## Overview

fortigatecheck allows you to write custom security rules in YAML. This lets you extend the built-in rule set with checks specific to your organization.

## Rule File Format

Create a YAML file in your rules directory:

```yaml
id: MY-CUSTOM-RULE-001
title: Check for custom condition
severity: medium
confidence: likely
entrypoint: my_rules:check_custom_condition
```

### Required Fields

| Field | Description | Values |
|-------|-------------|--------|
| `id` | Unique rule identifier | `MY-CUSTOM-RULE-001` |
| `title` | Human-readable description | Any string |
| `severity` | Finding severity | `critical`, `high`, `medium`, `low` |
| `confidence` | Detection confidence | `certain`, `likely`, `heuristic` |
| `entrypoint` | Python function to call | `module:function_name` |

## Writing the Rule Function

Create a Python file with your rule implementation:

```python
from typing import List, Optional
from fgcheck.model import ConfigModel, Node
from fgcheck.facts import Facts, get_table
from fgcheck.rules import Finding, Rule
from fgcheck.schema import SchemaView


def check_custom_condition(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Check for your custom condition."""
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []

    # Get a table
    policy_table = get_table(tables, ("firewall", "policy"))

    for policy_name, policy_node in policy_table.items():
        if not isinstance(policy_node, Node):
            continue

        fields = policy_node.effective_fields()

        # Your custom check
        if fields.get("action") == "accept" and fields.get("logtraffic") != "all":
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f"Policy {policy_name}: accept without full logging",
                evidence=[],
            ))

    return out
```

## Running Custom Rules

```bash
# Single custom rule file
fgcheck config.conf --rules my_rules.yaml

# Multiple rule files
fgcheck config.conf --rules rules1.yaml --rules rules2.yaml

# Custom rules directory
fgcheck config.conf --rules-dir ./my_rules/
```

## Rule Function Signature

Every rule function must have this exact signature:

```python
def rule_name(
    *, model: ConfigModel, facts: Facts, vdom: str,
    rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `model` | ConfigModel | Parsed configuration data |
| `facts` | Facts | Derived topology facts |
| `vdom` | str | Current VDOM being checked |
| `rule` | Rule | This rule's definition |
| `schema` | SchemaView | FortiOS schema (may be None) |

### Return Value

Return a list of `Finding` objects. Empty list = no issues found.

## Available Helpers

```python
from fgcheck.facts import get_table
from fgcheck.model import Node
from fgcheck.util import as_list

# Get a config table
table = get_table(tables, ("firewall", "policy"))

# Access node fields (respects unset)
fields = node.effective_fields()

# Convert multi-value fields to list
values = as_list(node.fields.get("service"))
```

## Best Practices

1. **Check schema support first** — use `_schema_supports_field()` if available
2. **Use effective_fields()** — respects `unset` semantics
3. **Provide evidence** — include the Evidence object when possible
4. **Use descriptive messages** — explain what's wrong and why
5. **Set appropriate confidence** — `certain` for schema-backed, `heuristic` for inference
6. **Test your rules** — write tests for both positive and negative cases

## Example: Check for Weak Encryption

```yaml
id: MY-CRYPTO-WEAK
title: Weak encryption algorithm detected
severity: high
confidence: certain
entrypoint: my_rules:check_weak_crypto
```

```python
def check_weak_crypto(*, model, facts, vdom, rule, schema=None):
    tables = model.vdoms.get(vdom, {})
    out = []

    phase1_table = get_table(tables, ("vpn", "ipsec", "phase1-interface"))
    for name, node in phase1_table.items():
        if not isinstance(node, Node):
            continue
        fields = node.effective_fields()
        proposal = str(fields.get("proposal", "")).lower()
        if "3des" in proposal or "des" in proposal:
            out.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                vdom=vdom,
                message=f"VPN {name} uses weak encryption: {proposal}",
                evidence=[],
            ))

    return out
```
