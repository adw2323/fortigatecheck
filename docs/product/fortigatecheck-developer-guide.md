# fortigatecheck Developer Guide

**Tags:** #fortigatecheck #development #contributing

---

## Development Setup

```bash
# Clone
git clone https://github.com/adw2323/fortigatecheck.git
cd fortigatecheck

# Install in dev mode
pip install -e .

# Install dev dependencies
pip install pytest pytest-xdist weasyprint
```

## Project Structure

```
fortigatecheck/
├── src/fgcheck/           # Main package
│   ├── __init__.py        # Package init
│   ├── cli.py             # CLI entry point (argparse)
│   ├── model.py           # Data classes
│   ├── parse.py           # FortiOS config parser
│   ├── rules.py           # Rule loading and execution
│   ├── rules_impl.py      # Rule implementations (35 rules)
│   ├── schema.py          # Schema validation
│   ├── authority.py       # Command/field authority
│   ├── facts.py           # Derived facts
│   ├── baseline.py        # Baseline comparison
│   ├── versioning.py      # FortiOS version resolution
│   ├── report.py          # Report generation
│   └── util.py            # Utilities
├── rules/builtin/         # YAML rule definitions
├── tests/                 # Test suite (39 files, 416 tests)
├── docs/                  # Documentation
├── scripts/               # Build and utility scripts
└── pyproject.toml         # Package configuration
```

## Running Tests

```bash
# All tests
python -m pytest tests/

# Specific test file
python -m pytest tests/test_rules_ssh_weak_ciphers.py -v

# With coverage
python -m pytest tests/ --cov=fgcheck

# Parallel
python -m pytest tests/ -n auto
```

## Adding a New Rule

### 1. Create YAML definition

File: `rules/builtin/FGT-XXX.yaml`

```yaml
id: FGT-XXX
title: Descriptive title of what this checks
severity: medium  # critical, high, medium, low
confidence: certain  # certain, heuristic
entrypoint: fgcheck.rules_impl:rule_xxx
```

### 2. Implement the rule

File: `src/fgcheck/rules_impl.py`

```python
def rule_xxx(
    *, model: ConfigModel, facts: Facts,
    vdom: str, rule: Rule, schema: Optional[SchemaView] = None
) -> List[Finding]:
    """Check for specific condition."""
    tables = model.vdoms.get(vdom, {})
    out: List[Finding] = []
    
    # Check schema support
    if schema is None or not schema.loaded:
        schema_unknown = True
    elif schema.has_table(("some", "table")):
        schema_unknown = schema.partial
    else:
        return out  # table not in schema
    
    # Inspect config
    # ...
    
    # Return findings with evidence
    out.append(Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        confidence=("heuristic" if schema_unknown else rule.confidence),
        vdom=vdom,
        message=f"Description of the issue",
        evidence=[],
    ))
    return out
```

### 3. Add tests

File: `tests/test_rules_xxx.py`

```python
import pytest
from fgcheck.model import ConfigModel
from fgcheck.facts import build_facts
from fgcheck.rules import Finding, Rule
from fgcheck.rules_impl import rule_xxx

def test_rule_xxx_finds_issue():
    config = """
config system interface
    edit "wan1"
        set allowaccess ssh
    next
end
"""
    # Parse and test
    # ...

def test_rule_xxx_no_issue():
    config = """
config system interface
    edit "wan1"
        set allowaccess https
    next
end
"""
    # Parse and test
    # ...
```

### 4. Update roadmap

Mark the rule as DONE in `docs/ROADMAP.md`.

## Code Style

- Type hints on all functions
- Docstrings on public functions
- Use `from __future__ import annotations`
- Follow existing patterns in rules_impl.py
- Use `_schema_supports_field()` for schema checks

## Architecture Decisions

1. **Deterministic** — no randomness, no external calls
2. **Evidence-first** — every finding has config line evidence
3. **Schema-gated** — check schema support before making claims
4. **Multi-VDOM** — check each VDOM independently
5. **YAML rules** — easy to add new checks
6. **Multiple outputs** — support all common formats

## Git Workflow

```bash
# Create feature branch
git checkout -b feature/fgc-xxx-description

# Make changes
# ...

# Run tests
python -m pytest tests/

# Commit
git add .
git commit -m "feat: add FGT-XXX rule"

# Push and create PR
git push origin feature/fgc-xxx-description
```

## Commit Messages

```
feat: add new feature
fix: fix a bug
docs: update documentation
test: add or update tests
refactor: refactor code
chore: maintenance tasks
```
