# fortigatecheck Architecture

**Tags:** #fortigatecheck #architecture #python

---

## System Architecture

```
┌─────────────────────────────────────────────┐
│                  CLI (cli.py)               │
│  fgcheck <path> --format <format>           │
└─────────────┬───────────────────────────────┘
              │
┌─────────────▼───────────────────────────────┐
│              Parser (parse.py)               │
│  parse_fortios_text(config_text)            │
│  → ConfigModel (vdoms, global_cfg, meta)    │
└─────────────┬───────────────────────────────┘
              │
┌─────────────▼───────────────────────────────┐
│              Facts (facts.py)                │
│  build_facts(model)                         │
│  → edge_interfaces, policies, etc.          │
└─────────────┬───────────────────────────────┘
              │
┌─────────────▼───────────────────────────────┐
│              Rules (rules.py)                │
│  load_rules() → run(model, facts, rules)    │
│  → List[Finding]                            │
└─────────────┬───────────────────────────────┘
              │
┌─────────────▼───────────────────────────────┐
│            Report (report.py)                │
│  findings_to_human/json/html/markdown/pdf   │
└─────────────────────────────────────────────┘
```

## Data Model

```python
@dataclass
class ConfigModel:
    meta: Dict[str, Any]        # version, source info
    global_cfg: Dict[str, Any]  # global config sections
    vdoms: Dict[str, Dict]      # vdom_name → config sections

@dataclass
class Node:
    fields: Dict[str, Any]      # field_name → value
    unsets: set[str]            # explicitly unset fields
    evidence: Dict[str, Evidence]  # field → evidence

@dataclass
class Evidence:
    file_id: str
    line_range: Tuple[int, int]
    path: Tuple[str, ...]       # config path
    raw_lines: List[str]
```

## Rule Implementation Pattern

```python
def rule_xxx(
    *, model: ConfigModel, facts: Facts, 
    vdom: str, rule: Rule, schema: SchemaView
) -> List[Finding]:
    """Check for specific condition."""
    tables = model.vdoms.get(vdom, {})
    out = []
    # Check schema support
    # Inspect config tables
    # Return findings with evidence
    return out
```

## Schema System

- Schema files: `docs/derived/schema/{version}/schema.json`
- Coverage levels: `table_only`, `field_level`
- Version resolution: 7.6.6 → 7.6 → 7.4
- Field validation: has_field(), allowed_values()

## Key Design Decisions

1. **Deterministic** — no randomness, no LLM calls
2. **Evidence-first** — every finding has config line evidence
3. **Schema-gated** — don't claim unsupported syntax
4. **Multi-VDOM** — check each VDOM independently
5. **YAML rules** — easy to add new checks
6. **Multiple outputs** — human, JSON, HTML, PDF, Markdown
