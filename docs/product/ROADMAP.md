# fortigatecheck Roadmap — Product Development

**Last Updated:** 2026-07-03
**Vision:** World-class FortiGate syntax and security checker — no hallucination, pure validation.

---

## Phase 1: Foundation (MVP for Distribution)

**Goal:** Make it installable, documented, and robust enough for real users.

| Task | Priority | Status | Description |
|------|----------|--------|-------------|
| FGC-1 | P1 | READY | pip installable (pyproject.toml, console_scripts) |
| FGC-2 | P1 | READY | License (MIT) and CHANGELOG |
| FGC-3 | P1 | READY | Syntax validation rules |
| FGC-4 | P1 | READY | Error handling hardening |
| FGC-5 | P2 | READY | User documentation |
| FGC-6 | P1 | READY | Parser edge cases |
| FGC-14 | P1 | READY | Large config performance (10MB+) |

**Exit criteria:**
- `pip install fgcheck` works
- CLI works as `fgcheck` command
- All existing 416 tests pass
- Documentation complete
- Handles malformed configs gracefully
- Processes 10MB configs in <30s

---

## Phase 2: Schema Depth

**Goal:** Know FortiOS deeply — not just tables, but fields and values.

| Task | Priority | Status | Description |
|------|----------|--------|-------------|
| FGC-7 | P1 | READY | Schema field-level coverage |
| FGC-15 | P2 | READY | FortiManager config support |

**Exit criteria:**
- Field-level validation for 7.4, 7.6, 8.0
- Allowed values checking
- FortiManager config parsing
- Type validation

---

## Phase 3: Security Depth

**Goal:** Comprehensive security posture analysis.

| Task | Priority | Status | Description |
|------|----------|--------|-------------|
| FGC-8 | P2 | READY | 50+ security rules |
| FGC-12 | P2 | READY | Compliance mapping (NIST/CIS) |
| FGC-13 | P2 | READY | Custom rule authoring |

**Exit criteria:**
- 50+ rules covering all major attack surfaces
- NIST 800-53 and CIS mapping
- Users can write custom rules

---

## Phase 4: Integration

**Goal:** Work with existing tools and workflows.

| Task | Priority | Status | Description |
|------|----------|--------|-------------|
| FGC-9 | P2 | READY | REST API |
| FGC-10 | P2 | READY | CI/CD integration |
| FGC-16 | P3 | READY | Config diff |

**Exit criteria:**
- REST API with OpenAPI docs
- GitHub Actions and GitLab CI templates
- Config diff functionality

---

## Phase 5: Distribution

**Goal:** Easy deployment and maintenance.

| Task | Priority | Status | Description |
|------|----------|--------|-------------|
| FGC-11 | P3 | READY | Docker support |

**Exit criteria:**
- Docker image published
- Docker Compose for API mode
- Multi-stage build

---

## Architecture

```
fortigatecheck/
├── src/fgcheck/
│   ├── cli.py          # CLI entry point
│   ├── model.py        # Data structures
│   ├── parse.py        # FortiOS config parser
│   ├── rules.py        # Rule loading/execution
│   ├── rules_impl.py   # Rule implementations
│   ├── schema.py       # Schema validation
│   ├── authority.py    # Command/field authority
│   ├── facts.py        # Derived facts
│   ├── baseline.py     # Baseline comparison
│   ├── versioning.py   # Version resolution
│   ├── report.py       # Report generation
│   └── util.py         # Utilities
├── rules/builtin/      # YAML rule definitions
├── tests/              # Test suite
├── docs/               # Documentation
└── pyproject.toml      # Package configuration
```

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Tests | 416 | 500+ |
| Rules | 35 | 50+ |
| Schema coverage | table_only | field_level |
| Install method | manual | pip install |
| Config formats | text only | text + FortiManager |
| Output formats | 5 | 6+ (add API) |
| Users | 0 | 100+ |
| Weekly downloads | 0 | 50+ |

---

## Definition of Done

A task is done when:
1. Implementation exists
2. Tests pass
3. Documentation updated
4. No regressions
5. Committed
6. Verified by test run
