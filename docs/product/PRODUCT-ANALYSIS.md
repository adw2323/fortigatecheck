# fortigatecheck — Comprehensive Product Analysis

**Date:** July 2026  
**Analyst:** Chief Product Architect  
**Status:** Internal Review

---

## Executive Summary

fortigatecheck (fgcheck) is a deterministic FortiGate configuration checker built in Python. It parses FortiOS text configs, validates against schema, checks 35 security rules, and reports findings in multiple formats. The architecture is sound and the engineering discipline is strong, but there are significant gaps between the current state and a distributable commercial product. This document provides a thorough analysis across 10 dimensions.

**Verdict:** This is a well-architected v0.1 with strong foundations. It is ~40% of the way to a distributable MVP and ~20% of the way to a commercial product. The critical path is: packaging → schema depth → more rules → CI/CD → distribution.

---

## 1. What This Product IS Today

### Strengths

**Architecture discipline.** The codebase follows a clean separation of concerns:
- `parse.py` (315 lines) — Deterministic FortiOS text config parser
- `model.py` (31 lines) — Minimal, frozen dataclasses (Node, Evidence, ConfigModel, ParseWarning)
- `facts.py` (179 lines) — Derived topology facts (edge interfaces, zones, SD-WAN)
- `rules.py` (76 lines) — Rule loading and execution orchestration
- `rules_impl.py` (2,515 lines) — 35 rule implementations in a single file
- `schema.py` (100 lines) — Schema view with table/field existence checks
- `authority.py` (217 lines) — Command/table/field authority lookup
- `report.py` (479 lines) — Multi-format report generation
- `baseline.py` (125 lines) — Finding suppression via baseline matchers
- `versioning.py` (48 lines) — FortiOS version resolution
- `cli.py` (347 lines) — CLI entry point with rich argument handling
- `util.py` (11 lines) — Single helper function

**Zero external hallucination.** The AGENTS.md contract is enforced at the code level: rules degrade from `certain` to `heuristic` when schema coverage is missing. Every finding carries `[schema_unknown]` markers when it cannot be validated against the corpus.

**Schema-gated correctness.** Rules check `_schema_supports_field()` before evaluating any finding. If a table or field doesn't exist in the schema for the target FortiOS version, the rule skips entirely. This prevents false positives from nonexistent config knobs.

**Evidence-first findings.** Every Finding includes a list of Evidence objects with file_id, line_range, path, and raw_lines. Findings point to exact config lines — not vague descriptions.

**Solid test suite.** 416 tests across 39 test files, all passing in ~8 seconds. Tests cover parser, facts, schema, individual rules, multi-VDOM, ordering, CLI, and report generation. The test-to-rule ratio (11.9 tests per rule) is healthy.

**Clean dependency graph.** DSM analysis shows zero above-diagonal edges — all dependencies flow downward. The acyclicity score is perfect (1.0). There are no circular imports.

**Baseline suppression workflow.** The `--write-baseline` / `--baseline` / `--baseline-update` / `--baseline-strict` / `--fail-on-severity` CLI flags create a complete CI-oriented suppression lifecycle. This is production-grade thinking.

**Multi-format output.** JSON, Markdown, human-readable text, HTML (with styled KPIs), PDF (via weasyprint), CSV, and summary JSON. The HTML output is visually polished with severity badges and KPI grids.

### Weaknesses

**`rules_impl.py` is a monolith.** At 2,515 lines and 86KB, this single file contains all 35 rule implementations. While each rule follows a consistent pattern (schema check → table lookup → iterate → emit Finding), the file is too large for comfortable navigation. The Sentrux modularity score is 0.333 — the weakest architectural dimension.

**Schema coverage is shallow.** Only 17 tables have field-level details out of 597-646 tables per version. This means most rules run at `heuristic` confidence. The schema is `table_only` — it knows tables exist but not what fields they contain for ~97% of the surface area.

**Rule YAML definitions are minimal.** Each rule file is only 5 lines (id, title, severity, confidence, entrypoint). There's no description, no remediation guidance, no compliance mapping, no documentation of what the rule checks or why.

**No LICENSE file.** The project has no open-source license, which blocks any form of distribution.

**No CI/CD.** No GitHub Actions, no pre-commit hooks, no automated testing pipeline.

**Parser has known structural limitations.** The parser flattens nested config blocks inside edit blocks. For example, `config ips sensor` → `edit "name"` → `config entries` becomes a separate top-level `entries` table, losing the profile association. This forces rules to work around parser limitations (see FGT-IPS-DEFAULT-SIGNATURE and FGT-AV-NO-HEURISTIC rules that must reach into flattened tables).

**No README installation section.** The README uses PowerShell-only examples with `$env:PYTHONPATH='src'`, suggesting development-mode usage only. There's no `pip install` quick-start.

**Single-author bus factor.** Git analysis shows 1.0 single-author ratio across 25 commits in 90 days. 56 of 56 files with churn have solo authorship.

### Gaps

| Gap | Impact |
|-----|--------|
| No license | Cannot distribute at all |
| No PyPI package | No `pip install fgcheck` |
| No Docker image | No containerized deployment |
| No CI/CD | No automated quality gate |
| No changelog | No version tracking |
| No API documentation | No programmatic usage guide |
| No compliance mapping | Cannot map to NIST/CIS/PCI frameworks |
| No FortiManager support | Cannot parse managed-device configs |
| No syntax validation | Only checks security, not correctness |
| No custom rule authoring | Users can't extend the rule set |
| No REST API | No automation interface |

---

## 2. What This Product SHOULD BE to Be Distributable

### Minimum Viable Distributable Product (MVP)

For another person to install and use fgcheck, it needs:

1. **`pip install fgcheck`** — PyPI package with proper metadata, classifiers, and entry points
2. **LICENSE file** — MIT or Apache 2.0 (MIT is simplest for this type of tool)
3. **Cross-platform CLI** — Works on Linux, macOS, Windows (currently README is Windows-only)
4. **Install and run in 3 commands:**
   ```
   pip install fgcheck
   fgcheck config.conf --format human
   fgcheck configs/ --format html --output report.html
   ```
5. **User documentation** — README with Linux/macOS examples, explanation of output, exit codes
6. **Error handling** — Graceful messages for missing files, malformed configs, missing schema
7. **Version pinning** — `--fortios` flag should document supported versions
8. **Exit code documentation** — 0=clean, 2=baseline-strict/new-findings, 3=severity-threshold
9. **Rule catalog documentation** — What each rule checks, severity rationale, remediation hints
10. **Changelog** — At minimum a CHANGELOG.md tracking releases

### Recommended additions for "comfortable" distribution

- Docker image: `docker run fgcheck /config.conf`
- GitHub Actions CI running on every push
- Pre-commit hook integration
- `fgcheck --version` flag
- SARIF output for GitHub code scanning integration
- JUnit XML output for CI test result aggregation
- Config validation mode (syntax-only, no security rules)
- Verbose/quiet modes beyond `--quiet`

---

## 3. The Gap Between Current State and World-Class

### Current State Assessment

| Dimension | Score (0-10) | Notes |
|-----------|-------------|-------|
| Architecture | 7 | Clean separation, but rules_impl monolith hurts |
| Test quality | 6 | 416 tests, but 15.5% coverage ratio per Sentrux |
| Schema depth | 3 | 17/600+ tables with fields (2.8%) |
| Rule coverage | 5 | 35 rules, but target is 75+ |
| Documentation | 3 | Good internal docs, no user guide |
| Packaging | 2 | pyproject.toml exists, no PyPI/Docker |
| CI/CD | 0 | No pipeline exists |
| Distribution | 1 | No license, no package, no container |
| Error handling | 4 | Graceful schema degradation, but no user-facing errors |
| Extensibility | 3 | YAML rules, but no custom rule authoring API |
| Reporting | 7 | Multi-format, polished HTML, PDF support |
| Performance | 5 | 416 tests in 8s, but no large-config benchmarks |

### What "World-Class" Looks Like

1. **100+ security rules** mapped to compliance frameworks (NIST 800-53, CIS FortiGate Benchmark, DISA STIG, PCI DSS)
2. **Full field-level schema** for all security-critical tables across all supported FortiOS versions
3. **REST API** with OpenAPI spec for automation and integration
4. **SARIF output** for native GitHub/GitLab security tab integration
5. **Custom rule authoring** — users write YAML rules with their own Python entrypoints
6. **FortiManager API integration** — pull configs directly from managed devices
7. **CVE-aware detection** — cross-reference config with CISA KEV and FortiGuard PSIRT
8. **Trend tracking** — compare scan results over time, detect config drift
9. **Multi-tenant support** — MSP-friendly with per-client baselines and reports
10. **Scheduled scanning** — cron/daemon mode for continuous monitoring
11. **Web dashboard** — interactive findings browser with filtering and export
12. **SIEM integration** — CEF/LEEF output for Splunk, Sentinel, QRadar
13. **Performance** — process 10MB+ configs in under 5 seconds
14. **Documentation** — MkDocs/Sphinx site with API reference, user guide, rule authoring guide

---

## 4. What's Missing for a Commercial/Distributable Product

### Critical (must-have before any distribution)

| Item | Effort | Impact |
|------|--------|--------|
| LICENSE file (MIT) | 1 hour | Blocks all distribution |
| `pip install fgcheck` on PyPI | 1 day | Primary distribution channel |
| Cross-platform README | 2 days | User onboarding |
| `--version` flag | 1 hour | Version identification |
| Error messages for common failures | 2 days | User experience |
| Rule catalog documentation | 1 day | Understanding findings |
| Exit code documentation | 1 hour | CI/CD integration |

### Important (must-have for MVP)

| Item | Effort | Impact |
|------|--------|--------|
| GitHub Actions CI | 1 day | Quality gate |
| Docker image | 1 day | Container deployment |
| CHANGELOG.md | 1 hour | Release tracking |
| 50+ rules (Wave 3+4) | 2-4 weeks | Comprehensive coverage |
| SARIF output | 2 days | GitHub security tab |
| Custom rule loading from user directories | 1 day | Extensibility |
| Syntax validation rules | 1 week | Beyond-security value |
| Performance benchmarks | 1 day | Large-config confidence |

### Nice-to-Have (commercial features)

| Item | Effort | Impact |
|------|--------|--------|
| REST API with FastAPI | 1 week | Automation |
| Web dashboard | 2-4 weeks | Enterprise sales |
| FortiManager API integration | 1 week | MSP value |
| Compliance mapping (NIST, CIS, PCI) | 2 weeks | Audit market |
| Multi-tenant support | 2 weeks | MSP market |
| Scheduled scanning daemon | 1 week | Continuous monitoring |
| SIEM output (CEF/LEEF) | 3 days | Enterprise integration |
| MCP server for AI agents | 1 week | Developer ecosystem |
| Trend tracking and drift detection | 1-2 weeks | Operational value |
| Config diff/compare | 1 week | Change management |

---

## 5. Architecture Assessment

### Is the Current Design Sound?

**Yes, fundamentally.** The architecture follows a clean pipeline:

```
Config File → Parser → ConfigModel → Facts Builder → Rule Engine → Findings → Reporter
```

Each stage is independently testable. The data flows in one direction. Dependencies flow downward (DSM shows zero inversions).

### Detailed Architecture Review

**Parser (`parse.py`, 315 lines)**
- State-machine based, line-by-line parsing
- Handles VDOM scope switching, multiline blobs, quoted strings
- Known limitation: flattens nested config blocks inside edit blocks
- Deterministic: same input always produces same output
- Preserves line numbers for evidence tracking
- Verdict: **Solid.** The flattening limitation is documented and worked around.

**Model (`model.py`, 31 lines)**
- Frozen dataclasses for Evidence, mutable for Node and ConfigModel
- Minimal — just data containers
- Verdict: **Excellent.** No unnecessary complexity.

**Facts Engine (`facts.py`, 179 lines)**
- Derives edge interfaces from default routes, policy routes, SD-WAN
- Resolves zone-to-interface mappings with hierarchy awareness
- Handles VLAN ancestry, software switch members
- Verdict: **Good.** Could benefit from deeper HA topology awareness.

**Rule Engine (`rules.py`, 76 lines)**
- YAML-based rule definitions with Python entrypoints
- Schema-aware execution with version resolution
- Results sorted deterministically
- Verdict: **Good but needs refactoring.** The `_import_callable` dynamic loading is simple but the monolithic `rules_impl.py` hurts maintainability.

**Rules Implementation (`rules_impl.py`, 2,515 lines)**
- 35 rules in a single file
- Each rule follows a consistent pattern but with significant boilerplate
- Strong schema-checking discipline
- Verdict: **Functionally solid, structurally problematic.** This is the #1 architectural debt item. Each rule function is 30-80 lines of mostly repetitive code. A rule framework/template system would eliminate 60% of the code.

**Schema (`schema.py`, 100 lines)**
- Loads JSON schema files from `docs/derived/schema/<version>/schema.json`
- Provides `has_table()`, `has_field()`, `allowed_values()`
- Version family fallback (8.0.1 → 8.0)
- Verdict: **Excellent design, shallow data.** The schema system is well-designed but the data coverage is only 2.8% (17/600+ tables with fields).

**Authority (`authority.py`, 217 lines)**
- Lookup commands (lookup/schema/docs) for validating FortiOS syntax
- Returns VALIDATED/PARTIALLY_VALIDATED/UNKNOWN
- Handles ambiguous matches gracefully
- Verdict: **Good.** Unique capability — no other tool offers this.

**Report (`report.py`, 479 lines)**
- JSON, Markdown, Human, HTML, PDF output
- HTML has professional styling with severity badges and KPI grids
- PDF via weasyprint (optional dependency)
- Verdict: **Good.** Could benefit from Jinja2 templates for customization.

**Baseline (`baseline.py`, 125 lines)**
- JSON-based finding suppression
- Matching by rule_id, severity, vdom, message, file_id, line range
- Merge and update workflows
- Verdict: **Good.** Clean and functional.

**CLI (`cli.py`, 347 lines)**
- Single-file and folder scanning
- Rich argument handling (baseline, severity, VDOM, format, output)
- Clean separation between single-file and folder paths
- Verdict: **Functional but has duplication.** The single-file and folder code paths duplicate significant logic. A refactor to share more code would reduce maintenance burden.

### Architectural Debt Items (Priority Order)

1. **rules_impl.py monolith** — Split into rule modules or create a rule framework
2. **CLI code duplication** — Single-file vs folder paths duplicate ~100 lines
3. **Rule boilerplate** — Every rule repeats schema-check + table-lookup + iterate + emit pattern
4. **No rule description/remediation** — YAML definitions lack documentation fields
5. **Parser flattening limitation** — Documented but causes workarounds in multiple rules

### Architecture Strengths Worth Preserving

1. **Evidence-first design** — Every finding has line-accurate evidence
2. **Schema-gating** — Rules gracefully degrade when schema is missing
3. **Deterministic execution** — Same input → same output, always
4. **Clean dependency graph** — Zero circular imports, downward flow
5. **YAML rule definitions** — Easy to add new rules without touching Python
6. **Baseline workflow** — Production-grade suppression lifecycle

---

## 6. What Would Make This the Best FortiGate Checker in Existence

### Differentiation Matrix

| Capability | fgcheck | Fortinet Audit Tools | Generic Linters | Custom Scripts |
|-----------|---------|---------------------|-----------------|----------------|
| Deterministic findings | ✅ | ✅ | ❌ | Varies |
| Schema-gated | ✅ | Partial | ❌ | ❌ |
| Evidence with line refs | ✅ | ❌ | ❌ | Varies |
| Multi-version support | ✅ (7.4,7.6,8.0) | Single version | ❌ | Varies |
| Multi-VDOM | ✅ | ❌ | ❌ | Varies |
| Topology-aware (edge detection) | ✅ | ❌ | ❌ | ❌ |
| Authority lookup | ✅ | ❌ | ❌ | ❌ |
| Baseline suppression | ✅ | ❌ | ❌ | Varies |
| CI/CD ready | Partial | ❌ | ✅ | Varies |
| Custom rules | Partial | ❌ | ❌ | N/A |
| Compliance mapping | ❌ | Partial | ❌ | ❌ |
| CVE-aware | Planned | ❌ | ❌ | Varies |
| API mode | ❌ | Partial | N/A | Varies |
| Free/open source | ❌ (no license) | ❌ | ✅ | ✅ |

### Top 10 Features to Become Best-in-Class

1. **Compliance framework mapping** — Tag every rule with NIST 800-53, CIS Benchmark, PCI DSS, HIPAA control IDs. Generate compliance reports showing pass/fail per framework.

2. **CVE-aware detection** — Cross-reference detected firmware version with CISA KEV and FortiGuard PSIRT. Flag configs running versions with known critical vulnerabilities.

3. **FortiManager API integration** — Pull configs directly from FortiManager for fleet-wide scanning. No manual config export required.

4. **Custom rule authoring SDK** — Allow users to write rules in YAML + Python, with a template generator (`fgcheck new-rule --name MY-RULE --category firewall --severity high`).

5. **SARIF output** — Native GitHub code scanning integration. Security findings appear in the repository Security tab.

6. **Config drift detection** — Compare current scan against historical baseline. Detect when new findings appear or known issues are reintroduced.

7. **Fleet dashboard** — Scan hundreds of FortiGates, aggregate results, show worst offenders, track posture over time.

8. **IDE integration** — VS Code extension that validates FortiOS configs as you type, showing findings inline.

9. **Network topology visualization** — Generate diagrams showing edge interfaces, zones, VPN tunnels, and their security posture.

10. **AI-assisted remediation** — While maintaining detector-only principle, provide semantic remediation intent that an AI agent can translate to CLI commands (without executing them).

---

## 7. Competitor Landscape

### Direct Competitors

**Fortinet FortiManager / FortiAnalyzer**
- Enterprise-grade but expensive
- Closed-source, requires Fortinet licensing
- Focused on management, not security audit
- Weak on configuration compliance checking

**Custom Ansible/Terraform Modules**
- Common approach for FortiGate automation
- Focused on provisioning, not auditing
- No standardized security rule set
- Maintenance burden falls on the team

**CIS Benchmark Tools**
- CIS provides FortiGate benchmarks (paid)
- Manual checklist approach
- No automated config checking
- Annual update cycle

**Security Audit Consultants**
- Manual config review by specialists
- Expensive ($5K-$50K per audit)
- Point-in-time, not continuous
- Inconsistent methodology

### Indirect Competitors

**General-purpose network config linters**
- Napalm/napalm-logs, Netmiko ecosystem
- Focused on operational correctness, not security
- No FortiOS-specific rules

**Cloud security posture management (CSPM)**
- Prisma Cloud, Wiz, Orca
- Focused on cloud, not on-prem firewalls
- No FortiOS config parsing

### Competitive Advantages of fgcheck

1. **Deterministic, schema-gated** — No other tool validates findings against FortiOS schema
2. **Free and open** (once licensed) — No Fortinet licensing required
3. **Evidence-first** — Every finding points to exact config lines
4. **CI/CD ready** — Baseline suppression and severity gating
5. **Topology-aware** — Understands edge interfaces, zones, routing
6. **Multi-version** — 7.4, 7.6, 8.0 with automatic version detection
7. **Authority lookup** — Unique capability to validate FortiOS syntax

### Competitive Risks

1. Fortinet could build this into FortiManager/FortiAnalyzer
2. CIS could release an automated benchmark tool
3. A well-funded startup could build a commercial equivalent
4. Community open-source projects could fragment the space

---

## 8. Target Audience and Use Cases

### Primary Audience: FortiGate Administrators

**Who:** Network engineers and security administrators managing FortiGate firewalls  
**Use case:** Pre-deployment security review, daily config validation, post-change verification  
**Pain point:** Manual review is time-consuming and error-prone  
**Value prop:** Automated security checks with exact evidence, runs in seconds

### Secondary Audience: Security Auditors / Compliance Teams

**Who:** Internal audit, external assessors, GRC teams  
**Use case:** Compliance assessment (PCI DSS, NIST, CIS), security posture reporting  
**Pain point:** Manual checklist approach doesn't scale  
**Value prop:** Automated compliance mapping, PDF/HTML reports for evidence packages

### Tertiary Audience: Managed Service Providers (MSPs)

**Who:** Fortinet-managed service providers, MSSPs  
**Use case:** Multi-client config monitoring, fleet-wide security posture, drift detection  
**Pain point:** Each client has different configs, manual review per-client  
**Value prop:** Batch scanning, baseline management, aggregate reporting

### Quaternary Audience: DevOps/NetOps

**Who:** Teams using Infrastructure-as-Code for FortiGate (Ansible, Terraform)  
**Use case:** CI/CD config validation, pre-deploy security gate  
**Pain point:** No automated way to validate FortiGate configs in pipelines  
**Value prop:** CLI tool with JSON output, exit codes, baseline integration

### Use Case Matrix

| Use Case | Frequency | Audience | Format | Integration |
|----------|-----------|----------|--------|-------------|
| Pre-deploy security review | Per change | Admin | HTML/PDF | Manual |
| Daily config validation | Daily | Admin | JSON/CSV | Cron |
| Compliance assessment | Quarterly | Auditor | PDF/HTML | Manual |
| CI/CD gate | Per commit | DevOps | JSON/SARIF | GitHub Actions |
| Fleet monitoring | Weekly | MSP | JSON/HTML | API |
| Incident response | Ad-hoc | Admin | Human/JSON | CLI |

---

## 9. Pricing Model Possibilities

### Option 1: Open Source (MIT) + Commercial Extensions

**Free tier (MIT license):**
- Core CLI tool
- 35+ builtin rules
- Multi-format output
- Baseline suppression
- Schema validation

**Commercial tier ($50-200/month per seat):**
- 100+ rules with compliance mapping
- FortiManager API integration
- REST API
- Web dashboard
- Fleet management
- Priority support
- Custom rule authoring SDK

### Option 2: Open Core

**Community edition (Apache 2.0):**
- All current features
- Custom rule authoring
- Community rule marketplace

**Enterprise edition ($100-500/month):**
- Fleet management dashboard
- SSO/RBAC
- Audit trail
- Scheduled scanning
- SIEM integration
- SLA-backed support

### Option 3: SaaS Platform

**Free (limited):**
- 1 config scan per day
- 10 rules
- JSON output only

**Pro ($49/month):**
- Unlimited scans
- All rules
- All output formats
- API access

**Enterprise ($299/month):**
- Fleet management
- Compliance reports
- SIEM integration
- Custom rules
- SSO/RBAC

### Recommendation

**Start with Option 1 (MIT + commercial extensions).** The core tool should be free to build community adoption and trust. Revenue comes from enterprise features that MSPs and large organizations need. The authority lookup feature alone could justify commercial licensing for automation integrations.

---

## 10. Technical Roadmap Priorities

### Phase 0: Make It Distributable (1-2 weeks)

| Task | Effort | Priority |
|------|--------|----------|
| Add MIT LICENSE | 1 hour | P0 |
| Add `--version` flag to CLI | 1 hour | P0 |
| Cross-platform README (Linux/macOS examples) | 2 hours | P0 |
| `pip install fgcheck` on PyPI | 1 day | P0 |
| CHANGELOG.md | 1 hour | P0 |
| Rule catalog documentation | 4 hours | P0 |
| Exit code documentation | 1 hour | P1 |
| Error messages for missing files/configs | 4 hours | P1 |
| GitHub Actions CI | 1 day | P1 |
| Docker image | 4 hours | P1 |

### Phase 1: Schema Depth (2-4 weeks)

| Task | Effort | Priority |
|------|--------|----------|
| Expand field extraction to 50+ security tables | 2 weeks | P1 |
| Schema coverage report tool | 1 day | P1 |
| Schema v2v diff tool | 1 day | P2 |
| FortiOS 7.0/7.2 heuristic support | 1 week | P2 |

### Phase 2: Rule Expansion (2-4 weeks)

| Task | Effort | Priority |
|------|--------|----------|
| Wave 3 remaining rules (5 planned) | 1 week | P1 |
| Wave 4 compliance rules (20 planned) | 2 weeks | P1 |
| Rule YAML schema: add description, remediation, compliance_tags | 2 days | P1 |
| Custom rule loading from user directories | 1 day | P2 |
| Rule framework to reduce rules_impl boilerplate | 1 week | P2 |

### Phase 3: Integration (2-4 weeks)

| Task | Effort | Priority |
|------|--------|----------|
| SARIF output | 2 days | P1 |
| JUnit XML output | 1 day | P2 |
| Python library API (import fgcheck) | 2 days | P1 |
| REST API with FastAPI | 1 week | P2 |
| FortiManager API integration | 1 week | P2 |

### Phase 4: Enterprise Features (4-8 weeks)

| Task | Effort | Priority |
|------|--------|----------|
| CVE-aware detection (Wave 5) | 2 weeks | P2 |
| Compliance mapping (NIST, CIS, PCI) | 2 weeks | P2 |
| Fleet management | 2 weeks | P3 |
| Web dashboard | 2-4 weeks | P3 |
| Config drift detection | 1 week | P3 |
| SIEM output (CEF/LEEF) | 3 days | P3 |

### Critical Path Dependencies

```
LICENSE → PyPI Package → User Adoption
Schema Depth → More Rules → Higher Confidence Findings
CI/CD → Quality Gate → Release Confidence
SARIF → GitHub Integration → Developer Adoption
Compliance Mapping → Enterprise Sales → Revenue
```

---

## Appendix A: Code-Level Gaps Summary

| File | Lines | Issue | Fix |
|------|-------|-------|-----|
| rules_impl.py | 2,515 | Monolithic, repetitive | Extract to rule modules or create framework |
| cli.py | 347 | Duplicated single-file/folder logic | Refactor shared pipeline |
| report.py | 479 | Inline HTML/CSS | Move to Jinja2 templates |
| model.py | 31 | Missing __repr__ for debugging | Add human-readable repr |
| parse.py | 315 | Flattens nested blocks | Document limitation, add workaround API |
| rules YAML | 5 lines each | No description/remediation | Extend YAML schema |
| pyproject.toml | 15 | Missing classifiers, license, URLs | Complete package metadata |
| No .gitignore entry for tests/real/ | — | Real configs could leak | Add to .gitignore |

## Appendix B: Key Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Source lines (src/) | 4,444 | — |
| Test lines | ~10,355 | — |
| Total lines | 14,799 | — |
| Builtin rules | 35 | 75+ |
| Schema tables with fields | 17 | 100+ |
| Schema versions | 3 | 5+ |
| Test count | 416 | 600+ |
| Quality signal (Sentrux) | 0.6432 | 0.80+ |
| Test coverage ratio | 15.5% | 80%+ |
| Acyclicity | 1.0 | 1.0 (maintain) |
| Bus factor | 1.0 | 2.0+ |
| Tests per second | ~52 | — |
| Days since last commit | 0 | — |
