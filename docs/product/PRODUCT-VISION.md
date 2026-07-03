# fortigatecheck Product Vision

**Date:** 2026-07-03
**Status:** Planning

---

## What fortigatecheck IS

A deterministic FortiGate configuration checker that:

1. **Parses** FortiOS text config files (show config full)
2. **Validates** against FortiOS schema (table/field existence)
3. **Checks** security posture via 35 built-in rules
4. **Reports** findings in human/JSON/markdown/HTML/PDF formats
5. **Compares** configs against baselines
6. **Resolves** FortiOS version-specific syntax

### Core Principles
- Detector-only: no automatic fix execution
- Schema-gated correctness: no unsupported syntax claims
- Evidence-first findings: exact config line evidence
- Deterministic: same input → same output, no LLM hallucination

---

## What fortigatecheck SHOULD BE

### The No-Hallucination FortiGate Platform

A tool that FortiGate administrators, security auditors, and managed service providers trust because it:

1. **Never hallucinates** — every finding is backed by schema evidence
2. **Catches syntax errors** — not just security, but config correctness
3. **Knows FortiOS deeply** — tables, fields, allowed values, CLI syntax
4. **Handles real-world configs** — multi-VDOM, FortiManager exports, HA artifacts
5. **Scales** — processes thousands of configs efficiently
6. **Integrates** — API, CI/CD, SIEM, FortiManager API
7. **Reports beautifully** — executive summaries, technical details, compliance mapping

---

## Target Audiences

1. **FortiGate Administrators** — daily config validation
2. **Security Auditors** — pre-deployment security review
3. **MSPs** — multi-client config monitoring
4. **Compliance Teams** — NIST/CIS/Fortinet best practices
5. **FortiManager Operators** — config drift detection
6. **DevOps/NetOps** — CI/CD config validation

---

## Gap Analysis (Current → World-Class)

### What EXISTS today
- ✅ 35 security rules
- ✅ Schema validation (table_only)
- ✅ Authority lookup
- ✅ Multi-format reporting
- ✅ Multi-VDOM support
- ✅ Baseline comparison
- ✅ 416 tests

### What's MISSING for distributable product
- ❌ Syntax validation (not just security)
- ❌ Complete FortiOS schema (table_only → full field coverage)
- ❌ FortiManager config parsing
- ❌ Large config performance (10MB+)
- ❌ CI/CD integration (GitHub Actions, GitLab CI)
- ❌ API mode (REST API for automation)
- ❌ Packaging (pip install, Docker)
- ❌ Documentation (user guide, API docs)
- ❌ License file
- ❌ Changelog
- ❌ Error handling for edge cases
- ❌ Concurrent scanning
- ❌ Config diff between versions
- ❌ FortiOS 7.0/7.2/8.0 syntax support
- ❌ YAML/JSON config format support
- ❌ Custom rule authoring
- ❌ Rule severity customization
- ❌ Baseline templates
- ❌ Compliance mapping (NIST, CIS, Fortinet)

---

## Roadmap Phases

### Phase 1: Foundation (Current → Distributable MVP)
- Syntax validation rules
- Complete parser edge case coverage
- Packaging (pip install fgcheck)
- CLI polish
- Error handling
- User documentation
- License and changelog

### Phase 2: Schema Depth
- Full FortiOS schema (field-level coverage)
- Allowed values validation
- Version-specific behavior
- FortiManager config support
- Large config performance

### Phase 3: Security Depth
- 50+ security rules
- Compliance mapping (NIST 800-53, CIS, Fortinet best practices)
- Custom rule authoring
- Rule severity customization
- Baseline templates

### Phase 4: Integration
- REST API
- CI/CD plugins
- FortiManager API integration
- SIEM export
- Batch processing
- Config diff

### Phase 5: Enterprise
- Multi-tenant support
- Web dashboard
- Scheduled scanning
- Alerting
- Audit trail
- SSO integration
