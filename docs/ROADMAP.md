# fgcheck Roadmap

Last updated: 2026-07-01

## Current State Summary

### By the Numbers
- **152 tests** — all passing
- **2,682 lines** of source code across 13 modules
- **3,977 lines** of test code across 20 test files
- **17 builtin rules** covering admin access, firewall policies, SSL VPN, IPSec, logging, local-in
- **2 schema versions** — 7.4 (597 tables) and 7.6 (625 tables)
- **17 priority tables** with field-level details (system interface, firewall policy, system admin, etc.)
- **CVE/PSIRT/KEV** corpus pipeline functional

### What Works
- **Parser**: Multiline blob handling, VDOM scope switching, nested config/end restoration, line-preserving
- **Facts engine**: Default-route edge detection, SD-WAN member resolution, policy-route edge projection, zone-to-interface mapping, software switch hierarchy, VLAN ancestry
- **Schema system**: Version family fallback, table/field lookup, allowed_values, table_only vs full coverage flagging
- **Versioning**: config-version header > --fortios flag > 7.4 default
- **Authority lookup**: lookup/schema/docs subcommands, VALIDATED/PARTIALLY_VALIDATED/UNKNOWN classification
- **Rule engine**: Schema-gated execution, confidence degradation when schema is partial, stable sorted output
- **CLI**: Single-file and folder scan, json/md/human/html output, PDF export, baseline suppression, severity gating, VDOM filtering, summary JSON, CSV output
- **Report**: Rich HTML with embedded documents, human-readable summaries, markdown tables

### Schema Coverage Status
Both 7.4 and 7.6 have `table_only` coverage for the corpus as a whole.
Priority tables (system interface, firewall policy, system admin, vpn ssl settings, etc.) have full field-level extraction.
600+ remaining tables have only table names without field details.

---

## Version Policy Update

### Current First-Class Support
- FortiOS **7.4.x** — latest point release: 7.4.12
- FortiOS **7.6.x** — latest point release: 7.6.7

### New Version to Add
- FortiOS **8.0.x** — 8.0.0 just released (CLI reference available at docs.fortinet.com)

### Version Support Tiers
1. **First-class**: 7.4.x, 7.6.x (schema + rules + tests)
2. **Next-first-class**: 8.0.x (schema ingestion + compatibility)
3. **Legacy**: 7.0.x, 7.2.x (best-effort, heuristic only)

---

## Phase Roadmap

### Phase 1: Stabilize and Expand Rules (Week 1-2)
**Goal**: Expand the detection surface from 17 to 30+ rules with full schema backing.

| Task | Priority | Rules Added |
|------|----------|-------------|
| DNS settings hardening | High | FGT-DNS-NO-ZT, FGT-DNS-DEFAULT-ONLY |
| NTP source validation | High | FGT-NTP-NO-NTPS |
| SNMP community hardening | High | FGT-SNMP-WEAK-COMMUNITY |
| Interface security | High | FGT-IFACE-NO-VLAN-SECURITY |
| DHCP snooping awareness | Medium | FGT-DHCP-SNOOP |
| FortiGuard web filter | Medium | FGT-FGFM-DEFAULT-OVERRIDE |
| Password policy | High | FGT-ADMIN-WEAK-PASSWORD-POLICY |
| Admin idle timeout | Medium | FGT-ADMIN-NO-IDLE-TIMEOUT |
| Certificate expiry | Medium | FGT-CERT-EXPIRING |
| Firmware version currency | High | FGT-FIRMWARE-OUTDATED |

### Phase 2: Schema Corpus Enrichment (Week 2-3)
**Goal**: Move from table_only to field-level coverage for all security-critical tables.

| Task | Priority |
|------|----------|
| Extract fields from 7.4.12 CLI reference | High |
| Extract fields from 7.6.7 CLI reference | High |
| Extract fields from 8.0.0 CLI reference | High |
| Add 8.0 to sources.yaml and build_corpus.py | High |
| Validate priority table field extraction accuracy | High |
| Add schema diff tooling (version-to-version changes) | Medium |

### Phase 3: FortiOS 8.0 Support (Week 3-4)
**Goal**: Full first-class support for 8.0.x alongside 7.4 and 7.6.

| Task | Priority |
|------|----------|
| Add 8.0 to sources.yaml with CLI reference URL | High |
| Run build_corpus.py to generate 8.0 schema | High |
| Add 8.0 version family to versioning.py | High |
| Update tests to cover 8.0 version resolution | High |
| Test all 17+ rules against 8.0 schema | High |
| Document 8.0-specific new/changed config paths | Medium |

### Phase 4: Facts Engine Depth (Week 4-5)
**Goal**: Deep interface hierarchy, HA topology, and wireless controller awareness.

| Task | Priority |
|------|----------|
| Software switch member port resolution | High |
| Nested parent/child interface ancestry (VLAN, LAG, etc.) | High |
| HA cluster topology facts | Medium |
| Wireless controller interface mapping | Medium |
| Zone membership through nested interfaces (extended) | Medium |

### Phase 5: Production Readiness (Week 5-6)
**Goal**: CI integration, performance, and documentation completeness.

| Task | Priority |
|------|----------|
| GitHub Actions CI with pytest + schema validation | High |
| Performance benchmarks for large configs (1000+ policies) | Medium |
| Baseline workflow documentation | Medium |
| Real-config regression suite (sanitized fixtures) | High |
| Rule documentation with rationale and remediation intent | Medium |
| API/library usage documentation | Medium |

---

## Overnight Work Plan (Phase 1 Kickoff)

### Workstream A: New Rules (Claude Code)
- Add FGT-DNS-NO-ZT, FGT-DNS-DEFAULT-ONLY, FGT-NTP-NO-NTPS
- Add FGT-SNMP-WEAK-COMMUNITY, FGT-ADMIN-WEAK-PASSWORD-POLICY
- Add FGT-ADMIN-NO-IDLE-TIMEOUT, FGT-FIRMWARE-OUTDATED
- Each rule: YAML definition + implementation in rules_impl.py + tests

### Workstream B: Schema Enrichment + 8.0 (Codex)
- Update sources.yaml with 8.0 CLI reference URL
- Update build_corpus.py to handle 8.0
- Add 8.0 version family to schema.py and versioning.py
- Add schema tests for 8.0 fallback behavior

### Workstream C: Documentation + Session Handoff (Hermes)
- Update SESSION_HANDOFF.md with current state
- Update sources.yaml with latest version references
- Update README.md with new rules and version info
- Write this roadmap

---

## Definition of Done

The project reaches production-grade trust when:

1. Parser handles real FortiOS 7.4, 7.6, and 8.0 configs without systematic false warnings
2. Facts correctly model edge/interface topology across common enterprise patterns
3. Rules are version-scoped and schema-gated for all three version families
4. Findings provide line-accurate evidence and truthful confidence
5. Corpus pipeline is reproducible and restricted to official sources
6. 30+ builtin rules covering the most critical FortiGate security checks
7. CI runs automatically on every push with full test suite
