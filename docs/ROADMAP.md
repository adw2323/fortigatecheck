# fgcheck Roadmap — Living Document

Last updated: 2026-07-03

> This is a living roadmap. It grows as the project grows. Every completed milestone
> adds the next frontier. The goal is never "done" — it is always expanding coverage,
> deepening detection, and hardening production readiness.

---

## Current State

### By the Numbers
| Metric | Value | Trend |
|--------|-------|-------|
| Tests passing | 416 | Up from 400 |
| Source files | 13 modules | Growing |
| Test files | 34 | Growing |
| Builtin rules | 35 | Up from 34 |
| Schema versions | 3 (7.4, 7.6, 8.0) | Up from 2 |
| Quality signal (Sentrux) | 0.6411 | Target: 0.80+ |
| Test coverage (Sentrux) | 20% | Target: 80%+ |

### Schema Coverage
| Version | Tables | With Fields | Coverage |
|---------|--------|-------------|----------|
| 7.4 | 597 | 17 | table_only |
| 7.6 | 625 | 17 | table_only |
| 8.0 | 646 | 17 | table_only |

---

## Growth Tracks

Each track is a continuous effort that expands over time. Items move from
Planned -> In Progress -> Done -> Expanded as the project matures.

---

### TRACK 1: Rule Coverage Expansion

**Goal**: Comprehensive detection of FortiGate security misconfigurations.
Start with critical/likely findings, expand to best-practice and hardening checks.

#### Wave 1 — Core Security Controls (20/30 target)
| Rule | Category | Severity | Status |
|------|----------|----------|--------|
| FGT-ADMIN-EDGE-SSH | Admin access | high | DONE |
| FGT-ADMIN-EDGE-HTTPS | Admin access | high | DONE |
| FGT-ADMIN-EDGE-TELNET | Admin access | critical | DONE |
| FGT-ADMIN-EDGE-HTTP | Admin access | critical | DONE |
| FGT-ADMIN-EDGE-ALLACCESS | Admin access | critical | DONE |
| FGT-ADMIN-NO-TRUSTED-HOSTS | Admin access | high | DONE |
| FGT-ADMIN-TRUSTHOST-UNRESTRICTED | Admin access | high | DONE |
| FGT-ADMIN-SUPER-NO-2FA | Admin access | high | DONE |
| FGT-POLICY-ANY-ANY-ALL | Firewall | critical | DONE |
| FGT-POLICY-LOG-001 | Firewall | medium | DONE |
| FGT-LOCAL-IN-PERMISSIVE | Local-in | high | DONE |
| FGT-LOCALIN-NO-PROTECTION | Local-in | critical | DONE |
| FGT-SSLVPN-MIN-TLS | SSL VPN | high | DONE |
| FGT-SSLVPN-SRCINTF-ANY | SSL VPN | high | DONE |
| FGT-SSLVPN-SRCADDR-ALL | SSL VPN | critical | DONE |
| FGT-IPSEC-WEAK-DH | IPSec | high | DONE |
| FGT-NO-REMOTE-LOGGING | Logging | high | DONE |
| FGT-DNS-NO-ZT | DNS | medium | DONE |
| FGT-NTP-NO-NTPS | NTP | medium | DONE |
| FGT-SNMP-WEAK-COMMUNITY | SNMP | high | DONE |

#### Wave 2 — Hardening and Policy (target: +10 rules)
| Rule | Category | Severity | Status |
|------|----------|----------|--------|
| FGT-ADMIN-WEAK-PASSWORD-POLICY | Password | high | DONE |
| FGT-ADMIN-NO-IDLE-TIMEOUT | Admin | high | DONE |
| FGT-FIRMWARE-OUTDATED | Firmware | high | DONE |
| FGT-DNS-DEFAULT-ONLY | DNS | medium | DONE |
| FGT-DHCP-SNOOP | DHCP | medium | DONE |
| FGT-IFACE-NO-VLAN-SECURITY | Interface | medium | DONE |
| FGT-FGFM-DEFAULT-OVERRIDE | FortiGuard | medium | DONE |
|| FGT-CERT-EXPIRING | Certificate | high | DONE |
| FGT-SSH-WEAK-CIPHERS | SSH | high | DONE |
| FGT-SNMP-NO-ACL | SNMP | medium | DONE |

#### Wave 3 — Deep Inspection (target: +15 rules)
| Rule | Category | Severity | Status |
|------|----------|----------|--------|
| FGT-IPS-DEFAULT-SIGNATURE | IPS | medium | DONE |
| FGT-WEBFILTER-DEFAULT-OVERRIDE | Web filter | medium | DONE |
| FGT-AV-NO-HEURISTIC | Antivirus | medium | DONE |
|| FGT-DLP-NO-SENSOR | DLP | low | DONE |
| FGT-WAF-NO-PROFILE | WAF | medium | PLANNED |
| FGT-EMAILFILTER-NO-DNSBL | Email filter | low | PLANNED |
| FGT-SSLVPN-NO-MFA | SSL VPN | high | DONE |
| FGT-ADMIN-LOCKOUT-NO-TRIES | Admin | medium | PLANNED |
| FGT-FW-NO-SENSITIVE-PATTERNS | Firewall | medium | PLANNED |
| FGT-LOG-NO-TRAFFIC | Logging | medium | PLANNED |
| FGT-HA-NO-HEARTBEAT | HA | high | PLANNED |
| FGT-SDWAN-NO-HEALTH-CHECK | SD-WAN | medium | PLANNED |
| FGT-ROUTING-NO-ROUTE-FILTER | Routing | low | PLANNED |
| FGT-ZONE-NO-SEGMENTATION | Zone | medium | PLANNED |
| FGT-VDOM-NO-RESOURCE-LIMIT | VDOM | low | PLANNED |

#### Wave 4 — Compliance and Audit (target: +20 rules)
Rules mapped to compliance frameworks:
| Rule | Framework | Status |
|------|-----------|--------|
| FGT-COMPLIANCE-FIPS-MODE | FIPS/CC | PLANNED |
| FGT-COMPLIANCE-NIST-AC-2 | NIST 800-53 | PLANNED |
| FGT-COMPLIANCE-NIST-AC-3 | NIST 800-53 | PLANNED |
| FGT-COMPLIANCE-NIST-SC-7 | NIST 800-53 | PLANNED |
| FGT-COMPLIANCE-PCI-1-2-1 | PCI DSS | PLANNED |
| FGT-COMPLIANCE-PCI-2-2-1 | PCI DSS | PLANNED |
| FGT-COMPLIANCE-PCI-6-5-6 | PCI DSS | PLANNED |
| FGT-COMPLIANCE-HIPAA-164-312 | HIPAA | PLANNED |
| FGT-COMPLIANCE-CIS-1-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-1-2-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-3-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-4-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-5-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-6-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-CIS-7-1-1 | CIS Benchmark | PLANNED |
| FGT-COMPLIANCE-STIG-CAT1 | DISA STIG | PLANNED |
| FGT-COMPLIANCE-STIG-CAT2 | DISA STIG | PLANNED |
| FGT-COMPLIANCE-STIG-CAT3 | DISA STIG | PLANNED |
| FGT-COMPLIANCE-BESTPRACTICE-AUDIT | Best Practice | PLANNED |
| FGT-COMPLIANCE-BESTPRACTICE-CHANGELOG | Best Practice | PLANNED |

#### Wave 5 — CVE-Aware Detection (target: +10 rules)
Rules that cross-reference CVE/PSIRT/KEV data with config:
| Rule | Description | Status |
|------|-------------|--------|
| FGT-CVE-UNPATCHED-SERVICE | Detect services exposed on unpatched versions | PLANNED |
| FGT-CVE-KEV-EXPOSURE | Flag configs with services matching KEV entries | PLANNED |
| FGT-CVE-PSIRT-OUTSTANDING | Check for outstanding PSIRT advisories | PLANNED |
| FGT-CVE-SSLVPN-HISTORY | Flag SSL VPN on versions with known vulns | PLANNED |
| FGT-CVE-IPSEC-WEAK | Cross-reference IPSec configs with CVE history | PLANNED |
| FGT-CVE-ADMIN-EXPOSED | Admin access + known admin CVEs | PLANNED |
| FGT-CVE-FIRMWARE-RISK | Firmware version + known CVE risk score | PLANNED |
| FGT-CVE-DNS-AMPLIFICATION | DNS config + amplification CVEs | PLANNED |
| FGT-CVE-SNMP-V2C | SNMPv2c + known SNMP CVEs | PLANNED |
| FGT-CVE-LOCALIN-EXPOSURE | Local-in + known exposure CVEs | PLANNED |

**Running target: 75 rules total across 5 waves.**

---

### TRACK 2: Schema Corpus Depth

**Goal**: Full field-level coverage for every security-relevant table in every supported FortiOS version.

#### Current: 17 priority tables with fields, 600+ table-only
#### Target: 100+ tables with full field extraction

| Milestone | Tables Targeted | Status |
|-----------|----------------|--------|
| Priority 17 (interface, policy, admin, ssl, ipsec, local-in, logging) | 17 | DONE |
| Security services (antivirus, ips, webfilter, emailfilter, dnsfilter) | +15 | PLANNED |
| VPN infrastructure (certificate, ssh, ssl, ipsec phase2) | +12 | PLANNED |
| System settings (global, settings, fips, ssh-config, password-policy) | +10 | PLANNED |
| SNMP + NTP + DNS + DHCP full field extraction | +8 | PLANNED |
| Switch controller + wireless controller tables | +15 | PLANNED |
| HA and clustering tables | +5 | PLANNED |
| DLP + WAF + reporting tables | +10 | PLANNED |
| Remaining tables | +80 | PLANNED |

#### Schema Tooling
| Tool | Purpose | Status |
|------|---------|--------|
| build_corpus.py | HTML extraction from Fortinet docs | DONE |
| schema diff (v2v) | Show what changed between versions | PLANNED |
| schema coverage report | Table/field coverage stats | PLANNED |
| schema validation CLI | Validate configs against schema directly | PLANNED |
| schema changelog generator | Auto-generate changelog from schema diffs | PLANNED |

---

### TRACK 3: FortiOS Version Coverage

**Goal**: Support every actively maintained FortiOS version with schema-backed detection.

| Version | Status | Schema | Notes |
|---------|--------|--------|-------|
| 7.4.x (latest 7.4.12) | First-class | 597 tables, 17 fields | DONE |
| 7.6.x (latest 7.6.7) | First-class | 625 tables, 17 fields | DONE |
| 8.0.x (8.0.0) | First-class | 646 tables, 17 fields | DONE |
| 7.0.x | Legacy/heuristic | Missing | PLANNED |
| 7.2.x | Legacy/heuristic | Missing | PLANNED |
| Future 7.6.x point releases | Auto-detect | Family fallback | DONE |
| Future 8.0.x point releases | Auto-detect | Family fallback | DONE |
| Future 8.2.x+ | Add on release | New extraction | PLANNED |

#### Version-Aware Rule Behavior
| Behavior | Status |
|----------|--------|
| Rules skip gracefully when schema is missing | DONE |
| Rules degrade from certain -> heuristic when partial | DONE |
| Version family fallback (8.0.1 -> 8.0) | DONE |
| Config header version detection | DONE |
| CLI --fortios override | DONE |

---

### TRACK 4: Facts Engine Depth

**Goal**: Model the complete FortiGate topology — interfaces, routing, zones, HA, VPN, wireless.

| Capability | Status |
|------------|--------|
| Default-route edge detection | DONE |
| SD-WAN member resolution | DONE |
| Policy-route output-device projection | DONE |
| Zone-to-interface mapping | DONE |
| Software switch hierarchy | DONE |
| VLAN ancestry | DONE |
| HA cluster topology | PLANNED |
| Wireless controller interfaces | PLANNED |
| 802.1Q VLAN trunk/access awareness | PLANNED |
| LAG/bonding interface mapping | PLANNED |
| Bridge domain facts | PLANNED |
| Virtual-wire pair detection | PLANNED |
| IPsec tunnel endpoint topology | PLANNED |
| SSL VPN tunnel routing facts | PLANNED |
| OSPF/BGP neighbor facts | PLANNED |
| Multi-hop routing path detection | PLANNED |

---

### TRACK 5: Parser Robustness

**Goal**: Handle every valid FortiOS config format without false warnings.

| Capability | Status |
|------------|--------|
| Standard set/value pairs | DONE |
| Multiline blobs (certs, keys) | DONE |
| VDOM scope switching | DONE |
| Nested config/end blocks | DONE |
| Line-preserving output | DONE |
| Encrypted blocks (redacted configs) | PLANNED |
| FortiManager/FortiAnalyzer import configs | PLANNED |
| Partial/truncated configs | PLANNED |
| Config merge annotations | PLANNED |
| Comment-only sections | PLANNED |
| Unicode/internationalized values | PLANNED |

---

### TRACK 6: Reporting and Output

**Goal**: Production-ready reporting for human consumers and CI pipelines.

| Capability | Status |
|------------|--------|
| JSON output | DONE |
| Markdown output | DONE |
| Human-readable output | DONE |
| HTML with embedded docs | DONE |
| PDF export (via weasyprint) | DONE |
| CSV findings export | DONE |
| Summary JSON | DONE |
| Baseline suppression | DONE |
| Baseline merge/update | DONE |
| Severity gating (fail on severity) | DONE |
| VDOM filtering | DONE |
| SARIF output (for GitHub code scanning) | PLANNED |
| CycloneDX SBOM-style output | PLANNED |
| JUnit XML output (for CI) | PLANNED |
| Dashboard HTML (interactive) | PLANNED |
| Trend tracking across scans | PLANNED |
| Finding deduplication across config sets | PLANNED |
| Comparative reports (before/after) | PLANNED |

---

### TRACK 7: Test Coverage

**Goal**: Every source module has comprehensive tests. Sentrux coverage target: 80%+.

#### Current: 416 tests, 36 test files, 35 rules
#### Target: 80%+ coverage

| Module | Lines | Tests | Coverage Status |
|--------|-------|-------|-----------------|
| parse.py | 315 | test_parse.py (83 lines) | GOOD |
| facts.py | 179 | test_facts.py (333 lines) | GOOD |
| schema.py | 100 | test_schema.py (123 lines) | GOOD |
| rules.py | 76 | test_rules_catalog.py, test_rules_* | GOOD |
| rules_impl.py | 2050 | test_rules_new_controls*.py, test_rules_requested_*.py, test_rules_iface_no_vlan_security.py, test_rules_dhcp_snoop.py | GOOD |
| versioning.py | 42 | test_versioning.py (32 lines) | GOOD |
| cli.py | 347 | test_cli_scan.py (743 lines), test_cli_defaults.py | GOOD |
| report.py | 478 | test_report.py (171 lines) | PARTIAL |
| baseline.py | 125 | test_baseline.py (80 lines) | PARTIAL |
| authority.py | 217 | test_authority.py (69 lines) | PARTIAL |
| model.py | 31 | test_model.py (19 tests) | GOOD |
| util.py | 11 | test_util.py (10 tests) | GOOD |
| __init__.py | 1 | — | N/A |

#### Test Expansion Plan
| Task | Priority | Status |
|------|----------|--------|
| model.py unit tests | HIGH | DONE |
| util.py unit tests | LOW | DONE |
| report.py edge cases (empty, huge, unicode) | MEDIUM | PLANNED |
| authority.py edge cases (ambiguous, missing) | MEDIUM | PLANNED |
| baseline.py edge cases (merge, conflict) | MEDIUM | PLANNED |
| Integration tests (full scan pipeline) | HIGH | PLANNED |
| Fuzz tests for parser | MEDIUM | PLANNED |
| Property-based tests for schema normalization | LOW | PLANNED |
| Performance regression tests | MEDIUM | PLANNED |

---

### TRACK 8: Production Infrastructure

**Goal**: CI/CD, packaging, distribution, and operational readiness.

| Milestone | Status |
|-----------|--------|
| pyproject.toml packaging | DONE |
| pip install -e . editable install | DONE |
| CLI entry point (fgcheck command) | DONE |
| GitHub Actions CI | PLANNED |
| PyPI package publishing | PLANNED |
| Docker container image | PLANNED |
| Pre-commit hooks | PLANNED |
| Release versioning (semver) | PLANNED |
| Changelog generation | PLANNED |
| Code of Conduct / Contributing guide | PLANNED |
| API reference docs (sphinx/mkdocs) | PLANNED |
| Performance benchmarks (CI) | PLANNED |
| Supply chain security (sigstore, SBOM) | PLANNED |

---

### TRACK 9: Integration Ecosystem

**Goal**: fgcheck works with the tools teams already use.

| Integration | Description | Status |
|-------------|-------------|--------|
| GitHub code scanning | SARIF output for GitHub Security tab | PLANNED |
| GitLab SAST | SARIF/JUnit output for GitLab CI | PLANNED |
| Azure DevOps | SARIF extension for Azure Pipelines | PLANNED |
| Ansible lint | Custom Ansible rule for FortiGate configs | PLANNED |
| Terraform validate | Cross-reference with terraform plan output | PLANNED |
| FortiManager export | Parse configs exported from FortiManager | PLANNED |
| FortiCloud API | Pull configs via FortiCloud REST API | PLANNED |
| Slack/Teams notifications | Alert on critical findings | PLANNED |
| Jira integration | Auto-create issues for critical findings | PLANNED |
| SIEM ingestion | Output findings to SIEM (CEF/LEEF format) | PLANNED |
| MCP server | Expose fgcheck as an MCP tool for AI agents | PLANNED |
| Python library API | Import fgcheck as a library, not just CLI | PLANNED |

---

## Version Support Tiers

| Tier | Versions | Schema | Rules | Confidence |
|------|----------|--------|-------|------------|
| First-class | 7.4.x, 7.6.x, 8.0.x | Full field extraction | All waves | certain/likely |
| Second-class | 7.0.x, 7.2.x | Table-only | Wave 1-2 only | likely/heuristic |
| Future | 8.2.x+ | Add on release | All waves | certain/likely |

---

## Sentrux Quality Targets

| Metric | Current | Target |
|--------|---------|--------|
| Quality signal | 0.6411 | 0.80+ |
| Modularity | 0.3333 | 0.60+ |
| Test coverage | 20% | 80%+ |
| Acyclicity | 1.0 | 1.0 (maintain) |
| Redundancy | 0.8893 | 0.90+ (maintain) |
| Bus factor | 1.0 | 2.0+ |

---

## How This Roadmap Grows

1. **Every completed item moves the frontier forward.** When a wave is done, the next wave becomes the active target.
2. **New rules are added as schema coverage expands.** More fields = more things to check = more rules.
3. **New FortiOS versions trigger schema re-extraction.** Each new version adds tables, fields, and potential rule changes.
4. **Community and real-world feedback shapes priorities.** False positives from real configs refine rules. New config patterns expand the parser.
5. **Compliance frameworks are added on demand.** Each new framework (SOC2, ISO 27001, etc.) adds a wave of rules.
6. **Integration targets are added as ecosystem needs emerge.** If a team uses a new tool, fgcheck should work with it.

This roadmap is never complete. It is a living document that grows with the project.
