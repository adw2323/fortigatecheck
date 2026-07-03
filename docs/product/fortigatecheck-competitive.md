# fortigatecheck Competitive Analysis

**Tags:** #fortigatecheck #competitive #market

---

## FortiGate Config Analysis Tools

### fortigatecheck (This Tool)
- **Type:** Python CLI library
- **Focus:** Security + syntax validation
- **Strengths:** Deterministic, evidence-first, schema-backed, open source
- **Weaknesses:** Limited schema coverage (table_only), no API, no GUI

### Fortinet FortiConverter
- **Type:** Vendor tool
- **Focus:** Migration between firewall vendors
- **Strengths:** Official vendor support
- **Weaknesses:** Not a security checker, limited config analysis

### FortiManager
- **Type:** Vendor management platform
- **Focus:** Centralized management, not security analysis
- **Strengths:** Deep FortiOS integration
- **Weaknesses:** Not a standalone security tool, expensive

### Ansible FortiOS Modules
- **Type:** Automation framework
- **Focus:** Config management, not security checking
- **Strengths:** Automation, idempotency
- **Weaknesses:** No security analysis built in

### Custom Scripts
- **Type:** Ad-hoc
- **Focus:** Specific checks
- **Strengths:** Tailored to needs
- **Weaknesses:** No maintenance, no documentation, no reuse

---

## Competitive Advantages of fortigatecheck

1. **No hallucination** — deterministic, evidence-backed
2. **Schema-aware** — knows what FortiOS supports
3. **Open source** — community can contribute rules
4. **Multiple outputs** — human, JSON, HTML, PDF
5. **Offline** — no cloud dependency
6. **Fast** — Python, no external services
7. **Extensible** — YAML rules, custom authoring

## What Would Make It Best-in-Class

1. Complete FortiOS schema (field-level)
2. 100+ security rules
3. Compliance mapping (NIST/CIS)
4. REST API for automation
5. CI/CD integration
6. FortiManager support
7. Config diff
8. Baseline templates
9. Web dashboard
10. Commercial support option
