# fortigatecheck — Product Overview

**Tags:** #fortigate #security #config-checker #python
**Status:** Active Development
**Repository:** github.com/adw2323/fortigatecheck

---

## What Is It

A deterministic FortiGate configuration checker that:

1. **Parses** FortiOS text configs (show config full)
2. **Validates** against FortiOS schema
3. **Checks** security posture via built-in rules
4. **Reports** in multiple formats (human/JSON/HTML/PDF)
5. **Never hallucinates** — every finding has schema evidence

## Architecture

```python
# Core flow
ConfigModel ← parse_fortios_text(config_text)
    ↓
Facts ← build_facts(model)
    ↓
Rules ← run(model, facts, rules)
    ↓
Findings → Report (human/json/html/pdf)
```

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| CLI | cli.py | Command-line interface |
| Parser | parse.py | FortiOS config parsing |
| Rules | rules_impl.py | 35 security rule implementations |
| Schema | schema.py | FortiOS schema validation |
| Authority | authority.py | Command/field lookup |
| Facts | facts.py | Derived configuration facts |
| Report | report.py | Multi-format output |

## Rules (35 total)

### Critical
- FGT-ADMIN-EDGE-TELNET
- FGT-ADMIN-EDGE-HTTP
- FGT-ADMIN-EDGE-ALLACCESS
- FGT-LOCALIN-NO-PROTECTION

### High
- FGT-ADMIN-EDGE-SSH
- FGT-ADMIN-EDGE-HTTPS
- FGT-ADMIN-NO-TRUSTED-HOSTS
- FGT-ADMIN-SUPER-NO-2FA
- FGT-FIRMWARE-OUTDATED
- FGT-SSH-WEAK-CIPHERS
- FGT-CERT-EXPIRING
- FGT-SSLVPN-NO-MFA

### Medium
- FGT-POLICY-LOG-001
- FGT-DHCP-SNOOP
- FGT-FGFM-DEFAULT-OVERRIDE
- FGT-SNMP-NO-ACL
- FGT-IPS-DEFAULT-SIGNATURE
- FGT-DLP-NO-SENSOR
- And more...

## CLI Usage

```bash
# Single file scan
fgcheck config.conf

# Folder scan
fgcheck configs/

# JSON output
fgcheck config.conf --format json

# HTML report
fgcheck configs/ --format html --output report.html

# Authority lookup
fgcheck authority "system interface"

# Schema query
fgcheck schema "firewall policy"
```

## Development

```bash
# Install in dev mode
pip install -e .

# Run tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_rules_ssh_weak_ciphers.py -v
```

---

## Related Notes

- [[fortigatecheck-roadmap]]
- [[fortigatecheck-rules]]
- [[fortigatecheck-architecture]]
