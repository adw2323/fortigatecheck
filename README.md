# fgcheck — FortiGate Configuration Checker

[![Tests](https://img.shields.io/badge/tests-416%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-35-blue)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**Deterministic FortiGate configuration checker focused on security and posture findings.**

- 🔒 **No hallucination** — every finding has schema evidence
- 📋 **35 security rules** — covering admin access, VPN, firewall, IPS, and more
- 📊 **Multiple outputs** — human, JSON, HTML, PDF, Markdown
- 🎯 **Schema-aware** — validates against FortiOS schema
- 🔍 **Authority lookup** — validates commands, tables, and fields
- 📁 **Multi-VDOM** — checks each VDOM independently

## Quick Start

```bash
# Install
pip install -e .

# Scan a config
fgcheck config.conf

# JSON output
fgcheck config.conf --format json

# HTML report
fgcheck configs/ --format html --output report.html

# Scan and fail on critical findings
fgcheck configs/ --fail-on critical
```

## Documentation

- [Getting Started](docs/product/fortigatecheck-getting-started.md)
- [User Guide](docs/product/fortigatecheck-user-guide.md)
- [Developer Guide](docs/product/fortigatecheck-developer-guide.md)
- [Rules Catalog](docs/product/fortigatecheck-rules-catalog.md)
- [Contributing](docs/product/fortigatecheck-contributing.md)
- [Architecture](docs/product/fortigatecheck-architecture.md)
- [Product Vision](docs/product/PRODUCT-VISION.md)
- [Roadmap](docs/product/ROADMAP.md)
- [Changelog](CHANGELOG.md)

## Core Principles

- **Detector-only** — no automatic fix execution
- **Schema-gated** — don't claim unsupported syntax
- **Evidence-first** — include exact config line evidence
- **Deterministic** — same input → same output

## Built-in Rules (35)

### Critical
- FGT-ADMIN-EDGE-TELNET, FGT-ADMIN-EDGE-HTTP
- FGT-ADMIN-EDGE-ALLACCESS, FGT-LOCALIN-NO-PROTECTION

### High
- FGT-ADMIN-EDGE-SSH, FGT-ADMIN-EDGE-HTTPS
- FGT-ADMIN-NO-TRUSTED-HOSTS, FGT-ADMIN-SUPER-NO-2FA
- FGT-FIRMWARE-OUTDATED, FGT-SSH-WEAK-CIPHERS
- FGT-CERT-EXPIRING, FGT-SSLVPN-NO-MFA

### Medium
- FGT-POLICY-LOG-001, FGT-DHCP-SNOOP
- FGT-FGFM-DEFAULT-OVERRIDE, FGT-SNMP-NO-ACL
- FGT-IPS-DEFAULT-SIGNATURE, FGT-WEBFILTER-DEFAULT-OVERRIDE
- FGT-AV-NO-HEURISTIC, and more

## Authority Lookup

Validate FortiOS commands, tables, and fields:

```bash
fgcheck authority "system interface"
fgcheck schema "firewall policy" --fortios 7.6 --strict
fgcheck docs "vpn ipsec phase1-interface"
```

## Tests

```bash
python -m pytest tests/ -q
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

See [Contributing Guide](docs/product/fortigatecheck-contributing.md).

We especially need rules for:
- Wireless security
- DNS filter profiles
- Application control
- HA configuration
- SD-WAN health checks

## All Built-in Rules

- `FGT-ADMIN-EDGE-ALLACCESS`
- `FGT-ADMIN-EDGE-HTTP`
- `FGT-ADMIN-EDGE-HTTPS`
- `FGT-ADMIN-EDGE-SSH`
- `FGT-ADMIN-EDGE-TELNET`
- `FGT-ADMIN-NO-IDLE-TIMEOUT`
- `FGT-ADMIN-NO-TRUSTED-HOSTS`
- `FGT-ADMIN-SUPER-NO-2FA`
- `FGT-ADMIN-TRUSTHOST-UNRESTRICTED`
- `FGT-ADMIN-WEAK-PASSWORD-POLICY`
- `FGT-AV-NO-HEURISTIC`
- `FGT-CERT-EXPIRING`
- `FGT-DHCP-SNOOP`
- `FGT-DLP-NO-SENSOR`
- `FGT-DNS-DEFAULT-ONLY`
- `FGT-DNS-NO-ZT`
- `FGT-FGFM-DEFAULT-OVERRIDE`
- `FGT-FIRMWARE-OUTDATED`
- `FGT-IFACE-NO-VLAN-SECURITY`
- `FGT-IPS-DEFAULT-SIGNATURE`
- `FGT-IPSEC-WEAK-DH`
- `FGT-LOCAL-IN-PERMISSIVE`
- `FGT-LOCALIN-NO-PROTECTION`
- `FGT-NO-REMOTE-LOGGING`
- `FGT-NTP-NO-NTPS`
- `FGT-POLICY-ANY-ANY-ALL`
- `FGT-POLICY-LOG-001`
- `FGT-SNMP-NO-ACL`
- `FGT-SNMP-WEAK-COMMUNITY`
- `FGT-SSH-WEAK-CIPHERS`
- `FGT-SSLVPN-MIN-TLS`
- `FGT-SSLVPN-NO-MFA`
- `FGT-SSLVPN-SRCADDR-ALL`
- `FGT-SSLVPN-SRCINTF-ANY`
- `FGT-WEBFILTER-DEFAULT-OVERRIDE`
- `FGT-SYNTAX-DEPRECATED`
- `FGT-SYNTAX-UNKNOWN-FIELD`
- `FGT-SYNTAX-UNKNOWN-TABLE`
- `FGT-ADMIN-LOCKOUT-NO-TRIES`
- `FGT-HA-NO-HEARTBEAT`
