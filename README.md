# fgcheck — FortiGate Configuration Checker

[![Tests](https://img.shields.io/badge/tests-496%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-75-blue)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**Deterministic FortiGate configuration checker focused on security and posture findings.**

- 🔒 **No hallucination** — every finding has schema evidence
- 📋 **75 security rules** — covering admin access, VPN, firewall, IPS, wireless, SD-WAN, and more
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

## Built-in Rules (75)

### Critical
- FGT-ADMIN-EDGE-TELNET, FGT-ADMIN-EDGE-HTTP
- FGT-ADMIN-EDGE-ALLACCESS, FGT-LOCALIN-NO-PROTECTION

### High
- FGT-ADMIN-EDGE-SSH, FGT-ADMIN-EDGE-HTTPS
- FGT-ADMIN-NO-TRUSTED-HOSTS, FGT-ADMIN-SUPER-NO-2FA
- FGT-FIRMWARE-OUTDATED, FGT-SSH-WEAK-CIPHERS
- FGT-CERT-EXPIRING, FGT-SSLVPN-NO-MFA
- FGT-IPSEC-NO-PFS, FGT-SSLVPN-WEAK-CIPHER
- FGT-WIFI-WPA-TKIP, FGT-WIFI-NO-RADIUS
- FGT-LOG-REMOTE-UNENCRYPTED, FGT-ZTNA-NO-TRUST-CERT

### Medium
- FGT-POLICY-LOG-001, FGT-DHCP-SNOOP
- FGT-FGFM-DEFAULT-OVERRIDE, FGT-SNMP-NO-ACL
- FGT-IPS-DEFAULT-SIGNATURE, FGT-WEBFILTER-DEFAULT-OVERRIDE
- FGT-AV-NO-HEURISTIC, FGT-DLP-NO-SENSOR
- FGT-POLICY-NO-IPS, FGT-POLICY-NO-AV, FGT-POLICY-NO-WEBFILTER
- FGT-POLICY-NO-DLP, FGT-DNS-FILTER-NO-PROFILE, FGT-APP-CTRL-NO-POLICY
- FGT-SDWAN-NO-HEALTH-CHECK, FGT-SWITCH-NO-PORT-SECURITY
- FGT-IPSEC-SHORT-LIFETIME, FGT-SYSTEM-NO-MGMT-INTERFACE
- FGT-ROUTING-NO-FILTER, FGT-DHCP-NO-RANGE-LIMIT
- FGT-CAPTCHA-NO-ENABLE, FGT-USER-NO-EXPIRY
- FGT-AUTOMATION-STITCH-NO-RESTRICT, FGT-API-TOKEN-NO-EXPIRY
- FGT-ICAP-NO-PROFILE, FGT-NAC-NO-POLICY
- FGT-FW-MULTICAST-NO-SECURE, and more

### Low
- FGT-POLICY-NO-LOG, FGT-SSLVPN-PORT
- FGT-REPORT-NO-SCHEDULE

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
- `FGT-ADMIN-LOCKOUT-NO-TRIES`
- `FGT-ADMIN-NO-2FA`
- `FGT-ADMIN-NO-IDLE-TIMEOUT`
- `FGT-ADMIN-NO-RESTRICT-VDOM`
- `FGT-ADMIN-NO-TRUSTED-HOSTS`
- `FGT-ADMIN-SUPER-NO-2FA`
- `FGT-ADMIN-TRUSTHOST-UNRESTRICTED`
- `FGT-ADMIN-WEAK-PASSWORD-POLICY`
- `FGT-API-TOKEN-NO-EXPIRY`
- `FGT-APP-CTRL-NO-POLICY`
- `FGT-AUTOMATION-STITCH-NO-RESTRICT`
- `FGT-AV-NO-HEURISTIC`
- `FGT-CAPTCHA-NO-ENABLE`
- `FGT-CERT-EXPIRING`
- `FGT-DHCP-NO-RANGE-LIMIT`
- `FGT-DHCP-SNOOP`
- `FGT-DLP-NO-SENSOR`
- `FGT-DNS-DEFAULT-ONLY`
- `FGT-DNS-FILTER-NO-PROFILE`
- `FGT-DNS-NO-ZT`
- `FGT-DNS-SERVER-ALLOW-TCP`
- `FGT-FGFM-DEFAULT-OVERRIDE`
- `FGT-FIRMWARE-OUTDATED`
- `FGT-FW-MULTICAST-NO-SECURE`
- `FGT-ICAP-NO-PROFILE`
- `FGT-IFACE-NO-VLAN-SECURITY`
- `FGT-INTERFACE-OPEN-PORT`
- `FGT-IPS-DEFAULT-SIGNATURE`
- `FGT-IPSEC-NO-PFS`
- `FGT-IPSEC-SHORT-LIFETIME`
- `FGT-IPSEC-WEAK-DH`
- `FGT-LOCAL-IN-PERMISSIVE`
- `FGT-LOCALIN-NO-LOG`
- `FGT-LOCALIN-NO-PROTECTION`
- `FGT-LOG-REMOTE-UNENCRYPTED`
- `FGT-NAC-NO-POLICY`
- `FGT-NO-REMOTE-LOGGING`
- `FGT-NTP-NO-NTPS`
- `FGT-POLICY-ANY-ANY-ALL`
- `FGT-POLICY-LOG-001`
- `FGT-POLICY-NO-AV`
- `FGT-POLICY-NO-DLP`
- `FGT-POLICY-NO-IPS`
- `FGT-POLICY-NO-LOG`
- `FGT-POLICY-NO-WEBFILTER`
- `FGT-REPORT-NO-SCHEDULE`
- `FGT-ROUTE-DEFAULT-INSECURE`
- `FGT-ROUTING-NO-FILTER`
- `FGT-SDWAN-NO-HEALTH-CHECK`
- `FGT-SNMP-NO-ACL`
- `FGT-SNMP-WEAK-COMMUNITY`
- `FGT-SSH-WEAK-CIPHERS`
- `FGT-SSL-INSPECTION-DISABLED`
- `FGT-SSLVPN-MIN-TLS`
- `FGT-SSLVPN-NO-MFA`
- `FGT-SSLVPN-PORT`
- `FGT-SSLVPN-SRCADDR-ALL`
- `FGT-SSLVPN-SRCINTF-ANY`
- `FGT-SSLVPN-WEAK-CIPHER`
- `FGT-SWITCH-NO-PORT-SECURITY`
- `FGT-SWITCH-NO-ROOT-GUARD`
- `FGT-SYNTAX-DEPRECATED`
- `FGT-SYSTEM-NO-MGMT-INTERFACE`
- `FGT-USER-NO-EXPIRY`
- `FGT-VPN-WEAK-ENCRYPTION`
- `FGT-WEBFILTER-DEFAULT-OVERRIDE`
- `FGT-WIFI-NO-RADIUS`
- `FGT-WIFI-WPA-TKIP`
- `FGT-WIRELESS-OPEN-SSID`
- `FGT-ZTNA-NO-TRUST-CERT`
