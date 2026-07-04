# fortigatecheck Product Roadmap v2.0

**Date:** 2026-07-03
**Status:** Active Development
**Vision:** World-class FortiGate syntax and security checker — no hallucination, pure validation.

---

## Current State (v0.1.0)

- 75 security rules, 506 tests
- REST API, Web UI, Fleet Dashboard
- SARIF output, Compliance mapping (NIST/CIS/Fortinet)
- Config diff, FortiManager detection
- Docker, CI/CD, pre-commit hooks

---

## Phase 1: Rule Expansion (Target: 120+ rules)

### ZTNA Rules (10 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-ZTNA-SERVER-NO-CERT | ZTNA server without certificate | critical |
| FGT-ZTNA-RULE-NO-USERS | ZTNA rule without user/group | high |
| FGT-ZTNA-NO-POSTURE | ZTNA without device posture check | high |
| FGT-ZTNA-DEFAULT-ACTION | ZTNA default action allow | high |
| FGT-ZTNA-NO-FORTICLIENT | ZTNA without FortiClient requirement | medium |
| FGT-ZTNA-PORT-STANDARD | ZTNA on non-standard port | medium |
| FGT-ZTNA-NO-REAUTH | ZTNA without re-authentication | medium |
| FGT-ZTNA-MULTI-VDOM | ZTNA across VDOMs | medium |
| FGT-ZTNA-NO-LOGGING | ZTNA without logging | medium |
| FGT-ZTNA-EXPOSED-APPS | ZTNA apps without access restrictions | high |

### SIA Rules (8 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-SIA-NO-DNS-FILTER | SIA without DNS filtering | high |
| FGT-SIA-NO-WEB-FILTER | SIA without web filtering | high |
| FGT-SIA-NO-SSL-INSPECT | SIA without SSL inspection | critical |
| FGT-SIA-NO-APP-CONTROL | SIA without application control | high |
| FGT-SIA-NO-IPS | SIA without IPS | high |
| FGT-SIA-NO-CAPTIVE-PORTAL | SIA without captive portal | medium |
| FGT-SIA-NO-LOG | SIA without logging | medium |
| FGT-SIA-NO-GEO-IP | SIA without geo-IP filtering | medium |

### VPN Hardening Rules (12 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-VPN-NO-DPD | VPN without dead peer detection | medium |
| FGT-VPN-NO-NAT-T | VPN without NAT traversal | low |
| FGT-VPN-SHORT-IKE | IKE SA lifetime too short | medium |
| FGT-VPN-NO-DH-GROUP14 | VPN using DH group 1-2 | high |
| FGT-VPN-NO-AUTH-LOCALID | VPN without local ID | medium |
| FGT-VPN-NO-REKEY | VPN without rekey | low |
| FGT-VPN-SSL-NO-MFA | SSL VPN without MFA | high |
| FGT-VPN-SSL-NO-CLIENT-CERT | SSL VPN without client cert | medium |
| FGT-VPN-SSL-DNS-SPLIT | SSL VPN DNS split tunnel | medium |
| FGT-VPN-IPSEC-NO-AUTOPICK | IPsec without auto-negotiate | low |
| FGT-VPN-IPSEC-NO-REPLAY | IPsec without anti-replay | medium |
| FGT-VPN-IPSEC-COMPRESSION | IPsec with compression | low |

### Routing Security Rules (15 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-ROUTING-BGP-NO-PASSWORD | BGP without authentication | high |
| FGT-ROUTING-BGP-NO-PREFIX-FILTER | BGP without prefix filter | high |
| FGT-ROUTING-BGP-NO-MAX-PREFIX | BGP without max prefix | medium |
| FGT-ROUTING-BGP-NO-SOFT-RECONFIG | BGP without soft reconfig | low |
| FGT-ROUTING-OSPF-NO-AUTH | OSPF without authentication | high |
| FGT-ROUTING-OSPF-NO-PASSIVE | OSPF without passive interfaces | medium |
| FGT-ROUTING-OSPF-NO-AREA-FILTER | OSPF without area filter | medium |
| FGT-ROUTING-STATIC-NO-GW-CHECK | Static route without gateway check | medium |
| FGT-ROUTING-STATIC-ONLINK | Static route with onlink | low |
| FGT-ROUTING-STATIC-DEFAULT-ONLY | Only default route | low |
| FGT-ROUTING-MULTI-PATH-NO-ECMP | Multi-path without ECMP | low |
| FGT-ROUTING-NO-ROUTE-MAP | No route maps configured | medium |
| FGT-ROUTING-NO-PREFIX-LIST | No prefix lists configured | medium |
| FGT-ROUTING-RIP-NO-AUTH | RIP without authentication | high |
| FGT-ROUTING-NO-REDISTRIBUTE | No route redistribution filtering | medium |

### FortiSwitch Rules (12 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-SWITCH-NO-8021X | Switch without 802.1X | high |
| FGT-SWITCH-NO-VLAN-SEG | No VLAN segmentation | high |
| FGT-SWITCH-NO-STORM-CONTROL | No storm control | medium |
| FGT-SWITCH-NO-MAC-LIMIT | No MAC address limit | medium |
| FGT-SWITCH-NO-LOOP-GUARD | No loop guard | medium |
| FGT-SWITCH-NO-BPDU-GUARD | No BPDU guard | medium |
| FGT-SWITCH-NO-ROOT-GUARD | No root guard | medium |
| FGT-SWITCH-NO-DHCP-SNOOP | No DHCP snooping | medium |
| FGT-SWITCH-NO-DYNAMIC-ARP | No dynamic ARP inspection | medium |
| FGT-SWITCH-NO-IP-SOURCE-GUARD | No IP source guard | medium |
| FGT-SWITCH-PORT-SEC-NO-MAC | Port security without MAC limit | medium |
| FGT-SWITCH-NO-LINK-AGG | No link aggregation | low |

### FortiAP Rules (10 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-AP-NO-WPA3 | AP without WPA3 | high |
| FGT-AP-OPEN-NETWORK | AP with open network | critical |
| FGT-AP-NO-CLIENT-ISOLATION | AP without client isolation | medium |
| FGT-AP-NO-MAX-CLIENTS | AP without client limit | medium |
| FGT-AP-NO-BAND-STEERING | AP without band steering | low |
| FGT-AP-NO-ROAMING | AP without fast roaming | low |
| FGT-AP-NO-RADIUS | Enterprise AP without RADIUS | high |
| FGT-AP-NO-LOGGING | AP without logging | medium |
| FGT-AP-NO-HIDDEN-SSID | AP broadcasting SSID | low |
| FGT-AP-NO-QOS | AP without QoS | low |

### Additional Security Rules (18 new)
| Rule ID | Title | Severity |
|---------|-------|----------|
| FGT-SECURITY-FABRIC-NO-FILTER | Security Fabric without filter | high |
| FGT-SECURITY-FABRIC-NO-SYNC | Security Fabric without sync | medium |
| FGT-FIREWALL-NO-DOSE | No DoS protection | high |
| FGT-FIREWALL-NO-ANTISPOOF | No anti-spoofing | high |
| FGT-FIREWALL-NO-UNICAST-ROUTE | No unicast reverse path | medium |
| FGT-LOG-NO-FORTIANALYZER | No FortiAnalyzer logging | medium |
| FGT-LOG-NO-FORTIGUARD | No FortiGuard logging | medium |
| FGT-AUTH-NO-RADIUS-SERVER | No RADIUS server | high |
| FGT-AUTH-NO-LDAP-SERVER | No LDAP server | medium |
| FGT-AUTH-NO-TACACS | No TACACS+ | medium |
| FGT-SYSTEM-NO-NTPS | System without NTPS | medium |
| FGT-SYSTEM-NO-SNMPv3 | System using SNMPv1/v2c | high |
| FGT-SYSTEM-NO-FIPS | System not in FIPS mode | low |
| FGT-SYSTEM-NO-FORTIGUARD | No FortiGuard updates | high |
| FGT-SYSTEM-NO-AUTOMATION | No automation stitches | low |
| FGT-SYSTEM-NO-REPORT | No reporting configured | low |
| FGT-SYSTEM-NO-DHCP-GUARD | No DHCP guard | medium |
| FGT-SYSTEM-NO-IP-VERIFY | No IP verify | medium |

---

## Phase 2: Advanced Features

### 1. Real Config Testing
- Download 20+ real FortiGate configs from public sources
- Test against all rules
- Fix parser edge cases found
- Improve rule accuracy

### 2. Fleet Management v2
- Device grouping and tags
- Compliance trend tracking
- Automated scanning via API
- Email/webhook notifications
- Export to CSV/PDF

### 3. Config Comparison
- Side-by-side diff view
- Change tracking over time
- Rollback support

### 4. Rule Customization
- Rule severity override
- Rule enable/disable
- Custom evidence formatting
- Rule packs (CIS, NIST, custom)

---

## Phase 3: Enterprise Features

### 1. Multi-tenant Support
- Tenant isolation
- Role-based access
- Audit logging

### 2. API Enhancements
- Batch scanning
- Async operations
- Webhook callbacks
- Rate limiting

### 3. Compliance Frameworks
- NIST 800-53 Rev 5
- CIS FortiGate Benchmark
- PCI-DSS
- HIPAA
- SOC 2

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Security rules | 120+ | 75 |
| Test coverage | 90%+ | 85% |
| Real configs tested | 20+ | 0 |
| Compliance frameworks | 5+ | 3 |
| API endpoints | 15+ | 12 |
| Documentation pages | 20+ | 16 |
