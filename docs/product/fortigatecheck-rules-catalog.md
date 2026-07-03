# fortigatecheck Rules Catalog

**Tags:** #fortigatecheck #rules #security

---

## Rule Categories

### Admin Access (10 rules)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-ADMIN-EDGE-TELNET | critical | Edge interface allows Telnet management |
| FGT-ADMIN-EDGE-HTTP | critical | Edge interface allows HTTP management |
| FGT-ADMIN-EDGE-ALLACCESS | critical | Edge interface allows all protocols |
| FGT-ADMIN-EDGE-SSH | high | Edge interface allows SSH management |
| FGT-ADMIN-EDGE-HTTPS | high | Edge interface allows HTTPS management |
| FGT-ADMIN-NO-TRUSTED-HOSTS | high | Admin accounts without trusted hosts |
| FGT-ADMIN-SUPER-NO-2FA | high | Super admin without 2FA |
| FGT-ADMIN-TRUSTHOST-UNRESTRICTED | high | Trusted hosts set to 0.0.0.0 |
| FGT-ADMIN-NO-IDLE-TIMEOUT | medium | Admin idle timeout not configured |
| FGT-ADMIN-WEAK-PASSWORD-POLICY | high | Weak password policy |

### Firewall (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-POLICY-LOG-001 | medium | Policies without logging |

### Local-In (2 rules)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-LOCALIN-NO-PROTECTION | critical | No local-in policy |
| FGT-LOCAL-IN-PERMISSIVE | high | Permissive local-in policy |

### SSL VPN (2 rules)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-SSLVPN-MIN-TLS | high | SSL VPN TLS version too low |
| FGT-SSH-WEAK-CIPHERS | high | SSH weak ciphers enabled |

### VPN (2 rules)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-IPSEC-WEAK-DH | high | IPsec weak DH groups |
| FGT-FGFM-DEFAULT-OVERRIDE | medium | FGFM default override |

### Network (3 rules)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-DHCP-SNOOP | medium | DHCP snooping |
| FGT-DNS-DEFAULT-ONLY | medium | DNS default only |
| FGT-IFACE-NO-VLAN-SECURITY | medium | Interface VLAN security |

### Firmware (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-FIRMWARE-OUTDATED | high | Firmware outdated |

### Certificate (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-CERT-EXPIRING | high | Certificates expiring soon |

### IPS (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-IPS-DEFAULT-SIGNATURE | medium | IPS without custom signatures |

### SNMP (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-SNMP-NO-ACL | medium | SNMP without ACL |

### Web Filter (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-WEBFILTER-DEFAULT-OVERRIDE | medium | Web filter default override |

### Antivirus (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-AV-NO-HEURISTIC | medium | AV without heuristic scanning |

### DLP (1 rule)
| Rule | Severity | What It Checks |
|------|----------|----------------|
| FGT-DLP-NO-SENSOR | low | DLP without sensor |

---

## Adding a New Rule

### 1. Create YAML definition

```yaml
id: FGT-XXX
title: Description of what this checks
severity: medium|high|critical|low
confidence: certain|heuristic
entrypoint: fgcheck.rules_impl:rule_xxx
```

### 2. Implement the rule

```python
def rule_xxx(*, model, facts, vdom, rule, schema=None):
    """Check for specific condition."""
    tables = model.vdoms.get(vdom, {})
    out = []
    # Implementation
    return out
```

### 3. Add tests

```python
def test_rule_xxx():
    config = "..."""
    findings = scan_config(config)
    assert any(f.rule_id == "FGT-XXX" for f in findings)
```

### 4. Update roadmap

Mark the rule as DONE in docs/ROADMAP.md.
