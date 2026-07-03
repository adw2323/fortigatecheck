# Session Handoff

Last updated: 2026-07-03
## Current Status Snapshot
### Completed Foundations
- **Parser**: Multiline quoted `set` blob handling, VDOM scope switching/restore, nested `config...end` table path restoration
- **Facts engine**: Default-route edge detection, SD-WAN logical device resolution, policy-route output-device edge projection, zone-to-interface projection, software switch member resolution, VLAN ancestry hierarchy
- **Schema system**: `src/fgcheck/schema.py` (load_schema, has_table, has_field, allowed_values), version family fallback, schema unknown behavior
- **Authority**: `src/fgcheck/authority.py` — lookup_authority for schema validation queries with VALIDATED/PARTIALLY_VALIDATED/UNKNOWN classification
- **Versioning**: `src/fgcheck/versioning.py` — header > flag > default (7.4) policy, CLI --fortios support
- **CLI**: Single-file and folder scan, json/md/human/html output, PDF export, baseline suppression, severity gating, VDOM filtering, summary JSON, CSV output, authority subcommands (lookup/schema/docs)
- **Report**: Rich HTML with embedded documents, human-readable summaries, markdown tables
- **Corpus pipeline**: `scripts/build_corpus.py` — HTML schema extraction, priority table field extraction, KEV normalization, PSIRT RSS/JSON parsing

### Schema State
- **7.4**: 597 tables, 17 with field details (priority tables: system interface 374 fields, firewall policy 176 fields, system admin 50 fields, vpn ssl settings 77 fields, etc.)
- **7.6**: 625 tables, 17 with field details (system interface 389 fields, firewall policy 185 fields, system admin 50 fields, vpn ssl settings 60 fields, etc.)
- **8.0**: 646 tables, 17 with field details

### Test Coverage
- 365 tests passing
- 33 test files covering: parser, facts, schema, rules (catalog, set, matrix, schema_gate, multivdom, ordering, new_controls, password_policy, idle_timeout, dns_default_only, firmware_outdated, ssh_weak_ciphers, snmp_no_acl, cert_expiring, fgfm_default_override, iface_no_vlan_security, dhcp_snoop, sslvpn_no_mfa, ips_default_signature), versioning, authority, baseline, CLI, report, build_corpus, readme, model, util

### Builtin Rules (32 total)
- Admin access: FGT-ADMIN-EDGE-SSH, FGT-ADMIN-EDGE-HTTPS, FGT-ADMIN-EDGE-TELNET, FGT-ADMIN-EDGE-HTTP, FGT-ADMIN-EDGE-ALLACCESS, FGT-ADMIN-NO-TRUSTED-HOSTS, FGT-ADMIN-TRUSTHOST-UNRESTRICTED, FGT-ADMIN-SUPER-NO-2FA
- Firewall: FGT-POLICY-ANY-ANY-ALL, FGT-POLICY-LOG-001
- Local-in: FGT-LOCAL-IN-PERMISSIVE, FGT-LOCALIN-NO-PROTECTION
- SSL VPN: FGT-SSLVPN-MIN-TLS, FGT-SSLVPN-SRCINTF-ANY, FGT-SSLVPN-SRCADDR-ALL
- IPSec: FGT-IPSEC-WEAK-DH
- Logging: FGT-NO-REMOTE-LOGGING
- Password: FGT-ADMIN-WEAK-PASSWORD-POLICY
- Admin idle: FGT-ADMIN-NO-IDLE-TIMEOUT
- DNS: FGT-DNS-NO-ZT, FGT-DNS-DEFAULT-ONLY
- Firmware: FGT-FIRMWARE-OUTDATED
- SSH: FGT-SSH-WEAK-CIPHERS
- NTP: FGT-NTP-NO-NTPS
- SNMP: FGT-SNMP-WEAK-COMMUNITY, FGT-SNMP-NO-ACL
- Certificate: FGT-CERT-EXPIRING
- FortiManager: FGT-FGFM-DEFAULT-OVERRIDE
- Switch controller: FGT-IFACE-NO-VLAN-SECURITY, FGT-DHCP-SNOOP
- SSL VPN MFA: FGT-SSLVPN-NO-MFA
- IPS: FGT-IPS-DEFAULT-SIGNATURE

## Version Policy Update
- First-class: 7.4.x (latest 7.4.12), 7.6.x (latest 7.6.7), 8.0.x (8.0.0 just released)
- sources.yaml updated with 8.0 CLI reference URL
- build_corpus.py needs 8.0 support added

## Known Gaps / Open Work
1. Schema corpus is table_only for ~600 tables; field extraction needed for security-critical tables beyond the 17 priority ones
2. Rule set is growing (32 rules); Wave 3 has 13 more PLANNED rules
3. Facts engine needs deeper interface hierarchy: HA cluster topology, virtual-wire pair detection
4. No CI pipeline yet (GitHub Actions)
5. No real-config regression suite with sanitized fixtures

## Active Priorities (Ordered)
1. Expand schema field extraction for security-critical tables beyond priority 17
2. Add CI pipeline (GitHub Actions with pytest + schema validation)
3. Deepen facts engine for HA topology and virtual-wire pair detection

## Do-Next Checklist
1. ~~Add FGT-IPS-DEFAULT-SIGNATURE rule with tests~~ DONE
2. Add FGT-WEBFILTER-DEFAULT-OVERRIDE rule with tests (next PLANNED in Wave 3)
3. Expand schema field extraction for security-critical tables beyond priority 17
4. Add CI pipeline (GitHub Actions with pytest + schema validation)
5. Deepen facts engine for HA topology and virtual-wire pair detection

## Known Pitfalls / Guardrails
- Do not present guessed FortiOS knobs as facts
- Do not mark findings `certain` when schema coverage is missing
- Do not generate executable remediation CLI commands
- Keep `tests/real` local-only (gitignored) and avoid coupling CI to local data
- Windows environment: use git-bash POSIX syntax in terminal, not PowerShell
- Package must be pip-installed (`pip install -e .`) for tests to resolve imports
- Parser flattens nested `config` blocks inside `edit` blocks: the entries for `config ips sensor` > `edit "name"` > `config entries` become a separate top-level `entries` table, not nested under `ips sensor`
- Schema table names are compound strings (e.g. `"ips sensor"`) not path tuples — use `has_table(("ips", "sensor"))` to check existence
