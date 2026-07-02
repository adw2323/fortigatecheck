# Session Handoff

Last updated: 2026-07-01

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
- **8.0**: Not yet generated (CLI reference URL added to sources.yaml, awaiting build_corpus run)

### Test Coverage
- 152 tests passing
- 20 test files covering: parser, facts, schema, rules (catalog, set, matrix, schema_gate, multivdom, ordering, new_controls), versioning, authority, baseline, CLI, report, build_corpus

### Builtin Rules (17 total)
- Admin access: FGT-ADMIN-EDGE-SSH, FGT-ADMIN-EDGE-HTTPS, FGT-ADMIN-EDGE-TELNET, FGT-ADMIN-EDGE-HTTP, FGT-ADMIN-EDGE-ALLACCESS, FGT-ADMIN-NO-TRUSTED-HOSTS, FGT-ADMIN-TRUSTHOST-UNRESTRICTED, FGT-ADMIN-SUPER-NO-2FA
- Firewall: FGT-POLICY-ANY-ANY-ALL, FGT-POLICY-LOG-001
- Local-in: FGT-LOCAL-IN-PERMISSIVE, FGT-LOCALIN-NO-PROTECTION
- SSL VPN: FGT-SSLVPN-MIN-TLS, FGT-SSLVPN-SRCINTF-ANY, FGT-SSLVPN-SRCADDR-ALL
- IPSec: FGT-IPSEC-WEAK-DH
- Logging: FGT-NO-REMOTE-LOGGING

## Version Policy Update
- First-class: 7.4.x (latest 7.4.12), 7.6.x (latest 7.6.7), 8.0.x (8.0.0 just released)
- sources.yaml updated with 8.0 CLI reference URL
- build_corpus.py needs 8.0 support added

## Known Gaps / Open Work
1. Schema corpus is table_only for ~600 tables; field extraction needed for security-critical tables beyond the 17 priority ones
2. Rule set is minimal (17 rules); should be expanded to 30+ covering DNS, NTP, SNMP, password policy, firmware currency, idle timeout
3. FortiOS 8.0 schema not yet generated; build_corpus.py and versioning.py need 8.0 support
4. Facts engine needs deeper interface hierarchy: software switch member ports, nested parent/child interface ancestry
5. No CI pipeline yet (GitHub Actions)
6. No real-config regression suite with sanitized fixtures

## Active Priorities (Ordered)
1. Add new rules (DNS, NTP, SNMP, password policy, firmware, idle timeout) — target 30+ rules
2. Generate FortiOS 8.0 schema and add full version support
3. Expand schema field extraction for security-critical tables beyond priority 17
4. Add CI pipeline (GitHub Actions with pytest + schema validation)
5. Deepen facts engine for interface hierarchy and HA topology

## Do-Next Checklist
1. Add FGT-DNS-NO-ZT, FGT-DNS-DEFAULT-ONLY rules with tests
2. Add FGT-NTP-NO-NTPS rule with tests
3. Add FGT-SNMP-WEAK-COMMUNITY rule with tests
4. Add FGT-ADMIN-WEAK-PASSWORD-POLICY rule with tests
5. Add FGT-ADMIN-NO-IDLE-TIMEOUT rule with tests
6. Add FGT-FIRMWARE-OUTDATED rule with tests
7. Update build_corpus.py to support 8.0 version
8. Update versioning.py to recognize 8.0 family
9. Run build_corpus.py to generate 8.0 schema.json
10. Add schema tests for 8.0 fallback behavior

## Known Pitfalls / Guardrails
- Do not present guessed FortiOS knobs as facts
- Do not mark findings `certain` when schema coverage is missing
- Do not generate executable remediation CLI commands
- Keep `tests/real` local-only (gitignored) and avoid coupling CI to local data
- Windows environment: use git-bash POSIX syntax in terminal, not PowerShell
- Package must be pip-installed (`pip install -e .`) for tests to resolve imports
