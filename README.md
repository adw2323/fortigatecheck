# fgcheck

Deterministic FortiGate configuration checker focused on security and posture findings.

## Core Principles
- Detector-only: no automatic fix execution.
- Schema-gated correctness: do not claim unsupported syntax/knobs.
- Evidence-first findings: include exact config line evidence.

## Quick Start

### Single file scan
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\path\to\config.conf --format json
```

### Folder scan
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json
```

### Optional FortiOS target override
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\path\to\config.conf --fortios 7.6 --format md
```

### Write report to file
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format human --output .\report.txt
```

### Rich embedded HTML report
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format html --output .\report.html --report-title "Client Security Report"
```

### Optional PDF export (from HTML)
```powershell
$env:PYTHONPATH='src'
pip install weasyprint
python -m fgcheck.cli .\configs\ --format html --output .\report.html --pdf-output .\report.pdf
```

Suppress stdout report output (artifact-only mode):
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format html --output .\report.html --quiet
```

Write run summary JSON:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --summary-output .\summary.json
```

### Baseline suppression
Generate a baseline from current findings:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --write-baseline .\baseline.json
```

Suppress known findings from that baseline:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format human --baseline .\baseline.json
```

Merge newly observed finding signatures into the existing baseline:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --baseline .\baseline.json --baseline-update
```

Write only unsuppressed findings to a JSON artifact for triage/CI:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --baseline .\baseline.json --new-findings-output .\new-findings.json
```

Write unsuppressed findings to CSV:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --baseline .\baseline.json --findings-csv-output .\findings.csv
```

Fail non-zero when new findings remain after baseline suppression:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --baseline .\baseline.json --baseline-strict
```

Fail non-zero when findings meet a severity threshold:
```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli .\configs\ --format json --fail-on-severity high
```

## Version Resolution
Target FortiOS version is chosen in this order:
1. `#config-version` header in the config file
2. CLI `--fortios <version>`
3. default `7.4` with `version_defaulted` warning

## Confidence Semantics
- `certain`: deterministic, schema-backed control.
- `likely`: best-practice guidance (context-dependent).
- `heuristic`: schema missing/unknown or non-deterministic inference.

When schema coverage is unavailable, findings must not claim certainty and should indicate `schema_unknown`.

## Builtin Rules (Current)
- `FGT-ADMIN-EDGE-SSH`
- `FGT-ADMIN-EDGE-HTTPS`
- `FGT-ADMIN-EDGE-TELNET`
- `FGT-ADMIN-EDGE-HTTP`
- `FGT-ADMIN-EDGE-ALLACCESS`
- `FGT-ADMIN-NO-TRUSTED-HOSTS`
- `FGT-ADMIN-TRUSTHOST-UNRESTRICTED`
- `FGT-ADMIN-SUPER-NO-2FA`
- `FGT-POLICY-LOG-001`
- `FGT-POLICY-ANY-ANY-ALL`
- `FGT-LOCAL-IN-PERMISSIVE`
- `FGT-LOCALIN-NO-PROTECTION`
- `FGT-SSLVPN-MIN-TLS`
- `FGT-SSLVPN-SRCINTF-ANY`
- `FGT-SSLVPN-SRCADDR-ALL`
- `FGT-IPSEC-WEAK-DH`
- `FGT-NO-REMOTE-LOGGING`
- `FGT-DNS-NO-ZT`
- `FGT-NTP-NO-NTPS`
- `FGT-SNMP-WEAK-COMMUNITY`
- `FGT-ADMIN-WEAK-PASSWORD-POLICY`
- `FGT-ADMIN-NO-IDLE-TIMEOUT`

### Deterministic Controls Added
- `FGT-ADMIN-EDGE-ALLACCESS`
- `FGT-ADMIN-EDGE-TELNET`
- `FGT-ADMIN-EDGE-HTTP`
- `FGT-ADMIN-NO-TRUSTED-HOSTS`
- `FGT-LOCALIN-NO-PROTECTION`
- `FGT-POLICY-ANY-ANY-ALL`
- `FGT-IPSEC-WEAK-DH`
- `FGT-NO-REMOTE-LOGGING`

## Schema / Corpus Layout
- Source registry: `docs/sources.yaml`
- Derived schema: `docs/derived/schema/<version>/schema.json`
- Derived CVE/PSIRT/KEV: `docs/derived/cves/cves.json`
- Corpus builder: `scripts/build_corpus.py`

## Authority Lookup
Use authority lookup commands to validate FortiOS tables, commands, and fields against local deterministic schema data:

```powershell
$env:PYTHONPATH='src'
python -m fgcheck.cli lookup "system interface" --fortios 7.6 --format json
python -m fgcheck.cli schema "firewall policy" --fortios 7.6 --strict
python -m fgcheck.cli docs "vpn ipsec phase1-interface" --fortios 7.6
```

Results classify commands as `VALIDATED`, `PARTIALLY_VALIDATED`, or `UNKNOWN`.
Strict mode exits non-zero unless validation is fully deterministic. Context7 or MCP output should pass through this lookup before being treated as executable FortiOS syntax.

## Tests
```powershell
$env:PYTHONPATH='src'
python -m pytest -q
```

## Local Real Configs
- Place local real configs under `tests/real/`.
- `tests/real/` is gitignored and intended for local validation only.

## Session Continuity Docs
- `AGENTS.md`
- `docs/PROJECT_GOALS.md`
- `docs/SESSION_HANDOFF.md`
- `docs/STARTUP_PROMPT.md`
