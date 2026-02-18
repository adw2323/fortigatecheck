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

## Schema / Corpus Layout
- Source registry: `docs/sources.yaml`
- Derived schema: `docs/derived/schema/<version>/schema.json`
- Derived CVE/PSIRT/KEV: `docs/derived/cves/cves.json`
- Corpus builder: `scripts/build_corpus.py`

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
