# fgcheck Project Goals

## Primary Goal
Build a production-grade, deterministic FortiGate configuration checker that detects security issues, misconfigurations, and best-practice violations.

## Product Stance
- Detector-only system.
- No automatic remediation execution.
- Remediation output is semantic intent only, never executable CLI fix scripts.

## Canonical Input
- FortiOS text config (`.conf`) is the primary truth source.

## Required Architecture Phases
1. Parser reliability (`src/fgcheck/parse.py`)
2. Facts/topology engine correctness (`src/fgcheck/facts.py`)
3. Rule engine correctness with schema gating (`rules/builtin/*.yaml`, `src/fgcheck/rules_impl.py`)
4. Unit/regression coverage (`tests/fixtures`, `tests/real` local-only)
5. Folder scanning/reporting in CLI (`src/fgcheck/cli.py`)
6. Corpus + schema system (`docs/sources.yaml`, `scripts/build_corpus.py`, `docs/derived/...`, `src/fgcheck/schema.py`)

## Required Capabilities
- Multi-VDOM parsing and robust scope handling.
- Multiline blob parsing (certificates/private keys) without parser desync.
- Edge detection from routing semantics (not role flags alone).
- SD-WAN and policy-route awareness in facts.
- Zone/interface resolution with hierarchy awareness.
- Findings include severity, confidence, rule id, explanation, and exact config evidence.

## Anti-Goals
- No guessed CLI knobs/paths/values.
- No third-party blogs as schema authority.
- No claims of correctness outside schema scope.

## Accepted Decisions
### Version Scope
- First-class: `7.4` and `7.6` family support (`7.4.x`, `7.6.x`).
- Version selection order:
  1. `#config-version` header if present
  2. `--fortios` CLI flag
  3. default `7.4` + `version_defaulted` warning

### Official Sources Only (first pass)
- `docs.fortinet.com`
- `fortinetweb.s3.amazonaws.com` (or equivalent official Fortinet doc CDN)
- `fortiguard.com` (PSIRT)
- `cisa.gov` (KEV)

### Curation Order
1. Schema/syntax extraction first.
2. CVE/PSIRT/KEV normalization can run in parallel.
3. Best-practice snippet/rationale extraction after schema foundation.

### Confidence Semantics
- Deterministic schema-backed controls: `certain`.
- Best-practice guidance: `likely` (unless docs make requirement explicit).
- Unknown schema support: `heuristic` + `schema_unknown`.

### CI Guidance
- By default, CI gates on `certain`.
- Do not fail CI on `likely`/`heuristic` by default.

## Definition Of Done (Production-Grade Trust)
1. Parser handles real FortiOS syntax without systematic false warnings.
2. Facts correctly model edge/interface topology across common enterprise patterns.
3. Rules are version-scoped and schema-gated.
4. Findings provide line-accurate evidence and truthful confidence.
5. Corpus pipeline is reproducible and restricted to official sources.
