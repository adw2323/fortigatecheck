# Session Handoff

## Current Status Snapshot

### Completed Foundations
- Parser:
  - multiline quoted `set` blob handling (certificate/private-key style blocks)
  - improved VDOM scope switching and restore
  - nested `config ... end` table path restoration for valid nested sections
- Facts engine:
  - default-route edge detection
  - SD-WAN logical device resolution to member interfaces
  - policy-route output-device edge projection
  - zone-to-interface projection
- Schema foundation:
  - `src/fgcheck/schema.py` implemented (`load_schema`, `has_table`, `has_field`, `allowed_values`)
  - version family fallback (example `7.4.11` -> `7.4`)
  - schema unknown behavior (`schema_unknown`) when unavailable/empty
- Versioning:
  - `src/fgcheck/versioning.py` implements header > flag > default policy
  - CLI `--fortios` support and default warning behavior
- CLI:
  - single-file scan
  - folder scan with per-file output and summary

### Test Coverage Added
- parser tests including multiline, VDOM, and nested config behavior
- facts tests for default route, SD-WAN, and policy-route
- schema tests for fallback and unknown behavior
- rules schema-gating tests
- CLI folder-scan test

## Known Gaps / Open Work
1. Facts engine still needs deeper interface hierarchy handling:
   - software switch member ports vs L3 switch-interface gateway
   - nested parent/child interface projection (including VLAN/interface ancestry)
2. Corpus ingestion is scaffolded but not yet populated from official online sources.
3. Best-practice rationale/snippet extraction is not yet implemented.
4. Rule set is minimal and should be expanded only with schema-backed checks.

## Active Priorities (Ordered)
1. Facts hierarchy correctness (software switch + interface ancestry).
2. Schema corpus online ingestion from allowed official sources.
3. Best-practice extraction and likely-confidence rule expansion.
4. Expanded regression suite using representative sanitized fixtures.

## Do-Next Checklist
1. Add failing tests for software-switch and interface hierarchy edge-cases.
2. Implement deterministic hierarchy resolution in `src/fgcheck/facts.py`.
3. Validate against `tests/real` for false-positive/false-negative reduction.
4. Extend `scripts/build_corpus.py` to fetch/normalize official-source schema facts.
5. Add schema-backed rule expansion with explicit confidence semantics.

## Known Pitfalls / Guardrails
- Do not present guessed FortiOS knobs as facts.
- Do not mark findings `certain` when schema coverage is missing.
- Do not generate executable remediation CLI commands.
- Keep `tests/real` local-only (gitignored) and avoid coupling CI to local data.
