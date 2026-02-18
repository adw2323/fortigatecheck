# fgcheck Agent Contract

## Mission
`fgcheck` is a detector-only FortiGate configuration checker focused on security vulnerabilities, misconfigurations, and best-practice violations.

## Non-Negotiables
1. Never generate or execute automatic CLI fixes.
2. Never hallucinate FortiGate CLI syntax, config keys, config paths, or allowed values.
3. Any syntax/knob/path/value claim must be schema-gated against version-scoped derived schema.
4. If schema does not confirm a claim, do not present it as correct:
   - skip the check, or
   - downgrade to heuristic confidence, and/or
   - mark with `schema_unknown`.

## Source Of Truth
- Schema and config surface: `docs/derived/schema/<fortios_version>/...`
- Source declarations and allowed upstreams: `docs/sources.yaml`
- CVE/PSIRT/KEV derived data: `docs/derived/cves/cves.json`

## Version Policy
- First-class support: FortiOS `7.4.x` and `7.6.x` families.
- Family and point-release layout must both be supported:
  - `docs/derived/schema/7.4/...`
  - `docs/derived/schema/7.6/...`
  - optional point release folders later (example `7.4.3`).

## Confidence Policy
- `certain`: deterministic/security-control findings backed by schema and objective config evidence.
- `likely`: best-practice findings from official guidance where context may vary.
- `heuristic`: schema missing/unknown or non-deterministic inference.
- If schema is missing/unknown, findings must not claim certainty and should include `schema_unknown`.

## Evidence Requirements
All findings must include config evidence with exact line references from the parsed file.

## Engineering Rules
1. Tests first for behavioral changes.
2. Incremental improvements; avoid broad rewrites.
3. Keep parser deterministic and line-preserving.
4. Keep rule logic and parser/facts responsibilities clearly separated.

## Session Bootstrap
At the start of a new session, read in this order:
1. `AGENTS.md`
2. `docs/PROJECT_GOALS.md`
3. `docs/SESSION_HANDOFF.md`
