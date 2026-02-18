# New Session Startup Prompt (Template)

Use this prompt at the beginning of a fresh Codex session:

```text
Continue work on fgcheck.

Important:
- Existing modified/untracked files are expected; do not stop just because the tree is dirty.
- Do not rewrite the whole codebase; work incrementally with tests first.
- Treat fgcheck as detector-only: no automatic CLI remediation generation/execution.
- Do not claim FortiGate syntax/knobs unless schema-backed.

Before coding:
1) Read AGENTS.md
2) Read docs/PROJECT_GOALS.md
3) Read docs/SESSION_HANDOFF.md

Then:
- Summarize current status and next highest-priority task.
- Implement that task end-to-end with tests and verification.
```

## Notes
- If target FortiOS version is not explicit, follow project policy:
  `#config-version` > `--fortios` > default `7.4` with `version_defaulted`.
