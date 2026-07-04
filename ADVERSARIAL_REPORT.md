# Adversarial Review: fortigatecheck

**Date:** July 3, 2026  
**Reviewer:** Hermes Agent (adversarial audit)  
**Scope:** Parser, rules engine, API, Web UI, CLI, Fleet DB, security of the tool itself

---

## Executive Summary

Fortigatecheck is a well-structured FortiGate configuration checker with 75+ security rules and 500+ tests. The parser is **remarkably robust** against malformed input. However, the tool itself has **7 confirmed security vulnerabilities** ranging from critical to medium, primarily in the API/Web UI layer and the rule import mechanism.

| Severity | Count | Category |
|----------|-------|----------|
| CRITICAL | 2 | Arbitrary code execution via rule imports |
| HIGH | 3 | Path traversal, XSS, no authentication |
| MEDIUM | 2 | Plaintext storage, markdown injection |
| INFO | 1 | FleetDB string path type bug |

---

## CRITICAL Findings

### C1: Arbitrary Module Import via `_import_callable` (RCE)

**Location:** `src/fgcheck/rules.py:30-33`  
**Impact:** Arbitrary code execution through malicious YAML rule files

The `_import_callable` function uses `__import__()` with no allowlist:

```python
def _import_callable(dotted: str) -> Callable[..., List[Finding]]:
    mod, fn = dotted.rsplit(":", 1)
    m = __import__(mod, fromlist=[fn])
    return getattr(m, fn)
```

**Confirmed exploitable entrypoints:**
- `subprocess:run` — **resolved successfully**, can execute arbitrary commands
- `shutil:rmtree` — **resolved successfully**, can delete files recursively
- `json:loads` — resolved successfully (benign example)

**Attack vector:** The CLI `--rules` flag accepts arbitrary YAML files. A malicious rule YAML with `"entrypoint": "subprocess:run"` would be imported and callable. If an attacker can place a YAML file in the rules path or supply one via `--rules`, they achieve RCE.

**Severity:** CRITICAL — any user-supplied rule file is a code execution vector.

**Fix:** Implement an allowlist of permitted modules (e.g., `fgcheck.*` only), or validate that the entrypoint string starts with `fgcheck.`.

---

### C2: Rule YAML File Code Execution via CLI

**Location:** `src/fgcheck/cli.py:100` and `src/fgcheck/rules.py:35-47`  
**Impact:** Same as C1, via CLI invocation

The `--rules` argument accepts arbitrary file paths:

```python
ap.add_argument("--rules", nargs="+", default=DEFAULT_RULE_FILES)
```

Combined with C1, any YAML file on the filesystem can be loaded as a rule with arbitrary Python entrypoints.

**Attack scenario:** An attacker with write access to a directory on the rule search path can place a malicious YAML that executes code when `fgcheck` scans any config.

**Severity:** CRITICAL

---

## HIGH Findings

### H1: API Path Traversal via `/rules/{rule_id}`

**Location:** `src/fgcheck/api.py:156`  
**Impact:** Read arbitrary `.yaml` files from the filesystem

```python
yaml_file = builtin_dir / f"{rule_id}.yaml"
```

No sanitization of `rule_id`. A request to `/rules/../../pyproject` constructs a path traversing outside the rules directory. While `.yaml` extension limits the impact, an attacker could read any file ending in `.yaml` on the system.

**Fix:** Validate `rule_id` contains only `[a-zA-Z0-9_-]` characters.

---

### H2: Stored XSS in Web UI via `innerHTML`

**Location:** `src/fgcheck/web.py:173-181` (scan UI), lines 228-234 (fleet dashboard)  
**Impact:** JavaScript execution in user's browser

The scan results UI injects finding data directly via `innerHTML`:

```javascript
findingsDiv.innerHTML = data.findings.map(f =>
    '<div class="finding ' + f.severity + '">' +
    '<span class="severity ' + f.severity + '">' + f.severity + '</span> ' +
    '<span class="rule-id">' + f.rule_id + '</span>' +
    '<div class="message">' + f.message + '</div>' +
    '</div>'
).join('');
```

The fleet dashboard is worse — device names from the database are injected directly:

```javascript
document.getElementById("devices").innerHTML = d.map(x =>
    `<tr><td>${x.device_name}</td>...`
).join("");
```

**Attack:** If a FortiGate config contains malicious content in field values (which become finding messages), or if an attacker stores a device name with `<script>` tags via the fleet scan API, XSS executes.

**Fix:** Use `textContent` instead of `innerHTML`, or escape all values with a JS escape function.

---

### H3: No Authentication on API or Web UI

**Location:** `src/fgcheck/api.py` (entire file), `src/fgcheck/web.py` (entire file)  
**Impact:** Unauthenticated access to scanning, fleet data, and configuration upload

Neither the API nor the Web UI has any authentication middleware. Anyone on the network can:
- Scan arbitrary FortiGate configurations
- Upload configuration files
- Access fleet management data (device names, findings, scan history)
- Store scan results via the fleet API

**Fix:** Add authentication middleware (API key, basic auth, or integrate with existing auth).

---

## MEDIUM Findings

### M1: Fleet DB Stores Security Findings in Plaintext

**Location:** `src/fgcheck/fleet_db.py` (entire file)  
**Impact:** Sensitive security data stored without encryption

The SQLite database at `~/.fgcheck/fleet.db` stores:
- All scan findings as plaintext JSON
- Device names and configuration metadata
- Compliance status

The database file is unencrypted SQLite. Any user with filesystem access can read all historical scan results.

**Fix:** Consider SQLCipher for encryption at rest, or at minimum restrict file permissions.

---

### M2: Markdown Injection via Evidence `raw_lines`

**Location:** `src/fgcheck/report.py:50-54`  
**Impact:** Potential code injection in markdown renderers

Evidence `raw_lines` are inserted directly into markdown code blocks:

```python
if ev.raw_lines:
    out.append("    ```\n")
    for rl in ev.raw_lines:
        out.append(f"    {rl}\n")
    out.append("    ```\n")
```

An attacker controlling config content can craft values that break out of code blocks or inject markdown directives in some renderers.

**Fix:** Escape all raw_lines content before inserting into markdown.

---

## INFO / Design Issues

### I1: FleetDB Crashes with String `db_path`

**Location:** `src/fgcheck/fleet_db.py:53`  
**Impact:** TypeError when passing string instead of Path

```python
self.db_path.parent.mkdir(parents=True, exist_ok=True)
```

The `db_path` parameter is typed as `Optional[Path]` but not enforced. Passing a `str` causes `AttributeError: 'str' object has no attribute 'parent'`. This is a type safety issue.

**Fix:** Wrap with `Path(db_path)`.

### I2: CLI `--output` Allows Arbitrary Filesystem Write

**Location:** `src/fgcheck/cli.py:143-146`  
**Impact:** Report output written to arbitrary paths

```python
out_path = Path(args.output)
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(text, encoding="utf-8")
```

No validation that the output path is within expected directories. Combined with `parents=True`, this creates directories and writes anywhere.

### I3: No CORS Configuration

The API and Web UI have no CORS middleware. Any web page can make cross-origin requests to the scanning API.

### I4: API File Upload Has No Size Limit

The `/scan/file` endpoint calls `file.read()` without size checks. The CLI has `--max-size` (default 10MB) but the API has no equivalent. A multi-GB upload could exhaust server memory.

---

## Parser Analysis

The FortiGate config parser (`parse.py`) is **exceptionally robust**:

| Edge Case | Result |
|-----------|--------|
| Empty config | ✅ Parses cleanly |
| Comments-only config | ✅ Parses cleanly |
| Deeply nested (200 levels) | ✅ No stack overflow |
| Unicode in values | ✅ Handled |
| UTF-8 BOM | ✅ Handled |
| CR+LF line endings | ✅ Handled |
| Tab indentation | ✅ Handled |
| Mixed case directives | ✅ Handled |
| Unmatched quotes | ✅ Graceful degradation |
| Mismatched `end`/`next` | ✅ Warnings generated |
| Long lines (100KB) | ✅ Handled |
| Hash in quoted values | ✅ Preserved correctly |
| Circular interface refs | ✅ Cycle detection works |
| Multiline quoted values | ✅ Handled |
| `set` without values | ✅ Warning generated |
| `unset` without key | ✅ Warning generated |
| Unknown directives | ✅ Warning generated |

**Parser does NOT handle:**
- Configs with binary data embedded
- Extremely large single values (>100MB) — may cause memory issues
- Nested `#config-version` headers — only first detection matters

---

## Rule Accuracy Analysis

### Confirmed False Positives

1. **FGT-ADMIN-LOCKOUT-NO-TRIES:** Fires on factory defaults (no `config system global` block). Factory default IS "no lockout" but flagging it assumes the admin hasn't reviewed the default.

2. **FGT-ADMIN-NO-2FA:** Flags ALL admin accounts without 2FA, including service/API accounts that legitimately don't need interactive 2FA.

3. **FGT-SSL-INSPECTION-DISABLED:** Flags any HTTPS policy without UTM, even for known-safe destinations (update servers, CDN endpoints) where inspection may be deliberately disabled.

4. **FGT-DNS-DEFAULT-ONLY:** Flags even when DNS-over-TLS/HTTPS is configured at the application layer; only checks the `protocol` field.

### Confirmed False Negatives

1. **SSH on non-edge interfaces behind NAT:** Rules only check edge interfaces (identified by default route). If a 1:1 NAT maps WAN:22 to LAN:22, SSH on the LAN interface is reachable but not flagged.

2. **FortiManager-managed configs:** The tool warns about FMGR configs but still runs all rules. The effective running config may differ significantly from the exported config.

3. **Nested sub-table flattening:** Parser flattens nested `config entries` blocks to root-level tables. This means rules can't determine which parent an entry belongs to (e.g., which IPS sensor owns which entries).

4. **`unset` followed by `set`:** While `effective_fields()` properly handles unsets, some rules check `fields` directly instead of `effective_fields()`, potentially missing the unset.

---

## Performance Assessment

| Scenario | Result |
|----------|--------|
| 1000 interfaces | ✅ Parses in <1s |
| 100 VDOMs | ✅ Handles well |
| 1000 `set` on same key | ✅ No memory explosion |
| Circular interface references | ✅ Cycle detection prevents infinite loop |

The parser handles large configs well. The main risk is the API endpoint which has no file size limit.

---

## Recommendations (Priority Order)

1. **CRITICAL: Add entrypoint allowlist to `_import_callable`** — restrict to `fgcheck.*` modules only
2. **HIGH: Sanitize `rule_id` in API** — reject paths containing `..` or `/`
3. **HIGH: Fix innerHTML XSS** — use `textContent` or escape all dynamic values
4. **HIGH: Add authentication** — at minimum API key auth for fleet/API endpoints
5. **MEDIUM: Encrypt fleet DB** — or at minimum restrict file permissions to owner-only
6. **MEDIUM: Add API file size limits** — mirror the CLI's `--max-size` protection
7. **LOW: Fix FleetDB string path type** — wrap `db_path` with `Path()`
8. **LOW: Add CORS configuration** — restrict to same-origin or configured origins

---

## Files Created/Modified

- `tests/test_adversarial_v2.py` — 23 adversarial tests confirming all findings above
- This report: `ADVERSARIAL_REPORT.md`

## Existing Test Suite

All 506 existing tests continue to pass. The adversarial tests add 23 new tests confirming the vulnerabilities described above.
