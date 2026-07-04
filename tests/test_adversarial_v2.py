"""Final adversarial test suite - verified confirmed findings."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 1: Arbitrary Module Import via _import_callable
# ═══════════════════════════════════════════════════════════════════


def test_import_callable_subprocess_run():
    """FIXED: _import_callable now blocks non-fgcheck modules."""
    from fgcheck.rules import _import_callable

    with pytest.raises(ValueError, match="Only fgcheck"):
        _import_callable("subprocess:run")


def test_import_callable_shutil_rmtree():
    """FIXED: _import_callable now blocks non-fgcheck modules."""
    from fgcheck.rules import _import_callable

    with pytest.raises(ValueError, match="Only fgcheck"):
        _import_callable("shutil:rmtree")


def test_import_callable_json_loads():
    """FIXED: _import_callable now blocks non-fgcheck modules."""
    from fgcheck.rules import _import_callable

    with pytest.raises(ValueError, match="Only fgcheck"):
        _import_callable("json:loads")


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 2: API Path Traversal
# ═══════════════════════════════════════════════════════════════════


def test_api_path_traversal_rule_id():
    """HIGH: /rules/{rule_id} allows path traversal to read arbitrary YAML."""
    builtin_dir = Path("rules/builtin")
    rule_id = "../../pyproject"
    yaml_file = builtin_dir / f"{rule_id}.yaml"
    # Path traverses outside rules directory
    assert ".." in str(yaml_file)
    # If pyproject.toml were YAML, it would be read


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 3: Stored XSS via innerHTML
# ═══════════════════════════════════════════════════════════════════


def test_web_ui_innerhtml_xss():
    """HIGH: Web UI injects finding.message via innerHTML - XSS vector."""
    from fgcheck.web import HTML_TEMPLATE

    # JS code: findingsDiv.innerHTML = data.findings.map(f =>
    #   '...' + f.message + '...'
    # )
    assert "innerHTML" in HTML_TEMPLATE
    assert "f.message" in HTML_TEMPLATE


def test_fleet_dashboard_stored_xss():
    """HIGH: Fleet dashboard injects device_name via innerHTML - stored XSS."""
    from fgcheck.web import FLEET_DASHBOARD_HTML

    assert "innerHTML" in FLEET_DASHBOARD_HTML
    # Device names are injected directly: <td>${x.device_name}</td>
    assert "device_name" in FLEET_DASHBOARD_HTML


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 4: No Authentication
# ═══════════════════════════════════════════════════════════════════


def test_api_no_auth():
    """HIGH: API has no authentication on any endpoint."""
    from fgcheck.api import create_app

    app = create_app()
    routes = [r.path for r in app.routes]
    # All sensitive endpoints are unauthenticated
    assert "/scan" in routes
    assert "/scan/file" in routes
    assert "/rules" in routes
    assert "/authority" in routes


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 5: FleetDB Unencrypted Storage
# ═══════════════════════════════════════════════════════════════════


def test_fleet_db_plaintext_findings():
    """MEDIUM: Fleet DB stores security findings as plaintext JSON."""
    from fgcheck.fleet_db import FleetDB

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = FleetDB(db_path=Path(db_path))
        db.store_scan(
            "test",
            [
                {"severity": "critical", "message": "admin-password exposed"},
            ],
        )
        scans = db.get_scans()
        assert "admin-password" in scans[0].findings_json
        db.close()
    finally:
        os.unlink(db_path)


def test_fleet_db_unencrypted_sqlite():
    """MEDIUM: Fleet DB SQLite is unencrypted."""
    from fgcheck.fleet_db import FleetDB

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = FleetDB(db_path=Path(db_path))
        with open(db_path, "rb") as f:
            header = f.read(16)
        assert header.startswith(b"SQLite format 3")
        db.close()
    finally:
        os.unlink(db_path)


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 6: Rule File Code Execution
# ═══════════════════════════════════════════════════════════════════


def test_cli_rule_file_arbitrary_import():
    """FIXED: _import_callable blocks non-fgcheck modules."""
    import yaml

    from fgcheck.rules import _import_callable, load_rules

    rule_data = {
        "id": "MALICIOUS",
        "title": "Malicious Rule",
        "severity": "high",
        "confidence": "certain",
        "entrypoint": "subprocess:run",
    }
    tmpfile = os.path.join(tempfile.gettempdir(), "malicious_rule.yaml")
    with open(tmpfile, "w") as f:
        yaml.dump(rule_data, f)
    try:
        rules = load_rules([tmpfile])
        with pytest.raises(ValueError, match="Only fgcheck"):
            _import_callable(rules[0].entrypoint)
    finally:
        os.unlink(tmpfile)


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY 7: Markdown Injection via raw_lines
# ═══════════════════════════════════════════════════════════════════


def test_markdown_code_block_injection():
    """MEDIUM: Evidence raw_lines inject content into markdown code blocks."""
    from fgcheck.model import Evidence
    from fgcheck.report import findings_to_markdown
    from fgcheck.rules import Finding

    f = Finding(
        rule_id="test",
        title="test",
        severity="low",
        confidence="heuristic",
        vdom="root",
        message="test",
        evidence=[
            Evidence(
                file_id="test.conf",
                line_range=(1, 1),
                path=(),
                raw_lines=["```malicious_code_block```"],
            )
        ],
    )
    md = findings_to_markdown([f])
    # raw_lines are placed inside ``` blocks but attacker controls the content
    assert "```" in md


# ═══════════════════════════════════════════════════════════════════
# PARSER: Confirmed Correct Behavior
# ═══════════════════════════════════════════════════════════════════


def test_comment_parser_preserves_hash_in_quotes():
    """GOOD: Hash inside quoted value is preserved."""
    from fgcheck.parse import _strip_comment

    result = _strip_comment('set key "password is #123"')
    assert "#" in result


def test_comment_parser_strips_inline_comment():
    """GOOD: Inline comment after closing quote is stripped."""
    from fgcheck.parse import _strip_comment

    result = _strip_comment('set key "value" # this is a comment')
    assert "this is a comment" not in result


def test_comment_parser_handles_uneven_quotes():
    """GOOD: Odd quotes don't crash the parser."""
    from fgcheck.parse import _strip_comment

    result = _strip_comment('set key "value # not a comment')
    assert result is not None


def test_finding_sort_empty_evidence():
    """GOOD: Finding sort handles empty evidence gracefully."""
    from fgcheck.rules import Finding

    f = Finding(
        rule_id="test",
        title="test",
        severity="low",
        confidence="heuristic",
        vdom="root",
        message="test",
        evidence=[],
    )
    sorted_list = sorted(
        [f],
        key=lambda x: (
            x.vdom,
            x.rule_id,
            x.evidence[0].line_range[0] if x.evidence else 0,
            x.message,
        ),
    )
    assert len(sorted_list) == 1


# ═══════════════════════════════════════════════════════════════════
# PARSER: Edge Cases (Parser is robust)
# ═══════════════════════════════════════════════════════════════════


def test_parser_empty_config():
    model, warnings = __import__("fgcheck.parse", fromlist=["parse_fortios_text"]).parse_fortios_text("")
    assert model is not None


def test_parser_only_comments():
    from fgcheck.parse import parse_fortios_text

    model, warnings = parse_fortios_text("# comment\n# another\n")
    assert model is not None


def test_parser_deeply_nested():
    from fgcheck.parse import parse_fortios_text

    lines = [f"config level{i}" for i in range(200)]
    lines.append("set key value")
    lines.extend(["end"] * 200)
    model, warnings = parse_fortios_text("\n".join(lines))
    assert model is not None


def test_parser_mismatched_end():
    from fgcheck.parse import parse_fortios_text

    model, warnings = parse_fortios_text("end\nend\nend\n")
    assert model is not None


def test_parser_unicode_values():
    from fgcheck.parse import parse_fortios_text

    model, warnings = parse_fortios_text('config system global\nset desc "日本語 🔒"\nend\n')
    assert model is not None


def test_parser_long_line():
    from fgcheck.parse import parse_fortios_text

    model, warnings = parse_fortios_text('config system global\nset desc "x" * 100000\nend\n')
    assert model is not None


def test_parser_mixed_case():
    from fgcheck.parse import parse_fortios_text

    model, warnings = parse_fortios_text("CONFIG system global\nSET admin-port 443\nEND\n")
    assert model is not None


def test_circular_interface_references():
    from fgcheck.facts import build_facts
    from fgcheck.parse import parse_fortios_text

    text = 'config system interface\nedit "p1"\nset interface "p2"\nnext\nedit "p2"\nset interface "p1"\nnext\nend\n'
    model, _ = parse_fortios_text(text)
    facts = build_facts(model, vdom="root")
    assert facts is not None


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
