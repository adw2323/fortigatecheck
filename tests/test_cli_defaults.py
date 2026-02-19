from pathlib import Path

from fgcheck.cli import DEFAULT_RULE_FILES


def test_cli_default_rules_match_builtin_catalog():
    builtin = sorted(str(p).replace("\\", "/") for p in (Path("rules") / "builtin").glob("*.yaml"))
    defaults = sorted(DEFAULT_RULE_FILES)
    assert defaults == builtin
