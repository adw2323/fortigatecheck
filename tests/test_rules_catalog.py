from pathlib import Path

import yaml


def _builtin_rule_files() -> list[Path]:
    return sorted((Path("rules") / "builtin").glob("*.yaml"))


def test_builtin_rules_exist_and_have_unique_ids():
    files = _builtin_rule_files()
    assert files
    ids = []
    for p in files:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert isinstance(data.get("id"), str) and data["id"].strip()
        ids.append(data["id"])
    assert len(ids) == len(set(ids))


def test_builtin_rules_use_allowed_severity_and_confidence():
    allowed_severity = {"critical", "high", "medium", "low", "info"}
    allowed_confidence = {"certain", "likely", "heuristic"}
    for p in _builtin_rule_files():
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert data["severity"] in allowed_severity, str(p)
        assert data["confidence"] in allowed_confidence, str(p)


def test_builtin_rule_entrypoints_are_importable_callables():
    for p in _builtin_rule_files():
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        dotted = data["entrypoint"]
        mod_name, fn_name = dotted.rsplit(":", 1)
        mod = __import__(mod_name, fromlist=[fn_name])
        fn = getattr(mod, fn_name)
        assert callable(fn), str(p)


def test_requested_deterministic_rules_are_marked_certain():
    deterministic_ids = {
        "FGT-ADMIN-EDGE-ALLACCESS",
        "FGT-ADMIN-NO-TRUSTED-HOSTS",
        "FGT-LOCALIN-NO-PROTECTION",
        "FGT-POLICY-ANY-ANY-ALL",
        "FGT-IPSEC-WEAK-DH",
        "FGT-NO-REMOTE-LOGGING",
    }
    for p in _builtin_rule_files():
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        if data["id"] in deterministic_ids:
            assert data["confidence"] == "certain", str(p)
