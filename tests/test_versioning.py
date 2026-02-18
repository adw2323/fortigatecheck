from fgcheck.model import ConfigModel
from fgcheck.parse import parse_fortios_text
from fgcheck.versioning import resolve_target_fortios


def test_resolve_target_fortios_prefers_config_header():
    conf = """
#config-version=FGT70F-7.6.6-FW-build3652-260127:opmode=0:vdom=0:user=admin
config system global
    set hostname "fw1"
end
""".strip()
    model, warnings = parse_fortios_text(conf, file_id="inline")
    assert warnings == []

    version, v_warnings = resolve_target_fortios(model, explicit_version="7.4")
    assert version == "7.6.6"
    assert v_warnings == []


def test_resolve_target_fortios_uses_explicit_when_no_header():
    model = ConfigModel(meta={"file_id": "inline"})
    version, v_warnings = resolve_target_fortios(model, explicit_version="7.6")
    assert version == "7.6"
    assert v_warnings == []


def test_resolve_target_fortios_defaults_to_74_and_warns():
    model = ConfigModel(meta={"file_id": "inline"})
    version, v_warnings = resolve_target_fortios(model, explicit_version=None)
    assert version == "7.4"
    assert "version_defaulted" in v_warnings
