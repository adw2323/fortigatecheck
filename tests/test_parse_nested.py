from fgcheck.parse import parse_fortios_text


def _warning_codes(warnings):
    return [w.code for w in warnings]


def test_nested_config_blocks_stay_under_parent_path():
    conf = """
config system sdwan
    config members
        edit 1
            set interface "wan1"
        next
    end
    config zone
        edit "internet"
            set interface "wan1" "wan2"
        next
    end
end
""".strip()

    model, warnings = parse_fortios_text(conf, file_id="inline")

    sdwan = model.vdoms["root"]["system"]["sdwan"]
    assert sdwan["members"]["1"].fields["interface"] == "wan1"
    assert sdwan["zone"]["internet"].fields["interface"] == ["wan1", "wan2"]
    assert "EDIT_OUTSIDE_TABLE" not in _warning_codes(warnings)
    assert "SET_OUTSIDE_EDIT" not in _warning_codes(warnings)
    assert "UNKNOWN_LINE" not in _warning_codes(warnings)


def test_end_of_nested_config_restores_parent_context_for_siblings():
    conf = """
config system sdwan
    config members
        edit 1
            set interface "wan1"
        next
    end
    config health-check
        edit "hc1"
            set server "1.1.1.1"
        next
    end
end
""".strip()

    model, warnings = parse_fortios_text(conf, file_id="inline")

    sdwan = model.vdoms["root"]["system"]["sdwan"]
    assert "members" in sdwan
    assert "health-check" in sdwan
    assert sdwan["health-check"]["hc1"].fields["server"] == "1.1.1.1"
    assert "EDIT_OUTSIDE_TABLE" not in _warning_codes(warnings)
    assert "SET_OUTSIDE_EDIT" not in _warning_codes(warnings)
