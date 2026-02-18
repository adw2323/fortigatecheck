from fgcheck.parse import parse_fortios_text


def _warning_codes(warnings):
    return [w.code for w in warnings]


def test_parse_multiline_certificate_and_private_key_blocks():
    conf = """
config vpn certificate local
    edit "mycert"
        set certificate "-----BEGIN CERTIFICATE-----
MIIB8zCCAZugAwIBAgIUQp7z
5g8Q/2v+QYxqQf6y8g==
-----END CERTIFICATE-----"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMw
YzA=
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
""".strip()

    model, warnings = parse_fortios_text(conf, file_id="inline")

    cert_obj = model.vdoms["root"]["vpn"]["certificate"]["local"]["mycert"]
    assert cert_obj.fields["certificate"][0].startswith("-----BEGIN CERTIFICATE-----")
    assert cert_obj.fields["certificate"][-1].endswith("-----END CERTIFICATE-----")
    assert cert_obj.fields["private-key"][0].startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert cert_obj.fields["private-key"][-1].endswith("-----END ENCRYPTED PRIVATE KEY-----")
    assert "UNKNOWN_LINE" not in _warning_codes(warnings)


def test_parse_vdom_scope_switches_and_restores_root_scope():
    conf = """
config vdom
    edit root
        config system interface
            edit "port1"
                set ip 10.0.0.1 255.255.255.0
            next
        end
    next
    edit app
        config system interface
            edit "port2"
                set ip 10.0.1.1 255.255.255.0
            next
        end
    next
end
config system global
    set hostname "after-vdom"
end
""".strip()

    model, warnings = parse_fortios_text(conf, file_id="inline")

    root_if = model.vdoms["root"]["system"]["interface"]["port1"]
    app_if = model.vdoms["app"]["system"]["interface"]["port2"]
    global_singleton = model.vdoms["root"]["system"]["global"]["__singleton__"]

    assert root_if.fields["ip"] == ["10.0.0.1", "255.255.255.0"]
    assert app_if.fields["ip"] == ["10.0.1.1", "255.255.255.0"]
    assert global_singleton.fields["hostname"] == "after-vdom"
    assert "UNKNOWN_LINE" not in _warning_codes(warnings)


def test_valid_fortios_snippet_has_no_unknown_line_warnings():
    conf = """
config system settings
    set gui-theme blue
    unset admin-scp
end
config firewall address
    edit "srv1"
        set subnet 192.0.2.10 255.255.255.255
    next
end
""".strip()

    _, warnings = parse_fortios_text(conf, file_id="inline")
    assert "UNKNOWN_LINE" not in _warning_codes(warnings)
