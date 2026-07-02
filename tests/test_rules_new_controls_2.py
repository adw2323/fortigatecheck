"""Comprehensive tests for the three new security rules:
FGT-DNS-NO-ZT, FGT-NTP-NO-NTPS, FGT-SNMP-WEAK-COMMUNITY.
"""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


# ---------------------------------------------------------------------------
# FGT-DNS-NO-ZT  – DNS zone-transfer enabled
# ---------------------------------------------------------------------------

class TestDNSZoneTransfer:
    """Tests for FGT-DNS-NO-ZT (DNS server with zone-transfer enabled)."""

    def test_zone_transfer_enabled_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer enable
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        f = findings[0]
        assert f.rule_id == "FGT-DNS-NO-ZT"
        assert f.confidence == "certain"
        assert f.severity == "medium"
        assert "dns1" in f.message
        assert "zone-transfer enabled" in f.message
        assert f.evidence  # must have evidence with line references

    def test_zone_transfer_disabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer disable
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_dns_server_table_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
            },
        })
        conf = """
config system interface
    edit "wan1"
        set allowaccess "https"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_zone_transfer_degrades_when_schema_missing(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "coverage": "table_only",
            "tables": {
                "dns server": {"fields": {}},
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer enable
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_multiple_dns_entries_only_zt_flagged(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer enable
    next
    edit "dns2"
        set zone-transfer disable
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "dns1" in findings[0].message

    def test_zone_transfer_field_absent_no_finding(self, tmp_path: Path):
        """When zone-transfer field is not set at all, no finding should be raised."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DNS-NO-ZT.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# FGT-NTP-NO-NTPS  – NTP without NTPS
# ---------------------------------------------------------------------------

class TestNTPNoNTPS:
    """Tests for FGT-NTP-NO-NTPS (NTP configured without NTPS)."""

    def test_ntps_not_set_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                        "type": {"allowed_values": ["custom", "fortiguard"]},
                    },
                },
            },
        })
        conf = """
config system ntp
    set type custom
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        f = findings[0]
        assert f.rule_id == "FGT-NTP-NO-NTPS"
        assert f.confidence == "likely"
        assert f.severity == "medium"
        assert "unencrypted" in f.message
        assert f.evidence

    def test_ntps_disabled_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                        "type": {"allowed_values": ["custom", "fortiguard"]},
                    },
                },
            },
        })
        conf = """
config system ntp
    set type custom
    set ntps disable
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        assert findings[0].rule_id == "FGT-NTP-NO-NTPS"

    def test_ntps_enabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                        "type": {"allowed_values": ["custom", "fortiguard"]},
                    },
                },
            },
        })
        conf = """
config system ntp
    set type custom
    set ntps enable
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_ntp_config_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                    },
                },
            },
        })
        conf = """
config system interface
    edit "wan1"
        set allowaccess "https"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_ntps_degrades_when_schema_missing(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "coverage": "table_only",
            "tables": {
                "system ntp": {"fields": {}},
            },
        })
        conf = """
config system ntp
    set type custom
    set ntps disable
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_ntps_schema_not_supported_skips(self, tmp_path: Path):
        """When the ntps field is not in the schema and schema is loaded, skip."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {"fields": {"type": {"allowed_values": ["custom"]}}},
            },
        })
        conf = """
config system ntp
    set type custom
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# FGT-SNMP-WEAK-COMMUNITY  – SNMP weak community strings
# ---------------------------------------------------------------------------

class TestSNMPWeakCommunity:
    """Tests for FGT-SNMP-WEAK-COMMUNITY (SNMP with default/weak community)."""

    def test_public_community_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "public"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        f = findings[0]
        assert f.rule_id == "FGT-SNMP-WEAK-COMMUNITY"
        assert f.confidence == "certain"
        assert f.severity == "high"
        assert "public" in f.message
        assert "weak" in f.message.lower()
        assert f.evidence

    def test_private_community_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "private"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        assert "private" in findings[0].message

    def test_custom_strong_community_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "Xk9#mP2$vL7!qR"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_no_snmp_table_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system interface
    edit "wan1"
        set allowaccess "https"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_weak_community_degrades_when_schema_missing(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "coverage": "table_only",
            "tables": {
                "system snmp community": {"fields": {}},
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "public"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings
        assert findings[0].confidence == "heuristic"
        assert "[schema_unknown]" in findings[0].message

    def test_multiple_weak_communities_all_flagged(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "public"
    next
    edit 2
        set name "private"
    next
    edit 3
        set name "monitoring"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 3
        flagged = {f.message for f in findings}
        assert any("public" in m for m in flagged)
        assert any("private" in m for m in flagged)
        assert any("monitoring" in m for m in flagged)

    def test_mixed_strong_and_weak_only_weak_flagged(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config system snmp community
    edit 1
        set name "public"
    next
    edit 2
        set name "Kj#8xM2$nQ4!"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "public" in findings[0].message

    def test_all_known_weak_communities_flagged(self, tmp_path: Path):
        """Verify every string in the weak list is flagged."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        weak_strings = [
            "public", "private", "community", "snmp", "monitoring",
            "default", "readonly", "readwrite", "read-only", "read-write",
        ]
        for ws in weak_strings:
            conf = f"""
config system snmp community
    edit 1
        set name "{ws}"
    next
end
""".strip()
            model, warnings = parse_fortios_text(conf, file_id="inline.conf")
            assert warnings == []
            findings = run(
                model,
                rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
                fortios_version="7.4",
                schema_base_dir=tmp_path,
            )
            assert findings, f"Weak community '{ws}' should have been flagged"
            assert findings[0].rule_id == "FGT-SNMP-WEAK-COMMUNITY"


# ---------------------------------------------------------------------------
# Cross-rule integration tests
# ---------------------------------------------------------------------------

class TestNewRulesIntegration:
    """Integration tests verifying all three new rules work together."""

    def test_all_three_rules_in_single_config(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                        "type": {"allowed_values": ["custom", "fortiguard"]},
                    },
                },
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer enable
    next
end
config system ntp
    set type custom
end
config system snmp community
    edit 1
        set name "public"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=[
                "rules/builtin/FGT-DNS-NO-ZT.yaml",
                "rules/builtin/FGT-NTP-NO-NTPS.yaml",
                "rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml",
            ],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        ids = {f.rule_id for f in findings}
        assert "FGT-DNS-NO-ZT" in ids
        assert "FGT-NTP-NO-NTPS" in ids
        assert "FGT-SNMP-WEAK-COMMUNITY" in ids

    def test_all_three_rules_clean_config_no_findings(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                    },
                },
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer disable
    next
end
config system ntp
    set ntps enable
end
config system snmp community
    edit 1
        set name "Xk9#mP2$vL7!qR"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=[
                "rules/builtin/FGT-DNS-NO-ZT.yaml",
                "rules/builtin/FGT-NTP-NO-NTPS.yaml",
                "rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml",
            ],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_evidence_has_line_references(self, tmp_path: Path):
        """Every finding from each rule must include evidence with valid line references."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dns server": {
                    "fields": {"zone-transfer": {"allowed_values": ["enable", "disable"]}},
                },
                "system ntp": {
                    "fields": {
                        "ntps": {"allowed_values": ["enable", "disable"]},
                        "type": {"allowed_values": ["custom"]},
                    },
                },
                "system snmp community": {
                    "fields": {"name": {"allowed_values": []}},
                },
            },
        })
        conf = """
config dns server
    edit "dns1"
        set zone-transfer enable
    next
end
config system ntp
    set type custom
end
config system snmp community
    edit 1
        set name "public"
    next
end
""".strip()
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=[
                "rules/builtin/FGT-DNS-NO-ZT.yaml",
                "rules/builtin/FGT-NTP-NO-NTPS.yaml",
                "rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml",
            ],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        for f in findings:
            assert f.evidence, f"{f.rule_id} must have evidence"
            for ev in f.evidence:
                line_start, line_end = ev.line_range
                assert isinstance(line_start, int) and line_start > 0, \
                    f"{f.rule_id} evidence line_range start must be positive int"
                assert isinstance(line_end, int) and line_end >= line_start, \
                    f"{f.rule_id} evidence line_range end must be >= start"
