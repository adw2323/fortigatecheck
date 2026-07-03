"""Tests for FGT-SSLVPN-NO-MFA rule."""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


_SCHEMA_WITH_FIELDS = {
    "tables": {
        "vpn ssl settings": {
            "fields": {
                "status": {},
                "two-factor": {},
            }
        }
    }
}

_SCHEMA_TABLE_ONLY = {
    "coverage": "table_only",
    "tables": {
        "vpn ssl settings": {"fields": {}},
    },
}

_SCHEMA_EMPTY = {
    "tables": {
        "vpn ssl settings": {"fields": {}},
    }
}


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------
class TestSslvpnNoMfa:
    """Test detection of SSL VPN without two-factor authentication."""

    def test_no_two_factor_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set port 10443
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-SSLVPN-NO-MFA"
        assert findings[0].severity == "high"
        assert "two-factor" in findings[0].message.lower()
        assert "SSL VPN" in findings[0].message

    def test_two_factor_none_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor none
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-SSLVPN-NO-MFA"
        assert "two-factor authentication is not configured" in findings[0].message

    def test_two_factor_invalid_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor some-invalid-value
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "some-invalid-value" in findings[0].message


# ---------------------------------------------------------------------------
# No finding when MFA is configured
# ---------------------------------------------------------------------------
class TestSslvpnMfaConfigured:
    """Test that SSL VPN with proper MFA produces no findings."""

    def test_two_factor_fortitoken_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor fortitoken
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_two_factor_email_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor email
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_two_factor_sms_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor sms
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_two_factor_fortitoken_cloud_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor fortitoken-cloud
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_two_factor_cert_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor cert
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# SSL VPN disabled -> no finding
# ---------------------------------------------------------------------------
class TestSslvpnDisabled:
    """Test that disabled SSL VPN produces no findings."""

    def test_sslvpn_disabled_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status disable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_sslvpn_no_status_block_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set port 10443
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------
class TestSslvpnNoMfaSchemaHandling:
    """Test schema fallback and degradation."""

    def test_no_ssl_settings_block_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_schema_unknown_downgrades_confidence(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_TABLE_ONLY)
        conf = """\
config vpn ssl settings
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].message.startswith("[schema_unknown]")

    def test_no_schema_version_uses_heuristic(self, tmp_path: Path):
        """Non-existent schema version -> heuristic."""
        conf = """\
config vpn ssl settings
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="99.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"

    def test_schema_field_not_supported_skips(self, tmp_path: Path):
        """When two-factor is not in schema and schema is loaded, skip."""
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "vpn ssl settings": {"fields": {"status": {}}}
            },
        })
        conf = """\
config vpn ssl settings
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        # two-factor NOT in schema -> skip
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence verification
# ---------------------------------------------------------------------------
class TestSslvpnNoMfaEvidence:
    """Verify evidence is captured correctly."""

    def test_evidence_from_two_factor_line(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
    set two-factor none
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert len(findings[0].evidence) == 1
        assert "two-factor" in findings[0].evidence[0].raw_lines[0]

    def test_evidence_from_status_line_when_no_two_factor(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", _SCHEMA_WITH_FIELDS)
        conf = """\
config vpn ssl settings
    set status enable
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SSLVPN-NO-MFA.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert len(findings[0].evidence) == 1
        assert "status" in findings[0].evidence[0].raw_lines[0]
