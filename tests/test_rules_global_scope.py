"""Tests for global-scope configuration detection (multi-VDOM configs).

In multi-VDOM FortiGate deployments, many system-level configs live under
``config global`` rather than inside individual VDOMs.  Rules must inspect
both the per-VDOM and global scopes.
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
# FGT-NTP-NO-NTPS — global scope
# ---------------------------------------------------------------------------
class TestNTPGlobalScope:
    """NTP without NTPS in config global should trigger."""

    def test_ntp_in_global_scope_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {"ntps": {}, "type": {}},
                }
            }
        })
        conf = """\
config global
    config system ntp
        set type custom
        set ntpserver "10.0.0.1"
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-NTP-NO-NTPS.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-NTP-NO-NTPS"

    def test_ntps_enable_in_global_no_finding(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system ntp": {
                    "fields": {"ntps": {}, "type": {}},
                }
            }
        })
        conf = """\
config global
    config system ntp
        set type custom
        set ntpserver "10.0.0.1"
        set ntps enable
    end
end"""
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
# FGT-SNMP-WEAK-COMMUNITY — global scope
# ---------------------------------------------------------------------------
class TestSNMPWeakCommunityGlobalScope:
    """Weak SNMP community in config global should trigger."""

    def test_weak_community_in_global_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {}},
                }
            }
        })
        conf = """\
config global
    config system snmp community
        edit 1
            set name "public"
        next
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-WEAK-COMMUNITY.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-SNMP-WEAK-COMMUNITY"
        assert "public" in findings[0].message


# ---------------------------------------------------------------------------
# FGT-SNMP-NO-ACL — global scope
# ---------------------------------------------------------------------------
class TestSNMPNoACLGlobalScope:
    """SNMP community without ACL in config global should trigger."""

    def test_no_acl_in_global_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system snmp community": {
                    "fields": {"name": {}, "hosts": {}},
                }
            }
        })
        conf = """\
config global
    config system snmp community
        edit 1
            set name "open-community"
        next
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-SNMP-NO-ACL.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-SNMP-NO-ACL"
        assert "open-community" in findings[0].message


# ---------------------------------------------------------------------------
# FGT-IPS-DEFAULT-SIGNATURE — global scope
# ---------------------------------------------------------------------------
class TestIPSDefaultSignatureGlobalScope:
    """IPS sensor without entries in config global should trigger."""

    def test_ips_sensor_in_global_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "ips sensor": {
                    "fields": {},
                    "source_url": "https://example.com",
                }
            }
        })
        conf = """\
config global
    config ips sensor
        edit "default-signature"
        next
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-IPS-DEFAULT-SIGNATURE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-IPS-DEFAULT-SIGNATURE"
        assert "default-signature" in findings[0].message


# ---------------------------------------------------------------------------
# FGT-AV-NO-HEURISTIC — global scope
# ---------------------------------------------------------------------------
class TestAVNoHeuristicGlobalScope:
    """AV profiles without heuristic in config global should trigger."""

    def test_av_profile_in_global_no_heuristic(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "antivirus profile": {
                    "fields": {},
                    "source_url": "https://example.com",
                }
            }
        })
        conf = """\
config global
    config antivirus profile
        edit "av-default"
        next
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-AV-NO-HEURISTIC.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-AV-NO-HEURISTIC"


# ---------------------------------------------------------------------------
# FGT-DLP-NO-SENSOR — global scope
# ---------------------------------------------------------------------------
class TestDLPNoSensorGlobalScope:
    """DLP sensor without rules in config global should trigger."""

    def test_dlp_sensor_in_global_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "dlp sensor": {
                    "fields": {},
                    "source_url": "https://example.com",
                }
            }
        })
        conf = """\
config global
    config dlpsensor sensor
        edit "dlp-default"
        next
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-DLP-NO-SENSOR.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-DLP-NO-SENSOR"
        assert "dlp-default" in findings[0].message


# ---------------------------------------------------------------------------
# FGT-FGFM-DEFAULT-OVERRIDE — global scope
# ---------------------------------------------------------------------------
class TestFGFMDefaultOverrideGlobalScope:
    """FortiManager default-override in config global should trigger."""

    def test_fgfm_override_in_global_triggers(self, tmp_path: Path):
        _write_schema(tmp_path, "7.4", {
            "tables": {
                "system fortimanager": {
                    "fields": {
                        "default-override": {},
                        "status": {},
                        "server": {},
                    }
                }
            }
        })
        conf = """\
config global
    config system fortimanager
        set status enable
        set server "10.0.0.100"
        set default-override enable
    end
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-FGFM-DEFAULT-OVERRIDE.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "FGT-FGFM-DEFAULT-OVERRIDE"
        assert "10.0.0.100" in findings[0].message


# ---------------------------------------------------------------------------
# FortiManager config detection
# ---------------------------------------------------------------------------
class TestFortiManagerDetection:
    """Tests for FortiManager config header detection."""

    def test_fmgr_header_detected(self):
        """Config with FMGR in config-version header sets metadata flag."""
        conf = """\
#config-version=FGT80F-FMGR-6003-F
#version=7.4.3
config system global
    set hostname fmgr-device
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert model.meta.get("fortimanager_config") is True

    def test_fortimanager_header_detected(self):
        """Config with FortiManager in header sets metadata flag."""
        conf = """\
#config-version=FGT80F-FortiManager-6003-F
#version=7.4.3
config system global
    set hostname fmgr-device
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert model.meta.get("fortimanager_config") is True

    def test_regular_config_no_fmgr_flag(self):
        """Normal FortiOS config does not set fortimanager_config flag."""
        conf = """\
#config-version=FGT80F-v7.4.3-build2573-F
#version=7.4.3
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert model.meta.get("fortimanager_config") is None

    def test_no_header_no_fmgr_flag(self):
        """Config without any header does not set fortimanager_config flag."""
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert model.meta.get("fortimanager_config") is None
