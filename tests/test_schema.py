import json
from pathlib import Path

from fgcheck.schema import load_schema


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


def test_load_schema_uses_point_release_then_family_fallback(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "allowaccess": {"allowed_values": ["ping", "https", "ssh"]},
                    }
                }
            }
        },
    )
    _write_schema(
        tmp_path,
        "7.4.3",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "allowaccess": {"allowed_values": ["https"]},
                    }
                }
            }
        },
    )

    point = load_schema("7.4.3", base_dir=tmp_path)
    assert point.resolved_version == "7.4.3"
    assert point.allowed_values(("system", "interface"), "allowaccess") == {"https"}

    family = load_schema("7.4.11", base_dir=tmp_path)
    assert family.resolved_version == "7.4"
    assert family.allowed_values(("system", "interface"), "allowaccess") == {"ping", "https", "ssh"}


def test_schema_unknown_when_missing_returns_empty_capabilities(tmp_path: Path):
    schema = load_schema("7.6.6", base_dir=tmp_path)

    assert schema.loaded is False
    assert "schema_unknown" in schema.warnings
    assert schema.has_table(("system", "interface")) is False
    assert schema.has_field(("system", "interface"), "allowaccess") is False
    assert schema.allowed_values(("system", "interface"), "allowaccess") is None


def test_empty_schema_file_is_treated_as_schema_unknown(tmp_path: Path):
    _write_schema(tmp_path, "7.6", {"tables": {}})
    schema = load_schema("7.6.6", base_dir=tmp_path)
    assert schema.loaded is False
    assert "schema_unknown" in schema.warnings


def test_table_and_field_lookup_normalizes_path_styles(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.6",
        {
            "tables": {
                "firewall policy": {
                    "fields": {
                        "action": {"allowed_values": ["accept", "deny"]},
                        "logtraffic": {"allowed_values": ["all", "utm", "disable"]},
                    }
                }
            }
        },
    )

    schema = load_schema("7.6.6", base_dir=tmp_path)
    assert schema.has_table(("firewall", "policy")) is True
    assert schema.has_table("firewall policy") is True
    assert schema.has_field(("firewall", "policy"), "action") is True
    assert schema.allowed_values(("firewall", "policy"), "action") == {"accept", "deny"}


def test_schema_partial_flag_set_when_coverage_table_only(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "table_only",
            "tables": {
                "system interface": {
                    "fields": {},
                }
            },
        },
    )
    schema = load_schema("7.4", base_dir=tmp_path)
    assert schema.loaded is True
    assert schema.partial is True


def test_schema_partial_flag_false_when_coverage_full_or_missing(tmp_path: Path):
    _write_schema(
        tmp_path,
        "7.4",
        {
            "coverage": "full",
            "tables": {
                "system interface": {
                    "fields": {"allowaccess": {"allowed_values": ["ssh"]}},
                }
            },
        },
    )
    schema = load_schema("7.4", base_dir=tmp_path)
    assert schema.loaded is True
    assert schema.partial is False


def test_load_schema_80_family_fallback(tmp_path: Path):
    """8.0 point-release falls back to the 8.0 family schema."""
    _write_schema(
        tmp_path,
        "8.0",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "allowaccess": {"allowed_values": ["ssh", "https", "ping"]},
                    }
                }
            }
        },
    )
    _write_schema(
        tmp_path,
        "8.0.0",
        {
            "tables": {
                "system interface": {
                    "fields": {
                        "allowaccess": {"allowed_values": ["ssh", "https"]},
                    }
                }
            }
        },
    )

    # Exact point-release match
    exact = load_schema("8.0.0", base_dir=tmp_path)
    assert exact.resolved_version == "8.0.0"
    assert exact.loaded is True
    assert exact.allowed_values(("system", "interface"), "allowaccess") == {"ssh", "https"}

    # Unknown patch version falls back to family
    fallback = load_schema("8.0.3", base_dir=tmp_path)
    assert fallback.resolved_version == "8.0"
    assert fallback.loaded is True
    assert fallback.allowed_values(("system", "interface"), "allowaccess") == {"ssh", "https", "ping"}


def test_load_schema_80_unknown_without_family_returns_empty(tmp_path: Path):
    """8.0.x with no schema files at all returns schema_unknown."""
    schema = load_schema("8.0.5", base_dir=tmp_path)
    assert schema.loaded is False
    assert "schema_unknown" in schema.warnings


def test_load_schema_80_partial_coverage(tmp_path: Path):
    """8.0 family schema with table_only coverage is flagged partial."""
    _write_schema(
        tmp_path,
        "8.0",
        {
            "coverage": "table_only",
            "tables": {
                "firewall policy": {
                    "fields": {},
                    "source_url": "https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/123/config-firewall-policy",
                }
            },
        },
    )
    schema = load_schema("8.0.0", base_dir=tmp_path)
    assert schema.loaded is True
    assert schema.partial is True
    assert schema.resolved_version == "8.0"
