import json
import subprocess
import sys
from pathlib import Path

from fgcheck.authority import PARTIALLY_VALIDATED, UNKNOWN, VALIDATED, lookup_authority


def test_lookup_validates_known_table_from_local_schema():
    result = lookup_authority("system interface", fortios="7.6", base_dir=Path("."))

    assert result.validation_result == VALIDATED
    assert result.matched_command == "config system interface"
    assert result.source_url and "docs.fortinet.com" in result.source_url
    assert "allowaccess" in (result.known_fields or [])


def test_lookup_validates_known_field_and_allowed_values():
    result = lookup_authority("allowaccess", fortios="7.6", base_dir=Path("."))

    assert result.validation_result in {VALIDATED, PARTIALLY_VALIDATED}
    assert result.matched_field == "allowaccess"
    assert result.source_url and "docs.fortinet.com" in result.source_url


def test_lookup_rejects_hallucinated_command():
    result = lookup_authority("deep packet ai shield", fortios="7.6", base_dir=Path("."))

    assert result.validation_result == UNKNOWN
    assert result.confidence_level == "none"
    assert "no_schema_match" in (result.warnings or [])


def test_cli_lookup_json_contract_for_known_command():
    proc = subprocess.run(
        [sys.executable, "-m", "fgcheck.cli", "lookup", "system interface", "--fortios", "7.6", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout)

    assert payload["validation_result"] == VALIDATED
    assert payload["matched_command"] == "config system interface"
    assert payload["source_url"].startswith("https://docs.fortinet.com/")
    assert isinstance(payload["known_fields"], list)


def test_cli_strict_blocks_unknown_command():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "fgcheck.cli",
            "lookup",
            "deep packet ai shield",
            "--fortios",
            "7.6",
            "--strict",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["validation_result"] == UNKNOWN
