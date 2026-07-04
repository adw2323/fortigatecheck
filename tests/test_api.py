"""Tests for the REST API."""

from __future__ import annotations

import pytest

try:
    from fastapi.testclient import TestClient

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


SAMPLE_CONFIG = """\
config system interface
    edit "wan1"
        set ip 10.0.0.2 255.255.255.0
        set allowaccess ping https ssh
    next
end

config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
        set gateway 10.0.0.1
    next
end
"""


@pytest.mark.skipif(not _HAS_FASTAPI, reason="FastAPI not installed")
class TestAPI:
    def setup_method(self):
        from fgcheck.api import create_app

        self.client = TestClient(create_app())

    def test_health(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_root(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "fortigatecheck"
        assert data["version"] == "0.1.0"

    def test_list_rules(self):
        resp = self.client.get("/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data
        assert data["count"] > 0
        rule_ids = [r["id"] for r in data["rules"]]
        assert "FGT-ADMIN-LOCKOUT-NO-TRIES" in rule_ids

    def test_scan_text(self):
        resp = self.client.post(
            "/scan",
            json={
                "config_text": SAMPLE_CONFIG,
                "fortios_version": "7.4",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "vdoms" in data
        assert data["finding_count"] >= 0

    def test_scan_invalid_config(self):
        resp = self.client.post(
            "/scan",
            json={
                "config_text": "this is not a valid config",
            },
        )
        # Should either parse with warnings or return 400
        assert resp.status_code in (200, 400)

    def test_authority(self):
        resp = self.client.post(
            "/authority",
            json={
                "query": "system interface",
                "fortios_version": "7.4",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "validation_result" in data

    def test_schema_info(self):
        resp = self.client.get("/schema/7.4")
        assert resp.status_code == 200
        data = resp.json()
        assert data["loaded"] is True
        assert data["table_count"] > 0

    def test_rule_not_found(self):
        resp = self.client.get("/rules/FGT-NONEXISTENT")
        assert resp.status_code == 404
