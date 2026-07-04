"""Tests for the web UI."""
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
class TestWebUI:
    def setup_method(self):
        from fgcheck.web import create_web_app
        self.client = TestClient(create_web_app())

    def test_index_loads(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert "fortigatecheck" in resp.text
        assert "upload" in resp.text.lower() or "drop" in resp.text.lower()

    def test_scan_endpoint(self):
        resp = self.client.post("/scan", json={
            "config_text": SAMPLE_CONFIG,
            "fortios_version": "7.4",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "vdoms" in data
        assert "total" in data

    def test_scan_invalid(self):
        resp = self.client.post("/scan", json={
            "config_text": "not a config",
        })
        # Should either parse with warnings or return error
        assert resp.status_code in (200, 400)

    def test_scan_empty(self):
        resp = self.client.post("/scan", json={
            "config_text": "",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
