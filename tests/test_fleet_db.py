"""Tests for fleet management database."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from fgcheck.fleet_db import FleetDB


@pytest.fixture
def fleet_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = FleetDB(Path(tmpdir) / "test.db")
        yield db
        db.close()


class TestFleetDB:
    def test_store_and_retrieve(self, fleet_db):
        findings = [
            {"rule_id": "FGT-TEST", "severity": "critical", "message": "test"},
            {"rule_id": "FGT-TEST2", "severity": "high", "message": "test2"},
        ]
        scan_id = fleet_db.store_scan("fw01", findings, config_file="test.conf")
        assert scan_id

        scans = fleet_db.get_scans(device_name="fw01")
        assert len(scans) == 1
        assert scans[0].device_name == "fw01"
        assert scans[0].finding_count == 2
        assert scans[0].critical_count == 1
        assert scans[0].high_count == 1

    def test_device_summary(self, fleet_db):
        fleet_db.store_scan("fw01", [{"severity": "critical", "rule_id": "A"}])
        fleet_db.store_scan("fw02", [{"severity": "low", "rule_id": "B"}])
        fleet_db.store_scan("fw01", [{"severity": "high", "rule_id": "C"}])

        summaries = fleet_db.get_device_summary()
        assert len(summaries) == 2
        names = {s.device_name for s in summaries}
        assert "fw01" in names
        assert "fw02" in names

    def test_fleet_stats(self, fleet_db):
        fleet_db.store_scan("fw01", [{"severity": "critical", "rule_id": "A"}])
        fleet_db.store_scan("fw02", [{"severity": "high", "rule_id": "B"}])

        stats = fleet_db.get_fleet_stats()
        assert stats["device_count"] == 2
        assert stats["total_scans"] == 2
        assert stats["total_findings"] == 2
        assert stats["total_critical"] == 1

    def test_empty_db(self, fleet_db):
        stats = fleet_db.get_fleet_stats()
        assert stats["device_count"] == 0
        assert stats["total_scans"] == 0

    def test_delete_device(self, fleet_db):
        fleet_db.store_scan("fw01", [{"severity": "low", "rule_id": "A"}])
        fleet_db.store_scan("fw01", [{"severity": "low", "rule_id": "B"}])
        deleted = fleet_db.delete_device("fw01")
        assert deleted == 2
        scans = fleet_db.get_scans(device_name="fw01")
        assert len(scans) == 0

    def test_severity_trend(self, fleet_db):
        fleet_db.store_scan("fw01", [
            {"severity": "critical", "rule_id": "A"},
            {"severity": "critical", "rule_id": "B"},
        ])
        trend = fleet_db.get_severity_trend(device_name="fw01")
        assert len(trend) >= 1

    def test_worst_devices(self, fleet_db):
        fleet_db.store_scan("fw01", [
            {"severity": "critical", "rule_id": "A"},
            {"severity": "critical", "rule_id": "B"},
        ])
        fleet_db.store_scan("fw02", [{"severity": "low", "rule_id": "C"}])

        worst = fleet_db.get_worst_devices()
        assert len(worst) == 2
        assert worst[0]["device_name"] == "fw01"
        assert worst[0]["critical_count"] == 2

    def test_metadata_and_compliance(self, fleet_db):
        meta = {"source": "test"}
        compliance = {"NIST-800-53": "partial"}
        fleet_db.store_scan("fw01", [], metadata=meta, compliance=compliance)

        scans = fleet_db.get_scans(device_name="fw01")
        assert json.loads(scans[0].metadata_json) == meta
        assert json.loads(scans[0].compliance_json) == compliance

    def test_pagination(self, fleet_db):
        for i in range(10):
            fleet_db.store_scan("fw01", [{"severity": "low", "rule_id": f"R{i}"}])

        page1 = fleet_db.get_scans(limit=3, offset=0)
        page2 = fleet_db.get_scans(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].id != page2[0].id

    def test_trend_calculation(self, fleet_db):
        # First scan: 5 findings
        fleet_db.store_scan("fw01", [{"severity": "high", "rule_id": f"R{i}"} for i in range(5)])
        # Second scan: 3 findings (improving)
        fleet_db.store_scan("fw01", [{"severity": "high", "rule_id": f"R{i}"} for i in range(3)])

        summaries = fleet_db.get_device_summary()
        fw01 = [s for s in summaries if s.device_name == "fw01"][0]
        assert fw01.trend == "improving"
