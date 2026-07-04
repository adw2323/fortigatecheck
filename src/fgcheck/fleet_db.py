"""Fleet management database for fortigatecheck.

Stores scan results in SQLite for historical tracking and fleet-wide analysis.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".fgcheck" / "fleet.db"


@dataclass
class ScanResult:
    """A stored scan result."""
    id: str
    device_name: str
    config_file: str
    scan_date: str
    fortios_version: str | None
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings_json: str  # JSON array of findings
    metadata_json: str  # JSON dict of additional metadata
    compliance_json: str  # JSON dict of compliance status


@dataclass
class DeviceSummary:
    """Summary for a device across scans."""
    device_name: str
    scan_count: int
    latest_scan: str
    latest_findings: int
    latest_critical: int
    trend: str  # "improving", "stable", "degrading"


class FleetDB:
    """Fleet management database."""

    def __init__(self, db_path: Path | None = None):
        if db_path is not None and not isinstance(db_path, Path):
            db_path = Path(db_path)
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                config_file TEXT,
                scan_date TEXT NOT NULL,
                fortios_version TEXT,
                finding_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                findings_json TEXT DEFAULT '[]',
                metadata_json TEXT DEFAULT '{}',
                compliance_json TEXT DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_scans_device ON scans(device_name);
            CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date);
            CREATE INDEX IF NOT EXISTS idx_scans_device_date ON scans(device_name, scan_date);
        """)
        self.conn.commit()

    def store_scan(
        self,
        device_name: str,
        findings: list[dict[str, Any]],
        config_file: str = "",
        fortios_version: str | None = None,
        metadata: dict[str, Any] | None = None,
        compliance: dict[str, Any] | None = None,
    ) -> str:
        """Store a scan result and return the scan ID."""
        scan_id = str(uuid.uuid4())[:12]
        now = datetime.utcnow().isoformat()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        self.conn.execute(
            """INSERT INTO scans
            (id, device_name, config_file, scan_date, fortios_version,
             finding_count, critical_count, high_count, medium_count, low_count,
             findings_json, metadata_json, compliance_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                device_name,
                config_file,
                now,
                fortios_version,
                len(findings),
                severity_counts["critical"],
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
                json.dumps(findings),
                json.dumps(metadata or {}),
                json.dumps(compliance or {}),
            ),
        )
        self.conn.commit()
        return scan_id

    def get_scans(
        self,
        device_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanResult]:
        """Get scan results with optional device filter."""
        if device_name:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE device_name = ? ORDER BY scan_date DESC LIMIT ? OFFSET ?",
                (device_name, limit, offset),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY scan_date DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def get_device_summary(self) -> list[DeviceSummary]:
        """Get summary for all devices."""
        rows = self.conn.execute("""
            SELECT
                device_name,
                COUNT(*) as scan_count,
                MAX(scan_date) as latest_scan,
                (SELECT finding_count FROM scans s2
                 WHERE s2.device_name = s1.device_name
                 ORDER BY scan_date DESC LIMIT 1) as latest_findings,
                (SELECT critical_count FROM scans s2
                 WHERE s2.device_name = s1.device_name
                 ORDER BY scan_date DESC LIMIT 1) as latest_critical
            FROM scans s1
            GROUP BY device_name
            ORDER BY latest_scan DESC
        """).fetchall()

        summaries = []
        for r in rows:
            trend = self._calc_trend(r["device_name"])
            summaries.append(DeviceSummary(
                device_name=r["device_name"],
                scan_count=r["scan_count"],
                latest_scan=r["latest_scan"],
                latest_findings=r["latest_findings"] or 0,
                latest_critical=r["latest_critical"] or 0,
                trend=trend,
            ))
        return summaries

    def get_fleet_stats(self) -> dict[str, Any]:
        """Get fleet-wide statistics."""
        row = self.conn.execute("""
            SELECT
                COUNT(DISTINCT device_name) as device_count,
                COUNT(*) as total_scans,
                SUM(finding_count) as total_findings,
                SUM(critical_count) as total_critical,
                SUM(high_count) as total_high,
                AVG(finding_count) as avg_findings,
                MAX(scan_date) as latest_scan
            FROM scans
        """).fetchone()

        return {
            "device_count": row["device_count"] or 0,
            "total_scans": row["total_scans"] or 0,
            "total_findings": row["total_findings"] or 0,
            "total_critical": row["total_critical"] or 0,
            "total_high": row["total_high"] or 0,
            "avg_findings": round(row["avg_findings"] or 0, 1),
            "latest_scan": row["latest_scan"],
        }

    def get_severity_trend(self, device_name: str | None = None, days: int = 30) -> list[dict[str, Any]]:
        """Get severity trend over time."""
        query = """
            SELECT
                DATE(scan_date) as date,
                SUM(critical_count) as critical,
                SUM(high_count) as high,
                SUM(medium_count) as medium,
                SUM(low_count) as low,
                SUM(finding_count) as total
            FROM scans
            WHERE scan_date >= datetime('now', ?)
        """
        params: list = [f"-{days} days"]
        if device_name:
            query += " AND device_name = ?"
            params.append(device_name)
        query += " GROUP BY DATE(scan_date) ORDER BY date"

        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_worst_devices(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get devices with most critical findings."""
        rows = self.conn.execute("""
            SELECT
                device_name,
                critical_count,
                high_count,
                finding_count,
                scan_date
            FROM scans
            WHERE (device_name, scan_date) IN (
                SELECT device_name, MAX(scan_date) FROM scans GROUP BY device_name
            )
            ORDER BY critical_count DESC, high_count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def delete_device(self, device_name: str) -> int:
        """Delete all scans for a device."""
        cursor = self.conn.execute("DELETE FROM scans WHERE device_name = ?", (device_name,))
        self.conn.commit()
        return cursor.rowcount

    def _calc_trend(self, device_name: str) -> str:
        """Calculate if findings are improving, stable, or degrading."""
        rows = self.conn.execute(
            "SELECT finding_count FROM scans WHERE device_name = ? ORDER BY scan_date DESC LIMIT 3",
            (device_name,),
        ).fetchall()
        if len(rows) < 2:
            return "stable"
        recent = rows[0]["finding_count"]
        older = rows[1]["finding_count"]
        if recent < older:
            return "improving"
        elif recent > older:
            return "degrading"
        return "stable"

    def _row_to_result(self, row: sqlite3.Row) -> ScanResult:
        return ScanResult(
            id=row["id"],
            device_name=row["device_name"],
            config_file=row["config_file"],
            scan_date=row["scan_date"],
            fortios_version=row["fortios_version"],
            finding_count=row["finding_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            findings_json=row["findings_json"],
            metadata_json=row["metadata_json"],
            compliance_json=row["compliance_json"],
        )

    def close(self):
        self.conn.close()
