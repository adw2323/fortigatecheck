"""Tests for compliance mapping."""
from __future__ import annotations

import pytest
from fgcheck.compliance import (
    get_compliance_for_rule,
    get_compliance_for_framework,
    get_frameworks,
    render_compliance_report,
)


class TestCompliance:
    def test_get_compliance_for_rule(self):
        controls = get_compliance_for_rule("FGT-ADMIN-EDGE-TELNET")
        assert len(controls) >= 2
        frameworks = {c.framework for c in controls}
        assert "NIST-800-53" in frameworks
        assert "CIS-FortiGate" in frameworks

    def test_get_compliance_for_unknown_rule(self):
        controls = get_compliance_for_rule("FGT-NONEXISTENT")
        assert len(controls) == 0

    def test_get_compliance_for_framework(self):
        result = get_compliance_for_framework("NIST-800-53")
        assert len(result) > 0
        assert "FGT-ADMIN-EDGE-TELNET" in result

    def test_get_frameworks(self):
        frameworks = get_frameworks()
        assert "NIST-800-53" in frameworks
        assert "CIS-FortiGate" in frameworks
        assert "Fortinet-BP" in frameworks

    def test_render_compliance_report(self):
        report = render_compliance_report("FGT-ADMIN-EDGE-TELNET")
        assert "FGT-ADMIN-EDGE-TELNET" in report
        assert "NIST-800-53" in report
        assert "CIS-FortiGate" in report

    def test_render_compliance_report_unknown(self):
        report = render_compliance_report("FGT-NONEXISTENT")
        assert "No compliance mapping" in report

    def test_2fa_compliance(self):
        controls = get_compliance_for_rule("FGT-ADMIN-SUPER-NO-2FA")
        assert any("IA-2" in c.control_id for c in controls)

    def test_ssl_inspection_compliance(self):
        controls = get_compliance_for_rule("FGT-SSL-INSPECTION-DISABLED")
        assert len(controls) >= 2
        frameworks = {c.framework for c in controls}
        assert "NIST-800-53" in frameworks

    def test_wireless_compliance(self):
        controls = get_compliance_for_rule("FGT-WIRELESS-OPEN-SSID")
        assert len(controls) >= 1
