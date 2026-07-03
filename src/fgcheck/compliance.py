"""Compliance mapping for fortigatecheck.

Maps security rules to compliance frameworks:
- NIST SP 800-53 Rev 5
- CIS FortiGate Benchmark
- Fortinet Best Practices
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ComplianceControl:
    """A single compliance control."""
    framework: str
    control_id: str
    title: str
    description: str


@dataclass
class ComplianceMapping:
    """Maps a rule ID to one or more compliance controls."""
    rule_id: str
    controls: List[ComplianceControl] = field(default_factory=list)


# ─── Compliance Mappings ───

COMPLIANCE_MAP: Dict[str, List[ComplianceControl]] = {
    # ── NIST SP 800-53 Rev 5 ──
    "FGT-ADMIN-EDGE-TELNET": [
        ComplianceControl("NIST-800-53", "AC-17", "Remote Access", "Ensure remote access is protected"),
        ComplianceControl("NIST-800-53", "SC-8", "Transmission Confidentiality", "Protect confidentiality of transmitted information"),
        ComplianceControl("CIS-FortiGate", "1.1", "Disable Telnet", "Disable Telnet management access"),
        ComplianceControl("Fortinet-BP", "BP-ADMIN-01", "No Telnet", "Never use Telnet for management"),
    ],
    "FGT-ADMIN-EDGE-HTTP": [
        ComplianceControl("NIST-800-53", "AC-17", "Remote Access", "Ensure remote access is protected"),
        ComplianceControl("NIST-800-53", "SC-8", "Transmission Confidentiality", "Protect confidentiality of transmitted information"),
        ComplianceControl("CIS-FortiGate", "1.2", "Disable HTTP", "Disable HTTP management access"),
        ComplianceControl("Fortinet-BP", "BP-ADMIN-02", "No HTTP", "Never use HTTP for management"),
    ],
    "FGT-ADMIN-EDGE-SSH": [
        ComplianceControl("NIST-800-53", "AC-17", "Remote Access", "Ensure remote access is protected"),
        ComplianceControl("CIS-FortiGate", "1.3", "Restrict SSH", "Restrict SSH to trusted hosts"),
    ],
    "FGT-ADMIN-EDGE-HTTPS": [
        ComplianceControl("NIST-800-53", "AC-17", "Remote Access", "Ensure remote access is protected"),
    ],
    "FGT-ADMIN-NO-TRUSTED-HOSTS": [
        ComplianceControl("NIST-800-53", "AC-3", "Access Enforcement", "Enforce approved authorizations"),
        ComplianceControl("NIST-800-53", "AC-4", "Information Flow Enforcement", "Control information flow"),
        ComplianceControl("CIS-FortiGate", "1.4", "Configure Trusted Hosts", "Configure trusted hosts for admin access"),
    ],
    "FGT-ADMIN-SUPER-NO-2FA": [
        ComplianceControl("NIST-800-53", "IA-2", "Identification and Authentication", "Use multi-factor authentication"),
        ComplianceControl("NIST-800-53", "IA-2(1)", "MFA for Privileged Access", "Multi-factor for privileged accounts"),
        ComplianceControl("CIS-FortiGate", "1.5", "Enable 2FA", "Enable two-factor authentication"),
    ],
    "FGT-ADMIN-NO-2FA": [
        ComplianceControl("NIST-800-53", "IA-2", "Identification and Authentication", "Use multi-factor authentication"),
        ComplianceControl("CIS-FortiGate", "1.5", "Enable 2FA", "Enable two-factor authentication"),
    ],
    "FGT-ADMIN-LOCKOUT-NO-TRIES": [
        ComplianceControl("NIST-800-53", "AC-7", "Unsuccessful Logon Attempts", "Limit consecutive failed logins"),
        ComplianceControl("CIS-FortiGate", "1.6", "Configure Lockout", "Configure admin lockout threshold"),
    ],
    "FGT-POLICY-LOG-001": [
        ComplianceControl("NIST-800-53", "AU-2", "Event Logging", "Log security-relevant events"),
        ComplianceControl("NIST-800-53", "AU-3", "Content of Audit Records", "Log sufficient detail"),
        ComplianceControl("CIS-FortiGate", "3.1", "Enable Logging", "Enable logging on all policies"),
    ],
    "FGT-LOCALIN-NO-PROTECTION": [
        ComplianceControl("NIST-800-53", "SC-7", "Boundary Protection", "Protect system boundary"),
        ComplianceControl("CIS-FortiGate", "2.1", "Configure Local-In", "Configure local-in policies"),
    ],
    "FGT-SSLVPN-MIN-TLS": [
        ComplianceControl("NIST-800-53", "SC-8", "Transmission Confidentiality", "Use FIPS validated cryptographic modules"),
        ComplianceControl("NIST-800-53", "SC-13", "Cryptographic Protection", "Use approved cryptographic methods"),
        ComplianceControl("CIS-FortiGate", "4.1", "Set Minimum TLS", "Set minimum TLS version for SSL VPN"),
    ],
    "FGT-SSH-WEAK-CIPHERS": [
        ComplianceControl("NIST-800-53", "SC-8", "Transmission Confidentiality", "Protect confidentiality of transmitted information"),
        ComplianceControl("NIST-800-53", "SC-13", "Cryptographic Protection", "Use approved cryptographic methods"),
        ComplianceControl("CIS-FortiGate", "1.7", "Strong SSH Ciphers", "Use strong SSH algorithms"),
    ],
    "FGT-IPSEC-WEAK-DH": [
        ComplianceControl("NIST-800-53", "SC-13", "Cryptographic Protection", "Use approved cryptographic methods"),
    ],
    "FGT-VPN-WEAK-ENCRYPTION": [
        ComplianceControl("NIST-800-53", "SC-13", "Cryptographic Protection", "Use approved cryptographic methods"),
    ],
    "FGT-SSL-INSPECTION-DISABLED": [
        ComplianceControl("NIST-800-53", "SC-7", "Boundary Protection", "Inspect encrypted traffic"),
        ComplianceControl("NIST-800-53", "SI-4", "Information System Monitoring", "Monitor for attacks and indicators"),
        ComplianceControl("Fortinet-BP", "BP-SSL-01", "Enable SSL Inspection", "Enable SSL deep inspection"),
    ],
    "FGT-NO-REMOTE-LOGGING": [
        ComplianceControl("NIST-800-53", "AU-6", "Audit Record Review", "Centralize log collection"),
    ],
    "FGT-FIRMWARE-OUTDATED": [
        ComplianceControl("NIST-800-53", "SI-2", "Flaw Remediation", "Repair security-relevant flaws"),
        ComplianceControl("CIS-FortiGate", "1.8", "Update Firmware", "Keep firmware up to date"),
    ],
    "FGT-CERT-EXPIRING": [
        ComplianceControl("NIST-800-53", "SC-17", "PKI Certificates", "Issue certificates from trusted CA"),
    ],
    "FGT-SNMP-WEAK-COMMUNITY": [
        ComplianceControl("NIST-800-53", "IA-5", "Authenticator Management", "Manage credentials securely"),
    ],
    "FGT-ADMIN-WEAK-PASSWORD-POLICY": [
        ComplianceControl("NIST-800-53", "IA-5", "Authenticator Management", "Enforce password complexity"),
    ],
    "FGT-HA-NO-HEARTBEAT": [
        ComplianceControl("NIST-800-53", "SC-7", "Boundary Protection", "Ensure availability"),
    ],
    "FGT-WIRELESS-OPEN-SSID": [
        ComplianceControl("NIST-800-53", "SC-8", "Transmission Confidentiality", "Protect wireless transmissions"),
    ],
    "FGT-DNS-SERVER-ALLOW-TCP": [
        ComplianceControl("NIST-800-53", "SC-7", "Boundary Protection", "Restrict DNS zone transfers"),
    ],
    "FGT-FIREWALL-ANY-ANY": [
        ComplianceControl("Fortinet-BP", "BP-POLICY-01", "No Any-Any Policies", "Avoid overly permissive policies"),
    ],
}


def get_compliance_for_rule(rule_id: str) -> List[ComplianceControl]:
    """Get compliance controls for a specific rule."""
    return COMPLIANCE_MAP.get(rule_id, [])


def get_compliance_for_framework(framework: str) -> Dict[str, List[ComplianceControl]]:
    """Get all rules mapped to a specific framework."""
    result = {}
    for rule_id, controls in COMPLIANCE_MAP.items():
        framework_controls = [c for c in controls if c.framework == framework]
        if framework_controls:
            result[rule_id] = framework_controls
    return result


def get_frameworks() -> List[str]:
    """Get all available compliance frameworks."""
    frameworks = set()
    for controls in COMPLIANCE_MAP.values():
        for c in controls:
            frameworks.add(c.framework)
    return sorted(frameworks)


def render_compliance_report(rule_id: str) -> str:
    """Render a human-readable compliance report for a rule."""
    controls = get_compliance_for_rule(rule_id)
    if not controls:
        return f"No compliance mapping found for {rule_id}"

    lines = [f"Compliance mapping for {rule_id}:"]
    for c in controls:
        lines.append(f"  [{c.framework}] {c.control_id}: {c.title}")
        lines.append(f"    {c.description}")
    return "\n".join(lines)


def compliance_main(argv: list[str]) -> None:
    """Handle compliance subcommand."""
    import argparse

    ap = argparse.ArgumentParser(prog="fgcheck compliance")
    sub = ap.add_subparsers(dest="compliance_cmd")
    sub.add_parser("frameworks", help="List available compliance frameworks")
    rp = sub.add_parser("rule", help="Show compliance mapping for a rule")
    rp.add_argument("rule_id", help="Rule ID to check")
    fp = sub.add_parser("framework", help="Show all rules for a framework")
    fp.add_argument("framework", help="Framework name")
    args = ap.parse_args(argv)

    if args.compliance_cmd == "frameworks":
        for fw in get_frameworks():
            print(fw)
    elif args.compliance_cmd == "rule":
        controls = get_compliance_for_rule(args.rule_id)
        if not controls:
            print(f"No compliance mapping found for {args.rule_id}")
            return
        print(render_compliance_report(args.rule_id))
    elif args.compliance_cmd == "framework":
        result = get_compliance_for_framework(args.framework)
        if not result:
            print(f"No rules mapped to framework {args.framework}")
            return
        for rule_id, controls in sorted(result.items()):
            print(f"{rule_id}:")
            for c in controls:
                print(f"  {c.control_id}: {c.title}")
    else:
        ap.print_help()
