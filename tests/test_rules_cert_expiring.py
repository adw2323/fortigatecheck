"""Tests for FGT-CERT-EXPIRING rule."""
import json
from pathlib import Path

from fgcheck.parse import parse_fortios_text
from fgcheck.rules import run


def _write_schema(base_dir: Path, version: str, payload: dict) -> None:
    out_dir = base_dir / "docs" / "derived" / "schema" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "schema.json").write_text(json.dumps(payload), encoding="utf-8")


_SCHEMA_EMPTY = {"tables": {}}

# Pre-generated PEM certificates with known expiry dates.
# Expired cert (expired ~10 days ago on 2026-07-13).
PEM_EXPIRED = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICsDCCAZigAwIBAgIUJOV6vFYgSPuYxSDeuho8NSf/Nf0wDQYJKoZIhvcNAQEL\n"
    "BQAwEjEQMA4GA1UEAwwHZXhwaXJlZDAeFw0yNTA1MjkwMzMwNTNaFw0yNjA2MjMw\n"
    "MzMwNTNaMBIxEDAOBgNVBAMMB2V4cGlyZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
    "DwAwggEKAoIBAQCha3hfGfcdcNtXidpcUZBrCv4BB9IuMkDOPfxHNDhVWcyKLRcT\n"
    "+p5O/mbgg6NjwTlCb9L//rsjaomIPtPYE/bls6ywFdSBH0UOT15xGY6XFyLM2jMI\n"
    "WgY0lMbzi79p0wsbaWfnn3QI2OL3oVuIkpBY80iacBDlzezJs/Iukcb3jY6vzc8g\n"
    "TpI9vvA5ACTwz8fhcc7R6L8c87vVOebVpxo12vY34n6bApFyv3sUJt0DQ7qS1d4s\n"
    "NXm6slITbdbKuXFbkqsDaZ8fIQfqLvvDqBOQ8wnoetTqLCGQ1V48S65hpXNNU8YH\n"
    "AFH0vsHWIz+2EqHKKaKjEZqDwiexR6dgKncJAgMBAAEwDQYJKoZIhvcNAQELBQAD\n"
    "ggEBAG9ECA/lv1Z4+L7rk84UnR2MnQoQEvtwWSbEA5m+pxdHxSO+HlsOQyEwFv58\n"
    "0Wt5bNEGQxZjm074PJTh5vlAn4/la6CJ7LROw7s74au5m96qLHmcX76jpn3G5EBz\n"
    "VyFS9R014ZwJI9IDJyN8uyMrYglPhG0o8Nc2XYtnLaM3bQWhAIEFawW7Y4Hofrnr\n"
    "EhGB6A+bKH+v+6A7ghYI3PIFbG6EQWaPrMlu4W7EsU2yFsAfS8LCe4ykMdqcxXB2\n"
    "cuiN/f9/Ua+wc10bcfd9LiCDuhH6d0x8el2gdzqGFXb9QcLH/VHH0bOMz8C0/ZKL\n"
    "zRrSJecIeHB57mIj9bTUCdLy9eA=\n"
    "-----END CERTIFICATE-----"
)

# Expiring soon cert (expires in 5 days).
PEM_EXPIRING = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICsTCCAZmgAwIBAgIUQsGWP9A7JvSv2iuxd+Vp9dtWJm4wDQYJKoZIhvcNAQEL\n"
    "BQAwEjEQMA4GA1UEAwwHZXhwaXJlZDAeFw0yNTA3MDgwMzMwNTNaFw0yNjA3MDgw\n"
    "MzMwNTNaMBMxETAPBgNVBAMMCGV4cGlyaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
    "AQ8AMIIBCgKCAQEAoWt4Xxn3HXDbV4naXFGQawr+AQfSLjJAzj38RzQ4VVnMii0X\n"
    "E/qeTv5m4IOjY8E5Qm/S//67I2qJiD7T2BP25bOssBXUgR9FDk9ecRmOlxcizNoz\n"
    "CFoGNJTG84u/adMLG2ln5590CNji96FbiJKQWPNImnAQ5c3sybPyLpHG942Or83P\n"
    "IE6SPb7wOQAk8M/H4XHO0ei/HPO71Tnm1acaNdr2N+J+mwKRcr97FCbdA0O6ktXe\n"
    "LDV5urJSE23WyrlxW5KrA2mfHyEH6i77w6gTkPMJ6HrU6iwhkNVePEuuYaVzTVPG\n"
    "BwBR9L7B1iM/thKhyimioxGag8InsUenYCp3CQIDAQABMA0GCSqGSIb3DQEBCwUA\n"
    "A4IBAQBOClSKFd1utw8XU18qw8nJZbNf853rK8yWTw8gI/0hI9EunXd8wXKAm/zg\n"
    "MxGpNU51ckOgszEiN9B/UI7f7m5M92wz21pssaXmTkoLP1wFuLSCD/AMpehQAS5u\n"
    "BHfhlj9GMo8ZGVM+kheSStyY92XfRQ3r6lwXpjH1VzWBuXiAszuC3JTj7x1Gamzd\n"
    "O8SfBKx7e5bkt5B4gE0KUv2tO0FDmMuweBUsn1VyP/o9pfs7wCBBK0MAFS9zIc7M\n"
    "HJCQ9miV7/kWB2Sx4rAz2jHSngpYPX7T3Rr2j9aBtTvDIi4nUzrrygKx+SE1NJTH\n"
    "rmwaVAftyOKpRJKVrttjf4ng+sNR\n"
    "-----END CERTIFICATE-----"
)

# Valid cert (expires in 365 days).
PEM_VALID = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICrjCCAZagAwIBAgIUTmYVi5gZonu7obmCkaGPpXM6jYMwDQYJKoZIhvcNAQEL\n"
    "BQAwEjEQMA4GA1UEAwwHZXhwaXJlZDAeFw0yNjA3MDMwMzMwNTNaFw0yNzA3MDMw\n"
    "MzMwNTNaMBAxDjAMBgNVBAMMBXZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
    "MIIBCgKCAQEAoWt4Xxn3HXDbV4naXFGQawr+AQfSLjJAzj38RzQ4VVnMii0XE/qe\n"
    "Tv5m4IOjY8E5Qm/S//67I2qJiD7T2BP25bOssBXUgR9FDk9ecRmOlxcizNozCFoG\n"
    "NJTG84u/adMLG2ln5590CNji96FbiJKQWPNImnAQ5c3sybPyLpHG942Or83PIE6S\n"
    "Pb7wOQAk8M/H4XHO0ei/HPO71Tnm1acaNdr2N+J+mwKRcr97FCbdA0O6ktXeLDV5\n"
    "urJSE23WyrlxW5KrA2mfHyEH6i77w6gTkPMJ6HrU6iwhkNVePEuuYaVzTVPGBwBR\n"
    "9L7B1iM/thKhyimioxGag8InsUenYCp3CQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB\n"
    "AQA70Fbm6s3oP5V5CEykPWa/JWlCXTGLaksI+ZAiLBpcBREniFbycKZhCTfANVhO\n"
    "k67k832z1a2Z8guXvG8/XLRBv0fgLwUTdzbawqdYmEMqBtl6AGW1UgSPjH9TxcCl\n"
    "Jse+QLsYOoAgKNfDvtFhuwHS9Cd3ic84pMbi9yCgITAqvY/N013Jx26WczNr9RBR\n"
    "kLOuK3wC1tgoimgRJmoE9m5mUFWDa59FMhq9gUsEJ1bktLD+bt8qLZnbJ3K7flba\n"
    "mXFVfDv0MO1JXzNiUv7pYCF1T7YIMN9r9eK+J7AcE1AxguXB8XVOrsgSdL0zw1Da\n"
    "jVKwRB7KbJf3DfGTxBTbzdE7\n"
    "-----END CERTIFICATE-----"
)


class TestCertExpiredDetected:
    """Test that expired certificates are flagged."""

    def test_expired_cert_detected(self, tmp_path: Path):
        """An expired certificate should produce a finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "expired-cert"
        set certificate "{PEM_EXPIRED}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-CERT-EXPIRING"
        assert f.severity == "high"
        assert f.confidence == "likely"
        assert "expired" in f.message.lower()
        assert "expired-cert" in f.message
        assert f.evidence  # must have evidence

    def test_expiring_cert_detected(self, tmp_path: Path):
        """A certificate expiring within 30 days should produce a finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "expiring-cert"
        set certificate "{PEM_EXPIRING}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-CERT-EXPIRING"
        assert f.severity == "high"
        assert "expires in" in f.message.lower()
        assert "expiring-cert" in f.message

    def test_multiple_certs_one_expired(self, tmp_path: Path):
        """Multiple certs where only one is expired should produce one finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "valid-cert"
        set certificate "{PEM_VALID}"
        set source user
    next
    edit "expired-cert"
        set certificate "{PEM_EXPIRED}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "expired-cert" in findings[0].message


class TestCertValid:
    """Test that valid certificates produce no findings."""

    def test_valid_cert_no_finding(self, tmp_path: Path):
        """A valid certificate (not expiring soon) should produce no findings."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "valid-cert"
        set certificate "{PEM_VALID}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_multiple_valid_certs_no_finding(self, tmp_path: Path):
        """Multiple valid certificates should produce no findings."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "cert-one"
        set certificate "{PEM_VALID}"
        set source user
    next
    edit "cert-two"
        set certificate "{PEM_VALID}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestCertNoCertificate:
    """Test behavior when no certificate config exists."""

    def test_no_cert_table_no_finding(self, tmp_path: Path):
        """No certificate config -> no finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = """\
config system global
    set hostname fw01
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert findings == []

    def test_cert_no_certificate_field_no_finding(self, tmp_path: Path):
        """Certificate entry with no certificate field -> no finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = """\
config certificate local
    edit "empty-cert"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert findings == []


class TestCertRedacted:
    """Test behavior with redacted/placeholder certificate values."""

    def test_redacted_cert_detected(self, tmp_path: Path):
        """A certificate with a redacted placeholder should produce a finding."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = """\
config certificate local
    edit "redacted-cert"
        set certificate "***"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "FGT-CERT-EXPIRING"
        assert "redacted" in f.message.lower() or "placeholder" in f.message.lower()
        assert f.confidence == "heuristic"


class TestCertVDOMScope:
    """Test certificate detection within VDOM scope."""

    def test_vdom_scoped_expired_cert(self, tmp_path: Path):
        """Expired cert in VDOM root should be detected."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config vdom
    edit root
        config certificate local
            edit "vdom-expired"
                set certificate "{PEM_EXPIRED}"
                set source user
            next
        end
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        assert findings[0].vdom == "root"
        assert "vdom-expired" in findings[0].message


class TestCertEvidence:
    """Test that evidence is correctly captured."""

    def test_evidence_contains_cert_line(self, tmp_path: Path):
        """Evidence should reference the certificate set line."""
        _write_schema(tmp_path, "7.6", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "expired-cert"
        set certificate "{PEM_EXPIRED}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.6",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
        ev = findings[0].evidence
        assert len(ev) >= 1
        assert ev[0].file_id == "inline.conf"
        # Evidence should reference the certificate line
        assert any("certificate" in line.lower() for line in ev[0].raw_lines)


class TestCertVersionCompatibility:
    """Test that the rule works across FortiOS versions."""

    def test_7_4_expired_cert(self, tmp_path: Path):
        """Expired cert detected on FortiOS 7.4."""
        _write_schema(tmp_path, "7.4", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "old-expired"
        set certificate "{PEM_EXPIRED}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="7.4",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1

    def test_8_0_expired_cert(self, tmp_path: Path):
        """Expired cert detected on FortiOS 8.0."""
        _write_schema(tmp_path, "8.0", _SCHEMA_EMPTY)
        conf = f"""\
config certificate local
    edit "new-expired"
        set certificate "{PEM_EXPIRED}"
        set source user
    next
end"""
        model, warnings = parse_fortios_text(conf, file_id="inline.conf")
        assert warnings == []
        findings = run(
            model,
            rule_files=["rules/builtin/FGT-CERT-EXPIRING.yaml"],
            fortios_version="8.0",
            schema_base_dir=tmp_path,
        )
        assert len(findings) == 1
