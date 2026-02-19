import importlib.util
import json
from pathlib import Path

import pytest
import yaml


def _load_build_corpus_module(repo_root: Path):
    mod_path = repo_root / "scripts" / "build_corpus.py"
    spec = importlib.util.spec_from_file_location("build_corpus_script", mod_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_sources(repo_root: Path, payload: dict) -> None:
    docs = repo_root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "sources.yaml").write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_build_corpus_ingests_schema_and_kev_from_official_sources(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())

    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4", "7.6"]},
            "allowed_domains": ["docs.fortinet.com", "cisa.gov"],
            "sources": {
                "schema": [
                    {
                        "id": "schema",
                        "versions": {
                            "7.4": "https://docs.fortinet.com/schema/7.4.json",
                            "7.6": "https://docs.fortinet.com/schema/7.6.json",
                        },
                    }
                ],
                "kev": [
                    {
                        "id": "kev",
                        "url": "https://cisa.gov/known_exploited_vulnerabilities.json",
                    }
                ],
            },
        },
    )

    fetch_payloads = {
        "https://docs.fortinet.com/schema/7.4.json": json.dumps(
            {
                "tables": {
                    "system/interface": {
                        "fields": {
                            "allowaccess": {"allowed_values": ["https", "ssh"]},
                        }
                    }
                }
            }
        ),
        "https://docs.fortinet.com/schema/7.6.json": json.dumps(
            {
                "tables": {
                    "firewall policy": {
                        "fields": {
                            "action": {"allowed_values": ["accept", "deny"]},
                        }
                    }
                }
            }
        ),
        "https://cisa.gov/known_exploited_vulnerabilities.json": json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-0001",
                        "vendorProject": "Fortinet",
                        "product": "FortiOS",
                        "dateAdded": "2024-01-01",
                    }
                ]
            }
        ),
    }

    mod.build_corpus(repo_root=tmp_path, fetcher=lambda url: fetch_payloads[url])

    schema_74 = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.4" / "schema.json").read_text(encoding="utf-8"))
    schema_76 = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.6" / "schema.json").read_text(encoding="utf-8"))
    cves = json.loads((tmp_path / "docs" / "derived" / "cves" / "cves.json").read_text(encoding="utf-8"))

    assert "system interface" in schema_74["tables"]
    assert "allowaccess" in schema_74["tables"]["system interface"]["fields"]
    assert "firewall policy" in schema_76["tables"]
    assert cves["entries"][0]["cve_id"] == "CVE-2024-0001"
    assert cves["entries"][0]["vendor"] == "Fortinet"


def test_build_corpus_rejects_disallowed_source_domain(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())

    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4"]},
            "allowed_domains": ["docs.fortinet.com"],
            "sources": {
                "schema": [
                    {
                        "id": "schema",
                        "versions": {
                            "7.4": "https://example.com/schema/7.4.json",
                        },
                    }
                ]
            },
        },
    )

    with pytest.raises(ValueError, match="not in allowed_domains"):
        mod.build_corpus(repo_root=tmp_path, fetcher=lambda _: "{}")


def test_build_corpus_extracts_tables_from_cli_reference_html(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())

    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4"]},
            "allowed_domains": ["docs.fortinet.com"],
            "sources": {
                "schema": [
                    {
                        "id": "fortinet_cli",
                        "versions": {
                            "7.4": "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference",
                        },
                    }
                ]
            },
        },
    )

    html_payload = """
<!DOCTYPE html>
<html>
  <body>
    <a class="toc" href="/document/fortigate/7.4.11/cli-reference/306021697/config-system-interface">
      config system interface
    </a>
    <a class="toc" href="/document/fortigate/7.4.11/cli-reference/333620/config-firewall-policy">
      config firewall policy
    </a>
  </body>
</html>
""".strip()

    mod.build_corpus(repo_root=tmp_path, fetcher=lambda _: html_payload)

    schema = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.4" / "schema.json").read_text(encoding="utf-8"))
    assert "system interface" in schema["tables"]
    assert "firewall policy" in schema["tables"]
    assert schema["coverage"] == "table_only"
    assert schema["tables"]["system interface"]["source_url"].startswith("https://docs.fortinet.com/document/fortigate/")


def test_build_corpus_enriches_priority_table_fields_from_table_page_html(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())

    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4"]},
            "allowed_domains": ["docs.fortinet.com"],
            "sources": {
                "schema": [
                    {
                        "id": "fortinet_cli",
                        "versions": {
                            "7.4": "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference",
                        },
                    }
                ]
            },
        },
    )

    toc_html = """
<!DOCTYPE html>
<html>
  <body>
    <a class="toc" href="/document/fortigate/7.4.11/cli-reference/317104469/config-system-interface">
      config system interface
    </a>
  </body>
</html>
""".strip()
    table_html = """
<!DOCTYPE html>
<html>
  <body>
    <pre>config system interface
    edit &lt;name&gt;
        set allowaccess {option1}, {option2}, ...
        set mode [static|dhcp]
        set status [up|down]
    next
end
    </pre>
  </body>
</html>
""".strip()

    payloads = {
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference": toc_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/317104469/config-system-interface": table_html,
    }

    mod.build_corpus(repo_root=tmp_path, fetcher=lambda url: payloads[url])

    schema = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.4" / "schema.json").read_text(encoding="utf-8"))
    fields = schema["tables"]["system interface"]["fields"]
    assert "allowaccess" in fields
    assert fields["mode"]["allowed_values"] == ["static", "dhcp"]
    assert fields["status"]["allowed_values"] == ["up", "down"]


def test_build_corpus_enriches_extended_high_impact_tables(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())
    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4"]},
            "allowed_domains": ["docs.fortinet.com"],
            "sources": {
                "schema": [
                    {
                        "id": "fortinet_cli",
                        "versions": {
                            "7.4": "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference",
                        },
                    }
                ]
            },
        },
    )

    toc_html = """
<!DOCTYPE html>
<html><body>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/11/config-system-admin">config system admin</a>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/22/config-vpn-ssl-settings">config vpn ssl settings</a>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/33/config-firewall-local-in-policy">config firewall local-in-policy</a>
</body></html>
""".strip()
    admin_html = """
<!DOCTYPE html><html><body><pre>config system admin
  edit &lt;name&gt;
    set accprofile {string}
    set trusthost1 {ipv4-address}
  next
end</pre></body></html>
""".strip()
    ssl_html = """
<!DOCTYPE html><html><body><pre>config vpn ssl settings
  set ssl-min-proto-ver [tls1-0|tls1-1|tls1-2|tls1-3]
  set source-interface {string}
end</pre></body></html>
""".strip()
    lip_html = """
<!DOCTYPE html><html><body><pre>config firewall local-in-policy
  edit &lt;id&gt;
    set action [accept|deny]
    set intf {string}
  next
end</pre></body></html>
""".strip()

    payloads = {
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference": toc_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/11/config-system-admin": admin_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/22/config-vpn-ssl-settings": ssl_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/33/config-firewall-local-in-policy": lip_html,
    }

    mod.build_corpus(repo_root=tmp_path, fetcher=lambda url: payloads[url])
    schema = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.4" / "schema.json").read_text(encoding="utf-8"))

    assert "accprofile" in schema["tables"]["system admin"]["fields"]
    assert "ssl-min-proto-ver" in schema["tables"]["vpn ssl settings"]["fields"]
    assert schema["tables"]["vpn ssl settings"]["fields"]["ssl-min-proto-ver"]["allowed_values"] == ["tls1-0", "tls1-1", "tls1-2", "tls1-3"]
    assert schema["tables"]["firewall local-in-policy"]["fields"]["action"]["allowed_values"] == ["accept", "deny"]


def test_build_corpus_enriches_ipsec_and_remote_logging_tables(tmp_path: Path):
    mod = _load_build_corpus_module(Path(".").resolve())
    _write_sources(
        tmp_path,
        {
            "fortios_versions": {"first_class": ["7.4"]},
            "allowed_domains": ["docs.fortinet.com"],
            "sources": {
                "schema": [
                    {
                        "id": "fortinet_cli",
                        "versions": {
                            "7.4": "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference",
                        },
                    }
                ]
            },
        },
    )

    toc_html = """
<!DOCTYPE html>
<html><body>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/101/config-vpn-ipsec-phase1-interface">config vpn ipsec phase1-interface</a>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/102/config-log-syslogd-setting">config log syslogd setting</a>
  <a class="toc" href="/document/fortigate/7.4.11/cli-reference/103/config-log-fortianalyzer-cloud-setting">config log fortianalyzer-cloud setting</a>
</body></html>
""".strip()
    ipsec_html = """
<!DOCTYPE html><html><body><pre>config vpn ipsec phase1-interface
  edit &lt;name&gt;
    set dhgrp [1|2|5|14]
  next
end</pre></body></html>
""".strip()
    syslog_html = """
<!DOCTYPE html><html><body><pre>config log syslogd setting
  set status [enable|disable]
end</pre></body></html>
""".strip()
    cloud_html = """
<!DOCTYPE html><html><body><pre>config log fortianalyzer-cloud setting
  set status [enable|disable]
end</pre></body></html>
""".strip()

    payloads = {
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/84566/fortios-cli-reference": toc_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/101/config-vpn-ipsec-phase1-interface": ipsec_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/102/config-log-syslogd-setting": syslog_html,
        "https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/103/config-log-fortianalyzer-cloud-setting": cloud_html,
    }

    mod.build_corpus(repo_root=tmp_path, fetcher=lambda url: payloads[url])
    schema = json.loads((tmp_path / "docs" / "derived" / "schema" / "7.4" / "schema.json").read_text(encoding="utf-8"))

    assert "dhgrp" in schema["tables"]["vpn ipsec phase1-interface"]["fields"]
    assert schema["tables"]["vpn ipsec phase1-interface"]["fields"]["dhgrp"]["allowed_values"] == ["1", "2", "5", "14"]
    assert schema["tables"]["log syslogd setting"]["fields"]["status"]["allowed_values"] == ["enable", "disable"]
    assert schema["tables"]["log fortianalyzer-cloud setting"]["fields"]["status"]["allowed_values"] == ["enable", "disable"]
