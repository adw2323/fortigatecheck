from __future__ import annotations

import argparse
import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

import yaml


FetchFunc = Callable[[str], str | bytes]
_PRIORITY_TABLES = {
    "system interface",
    "firewall policy",
    "router static",
    "router policy",
    "system admin",
    "vpn ssl settings",
    "firewall local-in-policy",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase1",
    "log syslogd setting",
    "log syslogd2 setting",
    "log syslogd3 setting",
    "log syslogd4 setting",
    "log fortianalyzer setting",
    "log fortianalyzer2 setting",
    "log fortianalyzer3 setting",
    "log fortianalyzer-cloud setting",
}


def _load_sources(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("sources.yaml must contain a mapping at the top level.")
    return data


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _decode_payload(payload: str | bytes) -> str:
    if isinstance(payload, bytes):
        return payload.decode("utf-8")
    return payload


def _fetch_text(url: str, *, fetcher: FetchFunc | None = None, timeout: float = 20.0) -> str:
    if fetcher is not None:
        return _decode_payload(fetcher(url))
    with urlopen(url, timeout=timeout) as resp:
        return _decode_payload(resp.read())


def _as_mapping(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _normalize_table_key(path: str) -> str:
    parts = [p.strip().lower() for p in path.replace("/", " ").split() if p.strip()]
    out = " ".join(parts)
    if out.startswith("config "):
        return out[len("config ") :]
    return out


def _normalize_schema_payload(raw: dict[str, Any]) -> dict[str, Any]:
    tables_in = _as_mapping(raw.get("tables"))
    tables_out: dict[str, Any] = {}
    for table_name, table_obj_any in tables_in.items():
        table_obj = _as_mapping(table_obj_any)
        fields_in = _as_mapping(table_obj.get("fields"))
        fields_out: dict[str, Any] = {}
        for field_name, field_obj_any in fields_in.items():
            field_obj = _as_mapping(field_obj_any)
            out_field: dict[str, Any] = {}
            allowed_values = field_obj.get("allowed_values")
            if isinstance(allowed_values, list):
                normalized_values: list[str] = []
                for val in allowed_values:
                    sval = str(val)
                    if sval not in normalized_values:
                        normalized_values.append(sval)
                out_field["allowed_values"] = normalized_values
            fields_out[str(field_name).strip().lower()] = out_field
        tables_out[_normalize_table_key(str(table_name))] = {"fields": fields_out}
    return {"tables": tables_out}


def _extract_schema_from_html(doc: str, *, base_url: str) -> dict[str, Any]:
    tables_out: dict[str, Any] = {}
    pat = r'<a[^>]*class="toc"[^>]*href="([^"]+)"[^>]*>\s*([^<]+?)\s*</a>'
    for m in re.finditer(pat, doc, flags=re.IGNORECASE):
        href = m.group(1).strip()
        label = html.unescape(m.group(2)).strip()
        if not label.lower().startswith("config "):
            continue
        table_name = _normalize_table_key(label)
        if table_name not in tables_out:
            tables_out[table_name] = {"fields": {}, "source_url": urljoin(base_url, href)}
    return {"tables": tables_out}


def _parse_allowed_values(raw: str) -> list[str] | None:
    m = re.search(r"\[([^\]]+)\]", raw)
    if not m:
        return None
    out: list[str] = []
    for piece in m.group(1).split("|"):
        token = piece.strip().strip(",")
        if not token or token == "...":
            continue
        if "..." in token:
            continue
        if token.startswith("{") and token.endswith("}"):
            continue
        if token not in out:
            out.append(token)
    return out or None


def _extract_fields_from_cli_table_html(doc: str, *, table_name: str) -> dict[str, Any]:
    blocks = re.findall(r"<pre[^>]*>(.*?)</pre>", doc, flags=re.IGNORECASE | re.DOTALL)
    target = _normalize_table_key(table_name)
    for block in blocks:
        text = html.unescape(block)
        lines = text.splitlines()
        if not any(_normalize_table_key(ln.strip()).startswith(target) for ln in lines):
            continue
        fields: dict[str, Any] = {}
        for ln in lines:
            m = re.match(r"^\s*set\s+([a-z0-9-]+)\s*(.*)$", ln.strip(), flags=re.IGNORECASE)
            if not m:
                continue
            field = m.group(1).lower()
            rest = m.group(2)
            field_payload: dict[str, Any] = {}
            allowed = _parse_allowed_values(rest)
            if allowed is not None:
                field_payload["allowed_values"] = allowed
            fields[field] = field_payload
        if fields:
            return fields
    return {}


def _merge_schema_tables(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = {"tables": dict(_as_mapping(base.get("tables")))}
    incoming_tables = _as_mapping(incoming.get("tables"))
    for table_name, table_obj_any in incoming_tables.items():
        table_name = str(table_name)
        table_obj = _as_mapping(table_obj_any)
        existing = _as_mapping(merged["tables"].get(table_name))
        existing_fields = dict(_as_mapping(existing.get("fields")))
        for field_name, field_obj_any in _as_mapping(table_obj.get("fields")).items():
            field_name = str(field_name)
            field_obj = _as_mapping(field_obj_any)
            old_field = _as_mapping(existing_fields.get(field_name))
            merged_field = dict(old_field)
            if "allowed_values" in field_obj:
                merged_field["allowed_values"] = field_obj["allowed_values"]
            existing_fields[field_name] = merged_field
        merged_table = dict(existing)
        merged_table["fields"] = existing_fields
        if "source_url" in table_obj:
            merged_table["source_url"] = table_obj["source_url"]
        merged["tables"][table_name] = merged_table
    return merged


def _normalize_kev_payload(raw: dict[str, Any]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for vuln_any in _as_list(raw.get("vulnerabilities")):
        vuln = _as_mapping(vuln_any)
        cve_id = str(vuln.get("cveID", "")).strip()
        if not cve_id:
            continue
        entries.append(
            {
                "cve_id": cve_id,
                "vendor": str(vuln.get("vendorProject", "")).strip(),
                "product": str(vuln.get("product", "")).strip(),
                "date_added": str(vuln.get("dateAdded", "")).strip(),
            }
        )
    return {"entries": entries}

def _extract_cves_from_text(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in re.finditer(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _collect_psirt_entries(raw: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    items: list[Any] = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        for key in ("advisories", "items", "data", "entries", "results"):
            if isinstance(raw.get(key), list):
                items = raw.get(key)  # type: ignore[assignment]
                break
        if not items:
            items = [raw]

    for item_any in items:
        item = _as_mapping(item_any)
        if not item:
            continue
        cves: list[str] = []
        for key in ("cve", "cve_id", "cveID", "cveId", "cves", "cve_list"):
            if key in item:
                val = item.get(key)
                if isinstance(val, list):
                    for v in val:
                        cves.extend(_extract_cves_from_text(str(v)))
                else:
                    cves.extend(_extract_cves_from_text(str(val)))
        if not cves:
            cves = _extract_cves_from_text(json.dumps(item))
        if not cves:
            continue

        advisory_id = str(
            item.get("id")
            or item.get("advisory_id")
            or item.get("advisoryID")
            or item.get("psirtID")
            or item.get("reference")
            or ""
        ).strip()
        title = str(item.get("title") or item.get("name") or "").strip()
        published = str(item.get("published") or item.get("date") or item.get("date_published") or item.get("release_date") or "").strip()

        for cve in cves:
            entries.append(
                {
                    "cve_id": cve,
                    "source": "psirt",
                    "advisory_id": advisory_id or None,
                    "title": title or None,
                    "published": published or None,
                }
            )
    return entries


def _collect_psirt_rss_entries(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    items = root.findall(".//item")
    entries: list[dict[str, Any]] = []
    for item in items:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        published = (item.findtext("pubDate") or "").strip()
        description = (item.findtext("description") or "").strip()
        cves = _extract_cves_from_text(" ".join([title, link, description]))
        if not cves:
            continue
        advisory_match = re.search(r"FG-IR-\d{2}-\d+", " ".join([title, link, description]), flags=re.IGNORECASE)
        advisory_id = advisory_match.group(0).upper() if advisory_match else None
        for cve in cves:
            entries.append(
                {
                    "cve_id": cve,
                    "source": "psirt",
                    "advisory_id": advisory_id,
                    "title": title or None,
                    "published": published or None,
                }
            )
    return entries


def _validate_allowed_url(url: str, allowed_domains: set[str]) -> None:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise ValueError(f"Invalid URL host: {url}")
    for allowed in allowed_domains:
        if host == allowed or host.endswith("." + allowed):
            return
    raise ValueError(f"Source URL domain '{host}' is not in allowed_domains.")


def _collect_schema_urls(
    schema_sources: list[Any],
    versions: list[str],
) -> dict[str, list[str]]:
    per_version: dict[str, list[str]] = {str(v): [] for v in versions}
    for source_any in schema_sources:
        source = _as_mapping(source_any)
        versions_map = _as_mapping(source.get("versions"))
        for version in versions:
            url = versions_map.get(str(version))
            if isinstance(url, str) and url.strip():
                per_version[str(version)].append(url.strip())
    return per_version


def build_corpus(*, repo_root: Path, dry_run: bool = False, fetcher: FetchFunc | None = None) -> None:
    sources_file = repo_root / "docs" / "sources.yaml"
    if not sources_file.exists():
        raise FileNotFoundError(f"Missing sources file: {sources_file}")

    sources = _load_sources(sources_file)
    versions = sources.get("fortios_versions", {}).get("first_class", [])
    if not isinstance(versions, list) or not versions:
        raise ValueError("sources.yaml must define fortios_versions.first_class.")
    versions = [str(v).strip() for v in versions if str(v).strip()]

    allowed_domains_cfg = sources.get("allowed_domains", [])
    if not isinstance(allowed_domains_cfg, list) or not allowed_domains_cfg:
        raise ValueError("sources.yaml must define allowed_domains.")
    allowed_domains = {str(d).strip().lower() for d in allowed_domains_cfg if str(d).strip()}

    sources_block = _as_mapping(sources.get("sources"))
    schema_sources = _as_list(sources_block.get("schema"))
    kev_sources = _as_list(sources_block.get("kev"))
    psirt_sources = _as_list(sources_block.get("psirt"))

    schema_urls_by_version = _collect_schema_urls(schema_sources, versions)
    kev_urls: list[str] = []
    for source_any in kev_sources:
        source = _as_mapping(source_any)
        url = source.get("url")
        if isinstance(url, str) and url.strip():
            kev_urls.append(url.strip())

    psirt_urls: list[str] = []
    for source_any in psirt_sources:
        source = _as_mapping(source_any)
        url = source.get("url")
        if isinstance(url, str) and url.strip():
            psirt_urls.append(url.strip())

    for urls in schema_urls_by_version.values():
        for url in urls:
            _validate_allowed_url(url, allowed_domains)
    for url in kev_urls:
        _validate_allowed_url(url, allowed_domains)
    for url in psirt_urls:
        _validate_allowed_url(url, allowed_domains)

    schema_root = repo_root / "docs" / "derived" / "schema"
    cve_root = repo_root / "docs" / "derived" / "cves"
    snippets_root = repo_root / "docs" / "derived" / "snippets"
    if not dry_run:
        _ensure_dir(schema_root)
        _ensure_dir(cve_root)
        _ensure_dir(snippets_root)

    for version in versions:
        schema_dir = schema_root / version
        snippets_dir = snippets_root / version
        if not dry_run:
            _ensure_dir(schema_dir)
            _ensure_dir(snippets_dir)

        merged_schema = {"tables": {}}
        fetch_cache: dict[str, str] = {}

        def fetch_cached(url: str) -> str:
            if url not in fetch_cache:
                fetch_cache[url] = _fetch_text(url, fetcher=fetcher)
            return fetch_cache[url]

        table_only_coverage = False
        for url in schema_urls_by_version.get(version, []):
            raw_text = fetch_cached(url)
            stripped = raw_text.lstrip()
            if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
                table_only_coverage = True
                normalized = _extract_schema_from_html(raw_text, base_url=url)
            else:
                raw = json.loads(raw_text)
                normalized = _normalize_schema_payload(_as_mapping(raw))
            merged_schema = _merge_schema_tables(merged_schema, normalized)

        for table_name in _PRIORITY_TABLES:
            table_obj = _as_mapping(_as_mapping(merged_schema.get("tables")).get(table_name))
            source_url = table_obj.get("source_url")
            if not isinstance(source_url, str) or not source_url.strip():
                continue
            table_doc = fetch_cached(source_url.strip())
            fields = _extract_fields_from_cli_table_html(table_doc, table_name=table_name)
            if not fields:
                continue
            current_fields = _as_mapping(table_obj.get("fields"))
            for fname, fobj_any in fields.items():
                fobj = _as_mapping(fobj_any)
                merged_field = dict(_as_mapping(current_fields.get(fname)))
                if "allowed_values" in fobj:
                    merged_field["allowed_values"] = fobj["allowed_values"]
                current_fields[fname] = merged_field
            table_obj["fields"] = current_fields
            _as_mapping(merged_schema.get("tables"))[table_name] = table_obj

        if dry_run:
            continue
        schema_file = schema_dir / "schema.json"
        _write_json(
            schema_file,
            {
                "version": version,
                "generated_by": "scripts/build_corpus.py",
                "coverage": ("table_only" if table_only_coverage else "full"),
                "tables": merged_schema["tables"],
            },
        )

    all_entries: list[dict[str, Any]] = []
    for url in kev_urls:
        raw = json.loads(_fetch_text(url, fetcher=fetcher))
        all_entries.extend(_normalize_kev_payload(_as_mapping(raw))["entries"])

    for url in psirt_urls:
        raw_text = _fetch_text(url, fetcher=fetcher)
        stripped = raw_text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                raw = json.loads(raw_text)
                all_entries.extend(_collect_psirt_entries(raw))
                continue
            except json.JSONDecodeError:
                pass
        if stripped.startswith("<"):
            rss_entries = _collect_psirt_rss_entries(raw_text)
            if rss_entries:
                all_entries.extend(rss_entries)
                continue
        cves = _extract_cves_from_text(raw_text)
        for cve in cves:
            all_entries.append({"cve_id": cve, "source": "psirt"})

    if not dry_run:
        cves_file = cve_root / "cves.json"
        seen: set[tuple[str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for entry in all_entries:
            cve_id = str(entry.get("cve_id", "")).strip()
            source = str(entry.get("source", "kev")).strip()
            key = (cve_id, source)
            if not cve_id or key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        _write_json(
            cves_file,
            {
                "generated_by": "scripts/build_corpus.py",
                "entries": deduped,
            },
        )


def main() -> None:
    ap = argparse.ArgumentParser(description="Build derived corpus scaffolding for fgcheck.")
    ap.add_argument("--repo-root", default=".", help="Repository root containing docs/sources.yaml.")
    ap.add_argument("--dry-run", action="store_true", help="Validate config but do not write files.")
    args = ap.parse_args()
    build_corpus(repo_root=Path(args.repo_root), dry_run=args.dry_run)


if __name__ == "__main__":
    main()
