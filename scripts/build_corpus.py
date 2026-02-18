from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def _load_sources(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("sources.yaml must contain a mapping at the top level.")
    return data


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_corpus(*, repo_root: Path, dry_run: bool = False) -> None:
    sources_file = repo_root / "docs" / "sources.yaml"
    if not sources_file.exists():
        raise FileNotFoundError(f"Missing sources file: {sources_file}")

    sources = _load_sources(sources_file)
    versions = sources.get("fortios_versions", {}).get("first_class", [])
    if not isinstance(versions, list) or not versions:
        raise ValueError("sources.yaml must define fortios_versions.first_class.")

    schema_root = repo_root / "docs" / "derived" / "schema"
    cve_root = repo_root / "docs" / "derived" / "cves"
    snippets_root = repo_root / "docs" / "derived" / "snippets"

    targets = [schema_root, cve_root, snippets_root]
    for t in targets:
        if not dry_run:
            _ensure_dir(t)

    for version in versions:
        schema_dir = schema_root / str(version)
        snippets_dir = snippets_root / str(version)
        if dry_run:
            continue
        _ensure_dir(schema_dir)
        _ensure_dir(snippets_dir)
        schema_file = schema_dir / "schema.json"
        if not schema_file.exists():
            _write_json(
                schema_file,
                {
                    "version": str(version),
                    "generated_by": "scripts/build_corpus.py",
                    "tables": {},
                },
            )

    cves_file = cve_root / "cves.json"
    if not dry_run and not cves_file.exists():
        _write_json(
            cves_file,
            {
                "generated_by": "scripts/build_corpus.py",
                "entries": [],
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
