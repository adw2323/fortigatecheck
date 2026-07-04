"""REST API for fortigatecheck.

Provides a FastAPI-based REST interface for programmatic access to
FortiGate configuration scanning, rule management, and authority lookup.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, File, HTTPException, Query, UploadFile
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

from .authority import lookup_authority, render_authority_json
from .parse import parse_fortios_text
from .report import findings_to_json
from .rules import run
from .schema import load_schema

# ─── Pydantic models (if available) ───

if _HAS_FASTAPI:
    app = FastAPI(
        title="fortigatecheck API",
        description="Deterministic FortiGate configuration checker — no hallucination, pure validation.",
        version="0.1.0",
    )

    class ScanRequest(BaseModel):
        config_text: str
        fortios_version: str | None = None
        rule_ids: list[str] | None = None

    class AuthorityRequest(BaseModel):
        query: str
        fortios_version: str = "7.6"

    class RuleInfo(BaseModel):
        id: str
        title: str
        severity: str
        confidence: str


def create_app() -> Any:
    """Create and configure the FastAPI application."""
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the REST API. "
            "Install with: pip install fgcheck[api]"
        )

    @app.get("/", tags=["health"])
    def root():
        return {"service": "fortigatecheck", "version": "0.1.0", "status": "healthy"}

    @app.get("/health", tags=["health"])
    def health():
        return {"status": "ok"}

    @app.post("/scan", tags=["scan"])
    async def scan_config(request: ScanRequest):
        """Scan a FortiGate configuration for security and syntax findings."""
        try:
            model, warnings = parse_fortios_text(request.config_text)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Parse error: {str(e)}") from e

        results = []
        vdoms = list(model.vdoms.keys()) or ["root"]
        for vdom in vdoms:
            findings = run(
                model,
                vdoms=[vdom],
                fortios_version=request.fortios_version,
            )
            if request.rule_ids:
                findings = [f for f in findings if f.rule_id in request.rule_ids]
            results.extend(findings)

        return JSONResponse(content={
            "findings": json.loads(findings_to_json(results)),
            "vdoms": vdoms,
            "warnings": [str(w) for w in warnings],
            "finding_count": len(results),
        })

    @app.post("/scan/file", tags=["scan"])
    async def scan_file(
        file: UploadFile = File(...),
        fortios_version: str | None = Query(None),
    ):
        """Upload and scan a FortiGate configuration file."""
        content = await file.read()
        text = content.decode("utf-8", errors="replace")

        try:
            model, warnings = parse_fortios_text(text)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Parse error: {str(e)}") from e

        results = []
        vdoms = list(model.vdoms.keys()) or ["root"]
        for vdom in vdoms:
            findings = run(model, vdoms=[vdom], fortios_version=fortios_version)
            results.extend(findings)

        return JSONResponse(content={
            "filename": file.filename,
            "findings": json.loads(findings_to_json(results)),
            "vdoms": vdoms,
            "warnings": [str(w) for w in warnings],
            "finding_count": len(results),
        })

    @app.get("/rules", tags=["rules"])
    def list_rules():
        """List all available security rules."""
        builtin_dir = Path(__file__).parent.parent.parent / "rules" / "builtin"
        if not builtin_dir.exists():
            builtin_dir = Path("rules") / "builtin"

        rules = []
        for yaml_file in sorted(builtin_dir.glob("*.yaml")):
            try:
                import yaml
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                rules.append({
                    "id": data.get("id", ""),
                    "title": data.get("title", ""),
                    "severity": data.get("severity", ""),
                    "confidence": data.get("confidence", ""),
                })
            except Exception:
                continue

        return {"rules": rules, "count": len(rules)}

    @app.get("/rules/{rule_id}", tags=["rules"])
    def get_rule(rule_id: str):
        """Get details for a specific rule."""
        builtin_dir = Path(__file__).parent.parent.parent / "rules" / "builtin"
        if not builtin_dir.exists():
            builtin_dir = Path("rules") / "builtin"

        yaml_file = builtin_dir / f"{rule_id}.yaml"
        if not yaml_file.exists():
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        import yaml
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        return data

    @app.post("/authority", tags=["authority"])
    def check_authority(request: AuthorityRequest):
        """Validate a FortiOS command, table, or field against schema."""
        result = lookup_authority(
            request.query, fortios=request.fortios_version, base_dir=Path(".")
        )
        return JSONResponse(content=json.loads(render_authority_json(result)))

    @app.get("/schema/{version}", tags=["schema"])
    def get_schema_info(version: str):
        """Get schema information for a FortiOS version."""
        schema = load_schema(version, base_dir=".")
        return {
            "requested_version": version,
            "resolved_version": schema.resolved_version,
            "loaded": schema.loaded,
            "partial": schema.partial,
            "table_count": len(schema._tables),
            "warnings": schema.warnings,
        }

    return app


# Allow running directly: python -m fgcheck.api
if __name__ == "__main__":
    import uvicorn
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)
