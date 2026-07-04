"""Web UI for fortigatecheck.

Provides a simple web interface for uploading and scanning FortiGate configs.
"""
from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False



HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>fortigatecheck - FortiGate Configuration Checker</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #94a3b8; margin-bottom: 2rem; font-size: 1.1rem; }
        .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
        .upload-zone { border: 2px dashed #475569; border-radius: 12px; padding: 3rem; text-align: center; cursor: pointer; transition: all 0.3s; }
        .upload-zone:hover { border-color: #3b82f6; background: rgba(59, 130, 246, 0.1); }
        .upload-zone.dragover { border-color: #8b5cf6; background: rgba(139, 92, 246, 0.1); }
        button { background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; border: none; padding: 0.75rem 2rem; border-radius: 8px; font-size: 1rem; cursor: pointer; font-weight: 600; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .results { display: none; }
        .results.active { display: block; }
        .finding { background: #0f172a; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid; }
        .finding.critical { border-left-color: #ef4444; }
        .finding.high { border-left-color: #f97316; }
        .finding.medium { border-left-color: #eab308; }
        .finding.low { border-left-color: #22c55e; }
        .finding.info { border-left-color: #3b82f6; }
        .severity { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .severity.critical { background: #ef4444; color: white; }
        .severity.high { background: #f97316; color: white; }
        .severity.medium { background: #eab308; color: #1e293b; }
        .severity.low { background: #22c55e; color: white; }
        .severity.info { background: #3b82f6; color: white; }
        .rule-id { font-family: monospace; color: #94a3b8; font-size: 0.875rem; }
        .message { margin-top: 0.5rem; }
        .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
        .stat { background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; border: 1px solid #334155; min-width: 120px; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { color: #94a3b8; font-size: 0.875rem; }
        .stat.critical .stat-value { color: #ef4444; }
        .stat.high .stat-value { color: #f97316; }
        .stat.medium .stat-value { color: #eab308; }
        .stat.low .stat-value { color: #22c55e; }
        .loading { display: none; text-align: center; padding: 2rem; }
        .loading.active { display: block; }
        .spinner { border: 3px solid #334155; border-top: 3px solid #3b82f6; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 1rem; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        select, input[type="text"] { background: #0f172a; border: 1px solid #475569; color: #e2e8f0; padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.875rem; }
        label { display: block; margin-bottom: 0.5rem; color: #94a3b8; font-size: 0.875rem; }
        .form-row { display: flex; gap: 1rem; margin-top: 1rem; }
        footer { text-align: center; color: #475569; margin-top: 3rem; font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>fortigatecheck</h1>
        <p class="subtitle">Deterministic FortiGate configuration checker — no hallucination, pure validation.</p>

        <div class="card">
            <div class="upload-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
                <p style="font-size: 1.25rem; margin-bottom: 0.5rem;">Drop your FortiGate config here</p>
                <p style="color: #64748b;">or click to browse</p>
                <input type="file" id="fileInput" accept=".conf,.txt" style="display: none" onchange="handleFile(this.files[0])">
            </div>
            <div class="form-row">
                <div>
                    <label>FortiOS Version (optional)</label>
                    <select id="fortiosVersion">
                        <option value="">Auto-detect</option>
                        <option value="7.4">7.4</option>
                        <option value="7.6">7.6</option>
                        <option value="8.0">8.0</option>
                    </select>
                </div>
                <div style="display: flex; align-items: flex-end;">
                    <button onclick="scanConfig()" id="scanBtn" disabled>Scan Configuration</button>
                </div>
            </div>
        </div>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Analyzing configuration...</p>
        </div>

        <div class="results" id="results">
            <div class="stats" id="stats"></div>
            <div id="findings"></div>
        </div>

        <footer>
            fortigatecheck v0.1.0 &middot; <a href="/docs" style="color: #3b82f6;">API Docs</a> &middot; <a href="https://github.com/adw2323/fortigatecheck" style="color: #3b82f6;">GitHub</a>
        </footer>
    </div>

    <script>
        let configText = '';
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const scanBtn = document.getElementById('scanBtn');

        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
        });

        function handleFile(file) {
            const reader = new FileReader();
            reader.onload = e => {
                configText = e.target.result;
                scanBtn.disabled = false;
                dropZone.innerHTML = '<p style="font-size: 1.1rem;">✓ ' + file.name + ' loaded (' + Math.round(file.size / 1024) + ' KB)</p>';
            };
            reader.readAsText(file);
        }

        async function scanConfig() {
            if (!configText) return;
            document.getElementById('loading').classList.add('active');
            document.getElementById('results').classList.remove('active');
            scanBtn.disabled = true;

            const version = document.getElementById('fortiosVersion').value;
            try {
                const resp = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ config_text: configText, fortios_version: version || null })
                });
                const data = await resp.json();
                displayResults(data);
            } catch (err) {
                alert('Scan failed: ' + err.message);
            } finally {
                document.getElementById('loading').classList.remove('active');
                scanBtn.disabled = false;
            }
        }

        function displayResults(data) {
            const results = document.getElementById('results');
            const statsDiv = document.getElementById('stats');
            const findingsDiv = document.getElementById('findings');

            const counts = { critical: 0, high: 0, medium: 0, low: 0 };
            data.findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

            statsDiv.innerHTML = Object.entries(counts).map(([sev, count]) =>
                '<div class="stat ' + sev + '"><div class="stat-value">' + count + '</div><div class="stat-label">' + sev + '</div></div>'
            ).join('');

            findingsDiv.innerHTML = data.findings.length === 0
                ? '<div class="card"><p style="text-align: center; color: #22c55e;">✓ No security findings detected</p></div>'
                : data.findings.map(f =>
                    '<div class="finding ' + f.severity + '">' +
                    '<span class="severity ' + f.severity + '">' + f.severity + '</span> ' +
                    '<span class="rule-id">' + f.rule_id + '</span>' +
                    '<div class="message">' + f.message + '</div>' +
                    '</div>'
                ).join('');

            results.classList.add('active');
        }
    </script>
</body>
</html>
"""


FLEET_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2rem; margin-bottom: 1rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; }
        .stat-value { font-size: 2.5rem; font-weight: 700; }
        .stat-label { color: #94a3b8; font-size: 0.875rem; }
        .stat-card.critical .stat-value { color: #ef4444; }
        .stat-card.high .stat-value { color: #f97316; }
        .table-card { background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; margin-bottom: 1.5rem; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: 600; font-size: 0.875rem; }
        .trend-improving { color: #22c55e; }
        .trend-degrading { color: #ef4444; }
        .trend-stable { color: #94a3b8; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge.critical { background: #ef4444; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Fleet Dashboard</h1>
        <div class="stats-grid" id="stats"></div>
        <div class="table-card"><h2 style="margin-bottom:1rem">Devices</h2><table><thead><tr><th>Device</th><th>Scans</th><th>Findings</th><th>Critical</th><th>Trend</th></tr></thead><tbody id="devices"></tbody></table></div>
        <div class="table-card"><h2 style="margin-bottom:1rem">Recent Scans</h2><table><thead><tr><th>Device</th><th>Date</th><th>Findings</th><th>Critical</th><th>High</th></tr></thead><tbody id="scans"></tbody></table></div>
    </div>
    <script>
    async function load() {
        const s = await (await fetch("/api/fleet/stats")).json();
        document.getElementById("stats").innerHTML = [{l:"Devices",v:s.device_count},{l:"Total Scans",v:s.total_scans},{l:"Critical",v:s.total_critical,c:"critical"},{l:"High",v:s.total_high,c:"high"}].map(x=>`<div class="stat-card ${x.c||""}"><div class="stat-value">${x.v}</div><div class="stat-label">${x.l}</div></div>`).join("");
        const d = await (await fetch("/api/fleet/devices")).json();
        document.getElementById("devices").innerHTML = d.map(x=>`<tr><td>${x.device_name}</td><td>${x.scan_count}</td><td>${x.latest_findings}</td><td>${x.latest_critical>0?`<span class="badge critical">${x.latest_critical}</span>`:"0"}</td><td class="trend-${x.trend}">${x.trend}</td></tr>`).join("");
        const sc = await (await fetch("/api/fleet/scans")).json();
        document.getElementById("scans").innerHTML = sc.map(x=>`<tr><td>${x.device_name}</td><td>${new Date(x.scan_date).toLocaleString()}</td><td>${x.finding_count}</td><td>${x.critical_count}</td><td>${x.high_count}</td></tr>`).join("");
    }
    load();
    </script>
</body>
</html>
"""

def create_web_app() -> Any:
    """Create the web UI FastAPI app."""
    if not _HAS_FASTAPI:
        raise ImportError("FastAPI required. Install: pip install fgcheck[api]")

    app = FastAPI(title="fortigatecheck", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTML_TEMPLATE

    @app.post("/scan")
    async def scan(request_body: dict):
        from .parse import parse_fortios_text
        from .rules import run

        config_text = request_body.get("config_text", "")
        fortios_version = request_body.get("fortios_version")

        try:
            model, warnings = parse_fortios_text(config_text)
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

        findings = []
        vdoms = list(model.vdoms.keys()) or ["root"]
        for vdom in vdoms:
            findings.extend(run(model, vdoms=[vdom], fortios_version=fortios_version))

        # Convert Finding objects to dicts
        results = []
        for f in findings:
            results.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "vdom": f.vdom,
                "message": f.message,
                "evidence_count": len(f.evidence),
            })

        return {"findings": results, "vdoms": vdoms, "total": len(results)}

    from .fleet_db import FleetDB

    @app.get("/fleet", response_class=HTMLResponse)
    def fleet_dashboard():
        return FLEET_DASHBOARD_HTML

    @app.get("/api/fleet/stats")
    def fleet_stats():
        db = FleetDB()
        stats = db.get_fleet_stats()
        db.close()
        return stats

    @app.get("/api/fleet/devices")
    def fleet_devices():
        db = FleetDB()
        summaries = db.get_device_summary()
        db.close()
        return [{"device_name": s.device_name, "scan_count": s.scan_count, "latest_scan": s.latest_scan, "latest_findings": s.latest_findings, "latest_critical": s.latest_critical, "trend": s.trend} for s in summaries]

    @app.get("/api/fleet/scans")
    def fleet_scans():
        db = FleetDB()
        scans = db.get_scans(limit=50)
        db.close()
        return [{"id": s.id, "device_name": s.device_name, "scan_date": s.scan_date, "finding_count": s.finding_count, "critical_count": s.critical_count, "high_count": s.high_count, "medium_count": s.medium_count, "low_count": s.low_count} for s in scans]

    @app.post("/api/fleet/scan")
    async def fleet_scan(request_body: dict):
        from .parse import parse_fortios_text
        from .rules import run
        config_text = request_body.get("config_text", "")
        device_name = request_body.get("device_name", "unknown")
        fortios_version = request_body.get("fortios_version")
        try:
            model, warnings = parse_fortios_text(config_text)
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})
        findings = []
        vdoms = list(model.vdoms.keys()) or ["root"]
        for vdom in vdoms:
            findings.extend(run(model, vdoms=[vdom], fortios_version=fortios_version))
        finding_dicts = [{"rule_id": f.rule_id, "severity": f.severity, "message": f.message} for f in findings]
        db = FleetDB()
        scan_id = db.store_scan(device_name, finding_dicts, fortios_version=fortios_version)
        db.close()
        return {"scan_id": scan_id, "device_name": device_name, "finding_count": len(findings)}
    return app


if __name__ == "__main__":
    import uvicorn
    app = create_web_app()
    uvicorn.run(app, host="0.0.0.0", port=8080)
