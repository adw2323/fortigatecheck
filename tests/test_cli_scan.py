import json
import shutil
import sys
from pathlib import Path

from fgcheck.cli import main


def test_cli_can_scan_folder_and_emit_summary_json(tmp_path, monkeypatch, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy("tests/fixtures/bad_edge_admin_on.conf", scan_dir / "bad.conf")
    (scan_dir / "good.conf").write_text(
        """
config system interface
    edit "port1"
        set ip 192.0.2.10 255.255.255.0
    next
end
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fgcheck",
            str(scan_dir),
            "--format",
            "json",
            "--fortios",
            "7.4",
            "--rules",
            "rules/builtin/FGT-ADMIN-EDGE-SSH.yaml",
        ],
    )
    main()
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["summary"]["files"] == 2
    assert payload["summary"]["findings"] >= 1
    assert len(payload["files"]) == 2
    assert {Path(f["file"]).name for f in payload["files"]} == {"bad.conf", "good.conf"}
