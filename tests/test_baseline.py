from fgcheck.baseline import (
    filter_finding_records,
    finding_to_record,
    load_baseline_matchers,
    merge_baseline_records,
    write_baseline_records,
)
from fgcheck.model import Evidence
from fgcheck.rules import Finding


def test_filter_finding_records_subset_match():
    rec = {
        "rule_id": "FGT-ADMIN-EDGE-SSH",
        "severity": "high",
        "confidence": "certain",
        "vdom": "root",
        "message": "allowaccess includes ssh on edge interface port1",
        "file_id": "sample.conf",
        "line_start": 10,
        "line_end": 10,
    }
    kept, suppressed = filter_finding_records([rec], [{"rule_id": "FGT-ADMIN-EDGE-SSH"}])
    assert kept == []
    assert suppressed == 1


def test_load_and_write_baseline_roundtrip(tmp_path):
    p = tmp_path / "baseline.json"
    records = [
        {
            "rule_id": "FGT-ADMIN-EDGE-SSH",
            "severity": "high",
            "confidence": "certain",
            "vdom": "root",
            "message": "m",
            "file_id": "f.conf",
            "line_start": 1,
            "line_end": 1,
        }
    ]
    write_baseline_records(str(p), records)
    loaded = load_baseline_matchers(str(p))
    assert loaded == records


def test_finding_to_record_extracts_first_evidence():
    f = Finding(
        rule_id="FGT-ADMIN-EDGE-SSH",
        title="t",
        severity="high",
        confidence="certain",
        vdom="root",
        message="m",
        evidence=[Evidence(file_id="a.conf", line_range=(12, 12), path=("x",), raw_lines=[])],
    )
    rec = finding_to_record(f)
    assert rec["rule_id"] == "FGT-ADMIN-EDGE-SSH"
    assert rec["file_id"] == "a.conf"
    assert rec["line_start"] == 12
    assert rec["line_end"] == 12


def test_merge_baseline_records_deduplicates(tmp_path):
    p = tmp_path / "baseline.json"
    write_baseline_records(
        str(p),
        [{"rule_id": "FGT-ADMIN-EDGE-SSH", "severity": "high"}],
    )
    merge_baseline_records(
        str(p),
        [
            {"rule_id": "FGT-ADMIN-EDGE-SSH", "severity": "high"},
            {"rule_id": "FGT-ADMIN-EDGE-HTTPS", "severity": "high"},
        ],
    )
    loaded = load_baseline_matchers(str(p))
    assert {"rule_id": "FGT-ADMIN-EDGE-SSH", "severity": "high"} in loaded
    assert {"rule_id": "FGT-ADMIN-EDGE-HTTPS", "severity": "high"} in loaded
    assert len(loaded) == 2
