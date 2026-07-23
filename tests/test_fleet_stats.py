"""Tests for scripts/fleet_stats.py — the findings x hosts matrix (design §7 item 4)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import driftwatch_common as dc
import fleet_stats

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "report" / "engagement"
RUN = "2026-07-22T0400Z"


@pytest.fixture()
def engagement(tmp_path) -> Path:
    dst = tmp_path / "engagement"
    shutil.copytree(FIXTURE, dst)
    return dst


def _findings(engagement: Path):
    return dc.load_ndjson(engagement / "findings" / f"{RUN}.ndjson")


# --------------------------------------------------------------------------- build_matrix

def test_build_matrix_cells_reflect_finding_hosts():
    findings = [
        {"finding_id": "f1", "severity": "critical", "fingerprint": "0001",
         "rule": "r1", "hosts": ["a", "b"]},
        {"finding_id": "f2", "severity": "low", "fingerprint": "0002",
         "rule": "r2", "hosts": ["c"]},
    ]
    m = fleet_stats.build_matrix(findings, ["a", "b", "c"])
    assert m["hosts"] == ["a", "b", "c"]
    row0 = m["rows"][0]
    assert row0["finding_id"] == "f1"  # critical sorts first
    assert row0["cells"] == {"a": True, "b": True, "c": False}
    assert row0["cells_ordered"] == [True, True, False]
    assert row0["present_count"] == 2
    assert m["rows"][1]["cells"] == {"a": False, "b": False, "c": True}


def test_build_matrix_sorted_by_severity_then_fingerprint():
    findings = [
        {"finding_id": "z", "severity": "high", "fingerprint": "ffff", "rule": "r", "hosts": []},
        {"finding_id": "a", "severity": "high", "fingerprint": "0001", "rule": "r", "hosts": []},
        {"finding_id": "c", "severity": "critical", "fingerprint": "9999", "rule": "r", "hosts": []},
    ]
    m = fleet_stats.build_matrix(findings, [])
    order = [(r["severity"], r["fingerprint"]) for r in m["rows"]]
    assert order == [("critical", "9999"), ("high", "0001"), ("high", "ffff")]


def test_build_matrix_empty():
    m = fleet_stats.build_matrix([], [])
    assert m == {"hosts": [], "rows": []}


# --------------------------------------------------------------------------- hosts_from

def test_hosts_from_unions_findings_and_run_status():
    findings = [{"hosts": ["b", "a"]}]
    run_status = {"hosts": {"c": {}}, "no_transport": ["d"], "t3_only": ["e"]}
    assert fleet_stats.hosts_from(findings, run_status) == ["a", "b", "c", "d", "e"]


def test_hosts_from_findings_only():
    assert fleet_stats.hosts_from([{"hosts": ["x"]}, {"hosts": ["y", "x"]}]) == ["x", "y"]


# --------------------------------------------------------------------------- CLI / build

def test_build_from_engagement_includes_targeted_hosts(engagement):
    matrix = fleet_stats.build(engagement, RUN)
    # Columns include hosts with findings AND targeted-but-finding-free hosts
    # (sw-legacy-3 is t3_only in the run status but has no finding row).
    assert "sw-legacy-3" in matrix["hosts"]
    assert "WIN-FS01" in matrix["hosts"]
    # Every row spans every column.
    for row in matrix["rows"]:
        assert set(row["cells"]) == set(matrix["hosts"])


def test_cli_writes_json_and_exits_zero(engagement, capsys):
    rc = fleet_stats.main(["matrix", "--engagement-dir", str(engagement),
                           "--run-id", RUN, "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hosts"]
    assert out["rows"][0]["severity"] == "critical"
    # The JSON artifact is persisted under reports/.
    written = engagement / "reports" / f"{RUN}.matrix.json"
    assert written.exists()
    persisted = json.loads(written.read_text(encoding="utf-8"))
    assert persisted["hosts"] == out["hosts"]


def test_cli_grid_format(engagement, capsys):
    rc = fleet_stats.main(["matrix", "--engagement-dir", str(engagement), "--run-id", RUN])
    assert rc == 0
    grid = capsys.readouterr().out
    assert "Fleet matrix" in grid
    assert "policy.windows.new_trusted_root_ca" in grid
    assert "●" in grid and "·" in grid


def test_cli_missing_engagement_dir_errors(tmp_path):
    rc = fleet_stats.main(["matrix", "--engagement-dir", str(tmp_path / "nope"),
                           "--run-id", RUN])
    assert rc == 1


def test_cli_missing_findings_produces_empty_matrix(tmp_path, capsys):
    eng = tmp_path / "eng"
    eng.mkdir()
    rc = fleet_stats.main(["matrix", "--engagement-dir", str(eng), "--run-id", RUN])
    assert rc == 0
    assert "0 findings" in capsys.readouterr().out
