"""End-to-end integration across the generated components, exercised through their CLI
contracts (CONTRACTS.md §6) so the test is robust to each script's internal naming.

Builds a real engagement from the fixtures + the repo's real rules/, runs the full
collect->diff->report->ship->baseline chain, and asserts the contract holds. Skips
individual stages whose script hasn't been generated yet, so the suite stays green while
the build workflow is still in flight and tightens automatically once everything lands.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
FIX = REPO / "tests" / "fixtures" / "diff"
PY = sys.executable


def _run_cli(script, *args, env=None):
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SCRIPTS) + os.pathsep + e.get("PYTHONPATH", "")
    if env:
        e.update(env)
    return subprocess.run([PY, str(SCRIPTS / script), *args],
                          capture_output=True, text=True, env=e, cwd=str(REPO))


@pytest.fixture
def engagement(tmp_path):
    eng = tmp_path / "acme-2026-07"
    (eng / "snapshots" / "web01").mkdir(parents=True)
    (eng / "inventory").mkdir(parents=True)
    (eng / "scope.yml").write_text(yaml.safe_dump({
        "engagement": "acme-2026-07",
        "in_scope": [{"cidr": "10.0.0.0/8", "groups": ["linux"]}],
        "settings": {"collector_account": "svc-driftwatch",
                     "outlier_max_prevalence": 0.05, "outlier_min_group": 20,
                     "splunk_hec_url": "", "elastic_url": ""}}))
    (eng / "inventory" / "fleet_groups.json").write_text(json.dumps({"web01": ["linux"]}))
    for name, rid in (("web01_run1.json", "2026-07-22T0400Z"),
                      ("web01_run2.json", "2026-07-23T0400Z")):
        (eng / "snapshots" / "web01" / f"{rid}.json").write_text((FIX / name).read_text())
    return eng


RUN2 = "2026-07-23T0400Z"


def _diff(engagement):
    """Run the diff engine against the repo's REAL rules/ + allowlists/."""
    sys.path.insert(0, str(SCRIPTS))
    import diff_engine  # noqa: E402
    return diff_engine.run(engagement, RUN2, REPO / "rules", REPO / "allowlists")


@pytest.mark.skipif(not (REPO / "rules" / "policy_checks.yml").exists(),
                    reason="rules not generated yet")
def test_real_rules_catch_planted_persistence(engagement):
    _diff(engagement)
    import driftwatch_common as dc
    findings = dc.load_ndjson(engagement / "findings" / f"{RUN2}.ndjson")
    rules = {f["rule"] for f in findings}
    # ld.so.preload is a design-mandated Critical policy rule; the fixture plants it.
    assert any("ld_so_preload" in r or "ld.so.preload" in r for r in rules), rules
    # a Critical severity finding must exist for the planted rootkit-surface changes
    assert any(f["severity"] == "critical" for f in findings)


@pytest.mark.skipif(not (SCRIPTS / "report_gen.py").exists(),
                    reason="report_gen not generated yet")
def test_report_render_produces_md_and_html(engagement):
    _diff(engagement)
    r = _run_cli("report_gen.py", "render", "--engagement-dir", str(engagement),
                 "--run-id", RUN2)
    assert r.returncode == 0, r.stderr
    md = engagement / "reports" / f"{RUN2}.md"
    html = engagement / "reports" / f"{RUN2}.html"
    assert md.exists() and html.exists(), r.stdout + r.stderr
    text = md.read_text(encoding="utf-8")
    assert "web01" in text


@pytest.mark.skipif(not (SCRIPTS / "fleet_stats.py").exists(),
                    reason="fleet_stats not generated yet")
def test_fleet_matrix_runs(engagement):
    _diff(engagement)
    r = _run_cli("fleet_stats.py", "matrix", "--engagement-dir", str(engagement),
                 "--run-id", RUN2)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not (SCRIPTS / "siem_ship.py").exists(),
                    reason="siem_ship not generated yet")
def test_siem_ship_dry_run_never_connects_or_leaks_token(engagement):
    _diff(engagement)
    r = _run_cli("siem_ship.py", "ship", "--engagement-dir", str(engagement),
                 "--run-id", RUN2, "--splunk", "--dry-run",
                 env={"vault_splunk_hec_token": "SECRET-TOKEN-XYZ"})
    assert r.returncode == 0, r.stderr
    assert "SECRET-TOKEN-XYZ" not in (r.stdout + r.stderr)


@pytest.mark.skipif(not (SCRIPTS / "baseline.py").exists(),
                    reason="baseline not generated yet")
def test_baseline_promote_writes_golden_with_provenance(engagement):
    r = _run_cli("baseline.py", "promote", "--engagement-dir", str(engagement),
                 "--host", "web01", "--run-id", "2026-07-22T0400Z", "--ticket", "ACME-1")
    assert r.returncode == 0, r.stderr
    golden = engagement / "baselines" / "web01.json"
    assert golden.exists()
    doc = json.loads(golden.read_text())
    # provenance recorded somewhere in meta
    meta = doc.get("meta", {})
    assert any(k in json.dumps(meta) for k in ("promoted", "ACME-1", "provenance"))
