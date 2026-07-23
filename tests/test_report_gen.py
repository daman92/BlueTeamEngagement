"""Tests for scripts/report_gen.py — the per-run report renderer (design §7)."""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

import report_gen

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "report" / "engagement"
RUN = "2026-07-22T0400Z"
PREV = "2026-07-22T0000Z"
FIXED_NOW = datetime(2026, 7, 23, 5, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def engagement(tmp_path) -> Path:
    dst = tmp_path / "engagement"
    shutil.copytree(FIXTURE, dst)
    return dst


@pytest.fixture()
def ctx(engagement) -> dict:
    return report_gen.build_context(engagement, RUN, now=FIXED_NOW)


# --------------------------------------------------------------------------- context

def test_engagement_and_meta(ctx):
    assert ctx["engagement"] == "acme-2026-07"
    assert ctx["client"] == "ACME Corp"
    assert ctx["prev_run_id"] == PREV
    assert ctx["no_findings"] is False


def test_totals_exclude_suppressed_from_active(ctx):
    t = ctx["totals"]
    assert t["total"] == 6
    assert t["active"] == 5
    assert t["suppressed"] == 1
    assert t["by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 1}


def test_run_health_from_status_file(ctx):
    rh = ctx["run_health"]
    assert rh["available"] is True
    assert rh["targeted"] == 7          # 5 hosts + no_transport + t3_only
    assert rh["collected"] == 3
    assert rh["partial"] == 1
    assert rh["unreachable"] == 1
    assert rh["no_transport"] == ["WIN-WS-07"]
    assert rh["t3_only"] == ["sw-legacy-3"]
    assert rh["unreachable_hosts"] == ["db01"]
    assert rh["partial_desc"] == ["WIN-FS03 (failed: software, drivers)"]


def test_executive_delta_vs_previous(ctx):
    d = ctx["delta"]
    assert d["prev_available"] is True
    assert d["prev_run_id"] == PREV
    assert d["total_current"] == 5
    assert d["total_previous"] == 2
    by = {r["severity"]: r for r in d["rows"]}
    assert by["critical"]["current"] == 1 and by["critical"]["previous"] == 0 and by["critical"]["delta"] == 1
    assert by["high"]["delta"] == 1
    assert by["medium"]["delta"] == 0


def test_new_this_run_is_first_seen_equals_run_id(ctx):
    new_ids = [f["finding_id"] for f in ctx["delta"]["new_this_run"]]
    # 0001 (critical), 0003 (high coverage), 0004 (medium) are first_seen == RUN.
    # 0002 and 0006 carried over (first_seen == PREV) and must NOT appear.
    assert new_ids == ["f-2026-07-22T0400Z-0001", "f-2026-07-22T0400Z-0003",
                       "f-2026-07-22T0400Z-0004"]
    assert all(f["new_this_run"] for f in ctx["delta"]["new_this_run"])


def test_severity_sections_only_active_sorted(ctx):
    sections = ctx["severity_sections"]
    sevs = [s["severity"] for s in sections]
    assert sevs == ["critical", "high", "medium", "info"]  # no "low" (only suppressed)
    # The suppressed low finding never appears in the active severity sections.
    all_ids = [f["finding_id"] for s in sections for f in s["findings"]]
    assert "f-2026-07-22T0400Z-0005" not in all_ids


def test_suppressed_findings_retained_in_appendix(ctx):
    supp = ctx["suppressed"]
    assert [f["finding_id"] for f in supp] == ["f-2026-07-22T0400Z-0005"]
    assert supp[0]["suppressed_by"] == "allow-chrome-autoupdate"


def test_matrix_excludes_suppressed_rows(ctx):
    ids = [r["finding_id"] for r in ctx["matrix"]["rows"]]
    assert "f-2026-07-22T0400Z-0005" not in ids
    assert ids[0] == "f-2026-07-22T0400Z-0001"  # critical first


def test_per_host_appendix_lists_touching_findings(ctx):
    per_host = {h["host"]: h for h in ctx["per_host"]}
    assert per_host["WIN-FS01"]["count"] == 2
    win_fs01_ids = [f["finding_id"] for f in per_host["WIN-FS01"]["findings"]]
    assert win_fs01_ids == ["f-2026-07-22T0400Z-0001", "f-2026-07-22T0400Z-0002"]
    # db01 appears only via its coverage-gap finding.
    assert per_host["db01"]["findings"][0]["rule"] == "coverage.host_unreachable"


def test_enrich_finding_presentation_fields():
    f = {
        "finding_id": "f-x", "severity": "critical", "rule": "policy.windows.new_trusted_root_ca",
        "platform": "windows", "category": "dns_trust", "change_type": "added",
        "hosts": ["WIN-FS01", "WIN-FS02"], "first_seen": RUN,
        "comparison": ["temporal", "fleet_outlier", "policy"],
        "detail": {"identity": {"kind": "root_cert", "key": "9F3A"}, "before": None,
                   "after": {"kind": "root_cert", "key": "9F3A", "subject": "CN=Corp Proxy CA 2"},
                   "prevalence": 0.014, "note": "n"},
    }
    e = report_gen.enrich_finding(f, RUN, {"windows": 143})
    assert e["host_scope"] == "2/143 windows"
    assert e["prevalence_pct"] == "1.4%"
    assert e["new_this_run"] is True
    assert e["change_lines"] == ['+ {"key": "9F3A", "kind": "root_cert", "subject": "CN=Corp Proxy CA 2"}']
    assert "policy match" in e["lens_labels"]


def test_coverage_gap_headline_is_friendly():
    f = {"finding_id": "f", "severity": "high", "rule": "coverage.host_unreachable",
         "platform": "linux", "category": "meta", "change_type": "coverage_gap",
         "hosts": ["db01"], "first_seen": RUN, "comparison": ["policy"],
         "detail": {"identity": {"kind": "host_unreachable"}, "after": {"host": "db01"}}}
    e = report_gen.enrich_finding(f, RUN)
    assert "unreachable" in e["headline"]
    assert e["change_lines"][0].startswith("! ")


# --------------------------------------------------------------------------- rendering

def test_render_writes_both_formats(engagement):
    summary = report_gen.render_report(engagement, RUN, ["md", "html"], now=FIXED_NOW)
    md = Path(summary["written"]["md"])
    html = Path(summary["written"]["html"])
    assert md.exists() and html.exists()
    md_text = md.read_text(encoding="utf-8")
    assert "## 1. Run health" in md_text
    assert "## 4. Fleet matrix" in md_text
    assert "policy.windows.new_trusted_root_ca" in md_text
    assert "allow-chrome-autoupdate" in md_text          # suppressed appendix present
    html_text = html.read_text(encoding="utf-8")
    assert "<title>driftwatch report" in html_text
    assert "class=\"pill critical\"" in html_text


def test_markdown_has_no_joined_headings(engagement):
    # Regression: trim_blocks must not glue a finding heading to its rule line.
    report_gen.render_report(engagement, RUN, ["md"], now=FIXED_NOW)
    md = (engagement / "reports" / f"{RUN}.md").read_text(encoding="utf-8")
    assert "### CRITICAL — added dns_trust · NEW\n" in md
    assert "`rule: policy.windows.new_trusted_root_ca`" in md


def test_cli_render_exit_zero(engagement):
    rc = report_gen.main(["render", "--engagement-dir", str(engagement),
                          "--run-id", RUN, "--format", "md,html"])
    assert rc == 0


def test_cli_bad_format_errors(engagement):
    rc = report_gen.main(["render", "--engagement-dir", str(engagement),
                          "--run-id", RUN, "--format", "pdf"])
    assert rc == 1


# --------------------------------------------------------------------------- empty / missing

def test_empty_engagement_renders_no_findings(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    summary = report_gen.render_report(eng, RUN, ["md", "html"], now=FIXED_NOW)
    assert summary["no_findings"] is True
    assert summary["findings_active"] == 0
    md = Path(summary["written"]["md"]).read_text(encoding="utf-8")
    assert "No active findings this run" in md
    html = Path(summary["written"]["html"]).read_text(encoding="utf-8")
    assert "No active findings this run" in html


def test_missing_run_status_reconstructs_from_findings(tmp_path):
    eng = tmp_path / "eng"
    (eng / "findings").mkdir(parents=True)
    # One coverage-gap finding, no run-status file.
    (eng / "findings" / f"{RUN}.ndjson").write_text(
        '{"finding_id":"f1","engagement":"e","run_id":"%s","severity":"high",'
        '"rule":"coverage.host_unreachable","platform":"linux","category":"meta",'
        '"change_type":"coverage_gap","hosts":["db9"],"detail":{"identity":'
        '{"kind":"host_unreachable"},"after":{"host":"db9"}},"first_seen":"%s",'
        '"comparison":["policy"],"suppressed":false,"suppressed_by":null,'
        '"fingerprint":"aa"}\n' % (RUN, RUN),
        encoding="utf-8",
    )
    ctx = report_gen.build_context(eng, RUN, now=FIXED_NOW)
    rh = ctx["run_health"]
    assert rh["available"] is False
    assert rh["unreachable"] == 1
    assert rh["unreachable_hosts"] == ["db9"]
