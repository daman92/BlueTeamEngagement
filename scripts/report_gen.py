"""report_gen — render the per-run report (design §7).

Canonical output is the findings NDJSON (§4); this renders the human-facing Markdown and
HTML from it. Layout (design §7):

  1. Run health      — targeted / collected / partial / unreachable (unreachables are findings)
  2. Executive delta — finding counts by severity vs the previous run; new-this-run at top
                       (new = first_seen == this run_id)
  3. Findings by severity — full affected-host list, before/after, first_seen, which lenses
  4. Fleet matrix    — findings x hosts grid (built by fleet_stats.build_matrix)
  5. Per-host appendix — every finding touching a given host
  + Suppressed appendix — findings with suppressed:true (never dropped, design §6)

Everything below the CLI is pure: `build_context()` assembles a template-ready dict from
findings + run status; the Jinja2 templates in scripts/templates/ turn it into MD/HTML.
Missing or empty findings render a clean "no findings" report and exit 0.

CLI:
  report_gen.py render --engagement-dir D --run-id R [--format md,html]
    -> reports/<run_id>.md and/or reports/<run_id>.html
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import driftwatch_common as dc
from fleet_stats import build_matrix, hosts_from

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# Friendly labels for the comparison lenses that caught a finding.
_LENS_LABELS = {
    "temporal": "changed vs previous run",
    "baseline": "differs from golden baseline",
    "fleet_outlier": "fleet outlier",
    "policy": "policy match",
}

# Friendly labels for coverage-gap kinds (rule = coverage.<kind>).
_COVERAGE_LABELS = {
    "host_unreachable": "host unreachable — authorized but not assessed",
    "partial_snapshot": "partial snapshot — collection incomplete",
    "category_failed": "category failed to collect",
    "no_transport": "no viable WinRM/SSH transport",
    "not_assessed": "authorized but not assessed",
    "t3_only": "assessed at generic T3 fallback only",
}


# --------------------------------------------------------------------------- loading

def _load_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return dc.load_ndjson(path)


def _load_json(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _previous_run_id(findings_dir: Path, run_id: str) -> str | None:
    """The most recent run whose findings file precedes run_id (run_ids sort chronologically)."""
    if not findings_dir.exists():
        return None
    prior = sorted(p.stem for p in findings_dir.glob("*.ndjson") if p.stem < run_id)
    return prior[-1] if prior else None


def _read_scope(engagement_dir: Path) -> dict:
    path = engagement_dir / "scope.yml"
    if not path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# --------------------------------------------------------------------------- counting

def _count_by_severity(findings) -> dict:
    counts = {s: 0 for s in dc.SEVERITIES}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _active(findings) -> list[dict]:
    return [f for f in findings if not f.get("suppressed")]


def _sort_findings(findings) -> list[dict]:
    return sorted(findings, key=lambda f: (dc.severity_rank(f.get("severity", "info")),
                                           f.get("fingerprint", "")))


# --------------------------------------------------------------------------- enrichment

def _compact(obj) -> str:
    if obj is None:
        return "—"
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def _change_lines(change_type: str, before, after, identity) -> list[str]:
    """The +/-/! delta lines shown under a finding, design §7 excerpt style."""
    if change_type == "added":
        return ["+ " + _compact(after if after is not None else identity)]
    if change_type == "removed":
        return ["- " + _compact(before if before is not None else identity)]
    if change_type == "changed":
        return ["- " + _compact(before), "+ " + _compact(after)]
    if change_type == "coverage_gap":
        return ["! " + _compact(after if after is not None else identity)]
    return ["  " + _compact(after if after is not None else identity)]


def _host_scope(host_count: int, platform: str, platform_totals: dict | None) -> str:
    if platform_totals and platform_totals.get(platform):
        return f"{host_count}/{platform_totals[platform]} {platform}"
    return f"{host_count} {platform}" if platform else str(host_count)


def enrich_finding(f: dict, run_id: str, platform_totals: dict | None = None) -> dict:
    detail = f.get("detail", {}) or {}
    identity = detail.get("identity", {}) or {}
    before = detail.get("before")
    after = detail.get("after")
    prevalence = detail.get("prevalence")
    comparison = list(f.get("comparison", []) or [])
    hosts = list(f.get("hosts", []) or [])
    change_type = f.get("change_type", "")
    category = f.get("category", "")

    coverage_kind = identity.get("kind") if category == "meta" else None
    headline = _COVERAGE_LABELS.get(coverage_kind) if coverage_kind else \
        f"{change_type} {category}".strip()

    return {
        "finding_id": f.get("finding_id", ""),
        "severity": f.get("severity", "info"),
        "severity_upper": str(f.get("severity", "info")).upper(),
        "rule": f.get("rule", ""),
        "platform": f.get("platform", ""),
        "category": category,
        "change_type": change_type,
        "headline": headline,
        "hosts": hosts,
        "hosts_str": ", ".join(hosts) if hosts else "(none)",
        "host_count": len(hosts),
        "host_scope": _host_scope(len(hosts), f.get("platform", ""), platform_totals),
        "first_seen": f.get("first_seen", ""),
        "new_this_run": f.get("first_seen", "") == run_id,
        "comparison": comparison,
        "comparison_str": ", ".join(comparison),
        "lens_labels": [_LENS_LABELS.get(c, c) for c in comparison],
        "identity_str": _compact(identity),
        "change_lines": _change_lines(change_type, before, after, identity),
        "before_str": _compact(before),
        "after_str": _compact(after),
        "prevalence": prevalence,
        "prevalence_pct": (f"{prevalence * 100:.1f}%" if isinstance(prevalence, (int, float))
                           else None),
        "note": detail.get("note", "") or "",
        "per_host": detail.get("per_host"),
        "suppressed": bool(f.get("suppressed", False)),
        "suppressed_by": f.get("suppressed_by"),
        "fingerprint": f.get("fingerprint", ""),
    }


# --------------------------------------------------------------------------- sections

def build_run_health(run_status: dict | None, findings: list[dict]) -> dict:
    """Section 1. Prefer the run status file; if absent, reconstruct what we can from
    coverage-gap findings so the report is still honest about who wasn't assessed."""
    if run_status:
        hosts = run_status.get("hosts", {}) or {}
        collected = partial = unreachable = 0
        host_rows = []
        platform_totals: dict[str, int] = {}
        for host, st in sorted(hosts.items()):
            st = st or {}
            status = st.get("status", "unknown")
            platform = st.get("platform", "")
            platform_totals[platform] = platform_totals.get(platform, 0) + 1
            if status == "ok":
                collected += 1
            elif status == "partial":
                partial += 1
            elif status == "unreachable":
                unreachable += 1
            host_rows.append({
                "host": host, "status": status, "platform": platform,
                "failed_categories": st.get("failed_categories", []) or [],
            })
        no_transport = sorted(run_status.get("no_transport", []) or [])
        t3_only = sorted(run_status.get("t3_only", []) or [])
        targeted = len(set(hosts) | set(no_transport) | set(t3_only))
        unreachable_hosts = [r["host"] for r in host_rows if r["status"] == "unreachable"]
        partial_desc = [
            r["host"] + (f" (failed: {', '.join(r['failed_categories'])})"
                         if r["failed_categories"] else "")
            for r in host_rows if r["status"] == "partial"
        ]
        return {
            "available": True,
            "targeted": targeted,
            "collected": collected,
            "partial": partial,
            "unreachable": unreachable,
            "no_transport": no_transport,
            "t3_only": t3_only,
            "host_rows": host_rows,
            "unreachable_hosts": unreachable_hosts,
            "partial_desc": partial_desc,
            "platform_totals": platform_totals,
        }

    # Fallback: derive coverage from the findings themselves.
    unreachable_hosts, partial_hosts, no_transport, t3_only = set(), set(), set(), set()
    all_hosts = set()
    for f in findings:
        all_hosts |= set(f.get("hosts", []) or [])
        if f.get("change_type") != "coverage_gap":
            continue
        kind = (f.get("detail", {}) or {}).get("identity", {}).get("kind")
        hs = f.get("hosts", []) or []
        if kind == "host_unreachable":
            unreachable_hosts |= set(hs)
        elif kind == "partial_snapshot":
            partial_hosts |= set(hs)
        elif kind == "no_transport":
            no_transport |= set(hs)
        elif kind == "t3_only":
            t3_only |= set(hs)
    return {
        "available": False,
        "targeted": len(all_hosts),
        "collected": None,
        "partial": len(partial_hosts),
        "unreachable": len(unreachable_hosts),
        "no_transport": sorted(no_transport),
        "t3_only": sorted(t3_only),
        "host_rows": [],
        "unreachable_hosts": sorted(unreachable_hosts),
        "partial_desc": sorted(partial_hosts),
        "platform_totals": {},
    }


def build_delta(active: list[dict], prev_active: list[dict], prev_run_id: str | None,
                run_id: str, platform_totals: dict | None) -> dict:
    """Section 2. Severity counts vs the previous run; new-this-run findings surfaced."""
    cur_counts = _count_by_severity(active)
    prev_counts = _count_by_severity(prev_active)
    rows = []
    for sev in dc.SEVERITIES:
        c, p = cur_counts[sev], prev_counts[sev]
        rows.append({"severity": sev, "current": c, "previous": p, "delta": c - p})
    new_this_run = [enrich_finding(f, run_id, platform_totals)
                    for f in _sort_findings(active)
                    if f.get("first_seen", "") == run_id]
    return {
        "prev_available": prev_run_id is not None,
        "prev_run_id": prev_run_id,
        "rows": rows,
        "new_this_run": new_this_run,
        "new_count": len(new_this_run),
        "total_current": len(active),
        "total_previous": len(prev_active),
    }


def build_severity_sections(active: list[dict], run_id: str,
                            platform_totals: dict | None) -> list[dict]:
    """Section 3. Active findings grouped by severity (only non-empty severities)."""
    ordered = _sort_findings(active)
    sections = []
    for sev in dc.SEVERITIES:
        group = [enrich_finding(f, run_id, platform_totals)
                 for f in ordered if f.get("severity") == sev]
        if group:
            sections.append({"severity": sev, "severity_upper": sev.upper(),
                             "count": len(group), "findings": group})
    return sections


def build_per_host(active: list[dict], hosts: list[str], run_id: str,
                   platform_totals: dict | None) -> list[dict]:
    """Section 5. For each host, every active finding touching it (severity-sorted)."""
    out = []
    for host in hosts:
        touching = _sort_findings([f for f in active if host in (f.get("hosts", []) or [])])
        if not touching:
            continue
        efindings = [enrich_finding(f, run_id, platform_totals) for f in touching]
        counts = {s: sum(1 for e in efindings if e["severity"] == s) for s in dc.SEVERITIES}
        platform = next((e["platform"] for e in efindings if e["platform"]), "")
        out.append({
            "host": host, "platform": platform, "count": len(efindings),
            "by_severity": counts, "findings": efindings,
        })
    return out


def build_context(engagement_dir: Path, run_id: str, now: datetime | None = None) -> dict:
    """Assemble the full template context from findings + run status. Pure: no rendering."""
    engagement_dir = Path(engagement_dir)
    findings_dir = engagement_dir / "findings"
    findings = _load_findings(findings_dir / f"{run_id}.ndjson")

    run_status_path = engagement_dir / "snapshots" / "_run" / f"{run_id}.json"
    run_status = _load_json(run_status_path) if run_status_path.exists() else None

    scope = _read_scope(engagement_dir)
    engagement = (findings[0].get("engagement") if findings else None) \
        or scope.get("engagement") or engagement_dir.name
    client = scope.get("client", "")
    authorized_by = scope.get("authorized_by", "")

    prev_run_id = _previous_run_id(findings_dir, run_id)
    prev_findings = _load_findings(findings_dir / f"{prev_run_id}.ndjson") if prev_run_id else []

    active = _active(findings)
    prev_active = _active(prev_findings)
    suppressed = [f for f in findings if f.get("suppressed")]

    run_health = build_run_health(run_status, findings)
    platform_totals = run_health.get("platform_totals") or None

    hosts = hosts_from(active, run_status)
    matrix = build_matrix(active, hosts)

    delta = build_delta(active, prev_active, prev_run_id, run_id, platform_totals)
    severity_sections = build_severity_sections(active, run_id, platform_totals)
    per_host = build_per_host(active, hosts, run_id, platform_totals)
    suppressed_e = [enrich_finding(f, run_id, platform_totals)
                    for f in _sort_findings(suppressed)]

    now = now or datetime.now(timezone.utc)
    return {
        "engagement": engagement,
        "client": client,
        "authorized_by": authorized_by,
        "run_id": run_id,
        "prev_run_id": prev_run_id,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "no_findings": len(findings) == 0,
        "totals": {
            "total": len(findings),
            "active": len(active),
            "suppressed": len(suppressed),
            "by_severity": _count_by_severity(active),
        },
        "run_health": run_health,
        "delta": delta,
        "severity_sections": severity_sections,
        "matrix": matrix,
        "per_host": per_host,
        "suppressed": suppressed_e,
    }


# --------------------------------------------------------------------------- rendering

def _should_autoescape(name: str | None) -> bool:
    return bool(name and (name.endswith(".html.j2") or name.endswith(".html")))


def _make_env():
    """Build the Jinja2 environment (imported lazily so the pure functions above stay
    usable without Jinja2 installed)."""
    from jinja2 import Environment, FileSystemLoader

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=_should_autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["sevrank"] = lambda s: dc.severity_rank(s)
    env.filters["_glyph"] = lambda present: "●" if present else "·"
    return env


def render(context: dict, fmt: str) -> str:
    """Render one format ("md" or "html") from a prepared context."""
    env = _make_env()
    template_name = {"md": "report.md.j2", "html": "report.html.j2"}[fmt]
    return env.get_template(template_name).render(**context)


def render_report(engagement_dir: Path, run_id: str, formats: list[str],
                  now: datetime | None = None) -> dict:
    """Build context and write reports/<run_id>.<fmt> for each requested format."""
    engagement_dir = Path(engagement_dir)
    context = build_context(engagement_dir, run_id, now=now)
    reports_dir = engagement_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    for fmt in formats:
        text = render(context, fmt)
        out_path = reports_dir / f"{run_id}.{fmt}"
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        written[fmt] = str(out_path)
    return {
        "run_id": run_id,
        "engagement": context["engagement"],
        "written": written,
        "findings_active": context["totals"]["active"],
        "findings_suppressed": context["totals"]["suppressed"],
        "no_findings": context["no_findings"],
    }


# --------------------------------------------------------------------------- CLI

def _parse_formats(raw: str) -> list[str]:
    fmts = [x.strip() for x in raw.split(",") if x.strip()]
    valid = []
    for f in fmts:
        if f not in ("md", "html"):
            raise ValueError(f"unknown format {f!r} (expected md and/or html)")
        if f not in valid:
            valid.append(f)
    return valid or ["md", "html"]


def cmd_render(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    if not engagement_dir.exists():
        sys.stderr.write(f"error: engagement dir not found: {engagement_dir}\n")
        return 1
    try:
        formats = _parse_formats(args.format)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    summary = render_report(engagement_dir, args.run_id, formats)
    print(json.dumps(summary, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="report_gen")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("render", help="render the per-run report (MD/HTML)")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--format", default="md,html",
                   help="comma-separated: md,html (default both)")
    args = parser.parse_args(argv)
    if args.cmd == "render":
        return cmd_render(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
