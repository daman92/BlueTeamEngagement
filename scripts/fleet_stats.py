"""fleet_stats — the findings x hosts matrix (design §7 item 4).

The fleet matrix is the direct answer to "which machines have what differences": one
row per finding, one column per host, a cell marked present when that finding touches
that host. Rows are sorted by (severity_rank, fingerprint) so the grid is deterministic
and the most-severe drift sits at the top — the same order report_gen renders findings in.

Library entry point (imported by report_gen):
  build_matrix(findings, hosts) -> {"hosts": [...], "rows": [{... "cells": {host: bool}}]}

CLI:
  fleet_stats.py matrix --engagement-dir D --run-id R [--format grid|json]
    reads findings/<run_id>.ndjson, prints the grid to stdout, and always writes the
    machine-readable grid to reports/<run_id>.matrix.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import driftwatch_common as dc

# Cell glyphs for the human-readable grid. ASCII fallbacks are used when the output
# stream's encoding can't represent the Unicode glyphs (e.g. a legacy Windows code page),
# so the CLI never crashes a caller that captures its stdout through a non-UTF-8 pipe.
_PRESENT = "●"   # ●
_ABSENT = "·"    # ·
_PRESENT_ASCII = "#"
_ABSENT_ASCII = "."


def _safe_glyphs(stream=None):
    stream = stream if stream is not None else sys.stdout
    enc = getattr(stream, "encoding", None) or "utf-8"
    try:
        (_PRESENT + _ABSENT).encode(enc)
        return _PRESENT, _ABSENT
    except (UnicodeEncodeError, LookupError):
        return _PRESENT_ASCII, _ABSENT_ASCII


# --------------------------------------------------------------------------- helpers

def _finding_hosts(f: dict) -> set:
    return set(f.get("hosts", []) or [])


def hosts_from(findings, run_status: dict | None = None) -> list[str]:
    """The fleet's host set (matrix columns): every host that any finding touches,
    unioned with every host the run targeted (so hosts with zero findings still show as
    a clean column, and unreachable/no-transport hosts are not dropped)."""
    hosts: set[str] = set()
    for f in findings:
        hosts |= _finding_hosts(f)
    if run_status:
        hosts |= set((run_status.get("hosts", {}) or {}).keys())
        hosts |= set(run_status.get("no_transport", []) or [])
        hosts |= set(run_status.get("t3_only", []) or [])
    return sorted(hosts)


def _row_sort_key(f: dict):
    return (dc.severity_rank(f.get("severity", "info")), f.get("fingerprint", ""))


def build_matrix(findings, hosts) -> dict:
    """Build the findings x hosts grid.

    findings: finding dicts (NDJSON records). hosts: ordered column host list.
    Returns {"hosts": [...], "rows": [...]} where each row carries the finding's
    identity fields plus `cells` = {host -> present bool} (the {finding -> {host -> bool}}
    mapping the contract calls for) and `present_count`. Rows are sorted by
    (severity_rank, fingerprint)."""
    cols = list(hosts)
    rows = []
    for f in sorted(findings, key=_row_sort_key):
        touched = _finding_hosts(f)
        cells = {h: (h in touched) for h in cols}
        rows.append({
            "finding_id": f.get("finding_id"),
            "rule": f.get("rule"),
            "severity": f.get("severity"),
            "platform": f.get("platform"),
            "category": f.get("category"),
            "change_type": f.get("change_type"),
            "fingerprint": f.get("fingerprint"),
            "suppressed": bool(f.get("suppressed", False)),
            "cells": cells,
            # cells_ordered aligns to `hosts` column order so text/Markdown renderers can
            # emit a row without re-looking-up the dict (and without trailing-block-tag
            # whitespace hazards in Jinja).
            "cells_ordered": [cells[h] for h in cols],
            "present_count": sum(1 for v in cells.values() if v),
        })
    return {"hosts": cols, "rows": rows}


# --------------------------------------------------------------------------- rendering

def render_grid(matrix: dict, run_id: str, present: str = _PRESENT,
                absent: str = _ABSENT) -> str:
    """Render the matrix as a compact fixed-width grid for a terminal / plain text.

    Hosts are numbered columns (a legend maps number -> host) so the grid stays narrow
    no matter how long the hostnames are. `present`/`absent` are the cell glyphs."""
    hosts = matrix["hosts"]
    rows = matrix["rows"]
    lines: list[str] = []
    lines.append(f"Fleet matrix — run {run_id} "
                 f"({len(rows)} finding{'s' if len(rows) != 1 else ''} x "
                 f"{len(hosts)} host{'s' if len(hosts) != 1 else ''})")
    lines.append("")

    if not hosts:
        lines.append("(no hosts)")
        return "\n".join(lines) + "\n"

    # Host legend: index -> host.
    lines.append("Hosts (columns):")
    idx_width = len(str(len(hosts)))
    host_w = max(len(h) for h in hosts)
    per_line = max(1, 80 // (idx_width + 2 + host_w + 3))
    legend_cells = [f"{i:>{idx_width}} {h:<{host_w}}" for i, h in enumerate(hosts, 1)]
    for i in range(0, len(legend_cells), per_line):
        lines.append("  " + "   ".join(legend_cells[i:i + per_line]))
    lines.append("")

    if not rows:
        lines.append("(no findings)")
        return "\n".join(lines) + "\n"

    lines.append(f"Findings x hosts ({present} present  {absent} absent):")
    sev_w = max(4, max(len(r["severity"]) for r in rows))
    fid_w = max(len("FINDING"), max(len(str(r["finding_id"] or "")) for r in rows))
    rule_w = max(len("RULE"), max(len(str(r["rule"] or "")) for r in rows))
    rule_w = min(rule_w, 44)
    header = (f"{'SEV':<{sev_w}}  {'FINDING':<{fid_w}}  {'RULE':<{rule_w}}  "
              + " ".join(str(i) for i in range(1, len(hosts) + 1)))
    lines.append(header)
    for r in rows:
        cells = " ".join(present if r["cells"][h] else absent for h in hosts)
        rule = str(r["rule"] or "")
        if len(rule) > rule_w:
            rule = rule[:rule_w - 1] + "…"
        flag = " (suppressed)" if r["suppressed"] else ""
        lines.append(f"{r['severity']:<{sev_w}}  {str(r['finding_id'] or ''):<{fid_w}}  "
                     f"{rule:<{rule_w}}  {cells}  ({r['present_count']}){flag}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- CLI

def _load_findings(engagement_dir: Path, run_id: str) -> list[dict]:
    path = engagement_dir / "findings" / f"{run_id}.ndjson"
    if not path.exists():
        return []
    return dc.load_ndjson(path)


def _load_run_status(engagement_dir: Path, run_id: str) -> dict | None:
    path = engagement_dir / "snapshots" / "_run" / f"{run_id}.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build(engagement_dir: Path, run_id: str) -> dict:
    """Load findings + run status and build the matrix (columns include targeted hosts)."""
    findings = _load_findings(engagement_dir, run_id)
    run_status = _load_run_status(engagement_dir, run_id)
    hosts = hosts_from(findings, run_status)
    return build_matrix(findings, hosts)


def cmd_matrix(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    if not engagement_dir.exists():
        sys.stderr.write(f"error: engagement dir not found: {engagement_dir}\n")
        return 1
    matrix = build(engagement_dir, args.run_id)

    reports_dir = engagement_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{args.run_id}.matrix.json"
    with open(json_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dc.canonical_json(matrix) + "\n")

    if args.format == "json":
        print(json.dumps(matrix, indent=2))
    else:
        present, absent = _safe_glyphs(sys.stdout)
        sys.stdout.write(render_grid(matrix, args.run_id, present, absent))
    sys.stderr.write(f"wrote {json_path}\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="fleet_stats")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("matrix", help="build the findings x hosts grid")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--format", choices=("grid", "json"), default="grid")
    args = parser.parse_args(argv)
    if args.cmd == "matrix":
        return cmd_matrix(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
