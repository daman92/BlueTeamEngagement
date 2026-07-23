"""diff_engine — compare canonical snapshots and emit findings (design §6).

Four lenses run every cycle and their results merge by fingerprint into one finding
each (§4): temporal (host vs its previous run), baseline (host vs promoted golden),
fleet_outlier (host vs its peers), and policy (baseline-free absolute rules that fire on
first contact). Coverage gaps (unreachable / partial / T3-only) are emitted as findings
too — a broken collection is a finding, not silence (§5 rule 5).

Pure functions do the comparison; `run()` orchestrates load → diff → merge → severity →
first_seen → suppression → write NDJSON. Library entry points:
  diff_documents(prev, cur, lens) -> [delta]
  policy_check(doc, rules)        -> [delta]
  fleet_outliers(docs, groups, settings) -> [delta]
  assemble(deltas, gaps, ...)     -> [Finding]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import _vendor  # noqa: F401  # puts bundled PyYAML/Jinja2 on sys.path (offline kit)
import yaml

import driftwatch_common as dc
from normalize import canonicalize, load_normalize_patterns

_MISSING = object()

# Categories where "rare across the fleet" is a meaningful signal. Config/state that is
# expected to differ per host (interfaces, routes, users) is excluded to avoid noise.
OUTLIER_CATEGORIES = frozenset({
    "processes", "listening", "scheduled_tasks", "services", "autoruns",
    "wmi_subscriptions", "drivers", "kernel_modules", "cron", "systemd_units",
    "software", "persistence", "tunnels", "mirror_sessions",
})


# --------------------------------------------------------------------------- deltas

def _delta(platform, category, change_type, identity, before, after, host, lens,
           collector_self=False, rule=None, severity=None, prevalence=None, note=""):
    return {
        "platform": platform, "category": category, "change_type": change_type,
        "identity": identity, "before": before, "after": after, "host": host,
        "lens": lens, "collector_self": collector_self, "rule": rule,
        "severity": severity, "prevalence": prevalence, "note": note,
    }


def diff_documents(prev: dict, cur: dict, lens: str) -> list[dict]:
    """Compare two canonical snapshot docs (same host). Returns added/removed/changed
    deltas. `prev` may be {} (baseline never promoted / first run) -> everything current
    is 'added' relative to nothing, which the temporal lens intentionally skips (handled
    by the caller passing prev only when it exists)."""
    platform = cur.get("meta", {}).get("platform")
    host = cur.get("meta", {}).get("host")
    specs = dc.CATEGORY_SPECS.get(platform, {})
    deltas: list[dict] = []

    for category, spec in specs.items():
        pv = prev.get(category, _MISSING)
        cv = cur.get(category, _MISSING)
        if cv is _MISSING and pv is _MISSING:
            continue
        if spec.kind == "array":
            deltas += _diff_array(platform, host, category, spec,
                                  pv if pv is not _MISSING else [],
                                  cv if cv is not _MISSING else [], lens)
        else:
            deltas += _diff_object(platform, host, category,
                                   pv if pv is not _MISSING else {},
                                   cv if cv is not _MISSING else {}, lens)
    return deltas


def _self(item) -> bool:
    return bool(isinstance(item, dict) and item.get("collector_self"))


def _diff_array(platform, host, category, spec, prev_items, cur_items, lens) -> list[dict]:
    prev_map = {dc.identity_tuple(it, spec): it for it in prev_items if isinstance(it, dict)}
    cur_map = {dc.identity_tuple(it, spec): it for it in cur_items if isinstance(it, dict)}
    out = []
    for idt, item in cur_map.items():
        ident = dc.identity_dict(item, spec)
        if idt not in prev_map:
            out.append(_delta(platform, category, "added", ident, None, item, host, lens,
                              collector_self=_self(item)))
        elif dc.canonical_json(item) != dc.canonical_json(prev_map[idt]):
            out.append(_delta(platform, category, "changed", ident, prev_map[idt], item,
                              host, lens, collector_self=_self(item)))
    for idt, item in prev_map.items():
        if idt not in cur_map:
            out.append(_delta(platform, category, "removed", dc.identity_dict(item, spec),
                              item, None, host, lens, collector_self=_self(item)))
    return out


def _diff_object(platform, host, category, prev_obj, cur_obj, lens) -> list[dict]:
    out = []
    for key in sorted(set(prev_obj) | set(cur_obj)):
        pv = prev_obj.get(key, _MISSING)
        cv = cur_obj.get(key, _MISSING)
        ident = {"key": key}
        if pv is _MISSING and cv is not _MISSING:
            out.append(_delta(platform, category, "added", ident, None, {key: cv}, host, lens))
        elif cv is _MISSING and pv is not _MISSING:
            out.append(_delta(platform, category, "removed", ident, {key: pv}, None, host, lens))
        elif dc.canonical_json(pv) != dc.canonical_json(cv):
            out.append(_delta(platform, category, "changed", ident, {key: pv}, {key: cv},
                              host, lens))
    return out


# --------------------------------------------------------------------------- policy DSL

def _get_field(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _eval_condition(item: dict, cond: dict) -> bool:
    field = cond["field"]
    op = cond["op"]
    val = cond.get("value")
    actual = _get_field(item, field)
    present = actual is not _MISSING
    if op == "exists":
        return present
    if op == "absent":
        return not present
    if not present:
        return False
    try:
        if op == "eq":
            return actual == val
        if op == "ne":
            return actual != val
        if op == "regex":
            import re
            return re.search(val, str(actual)) is not None
        if op == "in":
            return actual in (val or [])
        if op == "not_in":
            return actual not in (val or [])
        if op == "gt":
            return actual > val
        if op == "lt":
            return actual < val
        if op == "contains":
            if isinstance(actual, (list, tuple)):
                return val in actual
            return str(val) in str(actual)
    except TypeError:
        return False
    raise ValueError(f"unknown op {op!r}")


def match_rule(item: dict, match: dict) -> bool:
    """Evaluate a match DSL block: `all` (AND) and/or `any` (OR) of conditions."""
    if not match:
        return False
    ok = True
    if "all" in match:
        ok = all(_eval_condition(item, c) for c in match["all"])
    if ok and "any" in match:
        ok = any(_eval_condition(item, c) for c in match["any"])
    return ok


def policy_check(doc: dict, rules: list[dict]) -> list[dict]:
    """Fire policy rules against a snapshot doc. Array categories: one delta per matching
    item. Object categories: one delta if the whole object matches."""
    platform = doc.get("meta", {}).get("platform")
    host = doc.get("meta", {}).get("host")
    specs = dc.CATEGORY_SPECS.get(platform, {})
    out = []
    for rule in rules:
        if rule.get("platform", "any") not in (platform, "any"):
            continue
        category = rule["category"]
        spec = specs.get(category)
        if spec is None or category not in doc:
            continue
        change_type = rule.get("change_type", "added")
        sev = rule.get("severity", "high")
        if spec.kind == "array":
            for item in doc[category]:
                if isinstance(item, dict) and match_rule(item, rule["match"]):
                    out.append(_delta(platform, category, change_type,
                                      dc.identity_dict(item, spec), None, item, host,
                                      "policy", collector_self=_self(item),
                                      rule=rule["id"], severity=sev,
                                      note=rule.get("description", "")))
        else:
            obj = doc[category]
            if isinstance(obj, dict) and match_rule(obj, rule["match"]):
                out.append(_delta(platform, category, change_type, {"key": category},
                                  None, obj, host, "policy", rule=rule["id"], severity=sev,
                                  note=rule.get("description", "")))
    return out


# --------------------------------------------------------------------------- fleet outlier

def fleet_outliers(docs_by_host: dict, groups: dict, settings: dict) -> list[dict]:
    """Item present on <= max_prevalence of a group of >= min_group peers => outlier
    delta (change_type 'added') for each host that has it."""
    max_prev = float(settings.get("outlier_max_prevalence", 0.05))
    min_group = int(settings.get("outlier_min_group", 20))

    # group -> list of hosts that produced a snapshot this run
    group_hosts: dict[str, list[str]] = {}
    for host in docs_by_host:
        for g in groups.get(host, []):
            group_hosts.setdefault(g, []).append(host)

    out: list[dict] = []
    seen_fp: set[tuple] = set()   # (group, category, identity) dedup within outlier pass
    for group, members in group_hosts.items():
        if len(members) < min_group:
            continue
        # (category, identity_tuple) -> {hosts: [...], item, platform, spec}
        index: dict[tuple, dict] = {}
        for host in members:
            doc = docs_by_host[host]
            platform = doc.get("meta", {}).get("platform")
            specs = dc.CATEGORY_SPECS.get(platform, {})
            for category in OUTLIER_CATEGORIES:
                spec = specs.get(category)
                if spec is None or spec.kind != "array" or category not in doc:
                    continue
                for item in doc[category]:
                    if not isinstance(item, dict) or _self(item):
                        continue
                    idt = dc.identity_tuple(item, spec)
                    entry = index.setdefault((category, idt), {
                        "hosts": [], "item": item, "platform": platform, "spec": spec})
                    entry["hosts"].append(host)
        for (category, idt), entry in index.items():
            prevalence = len(entry["hosts"]) / len(members)
            if prevalence <= max_prev:
                spec = entry["spec"]
                ident = dc.identity_dict(entry["item"], spec)
                for host in entry["hosts"]:
                    key = (group, category, dc.canonical_json(ident))
                    if key in seen_fp:
                        continue
                    seen_fp.add(key)
                    out.append(_delta(
                        entry["platform"], category, "added", ident, None, entry["item"],
                        host, "fleet_outlier", prevalence=round(prevalence, 4),
                        note=f"present on {len(entry['hosts'])}/{len(members)} of group '{group}'"))
    return out


# --------------------------------------------------------------------------- coverage gaps

def coverage_gaps(run_status: dict, engagement: str, run_id: str) -> list[dict]:
    """Turn per-host collection status into coverage_gap deltas."""
    out = []
    for host, st in (run_status.get("hosts", {}) or {}).items():
        status = st.get("status")
        platform = st.get("platform", "linux")
        if status == "unreachable":
            out.append(_delta(platform, "meta", "coverage_gap", {"kind": "host_unreachable"},
                              None, {"host": host}, host, "policy",
                              rule="coverage.host_unreachable", severity="high",
                              note="authorized but not assessed — no successful collection"))
        elif status == "partial":
            out.append(_delta(platform, "meta", "coverage_gap", {"kind": "partial_snapshot"},
                              None, {"failed_categories": st.get("failed_categories", [])},
                              host, "policy", rule="coverage.partial_snapshot",
                              severity="high", note="snapshot incomplete"))
            for cat in st.get("failed_categories", []):
                out.append(_delta(platform, cat, "coverage_gap", {"kind": "category_failed",
                                  "category": cat}, None, {"category": cat}, host, "policy",
                                  rule="coverage.category_failed", severity="medium",
                                  note=f"category '{cat}' failed to collect"))
    for host in run_status.get("no_transport", []) or []:
        out.append(_delta("windows", "meta", "coverage_gap", {"kind": "no_transport"},
                          None, {"host": host}, host, "policy", rule="coverage.no_transport",
                          severity="high", note="no viable WinRM/SSH transport"))
    for host in run_status.get("t3_only", []) or []:
        out.append(_delta("network", "meta", "coverage_gap", {"kind": "t3_only"},
                          None, {"host": host}, host, "policy", rule="coverage.t3_only",
                          severity="medium", note="assessed at generic T3 fallback only"))
    return out


# --------------------------------------------------------------------------- severity

def load_severity_map(rules_dir: Path) -> dict:
    path = rules_dir / "severity_map.yml"
    if not path.exists():
        return {"defaults": {"added": "medium", "removed": "low", "changed": "medium",
                             "coverage_gap": "high"}, "overrides": []}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def base_severity(sev_map: dict, platform, category, change_type) -> str:
    for ov in sev_map.get("overrides", []) or []:
        if ov.get("platform", "any") not in (platform, "any"):
            continue
        if ov.get("category", "any") not in (category, "any"):
            continue
        if ov.get("change_type", "any") not in (change_type, "any"):
            continue
        return ov["severity"]
    return (sev_map.get("defaults", {}) or {}).get(change_type, "medium")


def _most_severe(sevs) -> str:
    return min(sevs, key=dc.severity_rank)


# --------------------------------------------------------------------------- assemble

def assemble(deltas: list[dict], sev_map: dict, engagement: str, run_id: str,
             state: dict) -> list[dc.Finding]:
    """Merge deltas by fingerprint into findings; resolve rule, severity, first_seen."""
    groups: dict[str, list[dict]] = {}
    for d in deltas:
        fp = dc.finding_fingerprint(d["platform"], d["category"], d["change_type"],
                                    d["identity"])
        groups.setdefault(fp, []).append(d)

    findings = []
    for fp, group in groups.items():
        first = group[0]
        platform, category, change_type = first["platform"], first["category"], first["change_type"]
        lenses = sorted({d["lens"] for d in group})
        hosts = sorted({d["host"] for d in group if d["host"]})

        policy_deltas = [d for d in group if d["rule"] and d["severity"]]
        if policy_deltas:
            best = min(policy_deltas, key=lambda d: dc.severity_rank(d["severity"]))
            rule = best["rule"]
            severity = best["severity"]
        elif change_type == "coverage_gap":
            rule = first["rule"] or f"coverage.{first['identity'].get('kind', 'unknown')}"
            severity = first["severity"] or base_severity(sev_map, platform, category, change_type)
        else:
            rule = f"drift.{platform}.{category}"
            severity = base_severity(sev_map, platform, category, change_type)

        # collector_self cap: only if EVERY contributing delta is collector-self.
        if group and all(d["collector_self"] for d in group):
            severity = "info"

        # detail: shared before/after; per-host afters when they diverge.
        afters = {d["host"]: d["after"] for d in group if d["after"] is not None}
        diverge = len({dc.canonical_json(a) for a in afters.values()}) > 1
        detail = {
            "identity": first["identity"],
            "before": first["before"],
            "after": first["after"],
        }
        if diverge:
            detail["per_host"] = afters
        prevalences = [d["prevalence"] for d in group if d["prevalence"] is not None]
        if prevalences:
            detail["prevalence"] = min(prevalences)
        notes = sorted({d["note"] for d in group if d["note"]})
        if notes:
            detail["note"] = "; ".join(notes)

        first_seen = state.get(fp, run_id)
        state[fp] = first_seen

        findings.append(dc.Finding(
            finding_id="",  # assigned after sort
            engagement=engagement, run_id=run_id, severity=severity, rule=rule,
            platform=platform, category=category, change_type=change_type, hosts=hosts,
            detail=detail, first_seen=first_seen, comparison=lenses, fingerprint=fp))
    return findings


# --------------------------------------------------------------------------- suppression

def load_allowlists(allowlists_dir: Path) -> list[dict]:
    entries = []
    if not allowlists_dir.exists():
        return entries
    for path in sorted(allowlists_dir.glob("*.yml")):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for e in data.get("entries", []) or []:
            e.setdefault("_source", path.name)
            entries.append(e)
    return entries


def apply_suppression(findings: list[dc.Finding], allowlists: list[dict], groups: dict,
                      run_id: str) -> list[str]:
    """Mark findings suppressed by matching, unexpired allowlist entries. Returns a list
    of warnings (expired entries, etc.)."""
    warnings = []
    active = []
    run_date = run_id[:10]  # YYYY-MM-DD
    for e in allowlists:
        expires = str(e.get("expires", ""))
        if not expires:
            warnings.append(f"allowlist '{e.get('id')}' has no expiry — ignored (expiry required)")
            continue
        if expires < run_date:
            warnings.append(f"allowlist '{e.get('id')}' expired {expires} — ignored")
            continue
        active.append(e)

    for f in findings:
        merged = dict(f.detail.get("identity", {}))
        if isinstance(f.detail.get("after"), dict):
            merged.update(f.detail["after"])
        merged["category"] = f.category
        merged["platform"] = f.platform
        for e in active:
            scope = e.get("scope", {}) or {}
            host_ok = _scope_hosts_match(f.hosts, scope, groups)
            if host_ok and match_rule(merged, e.get("match", {})):
                f.suppressed = True
                f.suppressed_by = e.get("id")
                break
    return warnings


def _scope_hosts_match(hosts, scope, groups) -> bool:
    scoped_hosts = set(scope.get("hosts", []) or [])
    scoped_groups = set(scope.get("groups", []) or [])
    if not scoped_hosts and not scoped_groups:
        return True  # empty scope = all
    for h in hosts:
        if h in scoped_hosts:
            return True
        if scoped_groups & set(groups.get(h, [])):
            return True
    return False


# --------------------------------------------------------------------------- run

def _load_json(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _canon_doc(doc, patterns, collector_account):
    return canonicalize(doc, patterns, collector_account)


def run(engagement_dir: Path, run_id: str, rules_dir: Path, allowlists_dir: Path) -> dict:
    scope = {}
    if (engagement_dir / "scope.yml").exists():
        with open(engagement_dir / "scope.yml", "r", encoding="utf-8") as fh:
            scope = yaml.safe_load(fh) or {}
    settings = scope.get("settings", {}) or {}
    engagement = scope.get("engagement", engagement_dir.name)
    collector_account = settings.get("collector_account")
    patterns = load_normalize_patterns(rules_dir)

    fleet_groups = {}
    fg_path = engagement_dir / "inventory" / "fleet_groups.json"
    if fg_path.exists():
        fleet_groups = _load_json(fg_path)

    # Load current + previous snapshots per host (canonicalized in-memory).
    snap_root = engagement_dir / "snapshots"
    cur_docs: dict[str, dict] = {}
    prev_docs: dict[str, dict] = {}
    if snap_root.exists():
        for host_dir in snap_root.iterdir():
            if not host_dir.is_dir() or host_dir.name.startswith("_"):
                continue
            runs = sorted(p.stem for p in host_dir.glob("*.json"))
            if run_id not in runs:
                continue
            host = host_dir.name
            cur_docs[host] = _canon_doc(_load_json(host_dir / f"{run_id}.json"),
                                        patterns, collector_account)
            idx = runs.index(run_id)
            if idx > 0:
                prev_docs[host] = _canon_doc(_load_json(host_dir / f"{runs[idx-1]}.json"),
                                             patterns, collector_account)

    policy_path = rules_dir / "policy_checks.yml"
    if policy_path.exists():
        with open(policy_path, "r", encoding="utf-8") as fh:
            policy_rules = (yaml.safe_load(fh) or {}).get("rules", [])
    else:
        policy_rules = []  # no policy file => pure drift/outlier diff, not a crash
    sev_map = load_severity_map(rules_dir)

    deltas: list[dict] = []
    # temporal + baseline + policy per host
    for host, cur in cur_docs.items():
        real_host = cur.get("meta", {}).get("host", host)
        if host in prev_docs:
            for d in diff_documents(prev_docs[host], cur, "temporal"):
                d["host"] = real_host
                deltas.append(d)
        baseline_path = engagement_dir / "baselines" / f"{host}.json"
        if baseline_path.exists():
            base_doc = _canon_doc(_load_json(baseline_path), patterns, collector_account)
            for d in diff_documents(base_doc, cur, "baseline"):
                d["host"] = real_host
                deltas.append(d)
        for d in policy_check(cur, policy_rules):
            deltas.append(d)
    # fleet outliers across the run
    deltas += fleet_outliers(cur_docs, fleet_groups, settings)

    # coverage gaps
    run_status_path = snap_root / "_run" / f"{run_id}.json"
    if run_status_path.exists():
        deltas += coverage_gaps(_load_json(run_status_path), engagement, run_id)

    # state (first_seen)
    findings_dir = engagement_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    state_path = findings_dir / "state.json"
    state = _load_json(state_path) if state_path.exists() else {}

    findings = assemble(deltas, sev_map, engagement, run_id, state)
    warnings = apply_suppression(findings, load_allowlists(allowlists_dir), fleet_groups, run_id)

    # deterministic order: severity, then fingerprint. Assign ids.
    findings.sort(key=lambda f: (dc.severity_rank(f.severity), f.fingerprint))
    for i, f in enumerate(findings, 1):
        f.finding_id = f"f-{run_id}-{i:04d}"

    out_path = findings_dir / f"{run_id}.ndjson"
    dc.dump_ndjson(findings, out_path)
    with open(state_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)

    active = [f for f in findings if not f.suppressed]
    by_sev = {s: sum(1 for f in active if f.severity == s) for s in dc.SEVERITIES}
    summary = {
        "run_id": run_id, "engagement": engagement,
        "findings_total": len(findings), "findings_active": len(active),
        "by_severity": by_sev, "suppressed": len(findings) - len(active),
        "warnings": warnings, "output": str(out_path),
    }
    return summary


def cmd_run(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    rules_dir = Path(args.rules_dir) if args.rules_dir else Path(__file__).resolve().parent.parent / "rules"
    allowlists_dir = Path(args.allowlists_dir) if args.allowlists_dir else Path(__file__).resolve().parent.parent / "allowlists"
    summary = run(engagement_dir, args.run_id, rules_dir, allowlists_dir)
    for w in summary["warnings"]:
        sys.stderr.write(f"warning: {w}\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "warnings"}, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="diff_engine")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--rules-dir")
    p.add_argument("--allowlists-dir")
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
