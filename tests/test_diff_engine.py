import json
from pathlib import Path

import pytest

import diff_engine as de
import driftwatch_common as dc
from normalize import canonicalize

FIX = Path(__file__).parent / "fixtures" / "diff"


def _load(name):
    return json.loads((FIX / name).read_text())


# ---------------------------------------------------------------- pure diff

def test_array_added_removed_changed():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    deltas = de.diff_documents(prev, cur, "temporal")
    kinds = {(d["category"], d["change_type"], d["identity"].get("path")): d for d in deltas}
    # /tmp/evil added as process and listening
    assert ("processes", "added", "/tmp/evil") in kinds
    # nginx pid changed but pid is volatile -> NO change finding for nginx
    assert ("processes", "changed", "/usr/sbin/nginx") not in kinds


def test_volatile_pid_change_is_not_a_finding():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    deltas = de.diff_documents(prev, cur, "temporal")
    nginx = [d for d in deltas if d["identity"].get("path") == "/usr/sbin/nginx"]
    assert nginx == []


def test_object_category_key_diff():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    deltas = de.diff_documents(prev, cur, "temporal")
    ssh = [d for d in deltas if d["category"] == "ssh_config" and d["change_type"] == "changed"]
    keys = {d["identity"]["key"] for d in ssh}
    assert "permit_root_login" in keys and "effective" in keys


def test_collector_self_delta_flagged():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    # backup process (svc-driftwatch) changed only in volatile pid/started -> no delta at all
    deltas = de.diff_documents(prev, cur, "temporal")
    assert not any(d["identity"].get("path") == "/usr/bin/backup" for d in deltas)


# ---------------------------------------------------------------- policy DSL

def test_match_dsl_ops():
    item = {"path": "/tmp/x", "uid": 0, "signed": False, "groups": ["wheel"]}
    assert de.match_rule(item, {"all": [{"field": "path", "op": "regex", "value": "^/tmp/"}]})
    assert de.match_rule(item, {"all": [{"field": "uid", "op": "eq", "value": 0}]})
    assert de.match_rule(item, {"all": [{"field": "signed", "op": "eq", "value": False}]})
    assert de.match_rule(item, {"any": [{"field": "groups", "op": "contains", "value": "wheel"}]})
    assert not de.match_rule(item, {"all": [{"field": "uid", "op": "gt", "value": 0}]})
    assert de.match_rule(item, {"all": [{"field": "path", "op": "exists"}]})
    assert de.match_rule(item, {"all": [{"field": "nope", "op": "absent"}]})
    assert de.match_rule(item, {"all": [{"field": "uid", "op": "in", "value": [0, 1]}]})


def test_policy_check_array_and_object():
    cur = canonicalize(_load("web01_run2.json"))
    rules = [
        {"id": "policy.linux.tmp_exec", "platform": "linux", "category": "processes",
         "severity": "high", "match": {"all": [{"field": "path", "op": "regex", "value": "^/tmp/"}]}},
        {"id": "policy.linux.ld_so_preload", "platform": "linux", "category": "persistence",
         "severity": "critical", "match": {"all": [
             {"field": "mechanism", "op": "eq", "value": "ld_so_preload"},
             {"field": "present", "op": "eq", "value": True}]}},
        {"id": "policy.linux.extra_uid0", "platform": "linux", "category": "users",
         "severity": "critical", "match": {"all": [{"field": "uid", "op": "eq", "value": 0}]}},
    ]
    deltas = de.policy_check(cur, rules)
    rule_ids = {d["rule"] for d in deltas}
    assert "policy.linux.tmp_exec" in rule_ids
    assert "policy.linux.ld_so_preload" in rule_ids
    # extra_uid0 matches root AND bob (both uid 0)
    uid0 = [d for d in deltas if d["rule"] == "policy.linux.extra_uid0"]
    assert len(uid0) == 2


def test_policy_platform_filter():
    cur = canonicalize(_load("web01_run2.json"))
    rules = [{"id": "policy.windows.x", "platform": "windows", "category": "processes",
              "severity": "high", "match": {"all": [{"field": "path", "op": "exists"}]}}]
    assert de.policy_check(cur, rules) == []


# ---------------------------------------------------------------- merge across lenses

def test_temporal_and_policy_merge_to_one_finding():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    temporal = de.diff_documents(prev, cur, "temporal")
    policy = de.policy_check(cur, [
        {"id": "policy.linux.tmp_exec", "platform": "linux", "category": "processes",
         "severity": "critical", "match": {"all": [{"field": "path", "op": "regex", "value": "^/tmp/"}]}}])
    sev_map = {"defaults": {"added": "medium"}, "overrides": []}
    findings = de.assemble(temporal + policy, sev_map, "eng", "2026-07-23T0400Z", {})
    evil = [f for f in findings if f.detail["identity"].get("path") == "/tmp/evil"
            and f.category == "processes"]
    assert len(evil) == 1
    f = evil[0]
    assert set(f.comparison) == {"temporal", "policy"}
    assert f.severity == "critical"          # policy severity wins
    assert f.rule == "policy.linux.tmp_exec"  # most-specific rule wins


def test_drift_only_finding_uses_drift_rule():
    prev = canonicalize(_load("web01_run1.json"))
    cur = canonicalize(_load("web01_run2.json"))
    deltas = de.diff_documents(prev, cur, "temporal")
    sev_map = {"defaults": {"added": "medium", "changed": "medium"}, "overrides": []}
    findings = de.assemble(deltas, sev_map, "eng", "r", {})
    port = [f for f in findings if f.category == "listening"
            and f.detail["identity"].get("port") == 4444]
    assert port and port[0].rule == "drift.linux.listening"


# ---------------------------------------------------------------- fleet outlier

def _mini(host, extra_procs):
    base = [{"path": "/usr/sbin/sshd", "sha256": "bbb", "user": "root", "args_norm": "sshd"}]
    return {"meta": {"platform": "linux", "host": host}, "processes": base + extra_procs}


def test_fleet_outlier_flags_rare_item():
    docs = {}
    groups = {}
    for i in range(25):
        host = f"h{i:02d}"
        extra = []
        if i < 2:  # only 2/25 = 8% ... need <=5% -> make it 1/25
            pass
        docs[host] = _mini(host, extra)
        groups[host] = ["fleet"]
    # put a rare binary on exactly 1 host (1/25 = 4% <= 5%)
    docs["h00"]["processes"].append(
        {"path": "/opt/rare", "sha256": "r", "user": "root", "args_norm": "rare"})
    canon = {h: canonicalize(d) for h, d in docs.items()}
    settings = {"outlier_max_prevalence": 0.05, "outlier_min_group": 20}
    deltas = de.fleet_outliers(canon, groups, settings)
    rare = [d for d in deltas if d["identity"].get("path") == "/opt/rare"]
    assert len(rare) == 1
    assert rare[0]["host"] == "h00"
    assert rare[0]["lens"] == "fleet_outlier"
    assert rare[0]["prevalence"] <= 0.05


def test_fleet_outlier_skips_small_groups():
    docs = {f"h{i}": canonicalize(_mini(f"h{i}", [])) for i in range(5)}
    docs["h0"]["processes"].append({"path": "/opt/rare", "sha256": "r", "user": "root", "args_norm": "x"})
    groups = {h: ["fleet"] for h in docs}
    deltas = de.fleet_outliers(docs, groups, {"outlier_min_group": 20})
    assert deltas == []  # group too small


def test_fleet_outlier_ignores_common_item():
    docs = {}
    groups = {}
    for i in range(25):
        h = f"h{i:02d}"
        docs[h] = canonicalize(_mini(h, []))  # sshd on everyone
        groups[h] = ["fleet"]
    deltas = de.fleet_outliers(docs, groups, {"outlier_max_prevalence": 0.05, "outlier_min_group": 20})
    assert not any(d["identity"].get("path") == "/usr/sbin/sshd" for d in deltas)


# ---------------------------------------------------------------- severity + collector_self

def test_collector_self_caps_severity_to_info():
    delta = de._delta("linux", "processes", "added", {"path": "/usr/bin/backup"},
                      None, {"path": "/usr/bin/backup"}, "web01", "temporal",
                      collector_self=True)
    sev_map = {"defaults": {"added": "high"}, "overrides": []}
    findings = de.assemble([delta], sev_map, "eng", "r", {})
    assert findings[0].severity == "info"


def test_severity_map_override():
    sev_map = {"defaults": {"added": "medium"},
               "overrides": [{"platform": "windows", "category": "services",
                              "change_type": "added", "severity": "high"}]}
    assert de.base_severity(sev_map, "windows", "services", "added") == "high"
    assert de.base_severity(sev_map, "linux", "services", "added") == "medium"


# ---------------------------------------------------------------- suppression

def test_suppression_marks_and_respects_expiry():
    f = dc.Finding("f-1", "eng", "2026-07-23T0400Z", "high", "drift.windows.scheduled_tasks",
                   "windows", "scheduled_tasks", "added", hosts=["WIN01"],
                   detail={"identity": {"task_path": "\\GoogleUpdateTaskMachineCore"},
                           "after": {"task_path": "\\GoogleUpdateTaskMachineCore"}})
    active = {"id": "allow-goog", "expires": "2026-08-15", "scope": {},
              "match": {"all": [{"field": "task_path", "op": "regex", "value": "^\\\\GoogleUpdateTask"}]}}
    expired = dict(active, id="allow-old", expires="2026-01-01")
    groups = {"WIN01": ["win_workstations"]}
    warnings = de.apply_suppression([f], [active], groups, "2026-07-23T0400Z")
    assert f.suppressed and f.suppressed_by == "allow-goog"
    # expired entry ignored + warned
    f.suppressed = False
    f.suppressed_by = None
    warns = de.apply_suppression([f], [expired], groups, "2026-07-23T0400Z")
    assert not f.suppressed
    assert any("expired" in w for w in warns)


def test_suppression_scope_by_group():
    f = dc.Finding("f-1", "eng", "r", "high", "drift.linux.packages", "linux", "packages",
                   "added", hosts=["web01"], detail={"identity": {"name": "curl"}, "after": {"name": "curl"}})
    entry = {"id": "a", "expires": "2999-01-01", "scope": {"groups": ["windows"]},
             "match": {"all": [{"field": "name", "op": "eq", "value": "curl"}]}}
    de.apply_suppression([f], [entry], {"web01": ["linux"]}, "2026-07-23T0400Z")
    assert not f.suppressed  # scoped to a group web01 isn't in


# ---------------------------------------------------------------- coverage gaps

def test_coverage_gaps_from_run_status():
    status = {"hosts": {
        "down01": {"status": "unreachable", "platform": "linux"},
        "part01": {"status": "partial", "platform": "windows", "failed_categories": ["drivers"]},
    }, "no_transport": ["win-ws-7"], "t3_only": ["oddvendor-sw"]}
    deltas = de.coverage_gaps(status, "eng", "r")
    rules = {d["rule"] for d in deltas}
    assert "coverage.host_unreachable" in rules
    assert "coverage.partial_snapshot" in rules
    assert "coverage.category_failed" in rules
    assert "coverage.no_transport" in rules
    assert "coverage.t3_only" in rules
    assert all(d["change_type"] == "coverage_gap" for d in deltas)


# ---------------------------------------------------------------- full run()

def _build_engagement(tmp_path):
    import yaml
    eng = tmp_path / "eng"
    (eng / "snapshots" / "web01").mkdir(parents=True)
    (eng / "inventory").mkdir(parents=True)
    (eng / "scope.yml").write_text(yaml.safe_dump({
        "engagement": "test-2026-07", "in_scope": [{"cidr": "10.0.0.0/8", "groups": ["linux"]}],
        "settings": {"collector_account": "svc-driftwatch",
                     "outlier_max_prevalence": 0.05, "outlier_min_group": 20}}))
    (eng / "inventory" / "fleet_groups.json").write_text(json.dumps({"web01": ["linux"]}))
    for name, rid in (("web01_run1.json", "2026-07-22T0400Z"), ("web01_run2.json", "2026-07-23T0400Z")):
        (eng / "snapshots" / "web01" / f"{rid}.json").write_text((FIX / name).read_text())
    return eng


def _write_rules(tmp_path):
    import yaml
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "policy_checks.yml").write_text(yaml.safe_dump({"rules": [
        {"id": "policy.linux.tmp_exec", "platform": "linux", "category": "processes",
         "severity": "critical", "match": {"all": [{"field": "path", "op": "regex", "value": "^/tmp/"}]}},
        {"id": "policy.linux.ld_so_preload", "platform": "linux", "category": "persistence",
         "severity": "critical", "description": "ld.so.preload present",
         "match": {"all": [{"field": "mechanism", "op": "eq", "value": "ld_so_preload"}]}},
        {"id": "policy.linux.new_root_ca", "platform": "linux", "category": "dns_trust",
         "severity": "critical", "match": {"all": [{"field": "kind", "op": "eq", "value": "ca_cert"}]}},
    ]}))
    (rules_dir / "severity_map.yml").write_text(yaml.safe_dump({
        "defaults": {"added": "medium", "removed": "low", "changed": "medium", "coverage_gap": "high"},
        "overrides": []}))
    (rules_dir / "normalize_patterns.yml").write_text(yaml.safe_dump({"patterns": []}))
    return rules_dir


def test_full_run_end_to_end(tmp_path):
    eng = _build_engagement(tmp_path)
    rules_dir = _write_rules(tmp_path)
    allow_dir = tmp_path / "allowlists"
    allow_dir.mkdir()

    summary = de.run(eng, "2026-07-23T0400Z", rules_dir, allow_dir)
    assert summary["findings_total"] > 0

    findings = dc.load_ndjson(eng / "findings" / "2026-07-23T0400Z.ndjson")
    by_rule = {f["rule"]: f for f in findings}

    # policy hits present
    assert "policy.linux.tmp_exec" in by_rule
    assert "policy.linux.ld_so_preload" in by_rule
    assert "policy.linux.new_root_ca" in by_rule

    # the /tmp/evil process is one finding, critical, caught by temporal+policy
    evil = by_rule["policy.linux.tmp_exec"]
    assert evil["severity"] == "critical"
    assert set(evil["comparison"]) == {"temporal", "policy"}
    assert evil["hosts"] == ["web01"]

    # findings sorted by severity; ids assigned
    assert findings[0]["finding_id"].startswith("f-2026-07-23T0400Z-")
    sevs = [dc.severity_rank(f["severity"]) for f in findings]
    assert sevs == sorted(sevs)

    # first_seen persisted in state.json
    state = json.loads((eng / "findings" / "state.json").read_text())
    assert state


def test_full_run_first_seen_persists_across_runs(tmp_path):
    eng = _build_engagement(tmp_path)
    rules_dir = _write_rules(tmp_path)
    allow_dir = tmp_path / "allowlists"
    allow_dir.mkdir()
    # Seed state as if a fingerprint was first seen in an earlier run.
    de.run(eng, "2026-07-23T0400Z", rules_dir, allow_dir)
    findings = dc.load_ndjson(eng / "findings" / "2026-07-23T0400Z.ndjson")
    for f in findings:
        assert f["first_seen"] == "2026-07-23T0400Z"
    # Re-run same run_id: first_seen must stay stable (idempotent).
    de.run(eng, "2026-07-23T0400Z", rules_dir, allow_dir)
    findings2 = dc.load_ndjson(eng / "findings" / "2026-07-23T0400Z.ndjson")
    assert {f["fingerprint"]: f["first_seen"] for f in findings} == \
           {f["fingerprint"]: f["first_seen"] for f in findings2}
