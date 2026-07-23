import json
from pathlib import Path

import normalize
import driftwatch_common as dc

FIX = Path(__file__).parent / "fixtures" / "diff"


def _load(name):
    return json.loads((FIX / name).read_text())


def test_canonicalize_sorts_arrays_by_identity():
    doc = {"meta": {"platform": "linux"},
           "listening": [
               {"proto": "tcp", "port": 443, "path": "/b", "pid": 2},
               {"proto": "tcp", "port": 22, "path": "/a", "pid": 1}]}
    out = normalize.canonicalize(doc)
    ports = [x["port"] for x in out["listening"]]
    assert ports == [22, 443]  # sorted by identity (proto, port, path)


def test_canonicalize_strips_volatile_fields():
    doc = _load("web01_run1.json")
    out = normalize.canonicalize(doc)
    for proc in out["processes"]:
        assert "pid" not in proc and "ppid" not in proc and "started" not in proc
        assert "path" in proc  # non-volatile kept


def test_canonicalize_is_idempotent():
    doc = _load("web01_run2.json")
    once = normalize.canonicalize(doc)
    twice = normalize.canonicalize(once)
    assert dc.canonical_json(once) == dc.canonical_json(twice)


def test_canonicalize_does_not_mutate_input():
    doc = _load("web01_run1.json")
    before = dc.canonical_json(doc)
    normalize.canonicalize(doc)
    assert dc.canonical_json(doc) == before


def test_args_norm_patterns_applied():
    doc = {"meta": {"platform": "linux"},
           "processes": [{"path": "/x", "sha256": "h", "user": "root",
                          "args_norm": "run 12345678 /tmp/xyz abc"}]}
    out = normalize.canonicalize(doc)
    an = out["processes"][0]["args_norm"]
    assert "<NUM>" in an and "<TMPPATH>" in an


def test_collector_self_tagging_matches_account():
    doc = _load("web01_run1.json")
    out = normalize.canonicalize(doc, collector_account="svc-driftwatch")
    backups = [p for p in out["processes"] if p["path"] == "/usr/bin/backup"]
    assert backups and backups[0].get("collector_self") is True
    nginx = [p for p in out["processes"] if p["path"] == "/usr/sbin/nginx"]
    assert "collector_self" not in nginx[0]


def test_object_category_volatile_strip():
    doc = {"meta": {"platform": "network"},
           "l2_state": {"stp_root": {"1": "aaaa"}, "mac_count_per_vlan": {"1": 50}}}
    out = normalize.canonicalize(doc)
    assert "mac_count_per_vlan" not in out["l2_state"]
    assert "stp_root" in out["l2_state"]
