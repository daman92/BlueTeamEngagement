import json

import pytest

import driftwatch_common as dc


def test_canonical_json_is_sorted_and_compact():
    assert dc.canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_fingerprint_excludes_rule_and_lens():
    ident = {"path": "/tmp/evil", "sha256": "e"}
    a = dc.finding_fingerprint("linux", "processes", "added", ident)
    b = dc.finding_fingerprint("linux", "processes", "added", ident)
    assert a == b and len(a) == 16
    # identity change => different fingerprint
    c = dc.finding_fingerprint("linux", "processes", "added", {"path": "/tmp/other"})
    assert c != a


def test_identity_tuple_stable_for_nested_values():
    spec = dc.CategorySpec("array", ("name", "groups"))
    item = {"name": "bob", "groups": ["a", "b"]}
    t = dc.identity_tuple(item, spec)
    assert t[0] == "bob"
    # list is made hashable via canonical json
    assert isinstance(t[1], str)
    assert dc.identity_tuple(item, spec) == dc.identity_tuple(dict(item), spec)


def test_finding_validates_severity_and_change_type():
    with pytest.raises(ValueError):
        dc.Finding("f", "e", "r", "not-a-sev", "rule", "linux", "processes", "added")
    with pytest.raises(ValueError):
        dc.Finding("f", "e", "r", "high", "rule", "linux", "processes", "not-a-change")


def test_finding_autofills_fingerprint_and_sorts_hosts():
    f = dc.Finding("f-1", "eng", "run", "high", "drift.linux.processes", "linux",
                   "processes", "added", hosts=["z", "a"],
                   detail={"identity": {"path": "/x"}})
    d = f.to_dict()
    assert d["hosts"] == ["a", "z"]
    assert len(d["fingerprint"]) == 16


def test_severity_rank_orders_critical_first():
    assert dc.severity_rank("critical") < dc.severity_rank("high") < dc.severity_rank("info")


def test_ndjson_roundtrip(tmp_path):
    recs = [{"a": 1}, {"b": 2}]
    p = tmp_path / "x.ndjson"
    dc.dump_ndjson(recs, p)
    assert dc.load_ndjson(p) == recs
    # each line is canonical json
    lines = p.read_text().strip().splitlines()
    assert lines[0] == '{"a":1}'


def test_every_category_spec_is_wellformed():
    for platform, cats in dc.CATEGORY_SPECS.items():
        assert platform in dc.PLATFORMS
        for name, spec in cats.items():
            assert spec.kind in ("array", "object")
            if spec.kind == "array":
                assert spec.identity, f"{platform}.{name} array needs an identity"
            # volatile fields must not also be identity fields
            assert not (set(spec.identity) & set(spec.volatile))
