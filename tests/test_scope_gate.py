import json

import pytest

import scope_gate
from scope_gate import Scope, ScopeError


SCOPE = {
    "engagement": "t", "client": "T", "authorized_by": "x",
    "in_scope": [
        {"cidr": "10.10.0.0/16", "groups": ["linux"]},
        {"host": "dc01", "ip": "10.10.1.5", "groups": ["windows", "crown_jewels"]},
    ],
    "deny": [{"cidr": "10.10.99.0/24"}],
    "oob_subnets": ["10.99.0.0/24"],
}


def test_in_scope_and_deny_precedence():
    s = Scope(SCOPE)
    assert s.is_in_scope("10.10.1.5")
    assert s.is_in_scope("10.10.5.5")       # inside allowed cidr
    assert not s.is_in_scope("10.10.99.5")  # denied subnet wins
    assert not s.is_in_scope("8.8.8.8")     # not in any allow


def test_fail_closed_on_garbage_ip():
    s = Scope(SCOPE)
    assert not s.is_in_scope("not-an-ip")
    assert not s.is_in_scope("")


def test_groups_for_ip():
    s = Scope(SCOPE)
    assert set(s.groups_for_ip("10.10.1.5")) == {"windows", "crown_jewels"}
    assert s.groups_for_ip("10.10.5.5") == ["linux"]


def test_oob_detection():
    s = Scope(SCOPE)
    assert s.is_oob("10.99.0.5")
    assert not s.is_oob("10.10.1.5")


def test_build_inventory_only_explicit_hosts(tmp_path):
    s = Scope(SCOPE)
    inv, groups = scope_gate.build_inventory(s)
    # CIDR-only range does not create a host; explicit dc01 does
    assert "dc01" in groups
    assert groups["dc01"] == ["windows", "crown_jewels"]
    assert "windows" in inv["all"]["children"]
    assert inv["all"]["children"]["windows"]["hosts"]["dc01"]["ansible_host"] == "10.10.1.5"


def _write_scope(tmp_path, data):
    import yaml
    (tmp_path / "scope.yml").write_text(yaml.safe_dump(data))
    return tmp_path


def test_generate_writes_inventory_and_audit(tmp_path):
    d = _write_scope(tmp_path, SCOPE)
    rc = scope_gate.main(["generate", "--engagement-dir", str(d)])
    assert rc == 0
    fg = json.loads((d / "inventory" / "fleet_groups.json").read_text())
    assert "dc01" in fg
    assert "generate" in (d / "audit.log").read_text()


def test_assert_run_aborts_on_out_of_scope(tmp_path):
    d = _write_scope(tmp_path, SCOPE)
    (tmp_path / "t.txt").write_text("10.10.1.5\n8.8.8.8\n")
    rc = scope_gate.main(["assert-run", "--engagement-dir", str(d),
                          "--targets-file", str(tmp_path / "t.txt"), "--operator", "brian"])
    assert rc == 2
    log = (d / "audit.log").read_text()
    assert "DENY target=8.8.8.8" in log and "ABORT" in log


def test_assert_run_passes_when_all_in_scope(tmp_path):
    d = _write_scope(tmp_path, SCOPE)
    (tmp_path / "t.txt").write_text("10.10.1.5\n10.10.2.2\n")
    rc = scope_gate.main(["assert-run", "--engagement-dir", str(d),
                          "--targets-file", str(tmp_path / "t.txt")])
    assert rc == 0


def test_load_scope_rejects_empty_in_scope(tmp_path):
    _write_scope(tmp_path, {"engagement": "t", "in_scope": []})
    with pytest.raises(ScopeError):
        scope_gate.load_scope(tmp_path)
