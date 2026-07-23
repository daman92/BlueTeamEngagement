"""scope_gate — the authorization rail (design §15.2).

Scope is checked in depth and ALWAYS fails closed (default deny). This module
implements two of the four layers from the design:

  Layer 1 (inventory generation): `generate` builds inventory/hosts.yml and
    fleet_groups.json purely from scope.yml's in_scope allow-list. An out-of-scope
    address cannot enter the inventory, so it is never addressable.
  Layer 2 (pre-flight gate): `assert-run` validates a resolved target list before
    any play executes. ANY out-of-scope or ambiguous target aborts the WHOLE run
    (exit 2) and is appended to the engagement audit.log — it never skips-and-continues.

Layers 3 (host egress firewall) and 4 (credential scoping) are enforced outside this
tool (kit firewall + handed-over account restrictions); `preflight` documents them.

Usage:
  scope_gate.py generate  --engagement-dir D
  scope_gate.py check     --engagement-dir D --ip IP          (exit 0 in / 2 out)
  scope_gate.py assert-run --engagement-dir D --targets-file F [--operator NAME]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


class ScopeError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_scope(engagement_dir: Path) -> dict:
    scope_path = engagement_dir / "scope.yml"
    if not scope_path.exists():
        raise ScopeError(f"no scope.yml in {engagement_dir}")
    with open(scope_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not data.get("in_scope"):
        # Fail closed: an empty scope authorizes nothing, it does not authorize everything.
        raise ScopeError("scope.yml has no in_scope entries — nothing is authorized")
    return data


def audit(engagement_dir: Path, line: str) -> None:
    with open(engagement_dir / "audit.log", "a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{_now_iso()} | {line}\n")


class Scope:
    """Compiled scope: fast membership test with explicit deny precedence."""

    def __init__(self, data: dict):
        self.data = data
        self._allow_nets: list[ipaddress._BaseNetwork] = []
        self._allow_hosts: dict[str, dict] = {}   # ip -> entry
        self._deny_nets: list[ipaddress._BaseNetwork] = []
        self._deny_hosts: set[str] = set()

        for entry in data.get("in_scope", []) or []:
            if "cidr" in entry:
                self._allow_nets.append(ipaddress.ip_network(entry["cidr"], strict=False))
            if entry.get("ip"):
                self._allow_hosts[str(ipaddress.ip_address(entry["ip"]))] = entry
        for entry in data.get("deny", []) or []:
            if "cidr" in entry:
                self._deny_nets.append(ipaddress.ip_network(entry["cidr"], strict=False))
            if entry.get("ip"):
                self._deny_hosts.add(str(ipaddress.ip_address(entry["ip"])))

    def is_in_scope(self, ip_str: str) -> bool:
        """True only if affirmatively allowed and not denied. Deny wins. Fails closed
        on unparseable input."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False  # ambiguous / non-IP => not affirmatively in scope
        canon = str(ip)
        if canon in self._deny_hosts or any(ip in net for net in self._deny_nets):
            return False
        if canon in self._allow_hosts:
            return True
        return any(ip in net for net in self._allow_nets)

    def groups_for_ip(self, ip_str: str) -> list[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return []
        canon = str(ip)
        if canon in self._allow_hosts:
            return list(self._allow_hosts[canon].get("groups", []))
        groups: list[str] = []
        for entry in self.data.get("in_scope", []) or []:
            if "cidr" in entry and ip in ipaddress.ip_network(entry["cidr"], strict=False):
                for g in entry.get("groups", []):
                    if g not in groups:
                        groups.append(g)
        return groups

    def oob_subnets(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(c, strict=False) for c in self.data.get("oob_subnets", []) or []]

    def is_oob(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self.oob_subnets())


# ---- inventory generation (layer 1) ----------------------------------------

def build_inventory(scope: Scope) -> tuple[dict, dict]:
    """Return (ansible_inventory_dict, fleet_groups_dict).

    Only explicit `host`/`ip` entries become inventory hosts — a bare CIDR declares
    an authorized *range* but not specific machines (those are discovered during
    collection and must be added explicitly before they are touched, per §15.2
    discovery != access). fleet_groups maps hostname -> [groups] for the Python side.
    """
    all_children: dict = {}
    fleet_groups: dict[str, list[str]] = {}

    def ensure_group(name: str) -> dict:
        grp = all_children.setdefault(name, {"hosts": {}})
        grp.setdefault("hosts", {})
        return grp

    for entry in scope.data.get("in_scope", []) or []:
        host = entry.get("host")
        ip = entry.get("ip")
        if not host and not ip:
            continue  # CIDR-only range: authorized, not yet an addressable host
        name = host or ip
        groups = entry.get("groups", []) or ["ungrouped"]
        hostvars = {}
        if ip:
            hostvars["ansible_host"] = ip
        for g in groups:
            ensure_group(g)["hosts"][name] = hostvars or None
        fleet_groups[name] = list(groups)

    inventory = {"all": {"children": {g: v for g, v in all_children.items()}}}
    return inventory, fleet_groups


def cmd_generate(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    scope = Scope(load_scope(engagement_dir))
    inventory, fleet_groups = build_inventory(scope)

    inv_dir = engagement_dir / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)
    with open(inv_dir / "hosts.yml", "w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(inventory, fh, default_flow_style=False, sort_keys=True)
    with open(inv_dir / "fleet_groups.json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(fleet_groups, fh, indent=2, sort_keys=True)

    audit(engagement_dir, f"scope | generate | hosts={len(fleet_groups)} | outcome=ok")
    print(f"generated inventory: {len(fleet_groups)} explicit host(s) across "
          f"{len(inventory['all']['children'])} group(s)")
    return 0


def cmd_check(args) -> int:
    scope = Scope(load_scope(Path(args.engagement_dir)))
    ok = scope.is_in_scope(args.ip)
    print(f"{args.ip}: {'IN SCOPE' if ok else 'OUT OF SCOPE'}")
    return 0 if ok else 2


def _read_targets(path: Path) -> list[str]:
    """Accept a plain list (one target per line) or a JSON list of {name?, ip}."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] in "[{":
        data = json.loads(text)
        out = []
        for item in data:
            if isinstance(item, dict):
                out.append(str(item.get("ip") or item.get("name")))
            else:
                out.append(str(item))
        return out
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def cmd_assert_run(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    scope = Scope(load_scope(engagement_dir))
    targets = _read_targets(Path(args.targets_file))
    operator = args.operator or "unknown"

    violations = [t for t in targets if not scope.is_in_scope(t)]
    if violations:
        for v in violations:
            audit(engagement_dir,
                  f"scope | assert-run | operator={operator} | DENY target={v} | outcome=ABORT")
        sys.stderr.write(
            "SCOPE VIOLATION — run aborted. Not affirmatively in scope:\n  "
            + "\n  ".join(violations)
            + "\nAdd them to scope.yml (a deliberate act) or remove them from the run.\n")
        return 2

    audit(engagement_dir,
          f"scope | assert-run | operator={operator} | targets={len(targets)} | outcome=ok")
    print(f"scope OK: all {len(targets)} target(s) in scope")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="scope_gate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("generate", "check", "assert-run"):
        p = sub.add_parser(name)
        p.add_argument("--engagement-dir", required=True)
        if name == "check":
            p.add_argument("--ip", required=True)
        if name == "assert-run":
            p.add_argument("--targets-file", required=True)
            p.add_argument("--operator")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "generate":
            return cmd_generate(args)
        if args.cmd == "check":
            return cmd_check(args)
        if args.cmd == "assert-run":
            return cmd_assert_run(args)
    except ScopeError as exc:
        sys.stderr.write(f"scope error: {exc}\n")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
