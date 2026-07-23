"""driftwatch_common — shared contracts for all control-node Python.

This module is the machine-readable form of docs/CONTRACTS.md §3–§4. Every other
script imports category specs, severity constants, and finding helpers from here;
nothing may re-declare them. Keep it stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0"
COLLECTOR_VERSION = "driftwatch 0.1.0"

SEVERITIES = ("critical", "high", "medium", "low", "info")
# change_type is what happened to the item; the LENS that caught it (temporal / baseline /
# fleet_outlier / policy) is recorded separately in a finding's `comparison` list, so the
# same drift seen through several lenses merges into one finding.
CHANGE_TYPES = ("added", "removed", "changed", "coverage_gap")
COMPARISON_MODES = ("temporal", "baseline", "fleet_outlier", "policy")
PLATFORMS = ("linux", "windows", "network", "ad")

RUN_ID_FORMAT = "%Y-%m-%dT%H%MZ"  # UTC, e.g. 2026-07-22T0400Z


@dataclass(frozen=True)
class CategorySpec:
    """Diff semantics for one snapshot category.

    kind: "array" (list of items) or "object" (single dict).
    identity: fields whose tuple defines item sameness (array kinds only).
    volatile: fields stripped before comparison. For object kinds these are
      top-level keys (dot-paths allowed one level deep, e.g. "l2_state" keys).
    All remaining fields are compared attributes; a difference => "changed".
    """

    kind: str
    identity: tuple[str, ...] = ()
    volatile: tuple[str, ...] = ()


A, O = "array", "object"

CATEGORY_SPECS: dict[str, dict[str, CategorySpec]] = {
    "linux": {
        "processes": CategorySpec(A, ("path", "sha256", "user", "args_norm"), ("pid", "ppid", "started")),
        "fileless": CategorySpec(A, ("indicator", "path", "user"), ("pid",)),
        "listening": CategorySpec(A, ("proto", "port", "path"), ("pid",)),
        "connections": CategorySpec(A, ("path", "remote_ip", "remote_port", "proto"), ("count",)),
        "cron": CategorySpec(A, ("source", "user", "schedule", "command")),
        "systemd_units": CategorySpec(A, ("kind", "name"), ("next_run", "last_run")),
        "persistence": CategorySpec(A, ("mechanism", "path")),
        "users": CategorySpec(A, ("name", "uid"), ("last_login",)),
        "groups": CategorySpec(A, ("name", "gid")),
        "ssh_keys": CategorySpec(A, ("user", "fingerprint")),
        "ssh_config": CategorySpec(O),
        "sudoers": CategorySpec(A, ("file",)),
        "kernel_modules": CategorySpec(A, ("name",), ("size", "used_by")),
        "kernel_state": CategorySpec(O),
        "packages": CategorySpec(A, ("name", "arch")),
        "file_integrity": CategorySpec(A, ("kind", "path")),
        "firewall": CategorySpec(A, ("rule",)),
        "dns_trust": CategorySpec(A, ("kind", "key")),
        "shares": CategorySpec(A, ("kind", "name")),
        "logging_health": CategorySpec(O),
    },
    "windows": {
        "processes": CategorySpec(A, ("path", "sha256", "owner", "cmdline_norm"), ("pid", "ppid", "started")),
        "fileless": CategorySpec(A, ("indicator", "detail"), ("pid",)),
        "listening": CategorySpec(A, ("proto", "port", "path"), ("pid",)),
        "connections": CategorySpec(A, ("path", "remote_ip", "remote_port", "proto"), ("count",)),
        "scheduled_tasks": CategorySpec(A, ("task_path", "action_exe", "action_args", "principal"), ("last_run", "next_run")),
        "services": CategorySpec(A, ("name",), ("state",)),
        "autoruns": CategorySpec(A, ("location", "name", "command")),
        "wmi_subscriptions": CategorySpec(A, ("kind", "name")),
        "users": CategorySpec(A, ("sid",), ("last_logon",)),
        "local_groups": CategorySpec(A, ("group", "member_sid")),
        "drivers": CategorySpec(A, ("name", "path")),
        "software": CategorySpec(A, ("name",)),
        "hotfixes": CategorySpec(A, ("hotfix_id",)),
        "firewall": CategorySpec(A, ("direction", "action", "program", "port", "profile")),
        "dns_trust": CategorySpec(A, ("kind", "key")),
        "audit_logging": CategorySpec(O),
        "shares": CategorySpec(A, ("name",)),
        "powershell_surface": CategorySpec(O),
        "security_posture": CategorySpec(O),
    },
    "ad": {
        "ad_admins": CategorySpec(A, ("object_sid",), ("last_logon_ts",)),
        "ad_privileged_groups": CategorySpec(A, ("group", "member_sid")),
        "ad_gpos": CategorySpec(A, ("guid",)),
        "ad_dcsync": CategorySpec(A, ("sid",)),
        "ad_delegation": CategorySpec(A, ("kind", "sid")),
        "ad_kerberoastable": CategorySpec(A, ("sam",)),
        "ad_krbtgt": CategorySpec(O),
        "ad_adminsdholder": CategorySpec(O),
    },
    "network": {
        "device_config": CategorySpec(O),
        "config_saved": CategorySpec(O),
        "change_provenance": CategorySpec(O, volatile=("entries",)),
        "local_accounts": CategorySpec(A, ("username",)),
        "aaa": CategorySpec(O),
        "mgmt_services": CategorySpec(A, ("service",)),
        "snmp": CategorySpec(A, ("kind", "key")),
        "logging_time": CategorySpec(O),
        "interfaces": CategorySpec(A, ("name",), ("counters", "last_flap")),
        "tunnels": CategorySpec(A, ("name",)),
        "mirror_sessions": CategorySpec(A, ("session_id",)),
        "l2_state": CategorySpec(O, volatile=("mac_count_per_vlan",)),
        "static_routes": CategorySpec(A, ("prefix", "next_hop")),
        "routing_neighbors": CategorySpec(A, ("protocol", "peer"), ("state", "uptime")),
        "firewall_rules": CategorySpec(A, ("rule_hash",), ("hits",)),
        "nat_rules": CategorySpec(A, ("rule_hash",)),
        "vpn_peers": CategorySpec(A, ("peer",)),
        "software_image": CategorySpec(O),
        "neighbors": CategorySpec(A, ("local_interface", "remote_device")),
        "protection_features": CategorySpec(O),
    },
}


def spec_for(platform: str, category: str) -> CategorySpec | None:
    return CATEGORY_SPECS.get(platform, {}).get(category)


def canonical_json(obj) -> str:
    """Canonical JSON: sorted keys, no whitespace. Used for hashing and comparison."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def identity_tuple(item: dict, spec: CategorySpec) -> tuple:
    """Stable identity tuple for an array item (missing fields -> None)."""
    return tuple(_stable(item.get(f)) for f in spec.identity)


def identity_dict(item: dict, spec: CategorySpec) -> dict:
    return {f: item.get(f) for f in spec.identity}


def _stable(v):
    """Make a field value hashable/sortable for identity tuples."""
    if isinstance(v, (list, dict)):
        return canonical_json(v)
    return v


def sort_key(item: dict, spec: CategorySpec):
    return tuple(canonical_json(x) if not isinstance(x, str) else x for x in identity_tuple(item, spec))


def finding_fingerprint(platform: str, category: str, change_type: str, identity: dict) -> str:
    """Host-independent, lens-independent fingerprint.

    Excludes the rule and the comparison mode deliberately: the same underlying change
    (this item, added, on these hosts) must be ONE finding whether the temporal lens,
    the fleet-outlier lens, or a policy rule surfaced it — the lenses accumulate in the
    finding's `comparison` list, and the most-specific rule wins as an attribute.
    """
    payload = "|".join([platform, category, change_type, canonical_json(identity)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class Finding:
    """One finding, serializable to the NDJSON schema in CONTRACTS.md §4."""

    finding_id: str
    engagement: str
    run_id: str
    severity: str
    rule: str
    platform: str
    category: str
    change_type: str
    hosts: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    first_seen: str = ""
    comparison: list = field(default_factory=list)
    suppressed: bool = False
    suppressed_by: str | None = None
    fingerprint: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if self.change_type not in CHANGE_TYPES:
            raise ValueError(f"invalid change_type {self.change_type!r}")
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                self.platform, self.category, self.change_type,
                self.detail.get("identity", {}),
            )

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "engagement": self.engagement,
            "run_id": self.run_id,
            "severity": self.severity,
            "rule": self.rule,
            "platform": self.platform,
            "category": self.category,
            "change_type": self.change_type,
            "hosts": sorted(self.hosts),
            "detail": self.detail,
            "first_seen": self.first_seen,
            "comparison": self.comparison,
            "suppressed": self.suppressed,
            "suppressed_by": self.suppressed_by,
            "fingerprint": self.fingerprint,
        }


def severity_rank(sev: str) -> int:
    """critical=0 ... info=4 (lower sorts first)."""
    return SEVERITIES.index(sev)


def load_ndjson(path) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def dump_ndjson(records, path) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(canonical_json(rec if isinstance(rec, dict) else rec.to_dict()) + "\n")
