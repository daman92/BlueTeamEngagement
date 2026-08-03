"""check_pins — verify every pinned Galaxy collection in requirements.yml actually exists.

Why this exists: a pin that names a version Galaxy never published fails the whole
`ansible-galaxy collection install -r requirements.yml` run — and it fails on ARRIVAL, on the
client's network, at the moment the kit is supposed to be working. The failure is also
misleading ("Failed to resolve the requested dependencies map"), so it reads like a network
or proxy problem rather than a bad pin.

The pins are deliberately exact (design: a reproducible kit rebuilt per engagement), so
they are only as good as the last time somebody checked them against reality. This does
that check in one command.

Requires network access to galaxy.ansible.com — run it on the BUILD host, not at a client
site. It is deliberately NOT part of the pytest suite, which must stay hermetic and offline.

Usage:
  python3 scripts/check_pins.py check [--requirements requirements.yml] [--latest]

Exit codes: 0 all pins valid · 1 error reaching Galaxy · 2 at least one pin is unpublished.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import _vendor  # noqa: F401  # puts bundled PyYAML on sys.path (offline kit)
import yaml

GALAXY_API = ("https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/"
              "collections/index/{ns}/{name}/versions/?limit=100")
PRERELEASE_RE = re.compile(r"(a|b|rc|dev|alpha|beta)", re.I)


def load_pins(requirements: Path) -> list[tuple[str, str]]:
    """Return [(fqcn, pinned_version), ...] for entries that pin an exact version."""
    data = yaml.safe_load(requirements.read_text(encoding="utf-8")) or {}
    pins = []
    for entry in data.get("collections", []) or []:
        if isinstance(entry, dict) and entry.get("name") and entry.get("version"):
            pins.append((entry["name"], str(entry["version"])))
    return pins


def version_key(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-]", v)[:3])


def published_versions(fqcn: str, timeout: int = 30) -> list[str]:
    ns, name = fqcn.split(".", 1)
    with urllib.request.urlopen(GALAXY_API.format(ns=ns, name=name), timeout=timeout) as resp:
        data = json.load(resp)
    return [d["version"] for d in data.get("data", [])]


def newest_stable(versions: list[str]) -> str:
    stables = [v for v in versions if not PRERELEASE_RE.search(v)]
    return max(stables, key=version_key) if stables else ""


def check(requirements: Path, show_latest: bool = False) -> int:
    pins = load_pins(requirements)
    if not pins:
        sys.stderr.write(f"no pinned collections found in {requirements}\n")
        return 1

    broken: list[tuple[str, str, str]] = []
    header = f"{'collection':<32} {'pinned':<10} {'published':<10}"
    print(header + ("  newest stable" if show_latest else ""))
    print("-" * (len(header) + (16 if show_latest else 0)))

    for fqcn, pinned in pins:
        try:
            versions = published_versions(fqcn)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"error querying Galaxy for {fqcn}: {exc}\n")
            return 1
        exists = pinned in versions
        latest = newest_stable(versions)
        line = f"{fqcn:<32} {pinned:<10} {'yes' if exists else 'NO':<10}"
        if show_latest:
            line += f"  {latest}"
        print(line)
        if not exists:
            broken.append((fqcn, pinned, latest))

    print()
    if broken:
        print("UNPUBLISHED PINS — `ansible-galaxy install -r` will fail on these:")
        for fqcn, pinned, latest in broken:
            print(f"  {fqcn}: {pinned} was never published (newest stable: {latest})")
        return 2
    print(f"all {len(pins)} pins are published on Galaxy")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="check_pins")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check", help="verify pinned collection versions exist on Galaxy")
    p.add_argument("--requirements", default="requirements.yml")
    p.add_argument("--latest", action="store_true",
                   help="also show the newest stable release of each collection")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return check(Path(args.requirements), args.latest)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
