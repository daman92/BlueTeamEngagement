"""normalize — turn raw snapshots into canonical form (design §6).

Canonicalization is deterministic and idempotent:
  * every array category is sorted by its identity tuple;
  * volatile fields are dropped (they stay in the raw on-disk snapshot; normalize
    operates on a copy);
  * args_norm / cmdline_norm get one-time-token regexes from
    rules/normalize_patterns.yml applied;
  * items whose user/owner/account matches settings.collector_account are tagged
    collector_self=true so the diff engine can cap their severity.

The diff engine calls `canonicalize()` directly; the CLI also runs this as a step so
`snapshots/<host>/<run_id>.json` on disk stays raw and auditable while comparisons use
the canonical form.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

import yaml

import driftwatch_common as dc

# Fields that identify the "owning principal" of an item, per platform-agnostic tagging.
_PRINCIPAL_FIELDS = ("user", "owner", "account", "principal", "run_as")


def load_normalize_patterns(rules_dir: Path) -> list[tuple[re.Pattern, str]]:
    path = rules_dir / "normalize_patterns.yml"
    if not path.exists():
        return _default_patterns()
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for item in data.get("patterns", []) or []:
        out.append((re.compile(item["pattern"]), item.get("replace", "")))
    return out or _default_patterns()


def _default_patterns() -> list[tuple[re.Pattern, str]]:
    # NB: no leading \b before a "/" — there is no word boundary between a space and a
    # slash, so \b/tmp would never match a space-preceded path. Longer alternatives first
    # so /var/tmp/x collapses whole, not to /var<TMPPATH>.
    return [
        (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<GUID>"),
        (re.compile(r"(?:/var/tmp|/dev/shm|/tmp)/[^\s\"']+"), "<TMPPATH>"),
        (re.compile(r"(?i)[A-Z]:\\(?:Users|Windows)\\Temp\\[^\s\"']+"), "<TMPPATH>"),
        (re.compile(r"\b\d{6,}\b"), "<NUM>"),  # long counters / one-time numeric tokens
    ]


def _apply_patterns(text: str, patterns) -> str:
    text = " ".join(text.split())  # collapse whitespace
    for pat, repl in patterns:
        text = pat.sub(repl, text)
    return text


def _is_collector_self(item: dict, collector_account: str | None) -> bool:
    if not collector_account:
        return False
    wanted = collector_account.lower()
    for f in _PRINCIPAL_FIELDS:
        val = item.get(f)
        if isinstance(val, str) and val.lower().split("\\")[-1] == wanted.split("\\")[-1]:
            return True
    return False


def canonicalize(doc: dict, patterns=None, collector_account: str | None = None) -> dict:
    """Return a canonical copy of a raw snapshot document. Does not mutate `doc`."""
    if patterns is None:
        patterns = _default_patterns()
    platform = doc.get("meta", {}).get("platform")
    if collector_account is None:
        collector_account = doc.get("meta", {}).get("collector_account")
    out = copy.deepcopy(doc)
    specs = dc.CATEGORY_SPECS.get(platform, {})

    for category, spec in specs.items():
        if category not in out:
            continue
        value = out[category]
        if spec.kind == "array":
            if not isinstance(value, list):
                continue
            items = []
            for item in value:
                if not isinstance(item, dict):
                    continue
                item = _norm_item(item, patterns, collector_account)
                for vf in spec.volatile:
                    item.pop(vf, None)
                items.append(item)
            items.sort(key=lambda it: dc.sort_key(it, spec))
            out[category] = items
        else:  # object
            if not isinstance(value, dict):
                continue
            for vf in spec.volatile:
                value.pop(vf, None)
            out[category] = value
    return out


def _norm_item(item: dict, patterns, collector_account: str | None) -> dict:
    item = dict(item)
    for tok_field in ("args_norm", "cmdline_norm"):
        if isinstance(item.get(tok_field), str):
            item[tok_field] = _apply_patterns(item[tok_field], patterns)
    if _is_collector_self(item, collector_account):
        item["collector_self"] = True
    return item


def cmd_normalize(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    rules_dir = Path(args.rules_dir) if args.rules_dir else Path(__file__).resolve().parent.parent / "rules"
    patterns = load_normalize_patterns(rules_dir)

    scope = {}
    scope_path = engagement_dir / "scope.yml"
    if scope_path.exists():
        with open(scope_path, "r", encoding="utf-8") as fh:
            scope = yaml.safe_load(fh) or {}
    collector_account = (scope.get("settings", {}) or {}).get("collector_account")

    snap_root = engagement_dir / "snapshots"
    hosts = [args.host] if args.host else [p.name for p in snap_root.iterdir() if p.is_dir()]
    count = 0
    for host in hosts:
        raw_path = snap_root / host / f"{args.run_id}.json"
        if not raw_path.exists():
            continue
        with open(raw_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        canon = canonicalize(doc, patterns, collector_account)
        out_dir = snap_root / host / ".canonical"
        out_dir.mkdir(exist_ok=True)
        with open(out_dir / f"{args.run_id}.json", "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dc.canonical_json(canon))
        count += 1
    print(f"normalized {count} snapshot(s) for run {args.run_id}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="normalize")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("normalize")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--host")
    p.add_argument("--rules-dir")
    args = parser.parse_args(argv)
    if args.cmd == "normalize":
        return cmd_normalize(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
