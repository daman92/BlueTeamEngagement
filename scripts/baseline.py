"""baseline — promote a collected snapshot to a golden baseline (design §8).

The baseline lifecycle: the first good snapshot of a host is a *candidate*; an analyst
reviews it and **promotes** it to golden, and expected drift (patch Tuesday, approved
deploys) is later absorbed by re-promoting a post-change snapshot that references its
change ticket — never by silently editing a baseline. ``promote`` implements that step.

  promote --engagement-dir D --host H --run-id R [--ticket T] [--note N] [--force]

It copies ``snapshots/<host>/<run_id>.json`` to ``baselines/<host>.json`` (the exact path
``diff_engine`` reads for the baseline lens), adding a provenance block under ``meta``:

  meta.provenance = {promoted_at, promoted_from_run, ticket, note}

A partial snapshot (``meta.partial: true``) is REFUSED (exit 2) unless ``--force`` — baking
a snapshot with known collection gaps into the golden state would make every future diff
lie about coverage. Every promotion (and every refusal) is appended to ``audit.log``.

Exit codes: 0 promoted · 1 error (missing/unreadable snapshot) · 2 refusal (partial without
``--force``). Library entry point: ``promote()``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


class PromoteError(Exception):
    """A promotion could not be performed (missing/unreadable source, etc.)."""


class PartialRefusal(Exception):
    """The source snapshot is partial and --force was not given."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit(engagement_dir: Path, line: str) -> None:
    """Append one line to the engagement's append-only audit.log (best-effort)."""
    try:
        with open(engagement_dir / "audit.log", "a", encoding="utf-8", newline="\n") as fh:
            fh.write(f"{_now_iso()} | {line}\n")
    except OSError:
        pass


def promote(engagement_dir: Path, host: str, run_id: str, ticket: str | None = None,
            note: str = "", force: bool = False, operator: str = "unknown") -> str:
    """Promote snapshots/<host>/<run_id>.json to baselines/<host>.json with provenance.

    Returns a one-paragraph human summary. Raises PartialRefusal (=> exit 2) or
    PromoteError / FileNotFoundError / json.JSONDecodeError (=> exit 1)."""
    src = engagement_dir / "snapshots" / host / f"{run_id}.json"
    if not src.exists():
        raise PromoteError(f"no snapshot to promote at {src}")
    with open(src, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise PromoteError(f"snapshot {src} is not a JSON object")

    meta = doc.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise PromoteError(f"snapshot {src} has a non-object 'meta'")
    partial = bool(meta.get("partial"))

    if partial and not force:
        failed = meta.get("failed_categories", [])
        _audit(engagement_dir,
               f"baseline | promote | host={host} | from_run={run_id} | "
               f"ticket={ticket or '-'} | partial=true | operator={operator} | outcome=REFUSED")
        raise PartialRefusal(
            f"REFUSED: snapshot {run_id} for host '{host}' is marked meta.partial=true "
            f"(failed_categories={failed}). Promoting it would bake collection gaps into the "
            f"golden baseline, so every future diff would under-report coverage. Re-collect a "
            f"complete snapshot, or pass --force to promote this partial snapshot deliberately.")

    # Provenance block (all four keys always present). When forced over a partial snapshot,
    # record that fact in the note so the baseline stays honest about how it was made.
    prov_note = note or ""
    if partial and force:
        forced = "promoted from a PARTIAL snapshot via --force"
        prov_note = f"{forced}; {prov_note}" if prov_note else forced
    meta["provenance"] = {
        "promoted_at": _now_iso(),
        "promoted_from_run": run_id,
        "ticket": ticket,
        "note": prov_note,
    }

    baselines_dir = engagement_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    dst = baselines_dir / f"{host}.json"
    replaced = dst.exists()
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")

    _audit(engagement_dir,
           f"baseline | promote | host={host} | from_run={run_id} | ticket={ticket or '-'} | "
           f"partial={str(partial).lower()} | forced={str(partial and force).lower()} | "
           f"operator={operator} | outcome=ok")

    summary = (
        f"Promoted snapshot {run_id} for host '{host}' to the golden baseline at {dst} "
        f"({'replacing the previous baseline' if replaced else 'a new baseline'}). "
        f"Provenance recorded under meta.provenance: promoted_at="
        f"{meta['provenance']['promoted_at']}, promoted_from_run={run_id}, "
        f"ticket={ticket or 'none'}"
        + (f", note=\"{prov_note}\"" if prov_note else "")
        + (". The source snapshot was partial and was promoted anyway via --force."
           if (partial and force) else ".")
        + " The promotion was appended to audit.log; diff_engine will now compare each new "
          f"'{host}' snapshot against this baseline."
    )
    return summary


def cmd_promote(args) -> int:
    engagement_dir = Path(args.engagement_dir)
    try:
        summary = promote(
            engagement_dir, args.host, args.run_id, ticket=args.ticket,
            note=args.note, force=args.force, operator=args.operator or "unknown")
    except PartialRefusal as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    except (PromoteError, FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    print(summary)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="baseline")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("promote")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--ticket")
    p.add_argument("--note", default="",
                   help="free-text reason recorded in meta.provenance.note")
    p.add_argument("--force", action="store_true",
                   help="promote even if the source snapshot is meta.partial=true")
    p.add_argument("--operator", help="operator name recorded in audit.log")
    args = parser.parse_args(argv)
    if args.cmd == "promote":
        return cmd_promote(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
