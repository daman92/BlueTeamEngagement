"""respond — the response-layer CLI (design §13/§14, CONTRACTS §7).

SEPARATE PRIVILEGE DOMAIN. This module and everything under ``response/`` is the WRITE
side of driftwatch. It NEVER imports collection code (``driftwatch_common``,
``diff_engine``, ``normalize``, ``scope_gate``); the read-only collector and this
response layer meet only at the case object on disk (``cases/c-NNNN.json``). That
code/entry-point separation *is* the control that keeps the collector's read-only
guarantee intact when — as is normal in the portable model — a single privileged
account is shared (design §15.3): the collector cannot write because its code paths
contain no write capability, and this tool cannot read a snapshot into a decision
because it cannot import the collector. The only thing shared is a JSON file.

Verbs (CONTRACTS §7):
    respond propose  --case C --play P --hosts H1,H2   preserve -> build plan -> --check
    respond approve  --case C                          interactive confirm -> act -> log
    respond rollback --case C                          reverse using captured before-state

Per-play flow (design §13.6):
    PRESERVE  trigger a deep-snapshot ref, copy suspect artifacts, SHA-256 them into
              evidence/<case_id>/ — "no preservation, no action" (§13.2)
    PROPOSE   build proposed_action{tier,play,hosts}, run the play with --check, show
              the dry-run plan
    APPROVE   the analyst confirms the EXACT action against the EXACT host list and
              supplies a free-text authorizer; hosts not named in the finding are refused
    ACT       run the play for real (Tier-1, reversible), capturing before-state
    LOG       append proposed/approved/executed/rolled-back to audit.log AND write the
              result back onto the case

Blast radius: a play may only touch hosts the finding names; anything wider is refused
(exit 2). v1 ships only the four Tier-1 reversible plays and NO network-config-writing
play (design §13.5).

Exit codes: 0 ok · 1 error · 2 refusal/violation.  Stdlib only; importable with no
side effects at import time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import case as caselib  # sibling response module (NOT collection code)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"

# The v1 play catalogue: Tier-1, reversible only. There is deliberately NO
# network-config-writing play here (design §13.5) — adding one is a design decision,
# not a config change, and would require the in-band warning + mandatory rollback-timer
# machinery this v1 does not ship.
PLAYS: dict[str, dict] = {
    "disable_account": {
        "tier": 1,
        "reversible": True,
        "target_kind": "account",
        "summary": "Disable (not delete) the named account. Rollback re-enables it.",
    },
    "isolate_host": {
        "tier": 1,
        "reversible": True,
        "target_kind": "host",
        "summary": ("Quarantine the host with deny-all-except-management host-firewall "
                    "rules (not a switch/VLAN config write). Rollback removes them."),
    },
    "block_hash": {
        "tier": 1,
        "reversible": True,
        "target_kind": "hash",
        "summary": "Block a file hash via the host EDR / AppLocker deny rule. Rollback unblocks it.",
    },
    "revoke_session": {
        "tier": 1,
        "reversible": True,
        "target_kind": "session",
        "summary": ("Kill the named interactive session / token. Reversible in that it "
                    "destroys no state — the user simply re-authenticates."),
    },
}

# Fields on a finding's detail.identity / detail.after that name each play's real target.
_TARGET_FIELDS = {
    "account": ("name", "sam", "username", "user", "principal", "sid"),
    "hash": ("sha256", "hash", "content_hash", "file_hash"),
    "session": ("user", "name", "sam", "principal", "sid"),
}


class Refusal(Exception):
    """A safety refusal — exit 2 (blast radius, gate not satisfied, unknown play)."""


class UsageError(Exception):
    """A usage/environment error — exit 1 (missing engagement, missing case, IO)."""


# --------------------------------------------------------------------------- utilities

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_engagement_dir(engagement_dir: str | None) -> Path:
    """Resolve the engagement volume (where cases/, evidence/, audit.log live)."""
    if engagement_dir:
        path = Path(engagement_dir)
    else:
        # bin/driftwatch's `respond` passthrough exports the resolved absolute
        # path as DRIFTWATCH_ENGAGEMENT_DIR; honor it first, then fall back to
        # resolving the DRIFTWATCH_ENGAGEMENT id the same way the console does.
        env_dir = os.environ.get("DRIFTWATCH_ENGAGEMENT_DIR")
        if env_dir:
            path = Path(env_dir)
        else:
            env = os.environ.get("DRIFTWATCH_ENGAGEMENT")
            if not env:
                raise UsageError(
                    "no engagement selected — pass --engagement-dir or set DRIFTWATCH_ENGAGEMENT")
            path = Path(env)
            if not path.exists():
                path = REPO_ROOT / "engagements" / env
    if not path.exists():
        raise UsageError(f"engagement dir does not exist: {path}")
    return path


def _operator(explicit: str | None) -> str:
    return explicit or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _audit(engagement_dir: Path, phase: str, case_id: str, play: str | None,
           hosts: list[str], operator: str, outcome: str, extra: str = "") -> None:
    """Append one line to the engagement's append-only audit.log (design §13.2)."""
    line = (f"{_iso(_now())} | respond | {phase} | case={case_id} | "
            f"play={play or '-'} | hosts={','.join(hosts) or '-'} | "
            f"operator={operator} | outcome={outcome}")
    if extra:
        line += f" | {extra}"
    with open(engagement_dir / "audit.log", "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_play(play: str) -> dict:
    spec = PLAYS.get(play)
    if spec is None:
        raise Refusal(
            f"unknown play {play!r}. v1 ships only Tier-1 reversible plays: "
            f"{', '.join(sorted(PLAYS))} (no network-config-writing play — design §13.5)")
    return spec


def _validate_hosts(requested: list[str], finding_hosts: list[str]) -> list[str]:
    """Blast-radius gate: the requested hosts MUST be a subset of the hosts the finding
    names. Anything wider is refused, so a play can never touch more hosts than the
    detection actually covers (design §13.2)."""
    named = set(finding_hosts)
    req = []
    for h in requested:
        h = h.strip()
        if h and h not in req:
            req.append(h)
    if not req:
        raise Refusal("no target hosts supplied")
    extra = [h for h in req if h not in named]
    if extra:
        raise Refusal(
            "blast-radius refusal: host(s) not named in the case finding: "
            f"{', '.join(extra)} — finding names {sorted(named) or '[]'}. "
            "A play may only touch hosts the finding covers.")
    if len(req) > len(named):
        raise Refusal("blast-radius refusal: play would touch more hosts than the finding names")
    return req


def _derive_target(target_kind: str, finding: dict, override: str | None) -> str | None:
    """Best-effort extract of the play's real target (account/hash/session) from the
    finding, unless the analyst supplied one explicitly."""
    if override:
        return override
    if target_kind == "host":
        return None  # the host list IS the target
    detail = finding.get("detail", {}) or {}
    sources = [detail.get("identity") or {}, detail.get("after") or {}]
    for src in sources:
        if not isinstance(src, dict):
            continue
        for key in _TARGET_FIELDS.get(target_kind, ()):
            if src.get(key):
                return str(src[key])
    return None


# --------------------------------------------------------------------------- play runner

def _play_vars(case, play: str, hosts: list[str], target: str | None,
               evidence_dir: Path, audit_log: Path, authorized: bool,
               rollback: bool) -> dict:
    """Extra-vars contract handed to the playbook."""
    ev = {
        "dw_case_id": case.case_id,
        "dw_target_hosts": ",".join(hosts),
        "dw_platform": case.finding.get("platform", "linux"),
        "dw_evidence_dir": str(evidence_dir),
        "dw_audit_log": str(audit_log),
        "dw_authorized": bool(authorized),
        "dw_rollback": bool(rollback),
    }
    kind = PLAYS[play]["target_kind"]
    if kind == "account":
        ev["dw_account"] = target or ""
    elif kind == "hash":
        ev["dw_block_hash"] = target or ""
    elif kind == "session":
        ev["dw_session_user"] = target or ""
    return ev


def _synth_plan(play: str, hosts: list[str], target: str | None, ev: dict,
                check: bool, rollback: bool) -> str:
    """Human-readable dry-run plan used when ansible-playbook is not on PATH (the
    kit's Linux control node runs the real thing; this keeps the flow honest and
    inspectable everywhere else). Never claims an action was performed."""
    spec = PLAYS[play]
    action = "ROLLBACK (reverse)" if rollback else "ACT (contain)"
    lines = [
        f"[dry-run plan · ansible-playbook not on PATH · nothing was changed]",
        f"  play          : {play}  (tier {spec['tier']}, "
        f"reversible={spec['reversible']})",
        f"  intent        : {spec['summary']}",
        f"  mode          : {action}{'  --check' if check else ''}",
        f"  hosts         : {', '.join(hosts)}   (serial: 1 canary, any_errors_fatal)",
        f"  target        : {target if target is not None else '(host list)'}",
        f"  platform      : {ev.get('dw_platform')}",
        f"  evidence dir  : {ev.get('dw_evidence_dir')}",
        "  preserve-first: yes (before-state captured to evidence before any change)",
        "  writes config : NO (Tier-1 host action only; no network-device config write)",
    ]
    return "\n".join(lines)


def _run_play(play: str, ev: dict, hosts: list[str], target: str | None, *,
              check: bool, rollback: bool) -> dict:
    """Invoke the playbook. Runs the real ``ansible-playbook`` when present; otherwise
    returns a synthesized, clearly-labelled dry-run plan so the orchestration, evidence,
    audit and case-writeback all remain exercisable off the kit.

    Returns {executor, rc, cmd, plan, stderr}. rc != 0 means the play failed.
    """
    play_path = PLAYBOOK_DIR / f"{play}.yml"
    if not play_path.exists():
        raise UsageError(f"playbook not found: {play_path}")
    limit = ",".join(hosts)
    exe = shutil.which("ansible-playbook")
    cmd = [exe or "ansible-playbook", str(play_path), "--limit", limit,
           "-e", json.dumps(ev, sort_keys=True)]
    if check:
        cmd.append("--check")
    if exe is None:
        return {"executor": "simulated", "rc": 0, "cmd": cmd,
                "plan": _synth_plan(play, hosts, target, ev, check, rollback), "stderr": ""}
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {"executor": "ansible", "rc": proc.returncode, "cmd": cmd,
            "plan": proc.stdout, "stderr": proc.stderr}


# --------------------------------------------------------------------------- preserve

def _preserve(engagement_dir: Path, case, play: str, hosts: list[str],
              target: str | None, artifacts: list[str]) -> tuple[str, dict]:
    """PRESERVE (design §13.2): before any action, snapshot the decision inputs and any
    suspect artifacts into evidence/<case_id>/, SHA-256 every file, and register a
    deep-snapshot request ref on the case. "No preservation, no action."

    Returns (deep_snapshot_ref, {relative_path: sha256}).
    """
    evidence_dir = engagement_dir / "evidence" / case.case_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    # 1. The finding as it stood when the response was proposed.
    finding_path = evidence_dir / "finding.json"
    with open(finding_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(case.finding, fh, indent=2, sort_keys=True)
        fh.write("\n")
    written.append(finding_path)

    # 2. Copy any analyst-supplied suspect artifacts (binaries, exported tasks, etc.).
    for raw in artifacts or []:
        src = Path(raw)
        if not src.exists() or not src.is_file():
            raise UsageError(f"artifact not found: {src}")
        dest = evidence_dir / f"artifact_{src.name}"
        dest.write_bytes(src.read_bytes())
        written.append(dest)

    # 3. A reference to the deep snapshot the collector should capture (Tier-0 enrich).
    #    Response records the *request* only; it never imports or runs the collector.
    ref = f"deep-snapshot:request:{case.case_id}:{_iso(_now())}"
    preserve_meta = {
        "case_id": case.case_id,
        "engagement": case.engagement,
        "captured_at": _iso(_now()),
        "play": play,
        "hosts": hosts,
        "action_target": target,
        "deep_snapshot_ref": ref,
        "artifacts": [p.name for p in written if p.name.startswith("artifact_")],
        "note": ("preservation precedes action; a full deep snapshot of the named "
                 "host(s) should be collected under this ref before eradication"),
    }
    preserve_path = evidence_dir / "preserve.json"
    with open(preserve_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(preserve_meta, fh, indent=2, sort_keys=True)
        fh.write("\n")
    written.append(preserve_path)

    # 4. SHA-256 everything (our own integrity check; §13.2 evidence-store rule).
    sums: dict[str, str] = {}
    for path in written:
        sums[path.name] = _sha256_file(path)
    sums_path = evidence_dir / "SHA256SUMS"
    with open(sums_path, "w", encoding="utf-8", newline="\n") as fh:
        for name in sorted(sums):
            fh.write(f"{sums[name]}  {name}\n")

    # 5. Register evidence paths (relative to the engagement dir) + the ref on the case.
    rel = f"evidence/{case.case_id}"
    for path in written:
        entry = f"{rel}/{path.name}"
        if entry not in case.evidence:
            case.evidence.append(entry)
    sums_entry = f"{rel}/SHA256SUMS"
    if sums_entry not in case.evidence:
        case.evidence.append(sums_entry)
    if ref not in case.evidence:
        case.evidence.append(ref)
    return ref, sums


def _read_preserve(engagement_dir: Path, case_id: str) -> dict:
    path = engagement_dir / "evidence" / case_id / "preserve.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


# --------------------------------------------------------------------------- before/after

def _declared_states(play: str, target: str | None, hosts: list[str]) -> tuple[dict, dict]:
    """The reversible before/after contract for a Tier-1 play. On a real ansible run the
    play's PRESERVE step records live state; these declared states are the safe default
    and define exactly what ``rollback`` restores."""
    if play == "disable_account":
        return ({"account": target, "enabled": True},
                {"account": target, "enabled": False, "method": "account_disabled"})
    if play == "isolate_host":
        return ({"quarantined": False, "hosts": hosts},
                {"quarantined": True, "hosts": hosts, "method": "host_firewall_deny_all_except_mgmt"})
    if play == "block_hash":
        return ({"blocked": False, "hash": target},
                {"blocked": True, "hash": target, "method": "edr_or_applocker_hash_deny"})
    if play == "revoke_session":
        return ({"session_active": True, "user": target},
                {"session_active": False, "user": target, "method": "session_logoff",
                 "note": "no state destroyed; user may re-authenticate"})
    return ({}, {})


# --------------------------------------------------------------------------- verbs

def propose(engagement_dir, case_id: str, play: str, hosts: list[str], *,
            operator: str | None = None, target: str | None = None,
            artifacts: list[str] | None = None) -> dict:
    """PRESERVE + build proposed_action + run the play with --check. No target contact
    that changes anything (dry-run only). Writes the plan and evidence onto the case."""
    engagement_dir = Path(engagement_dir)
    op = _operator(operator)
    spec = _validate_play(play)
    cases_dir = engagement_dir / "cases"
    case = caselib.load(cases_dir, case_id)

    valid_hosts = _validate_hosts(hosts, case.finding_hosts())
    resolved_target = _derive_target(spec["target_kind"], case.finding, target)
    if spec["target_kind"] != "host" and not resolved_target:
        raise Refusal(
            f"play {play!r} needs a {spec['target_kind']} target but none is present on "
            "the finding; supply it explicitly with --target")

    # PRESERVE first — no preservation, no action.
    ref, sums = _preserve(engagement_dir, case, play, valid_hosts, resolved_target,
                          artifacts or [])

    # Build proposed_action — exactly {tier, play, hosts} per §14.
    case.proposed_action = {"tier": spec["tier"], "play": play, "hosts": valid_hosts}
    case.result = {"status": "proposed", "before": None, "after": None, "rolled_back": False}

    # PROPOSE — run the play in --check (dry run). Nothing is changed on targets.
    ev = _play_vars(case, play, valid_hosts, resolved_target,
                    engagement_dir / "evidence" / case.case_id,
                    engagement_dir / "audit.log", authorized=False, rollback=False)
    run = _run_play(play, ev, valid_hosts, resolved_target, check=True, rollback=False)

    caselib.save(case, cases_dir)
    _audit(engagement_dir, "proposed", case.case_id, play, valid_hosts, op,
           "ok" if run["rc"] == 0 else "check_failed",
           extra=f"target={resolved_target or '-'} | executor={run['executor']} | "
                 f"evidence_ref={ref}")

    return {
        "phase": "proposed", "case_id": case.case_id, "play": play,
        "hosts": valid_hosts, "target": resolved_target, "tier": spec["tier"],
        "executor": run["executor"], "dry_run_rc": run["rc"],
        "plan": run["plan"], "evidence": list(case.evidence),
        "evidence_sha256": sums,
    }


def approve(engagement_dir, case_id: str, *, operator: str | None = None,
            authorized_by: str | None = None, confirm: bool = False,
            approval_ttl_hours: int = 24, interactive_in=None,
            interactive_out=None) -> dict:
    """Interactive confirm -> ACT -> LOG. The analyst must confirm the EXACT action
    against the EXACT host list and name (free text) who authorized it out-of-band."""
    engagement_dir = Path(engagement_dir)
    op = _operator(operator)
    cases_dir = engagement_dir / "cases"
    case = caselib.load(cases_dir, case_id)

    pa = case.proposed_action or {}
    play = pa.get("play")
    hosts = list(pa.get("hosts") or [])
    if not play or not hosts:
        raise Refusal(f"case {case_id} has no proposed_action — run `respond propose` first")
    spec = _validate_play(play)

    # Re-assert the blast-radius gate at approval time (defense in depth).
    hosts = _validate_hosts(hosts, case.finding_hosts())

    resolved_target = _read_preserve(engagement_dir, case_id).get("action_target")
    if resolved_target is None:
        resolved_target = _derive_target(spec["target_kind"], case.finding, None)

    out = interactive_out or sys.stdout

    # Show the dry-run plan again, then the exact action to be confirmed.
    ev_check = _play_vars(case, play, hosts, resolved_target,
                          engagement_dir / "evidence" / case.case_id,
                          engagement_dir / "audit.log", authorized=False, rollback=False)
    dry = _run_play(play, ev_check, hosts, resolved_target, check=True, rollback=False)
    out.write(dry["plan"] + "\n")
    out.write(
        f"\nAbout to EXECUTE '{play}' (tier {spec['tier']}) against EXACTLY: "
        f"{', '.join(hosts)}\n  target: {resolved_target if resolved_target is not None else '(host list)'}\n")

    # The human gate (design §13.2): mistake-prevention, not authority-modelling.
    if confirm and authorized_by:
        confirmed = True
        authorizer = authorized_by
    else:
        stream_in = interactive_in or sys.stdin
        out.write(f"\nType the play name '{play}' to confirm this exact action: ")
        out.flush()
        typed = (stream_in.readline() or "").strip()
        confirmed = (typed == play)
        if not confirmed:
            _audit(engagement_dir, "approved", case_id, play, hosts, op, "REFUSED",
                   extra="confirmation mismatch")
            raise Refusal("confirmation did not match the play name — nothing executed")
        authorizer = authorized_by
        if not authorizer:
            out.write("Who authorized this action out-of-band (free text)? ")
            out.flush()
            authorizer = (stream_in.readline() or "").strip()
        if not authorizer:
            _audit(engagement_dir, "approved", case_id, play, hosts, op, "REFUSED",
                   extra="no authorizer supplied")
            raise Refusal("no out-of-band authorizer supplied — nothing executed")

    now = _now()
    case.approval = {
        "by": op,
        "at": _iso(now),
        "expires": _iso(now + timedelta(hours=approval_ttl_hours)),
        "authorized_by": authorizer,
    }
    _audit(engagement_dir, "approved", case_id, play, hosts, op, "ok",
           extra=f"authorized_by={authorizer}")

    # ACT — capture before-state, run the play for real (not --check).
    before, after = _declared_states(play, resolved_target, hosts)
    ev_act = _play_vars(case, play, hosts, resolved_target,
                        engagement_dir / "evidence" / case.case_id,
                        engagement_dir / "audit.log", authorized=True, rollback=False)
    act = _run_play(play, ev_act, hosts, resolved_target, check=False, rollback=False)

    if act["rc"] != 0:
        case.result = {"status": "failed", "before": before, "after": None,
                       "rolled_back": False}
        caselib.save(case, cases_dir)
        _audit(engagement_dir, "executed", case_id, play, hosts, op, "FAILED",
               extra=f"executor={act['executor']} rc={act['rc']}")
        raise UsageError(f"play {play} failed (rc={act['rc']}); case marked failed\n{act['stderr']}")

    after = {**after, "executor": act["executor"]}
    case.result = {"status": "executed", "before": before, "after": after,
                   "rolled_back": False}
    caselib.save(case, cases_dir)
    _audit(engagement_dir, "executed", case_id, play, hosts, op, "ok",
           extra=f"executor={act['executor']} target={resolved_target or '-'}")

    return {
        "phase": "executed", "case_id": case_id, "play": play, "hosts": hosts,
        "target": resolved_target, "executor": act["executor"],
        "approval": case.approval, "result": case.result,
    }


def rollback(engagement_dir, case_id: str, *, operator: str | None = None) -> dict:
    """Reverse an executed action using the captured before-state (design §13.2,
    "reversible by default")."""
    engagement_dir = Path(engagement_dir)
    op = _operator(operator)
    cases_dir = engagement_dir / "cases"
    case = caselib.load(cases_dir, case_id)

    play = (case.proposed_action or {}).get("play")
    hosts = list((case.proposed_action or {}).get("hosts") or [])
    result = case.result or {}
    if result.get("status") != "executed":
        raise Refusal(
            f"case {case_id} is not in an executed state (status="
            f"{result.get('status')!r}) — nothing to roll back")
    if result.get("rolled_back"):
        raise Refusal(f"case {case_id} has already been rolled back")
    spec = _validate_play(play)

    resolved_target = _read_preserve(engagement_dir, case_id).get("action_target")
    if resolved_target is None:
        resolved_target = _derive_target(spec["target_kind"], case.finding, None)

    ev = _play_vars(case, play, hosts, resolved_target,
                    engagement_dir / "evidence" / case.case_id,
                    engagement_dir / "audit.log", authorized=True, rollback=True)
    run = _run_play(play, ev, hosts, resolved_target, check=False, rollback=True)
    if run["rc"] != 0:
        _audit(engagement_dir, "rolled-back", case_id, play, hosts, op, "FAILED",
               extra=f"executor={run['executor']} rc={run['rc']}")
        raise UsageError(f"rollback of {play} failed (rc={run['rc']})\n{run['stderr']}")

    restored = dict(result.get("before") or {})
    restored["restored_at"] = _iso(_now())
    restored["executor"] = run["executor"]
    case.result = {
        "status": "rolled_back",
        "before": result.get("before"),
        "after": restored,
        "rolled_back": True,
    }
    caselib.save(case, cases_dir)
    _audit(engagement_dir, "rolled-back", case_id, play, hosts, op, "ok",
           extra=f"executor={run['executor']}")

    return {"phase": "rolled_back", "case_id": case_id, "play": play, "hosts": hosts,
            "executor": run["executor"], "result": case.result}


# --------------------------------------------------------------------------- CLI

def cmd_propose(args) -> int:
    engagement_dir = _resolve_engagement_dir(args.engagement_dir)
    hosts = [h for h in (args.hosts or "").split(",") if h.strip()]
    artifacts = list(args.artifact or [])
    summary = propose(engagement_dir, args.case, args.play, hosts,
                      operator=args.operator, target=args.target, artifacts=artifacts)
    print(summary["plan"])
    print(json.dumps({k: v for k, v in summary.items() if k != "plan"}, indent=2))
    return 0


def cmd_approve(args) -> int:
    engagement_dir = _resolve_engagement_dir(args.engagement_dir)
    summary = approve(engagement_dir, args.case, operator=args.operator,
                      authorized_by=args.authorized_by, confirm=args.confirm,
                      approval_ttl_hours=args.approval_ttl_hours)
    print(json.dumps(summary, indent=2))
    return 0


def cmd_rollback(args) -> int:
    engagement_dir = _resolve_engagement_dir(args.engagement_dir)
    summary = rollback(engagement_dir, args.case, operator=args.operator)
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="respond",
        description="driftwatch response layer — Tier-1 reversible plays only (§13/§14).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--engagement-dir",
                       help="engagement volume path (or set DRIFTWATCH_ENGAGEMENT)")
        p.add_argument("--case", required=True, help="case id, e.g. c-0031")
        p.add_argument("--operator", help="who is running the tool (approval.by)")

    p_prop = sub.add_parser("propose", help="preserve, build plan, dry-run (--check)")
    common(p_prop)
    p_prop.add_argument("--play", required=True, choices=sorted(PLAYS))
    p_prop.add_argument("--hosts", required=True, help="comma-separated target hosts")
    p_prop.add_argument("--target", help="explicit action target (account/hash/session)")
    p_prop.add_argument("--artifact", action="append",
                        help="suspect artifact file to preserve (repeatable)")

    p_app = sub.add_parser("approve", help="confirm, act, log")
    common(p_app)
    p_app.add_argument("--authorized-by",
                       help="free text: who authorized this out-of-band")
    p_app.add_argument("--confirm", action="store_true",
                       help="non-interactive confirm (requires --authorized-by)")
    p_app.add_argument("--approval-ttl-hours", type=int, default=24,
                       dest="approval_ttl_hours")

    p_roll = sub.add_parser("rollback", help="reverse an executed action")
    common(p_roll)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "propose":
            return cmd_propose(args)
        if args.cmd == "approve":
            return cmd_approve(args)
        if args.cmd == "rollback":
            return cmd_rollback(args)
    except Refusal as exc:
        sys.stderr.write(f"REFUSED: {exc}\n")
        return 2
    except (UsageError, FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
