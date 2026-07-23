"""case — the Case object: the single record detection and response share (design §14).

This is a RESPONSE-SIDE module. It holds no collection logic and imports NO collection
code (`driftwatch_common`, `diff_engine`, `normalize`, `scope_gate`). The case is the
*only* thing the two privilege domains ever exchange, and they exchange it as a plain
JSON file on disk — never as a live import. Detection writes the ``finding``; response
reads it and writes ``proposed_action`` -> ``approval`` -> ``result`` back onto the same
record (design §14: "the case is the unit of unification").

Schema (CONTRACTS.md §7 / design §14) — the six top-level keys are fixed:

    {
      "case_id":         "c-0031",              # c-NNNN, 4-digit within the engagement
      "engagement":      "acme-2026-07",
      "finding":         { ... the §4 finding ... },
      "evidence":        [ "evidence/c-0031/finding.json", "deep-snapshot:request:..." ],
      "proposed_action": {"tier": 1, "play": "isolate_host", "hosts": ["WIN-FS01"]},
      "approval":        {"by": "analyst-b", "at": "...", "expires": "...",
                          "authorized_by": "J. Doe, IR lead (verbal, 2026-07-23)"},
      "result":          {"status": "executed", "before": {...}, "after": {...},
                          "rolled_back": false}
    }

``authorized_by`` is added to the §14 ``approval`` block on purpose (CONTRACTS §7 /
design §13.2): the tool records *who confirmed the action in the tool* (``by``) and,
as free text, *who authorized it out-of-band* (``authorized_by``).

Stdlib only. Importable with no side effects.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# case id: c-NNNN, 4-digit sequence within an engagement (CONTRACTS §1.3).
CASE_ID_RE = re.compile(r"^c-(\d{4,})$")


def _empty_proposed_action() -> dict:
    """proposed_action{tier, play, hosts} — exactly the §14 keys, empty until proposed."""
    return {"tier": None, "play": None, "hosts": []}


def _empty_approval() -> dict:
    """approval{by, at, expires} + free-text authorized_by — empty until approved."""
    return {"by": None, "at": None, "expires": None, "authorized_by": None}


def _empty_result() -> dict:
    """result{status, before, after, rolled_back} — empty until acted on."""
    return {"status": None, "before": None, "after": None, "rolled_back": False}


@dataclass
class Case:
    """One case: the shared record described in design §14.

    The six fields map one-to-one to the on-disk schema. ``finding`` is stored verbatim
    as a plain dict copied from the detection side's NDJSON — the case never re-derives
    or re-validates it, keeping the response domain free of collection code.
    """

    case_id: str
    engagement: str
    finding: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    proposed_action: dict = field(default_factory=_empty_proposed_action)
    approval: dict = field(default_factory=_empty_approval)
    result: dict = field(default_factory=_empty_result)

    # ---- serialization -----------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to the exact §14 key order/shape."""
        return {
            "case_id": self.case_id,
            "engagement": self.engagement,
            "finding": self.finding,
            "evidence": list(self.evidence),
            "proposed_action": dict(self.proposed_action),
            "approval": dict(self.approval),
            "result": dict(self.result),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        """Rebuild a Case from a loaded dict, tolerating older/partial records by
        filling any missing block with its empty template."""
        if not isinstance(data, dict):
            raise ValueError("case file is not a JSON object")
        case_id = data.get("case_id")
        if not case_id or not CASE_ID_RE.match(str(case_id)):
            raise ValueError(f"invalid or missing case_id: {case_id!r}")

        proposed = {**_empty_proposed_action(), **(data.get("proposed_action") or {})}
        approval = {**_empty_approval(), **(data.get("approval") or {})}
        result = {**_empty_result(), **(data.get("result") or {})}
        return cls(
            case_id=str(case_id),
            engagement=str(data.get("engagement", "")),
            finding=dict(data.get("finding") or {}),
            evidence=list(data.get("evidence") or []),
            proposed_action=proposed,
            approval=approval,
            result=result,
        )

    # ---- convenience -------------------------------------------------------

    def finding_hosts(self) -> list[str]:
        """The hosts the finding names — the blast-radius ceiling for any play."""
        return list(self.finding.get("hosts", []) or [])

    def save(self, cases_dir) -> Path:
        """Write this case to ``cases_dir/<case_id>.json`` (deterministic, sorted keys)."""
        return save(self, cases_dir)


# --------------------------------------------------------------------------- helpers

def case_path(cases_dir, case_id: str) -> Path:
    return Path(cases_dir) / f"{case_id}.json"


def next_case_id(cases_dir) -> str:
    """Allocate the next ``c-NNNN`` id by scanning existing case files."""
    cases_dir = Path(cases_dir)
    highest = 0
    if cases_dir.exists():
        for path in cases_dir.glob("c-*.json"):
            match = CASE_ID_RE.match(path.stem)
            if match:
                highest = max(highest, int(match.group(1)))
    return f"c-{highest + 1:04d}"


def new_case(cases_dir, engagement: str, finding: dict | None = None,
             case_id: str | None = None) -> Case:
    """Create and persist a new case.

    The id is reserved by writing the file immediately, so two intake calls never
    collide on the same ``c-NNNN``. Case creation is the intake step (the detection
    side triages a finding into a case); response verbs operate on an existing case.
    """
    cases_dir = Path(cases_dir)
    cases_dir.mkdir(parents=True, exist_ok=True)
    cid = case_id or next_case_id(cases_dir)
    if not CASE_ID_RE.match(cid):
        raise ValueError(f"case_id must match c-NNNN, got {cid!r}")
    if case_path(cases_dir, cid).exists():
        raise FileExistsError(f"case {cid} already exists in {cases_dir}")
    case = Case(case_id=cid, engagement=engagement, finding=dict(finding or {}))
    save(case, cases_dir)
    return case


def load(cases_dir, case_id: str) -> Case:
    """Load a case by id from ``cases_dir``."""
    path = case_path(cases_dir, case_id)
    if not path.exists():
        raise FileNotFoundError(f"no case {case_id} in {cases_dir}")
    with open(path, "r", encoding="utf-8") as fh:
        return Case.from_dict(json.load(fh))


def save(case: Case, cases_dir) -> Path:
    """Persist a case to ``cases_dir/<case_id>.json``."""
    cases_dir = Path(cases_dir)
    cases_dir.mkdir(parents=True, exist_ok=True)
    path = case_path(cases_dir, case.case_id)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(case.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
