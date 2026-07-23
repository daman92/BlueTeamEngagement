"""siem_ship — ship findings and snapshots to the kit's SIEM stack (design §7).

Two destinations, deliberately split:

  * Splunk (findings ONLY) — one HEC event per finding, ``sourcetype=driftwatch:finding``,
    on a deliberately small data volume (a few hundred events/run) that stays inside a
    Splunk Free/dev license. Each event carries ``run_id`` + host so an analyst can pivot
    from the Splunk finding to the underlying raw state in Security Onion.

  * Security Onion / Elastic (findings AND full snapshot JSON) — the bulk index and system
    of record. Findings + every host/domain snapshot for the run are ECS-mapped and pushed
    as one bulk NDJSON request to ``<elastic_url>/_bulk``. This is where the raw-state pivot
    lives, so snapshot state is queryable instead of re-collected.

Config comes from ``scope.yml`` ``settings``: ``splunk_hec_url``, ``splunk_hec_token_var``,
``elastic_url``. The HEC token is read from the ENVIRONMENT variable *named* by
``splunk_hec_token_var`` — never from argv, never logged. If a requested destination's URL
or token is missing, shipping to it is disabled (clear message, exit 0), not an error.

``--dry-run`` reports exactly what WOULD ship — counts, endpoints, sourcetype, index names,
and whether the token env var is present — without opening a socket or printing the token.
This is the offline/test path; ``--splunk``/``--elastic`` absent means no network calls.

Library entry points: ``ship()``, ``build_splunk()``, ``build_elastic()``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

import driftwatch_common as dc

SPLUNK_SOURCETYPE = "driftwatch:finding"
FINDINGS_INDEX = "driftwatch-findings"
SNAPSHOTS_INDEX = "driftwatch-snapshots"
HTTP_TIMEOUT = 30  # seconds

# ECS event.severity is a numeric field; map driftwatch's ordinal severities onto it.
_ECS_SEVERITY = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}


# --------------------------------------------------------------------------- time helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id_dt(run_id: str) -> datetime:
    return datetime.strptime(run_id, dc.RUN_ID_FORMAT).replace(tzinfo=timezone.utc)


def _run_id_epoch(run_id: str) -> float:
    """Epoch seconds for the HEC ``time`` field; falls back to now on a bad run_id."""
    try:
        return _run_id_dt(run_id).timestamp()
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).timestamp()


def _run_id_iso(run_id: str) -> str:
    try:
        return _run_id_dt(run_id).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return _now_iso()


# --------------------------------------------------------------------------- loading

def load_scope_settings(engagement_dir: Path) -> tuple[dict, str]:
    """Return (settings, engagement_id) from scope.yml. Missing file => empty settings."""
    path = engagement_dir / "scope.yml"
    if not path.exists():
        return {}, engagement_dir.name
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return (data.get("settings", {}) or {}), data.get("engagement", engagement_dir.name)


def load_findings(engagement_dir: Path, run_id: str) -> tuple[list[dict], str]:
    """Load findings NDJSON for the run. Missing file is not an error (nothing to ship)."""
    path = engagement_dir / "findings" / f"{run_id}.ndjson"
    if not path.exists():
        return [], f"no findings file at {path} - nothing to ship for findings"
    return dc.load_ndjson(path), ""


def load_snapshots(engagement_dir: Path, run_id: str) -> list[dict]:
    """Every host and per-domain snapshot document for this run.

    Includes ``_domain_<fqdn>`` AD documents; excludes the ``_run`` collection-status file
    (it is run metadata, not a snapshot conforming to the §2 schema)."""
    root = engagement_dir / "snapshots"
    out: list[dict] = []
    if not root.exists():
        return out
    for sub in sorted(root.iterdir()):
        if not sub.is_dir() or sub.name == "_run":
            continue
        snap = sub / f"{run_id}.json"
        if not snap.exists():
            continue
        try:
            with open(snap, "r", encoding="utf-8") as fh:
                out.append(json.load(fh))
        except (json.JSONDecodeError, OSError):
            continue
    return out


# --------------------------------------------------------------------------- Splunk (findings)

def _hec_endpoint(url: str) -> str:
    """Resolve the HEC event endpoint from the configured base URL."""
    u = url.rstrip("/")
    if "/services/collector" in u:
        return u
    return u + "/services/collector/event"


def _hec_event(finding: dict, engagement: str) -> dict:
    """One HEC envelope per finding.

    The event payload IS the finding, which already carries ``run_id`` and ``hosts`` — the
    keys an analyst needs to pivot to the raw state in Security Onion (§7). The envelope's
    metadata ``host`` is set to the first affected host (findings can span several)."""
    hosts = finding.get("hosts") or []
    host = hosts[0] if hosts else engagement
    return {
        "time": _run_id_epoch(finding.get("run_id", "")),
        "host": host,
        "source": "driftwatch",
        "sourcetype": SPLUNK_SOURCETYPE,
        "event": finding,
    }


def build_splunk(settings: dict, engagement: str, findings: list[dict]) -> tuple[dict, tuple | None]:
    """Return (plan, payload). ``plan`` is safe to print (never the token). ``payload`` is
    (events, token) when enabled, else None. Disabled when the URL or token is missing."""
    url = (settings.get("splunk_hec_url") or "").strip()
    token_var = settings.get("splunk_hec_token_var") or ""
    token = os.environ.get(token_var) if token_var else None

    if not url:
        return {"enabled": False, "reason": "splunk_hec_url not set in scope.yml settings"}, None
    if not token_var:
        return {"enabled": False,
                "reason": "splunk_hec_token_var not set in scope.yml settings"}, None
    if not token:
        return {"enabled": False, "token_var": token_var, "token_present": False,
                "reason": f"HEC token env var '{token_var}' is not set in the environment"}, None

    events = [_hec_event(f, engagement) for f in findings]
    plan = {
        "enabled": True,
        "endpoint": _hec_endpoint(url),
        "sourcetype": SPLUNK_SOURCETYPE,
        "token_var": token_var,
        "token_present": True,
        "events": len(events),
    }
    return plan, (events, token)


def _send_splunk(endpoint: str, events: list[dict], token: str) -> tuple[int, str]:
    # HEC accepts newline-delimited event objects in a single request.
    body = "\n".join(dc.canonical_json(e) for e in events).encode("utf-8")
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    return _http_post(endpoint, body, headers)


# --------------------------------------------------------------------------- Elastic (bulk)

def _index_name(base: str, engagement: str) -> str:
    """Per-engagement index name (Elastic requires lowercase, restricted charset)."""
    eng = re.sub(r"[^a-z0-9._-]", "-", (engagement or "").lower()).strip("-_+.")
    return f"{base}-{eng}" if eng else base


def _ecs_finding(finding: dict) -> dict:
    """ECS-ish mapping of a finding. The full finding is preserved under ``driftwatch``;
    ECS overlays give Elastic-native fields to correlate against Zeek/Suricata telemetry."""
    return {
        "@timestamp": _run_id_iso(finding.get("run_id", "")),
        "event": {
            "kind": "alert",
            "module": "driftwatch",
            "dataset": "driftwatch.finding",
            "action": finding.get("change_type"),
            "category": ["configuration"],
            "id": finding.get("finding_id"),
            "severity": _ECS_SEVERITY.get(finding.get("severity"), 0),
        },
        "rule": {"name": finding.get("rule"), "ruleset": "driftwatch"},
        "host": {"name": finding.get("hosts") or []},
        "driftwatch": finding,
    }


def _ecs_snapshot(doc: dict) -> dict:
    """ECS-ish mapping of a full snapshot document. The full snapshot is preserved under
    ``snapshot`` — this is the bulk raw state that makes the finding->state pivot a query."""
    meta = doc.get("meta", {}) if isinstance(doc, dict) else {}
    ts = meta.get("collected_at") or _run_id_iso(meta.get("run_id", ""))
    return {
        "@timestamp": ts,
        "event": {"kind": "state", "module": "driftwatch", "dataset": "driftwatch.snapshot"},
        "host": {"name": meta.get("host"), "os": {"full": meta.get("os")}},
        "driftwatch": {
            "schema_version": meta.get("schema_version"),
            "run_id": meta.get("run_id"),
            "engagement": meta.get("engagement"),
            "platform": meta.get("platform"),
            "partial": meta.get("partial"),
        },
        "snapshot": doc,
    }


def build_elastic(settings: dict, engagement: str, findings: list[dict],
                  snapshots: list[dict]) -> tuple[dict, list | None]:
    """Return (plan, pairs). ``pairs`` is [(index, doc), ...] when enabled, else None.
    Disabled when ``elastic_url`` is missing."""
    url = (settings.get("elastic_url") or "").strip()
    if not url:
        return {"enabled": False, "reason": "elastic_url not set in scope.yml settings"}, None

    f_index = _index_name(FINDINGS_INDEX, engagement)
    s_index = _index_name(SNAPSHOTS_INDEX, engagement)
    pairs: list[tuple[str, dict]] = [(f_index, _ecs_finding(f)) for f in findings]
    pairs += [(s_index, _ecs_snapshot(d)) for d in snapshots]

    plan = {
        "enabled": True,
        "endpoint": url.rstrip("/") + "/_bulk",
        "indices": {f_index: len(findings), s_index: len(snapshots)},
        "docs": len(pairs),
    }
    return plan, pairs


def _bulk_body(pairs: list[tuple[str, dict]]) -> str:
    """Elastic ``_bulk`` NDJSON: an action line then the document line, per doc."""
    lines: list[str] = []
    for index, doc in pairs:
        lines.append(dc.canonical_json({"index": {"_index": index}}))
        lines.append(dc.canonical_json(doc))
    return "\n".join(lines) + "\n"


def _send_elastic(endpoint: str, pairs: list[tuple[str, dict]]) -> tuple[int, str]:
    body = _bulk_body(pairs).encode("utf-8")
    headers = {"Content-Type": "application/x-ndjson"}
    return _http_post(endpoint, body, headers)


def _bulk_had_errors(body: str) -> bool:
    try:
        return bool(json.loads(body).get("errors"))
    except (json.JSONDecodeError, AttributeError, TypeError):
        return False


# --------------------------------------------------------------------------- HTTP

def _http_post(url: str, data: bytes, headers: dict) -> tuple[int, str]:
    """POST via stdlib urllib only. Raises urllib.error.URLError / OSError on failure."""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310 (kit-internal)
        return getattr(resp, "status", resp.getcode()), resp.read().decode("utf-8", "replace")


# --------------------------------------------------------------------------- orchestration

def ship(engagement_dir: Path, run_id: str, do_splunk: bool, do_elastic: bool,
         dry_run: bool) -> tuple[dict, int]:
    """Plan (and unless dry_run, execute) shipping to the requested destinations.

    Returns (result, error_count). A destination that is requested but unconfigured is
    reported as disabled and is NOT an error. Errors count only real send failures."""
    settings, engagement = load_scope_settings(engagement_dir)
    findings, findings_note = load_findings(engagement_dir, run_id)
    snapshots = load_snapshots(engagement_dir, run_id) if do_elastic else []

    result: dict = {
        "run_id": run_id,
        "engagement": engagement,
        "dry_run": dry_run,
        "findings_available": len(findings),
    }
    if findings_note:
        result["note"] = findings_note
    errors = 0

    # --- Splunk: findings only ---
    if do_splunk:
        plan, payload = build_splunk(settings, engagement, findings)
        if plan.get("enabled") and not dry_run:
            events, token = payload
            if not events:
                plan["shipped"] = True
                plan["ship_note"] = "no findings to ship"
            else:
                try:
                    status, _ = _send_splunk(plan["endpoint"], events, token)
                    plan["shipped"] = True
                    plan["http_status"] = status
                except (urllib.error.URLError, OSError) as exc:
                    plan["shipped"] = False
                    plan["error"] = str(exc)
                    errors += 1
        result["splunk"] = plan
    else:
        result["splunk"] = {"enabled": False, "reason": "not requested (--splunk absent)"}

    # --- Elastic / Security Onion: findings AND full snapshots ---
    if do_elastic:
        plan, pairs = build_elastic(settings, engagement, findings, snapshots)
        plan["snapshots_available"] = len(snapshots)
        if plan.get("enabled") and not dry_run:
            if not pairs:
                plan["shipped"] = True
                plan["ship_note"] = "nothing to ship"
            else:
                try:
                    status, resp_body = _send_elastic(plan["endpoint"], pairs)
                    had_errors = _bulk_had_errors(resp_body)
                    plan["shipped"] = not had_errors
                    plan["http_status"] = status
                    if had_errors:
                        plan["error"] = "elastic _bulk response reported item-level errors"
                        errors += 1
                except (urllib.error.URLError, OSError) as exc:
                    plan["shipped"] = False
                    plan["error"] = str(exc)
                    errors += 1
        result["elastic"] = plan
    else:
        result["elastic"] = {"enabled": False, "reason": "not requested (--elastic absent)"}

    result["errors"] = errors
    return result, errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="siem_ship")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ship")
    p.add_argument("--engagement-dir", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--splunk", action="store_true", help="ship findings to Splunk over HEC")
    p.add_argument("--elastic", action="store_true",
                   help="ship findings + full snapshots to Security Onion / Elastic")
    p.add_argument("--dry-run", action="store_true",
                   help="report what would ship without connecting (never prints the token)")
    args = parser.parse_args(argv)

    if args.cmd != "ship":
        return 1

    engagement_dir = Path(args.engagement_dir)
    if not engagement_dir.exists():
        sys.stderr.write(f"error: engagement dir not found: {engagement_dir}\n")
        return 1

    result, errors = ship(engagement_dir, args.run_id, args.splunk, args.elastic, args.dry_run)

    # Clear human messages for requested-but-disabled destinations (still exit 0).
    for dest in ("splunk", "elastic"):
        info = result.get(dest, {})
        if getattr(args, dest) and not info.get("enabled"):
            sys.stderr.write(f"{dest} shipping disabled: {info.get('reason')}\n")
    if not args.splunk and not args.elastic:
        sys.stderr.write("no destinations selected - pass --splunk and/or --elastic\n")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
