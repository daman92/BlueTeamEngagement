"""gui_server — the local operator GUI for driftwatch (design §7, §9, §13.6, §15.2).

WHY this exists: the canonical outputs are NDJSON findings and a rendered report (§7), and
the CLI is the sanctioned way to drive a run. But an analyst triaging a fleet needs to pivot
— filter by severity, ask "which machines have this?", read the before/after — and doing that
by re-rendering reports is slow. This serves the SAME data the report is built from
(report_gen.build_context, fleet_stats.build_matrix) as a browsable local page.

WHY it is built like a bunker: this process runs on the kit, which holds privileged
credentials for an entire client fleet (§9 — treat it like a tier-0 asset). Appendix C.1
rejected AWX partly to avoid exactly this attack surface, so the GUI earns its place only by
being tightly constrained:

  * Loopback only. The listener is hard-wired to 127.0.0.1; there is deliberately no --host
    flag, so "bind it to 0.0.0.0 for a second" is not a thing an operator can typo into.
  * Per-run bearer token (secrets.token_urlsafe(32), regenerated every start). Every request
    presents it — query param on first load, then an HttpOnly SameSite=Strict cookie, or an
    X-DW-Token header. Compared with secrets.compare_digest. Anything else: 403.
  * Host-header allowlist (DNS-rebinding defence): only 127.0.0.1:<port> / localhost:<port>.
  * Mutating routes are POST-only and additionally require the token in the X-DW-Token
    HEADER plus a same-origin Origin/Referer — a combination no cross-origin page can forge
    (it cannot read /api/state to learn the token, and it cannot set the header without a
    CORS preflight this server never approves).
  * The response layer is ABSENT, not hidden: no respond/approve/rollback, no teardown, no
    vault or credential access. §13.6 says response must not grow a web UI; this is the
    collection side's read/trigger console and nothing more.
  * Untrusted content stays data. Findings carry attacker-controlled strings (process args,
    file paths, cert subjects); the frontend builds every node with textContent/createElement
    and the CSP forbids inline script, so a malicious command line cannot script the analyst.
    Rendered HTML reports are shown inside a fully sandboxed iframe.
  * Engagement/run ids from the client are matched against strict allowlist regexes and
    re-resolved inside engagements/ — no traversal, no symlink escape.
  * Every action the GUI triggers appends to the engagement audit.log in the CLI's format
    ("<ISO8601> | <verb> | <run_id> | <operator> | <outcome>"), because §15.2 says the audit
    trail is the operator's own evidence of staying inside authorization.

Actions shell out to bin/driftwatch (never shell=True, always an argv list) so the CLI stays
the single implementation of what a verb means; the GUI only ever *asks* for doctor, diff,
report, collect, or scope_gate generate.

CLI:
  gui_server.py serve [--port 8787] [--engagement ID] [--no-browser] [--print-url]
Exit: 0 ok / 1 error / 2 refusal.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import uuid
import webbrowser
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import _vendor  # noqa: F401  # puts bundled PyYAML/Jinja2 on sys.path (offline kit)
import driftwatch_common as dc
import report_gen
import scope_gate

__all__ = ["serve", "main", "build_app", "GuiApp"]

BIND_HOST = "127.0.0.1"          # never configurable; see module docstring
DEFAULT_PORT = 8787
PORT_SCAN = 10                   # if the port is taken, try the next few
MAX_BODY = 256 * 1024            # request bodies are small JSON documents
MAX_JOB_OUTPUT = 4 * 1024 * 1024
AUDIT_TAIL_MAX = 5000

# --- allowlists -------------------------------------------------------------------------
# engagement_id is <client>-<yyyy>-<mm> in practice; the regex is deliberately stricter than
# the filesystem so no separator, dot-segment, or absolute path can ever reach a join().
#
# Every one of these anchors with \Z, NOT $. In Python `$` also matches immediately before a
# trailing newline, so `^...$` would accept "acme-2026-07\n" — a value that is not the id the
# operator authorised but that still reaches mkdir()/glob()/argv. \Z is the true end of string.
ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
RUN_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{4}Z\Z")        # CONTRACTS §1.3
HOSTNAME_RE = re.compile(r"^(?=.{1,253}\Z)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
GROUP_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}\Z")
# The per-run token is compared with compare_digest, but it is also echoed into a Set-Cookie
# header; refuse anything outside the token_urlsafe alphabet so a token can never carry CR/LF.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}\Z")
HASH_POLICIES = ("full", "tiered", "servers_only")

# Verbs the GUI is allowed to trigger. Read-only or control-node-only, except `collect`,
# which reaches the fleet and is confirmed in the UI with the target count. There is no
# entry here for respond/approve/rollback (§13.6), teardown, ship, or anything vault-shaped.
ACTIONS: dict[str, dict] = {
    "doctor": {"label": "doctor", "reaches_fleet": False,
               "desc": "environment self-check (read-only)"},
    "diff": {"label": "diff", "reaches_fleet": False,
             "desc": "normalize + diff engine on the control node"},
    "report": {"label": "report", "reaches_fleet": False,
               "desc": "render the Markdown + HTML report"},
    "collect": {"label": "collect", "reaches_fleet": True,
                "desc": "scope gate -> snapshot the fleet -> diff -> report"},
    "scope-generate": {"label": "scope_gate generate", "reaches_fleet": False,
                       "desc": "regenerate inventory/hosts.yml from scope.yml"},
}

STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "findings.js": "application/javascript; charset=utf-8",
    "wizard.js": "application/javascript; charset=utf-8",
}

# No inline script, no remote anything: the kit is air-gapped and findings are untrusted.
APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
           "form-action 'none'")
# The rendered report is engagement-derived HTML: fully sandboxed (opaque origin, no script).
FRAME_CSP = ("sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
             "frame-ancestors 'self'")

COOKIE_NAME = "dw_token"


# --------------------------------------------------------------------------- small helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_from_mtime(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def _audit_safe(value: str) -> str:
    """One audit entry must stay one line with five fields (CONTRACTS §8).

    The operator name comes from $DRIFTWATCH_OPERATOR, so a newline or a pipe in it would
    let whoever set that variable forge or split audit lines — and the audit log is exactly
    what design §15.2 relies on as evidence of staying inside authorization.
    """
    return re.sub(r"[\r\n|]+", " ", str(value)).strip() or "unknown"


def _operator() -> str:
    op = os.environ.get("DRIFTWATCH_OPERATOR", "").strip()
    if op:
        return _audit_safe(op)
    try:
        import getpass
        return _audit_safe(getpass.getuser())
    except Exception:  # pragma: no cover - getuser can fail on odd environments
        return "unknown"


def _count_by_severity(findings) -> dict:
    counts = {s: 0 for s in dc.SEVERITIES}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


# --------------------------------------------------------------------------- job runner

class Busy(Exception):
    """Another action is already running (one at a time, deliberately)."""


class Job:
    """One shelled-out CLI invocation, streamed into a buffer the UI polls.

    Threaded + polled rather than SSE: http.server gives us a thread per request anyway,
    and a poll loop degrades gracefully if the analyst closes the tab mid-collect.
    """

    def __init__(self, verb: str, engagement: str, argv: list[str], label: str):
        self.id = uuid.uuid4().hex
        self.verb = verb
        self.engagement = engagement
        self.argv = argv
        self.label = label
        self.status = "running"          # running | done | failed
        self.rc: int | None = None
        self.started_at = _now_iso()
        self.finished_at = ""
        self._buf: list[str] = []
        self._len = 0
        self._truncated = False
        self._lock = threading.Lock()

    def write(self, text: str) -> None:
        with self._lock:
            if self._len >= MAX_JOB_OUTPUT:
                if not self._truncated:
                    self._truncated = True
                    self._buf.append("\n[output truncated by the GUI at "
                                     f"{MAX_JOB_OUTPUT} bytes — see the terminal or audit/ "
                                     "for the full log]\n")
                return
            self._buf.append(text)
            self._len += len(text)

    def read(self, offset: int) -> tuple[str, int]:
        with self._lock:
            text = "".join(self._buf)
        offset = max(0, min(offset, len(text)))
        return text[offset:], len(text)

    def summary(self) -> dict:
        return {"job_id": self.id, "verb": self.verb, "label": self.label,
                "engagement": self.engagement, "status": self.status, "rc": self.rc,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "argv": self.argv}


class JobRunner:
    """Runs one action at a time and keeps the last few for polling."""

    KEEP = 20

    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._active: Job | None = None
        self._lock = threading.Lock()

    def active(self) -> Job | None:
        with self._lock:
            return self._active

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def start(self, verb: str, engagement: str, argv: list[str], label: str,
              cwd: Path, env: dict, on_done) -> Job:
        job = Job(verb, engagement, argv, label)
        with self._lock:
            if self._active is not None and self._active.status == "running":
                raise Busy(f"'{self._active.verb}' is still running")
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.KEEP:
                self._jobs.pop(self._order.pop(0), None)
            self._active = job
        threading.Thread(target=self._run, args=(job, cwd, env, on_done),
                         daemon=True, name=f"dw-job-{verb}").start()
        return job

    def _run(self, job: Job, cwd: Path, env: dict, on_done) -> None:
        job.write(f"$ {' '.join(job.argv)}\n\n")
        try:
            proc = subprocess.Popen(
                job.argv, cwd=str(cwd), env=env, shell=False,   # never shell=True
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", bufsize=1,
            )
        except OSError as exc:
            job.write(f"failed to start: {exc}\n")
            job.rc, job.status, job.finished_at = 127, "failed", _now_iso()
            self._finish(job, on_done)
            return
        assert proc.stdout is not None
        for line in proc.stdout:
            job.write(line)
        job.rc = proc.wait()
        job.status = "done" if job.rc == 0 else "failed"
        job.finished_at = _now_iso()
        job.write(f"\n[exit {job.rc}]\n")
        self._finish(job, on_done)

    def _finish(self, job: Job, on_done) -> None:
        try:
            on_done(job)
        finally:
            with self._lock:
                if self._active is job:
                    self._active = None


# --------------------------------------------------------------------------- the app

class GuiApp:
    """Everything the handler needs, with no HTTP in it (so it is unit-testable)."""

    def __init__(self, repo_root: Path, token: str, port: int, operator: str,
                 engagement: str | None = None):
        # The token is echoed into a Set-Cookie header; a caller-supplied value containing
        # CR/LF would be header injection, so refuse anything that is not token_urlsafe-shaped.
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            raise ValueError("token must be a urlsafe string of 16-128 chars")
        self.repo_root = Path(repo_root).resolve()
        self.engagements_dir = (self.repo_root / "engagements").resolve()
        self.static_dir = (Path(__file__).resolve().parent / "gui").resolve()
        self.scripts_dir = Path(__file__).resolve().parent
        self.cli_path = self.repo_root / "bin" / "driftwatch"
        self.token = token
        self.port = port
        self.operator = operator
        self.engagement = engagement
        self.jobs = JobRunner()

    # ---- path safety ---------------------------------------------------------------
    def engagement_dir(self, engagement_id: str) -> Path:
        """Resolve engagements/<id>, refusing anything that is not a direct child.

        Two independent checks: the id must match the allowlist regex (so '..', '/', and
        absolute paths never reach the join), and the RESOLVED path must still be a direct
        child of the resolved engagements dir (so a symlink cannot escape either).
        """
        if not isinstance(engagement_id, str) or not ENGAGEMENT_RE.match(engagement_id):
            raise ValueError(f"invalid engagement id: {engagement_id!r}")
        candidate = (self.engagements_dir / engagement_id).resolve()
        if candidate.parent != self.engagements_dir:
            raise ValueError(f"engagement id escapes the engagements dir: {engagement_id!r}")
        return candidate

    def existing_engagement_dir(self, engagement_id: str) -> Path:
        path = self.engagement_dir(engagement_id)
        if not path.is_dir():
            raise ValueError(f"no such engagement: {engagement_id}")
        return path

    @staticmethod
    def valid_run_id(run_id: str) -> bool:
        return isinstance(run_id, str) and bool(RUN_ID_RE.match(run_id))

    # ---- audit ---------------------------------------------------------------------
    def audit(self, engagement_dir: Path, verb: str, run_id: str, outcome: str) -> None:
        """One line per GUI-triggered action, CLI format (CONTRACTS §8). `via=gui` in the
        outcome keeps GUI-initiated work distinguishable from a terminal invocation."""
        line = (f"{_now_iso()} | {_audit_safe(verb)} | {_audit_safe(run_id) if run_id else '-'} "
                f"| {_audit_safe(self.operator)} | {_audit_safe(outcome)}\n")
        try:
            engagement_dir.mkdir(parents=True, exist_ok=True)
            with open(engagement_dir / "audit.log", "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line)
        except OSError as exc:  # never let an audit failure hide the action
            sys.stderr.write(f"[gui] WARN: could not append to audit.log: {exc}\n")

    # ---- read models ---------------------------------------------------------------
    def list_engagements(self) -> list[dict]:
        out = []
        if not self.engagements_dir.is_dir():
            return out
        for path in sorted(self.engagements_dir.iterdir()):
            if not path.is_dir() or path.name.startswith("_"):
                continue
            if not ENGAGEMENT_RE.match(path.name):
                continue
            # A symlink/junction planted in engagements/ points somewhere else entirely;
            # listing it would glob (and later name) files outside the engagement tree, and
            # selecting it 400s anyway. Same containment rule as engagement_dir().
            try:
                if path.resolve().parent != self.engagements_dir:
                    continue
            except OSError:
                continue
            out.append({
                "id": path.name,
                "has_scope": (path / "scope.yml").is_file(),
                "runs": len(self.run_ids(path)),
            })
        return out

    def run_ids(self, engagement_dir: Path) -> list[str]:
        """Every run this engagement knows about, newest first (run_ids sort chronologically)."""
        ids: set[str] = set()
        for sub, pattern in (("findings", "*.ndjson"), ("snapshots/_run", "*.json"),
                             ("reports", "*.md"), ("reports", "*.html")):
            d = engagement_dir.joinpath(*sub.split("/"))
            if not d.is_dir():
                continue
            for p in d.glob(pattern):
                if RUN_ID_RE.match(p.stem):
                    ids.add(p.stem)
        return sorted(ids, reverse=True)

    def read_scope(self, engagement_dir: Path) -> dict:
        """Parsed scope.yml plus a parse-status the health strip can show honestly."""
        path = engagement_dir / "scope.yml"
        info: dict = {"exists": path.is_file(), "parses": False, "error": "", "data": {},
                      "path": str(path), "raw": ""}
        if not info["exists"]:
            return info
        import yaml
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
            if not isinstance(data, dict):
                raise ValueError("scope.yml is not a mapping")
            info.update(parses=True, data=data, raw=raw)
        except Exception as exc:
            info["error"] = str(exc)
        return info

    def health(self, engagement_id: str) -> dict:
        """Dashboard health strip: is this engagement actually ready to be worked?"""
        d = self.existing_engagement_dir(engagement_id)
        scope = self.read_scope(d)
        data = scope["data"]
        in_scope = data.get("in_scope") or []
        ranges = sum(1 for e in in_scope if isinstance(e, dict) and e.get("cidr"))
        hosts = sum(1 for e in in_scope if isinstance(e, dict) and (e.get("host") or e.get("ip")))

        fleet_groups_path = d / "inventory" / "fleet_groups.json"
        inventory_hosts = 0
        if fleet_groups_path.is_file():
            try:
                inventory_hosts = len(json.loads(fleet_groups_path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                inventory_hosts = 0

        snapshots_dir = d / "snapshots"
        snapshot_hosts = snapshot_docs = 0
        if snapshots_dir.is_dir():
            for host_dir in snapshots_dir.iterdir():
                if host_dir.is_dir() and host_dir.name != "_run":
                    snapshot_hosts += 1
                    snapshot_docs += len(list(host_dir.glob("*.json")))

        runs = self.run_ids(d)
        latest = runs[0] if runs else None
        findings_files = len(list((d / "findings").glob("*.ndjson"))) if (d / "findings").is_dir() else 0
        reports = self.list_reports(d)

        latest_summary = {"available": False, "by_severity": _count_by_severity([]),
                          "active": 0, "suppressed": 0, "total": 0, "new_this_run": 0,
                          "collected_at": ""}
        if latest:
            try:
                ctx = report_gen.build_context(d, latest)
                latest_summary = {
                    "available": True,
                    "by_severity": ctx["totals"]["by_severity"],
                    "active": ctx["totals"]["active"],
                    "suppressed": ctx["totals"]["suppressed"],
                    "total": ctx["totals"]["total"],
                    "new_this_run": ctx["delta"]["new_count"],
                    "collected_at": _iso_from_mtime(d / "snapshots" / "_run" / f"{latest}.json")
                    or _iso_from_mtime(d / "findings" / f"{latest}.ndjson"),
                }
            except Exception as exc:
                latest_summary["error"] = f"could not summarize {latest}: {exc}"

        return {
            "engagement": engagement_id,
            "path": str(d),
            "scope": {
                "exists": scope["exists"], "parses": scope["parses"], "error": scope["error"],
                "path": scope["path"],
                "client": data.get("client", "") if scope["parses"] else "",
                "authorized_by": data.get("authorized_by", "") if scope["parses"] else "",
                "engagement_field": data.get("engagement", "") if scope["parses"] else "",
                "in_scope_ranges": ranges, "in_scope_hosts": hosts,
                "deny": len(data.get("deny") or []),
                "oob_subnets": len(data.get("oob_subnets") or []),
                "settings": data.get("settings") or {},
                "authorizes_nothing": scope["parses"] and not in_scope,
            },
            "inventory": {
                "generated": (d / "inventory" / "hosts.yml").is_file() and fleet_groups_path.is_file(),
                "hosts": inventory_hosts,
                "path": str(d / "inventory" / "hosts.yml"),
            },
            "vault": {"present": (d / "vault" / "vault.yml").is_file()},
            "counts": {
                "snapshot_hosts": snapshot_hosts, "snapshot_docs": snapshot_docs,
                "runs": len(runs), "findings_files": findings_files, "reports": len(reports),
            },
            "latest_run": latest,
            "latest": latest_summary,
            "runs": runs,
        }

    def run_payload(self, engagement_id: str, run_id: str) -> dict:
        """Everything the findings browser + fleet matrix need, in one fetch.

        Built from report_gen.build_context so the GUI shows exactly what the report shows
        (same enrichment, same severity ordering, same matrix from fleet_stats.build_matrix)
        rather than a second, drifting implementation.
        """
        d = self.existing_engagement_dir(engagement_id)
        if not self.valid_run_id(run_id):
            raise ValueError(f"invalid run id: {run_id!r}")
        ctx = report_gen.build_context(d, run_id)

        # The context splits findings across severity sections + a suppressed appendix;
        # the browser wants one list. Raw `detail` rides along for the before/after panel.
        raw_by_id = {}
        ndjson = d / "findings" / f"{run_id}.ndjson"
        if ndjson.is_file():
            for rec in dc.load_ndjson(ndjson):
                raw_by_id[rec.get("finding_id")] = rec.get("detail", {}) or {}

        findings = []
        for section in ctx["severity_sections"]:
            findings.extend(section["findings"])
        findings.extend(ctx["suppressed"])
        for f in findings:
            f["detail"] = raw_by_id.get(f["finding_id"], {})

        hosts = sorted({h for f in findings for h in f["hosts"]} | set(ctx["matrix"]["hosts"]))
        categories = sorted({f["category"] for f in findings if f["category"]})
        return {
            "engagement": ctx["engagement"], "client": ctx["client"],
            "authorized_by": ctx["authorized_by"],
            "run_id": run_id, "prev_run_id": ctx["prev_run_id"],
            "generated_at": ctx["generated_at"],
            "totals": ctx["totals"], "run_health": ctx["run_health"],
            "delta": {k: ctx["delta"][k] for k in
                      ("prev_available", "prev_run_id", "rows", "new_count",
                       "total_current", "total_previous")},
            "matrix": ctx["matrix"], "findings": findings,
            "hosts": hosts, "categories": categories,
            "runs": self.run_ids(d),
        }

    def list_reports(self, engagement_dir: Path) -> list[dict]:
        out = []
        reports_dir = engagement_dir / "reports"
        if not reports_dir.is_dir():
            return out
        seen: dict[str, dict] = {}
        for path in sorted(reports_dir.iterdir()):
            if path.suffix not in (".md", ".html") or not RUN_ID_RE.match(path.stem):
                continue
            entry = seen.setdefault(path.stem, {"run_id": path.stem, "formats": {}})
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            entry["formats"][path.suffix.lstrip(".")] = {
                "path": str(path), "size": size, "modified": _iso_from_mtime(path),
            }
        out = [seen[k] for k in sorted(seen, reverse=True)]
        return out

    def report_path(self, engagement_id: str, run_id: str, fmt: str) -> Path:
        """Report files are addressed by (validated) run id + fixed extension — the client
        never supplies a filename, so there is nothing to traverse with."""
        if fmt not in ("md", "html"):
            raise ValueError(f"invalid format: {fmt!r}")
        if not self.valid_run_id(run_id):
            raise ValueError(f"invalid run id: {run_id!r}")
        d = self.existing_engagement_dir(engagement_id)
        path = (d / "reports" / f"{run_id}.{fmt}").resolve()
        if path.parent != (d / "reports").resolve():
            raise ValueError("report path escapes the reports dir")
        if not path.is_file():
            raise ValueError(f"no {fmt} report for run {run_id}")
        return path

    def audit_tail(self, engagement_id: str, limit: int = 500) -> dict:
        d = self.existing_engagement_dir(engagement_id)
        path = d / "audit.log"
        if not path.is_file():
            return {"path": str(path), "exists": False, "lines": []}
        limit = max(1, min(int(limit), AUDIT_TAIL_MAX))
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        tail = lines[-limit:]
        parsed = []
        for raw in reversed(tail):                       # newest first
            parts = [p.strip() for p in raw.split("|")]
            parsed.append({
                "raw": raw,
                "ts": parts[0] if len(parts) > 0 else "",
                "verb": parts[1] if len(parts) > 1 else "",
                "run_id": parts[2] if len(parts) > 2 else "",
                "operator": parts[3] if len(parts) > 3 else "",
                "outcome": " | ".join(parts[4:]) if len(parts) > 4 else "",
            })
        return {"path": str(path), "exists": True, "total": len(lines), "lines": parsed}

    # ---- actions -------------------------------------------------------------------
    def action_argv(self, verb: str, engagement_id: str, deep: bool = False) -> list[str]:
        """Build the argv for a verb. Always a list, never a shell string."""
        d = self.existing_engagement_dir(engagement_id)
        if verb == "scope-generate":
            # scope_gate is control-node Python; call it directly with this interpreter so
            # the wizard's "generate inventory" works even where bash is not the shell.
            return [sys.executable, str(self.scripts_dir / "scope_gate.py"),
                    "generate", "--engagement-dir", str(d)]
        argv = [str(self.cli_path), "--engagement", engagement_id, verb]
        if verb == "collect" and deep:
            argv.append("--deep")
        # bin/driftwatch is bash. On a non-POSIX shell (or a ZIP checkout that lost the exec
        # bit) invoke it through bash explicitly rather than failing with EACCES/WinError.
        if os.name == "nt" or not os.access(self.cli_path, os.X_OK):
            bash = shutil.which("bash")
            if bash:
                argv = [bash] + argv
        return argv

    def start_action(self, verb: str, engagement_id: str, deep: bool = False) -> Job:
        if verb not in ACTIONS:
            raise ValueError(f"verb not permitted from the GUI: {verb!r}")
        d = self.existing_engagement_dir(engagement_id)
        argv = self.action_argv(verb, engagement_id, deep=deep)
        label = ACTIONS[verb]["label"] + (" --deep" if (verb == "collect" and deep) else "")
        env = dict(os.environ)
        env.update(DRIFTWATCH_ENGAGEMENT=engagement_id,
                   DRIFTWATCH_ENGAGEMENT_DIR=str(d),
                   DRIFTWATCH_OPERATOR=self.operator,
                   PYTHONIOENCODING="utf-8")

        def on_done(job: Job) -> None:
            outcome = "ok" if job.rc == 0 else "FAILED"
            self.audit(d, verb, "-", f"via=gui rc={job.rc} {outcome}")

        self.audit(d, verb, "-", f"via=gui started ({label})")
        return self.jobs.start(verb, engagement_id, argv, label, self.repo_root, env, on_done)


# --------------------------------------------------------------------------- scope wizard

def _err(errors: list[str], msg: str) -> None:
    errors.append(msg)


def validate_scope_form(form: dict) -> tuple[dict, list[str]]:
    """Validate a wizard submission and shape it into the CONTRACTS §1.4 document.

    Fail closed (design §15.2): a blank `authorized_by` or an empty `in_scope` is a REFUSAL,
    not a warning — an empty scope authorizes nothing, and writing a permissive file to be
    "helpful" would defeat the one control that keeps the kit inside its authorization.
    """
    errors: list[str] = []
    if not isinstance(form, dict):
        return {}, ["malformed request body"]

    engagement = str(form.get("engagement", "") or "").strip()
    if not ENGAGEMENT_RE.match(engagement):
        _err(errors, "engagement id must be letters/digits/._- (e.g. acme-2026-07)")

    client = str(form.get("client", "") or "").strip()
    if not client:
        _err(errors, "client is required")

    authorized_by = str(form.get("authorized_by", "") or "").strip()
    if not authorized_by:
        _err(errors, "authorized_by is REQUIRED — name who authorized this and the SOW "
                     "reference; no run proceeds without it (design §15.2)")

    def groups_of(entry: dict, where: str) -> list[str]:
        raw = entry.get("groups")
        if isinstance(raw, str):
            raw = [g.strip() for g in raw.split(",")]
        groups = [str(g).strip() for g in (raw or []) if str(g).strip()]
        for g in groups:
            if not GROUP_RE.match(g):
                _err(errors, f"{where}: '{g}' is not a valid ansible group name")
        if not groups:
            _err(errors, f"{where}: at least one group is required")
        return groups

    raw_in_scope = form.get("in_scope") or []
    if not isinstance(raw_in_scope, list):
        # A string would otherwise be iterated character by character; a mapping by key.
        # Refuse the shape outright rather than "interpreting" an authorization document.
        _err(errors, "in_scope must be a list of entries")
        raw_in_scope = []
    in_scope = []
    for i, entry in enumerate(raw_in_scope, 1):
        if not isinstance(entry, dict):
            _err(errors, f"in_scope[{i}]: malformed entry")
            continue
        where = f"in_scope[{i}]"
        cidr = str(entry.get("cidr", "") or "").strip()
        host = str(entry.get("host", "") or "").strip()
        ip = str(entry.get("ip", "") or "").strip()
        if cidr and not (host or ip):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                _err(errors, f"{where}: bad CIDR '{cidr}' ({exc})")
                continue
            in_scope.append({"cidr": str(net), "groups": groups_of(entry, where)})
        elif host or ip:
            if not HOSTNAME_RE.match(host):
                _err(errors, f"{where}: '{host}' is not a valid hostname/FQDN "
                             "(Kerberos resolves SPNs by name, design §3.1)")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                _err(errors, f"{where}: '{ip}' is not a valid IP — the scope gate keys off "
                             "IPs and fails closed without one")
                continue
            in_scope.append({"host": host, "ip": str(ipaddress.ip_address(ip)),
                             "groups": groups_of(entry, where)})
        else:
            _err(errors, f"{where}: needs either a cidr, or a host + ip")
    if not in_scope:
        _err(errors, "REFUSED: in_scope is empty. An empty scope authorizes nothing — "
                     "the wizard will not write a file that could later be read as "
                     "permissive (design §15.2, fail closed)")

    def nets(key: str) -> list[str]:
        out = []
        values = form.get(key) or []
        if not isinstance(values, list):
            _err(errors, f"{key} must be a list of CIDRs")
            return out
        for raw in values:
            raw = str(raw).strip()
            if not raw:
                continue
            try:
                out.append(str(ipaddress.ip_network(raw, strict=False)))
            except ValueError as exc:
                _err(errors, f"{key}: bad CIDR '{raw}' ({exc})")
        return out

    deny = [{"cidr": c} for c in nets("deny")]
    oob = nets("oob_subnets")

    s_in = form.get("settings") or {}
    if not isinstance(s_in, dict):
        _err(errors, "settings must be a mapping")
        s_in = {}
    hash_policy = str(s_in.get("hash_policy", "tiered") or "tiered").strip()
    if hash_policy not in HASH_POLICIES:
        _err(errors, f"hash_policy must be one of: {', '.join(HASH_POLICIES)}")
    collector = str(s_in.get("collector_account", "") or "").strip()
    if not collector:
        _err(errors, "collector_account is required (the normalizer tags its own artifacts "
                     "with it, CONTRACTS §6)")
    try:
        max_prev = float(s_in.get("outlier_max_prevalence", 0.05))
        if not 0 < max_prev <= 1:
            raise ValueError
    except (TypeError, ValueError):
        max_prev = 0.05
        _err(errors, "outlier_max_prevalence must be a fraction in (0, 1], e.g. 0.05")
    try:
        min_group = int(s_in.get("outlier_min_group", 20))
        if min_group < 1:
            raise ValueError
    except (TypeError, ValueError):
        min_group = 20
        _err(errors, "outlier_min_group must be a positive integer")

    doc = {
        "engagement": engagement,
        "client": client,
        "authorized_by": authorized_by,
        "in_scope": in_scope,
        "deny": deny,
        "oob_subnets": oob,
        "settings": {
            "hash_policy": hash_policy,
            "collector_account": collector,
            "outlier_max_prevalence": max_prev,
            "outlier_min_group": min_group,
            "fast_interval": str(s_in.get("fast_interval", "2h") or "2h"),
            "deep_interval": str(s_in.get("deep_interval", "24h") or "24h"),
            "splunk_hec_url": str(s_in.get("splunk_hec_url", "") or ""),
            "splunk_hec_token_var": str(s_in.get("splunk_hec_token_var", "")
                                        or "vault_splunk_hec_token"),
            "elastic_url": str(s_in.get("elastic_url", "") or ""),
        },
    }
    return doc, errors


_SCOPE_HEADER = """\
# driftwatch — engagement scope.yml (CONTRACTS.md §1.4; design §15.2)
# Written by the driftwatch GUI setup wizard on {ts} by {operator}.
#
# This file is the authorization rail: the ONLY source for inventory generation and the
# single place that says which addresses this engagement may touch. It fails CLOSED —
# scripts/scope_gate.py refuses to run when in_scope is empty. Fill it in from the SIGNED
# authorization document, not from what happens to be reachable (design §15.2).
#
# A bare `cidr` entry authorizes a RANGE but creates no addressable inventory host: hosts
# discovered inside it must be added explicitly as host/ip entries before they are ever
# touched (discovery != access). Every device NOT in `oob_subnets` is assumed IN-BAND
# (design §13.5), which is what makes the response layer warn before it cuts the path it
# is talking over.
"""


def render_scope_yaml(doc: dict, operator: str) -> str:
    """Serialize with yaml.safe_dump (never hand-built strings — the values are analyst
    input and safe_dump is what guarantees they are quoted/escaped correctly)."""
    import yaml
    body = yaml.safe_dump(doc, default_flow_style=False, sort_keys=False, allow_unicode=True,
                          width=100)
    return _SCOPE_HEADER.format(ts=_now_iso(), operator=operator) + "\n" + body


def verify_scope_yaml(text: str) -> list[str]:
    """Round-trip the generated YAML through the real authorization-rail code before it is
    ever written: if scope_gate cannot load and compile it, the analyst does not get it."""
    import yaml
    errors: list[str] = []
    try:
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        return [f"generated YAML does not parse: {exc}"]
    if not data.get("in_scope"):
        return ["generated YAML has no in_scope entries — refusing (fail closed)"]
    try:
        compiled = scope_gate.Scope(data)
        scope_gate.build_inventory(compiled)
    except Exception as exc:
        errors.append(f"scope_gate rejected the generated scope: {exc}")
    return errors


ENGAGEMENT_SUBDIRS = ("inventory", "vault", "preflight", "snapshots/_run", "configs",
                      "baselines", "findings", "cases", "evidence", "reports",
                      "audit/hostlogs")


def create_engagement_volume(path: Path) -> None:
    """Create the CONTRACTS §1.2 skeleton. No credentials are created or touched here —
    vault/ is made empty and 0700; filling it stays a deliberate CLI/operator act (§15.3)."""
    for sub in ENGAGEMENT_SUBDIRS:
        path.joinpath(*sub.split("/")).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path / "vault", 0o700)
    except OSError:
        pass
    audit_log = path / "audit.log"
    if not audit_log.exists():
        audit_log.touch()
    gitignore = path / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("vault/\n.factcache/\n.retry/\n*.lock\n",
                             encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------- HTTP layer

class _Refuse(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "driftwatch-gui"
    sys_version = ""
    # Without this a connection that stops sending bytes mid-request pins a thread forever;
    # a handful of them starves the console. Loopback has no excuse to be slow.
    timeout = 30
    app: GuiApp = None  # type: ignore[assignment]

    # ---- logging: never echo the query string (it can carry the token) -------------
    def log_message(self, fmt, *args):  # noqa: A003
        path = urlparse(self.path).path
        sys.stderr.write(f"[gui] {self.command} {path} -> {args[1] if len(args) > 1 else ''}\n")

    def log_error(self, fmt, *args):
        return

    # ---- response helpers ----------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        headers = {"X-Frame-Options": "DENY", "Content-Security-Policy": APP_CSP}
        headers.update(extra or {})
        if status >= 400:
            # Every refusal path (403 for a bad token, 415/413 in _read_json, 404) answers
            # BEFORE the request body has been consumed. On a keep-alive HTTP/1.1 connection
            # those unread bytes are then parsed as the next request — so a single refused
            # POST whose body happens to contain "GET /api/... HTTP/1.1" gets that buried
            # request executed and desynchronises the response queue. Refusing to keep the
            # connection is the fix: the leftover body dies with the socket.
            self.close_connection = True
            headers["Connection"] = "close"
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _internal_error(self, exc: BaseException) -> None:
        """Unexpected failures go to the operator's terminal, never to the browser.

        The exception text carries absolute paths and engagement contents; the analyst can
        read the console they launched this from, and nothing else needs to see it.
        """
        sys.stderr.write(f"[gui] ERROR: {self.command} {urlparse(self.path).path}: "
                         f"{type(exc).__name__}: {exc}\n")
        self._error(500, "internal error — see the terminal running `driftwatch gui`")

    # ---- security gates ------------------------------------------------------------
    def _check_client(self) -> None:
        """Belt and braces behind the loopback bind."""
        addr = self.client_address[0] if self.client_address else ""
        if addr not in ("127.0.0.1", "::1"):
            raise _Refuse(403, "non-local client")

    def _check_host_header(self) -> None:
        """DNS-rebinding defence: a rebound name resolving to 127.0.0.1 still arrives with
        the attacker's Host header, so only the two names we actually serve are accepted."""
        host = (self.headers.get("Host") or "").strip()
        allowed = {f"127.0.0.1:{self.app.port}", f"localhost:{self.app.port}"}
        if host not in allowed:
            raise _Refuse(403, "bad Host header")

    def _presented_token(self) -> str | None:
        header = self.headers.get("X-DW-Token")
        if header:
            return header.strip()
        raw = self.headers.get("Cookie")
        if raw:
            try:
                cookie = SimpleCookie()
                cookie.load(raw)
            except Exception:
                return None
            morsel = cookie.get(COOKIE_NAME)
            if morsel:
                return morsel.value
        return None

    def _token_ok(self, presented: str | None) -> bool:
        if not presented:
            return False
        try:
            return secrets.compare_digest(presented, self.app.token)
        except (TypeError, ValueError):
            return False

    def _check_token(self) -> None:
        if not self._token_ok(self._presented_token()):
            raise _Refuse(403, "missing or invalid token")

    def _check_mutating(self) -> None:
        """POST-only routes need the token in the HEADER (a cookie alone is forgeable
        cross-site) AND a same-origin Origin/Referer. Together those defeat CSRF from any
        other page the analyst has open."""
        header = self.headers.get("X-DW-Token")
        if not self._token_ok(header.strip() if header else None):
            raise _Refuse(403, "mutating requests require the X-DW-Token header")
        origins = {f"http://127.0.0.1:{self.app.port}", f"http://localhost:{self.app.port}"}
        origin = (self.headers.get("Origin") or "").strip()
        referer = (self.headers.get("Referer") or "").strip()
        if origin:
            if origin not in origins:
                raise _Refuse(403, "cross-origin request refused")
        elif referer:
            parsed = urlparse(referer)
            if f"{parsed.scheme}://{parsed.netloc}" not in origins:
                raise _Refuse(403, "cross-origin referer refused")
        else:
            raise _Refuse(403, "missing Origin/Referer on a mutating request")

    def _read_json(self) -> dict:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise _Refuse(415, "expected Content-Type: application/json")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise _Refuse(400, "bad Content-Length")
        if length <= 0:
            raise _Refuse(400, "empty body")
        if length > MAX_BODY:
            raise _Refuse(413, "body too large")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise _Refuse(400, "malformed JSON body")
        if not isinstance(body, dict):
            # Every POST route reaches for .get(); a bare list/string/null would otherwise
            # surface as a 500 carrying a Python type error.
            raise _Refuse(400, "expected a JSON object")
        return body

    # ---- dispatch ------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        try:
            self._check_client()
            self._check_host_header()
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            path = parsed.path

            # First load: accept the token from the query, hand back an HttpOnly cookie and
            # redirect to a clean URL so the token stops living in the address bar/history.
            if path == "/" and "token" in query:
                if not self._token_ok(query["token"][0]):
                    raise _Refuse(403, "invalid token")
                self._send(303, b"", "text/plain; charset=utf-8", {
                    "Location": "/",
                    "Set-Cookie": (f"{COOKIE_NAME}={self.app.token}; Path=/; HttpOnly; "
                                   "SameSite=Strict"),
                })
                return

            self._check_token()
            if path in ("/", "/index.html"):
                return self._serve_static("index.html")
            name = path.lstrip("/")
            if name in STATIC_FILES:
                return self._serve_static(name)
            if path.startswith("/api/"):
                return self._api_get(path, query)
            self._error(404, "not found")
        except _Refuse as exc:
            self._error(exc.status, exc.message)
        except Exception as exc:  # keep the analyst informed rather than dying silently
            self._internal_error(exc)

    def do_POST(self):  # noqa: N802
        try:
            self._check_client()
            self._check_host_header()
            self._check_token()
            self._check_mutating()
            path = urlparse(self.path).path
            body = self._read_json()
            if path == "/api/action":
                return self._post_action(body)
            if path == "/api/scope/preview":
                return self._post_scope_preview(body)
            if path == "/api/scope/save":
                return self._post_scope_save(body)
            self._error(404, "not found")
        except _Refuse as exc:
            self._error(exc.status, exc.message)
        except Exception as exc:
            self._internal_error(exc)

    def do_OPTIONS(self):  # noqa: N802
        # No CORS. Ever. (Refusing the preflight is half of why X-DW-Token works as a
        # CSRF defence.)
        self._error(405, "method not allowed")

    def do_PUT(self):  # noqa: N802
        self._error(405, "method not allowed")

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_HEAD = do_PUT

    # ---- static --------------------------------------------------------------------
    def _serve_static(self, name: str) -> None:
        content_type = STATIC_FILES.get(name)
        if not content_type:
            return self._error(404, "not found")
        path = (self.app.static_dir / name).resolve()
        if path.parent != self.app.static_dir or not path.is_file():
            return self._error(404, f"missing asset: {name}")
        self._send(200, path.read_bytes(), content_type)

    # ---- GET api -------------------------------------------------------------------
    @staticmethod
    def _one(query: dict, key: str, default: str = "") -> str:
        values = query.get(key)
        return values[0] if values else default

    def _api_get(self, path: str, query: dict) -> None:
        app = self.app
        try:
            if path == "/api/state":
                return self._json({
                    # The SPA echoes this in X-DW-Token on POSTs. Safe to hand out here:
                    # a cross-origin page cannot read this response (no CORS headers), and
                    # the cookie that authenticates the request is HttpOnly + SameSite=Strict.
                    "csrf_token": app.token,
                    "engagements": app.list_engagements(),
                    "engagement": app.engagement,
                    "operator": app.operator,
                    "repo_root": str(app.repo_root),
                    "engagements_dir": str(app.engagements_dir),
                    "cli": {"path": str(app.cli_path), "present": app.cli_path.is_file()},
                    "actions": ACTIONS,
                    "severities": list(dc.SEVERITIES),
                    "hash_policies": list(HASH_POLICIES),
                    "version": dc.COLLECTOR_VERSION,
                    "port": app.port,
                })
            if path == "/api/engagement":
                return self._json(app.health(self._one(query, "engagement")))
            if path == "/api/run":
                return self._json(app.run_payload(self._one(query, "engagement"),
                                                  self._one(query, "run")))
            if path == "/api/reports":
                d = app.existing_engagement_dir(self._one(query, "engagement"))
                return self._json({"reports": app.list_reports(d)})
            if path == "/api/report":
                report = app.report_path(self._one(query, "engagement"),
                                         self._one(query, "run"),
                                         self._one(query, "fmt", "md"))
                return self._json({"path": str(report),
                                   "text": report.read_text(encoding="utf-8", errors="replace")})
            if path == "/api/report/frame":
                report = app.report_path(self._one(query, "engagement"),
                                         self._one(query, "run"), "html")
                # Sandboxed twice: this header plus the iframe's own sandbox attribute.
                return self._send(200, report.read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": FRAME_CSP,
                                   "X-Frame-Options": "SAMEORIGIN"})
            if path == "/api/audit":
                return self._json(app.audit_tail(self._one(query, "engagement"),
                                                 int(self._one(query, "limit", "500") or 500)))
            if path == "/api/scope":
                d = app.existing_engagement_dir(self._one(query, "engagement"))
                info = app.read_scope(d)
                return self._json(info)
            if path == "/api/job":
                job = app.jobs.get(self._one(query, "id"))
                if job is None:
                    return self._error(404, "unknown job")
                try:
                    offset = int(self._one(query, "offset", "0") or 0)
                except ValueError:
                    offset = 0
                chunk, new_offset = job.read(offset)
                payload = job.summary()
                payload.update(chunk=chunk, offset=new_offset)
                return self._json(payload)
        except ValueError as exc:
            return self._error(400, str(exc))
        self._error(404, "not found")

    # ---- POST api ------------------------------------------------------------------
    def _post_action(self, body: dict) -> None:
        verb = str(body.get("verb", ""))
        engagement = str(body.get("engagement", ""))
        deep = bool(body.get("deep", False))
        if verb not in ACTIONS:
            return self._error(403, f"verb not permitted from the GUI: {verb!r}")
        try:
            job = self.app.start_action(verb, engagement, deep=deep)
        except Busy as exc:
            return self._error(409, f"another action is running: {exc}")
        except ValueError as exc:
            return self._error(400, str(exc))
        self._json(job.summary(), 202)

    def _post_scope_preview(self, body: dict) -> None:
        # NOT `or {}`: an empty/odd form must reach validate_scope_form and be REFUSED there,
        # never quietly turned into a document with defaults.
        doc, errors = validate_scope_form(body.get("form"))
        text = render_scope_yaml(doc, self.app.operator) if not errors else ""
        if text:
            errors.extend(verify_scope_yaml(text))
        self._json({"ok": not errors, "errors": errors, "yaml": text})

    def _post_scope_save(self, body: dict) -> None:
        form = body.get("form")
        mode = str(body.get("mode", "edit"))
        overwrite = bool(body.get("overwrite", False))
        doc, errors = validate_scope_form(form)
        if errors:
            return self._json({"ok": False, "errors": errors}, 422)

        text = render_scope_yaml(doc, self.app.operator)
        errors = verify_scope_yaml(text)
        if errors:
            return self._json({"ok": False, "errors": errors}, 422)

        engagement_id = doc["engagement"]
        try:
            target = self.app.engagement_dir(engagement_id)
        except ValueError as exc:
            return self._json({"ok": False, "errors": [str(exc)]}, 400)

        created = False
        if mode == "new":
            if target.exists():
                return self._json({"ok": False, "errors": [
                    f"engagement '{engagement_id}' already exists — edit it instead"]}, 409)
            create_engagement_volume(target)
            created = True
        else:
            if not target.is_dir():
                return self._json({"ok": False, "errors": [
                    f"no such engagement: {engagement_id}"]}, 404)
            if (target / "scope.yml").is_file() and not overwrite:
                return self._json({"ok": False, "errors": [
                    "scope.yml already exists — confirm the overwrite to replace the "
                    "authorization record"]}, 409)

        scope_path = target / "scope.yml"
        scope_path.write_text(text, encoding="utf-8", newline="\n")
        self.app.audit(target, "scope-write", "-",
                       f"via=gui {'created volume + ' if created else ''}wrote scope.yml "
                       f"in_scope={len(doc['in_scope'])} authorized_by set")
        self._json({"ok": True, "errors": [], "engagement": engagement_id,
                    "created": created, "path": str(scope_path), "yaml": text})


# --------------------------------------------------------------------------- server

def build_app(repo_root: Path | None = None, port: int = DEFAULT_PORT,
              engagement: str | None = None, token: str | None = None) -> GuiApp:
    """Assemble a GuiApp. Exposed so tests can point it at a scratch repo root."""
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    return GuiApp(root, token or secrets.token_urlsafe(32), port, _operator(), engagement)


class LoopbackServer(ThreadingHTTPServer):
    """Loopback listener that refuses to share its port.

    allow_reuse_address is OFF deliberately. socketserver turns it into SO_REUSEADDR, whose
    Windows semantics let ANY other local process bind the same port and start receiving our
    requests — which would hand it the analyst's token along with them. SO_EXCLUSIVEADDRUSE
    (Windows-only) states the same refusal explicitly. The cost is that a restart inside
    TIME_WAIT may have to move to the next port, which _bind already handles and reports.
    """

    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
            except OSError:
                pass
        super().server_bind()


def _bind(app: GuiApp, first_port: int) -> tuple[ThreadingHTTPServer, int]:
    """Bind 127.0.0.1 on the first free port in a small range."""
    last: OSError | None = None
    for port in range(first_port, first_port + PORT_SCAN):
        handler = type("BoundHandler", (Handler,), {"app": app})
        try:
            httpd = LoopbackServer((BIND_HOST, port), handler)
        except OSError as exc:
            last = exc
            continue
        app.port = port
        return httpd, port
    raise OSError(f"no free port in {first_port}..{first_port + PORT_SCAN - 1}: {last}")


def serve(port: int = DEFAULT_PORT, engagement: str | None = None, open_browser: bool = True,
          repo_root: Path | None = None, print_url_only: bool = False) -> int:
    app = build_app(repo_root=repo_root, port=port, engagement=engagement)

    if not app.engagements_dir.is_dir():
        sys.stderr.write(f"[gui] ERROR: no engagements dir at {app.engagements_dir} - "
                         "is this a driftwatch checkout?\n")
        return 1
    if not app.static_dir.is_dir():
        sys.stderr.write(f"[gui] ERROR: missing GUI assets at {app.static_dir}\n")
        return 1
    if engagement:
        try:
            app.existing_engagement_dir(engagement)
        except ValueError as exc:
            sys.stderr.write(f"[gui] REFUSED: {exc}\n")
            return 2

    try:
        httpd, bound_port = _bind(app, port)
    except OSError as exc:
        sys.stderr.write(f"[gui] ERROR: {exc}\n")
        return 1

    url = f"http://{BIND_HOST}:{bound_port}/?token={app.token}"
    if not print_url_only:
        if bound_port != port:
            sys.stderr.write(f"[gui] port {port} was busy, using {bound_port}\n")
        sys.stderr.write(
            f"[gui] driftwatch operator GUI on http://{BIND_HOST}:{bound_port} "
            f"(loopback only)\n"
            f"[gui] operator={app.operator} repo={app.repo_root}\n"
            f"[gui] this token is per-run: anyone without it gets 403. Ctrl-C to stop.\n")
    print(url, flush=True)

    if engagement:
        try:
            app.audit(app.existing_engagement_dir(engagement), "gui", "-",
                      f"via=gui started on 127.0.0.1:{bound_port}")
        except ValueError:
            pass

    if open_browser and not print_url_only:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[gui] stopping\n")
    finally:
        httpd.server_close()
        if engagement:
            try:
                app.audit(app.existing_engagement_dir(engagement), "gui", "-",
                          "via=gui stopped")
            except ValueError:
                pass
    return 0


def _port_arg(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port number: {raw!r}")
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return port


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="gui_server",
        description="Local-only operator GUI for driftwatch. Always binds 127.0.0.1 "
                    "(there is deliberately no --host flag) and mints a fresh token per run.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve", help="serve the operator GUI on loopback")
    p.add_argument("--port", type=_port_arg, default=DEFAULT_PORT,
                   help=f"first port to try (default {DEFAULT_PORT}); "
                        f"the next {PORT_SCAN - 1} are tried if it is busy")
    p.add_argument("--engagement", help="engagement id to open with")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser")
    p.add_argument("--print-url", action="store_true",
                   help="print only the tokenised URL (implies --no-browser)")
    args = parser.parse_args(argv)
    if args.cmd != "serve":
        return 1
    return serve(port=args.port, engagement=args.engagement,
                 open_browser=not (args.no_browser or args.print_url),
                 print_url_only=args.print_url)


if __name__ == "__main__":
    raise SystemExit(main())
