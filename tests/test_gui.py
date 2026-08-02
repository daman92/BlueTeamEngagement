"""Tests for scripts/gui_server.py — the LOCAL-ONLY operator GUI (design §7, §9, §13.6, §15.2).

This process listens on a kit that holds privileged credentials for a whole client fleet, so
most of what is asserted here is a security control rather than a feature:

  * loopback-only bind, with no way to configure an external address (design §9);
  * per-run token on EVERY request, compared with compare_digest;
  * Host-header allowlist (DNS-rebinding defence);
  * mutating routes: POST + X-DW-Token HEADER + same-origin Origin/Referer (CSRF);
  * path-traversal containment for every engagement/run id the client supplies;
  * findings are attacker-controlled data and must never reach an HTML-parsing sink;
  * the response layer (respond/approve/rollback) and teardown are ABSENT, not hidden (§13.6);
  * the wizard fails CLOSED — a blank authorized_by or an empty in_scope writes nothing (§15.2);
  * every GUI-triggered action lands in the engagement audit.log in the CLI's format (§8).

Hermetic by construction: no browser, no ansible, no container, no network beyond an
ephemeral loopback port. The server runs in a thread bound to 127.0.0.1:0 and is shut down
in the fixture, so no thread or port leaks between tests. Engagement data is a copytree of
tests/fixtures/report/engagement into a scratch repo root, so the real engagements/ volume is
never touched.

The frontend filter (severity / host / search) lives in scripts/gui/findings.js and cannot be
executed from pytest. It is covered two ways instead: `_client_matches` below is a faithful
port of that function exercised against the REAL API payload, and
`test_search_haystack_fields_are_all_served` re-reads findings.js and asserts every field the
JS filter reads is actually present on every finding the server sends — so the filter can
never silently narrow to nothing because the server stopped emitting a field.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

import driftwatch_common as dc
import fleet_stats
import gui_server
import report_gen

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "report" / "engagement"
GUI_DIR = Path(gui_server.__file__).resolve().parent / "gui"

ENGAGEMENT = "acme-2026-07"
RUN = "2026-07-22T0400Z"
PREV = "2026-07-22T0000Z"
EMPTY_ENGAGEMENT = "empty-2026-01"

# Strings that must never come back as executable markup. They are seeded into a finding's
# identity, which is where a real attacker controls the bytes (process args, file paths,
# cert subjects — CONTRACTS §3).
XSS_SCRIPT = "<script>alert(1)</script>"
XSS_IMG = '<img src=x onerror=alert(1)>'
XSS_SVG = "<svg onload=alert(1)>"

# CONTRACTS §4: the finding fields the GUI's findings browser reads.
CONTRACT_FIELDS = ("finding_id", "severity", "rule", "platform", "category", "change_type",
                   "hosts", "detail", "first_seen", "comparison", "suppressed",
                   "suppressed_by", "fingerprint")

# CONTRACTS §8: "<ISO8601> | <verb> | <run_id> | <operator> | <outcome>"
AUDIT_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \| [^|]+ \| [^|]+ \| [^|]+ \| .+$")

_DEFAULT = object()      # "use the fixture's real value"
_OMIT = object()         # "do not send this header at all"


# --------------------------------------------------------------------------- scratch repo

@pytest.fixture()
def repo_root(tmp_path) -> Path:
    """A scratch driftwatch checkout: engagements/ seeded from the report fixture.

    Also plants a file OUTSIDE engagements/ that no traversal test may ever surface.
    """
    root = tmp_path / "kit"
    (root / "engagements").mkdir(parents=True)
    shutil.copytree(FIXTURE, root / "engagements" / ENGAGEMENT)
    (root / "engagements" / EMPTY_ENGAGEMENT).mkdir()
    (root / "bin").mkdir()
    (tmp_path / "outside-secret.txt").write_text("TOPSECRET-VAULT-PASSPHRASE\n",
                                                 encoding="utf-8")
    return root


@pytest.fixture()
def app(repo_root) -> gui_server.GuiApp:
    a = gui_server.build_app(repo_root=repo_root, port=0, token=secrets.token_urlsafe(32))
    a.operator = "test-operator"
    return a


@pytest.fixture()
def engagement_dir(repo_root) -> Path:
    return repo_root / "engagements" / ENGAGEMENT


# --------------------------------------------------------------------------- HTTP client

class Resp:
    """A response (or refusal) with the bits the assertions care about."""

    def __init__(self, status: int, headers, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default) or default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow the 303 the token handshake issues — the test wants to SEE it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, app: gui_server.GuiApp, port: int):
        self.app = app
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self.origin = f"http://127.0.0.1:{port}"
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(self, path: str, method: str = "GET", *, token=_DEFAULT, cookie=None,
                origin=_OMIT, referer=_OMIT, host=None, body: bytes | None = None,
                content_type: str | None = None, extra: dict | None = None) -> Resp:
        headers: dict[str, str] = {}
        if token is _DEFAULT:
            headers["X-DW-Token"] = self.app.token
        elif token is not None:
            headers["X-DW-Token"] = token
        if cookie is _DEFAULT:
            headers["Cookie"] = f"{gui_server.COOKIE_NAME}={self.app.token}"
        elif cookie is not None:
            headers["Cookie"] = cookie
        if origin is _DEFAULT:
            headers["Origin"] = self.origin
        elif origin is not _OMIT and origin is not None:
            headers["Origin"] = origin
        if referer is _DEFAULT:
            headers["Referer"] = self.origin + "/"
        elif referer is not _OMIT and referer is not None:
            headers["Referer"] = referer
        if host:
            headers["Host"] = host
        if content_type:
            headers["Content-Type"] = content_type
        headers.update(extra or {})

        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers=headers)
        try:
            with self._opener.open(req, timeout=15) as resp:
                return Resp(resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as exc:      # 4xx/5xx and the un-followed 303
            return Resp(exc.code, dict(exc.headers), exc.read())

    def get(self, path: str, **kw) -> Resp:
        return self.request(path, "GET", **kw)

    def post(self, path: str, payload, *, token=_DEFAULT, origin=_DEFAULT, **kw) -> Resp:
        body = json.dumps(payload).encode("utf-8")
        return self.request(path, "POST", token=token, origin=origin, body=body,
                            content_type="application/json", **kw)

    # Convenience for the two payloads most tests need.
    def run_payload(self, engagement: str = ENGAGEMENT, run: str = RUN):
        resp = self.get(f"/api/run?engagement={engagement}&run={run}")
        assert resp.status == 200, resp.text
        return resp.json()


@pytest.fixture()
def gui(app):
    """A live server on 127.0.0.1:<ephemeral>, torn down with no leaked thread or port."""
    handler = type("BoundHandler", (gui_server.Handler,), {"app": app})
    httpd = gui_server.LoopbackServer((gui_server.BIND_HOST, 0), handler)
    app.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02},
                              daemon=True, name="dw-gui-test")
    thread.start()
    try:
        yield Client(app, app.port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=10)
        assert not thread.is_alive(), "the GUI server thread outlived its test"


# --------------------------------------------------------------------------- helpers

def seed_xss_finding(engagement_dir: Path, run_id: str = RUN) -> dict:
    """Append a finding whose attacker-controlled fields are live XSS payloads."""
    rec = {
        "finding_id": f"f-{run_id}-0099",
        "engagement": ENGAGEMENT,
        "run_id": run_id,
        "severity": "critical",
        "rule": "drift.linux.processes",
        "platform": "linux",
        "category": "processes",
        "change_type": "added",
        "hosts": ["web01"],
        "detail": {
            "identity": {"path": f"/tmp/{XSS_SCRIPT}", "args_norm": XSS_IMG,
                         "sha256": "deadbeef", "user": "root"},
            "before": None,
            "after": {"path": f"/tmp/{XSS_SCRIPT}", "args_norm": XSS_IMG},
            "note": XSS_SVG,
        },
        "first_seen": run_id,
        "comparison": ["temporal"],
        "suppressed": False,
        "suppressed_by": None,
        "fingerprint": "00abcdef00abcdef",
    }
    path = engagement_dir / "findings" / f"{run_id}.ndjson"
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(dc.canonical_json(rec) + "\n")
    return rec


def audit_lines(engagement_dir: Path) -> list[str]:
    path = engagement_dir / "audit.log"
    if not path.is_file():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _client_matches(f: dict, *, severities=None, host="", category="", q="",
                    suppressed="all") -> bool:
    """Faithful Python port of `matches()` in scripts/gui/findings.js.

    Kept deliberately literal (same field list, same lowercase substring search) so that a
    divergence between the served payload and what the browser filters on shows up here.
    """
    if severities is not None and f["severity"] not in severities:
        return False
    if suppressed == "hide" and f["suppressed"]:
        return False
    if suppressed == "only" and not f["suppressed"]:
        return False
    if host and host not in f["hosts"]:
        return False
    if category and f["category"] != category:
        return False
    if q:
        hay = " ".join(str(x) for x in [
            f["rule"], f["identity_str"], f["category"], f["change_type"], f["platform"],
            f["before_str"], f["after_str"], f["note"], " ".join(f["hosts"]),
            f["finding_id"], f["fingerprint"], f["headline"],
        ]).lower()
        if q.lower() not in hay:
            return False
    return True


# =========================================================================== bind posture

def test_bind_host_is_hardwired_loopback():
    assert gui_server.BIND_HOST == "127.0.0.1"


def test_cli_exposes_no_host_flag(capsys):
    """Requirement 1: "bind it to 0.0.0.0 for a second" must not be typo-able."""
    with pytest.raises(SystemExit):
        gui_server.main(["serve", "--help"])
    out = capsys.readouterr().out
    assert "--host" not in out
    assert "--port" in out
    # And not through serve()/build_app() either.
    for fn in (gui_server.serve, gui_server.build_app):
        assert "host" not in fn.__code__.co_varnames[:fn.__code__.co_argcount]


def test_server_socket_is_bound_to_loopback(gui):
    assert gui.app.port > 0
    resp = gui.get("/api/state")
    assert resp.status == 200
    assert resp.json()["port"] == gui.app.port


def test_port_arg_rejects_privileged_and_nonsense():
    import argparse
    for bad in ("0", "80", "70000", "eighty"):
        with pytest.raises(argparse.ArgumentTypeError):
            gui_server._port_arg(bad)
    assert gui_server._port_arg("8787") == 8787


def test_token_shape_is_enforced_against_header_injection(repo_root):
    """The token is echoed into Set-Cookie; CR/LF in it would be header injection."""
    for bad in ("short", "tok\r\nSet-Cookie: evil=1", "tok en", "", "a" * 200):
        with pytest.raises(ValueError):
            gui_server.GuiApp(repo_root, bad, 8787, "op")
    ok = secrets.token_urlsafe(32)
    assert gui_server.GuiApp(repo_root, ok, 8787, "op").token == ok


# =========================================================================== auth (token)

def test_no_token_is_403(gui):
    for path in ("/", "/index.html", "/app.js", "/api/state",
                 f"/api/run?engagement={ENGAGEMENT}&run={RUN}"):
        resp = gui.get(path, token=None)
        assert resp.status == 403, f"{path} -> {resp.status}"
        assert "token" in resp.json()["error"]


def test_wrong_token_is_403(gui):
    wrong = secrets.token_urlsafe(32)
    assert wrong != gui.app.token
    assert gui.get("/api/state", token=wrong).status == 403
    # Truncated, extended and non-ASCII variants must all fail closed, not explode.
    assert gui.get("/api/state", token=gui.app.token[:-1]).status == 403
    assert gui.get("/api/state", token=gui.app.token + "x").status == 403
    assert gui.get("/api/state", token="tokén-with-non-ascii").status == 403
    assert gui.get("/api/state", cookie=f"{gui_server.COOKIE_NAME}={wrong}",
                   token=None).status == 403


def test_right_token_is_200_via_header_and_via_cookie(gui):
    by_header = gui.get("/api/state")
    assert by_header.status == 200
    assert by_header.json()["csrf_token"] == gui.app.token

    by_cookie = gui.get("/api/state", token=None, cookie=_DEFAULT)
    assert by_cookie.status == 200
    assert by_cookie.json()["engagements"], "the fixture engagement should be listed"


def test_first_load_token_in_query_sets_httponly_cookie_and_redirects(gui):
    resp = gui.get(f"/?token={gui.app.token}", token=None)
    assert resp.status == 303
    assert resp.header("Location") == "/"
    cookie = resp.header("Set-Cookie")
    assert cookie.startswith(f"{gui_server.COOKIE_NAME}={gui.app.token}")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    # A wrong token in the query gets no cookie at all.
    bad = gui.get("/?token=" + secrets.token_urlsafe(32), token=None)
    assert bad.status == 403
    assert "Set-Cookie" not in bad.headers


def test_token_is_compared_with_compare_digest():
    src = Path(gui_server.__file__).read_text(encoding="utf-8")
    assert "secrets.compare_digest" in src
    assert "== self.app.token" not in src and "== app.token" not in src


def test_static_assets_need_the_token_too(gui):
    for name in gui_server.STATIC_FILES:
        assert gui.get("/" + name, token=None).status == 403
        ok = gui.get("/" + name)
        assert ok.status == 200
        assert ok.header("Content-Type") == gui_server.STATIC_FILES[name]


# =========================================================================== Host header

def test_evil_host_header_is_rejected(gui):
    """DNS rebinding: the rebound name still arrives with the attacker's Host."""
    for bad in ("evil.com", f"evil.com:{gui.app.port}", "driftwatch.internal",
                f"127.0.0.1:{gui.app.port + 1}", "127.0.0.1", "0.0.0.0",
                f"[::1]:{gui.app.port}"):
        resp = gui.get("/api/state", host=bad)
        assert resp.status == 403, f"Host: {bad} -> {resp.status}"
        assert resp.json()["error"] == "bad Host header"


def test_allowed_host_headers(gui):
    for good in (f"127.0.0.1:{gui.app.port}", f"localhost:{gui.app.port}"):
        assert gui.get("/api/state", host=good).status == 200


def test_host_header_is_checked_before_anything_is_read(gui):
    resp = gui.post("/api/scope/save", {"form": {}}, host="evil.com")
    assert resp.status == 403
    assert resp.json()["error"] == "bad Host header"


# =========================================================================== mutating routes

def test_get_on_action_endpoints_is_rejected(gui):
    """Actions are POST-only: GET must not reach the job runner."""
    for path in ("/api/action", "/api/scope/save", "/api/scope/preview"):
        resp = gui.get(path)
        assert resp.status in (403, 404, 405), f"GET {path} -> {resp.status}"
        assert resp.status != 200
    assert gui.app.jobs.active() is None


def test_other_methods_on_action_endpoints_are_405(gui):
    for method in ("PUT", "DELETE", "PATCH", "HEAD"):
        resp = gui.request("/api/action", method)
        assert resp.status == 405, f"{method} -> {resp.status}"


def test_no_cors_preflight_is_ever_granted(gui):
    """Refusing OPTIONS is half of why the X-DW-Token header works as a CSRF defence."""
    resp = gui.request("/api/action", "OPTIONS")
    assert resp.status == 405
    assert "Access-Control-Allow-Origin" not in resp.headers
    ok = gui.get("/api/state")
    assert "Access-Control-Allow-Origin" not in ok.headers


def test_post_without_the_token_header_is_rejected(gui):
    """A cookie alone authenticates a GET but must not authorize a mutation."""
    resp = gui.post("/api/scope/preview", {"form": {}}, token=None, cookie=_DEFAULT)
    assert resp.status == 403
    assert "X-DW-Token header" in resp.json()["error"]


def test_post_with_no_token_at_all_is_rejected(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, token=None)
    assert resp.status == 403


def test_post_with_wrong_token_header_is_rejected(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, token=secrets.token_urlsafe(32),
                    cookie=_DEFAULT)
    assert resp.status == 403


def test_post_from_a_foreign_origin_is_rejected(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, origin="https://evil.example")
    assert resp.status == 403
    assert "cross-origin" in resp.json()["error"]


def test_post_with_a_foreign_referer_is_rejected(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, origin=_OMIT,
                    referer="https://evil.example/x")
    assert resp.status == 403
    assert "referer" in resp.json()["error"]


def test_post_with_no_origin_or_referer_is_rejected(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, origin=_OMIT, referer=_OMIT)
    assert resp.status == 403
    assert "Origin/Referer" in resp.json()["error"]


def test_post_with_same_origin_referer_only_is_accepted(gui):
    resp = gui.post("/api/scope/preview", {"form": {}}, origin=_OMIT, referer=_DEFAULT)
    assert resp.status == 200                      # reaches validation...
    assert resp.json()["ok"] is False              # ...and is refused on the merits


def test_post_body_must_be_a_json_object(gui):
    assert gui.request("/api/scope/preview", "POST", origin=_DEFAULT,
                       body=b"[1,2,3]", content_type="application/json").status == 400
    assert gui.request("/api/scope/preview", "POST", origin=_DEFAULT,
                       body=b"{}", content_type="text/plain").status == 415
    assert gui.request("/api/scope/preview", "POST", origin=_DEFAULT,
                       body=b"not json", content_type="application/json").status == 400


# =========================================================================== findings API

def test_findings_api_returns_the_fixture_findings(gui):
    data = gui.run_payload()
    ids = [f["finding_id"] for f in data["findings"]]
    assert len(ids) == 6
    assert set(ids) == {f"f-{RUN}-{n}" for n in
                        ("0001", "0002", "0003", "0004", "0005", "0006")}
    assert data["engagement"] == ENGAGEMENT
    assert data["client"] == "ACME Corp"
    assert data["run_id"] == RUN
    assert data["prev_run_id"] == PREV
    assert data["totals"] == {"total": 6, "active": 5, "suppressed": 1,
                              "by_severity": {"critical": 1, "high": 2, "medium": 1,
                                              "low": 0, "info": 1}}


def test_findings_are_sorted_critical_first(gui):
    data = gui.run_payload()
    active = [f for f in data["findings"] if not f["suppressed"]]
    ranks = [dc.severity_rank(f["severity"]) for f in active]
    assert ranks == sorted(ranks), "active findings must run critical -> info"
    assert active[0]["severity"] == "critical"
    assert active[0]["finding_id"] == f"f-{RUN}-0001"
    # Suppressed findings are retained (CONTRACTS §4) but sit after every active one.
    last_active = max(i for i, f in enumerate(data["findings"]) if not f["suppressed"])
    first_supp = min(i for i, f in enumerate(data["findings"]) if f["suppressed"])
    assert first_supp > last_active


def test_finding_shape_matches_contracts_section_4(gui):
    data = gui.run_payload()
    for f in data["findings"]:
        for key in CONTRACT_FIELDS:
            assert key in f, f"{f.get('finding_id')} is missing {key}"
        assert isinstance(f["hosts"], list) and all(isinstance(h, str) for h in f["hosts"])
        assert isinstance(f["comparison"], list)
        assert isinstance(f["suppressed"], bool)
        assert isinstance(f["detail"], dict)
        assert f["severity"] in dc.SEVERITIES
        assert f["change_type"] in dc.CHANGE_TYPES
        assert re.fullmatch(r"[0-9a-f]{16}", f["fingerprint"])
    by_id = {f["finding_id"]: f for f in data["findings"]}
    crit = by_id[f"f-{RUN}-0001"]
    assert crit["rule"] == "policy.windows.new_trusted_root_ca"
    assert crit["hosts"] == ["WIN-FS01", "WIN-FS02"]
    assert crit["detail"]["identity"] == {"key": "9F3A", "kind": "root_cert"}
    assert crit["detail"]["after"]["subject"] == "CN=Corp Proxy CA 2"
    assert by_id[f"f-{RUN}-0005"]["suppressed_by"] == "allow-chrome-autoupdate"


def test_run_payload_facets_and_run_list(gui):
    data = gui.run_payload()
    assert data["hosts"] == ["WIN-FS01", "WIN-FS02", "WIN-FS03", "WIN-WS-07",
                             "db01", "sw-legacy-3", "web01"]
    assert data["categories"] == ["connections", "dns_trust", "meta", "processes",
                                  "scheduled_tasks", "services"]
    assert data["runs"] == [RUN, PREV]
    assert data["run_health"]["targeted"] == 7
    assert data["delta"]["new_count"] == 3


def test_run_payload_matches_report_context(gui, engagement_dir):
    """The GUI must show what the report shows — same build_context, not a second engine."""
    ctx = report_gen.build_context(engagement_dir, RUN)
    data = gui.run_payload()
    assert data["totals"] == ctx["totals"]
    assert data["run_health"] == ctx["run_health"]
    assert data["matrix"] == ctx["matrix"]


# =========================================================================== filtering

def test_filter_by_severity_narrows(gui):
    findings = gui.run_payload()["findings"]
    assert len(findings) == 6
    crit = [f for f in findings if _client_matches(f, severities={"critical"})]
    assert [f["finding_id"] for f in crit] == [f"f-{RUN}-0001"]
    high = [f for f in findings if _client_matches(f, severities={"high"})]
    assert {f["finding_id"] for f in high} == {f"f-{RUN}-0002", f"f-{RUN}-0003"}
    everything = [f for f in findings if _client_matches(f, severities=set(dc.SEVERITIES))]
    assert len(everything) == 6


def test_filter_by_host_narrows(gui):
    findings = gui.run_payload()["findings"]
    on_fs01 = [f["finding_id"] for f in findings if _client_matches(f, host="WIN-FS01")]
    assert on_fs01 == [f"f-{RUN}-0001", f"f-{RUN}-0002"]
    assert [f["finding_id"] for f in findings if _client_matches(f, host="db01")] == \
        [f"f-{RUN}-0003"]
    # A host with no findings of its own narrows to nothing rather than to everything.
    assert [f for f in findings if _client_matches(f, host="sw-legacy-3")] == []


def test_filter_by_search_narrows(gui):
    findings = gui.run_payload()["findings"]

    def ids(**kw):
        return [f["finding_id"] for f in findings if _client_matches(f, **kw)]

    assert ids(q="evilsvc") == [f"f-{RUN}-0002"]           # identity string
    assert ids(q="9F3A") == [f"f-{RUN}-0001"]              # case-insensitive identity
    assert ids(q="a1b2c3d4e5f60718") == [f"f-{RUN}-0001"]  # paste a fingerprint
    assert ids(q="unreachable") == [f"f-{RUN}-0003"]       # coverage-gap headline
    assert ids(q="/tmp/x") == [f"f-{RUN}-0004"]            # attacker-controlled path
    assert ids(q="win-fs03") == [f"f-{RUN}-0002"]          # host list is in the haystack
    assert ids(q="zzz-no-such-thing") == []


def test_filter_by_category_and_suppression_narrows(gui):
    findings = gui.run_payload()["findings"]
    assert [f["finding_id"] for f in findings if _client_matches(f, category="services")] == \
        [f"f-{RUN}-0002"]
    assert len([f for f in findings if _client_matches(f, suppressed="hide")]) == 5
    assert [f["finding_id"] for f in findings if _client_matches(f, suppressed="only")] == \
        [f"f-{RUN}-0005"]


def test_filters_compose(gui):
    findings = gui.run_payload()["findings"]
    combined = [f["finding_id"] for f in findings
                if _client_matches(f, severities={"critical", "high"}, host="WIN-FS01",
                                   q="dns_trust")]
    assert combined == [f"f-{RUN}-0001"]


def test_search_haystack_fields_are_all_served(gui):
    """Every field findings.js searches must exist on every finding the server sends."""
    js = (GUI_DIR / "findings.js").read_text(encoding="utf-8")
    block = re.search(r"var hay = \[(.*?)\]\.join", js, re.S)
    assert block, "could not locate the search haystack in findings.js"
    fields = sorted(set(re.findall(r"\bf\.(\w+)", block.group(1))))
    assert fields, "haystack field extraction found nothing"
    for f in gui.run_payload()["findings"]:
        missing = [k for k in fields if k not in f]
        assert not missing, f"{f['finding_id']} is missing filter fields {missing}"
    # And the fields the filter/sort read outside the haystack.
    for f in gui.run_payload()["findings"]:
        for key in ("severity", "suppressed", "hosts", "category", "host_count",
                    "first_seen"):
            assert key in f


# =========================================================================== fleet matrix

def test_matrix_endpoint_agrees_with_fleet_stats_build_matrix(gui, engagement_dir):
    data = gui.run_payload()
    findings = dc.load_ndjson(engagement_dir / "findings" / f"{RUN}.ndjson")
    active = [f for f in findings if not f.get("suppressed")]
    run_status = json.loads(
        (engagement_dir / "snapshots" / "_run" / f"{RUN}.json").read_text(encoding="utf-8"))
    expected = fleet_stats.build_matrix(active, fleet_stats.hosts_from(active, run_status))
    assert data["matrix"] == expected


def test_matrix_cells_and_ordering(gui):
    matrix = gui.run_payload()["matrix"]
    assert matrix["hosts"] == ["WIN-FS01", "WIN-FS02", "WIN-FS03", "WIN-WS-07",
                               "db01", "sw-legacy-3", "web01"]
    assert [r["finding_id"] for r in matrix["rows"]][0] == f"f-{RUN}-0001"
    assert [r["severity"] for r in matrix["rows"]] == \
        sorted((r["severity"] for r in matrix["rows"]), key=dc.severity_rank)
    row = next(r for r in matrix["rows"] if r["finding_id"] == f"f-{RUN}-0001")
    assert row["cells"]["WIN-FS01"] is True and row["cells"]["WIN-FS02"] is True
    assert row["cells"]["web01"] is False
    assert row["present_count"] == 2
    # Suppressed findings never become matrix rows.
    assert f"f-{RUN}-0005" not in {r["finding_id"] for r in matrix["rows"]}


# =========================================================================== XSS defence

def test_untrusted_finding_content_is_served_as_json_data_not_markup(gui, engagement_dir):
    seed_xss_finding(engagement_dir)
    resp = gui.get(f"/api/run?engagement={ENGAGEMENT}&run={RUN}")
    assert resp.status == 200
    assert resp.header("Content-Type") == "application/json; charset=utf-8"
    # nosniff is what stops a browser guessing "this JSON looks like HTML".
    assert resp.header("X-Content-Type-Options") == "nosniff"
    seeded = next(f for f in resp.json()["findings"] if f["finding_id"] == f"f-{RUN}-0099")
    # Preserved exactly as DATA — the analyst must still see the real command line.
    assert seeded["detail"]["identity"]["path"] == f"/tmp/{XSS_SCRIPT}"
    assert seeded["detail"]["identity"]["args_norm"] == XSS_IMG
    assert seeded["note"] == XSS_SVG


def test_no_html_response_ever_contains_the_payload_raw(gui, engagement_dir):
    seed_xss_finding(engagement_dir)
    # Warm every route that can return text/html.
    html_bodies = []
    for path in ("/", "/index.html"):
        resp = gui.get(path)
        assert resp.status == 200
        assert "text/html" in resp.header("Content-Type")
        html_bodies.append(resp.text)
    report_gen.render_report(engagement_dir, RUN, ["html"])
    frame = gui.get(f"/api/report/frame?engagement={ENGAGEMENT}&run={RUN}")
    assert frame.status == 200
    html_bodies.append(frame.text)
    # The executable forms — a tag that a parser would open — must appear nowhere.
    for body in html_bodies:
        for payload in (XSS_SCRIPT, XSS_IMG, XSS_SVG, "<script>alert", "<img src=x",
                        "<svg onload", "javascript:alert"):
            assert payload not in body, f"raw {payload!r} reached an HTML context"
    # The report DID render the finding — escaped into text, not dropped.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_bodies[-1]
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_bodies[-1]


def test_report_frame_is_sandboxed(gui, engagement_dir):
    report_gen.render_report(engagement_dir, RUN, ["html"])
    resp = gui.get(f"/api/report/frame?engagement={ENGAGEMENT}&run={RUN}")
    csp = resp.header("Content-Security-Policy")
    assert csp.startswith("sandbox")           # opaque origin, scripts cannot run
    assert "default-src 'none'" in csp
    assert "script-src" not in csp


def test_app_csp_forbids_inline_and_remote_script(gui):
    csp = gui.get("/index.html").header("Content-Security-Policy")
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "default-src 'none'" in csp
    assert gui.get("/index.html").header("X-Frame-Options") == "DENY"


def _js_code_only(text: str) -> str:
    """Drop /* ... */ and // ... so the sink scan reads code, not the prose ABOUT sinks."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"(?<![:\"'])//.*$", "", line) for line in text.splitlines())


def test_frontend_has_no_html_parsing_sinks():
    """Requirement 6 is a control, not a style rule: no data may reach an HTML parser.

    Matches the *use* of a sink (assignment / call), so the defensive BANNED_PROPS regex in
    app.js — which exists to refuse those very property names — is not mistaken for one.
    """
    sinks = re.compile(
        r"\.innerHTML\s*=|\.outerHTML\s*=|\.srcdoc\s*=|insertAdjacentHTML\s*\("
        r"|document\.write\s*\(|\beval\s*\(|new Function\s*\("
        r"|setAttribute\s*\(\s*[\"'](?:srcdoc|on\w+)")
    assert sorted(p.name for p in GUI_DIR.glob("*.js")), "no GUI scripts found"
    for asset in sorted(GUI_DIR.glob("*.js")):
        for i, line in enumerate(_js_code_only(asset.read_text(encoding="utf-8"))
                                 .splitlines(), 1):
            assert not sinks.search(line), f"{asset.name}:{i} uses an HTML-parsing sink"


def test_frontend_builds_nodes_with_text_content():
    """The positive half of the same control: nodes are created, values are textContent."""
    app_js = (GUI_DIR / "app.js").read_text(encoding="utf-8")
    assert "createElement" in app_js and "textContent" in app_js
    # app.js's el() helper refuses the dangerous property names outright.
    assert re.search(r"BANNED_PROPS\s*=\s*/.*HTML.*srcdoc.*on", app_js)


def test_static_html_has_no_inline_script_or_remote_assets():
    html = (GUI_DIR / "index.html").read_text(encoding="utf-8")
    # Every <script> is a src= reference to a same-origin file, never inline code.
    tags = re.findall(r"<script[^>]*>", html)
    assert tags, "index.html loads no scripts at all?"
    for tag in tags:
        assert "src=" in tag, f"inline script: {tag}"
        assert "//" not in tag.split("src=")[1][:12], f"remote script: {tag}"
    assert not re.search(r'(src|href)\s*=\s*["\']?(https?:)?//', html), "remote asset"
    assert not re.search(r"\son\w+\s*=", html), "inline event handler"


# =========================================================================== path traversal

@pytest.mark.parametrize("bad", [
    "../../etc", "..%2f..", "../..", "..", ".", "/etc/passwd", "C:/Windows",
    "C:\\Windows", "acme-2026-07/../../etc", "acme-2026-07%00", "engagements/../..",
    "~", "acme-2026-07\n", "\\\\server\\share",
])
def test_traversal_engagement_ids_are_rejected(gui, bad):
    quoted = urllib.parse.quote(bad, safe="")
    for path in (f"/api/engagement?engagement={quoted}",
                 f"/api/run?engagement={quoted}&run={RUN}",
                 f"/api/reports?engagement={quoted}",
                 f"/api/audit?engagement={quoted}",
                 f"/api/scope?engagement={quoted}"):
        resp = gui.get(path)
        assert 400 <= resp.status < 500, f"{path} -> {resp.status}"
        assert "TOPSECRET" not in resp.text


@pytest.mark.parametrize("bad", [
    "../../../etc/passwd", "..%2f..%2fscope", "/etc/passwd", "2026-07-22T0400Z/../x",
    "..", "2026-07-22T0400", "not-a-run-id", "2026-07-22T0400Z\n",
])
def test_traversal_run_ids_are_rejected(gui, bad):
    quoted = urllib.parse.quote(bad, safe="")
    for path in (f"/api/run?engagement={ENGAGEMENT}&run={quoted}",
                 f"/api/report?engagement={ENGAGEMENT}&run={quoted}&fmt=md",
                 f"/api/report/frame?engagement={ENGAGEMENT}&run={quoted}"):
        resp = gui.get(path)
        assert 400 <= resp.status < 500, f"{path} -> {resp.status}"
        assert "TOPSECRET" not in resp.text


def test_report_format_is_an_allowlist(gui):
    for fmt in ("../../etc/passwd", "yml", "exe", "md.j2", ""):
        resp = gui.get(f"/api/report?engagement={ENGAGEMENT}&run={RUN}&"
                       f"fmt={urllib.parse.quote(fmt, safe='')}")
        assert 400 <= resp.status < 500


def test_static_route_is_an_allowlist_not_a_filesystem(gui):
    for path in ("/../scripts/gui_server.py", "/..%2fgui_server.py", "/templates/report.md.j2",
                 "/gui_server.py", "/_vendor.py"):
        resp = gui.get(path)
        assert resp.status == 404, f"{path} -> {resp.status}"


def test_engagement_dir_helper_refuses_escapes(app):
    for bad in ("../../etc", "..", "a/b", "/abs", "C:/x", "", "acme\x00", ".hidden",
                "-leading-dash", "a" * 64, "acme-2026-07\n"):
        with pytest.raises(ValueError):
            app.engagement_dir(bad)
    good = app.engagement_dir(ENGAGEMENT)
    assert good.parent == app.engagements_dir
    with pytest.raises(ValueError):
        app.existing_engagement_dir("no-such-engagement")


def _link_dir(target: Path, link: Path) -> None:
    """Symlink where allowed; a directory junction on Windows (needs no privilege)."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError, AttributeError):
        pass
    try:
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    except Exception as exc:                       # pragma: no cover - exotic host
        pytest.skip(f"cannot create a directory link on this host: {exc}")


def test_symlinked_engagement_cannot_escape(app, tmp_path):
    """The regex alone is not enough: a link planted in engagements/ must be refused too."""
    outside = tmp_path / "outside-engagement"
    (outside / "findings").mkdir(parents=True)
    (outside / "scope.yml").write_text("engagement: sneaky\n", encoding="utf-8")
    _link_dir(outside, app.engagements_dir / "sneaky-2026-01")
    with pytest.raises(ValueError):
        app.engagement_dir("sneaky-2026-01")
    assert "sneaky-2026-01" not in [e["id"] for e in app.list_engagements()]


def test_engagement_listing_only_shows_real_children(app):
    ids = [e["id"] for e in app.list_engagements()]
    assert ids == [ENGAGEMENT, EMPTY_ENGAGEMENT] or ids == [EMPTY_ENGAGEMENT, ENGAGEMENT]
    entry = next(e for e in app.list_engagements() if e["id"] == ENGAGEMENT)
    assert entry["has_scope"] is True
    assert entry["runs"] == 2


# =========================================================================== forbidden surface

@pytest.mark.parametrize("path", [
    "/api/respond", "/api/approve", "/api/rollback", "/api/teardown", "/api/response",
    "/api/vault", "/api/credentials", "/api/cases", "/api/ship", "/api/exec", "/api/shell",
    "/response/scripts/respond.py", "/api/action/respond",
])
def test_no_route_exists_for_the_response_layer_or_teardown(gui, path):
    """design §13.6: the response layer must not grow a web UI. Absent, not hidden."""
    get_resp = gui.get(path)
    assert get_resp.status in (403, 404, 405), f"GET {path} -> {get_resp.status}"
    post_resp = gui.post(path, {})
    assert post_resp.status in (403, 404, 405), f"POST {path} -> {post_resp.status}"


@pytest.mark.parametrize("verb", [
    "respond", "propose", "approve", "rollback", "teardown", "ship", "new-engagement",
    "baseline", "status", "preflight", "", "collect; rm -rf /", "doctor --help",
])
def test_action_verb_allowlist_refuses_everything_off_it(gui, verb):
    resp = gui.post("/api/action", {"verb": verb, "engagement": ENGAGEMENT})
    assert resp.status == 403, f"verb {verb!r} -> {resp.status}"
    assert "not permitted" in resp.json()["error"]
    assert gui.app.jobs.active() is None


def test_permitted_action_set_is_exactly_the_read_or_control_node_verbs():
    assert set(gui_server.ACTIONS) == {"doctor", "diff", "report", "collect", "scope-generate"}
    for forbidden in ("respond", "approve", "rollback", "teardown", "ship"):
        assert forbidden not in gui_server.ACTIONS


def test_source_never_reads_credentials_or_the_vault():
    src = Path(gui_server.__file__).read_text(encoding="utf-8")
    # No vault path is ever opened/read/executed; the only vault reference permitted is a
    # presence probe for the health strip, plus mkdir/chmod of an EMPTY vault dir.
    assert re.search(r"vault[^\n]{0,80}\.(read_text|read_bytes|open)\b", src) is None
    for banned in ("ansible-vault", "--vault", "vault_password", "vault-password",
                   "ask-vault", "become_password", "ansible_password"):
        assert banned not in src, f"gui_server references {banned}"
    for line in src.splitlines():
        if "vault" not in line.lower() or line.lstrip().startswith("#"):
            continue
        assert not re.search(r"\bopen\(|read_text|read_bytes|subprocess", line), line
    # And no route hands vault contents out.
    assert "vault.yml" in src                        # the presence probe exists...
    assert src.count("vault.yml") == 1               # ...exactly once, nowhere else.


def test_health_exposes_vault_presence_only(gui):
    health = gui.get(f"/api/engagement?engagement={ENGAGEMENT}").json()
    assert health["vault"] == {"present": False}
    assert set(health["vault"]) == {"present"}
    assert "TOPSECRET" not in json.dumps(health)


def test_state_payload_exposes_only_the_session_token(gui):
    state = gui.get("/api/state").json()
    assert state["csrf_token"] == gui.app.token
    blob = json.dumps({k: v for k, v in state.items() if k != "csrf_token"}).lower()
    for banned in ("password", "passphrase", "vault", "private_key", "topsecret"):
        assert banned not in blob


# =========================================================================== actions + audit

class _StubRunner:
    """Stands in for JobRunner so no test ever executes bin/driftwatch or ansible."""

    def __init__(self):
        self.started: list[dict] = []
        self._jobs: dict[str, gui_server.Job] = {}

    def start(self, verb, engagement, argv, label, cwd, env, on_done):
        job = gui_server.Job(verb, engagement, argv, label)
        job.status, job.rc = "done", 0
        job.finished_at = gui_server._now_iso()
        self.started.append({"verb": verb, "engagement": engagement, "argv": argv,
                             "label": label, "cwd": cwd, "env": env})
        self._jobs[job.id] = job
        on_done(job)
        return job

    def get(self, job_id):
        return self._jobs.get(job_id)

    def active(self):
        return None


def test_permitted_action_starts_and_is_audited(gui, engagement_dir):
    gui.app.jobs = _StubRunner()
    before = len(audit_lines(engagement_dir))
    resp = gui.post("/api/action", {"verb": "doctor", "engagement": ENGAGEMENT})
    assert resp.status == 202
    summary = resp.json()
    assert summary["verb"] == "doctor" and summary["engagement"] == ENGAGEMENT

    call = gui.app.jobs.started[0]
    assert isinstance(call["argv"], list), "argv must never be a shell string"
    assert "--engagement" in call["argv"] and ENGAGEMENT in call["argv"]
    assert call["env"]["DRIFTWATCH_ENGAGEMENT"] == ENGAGEMENT
    assert call["env"]["DRIFTWATCH_OPERATOR"] == "test-operator"

    lines = audit_lines(engagement_dir)[before:]
    assert len(lines) == 2                                  # started + outcome
    for line in lines:
        assert AUDIT_LINE_RE.match(line), line
        parts = [p.strip() for p in line.split("|")]
        assert len(parts) == 5
        assert parts[1] == "doctor" and parts[3] == "test-operator"
        assert "via=gui" in parts[4]


def test_action_argv_is_never_a_shell_string(app):
    for verb in ("doctor", "diff", "report", "collect"):
        argv = app.action_argv(verb, ENGAGEMENT)
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        assert verb in argv
        assert not any(";" in a or "&&" in a or "|" in a for a in argv)
    deep = app.action_argv("collect", ENGAGEMENT, deep=True)
    assert deep[-1] == "--deep"
    scope = app.action_argv("scope-generate", ENGAGEMENT)
    assert scope[1].endswith("scope_gate.py") and scope[2] == "generate"


def test_action_on_unknown_engagement_is_400_not_500(gui):
    gui.app.jobs = _StubRunner()
    resp = gui.post("/api/action", {"verb": "doctor", "engagement": "no-such-2026-01"})
    assert resp.status == 400
    assert gui.app.jobs.started == []


def test_audit_entries_cannot_be_forged_by_the_operator_name(app, engagement_dir):
    """$DRIFTWATCH_OPERATOR is attacker-adjacent input; one action = exactly one line."""
    app.operator = "evil\n2026-01-01T00:00:00Z | teardown | - | root | ok\nmore | pipes"
    before = len(audit_lines(engagement_dir))
    app.audit(engagement_dir, "doctor", "-", "via=gui ok")
    lines = audit_lines(engagement_dir)[before:]
    assert len(lines) == 1, "an injected newline must not be able to forge a second entry"
    assert AUDIT_LINE_RE.match(lines[0])
    parts = [p.strip() for p in lines[0].split("|")]
    assert len(parts) == 5, "an injected pipe must not be able to split the fields"
    # The injected text survives as inert operator-field text; it never becomes a verb.
    assert parts[1] == "doctor" and parts[2] == "-" and parts[4] == "via=gui ok"
    assert "teardown" in parts[3] and "\n" not in parts[3]


def test_audit_safe_collapses_separators():
    assert gui_server._audit_safe("a\nb") == "a b"
    assert gui_server._audit_safe("a|b") == "a b"
    assert gui_server._audit_safe("  ") == "unknown"
    assert gui_server._audit_safe("\r\n|") == "unknown"


def test_job_polling_is_token_gated_and_404s_on_unknown_ids(gui):
    assert gui.get("/api/job?id=deadbeef").status == 404
    assert gui.get("/api/job?id=deadbeef", token=None).status == 403


# =========================================================================== scope wizard

GOOD_FORM = {
    "engagement": "wizard-2026-08",
    "client": "Wizard Corp",
    "authorized_by": "A. Operator, CISO (signed SOW 2026-08-01)",
    "in_scope": [
        {"cidr": "10.20.0.0/16", "groups": ["linux"]},
        {"host": "dc01.wizard.example", "ip": "10.20.1.5",
         "groups": ["windows", "crown_jewels"]},
    ],
    "deny": ["10.20.99.0/24"],
    "oob_subnets": ["192.168.50.0/24"],
    "settings": {"hash_policy": "tiered", "collector_account": "svc-driftwatch"},
}


def test_wizard_writes_a_contracts_conformant_scope_yml(gui, repo_root):
    import yaml
    resp = gui.post("/api/scope/save", {"form": GOOD_FORM, "mode": "new"})
    assert resp.status == 200, resp.text
    payload = resp.json()
    assert payload["ok"] is True and payload["created"] is True

    target = repo_root / "engagements" / "wizard-2026-08"
    scope_path = target / "scope.yml"
    assert scope_path.is_file()
    doc = yaml.safe_load(scope_path.read_text(encoding="utf-8"))

    # CONTRACTS §1.4 shape.
    assert set(doc) == {"engagement", "client", "authorized_by", "in_scope", "deny",
                        "oob_subnets", "settings"}
    assert doc["engagement"] == "wizard-2026-08"
    assert doc["client"] == "Wizard Corp"
    assert doc["authorized_by"].startswith("A. Operator, CISO")
    assert doc["in_scope"] == [
        {"cidr": "10.20.0.0/16", "groups": ["linux"]},
        {"host": "dc01.wizard.example", "ip": "10.20.1.5",
         "groups": ["windows", "crown_jewels"]},
    ]
    assert doc["deny"] == [{"cidr": "10.20.99.0/24"}]
    assert doc["oob_subnets"] == ["192.168.50.0/24"]
    assert set(doc["settings"]) == {"hash_policy", "collector_account",
                                    "outlier_max_prevalence", "outlier_min_group",
                                    "fast_interval", "deep_interval", "splunk_hec_url",
                                    "splunk_hec_token_var", "elastic_url"}
    assert doc["settings"]["hash_policy"] in gui_server.HASH_POLICIES
    # The token VAR name, never the secret (CONTRACTS §1.4).
    assert doc["settings"]["splunk_hec_token_var"] == "vault_splunk_hec_token"

    # The CONTRACTS §1.2 volume skeleton exists and the write is audited.
    for sub in ("inventory", "vault", "findings", "reports", "snapshots/_run"):
        assert target.joinpath(*sub.split("/")).is_dir()
    lines = audit_lines(target)
    assert lines and AUDIT_LINE_RE.match(lines[-1])
    assert "scope-write" in lines[-1]


def test_wizard_output_round_trips_through_the_real_scope_gate(gui, repo_root):
    import scope_gate
    assert gui.post("/api/scope/save", {"form": GOOD_FORM, "mode": "new"}).status == 200
    target = repo_root / "engagements" / "wizard-2026-08"
    data = scope_gate.load_scope(target)
    compiled = scope_gate.Scope(data)
    assert compiled.is_in_scope("10.20.1.5") is True
    assert compiled.is_in_scope("10.20.99.5") is False        # deny wins
    assert compiled.is_in_scope("192.168.1.1") is False       # default deny
    _, fleet_groups = scope_gate.build_inventory(compiled)
    assert fleet_groups == {"dc01.wizard.example": ["windows", "crown_jewels"]}


def test_wizard_refuses_blank_authorized_by_and_writes_nothing(gui, repo_root):
    form = dict(GOOD_FORM, authorized_by="   ")
    resp = gui.post("/api/scope/save", {"form": form, "mode": "new"})
    assert resp.status == 422
    body = resp.json()
    assert body["ok"] is False
    assert any("authorized_by" in e for e in body["errors"])
    assert not (repo_root / "engagements" / "wizard-2026-08").exists()


def test_wizard_refuses_empty_in_scope_and_writes_nothing(gui, repo_root):
    for empty in ([], None, "10.20.0.0/16", {"cidr": "10.20.0.0/16"}):
        form = dict(GOOD_FORM, in_scope=empty)
        resp = gui.post("/api/scope/save", {"form": form, "mode": "new"})
        assert resp.status == 422, f"{empty!r} -> {resp.status}"
        assert any("REFUSED" in e or "in_scope" in e for e in resp.json()["errors"])
        assert not (repo_root / "engagements" / "wizard-2026-08").exists()


def test_wizard_refusals_are_fail_closed_at_the_function_level():
    """Both refusals, asserted on the pure validator so the guarantee is not route-shaped."""
    doc, errors = gui_server.validate_scope_form(dict(GOOD_FORM, authorized_by=""))
    assert any("authorized_by" in e for e in errors)
    doc, errors = gui_server.validate_scope_form(dict(GOOD_FORM, in_scope=[]))
    assert any("REFUSED" in e for e in errors)
    doc, errors = gui_server.validate_scope_form({})
    assert errors and len(errors) >= 3
    doc, errors = gui_server.validate_scope_form(None)
    assert errors == ["malformed request body"]
    doc, errors = gui_server.validate_scope_form(GOOD_FORM)
    assert errors == []


def test_wizard_rejects_bad_cidrs_hostnames_and_settings(gui):
    bad_forms = [
        dict(GOOD_FORM, in_scope=[{"cidr": "10.20.0.0/99", "groups": ["linux"]}]),
        dict(GOOD_FORM, in_scope=[{"host": "not a host", "ip": "10.0.0.1",
                                   "groups": ["linux"]}]),
        dict(GOOD_FORM, in_scope=[{"host": "h.example", "ip": "999.1.1.1",
                                   "groups": ["linux"]}]),
        dict(GOOD_FORM, in_scope=[{"cidr": "10.20.0.0/16", "groups": []}]),
        dict(GOOD_FORM, deny=["not-a-cidr"]),
        dict(GOOD_FORM, settings={"hash_policy": "everything",
                                  "collector_account": "svc-driftwatch"}),
        dict(GOOD_FORM, settings={"hash_policy": "tiered", "collector_account": ""}),
        dict(GOOD_FORM, engagement="../../etc"),
        dict(GOOD_FORM, client=""),
    ]
    for form in bad_forms:
        resp = gui.post("/api/scope/save", {"form": form, "mode": "new"})
        assert resp.status == 422, f"accepted {form!r}"
        assert resp.json()["errors"]


def test_wizard_preview_writes_nothing(gui, repo_root):
    resp = gui.post("/api/scope/preview", {"form": GOOD_FORM})
    assert resp.status == 200
    body = resp.json()
    assert body["ok"] is True
    assert "authorized_by:" in body["yaml"] and "in_scope:" in body["yaml"]
    assert not (repo_root / "engagements" / "wizard-2026-08").exists()


def test_wizard_will_not_silently_replace_an_authorization_record(gui, engagement_dir):
    form = dict(GOOD_FORM, engagement=ENGAGEMENT)
    original = (engagement_dir / "scope.yml").read_text(encoding="utf-8")
    resp = gui.post("/api/scope/save", {"form": form, "mode": "edit"})
    assert resp.status == 409
    assert (engagement_dir / "scope.yml").read_text(encoding="utf-8") == original
    # New-mode over an existing volume is refused too.
    assert gui.post("/api/scope/save", {"form": form, "mode": "new"}).status == 409
    # Only an explicit overwrite replaces it.
    ok = gui.post("/api/scope/save", {"form": form, "mode": "edit", "overwrite": True})
    assert ok.status == 200
    assert (engagement_dir / "scope.yml").read_text(encoding="utf-8") != original


def test_wizard_edit_of_a_missing_engagement_is_404(gui):
    form = dict(GOOD_FORM, engagement="ghost-2026-01")
    assert gui.post("/api/scope/save", {"form": form, "mode": "edit"}).status == 404


# =========================================================================== empty states

def test_engagement_with_nothing_in_it_returns_a_valid_payload(gui, repo_root):
    health = gui.get(f"/api/engagement?engagement={EMPTY_ENGAGEMENT}")
    assert health.status == 200
    body = health.json()
    assert body["engagement"] == EMPTY_ENGAGEMENT
    assert body["scope"]["exists"] is False and body["scope"]["parses"] is False
    assert body["latest_run"] is None
    assert body["latest"]["available"] is False
    assert body["latest"]["by_severity"] == {s: 0 for s in dc.SEVERITIES}
    assert body["counts"] == {"snapshot_hosts": 0, "snapshot_docs": 0, "runs": 0,
                              "findings_files": 0, "reports": 0}
    assert body["runs"] == []


def test_run_payload_for_an_empty_engagement_is_empty_not_500(gui):
    resp = gui.get(f"/api/run?engagement={EMPTY_ENGAGEMENT}&run={RUN}")
    assert resp.status == 200
    data = resp.json()
    assert data["findings"] == []
    assert data["matrix"] == {"hosts": [], "rows": []}
    assert data["hosts"] == [] and data["categories"] == [] and data["runs"] == []
    assert data["totals"]["total"] == 0
    assert data["run_health"]["available"] is False


def test_reports_and_audit_empty_states(gui):
    reports = gui.get(f"/api/reports?engagement={EMPTY_ENGAGEMENT}")
    assert reports.status == 200 and reports.json() == {"reports": []}
    audit = gui.get(f"/api/audit?engagement={EMPTY_ENGAGEMENT}")
    assert audit.status == 200
    assert audit.json()["exists"] is False and audit.json()["lines"] == []
    scope = gui.get(f"/api/scope?engagement={EMPTY_ENGAGEMENT}")
    assert scope.status == 200
    assert scope.json()["exists"] is False and scope.json()["data"] == {}


def test_missing_report_is_400_not_500(gui):
    for path in (f"/api/report?engagement={ENGAGEMENT}&run={RUN}&fmt=md",
                 f"/api/report/frame?engagement={ENGAGEMENT}&run={RUN}"):
        resp = gui.get(path)
        assert resp.status == 400, f"{path} -> {resp.status}"
        assert "no md report" in resp.text or "no html report" in resp.text


def test_state_works_with_no_engagement_selected(gui):
    state = gui.get("/api/state").json()
    assert state["engagement"] is None
    assert state["severities"] == list(dc.SEVERITIES)
    assert state["hash_policies"] == list(gui_server.HASH_POLICIES)
    assert state["version"] == dc.COLLECTOR_VERSION
    assert set(state["actions"]) == set(gui_server.ACTIONS)
    assert state["cli"]["present"] is False        # scratch root has no bin/driftwatch


def test_state_works_with_an_empty_engagements_dir(tmp_path):
    root = tmp_path / "fresh-kit"
    (root / "engagements").mkdir(parents=True)
    app = gui_server.build_app(repo_root=root, port=0, token=secrets.token_urlsafe(32))
    assert app.list_engagements() == []
    assert app.run_ids(root / "engagements") == []


def test_works_without_git_metadata(repo_root):
    """The kit is often unpacked from a ZIP: nothing may depend on a .git dir."""
    assert not (repo_root / ".git").exists()
    app = gui_server.build_app(repo_root=repo_root, port=0, token=secrets.token_urlsafe(32))
    assert [e["id"] for e in app.list_engagements()]


def test_unknown_api_route_is_404(gui):
    assert gui.get("/api/nope").status == 404
    assert gui.get("/nope").status == 404
    assert gui.post("/api/nope", {}).status == 404
