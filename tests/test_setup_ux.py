"""Setup UX contracts: `driftwatch doctor`, the `new-engagement --interactive` scope
wizard, and install.sh.

These three are what an operator touches BEFORE the kit has collected anything, so they
are tested the way the operator meets them: as processes, over a pipe, against a throwaway
COPY of the repository. Design Appendix D.3 wants the fresh-kit checklist to be a scripted
verb that "fails loudly with specific remediation text, not diagnosed by hand", so what is
asserted here is the operator-visible contract — exit codes, the --json shape (CONTRACTS
§8), a fix line on every non-PASS check, the §1.4 scope.yml the wizard authors, and the
fail-closed refusals — not internal shell helpers.

Hermetic per CONTRACTS §9: no network, no ansible execution, no container build. Every
subprocess runs inside a tmp copy of the repo; the real checkout is never written to.
Individual tests skip (rather than fail) when the runner lacks bash or a bash-visible
python3, since bin/ is Linux-kit bash and CI may not be.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")

# Copied into every kit: the .git history, the dev venv and the caches are noise, and
# vendor/wheels + vendor/collections are the offline BUNDLE — gitignored, built on a
# connected host by bin/vendor-deps, and deliberately absent from a just-cloned kit
# (README "Dependencies & the offline kit"). Leaving them out is what a fresh clone looks
# like, and install.sh --offline is expected to say so loudly rather than half-install.
_SKIP_ANYWHERE = {".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__"}
_SKIP_PATHS = {("vendor", "wheels"), ("vendor", "collections")}

# Client data — snapshots, findings, credentials, evidence — lives ONLY under
# engagements/<id>/ (gitignored). It is not copied anywhere, least of all into a world-
# readable temp directory, so the kits below get the tracked _template and nothing else.
# It also keeps the tests hermetic: `acme-2026-07` is the documented example id, so a
# developer's own checkout could otherwise collide with the volumes these tests create.
_ENGAGEMENTS_KEEP = {"_template"}

# bin/ is invoked as `bash bin/driftwatch ...` so the exec bit is not load-bearing for the
# tests themselves — but doctor's exec_bits check reads it, and a checkout made from a
# GitHub ZIP has it stripped (README). Restore it in the copy so the checks under test see
# a correctly-deployed kit.
_EXEC_FILES = ("bin/driftwatch", "bin/bootstrap", "bin/vendor-deps", "install.sh",
               "deploy/container/driftwatch-container")


def _bash_has_python3() -> bool:
    if BASH is None:
        return False
    try:
        return subprocess.run([BASH, "-c", "command -v python3"],
                              capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


HAS_PYTHON3 = _bash_has_python3()

requires_bash = pytest.mark.skipif(
    BASH is None, reason="no bash on this runner; bin/ and install.sh are bash (CONTRACTS §1.1)")
requires_python3 = pytest.mark.skipif(
    not HAS_PYTHON3, reason="no bash-visible python3; the wizard validates addresses with it")


# --------------------------------------------------------------------------- kit copies
def _copy_ignore(src, names):
    rel = Path(src).resolve().relative_to(REPO_ROOT)
    drop = {n for n in names if n in _SKIP_ANYWHERE}
    for parts in _SKIP_PATHS:
        if rel.parts == parts[:-1] and parts[-1] in names:
            drop.add(parts[-1])
    if rel.parts == ("engagements",):
        drop |= {n for n in names if n not in _ENGAGEMENTS_KEEP}
    return drop


def _make_kit(dest: Path) -> Path:
    shutil.copytree(REPO_ROOT, dest, ignore=_copy_ignore, symlinks=True)
    copied = {p.name for p in (dest / "engagements").iterdir()}
    assert copied <= _ENGAGEMENTS_KEEP, \
        f"client engagement data leaked into the test kit: {sorted(copied - _ENGAGEMENTS_KEEP)}"
    for rel in _EXEC_FILES:
        path = dest / rel
        if path.exists():
            path.chmod(path.stat().st_mode | 0o111)
    return dest


@pytest.fixture(scope="session")
def kit_source(tmp_path_factory) -> Path:
    """One pristine copy per session; every other kit is copied from this one."""
    return _make_kit(tmp_path_factory.mktemp("kit-source") / "driftwatch")


@pytest.fixture(scope="session")
def make_kit(kit_source, tmp_path_factory):
    def _clone(label: str) -> Path:
        dest = tmp_path_factory.mktemp(f"kit-{label}", numbered=True) / "driftwatch"
        shutil.copytree(kit_source, dest, symlinks=True)
        return dest
    return _clone


@pytest.fixture
def kit(make_kit) -> Path:
    """A throwaway kit for one test that is allowed to write to it."""
    return make_kit("fn")


# --------------------------------------------------------------------------- process runner
def _kit_env(**extra) -> dict:
    env = os.environ.copy()
    # The console errors rather than guessing which client it is pointed at (CONTRACTS
    # §1.2), so the developer's own exported engagement must not leak into these runs.
    for var in ("DRIFTWATCH_ENGAGEMENT", "DRIFTWATCH_ENGAGEMENT_DIR", "ANSIBLE_CONFIG",
                "PYTHONPATH"):
        env.pop(var, None)
    env["DRIFTWATCH_OPERATOR"] = "pytest"   # audit.log lines must be deterministic
    env.update(extra)
    return env


def _run(kit_dir: Path, argv, stdin: str = "", timeout: int = 300, **env_extra):
    """Run a bash entry point inside the kit copy with stdin as a closed pipe.

    stdin is ALWAYS a pipe (empty by default): the wizard's fail-closed behaviour on a
    truncated stdin is part of the contract, and inheriting pytest's stdin would test
    something else entirely.
    """
    return subprocess.run(
        [BASH, *argv], cwd=str(kit_dir), input=stdin, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
        env=_kit_env(**env_extra), timeout=timeout,
    )


def _answers(*lines: str) -> str:
    """Wizard answers as a piped answer file — one line each, blank line = take default."""
    return "".join(line + "\n" for line in lines)


def _doctor(kit_dir: Path, *args, engagement: str | None = None):
    env = {"DRIFTWATCH_ENGAGEMENT": engagement} if engagement else {}
    return _run(kit_dir, ["bin/driftwatch", "doctor", *args], **env)


def _load_doctor_json(proc) -> dict:
    # CONTRACTS §8: "--json writes one JSON object to stdout and nothing else". One line,
    # parseable on its own — a kit whose python3 is broken still has to be diagnosable.
    assert proc.stdout.endswith("\n"), "doctor --json must terminate its object with a newline"
    assert proc.stdout.count("\n") == 1, f"doctor --json wrote more than one line:\n{proc.stdout}"
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------- shared kits
@pytest.fixture(scope="module")
def ready_kit(make_kit) -> Path:
    """A kit with nothing FAILing, so `doctor` can be tested on its exit-0 path.

    ansible is the one kit dependency a test runner cannot be assumed to have; doctor
    already downgrades "not on PATH but present in .venv" to a WARN, so an executable stub
    at that exact path reproduces a bootstrapped kit without installing (or running)
    ansible. Nothing in these tests executes it.
    """
    kit_dir = make_kit("ready")
    venv_bin = kit_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True, exist_ok=True)
    stub = venv_bin / "ansible-playbook"
    stub.write_text("#!/bin/sh\necho 'ansible-playbook [core 2.16.0]'\n", encoding="utf-8")
    stub.chmod(0o755)
    return kit_dir


@pytest.fixture(scope="module")
def broken_kit(make_kit) -> Path:
    """A kit holding two engagements that doctor must condemn: an untouched template
    volume (placeholder authorized_by, empty in_scope) and one with unparseable YAML."""
    kit_dir = make_kit("broken")
    for eng in ("broken-2026-07", "malformed-2026-08"):
        proc = _run(kit_dir, ["bin/driftwatch", "new-engagement", eng])
        assert proc.returncode == 0, proc.stderr
    # Quoting/indentation damage of the kind an operator makes editing scope.yml on site.
    (kit_dir / "engagements/malformed-2026-08/scope.yml").write_text(
        'engagement: "malformed-2026-08\nclient: [ACME\n  authorized_by: nope\n',
        encoding="utf-8")
    return kit_dir


@pytest.fixture(scope="module")
def doctor_ready(ready_kit):
    return ready_kit, _doctor(ready_kit, "--json")


@pytest.fixture(scope="module")
def doctor_broken(broken_kit):
    return _doctor(broken_kit, "--json", engagement="broken-2026-07")


@pytest.fixture(scope="module")
def doctor_malformed(broken_kit):
    return _doctor(broken_kit, "--json", engagement="malformed-2026-08")


# =========================================================================== doctor --json
@requires_bash
def test_doctor_json_shape(doctor_ready):
    """CONTRACTS §8: {"checks":[{id,label,status,detail,remediation}...],
    "summary":{pass,warn,fail}} — and the summary is the tally of the checks."""
    _, proc = doctor_ready
    data = _load_doctor_json(proc)

    assert set(data) == {"checks", "summary"}
    assert isinstance(data["checks"], list) and data["checks"], "doctor ran no checks"
    assert set(data["summary"]) == {"pass", "warn", "fail"}

    seen = set()
    for check in data["checks"]:
        assert set(check) == {"id", "label", "status", "detail", "remediation"}
        assert all(isinstance(v, str) for v in check.values())
        assert check["id"] and check["id"] not in seen, f"duplicate/empty check id: {check!r}"
        seen.add(check["id"])
        assert check["status"] in {"pass", "warn", "fail"}
        assert check["label"], f"check {check['id']} has no label"

    for status in ("pass", "warn", "fail"):
        counted = sum(1 for c in data["checks"] if c["status"] == status)
        assert data["summary"][status] == counted, f"summary.{status} disagrees with checks[]"
    assert sum(data["summary"].values()) == len(data["checks"])


@requires_bash
def test_doctor_json_is_the_only_thing_on_stdout(doctor_ready):
    """Parseability is the point: human output goes to stderr, and in --json mode there
    is none at all, so `doctor --json | jq` works on a half-broken kit."""
    _, proc = doctor_ready
    assert proc.stderr == "", f"doctor --json wrote to stderr:\n{proc.stderr}"
    assert "\x1b[" not in proc.stdout, "colour escapes must never reach a non-tty"


@requires_bash
def test_doctor_json_exits_zero_when_nothing_fails(doctor_ready):
    """Exit 0 when there is no FAIL (warnings are advisory), 1 when any check FAILs."""
    _, proc = doctor_ready
    data = _load_doctor_json(proc)
    failing = [c["id"] for c in data["checks"] if c["status"] == "fail"]
    assert failing == [], f"unexpected FAIL on the prepared kit: {failing}"
    assert data["summary"]["fail"] == 0
    assert data["summary"]["warn"] > 0, "a kit with no krb5/ansible should still warn"
    assert proc.returncode == 0


@requires_bash
def test_doctor_json_covers_the_kit_and_kerberos_checks(doctor_ready):
    """doctor "always runs the kit/tooling and Windows-transport checks" (CONTRACTS §8);
    the Kerberos prereqs are design §3.1's rung 1 and cause most transport incidents."""
    _, proc = doctor_ready
    ids = {c["id"] for c in _load_doctor_json(proc)["checks"]}
    assert {"bash", "platform", "python", "engine_deps", "ansible", "collections",
            "exec_bits"} <= ids
    assert {"krb5_tools", "krb5_conf", "tgt", "clock"} <= ids


@requires_bash
def test_doctor_with_no_engagement_does_not_crash(doctor_ready):
    """doctor is the ONE verb that runs with no engagement selected — the fresh-kit check
    (CONTRACTS §8). It must report the absence, not resolve/refuse like every other verb."""
    _, proc = doctor_ready
    data = _load_doctor_json(proc)
    checks = {c["id"]: c for c in data["checks"]}

    assert checks["engagement"]["status"] == "warn"
    assert "none" in checks["engagement"]["detail"]
    assert "DRIFTWATCH_ENGAGEMENT" in checks["engagement"]["remediation"]
    # No engagement means no engagement checks — not empty/bogus ones.
    assert not ({"scope", "scope_auth", "scope_in", "inventory", "vault", "artifacts"} & set(checks))
    assert "no engagement selected" not in proc.stdout   # the other verbs' die() message
    assert proc.returncode == 0


@requires_bash
def test_doctor_human_mode_with_no_engagement_is_clean(ready_kit):
    """Same situation through the human renderer: the kit sections still print and the
    verb exits 0."""
    proc = _doctor(ready_kit)
    assert proc.stdout == "", "human mode belongs on stderr; stdout stays free for --json"
    assert "kit / tooling" in proc.stderr
    assert "windows transport prereqs" in proc.stderr
    assert "engagement checks skipped" in proc.stderr
    assert "kit ready" in proc.stderr
    assert "Traceback" not in proc.stderr and "unbound variable" not in proc.stderr
    assert proc.returncode == 0


# ================================================================= doctor: broken engagement
@requires_bash
@requires_python3
def test_doctor_condemns_an_unfilled_scope(doctor_broken):
    """An untouched template volume is NOT ready: authorized_by is still the placeholder
    and in_scope is empty, which under fail-closed scope authorizes nothing (§15.2)."""
    proc = doctor_broken
    data = _load_doctor_json(proc)
    checks = {c["id"]: c for c in data["checks"]}

    assert {"engagement", "scope", "scope_auth", "scope_in", "inventory", "vault",
            "artifacts"} <= set(checks)
    assert checks["scope"]["status"] == "pass"          # the YAML itself is fine
    assert checks["scope_auth"]["status"] == "fail"
    assert "CHANGE ME" in checks["scope_auth"]["detail"]
    assert checks["scope_in"]["status"] == "fail"
    assert "EMPTY" in checks["scope_in"]["detail"]
    assert "scope_gate.py generate" in checks["scope_in"]["remediation"]

    assert data["summary"]["fail"] >= 2
    assert proc.returncode == 1, "any FAIL means exit 1"


@requires_bash
@requires_python3
def test_doctor_json_survives_a_malformed_scope(doctor_malformed):
    """A YAML parser message is arbitrary text with quotes and newlines in it. --json is
    emitted by bash precisely so it still works when python3/PyYAML is what is broken, so
    the object has to stay parseable with that message inside it."""
    proc = doctor_malformed
    data = _load_doctor_json(proc)       # would raise if the escaping leaked
    checks = {c["id"]: c for c in data["checks"]}

    assert checks["scope"]["status"] == "fail"
    assert "does not parse" in checks["scope"]["detail"]
    assert "scope.yml" in checks["scope"]["remediation"]
    assert "\n" not in checks["scope"]["detail"] and "\r" not in checks["scope"]["detail"]
    assert proc.returncode == 1


@requires_bash
@requires_python3
def test_every_non_pass_check_carries_its_fix(doctor_ready, doctor_broken, doctor_malformed):
    """Design Appendix D.3, the whole reason this verb exists: "fails loudly with specific
    remediation text, not diagnosed by hand". "Kerberos is broken" is not a diagnosis."""
    _, ready = doctor_ready
    for proc in (ready, doctor_broken, doctor_malformed):
        for check in _load_doctor_json(proc)["checks"]:
            if check["status"] == "pass":
                continue
            assert check["remediation"].strip(), \
                f"non-PASS check {check['id']!r} ships no remediation text"


@requires_bash
@requires_python3
def test_doctor_human_mode_prints_the_remediation(broken_kit):
    """The operator-facing rendering of the same failure: FAIL lines, each followed by the
    exact command that fixes it, and a non-zero exit."""
    proc = _doctor(broken_kit, engagement="broken-2026-07")

    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "\x1b[" not in proc.stderr, "no colour escapes when stderr is a pipe"
    assert "FAIL" in proc.stderr
    assert "scope authorized_by" in proc.stderr
    assert "scope in_scope" in proc.stderr
    assert "fix: set authorized_by in engagements/broken-2026-07/scope.yml" in proc.stderr
    assert ("fix: add cidr/host entries to engagements/broken-2026-07/scope.yml, then: "
            "python3 scripts/scope_gate.py generate --engagement-dir "
            "engagements/broken-2026-07") in proc.stderr
    assert "not ready" in proc.stderr

    # Every FAIL/WARN row in the table is immediately followed by its fix line.
    rows = proc.stderr.splitlines()
    for i, line in enumerate(rows):
        match = re.match(r"^ {4}(PASS|WARN|FAIL)\s{2}", line)
        if not match or match.group(1) == "PASS":
            continue
        assert i + 1 < len(rows) and "fix: " in rows[i + 1], \
            f"non-PASS row without a fix line: {line!r}"


@requires_bash
@requires_python3
def test_doctor_records_itself_in_the_engagement_audit_log(broken_kit, doctor_broken):
    """CONTRACTS §8: every verb appends one line to audit.log — the operator's record.
    (doctor_broken is the run under inspection, hence the fixture dependency.)"""
    log = (broken_kit / "engagements/broken-2026-07/audit.log").read_text(encoding="utf-8")
    entries = [ln for ln in log.splitlines() if " | doctor | " in ln]
    assert entries, f"doctor left no audit trail:\n{log}"
    for entry in entries:
        assert re.match(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \| doctor \| - \| pytest \| "
            r"pass=\d+ warn=\d+ fail=\d+$", entry), entry


# ============================================================ new-engagement --interactive
FULL_WIZARD_ANSWERS = _answers(
    "acme-2026-07",                          # engagement id
    "ACME Corp",                             # client legal name
    "J. Doe, CISO (signed SOW 2026-07-01)",  # authorized_by (REQUIRED)
    "cidr",                                  # in_scope entry 1: kind
    "10.10.0.0/16",                          #   CIDR
    "linux",                                 #   ansible groups
    "y",                                     # add another in_scope entry
    "host",                                  # in_scope entry 2: kind
    "dc01.acme.example",                     #   hostname / FQDN
    "10.10.1.5",                             #   ip
    "windows, win_servers, crown_jewels",    #   ansible groups
    "n",                                     # no more in_scope entries
    "y",                                     # add deny CIDRs
    "10.10.99.0/24",                         #   deny CIDR
    "n",                                     # no more deny CIDRs
    "y",                                     # add oob_subnets
    "192.168.99.0/24",                       #   oob subnet
    "n",                                     # no more oob subnets
    "tiered",                                # hash_policy
    "svc-driftwatch",                        # collector_account
    "y",                                     # write the volume
    "y",                                     # generate the inventory now
)

CIDR_ONLY_ANSWERS = _answers(
    "",                                      # engagement id: take the one passed as argv
    "CIDR Only Ltd",
    "K. Roe, CISO (signed SOW 2026-08-01)",
    "cidr", "10.20.0.0/16", "linux", "n",
    "n",                                     # no deny
    "n",                                     # no oob_subnets
    "full",                                  # hash_policy
    "svc-collector",                         # collector_account
    "y", "y",
)


@pytest.fixture(scope="module")
def wizard_kit(make_kit):
    kit_dir = make_kit("wizard")
    proc = _run(kit_dir, ["bin/driftwatch", "new-engagement", "--interactive"],
                stdin=FULL_WIZARD_ANSWERS)
    assert proc.returncode == 0, f"wizard failed:\n{proc.stderr}"
    return kit_dir, proc


@requires_bash
@requires_python3
def test_wizard_writes_a_contract_conformant_scope(wizard_kit):
    """CONTRACTS §1.4 — key for key, with real values (nothing says CHANGE ME) so the
    engagement is runnable as written."""
    kit_dir, _ = wizard_kit
    text = (kit_dir / "engagements/acme-2026-07/scope.yml").read_text(encoding="utf-8")
    scope = yaml.safe_load(text)

    assert set(scope) == {"engagement", "client", "authorized_by", "in_scope", "deny",
                          "oob_subnets", "settings"}
    assert scope["engagement"] == "acme-2026-07" and isinstance(scope["engagement"], str)
    assert scope["client"] == "ACME Corp"
    assert scope["authorized_by"] == "J. Doe, CISO (signed SOW 2026-07-01)"
    assert scope["in_scope"] == [
        {"cidr": "10.10.0.0/16", "groups": ["linux"]},
        {"host": "dc01.acme.example", "ip": "10.10.1.5",
         "groups": ["windows", "win_servers", "crown_jewels"]},
    ]
    assert scope["deny"] == [{"cidr": "10.10.99.0/24"}]
    assert scope["oob_subnets"] == ["192.168.99.0/24"]

    assert set(scope["settings"]) == {
        "hash_policy", "collector_account", "outlier_max_prevalence", "outlier_min_group",
        "fast_interval", "deep_interval", "splunk_hec_url", "splunk_hec_token_var",
        "elastic_url"}
    assert scope["settings"]["hash_policy"] == "tiered"
    assert scope["settings"]["collector_account"] == "svc-driftwatch"
    assert scope["settings"]["outlier_max_prevalence"] == 0.05
    assert scope["settings"]["outlier_min_group"] == 20
    # The secret's NAME, never the secret (CONTRACTS §1.4).
    assert scope["settings"]["splunk_hec_token_var"] == "vault_splunk_hec_token"
    assert scope["settings"]["splunk_hec_url"] == ""
    assert scope["settings"]["elastic_url"] == ""

    assert "CHANGE ME" not in text, "the guided path must leave no placeholder behind"


@requires_bash
@requires_python3
def test_wizard_creates_the_engagement_volume_layout(wizard_kit):
    """CONTRACTS §1.2 — the same tree the non-interactive path produces."""
    kit_dir, proc = wizard_kit
    eng = kit_dir / "engagements/acme-2026-07"
    for rel in ("inventory", "vault", "preflight", "snapshots/_run", "configs", "baselines",
                "findings", "cases", "evidence", "reports", "audit/hostlogs"):
        assert (eng / rel).is_dir(), f"missing {rel} from the engagement volume"
    assert (eng / "scope.yml").is_file()
    assert (eng / "audit.log").is_file()

    audit = (eng / "audit.log").read_text(encoding="utf-8").splitlines()
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \| new-engagement \| - \| pytest \| "
                    r"created interactive in_scope=2 deny=1 oob=1 authorized_by=set$",
                    audit[0]), audit
    assert "Ctrl-C aborts" in proc.stderr        # the "nothing is written yet" promise
    assert "--- summary ---" in proc.stderr      # confirmed before anything is written


@requires_bash
@requires_python3
def test_wizard_scope_is_accepted_by_scope_gate(wizard_kit, tmp_path):
    """The point of validating answers with the same `ipaddress` module scope_gate uses:
    `scope_gate.py generate` must accept the result and build the inventory from it
    (CONTRACTS §1.4/§6). Run against a copy so the shared kit stays untouched."""
    kit_dir, _ = wizard_kit
    eng = tmp_path / "acme-2026-07"
    shutil.copytree(kit_dir / "engagements/acme-2026-07", eng)
    shutil.rmtree(eng / "inventory")              # prove generate rebuilds it from scope

    proc = subprocess.run(
        [sys.executable, "scripts/scope_gate.py", "generate", "--engagement-dir", str(eng)],
        cwd=str(kit_dir), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "1 explicit host(s) across 3 group(s)" in proc.stdout

    inventory = yaml.safe_load((eng / "inventory/hosts.yml").read_text(encoding="utf-8"))
    groups = inventory["all"]["children"]
    assert set(groups) == {"windows", "win_servers", "crown_jewels"}
    for group in groups.values():
        assert group["hosts"]["dc01.acme.example"] == {"ansible_host": "10.10.1.5"}

    fleet_groups = json.loads((eng / "inventory/fleet_groups.json").read_text(encoding="utf-8"))
    assert fleet_groups == {"dc01.acme.example": ["windows", "win_servers", "crown_jewels"]}


@requires_bash
@requires_python3
def test_wizard_generates_the_inventory_itself(wizard_kit):
    """The wizard's last step runs the generator, so the operator lands on a ready volume."""
    kit_dir, proc = wizard_kit
    eng = kit_dir / "engagements/acme-2026-07"
    assert "generated inventory: 1 explicit host(s)" in proc.stdout
    assert json.loads((eng / "inventory/fleet_groups.json").read_text(encoding="utf-8")) == {
        "dc01.acme.example": ["windows", "win_servers", "crown_jewels"]}
    audit = (eng / "audit.log").read_text(encoding="utf-8")
    assert "| scope | generate | hosts=1 | outcome=ok" in audit


@requires_bash
@requires_python3
def test_wizard_cidr_only_scope_authorizes_a_range_but_no_machines(kit):
    """discovery != access (design §15.2): a bare CIDR declares an authorized range and
    makes NOTHING addressable — the wizard says so and the inventory comes out empty.
    Also covers the unused deny/oob rendering as explicit empty lists."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "--interactive", "cidronly-2026-07"],
                stdin=CIDR_ONLY_ANSWERS)
    assert proc.returncode == 0, proc.stderr

    eng = kit / "engagements/cidronly-2026-07"
    scope = yaml.safe_load((eng / "scope.yml").read_text(encoding="utf-8"))
    assert scope["engagement"] == "cidronly-2026-07"      # the id came from argv's default
    assert scope["in_scope"] == [{"cidr": "10.20.0.0/16", "groups": ["linux"]}]
    assert scope["deny"] == [] and scope["oob_subnets"] == []
    assert scope["settings"]["hash_policy"] == "full"
    assert scope["settings"]["collector_account"] == "svc-collector"

    assert "no host entries" in proc.stderr
    assert "discovery != access" in proc.stderr
    assert "generated inventory: 0 explicit host(s)" in proc.stdout
    assert json.loads((eng / "inventory/fleet_groups.json").read_text(encoding="utf-8")) == {}


# ------------------------------------------------------------------ wizard: fail closed
def _assert_nothing_written(kit_dir: Path, engagement_id: str, proc):
    assert proc.returncode != 0, "a refused wizard must exit non-zero"
    assert not (kit_dir / "engagements" / engagement_id).exists(), \
        "a refused wizard left an engagement volume behind"
    assert "nothing" in proc.stderr.lower()


@requires_bash
@requires_python3
def test_wizard_refuses_a_blank_authorized_by(kit):
    """design §15.2 derives scope from a signed authorization; a scope.yml that cannot
    name its authorization is not one. Blank answers re-prompt, and running out of input
    aborts with nothing written — never a silent default."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "-i"],
                stdin=_answers("noauth-2026-09", "No Auth Ltd", "", "", ""))
    assert "authorized_by is REQUIRED" in proc.stderr
    assert "stdin closed" in proc.stderr
    _assert_nothing_written(kit, "noauth-2026-09", proc)


@requires_bash
@requires_python3
def test_wizard_refuses_an_empty_in_scope(kit):
    """in_scope is the ONLY source of inventory and an empty one authorizes nothing, so
    the wizard cannot be walked past it: invalid entries re-prompt and EOF aborts."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "-i"],
                stdin=_answers("noscope-2026-09", "No Scope Ltd",
                               "J. Doe, CISO (signed SOW 2026-09-01)",
                               "cidr", "not-a-cidr", "10.10.0.0/33"))
    assert "is not a valid network" in proc.stderr
    _assert_nothing_written(kit, "noscope-2026-09", proc)


@requires_bash
@requires_python3
def test_wizard_writes_nothing_until_the_summary_is_confirmed(kit):
    """Everything is collected and confirmed BEFORE anything is written, so declining the
    summary leaves no half-built volume and no permissive scope.yml behind."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "-i"],
                stdin=_answers("declined-2026-09", "Declined Ltd",
                               "J. Doe, CISO (signed SOW 2026-09-01)",
                               "cidr", "10.30.0.0/16", "linux", "n", "n", "n",
                               "tiered", "svc-driftwatch",
                               "n"))            # decline at the summary
    assert "aborted at the summary" in proc.stderr
    _assert_nothing_written(kit, "declined-2026-09", proc)


@requires_bash
@requires_python3
def test_wizard_refuses_an_id_that_would_break_scope_yml(kit):
    """The id is both a directory name and a YAML scalar; anything outside [A-Za-z0-9._-]
    produces a scope.yml scope_gate would refuse — which is what the wizard exists to
    prevent, so it re-prompts rather than warning and continuing."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "-i"],
                stdin=_answers("../escape", "a: b # x", "*"))
    assert "characters outside" in proc.stderr
    assert not (kit / "engagements").exists() or not list((kit / "engagements").glob("*escape*"))
    assert proc.returncode != 0


# ==================================================== new-engagement (non-interactive)
@requires_bash
def test_new_engagement_non_interactive_still_works(kit):
    """Regression guard: the flagless verb is unchanged — template scope.yml, §1.2 layout,
    audit line — and it is still the fail-closed starting point (empty in_scope)."""
    proc = _run(kit, ["bin/driftwatch", "new-engagement", "acme-2026-07"])
    assert proc.returncode == 0, proc.stderr

    eng = kit / "engagements/acme-2026-07"
    for rel in ("inventory", "vault", "preflight", "snapshots/_run", "configs", "baselines",
                "findings", "cases", "evidence", "reports", "audit/hostlogs"):
        assert (eng / rel).is_dir(), f"missing {rel} from the engagement volume"

    text = (eng / "scope.yml").read_text(encoding="utf-8")
    scope = yaml.safe_load(text)
    assert scope["engagement"] == "acme-2026-07"
    assert scope["authorized_by"].startswith("CHANGE ME")
    assert not scope["in_scope"], "the template must authorize nothing until it is filled in"
    assert scope["deny"] is None and scope["oob_subnets"] == []
    assert set(scope["settings"]) == {
        "hash_policy", "collector_account", "outlier_max_prevalence", "outlier_min_group",
        "fast_interval", "deep_interval", "splunk_hec_url", "splunk_hec_token_var",
        "elastic_url"}

    audit = (eng / "audit.log").read_text(encoding="utf-8")
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \| new-engagement \| - \| pytest \| "
                    r"created$", audit.splitlines()[0]), audit
    assert "scope.yml" in proc.stderr and "ansible-vault create" in proc.stderr


@requires_bash
def test_new_engagement_never_overwrites_an_existing_volume(kit):
    """Client data lives in the volume; re-running the verb must not touch it."""
    first = _run(kit, ["bin/driftwatch", "new-engagement", "acme-2026-07"])
    assert first.returncode == 0, first.stderr
    marker = kit / "engagements/acme-2026-07/findings/evidence.ndjson"
    marker.write_text("do not lose me\n", encoding="utf-8")

    second = _run(kit, ["bin/driftwatch", "new-engagement", "acme-2026-07"])
    assert second.returncode == 1
    assert "already exists" in second.stderr
    assert marker.read_text(encoding="utf-8") == "do not lose me\n"


# =========================================================================== install.sh
def _snapshot_tree(root: Path) -> dict:
    """rel path -> sha256 (files) / marker (dirs). Catches any create, modify or delete."""
    snap = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_dir():
            snap[rel + "/"] = "dir"
        elif path.is_file():
            snap[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            snap[rel] = "special"
    return snap


def _tree_delta(before: dict, after: dict) -> list:
    return [key for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]


@requires_bash
def test_install_help_documents_the_modes(kit):
    proc = _run(kit, ["install.sh", "--help"])
    assert proc.returncode == 0
    text = proc.stdout + proc.stderr
    for flag in ("--mode native|container", "--offline", "--check", "--yes", "--help"):
        assert flag in text, f"install.sh --help does not document {flag}"
    assert "bin/vendor-deps bundle" in text, "the offline bundle's build command belongs in --help"


@requires_bash
def test_install_check_is_read_only(kit):
    """--check "changes nothing on disk" — it is what an operator runs on a client's host
    before deciding to install anything, so it has to be safe to run there."""
    before = _snapshot_tree(kit)
    proc = _run(kit, ["install.sh", "--check"])
    after = _snapshot_tree(kit)

    assert _tree_delta(before, after) == [], "install.sh --check wrote to the kit"
    assert proc.stdout == "", "install.sh keeps stdout clean; its report is on stderr"
    assert "Nothing above was executed" in proc.stderr
    assert "bin/bootstrap" in proc.stderr, "--check must name the step it would delegate to"
    assert proc.returncode in (0, 1), f"unexpected exit {proc.returncode}:\n{proc.stderr}"
    # The verdict line and the exit code are one statement, not two.
    if proc.returncode == 0:
        assert "PREREQUISITES MET" in proc.stderr
    else:
        assert "NOT INSTALLABLE" in proc.stderr
        assert "        $ " in proc.stderr, "a blocker without a remediation command"


@requires_bash
def test_install_check_offline_refuses_a_missing_bundle(kit):
    """Offline/air-gapped is a first-class path: vendor/wheels + vendor/collections are
    built on a connected host by bin/vendor-deps and carried in. Without them --offline
    must fail loudly, with the command that builds them — and still change nothing."""
    before = _snapshot_tree(kit)
    proc = _run(kit, ["install.sh", "--offline", "--check"])
    after = _snapshot_tree(kit)

    assert _tree_delta(before, after) == [], "install.sh --offline --check wrote to the kit"
    assert proc.returncode == 1
    assert "NOT INSTALLABLE" in proc.stderr
    assert "vendor/wheels" in proc.stderr and "vendor/collections" in proc.stderr
    assert "bin/vendor-deps bundle" in proc.stderr
    assert "bin/bootstrap --offline" in proc.stderr, "the offline plan must name the offline step"
