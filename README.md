# driftwatch — Blue-Team Baseline & Drift Detection

[![driftwatch-ci](https://github.com/daman92/BlueTeamEngagement/actions/workflows/ci.yml/badge.svg)](https://github.com/daman92/BlueTeamEngagement/actions/workflows/ci.yml)

An agentless, read-only framework that collects point-in-time security snapshots from
every host and network device in an engagement, normalizes them into a canonical JSON
format, and compares them through four lenses to answer, per finding, **which machines
have this difference, when it first appeared, and how severe it is.**

Built for the **portable per-engagement kit** model: a single analyst, a hardened laptop,
an in-kit SIEM (Security Onion + Splunk), deployed onto networks you don't own with
credentials handed to you on arrival. See [docs/design.md](docs/design.md) for the full
design and [docs/CONTRACTS.md](docs/CONTRACTS.md) for the exact schemas and interfaces.

> Status: v0.1, built and reviewed. The engine and every component (scope gate, normalizer,
> diff engine, reporting, SIEM shipping, operator CLI, response layer, read-only lint) are
> implemented and reviewed for contract conformance; the 85-test suite and the read-only
> lint run green in CI, and dependencies are vendored for offline use. **Nothing here has
> run against a live fleet** — treat every playbook as needing a lab shakedown before an
> engagement.

## The four lenses

Every collection cycle compares snapshots four ways and merges the results into one finding
per underlying change (design §6):

1. **Temporal** — host vs. its own previous run ("what changed since yesterday").
2. **Baseline** — host vs. its promoted golden state ("how far from known-good").
3. **Fleet outlier** — host vs. its peers ("only 2 of 200 hosts run this"). Needs no history.
4. **Policy** — baseline-free absolute rules that fire on first contact (`ld.so.preload`
   present, new trusted root CA, telnet enabled, audit log cleared, extra UID-0 account…).

Because the fingerprint is host- and lens-independent, the same drift caught by several
lenses is **one** finding whose `comparison` list records every lens that saw it and whose
`rule` is upgraded to the most-specific match.

## Design guarantees

- **Agentless & read-only.** Collection uses SSH / WinRM only; roles write nothing to
  targets. `scripts/lint_readonly.py` enforces this in CI as a *security control* — with a
  single shared privileged account the collector's safety is "does not write", and the lint
  is what makes that true (design §15.3).
- **Evidence leaves the host immediately.** Snapshots assemble on the control node
  (`delegate_to: localhost`), never touch target disk, and are git-versioned + hashed.
- **Scope fails closed.** Targets are authorized via a signed `scope.yml`; the scope gate
  refuses any target not affirmatively in scope and aborts the whole run, logging the
  attempt (design §15.2).
- **A broken collection is a finding, not silence.** Unreachable hosts, partial snapshots,
  and no-transport / T3-only devices are reported as coverage gaps (design §5).

## Layout

```
install.sh              one-command control-node setup: check this host -> bootstrap -> self-test
bin/
  driftwatch            operator console (doctor / new-engagement / preflight / collect / diff /
                          report / ship / baseline / respond / status / teardown)
  bootstrap             stand up the Ansible env (.venv + collections), online or --offline
  vendor-deps           build the offline dependency bundles (see Dependencies below)
deploy/container/       OPTIONAL container image + hardened run wrapper (opt-in; see below)
playbooks/              preflight, snapshot, snapshot_network, diff_report, posture_checks
roles/snapshot_*        agentless collection (linux / windows / ad / network)
scripts/                control-node engine (Python 3.11, stdlib + PyYAML + Jinja2)
  driftwatch_common.py    category specs + finding schema as code (the contract)
  scope_gate.py           authorization rail: inventory gen + fail-closed pre-flight gate
  normalize.py            canonicalize: sort, strip volatile, tag collector-self
  diff_engine.py          four lenses -> findings NDJSON
  report_gen.py           Markdown/HTML report from findings (templates in templates/)
  fleet_stats.py          findings x hosts matrix
  siem_ship.py            Splunk (findings) + Security Onion (findings + snapshots)
  baseline.py             promote a snapshot to golden
  lint_readonly.py        the read-only security lint
  gui_server.py + gui/    local-only operator GUI (127.0.0.1, stdlib, no external assets)
  _vendor.py              sys.path shim: engine deps resolve from vendor/python/
rules/                  policy_checks.yml, severity_map.yml, normalize_patterns.yml
allowlists/             expiring, reviewed suppressions
engagements/            per-engagement encrypted volumes (only _template is tracked)
response/               SEPARATE privilege domain: Tier-1 reversible plays, human-gated
systemd/                fast / deep / network collection timers
tests/                  pytest — engine + scripts (no network, no ansible execution)
docs/                   design.md (the why) + CONTRACTS.md (the interop contract)
vendor/python/          committed pure-Python engine deps (PyYAML/Jinja2/MarkupSafe)
```

Client data — snapshots, findings, credentials, evidence — lives **only** under
`engagements/<id>/` and is gitignored. Nothing crosses between engagements.

## Quick start (control node / kit, Linux)

```bash
./install.sh                                    # check this host, set it up, self-test it
. .venv/bin/activate                            # driftwatch needs ansible* ON PATH
./bin/driftwatch doctor                         # kit self-check; every non-PASS names its fix
./bin/driftwatch gui                            # or drive the whole thing from a browser
./bin/driftwatch new-engagement --interactive   # ...or stay in the terminal: guided scope.yml

# variants: --check (report only, changes nothing; exit 0 ready / 1 not) · --offline (install
#   only from vendor/wheels + vendor/collections) · --yes (unattended) · --mode container
```

`install.sh` names what this host is missing in that host's *own* package-manager
vocabulary, restores the executable bits, hands the venv/pip/collections work to
`bin/bootstrap`, adds the Windows transport stack, and self-tests the result (read-only
lint + unit suite). It is idempotent — re-run it freely.

**From a GitHub ZIP, run `bash install.sh`.** "Download ZIP" drops the Unix executable bit,
so `./install.sh` and `./bin/driftwatch` fail with *Permission denied*; through `bash` it
runs anyway and restores the bit on itself, on all of `bin/`, and on the container wrapper.
Everything in `bin/` is **bash**, not Python — `python3 bin/driftwatch …` fails while
parsing shell syntax.

Or, step by step — `install.sh` composes tools that still stand alone:

```bash
bin/bootstrap                                # online: .venv + pip + ansible-galaxy
bin/bootstrap --offline                      # air-gapped: vendor/wheels + vendor/collections
bin/driftwatch new-engagement acme-2026-07   # template scope.yml instead of the wizard
$EDITOR engagements/acme-2026-07/scope.yml   # authorized_by + in_scope ARE the authorization
```

The Python **engine** needs no venv at all — PyYAML/Jinja2 are vendored under
`vendor/python/`, so `python3 scripts/diff_engine.py …` runs on a bare Python 3.11+ with no
pip and no internet.

### Running an engagement

```bash
export DRIFTWATCH_ENGAGEMENT=acme-2026-07                       # or --engagement <id> per verb
ansible-vault create engagements/acme-2026-07/vault/vault.yml   # handed-over credentials

bin/driftwatch preflight    # Kerberos DNS/clock/TGT + the Windows transport matrix
bin/driftwatch collect      # scope gate -> snapshot -> diff -> report (--deep, --collect-only)
bin/driftwatch status       # read-only engagement dashboard
bin/driftwatch ship         # optional: Splunk / Security Onion, per scope.yml settings
bin/driftwatch teardown     # shred the volume; report kept by default, vault ALWAYS
```

`collect` runs `diff` then `report` for you; the standalone verbs re-run those stages on the
control node against an existing `--run-id`. `doctor` is the only verb that needs no
engagement selected — given one, it adds the scope / inventory / vault checks.

### The GUI

```bash
bin/driftwatch gui          # opens http://127.0.0.1:8787 with a one-time token
```

Dashboard, findings browser (filter by severity/host/category, search, before/after diffs),
the fleet matrix, report viewer, audit log, and a **setup wizard** that authors `scope.yml`
with live CIDR/IP validation — a browser alternative to the terminal for everything except
the dangerous verbs.

It is deliberately constrained, because this listens on a machine holding admin credentials
for the client's whole fleet (design §9; §13.6 forbids a web UI for the response layer):

- **Loopback only.** Hard-coded `127.0.0.1` — there is no `--host` flag to get wrong.
- **Token on every request**, moved into an `HttpOnly; SameSite=Strict` cookie on first load;
  `Host`-header allowlisting blocks DNS rebinding; mutations need the token in a header plus
  a same-origin check, so no other page you have open can drive it.
- **No write path.** `respond`/approve, `teardown`, `ship`, and anything touching the vault
  have no route at all. The only actions are `doctor`, `diff`, `report`, `scope-generate`,
  and `collect` — which is flagged as fleet-reaching and confirmed before it runs.
- **Treats findings as hostile input.** Process command lines and cert subjects come from
  possibly-compromised hosts, so the DOM is built with `textContent`/`createElement` only,
  under a strict CSP, with HTML reports sandboxed in an iframe.
- Stdlib + vendored PyYAML, zero external assets — it works air-gapped.

Every GUI-triggered action lands in the engagement's `audit.log` marked `via=gui`.

### Optional: containerized tooling

`deploy/container/` builds an image of the **tooling**, for operators who want the
control-node dependency set byte-identical between the build host and the kit. It is
strictly opt-in: the supported default is the native install above, which needs no
container runtime at all.

```bash
./install.sh --mode container --check   # is a container runtime present? (podman preferred)
./install.sh --mode container           # build driftwatch:0.1.0 and driftwatch:latest

# then run any verb through the wrapper (--dry-run prints the command and runs nothing)
DRIFTWATCH_ENGAGEMENT=acme-2026-07 ./deploy/container/driftwatch-container status
```

The image holds code and dependencies and **nothing else**: engagement volumes, the vault,
snapshots and reports live in bind mounts, never in a layer — a layer cannot be shredded at
teardown (design §15.4), so the teardown guarantee is only true if client data was never
baked in. It publishes **no ports** and carries no `EXPOSE` line; driftwatch has no web UI,
and Appendix C.1 already declined to put a listener holding fleet credentials on the kit.

Mounts, the Kerberos and `known_hosts` caveats, what `--network host` means for scope
layer 3, and air-gapped `save`/`load` transfer:
[deploy/container/README.md](deploy/container/README.md).

## Dependencies & the offline kit

The kit deploys onto client networks that are frequently air-gapped, so dependencies
travel *with* it — nothing is fetched from the internet in the field.

| Dependency | How it's bundled |
|---|---|
| Engine deps — PyYAML, Jinja2, MarkupSafe | **Vendored into git** at `vendor/python/` (pure-Python, ~1.7 MB). `scripts/_vendor.py` puts them on `sys.path`, so the engine runs on a bare interpreter. Pinned in `requirements.txt`. |
| Ansible core + Galaxy collections | Collections pinned in `requirements.yml`; ansible-core version-constrained by `bin/vendor-deps`. Not in git (100s of MB); `bin/vendor-deps bundle` downloads them into `vendor/wheels/` + `vendor/collections/` for the **kit image** to bake, and `bin/bootstrap --offline` installs from there with no network. |
| OS packages — krb5, chrony | Baked into the kit image (design §3.1); see [systemd/README.md](systemd/README.md). |

Rebuild the vendored Python deps after bumping a pin: `bin/vendor-deps python`.
CI installs *only* `pytest` and runs the suite against the vendored `yaml`/`jinja2` — a
green run proves the offline bundle is complete on a clean interpreter.

## Development

```bash
pip install -r requirements-dev.txt                 # pytest + pinned engine deps (dev only)
python -m pytest tests/ -q                           # unit tests
python scripts/lint_readonly.py check --roles-dir roles   # security lint (must pass)
```

The interop contract is [docs/CONTRACTS.md](docs/CONTRACTS.md). Any change to a category,
field name, or finding shape happens there and in `scripts/driftwatch_common.py` first —
every other component keys off those names.

## Scope & non-goals

driftwatch **complements** EDR, a SIEM, and network monitoring — it does not replace them.
Out of scope by design: real-time detection between snapshots, deep memory forensics,
packet capture (Security Onion's Zeek/Suricata travel alongside for that), full-filesystem
FIM, and *autonomous* remediation. The response layer (design §13) exists but is
human-gated, evidence-first, and architecturally separate from collection.
