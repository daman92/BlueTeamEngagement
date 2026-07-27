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
bin/
  driftwatch            operator console (new-engagement / preflight / collect / diff /
                          report / ship / baseline / respond / status / teardown)
  bootstrap             stand up the Ansible env (.venv + collections), online or --offline
  vendor-deps           build the offline dependency bundles (see Dependencies below)
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

**Get the code onto the kit with `git clone`.** GitHub's "Download ZIP" does not preserve
the Unix executable bit, so `./bin/driftwatch` fails with *Permission denied* from a ZIP.
If you must use a ZIP (air-gapped transfer), restore the bit first:

```bash
chmod +x bin/driftwatch bin/bootstrap bin/vendor-deps
```

Everything in `bin/` is **bash**, not Python — run `./bin/driftwatch …` (or
`bash bin/driftwatch …`). Invoking it with `python3` fails while parsing shell syntax.

```bash
# Set up Ansible + collections. Online, or --offline from the baked-in bundle (see below).
bin/bootstrap                 # online: .venv + pip + ansible-galaxy
# bin/bootstrap --offline     # air-gapped: install only from vendor/wheels + vendor/collections

# The Python ENGINE needs no venv at all — PyYAML/Jinja2 are vendored under vendor/python/,
# so `python scripts/diff_engine.py ...` runs on a bare Python 3.11+ with no pip/internet.

# 1. Stand up an engagement from the template, then edit scope.yml
bin/driftwatch new-engagement acme-2026-07
$EDITOR engagements/acme-2026-07/scope.yml     # in_scope subnets/hosts, oob_subnets, settings

export DRIFTWATCH_ENGAGEMENT=acme-2026-07

# 2. Verify Windows transport prerequisites (Kerberos DNS/clock/TGT, WinRM/OpenSSH probe)
bin/driftwatch preflight

# 3. Collect -> diff -> report
bin/driftwatch collect            # fast set; add --deep for hashing/packages/cert stores
bin/driftwatch diff               # normalize + four-lens diff -> findings NDJSON
bin/driftwatch report             # Markdown + HTML into reports/
bin/driftwatch ship               # optional: to Splunk / Security Onion, per scope.yml settings

# 4. Close out
bin/driftwatch teardown           # default: shred everything except the report; vault always shredded
```

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
