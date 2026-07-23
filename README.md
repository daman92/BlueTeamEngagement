# driftwatch — Blue-Team Baseline & Drift Detection

An agentless, read-only framework that collects point-in-time security snapshots from
every host and network device in an engagement, normalizes them into a canonical JSON
format, and compares them through four lenses to answer, per finding, **which machines
have this difference, when it first appeared, and how severe it is.**

Built for the **portable per-engagement kit** model: a single analyst, a hardened laptop,
an in-kit SIEM (Security Onion + Splunk), deployed onto networks you don't own with
credentials handed to you on arrival. See [docs/design.md](docs/design.md) for the full
design and [docs/CONTRACTS.md](docs/CONTRACTS.md) for the exact schemas and interfaces.

> Status: v0.1 scaffold. The control-node engine (scope gate, normalizer, diff engine,
> read-only lint) is implemented and unit-tested; Ansible roles, reporting, SIEM shipping,
> the operator CLI, and the response layer are generated against the contract. Nothing
> here has run against a live fleet — treat every playbook as needing a lab shakedown
> before an engagement.

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
bin/driftwatch          operator console (collect / diff / report / ship / respond / teardown)
playbooks/              preflight, snapshot, snapshot_network, diff_report, posture_checks
roles/snapshot_*        agentless collection (linux / windows / ad / network)
scripts/                control-node engine (Python 3.11, stdlib + PyYAML + Jinja2)
  driftwatch_common.py    category specs + finding schema as code (the contract)
  scope_gate.py           authorization rail: inventory gen + fail-closed pre-flight gate
  normalize.py            canonicalize: sort, strip volatile, tag collector-self
  diff_engine.py          four lenses -> findings NDJSON
  report_gen.py           Markdown/HTML report from findings
  fleet_stats.py          findings x hosts matrix
  siem_ship.py            Splunk (findings) + Security Onion (findings + snapshots)
  baseline.py             promote a snapshot to golden
  lint_readonly.py        the read-only security lint
rules/                  policy_checks.yml, severity_map.yml, normalize_patterns.yml
allowlists/             expiring, reviewed suppressions
engagements/            per-engagement encrypted volumes (only _template is tracked)
response/               SEPARATE privilege domain: Tier-1 reversible plays, human-gated
systemd/                fast / deep / network collection timers
tests/                  pytest — engine + scripts (no network, no ansible execution)
```

Client data — snapshots, findings, credentials, evidence — lives **only** under
`engagements/<id>/` and is gitignored. Nothing crosses between engagements.

## Quick start (control node / kit, Linux)

```bash
python -m venv .venv && . .venv/bin/activate
pip install pyyaml jinja2 pytest ansible-core
ansible-galaxy collection install -r requirements.yml

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
bin/driftwatch ship --splunk      # optional: findings to Splunk, everything to Security Onion

# 4. Close out
bin/driftwatch teardown           # default: shred everything except the report; vault always shredded
```

## Development

```bash
python -m pytest tests/ -q                          # unit tests
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
