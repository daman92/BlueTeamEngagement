# Engagement volume template

Everything for one client engagement lives in a single, self-contained,
encrypted volume under `engagements/<engagement_id>/`. **Nothing crosses between
engagements** — that is both client confidentiality and blast-radius control
(design §15.1). This directory is the template that seeds a new volume; real
volumes are git-ignored (see the repo `.gitignore`).

- `engagement_id` format: `<client>-<yyyy>-<mm>` (e.g. `acme-2026-07`).
- The active engagement is selected per command by `--engagement <id>` or the
  `DRIFTWATCH_ENGAGEMENT` env var. The CLI errors if neither is set — it never
  guesses (CONTRACTS §1.2).

## What's tracked here

| Path | Purpose |
|---|---|
| `scope.yml` | The authorization rail. Fully commented; ships fail-closed (authorizes nothing). Fill it in first. |
| `README.md` | This file. |

Everything else in the layout below is **generated or collected at runtime** and
never committed.

## Volume layout (created as the engagement runs — CONTRACTS §1.2)

```
engagements/<engagement_id>/
├── scope.yml                     # authorization boundary + settings (you fill this in)
├── inventory/hosts.yml           # GENERATED from scope.yml by scope_gate.py
├── inventory/fleet_groups.json   # GENERATED: {host: [group, ...]} for the Python side
├── vault/vault.yml               # ansible-vault encrypted creds; NEVER committed
├── preflight/transport_matrix.json
├── snapshots/<host>/<run_id>.json
├── configs/<host>/<run_id>.conf  # sanitized network config text
├── baselines/<host>.json         # promoted golden snapshots
├── findings/<run_id>.ndjson      # one finding per line
├── findings/state.json           # first_seen / fingerprint tracking across runs
├── cases/c-NNNN.json
├── evidence/<case_id>/
├── reports/<run_id>.{md,html}
└── audit.log                     # append-only; every run, every scope denial
```

## Standing up an engagement

Use `bin/driftwatch new-engagement <id>` (which scaffolds the volume layout and
writes a scope.yml equivalent to the annotated template here), or copy this
template by hand. Then:

1. **Fill `scope.yml`.** Set `engagement`, `client`, `authorized_by`, and the
   `in_scope` allow-list from the signed authorization document. Add `deny`
   carve-outs and `oob_subnets` as needed. Until `in_scope` has entries, every
   command fails closed — by design.

2. **Inject credentials.** Load the handed-over accounts into
   `vault/vault.yml`, encrypted with a per-engagement Ansible-Vault password
   held only by you (design §15.3). Reference secrets by vault-variable *name*
   only — never place plaintext in `scope.yml` or the inventory. Expect a single
   privileged account; note in the report that collection ran under it.

3. **Generate the inventory (scope layer 1).**
   `scripts/scope_gate.py generate --engagement-dir engagements/<id>` builds
   `inventory/hosts.yml` and `fleet_groups.json` purely from `in_scope`. Only
   explicit `host`/`ip` entries become addressable hosts; a bare `cidr` declares
   an authorized range but no machines (discovery != access, §15.2).

4. **Pre-flight.** `bin/driftwatch preflight` verifies the Windows transport
   ladder (Kerberos/WinRM-HTTPS → OpenSSH → NTLM), DNS-at-DC, and clock sync,
   and writes `preflight/transport_matrix.json`. Hosts with no viable transport
   become documented coverage gaps, not silent skips (design §3.1).

5. **Collect → diff → report.**
   `bin/driftwatch collect [--deep] [--limit PATTERN]` runs the read-only
   snapshot roles (every target re-validated against scope, layer 2), then
   `diff` normalizes + compares + emits findings, and `report` renders
   `reports/<run_id>.{md,html}`. Optionally `ship` to Splunk / Security Onion.

6. **Baselines & allowlists.** Promote a reviewed golden snapshot with
   `baseline promote <host> <run_id>`; suppress confirmed known-good findings
   with expiring entries under the repo-level `allowlists/`.

7. **Teardown.** At close-out, `bin/driftwatch teardown [--retain ...]` exports
   what the retention profile keeps, then shreds the rest. The vault and its key
   are **always** shredded, regardless of profile (design §15.4). Rebuild the
   kit from image before the next engagement.

## Non-negotiables

- Collection is read-only. The snapshot roles contain no write-capable modules
  by construction (enforced by `scripts/lint_readonly.py`).
- Scope fails closed and is checked in depth (§15.2). Every out-of-scope attempt
  is written to `audit.log`.
- Credentials live only in this volume and are destroyed at teardown.
