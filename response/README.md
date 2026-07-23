# driftwatch — response layer

This directory is the **write side** of driftwatch: a small set of reviewed, human-gated
containment plays. It is a **separate privilege domain** from collection. In production it
is a separate repository with its own credentials; here the boundary is enforced by
code/entry-point separation (design §15.3). Read design §13, §14 and CONTRACTS §7 before
changing anything under `response/`.

## Why response is separated from collection

Everything in the collection half of driftwatch is read-only by construction, and the
whole security argument for the kit rests on that: a compromised control node can *leak*
snapshots but cannot *damage* the fleet. Response breaks that guarantee on purpose — it
hands a system that holds admin credentials the ability to disable accounts, quarantine
hosts, and block binaries. That is the single most dangerous capability in the tool, for
three reasons (design §13.1):

1. **A false positive becomes a self-inflicted outage.** Acting on a bad detection can
   take down production faster than any attacker.
2. **Your automation becomes the attacker's weapon.** If the response layer were reachable
   from the collector and an adversary landed on the control node, you would have built
   them a fleet-wide destruction button.
3. **Acting destroys evidence.** Killing a process or deleting persistence wipes the
   artifacts you need to understand scope — often before you know how far it spread.

So response is **not tasks bolted onto the collection roles.** It is a separate system:

- **It never imports collection code.** `respond.py` and `case.py` do not import
  `driftwatch_common`, `diff_engine`, `normalize`, or `scope_gate`, and collection code
  never imports these. The two domains meet at exactly one place: the **case file**
  (`cases/c-NNNN.json`), exchanged as plain JSON on disk, never as a live import.
- **The case is the unit of unification** (design §14). Detection writes `finding`;
  response reads it and writes `proposed_action` → `approval` → `result` back onto the
  same record, so the report tells one story: *detected → contained → outcome*.
- **The single privileged account is why this matters.** In the portable model you usually
  get one privileged credential, not a read-only/privileged split. The collector's safety
  therefore degrades from *cannot write* to *does not write*, and the load-bearing control
  moves into the code: the collector has no write capability, and this layer cannot reach a
  snapshot to act on because it cannot import the collector (design §15.3). Keep it that
  way — the separation is the control.

## The flow (every play, no exceptions)

Driven by `respond.py` (CONTRACTS §7): `propose` → `approve` → `rollback`.

```
PRESERVE  capture the finding + suspect artifacts + a deep-snapshot request ref into
          evidence/<case_id>/, SHA-256 every file. No preservation, no action (§13.2).
PROPOSE   build proposed_action{tier,play,hosts}; run the play with --check; show the
          dry-run plan. No target contact that changes anything.
APPROVE   the analyst confirms the EXACT action against the EXACT host list and supplies
          a free-text authorizer (who authorized it out-of-band). The gate is about
          mistakes, not authority (§13.2) — the analyst holds authority in the tool.
ACT       run the play for real. Tier-1, reversible, before-state captured.
LOG       append proposed / approved / executed / rolled-back to the engagement's
          append-only audit.log AND write result{status,before,after,rolled_back} onto
          the case.
```

**Blast-radius controls** (design §13.2): a play may only touch hosts the finding names.
`respond.py` refuses (exit 2) any host not in the finding, and refuses a request wider than
the finding's host set — a play can never touch more hosts than the detection covered.
Plays run `serial: 1` behind a canary with `any_errors_fatal`, so a mistake halts instead
of fanning out.

## The four v1 plays — Tier-1 reversible only

| Play | Action (reversible) | Rollback |
|---|---|---|
| `disable_account` | Disable (not delete) the account | Re-enable it |
| `isolate_host` | Deny-all-except-mgmt **host-firewall** quarantine | Remove the rules |
| `block_hash` | EDR / AppLocker deny of a SHA-256 | Unblock the hash |
| `revoke_session` | Kill the session / purge tickets | No-op (user re-authenticates) |

Every play preserves before it acts, honours `--check`, refuses to mutate without an
approved case (`dw_authorized`), and carries a `dw_rollback` reverse branch. Since Ansible
does not execute in this repo, the playbooks are the reviewed, valid definitions; on the
Linux kit `respond.py` runs `ansible-playbook` against them, and off the kit it emits a
clearly-labelled synthesized dry-run plan so the orchestration, evidence, audit, and case
write-back stay exercisable.

## Deliberate limits — the guardrail against reimplementing a SOAR

The line to hold (design §13.6, Decisions Log #7): **response stays a small set of audited,
human-confirmed plays.** With a single analyst who holds full authority, a SOAR would add a
platform to carry, configure, and tear down per engagement in exchange for
approval/case/queue features one operator does not need. So:

- **No autonomous action, ever.** No play runs without the human confirm gate. Autonomous
  remediation is a permanent non-goal (design §12).
- **No network-config-writing play in v1** (design §13.5). `isolate_host` contains at the
  *host* firewall, not by rewriting a switch/VLAN or device ACL. Config remediation on
  network gear can black-hole your own management plane and needs in-band-path warnings and
  mandatory rollback timers this version does not ship. That play is deliberately deferred.
- **No scheduler, no multi-user queue, no web UI.** Case management is the `cases/`
  directory plus Splunk search (§13.6) — not a product. **If the response side starts
  growing scheduling, multi-user queues, or its own UI, stop and reassess rather than
  building them.** That drift is the signal you are reinventing a SOAR badly.
- **Tiers above 1 are out of scope for v1.** Hard containment, eradication, and recovery
  (kill process, remove persistence, re-image, restore device config) stay manual and
  evidence-first (design §13.3). Prefer re-imaging over surgical eradication once a host is
  genuinely compromised.

## Files

```
response/
├── README.md                     this file
├── scripts/
│   ├── respond.py                CLI: propose / approve / rollback (CONTRACTS §7)
│   └── case.py                   Case dataclass + new_case / load / save (design §14)
├── playbooks/
│   ├── disable_account.yml       Tier-1 reversible
│   ├── isolate_host.yml          Tier-1 reversible (host-firewall quarantine)
│   ├── block_hash.yml            Tier-1 reversible (EDR / AppLocker)
│   └── revoke_session.yml        Tier-1 reversible
└── cases/                        case files live in the engagement volume
                                  (engagements/<id>/cases/c-NNNN.json); this dir holds
                                  the response repo's placeholder only
```

## Usage

```bash
# 1) Detection has already written finding(s) and a case (engagements/<id>/cases/c-0031.json).

# 2) PRESERVE + PROPOSE (dry run) — refuses hosts the finding does not name:
respond propose  --engagement-dir engagements/acme-2026-07 \
                 --case c-0031 --play isolate_host --hosts WIN-FS01 \
                 --artifact /path/to/suspect.exe

# 3) APPROVE (interactive confirm) — records approver + free-text authorizer, then acts:
respond approve  --engagement-dir engagements/acme-2026-07 --case c-0031
#   ... or non-interactively for a scripted run, still recording the authorizer:
respond approve  --engagement-dir engagements/acme-2026-07 --case c-0031 \
                 --confirm --authorized-by "J. Doe, IR lead (verbal, 2026-07-23)"

# 4) ROLLBACK (reverse using the captured before-state):
respond rollback --engagement-dir engagements/acme-2026-07 --case c-0031
```

`--engagement-dir` (or `DRIFTWATCH_ENGAGEMENT`) selects the engagement volume; that is
where `cases/`, `evidence/<case_id>/`, and the append-only `audit.log` live. Exit codes:
`0` ok · `1` error · `2` refusal/violation.
