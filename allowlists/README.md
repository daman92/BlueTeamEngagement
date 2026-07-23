# Allowlists — expiring, reviewed suppressions

Allowlists silence *known-good* findings so the report shows only what needs a
human's attention. They are the running inventory of "yes, we looked at this and
it is expected here." driftwatch treats them as security-relevant config:
**reviewed like code, always time-boxed, never permanent.**

See `CONTRACTS.md` §5.3 for the authoritative format and `docs/design.md` §6 and
§8 for the intent and lifecycle. `example.yml` is a worked reference entry.

## How suppression works

- Every `*.yml` in this directory is loaded and its `entries:` list is merged
  (`scripts/diff_engine.py:load_allowlists`).
- A finding is suppressed when an **active** entry's `scope` covers one of the
  finding's hosts **and** its `match` block matches. First matching entry wins;
  the finding is stamped `suppressed: true`, `suppressed_by: <entry id>`.
- **Suppressed findings are never dropped.** They remain in
  `findings/<run_id>.ndjson` and render in the report's suppression appendix, so
  a suppression is always auditable and reversible.
- Collector-self items are handled separately (capped at `info` by the diff
  engine, not suppressed here) — do not write allowlist entries for them.

## Entry fields (all required unless noted)

| Field | Meaning |
|---|---|
| `id` | Stable, unique identifier; appears in the report as `suppressed_by`. |
| `reason` | Why this is known-good. Write it for the next analyst, not yourself. |
| `approver` | Who reviewed and accepted it. |
| `ticket` | Change/exception ticket reference. |
| `expires` | `YYYY-MM-DD`. **Required.** After this date the entry is ignored and a warning is emitted — there are no silent permanent exceptions (design §6). |
| `scope` | `{hosts: [...], groups: [...]}`. Empty hosts **and** empty groups = fleet-wide. Group membership comes from `inventory/fleet_groups.json`. |
| `match` | Same DSL as policy rules (`all`/`any` of `{field, op, value}`), evaluated against `detail.identity` + `detail.after` + the synthetic `category` and `platform` fields. |

## Match DSL quick reference

Ops: `eq` `ne` `regex` (search) `in` `not_in` `gt` `lt` `exists` `absent`
`contains`. `field` is a dot-path. Regexes are Python `re`; in YAML, single-quote
them so backslashes stay literal (`'^\\GoogleUpdateTask'` matches a task path
beginning `\GoogleUpdateTask`).

Scope your `match` as tightly as the finding allows — always pin `platform` and
`category`, then one or two identity fields. A loose `match` can hide a real
finding that happens to share a field value.

## Lifecycle

1. Triage a run; confirm a finding is expected/known-good.
2. Add an entry to a reviewed `*.yml` (a PR/commit review, like a code change),
   with a real `expires`, `approver`, and `ticket`.
3. The finding shows as suppressed from the next run on.
4. Entries expire on their own. The report's "expiring soon / expired" section
   (design §8) surfaces them for re-review — re-confirm and re-date, or let it
   lapse and the finding returns to the active set. Do not blanket-extend.

## What does NOT belong here

- Permanent exceptions — use a short `expires` and renew deliberately.
- Suppressing an entire category or platform — that blinds you; fix the noise at
  its source (a `normalize_patterns.yml` rule, a baseline re-promotion, or a
  tighter policy rule) instead.
- Anything you cannot explain in `reason`.
