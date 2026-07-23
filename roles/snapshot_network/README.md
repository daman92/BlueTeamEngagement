# role: `snapshot_network`

Read-only, three-tier network-device snapshot collector for **driftwatch**.
Implements design §4.3 (T1/T2/T3 tiering) + the §4.4 virtual-device note, and
produces the `docs/CONTRACTS.md` §3.4 `network` snapshot document — one canonical
JSON file per device per run.

## Read-only guarantee

The role writes **nothing** to a target. With a single shared privileged account
(the portable-engagement norm, design §15.3) the guarantee "cannot write" becomes
"does not write", enforced by `scripts/lint_readonly.py` — a security control, not
style. This role is built to pass it:

- collection uses only `ansible.netcommon.cli_command`, vendor `*_command`, and
  `*_facts` modules — **never** an `ios_config`/`*_config` module;
- every command task carries `tags: [readonly]`, the author's assertion that the
  command only reads;
- the **only** writes are the assembled snapshot JSON and the sanitized config
  text, both `delegate_to: localhost` (the control node).

```bash
python scripts/lint_readonly.py check --roles-dir roles   # must exit 0
```

## Tiering (detect, then degrade)

Decided in `tasks/main.yml`:

| Tier | Selected when | Handler | Output |
|---|---|---|---|
| **T1** | `ansible_network_os` maps to a native handler (IOS/IOS-XE shipped) | `tasks/t1_ios.yml` | full §3.4 category set |
| **T2** | banner fingerprint (or `ansible_network_os`) matches a command pack | `tasks/t2_commandpack.yml` | config text + whatever categories the pack defines |
| **T3** | unknown device that answers SSH | `tasks/t3_generic.yml` | `device_config` only (universal config-text backstop) |

The chosen tier is recorded in `meta.collection_tier` (`T1`|`T2`|`T3`) so the
report can explain *why* a device has thin coverage. Additional T1 handlers
(`t1_nxos.yml`, `t1_eos.yml`, `t1_junos.yml`, …) follow the exact shape of the
IOS example; only IOS ships as the worked example in v1. New T2 vendors are added
as **data** — see `command_packs/README.md`.

## Config sanitization → `device_config`

For every tier, the retrieved running config is (design §6):

1. **volatile-stripped** — `Building/Current configuration`, `Last configuration
   change`, NVRAM/uptime headers, etc. (`dw_net_volatile_patterns`);
2. **secret-redacted** — each secret token (`enable secret`, `username … secret`,
   `snmp-server community`, `key 7`, TACACS/RADIUS keys, …) is replaced by
   `salted-sha256(dw_redaction_salt + secret)`. Because the salt is stable within
   an engagement, a *changed* secret still changes its hash (drift stays
   detectable) while the plaintext secret is **never stored**.

The sanitized text is written to
`{{ dw_engagement_dir }}/configs/{{ inventory_hostname }}/{{ dw_run_id }}.conf`
and summarized as the `device_config` object:
`{ sha256, line_count, config_path, tier }` (`config_path` is relative to the
engagement dir, per §3.4).

## Output document

Path (assembled on the control node):

```
{{ dw_snapshot_dir }}/{{ inventory_hostname }}/{{ dw_run_id }}.json
```

Top-level keys are exactly `meta` + the §3.4 `network` category keys that the
selected tier produced. `meta` carries `schema_version`, `host`, `platform:
network`, `os`, `collected_at`, `collector_version`, `engagement`, `run_id`,
`partial`, `failed_categories`, `collection_tier`, and `hash_policy`.

## Failure handling

A failed category never fails the play: source commands run with `ignore_errors`,
each tier handler records the affected category in `meta.failed_categories`, and
`meta.partial` is set true when that list is non-empty. Coverage-gap findings
(`host_unreachable`, `partial_snapshot`, `category_failed`, `t3_only`) are emitted
downstream by `diff_engine.py` from the run status the CLI records — not by this
role.

## Variables

Provided by `group_vars` / `-e` from `bin/driftwatch` (CONTRACTS.md §1.5);
`defaults/main.yml` supplies safe fallbacks and the sanitization/tiering knobs.

| Variable | Meaning |
|---|---|
| `dw_engagement`, `dw_engagement_dir` | engagement id and volume path |
| `dw_run_id` | one collection cycle, fleet-wide |
| `dw_snapshot_dir` | `{{ dw_engagement_dir }}/snapshots` |
| `dw_deep` (bool) | include expensive categories (ACL rule base, routing neighbors) |
| `dw_hash_policy` | recorded in `meta.hash_policy` |
| `dw_redaction_salt` | stable per-engagement salt for secret redaction (from vault) |
| `dw_net_volatile_patterns`, `dw_net_secret_rules` | sanitization rules (data) |
| `dw_net_t1_ios_os`, `dw_net_fingerprint_command`, `dw_net_t3_ladder` | tier detection knobs |

## §4.4 — virtual network devices

vEOS / vSRX / CSR / virtual FortiGate run the same OS as their physical
counterparts, so T1/T2/T3 collection here works unchanged — the config snapshot is
identical. Their *security boundary* is not: snapshots/clones, promiscuous-mode
port groups, added vNICs, and the hypervisor management plane (§4.4 checks V1–V6)
live at the **hypervisor**, which is a separate scope and credential question
(Appendix D) handled by running the §4.1 Linux collection against in-scope ESXi/
Proxmox/KVM hosts — not by this role. Where hypervisor access is out of scope,
those checks are reported as coverage gaps rather than collected here.

## Files

```
roles/snapshot_network/
├── tasks/main.yml            # tier detection -> dispatch -> sanitize/hash/assemble/write
├── tasks/t1_ios.yml          # Cisco IOS/IOS-XE worked T1 example (full §3.4 set)
├── tasks/t2_commandpack.yml  # generic, data-driven command-pack handler
├── tasks/t3_generic.yml      # universal ladder, config-text backstop
├── command_packs/            # vendor packs as DATA (README + example_aruba.yml)
├── templates/snapshot.json.j2
├── defaults/main.yml
└── meta/main.yml
```
