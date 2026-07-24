# driftwatch — Interop Contracts (v1.0)

This file is the **single source of truth** for names, paths, schemas, and interfaces
shared across roles, playbooks, scripts, rules, and the CLI. [design.md](design.md) is the
source of truth for *intent*; if the two conflict on a mechanical detail, **this file wins**.

`scripts/driftwatch_common.py` encodes §3 (category specs) and §4 (finding schema) as code.
Python components MUST import from it rather than re-declaring specs.

---

## 1. Layout, naming, shared variables

### 1.1 Repository layout (fixed)

```
bin/driftwatch                  # operator console (bash, runs on the Linux kit)
bin/{bootstrap,vendor-deps}     # env setup (.venv/collections; --offline) + offline dep bundler
playbooks/{preflight,snapshot,snapshot_network,diff_report,posture_checks}.yml
roles/{snapshot_linux,snapshot_windows,snapshot_ad,snapshot_network}/
scripts/                        # control-node Python (3.11+), no deps beyond PyYAML+Jinja2
rules/{policy_checks,severity_map,normalize_patterns}.yml
allowlists/*.yml
baselines/                      # PORTABLE reference data only (no client data)
systemd/                        # timer + service units (installed on the kit)
engagements/<engagement_id>/    # ALL client data lives here (see 1.2)
response/                       # separate privilege domain (separate repo in production)
tests/                          # pytest; fixtures under tests/fixtures/<component>/
vendor/python/                  # committed pure-Python PyYAML/Jinja2/MarkupSafe; scripts/_vendor.py
                                #   puts it on sys.path so the engine runs on a bare Python 3.11+
requirements.txt                # pinned engine deps (source for vendor/python)
requirements-dev.txt            # dev/test tooling (pytest, lint)
```

### 1.2 Engagement volume layout (created by `driftwatch new-engagement`)

```
engagements/<engagement_id>/
├── scope.yml                   # authorization boundary + settings (see 1.4)
├── inventory/hosts.yml         # GENERATED from scope.yml by scripts/scope_gate.py
├── inventory/fleet_groups.json # GENERATED: {host: [group, ...]} for the Python side
├── vault/vault.yml             # ansible-vault encrypted; never committed
├── preflight/transport_matrix.json
├── snapshots/<host>/<run_id>.json
├── configs/<host>/<run_id>.conf     # sanitized network config text
├── baselines/<host>.json            # promoted golden snapshots (per host or host-class)
├── findings/<run_id>.ndjson         # one finding per line
├── findings/state.json              # first_seen / fingerprint tracking across runs
├── cases/c-NNNN.json
├── evidence/<case_id>/
├── reports/<run_id>.{md,html}
├── audit/                           # ansible-run.log + hostlogs/ (ansible output = engagement data)
└── audit.log                        # append-only; every run, every scope denial
```

- `engagement_id` format: `<client>-<yyyy>-<mm>` (e.g. `acme-2026-07`).
- Active engagement selected by `--engagement <id>` flag or `DRIFTWATCH_ENGAGEMENT` env
  var; the CLI errors if neither is set (never guesses).

### 1.3 Shared identifiers

| Name | Format / value |
|---|---|
| `run_id` | UTC `%Y-%m-%dT%H%MZ`, e.g. `2026-07-22T0400Z`. One collection cycle = one run_id fleet-wide. |
| `schema_version` | `"1.0"` |
| `collector_version` | `"driftwatch 0.1.0"` |
| snapshot path | `engagements/<id>/snapshots/<inventory_hostname>/<run_id>.json` |
| finding id | `f-<run_id>-<NNNN>` (4-digit sequence within the run) |
| case id | `c-<NNNN>` (4-digit sequence within the engagement) |

### 1.4 `scope.yml` schema (engagement config — the authorization rail)

```yaml
engagement: acme-2026-07
client: "ACME Corp"
authorized_by: "J. Doe, CISO (signed SOW 2026-07-01)"   # free text, required
in_scope:                       # ONLY source for inventory generation. CIDRs or FQDNs.
  - cidr: 10.10.0.0/16
    groups: [linux]             # ansible groups to place discovered/declared hosts in
  - host: dc01.acme.example
    ip: 10.10.1.5
    groups: [windows, win_servers, crown_jewels]
deny:                           # explicit never-touch, wins over in_scope
  - cidr: 10.10.99.0/24
oob_subnets: []                 # devices NOT in these are assumed in-band (§13.5)
settings:
  hash_policy: tiered           # full | tiered | servers_only
  collector_account: svc-driftwatch    # tagged collector_self by the normalizer
  outlier_max_prevalence: 0.05  # fleet-outlier: item on <=5% ...
  outlier_min_group: 20         #   ... of a group with >=20 members
  fast_interval: 2h             # informational; systemd units read these
  deep_interval: 24h
  splunk_hec_url: ""            # empty = shipping disabled
  splunk_hec_token_var: vault_splunk_hec_token   # name of the vault var, never the secret
  elastic_url: ""
```

Hosts enter the inventory **only** via `in_scope`. `scripts/scope_gate.py`:
`generate` (scope.yml → inventory/hosts.yml + fleet_groups.json, fail-closed),
`check --ip <ip>` (exit 0 in scope / 2 out of scope), `assert-run` (validate a resolved
target list before a play; ANY out-of-scope or ambiguous target aborts the whole run and
appends to audit.log).

### 1.5 Shared Ansible variables (prefix `dw_`)

| Var | Meaning |
|---|---|
| `dw_engagement` | engagement id |
| `dw_engagement_dir` | absolute path to the engagement volume |
| `dw_run_id` | run id (set once per run by the CLI, passed with `-e`) |
| `dw_snapshot_dir` | `{{ dw_engagement_dir }}/snapshots` |
| `dw_deep` | bool — include deep/expensive categories (hashing, packages, cert stores) |
| `dw_hash_policy` | `full` / `tiered` / `servers_only` |
| `dw_transport_matrix` | path to `preflight/transport_matrix.json` (passed by `collect`) |

Roles write **nothing to targets**. Each category task registers results; a final
`assemble` task builds the full snapshot dict and writes it with `ansible.builtin.copy`
(content=json) **`delegate_to: localhost`**. Write modules are permitted ONLY with
`delegate_to: localhost` (enforced by `scripts/lint_readonly.py`).

A failed category never fails the play: every category task has `ignore_errors: true` +
failure recorded in `meta.failed_categories`, and the snapshot is marked `partial`.

---

## 2. Snapshot document schema

One JSON document per host per run. Top level: `meta` + one key per category (§3).

```json
{
  "meta": {
    "schema_version": "1.0",
    "host": "web01.acme.example",
    "platform": "linux",             // linux | windows | network | ad
    "os": "RHEL 9.4",
    "collected_at": "2026-07-22T04:00:12Z",
    "collector_version": "driftwatch 0.1.0",
    "engagement": "acme-2026-07",
    "run_id": "2026-07-22T0400Z",
    "partial": false,
    "failed_categories": [],
    "transport": "kerberos",         // windows only: kerberos|ssh|ntlm
    "collection_tier": "T1",         // network only: T1|T2|T3
    "hash_policy": "tiered"
  },
  "processes": [ ... ],              // categories per §3
  "listening": [ ... ]
}
```

- AD enrichment is its own document: `platform: "ad"`, `host: "<domain fqdn>"`, stored at
  `snapshots/_domain_<fqdn>/<run_id>.json` — one per domain per run, not per host.
- Array categories: list of flat(ish) objects. Object categories: a single dict.
- Roles emit **raw** snapshots (volatile fields included as attributes). Normalization
  (sorting, volatile-strip, args_norm) happens in `scripts/normalize.py` on the control
  node — roles should NOT pre-normalize beyond producing the documented fields.

---

## 3. Categories: identity keys and volatile fields

Semantics used by the diff engine (`normalize.py` + `diff_engine.py`):

- **identity**: fields whose tuple defines "the same item" across runs. Added/removed
  findings key off this.
- **volatile**: fields stripped before comparison (kept in the raw snapshot). Changes to
  them are NOT findings.
- Every other field is a **compared attribute**: a change produces a `changed` finding.
- Array categories are sorted by identity tuple in canonical form; canonical JSON is
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.

The authoritative machine-readable table is `CATEGORY_SPECS` in
`scripts/driftwatch_common.py`. Summary (field names are exact):

### 3.1 platform `linux`

| category | type | identity | volatile | other fields |
|---|---|---|---|---|
| `processes` | array | path, sha256, user, args_norm | pid, ppid, started | args (raw), signed_na |
| `fileless` | array | indicator, path, user | pid | detail — indicator: `deleted_exe`\|`memfd`\|`anon_exec_map` |
| `listening` | array | proto, port, path | pid | bind, user |
| `connections` | array | path, remote_ip, remote_port, proto | count | user |
| `cron` | array | source, user, schedule, command | — | file_hash |
| `systemd_units` | array | kind, name | next_run, last_run | enabled_state, file_hash — kind: `unit`\|`timer`\|`dropin` |
| `persistence` | array | mechanism, path | — | content_hash, present — mechanism: `ld_so_preload`\|`ld_preload_env`\|`profile_d`\|`rc_local`\|`init_d`\|`udev_rule`\|`motd_script`\|`shell_rc` |
| `users` | array | name, uid | last_login | gid, shell, home, locked, pw_last_set, home_ctime, groups (sorted list) |
| `groups` | array | name, gid | — | members (sorted list) |
| `ssh_keys` | array | user, fingerprint | — | key_type, comment, file |
| `ssh_config` | object | — | — | file_hash, permit_root_login, password_authentication, effective (dict of `sshd -T` subset) |
| `sudoers` | array | file | — | sha256, grants (sorted list of grant strings) |
| `kernel_modules` | array | name | size, used_by | sha256 |
| `kernel_state` | object | — | — | tainted, sysctls (dict) |
| `packages` | array | name, arch | — | version |
| `file_integrity` | array | kind, path | — | sha256, mode, owner, suid — kind: `suid`\|`critical` |
| `firewall` | array | rule | — | table, chain — rule = normalized rule text |
| `dns_trust` | array | kind, key | — | value — kind: `resolver`\|`hosts_entry`\|`proxy`\|`ca_bundle`\|`ca_cert` |
| `shares` | array | kind, name | — | path, options — kind: `nfs_export`\|`smb_share` |
| `logging_health` | object | — | — | rsyslog_active, journald_forward, auditd_active, audit_rules_hash, forward_targets (list) |

### 3.2 platform `windows`

| category | type | identity | volatile | other fields |
|---|---|---|---|---|
| `processes` | array | path, sha256, owner, cmdline_norm | pid, ppid, started | name, cmdline, signed, signer, user_writable_path (bool) |
| `fileless` | array | indicator, detail | pid | — indicator: `null_path`\|`name_path_mismatch`\|`lolbin_cmdline`\|`encoded_powershell` |
| `listening` | array | proto, port, path | pid | bind |
| `connections` | array | path, remote_ip, remote_port, proto | count | owner |
| `scheduled_tasks` | array | task_path, action_exe, action_args, principal | last_run, next_run | state, xml_hash, triggers, author |
| `services` | array | name | state | display_name, path, args, start_type, account, unquoted (bool) |
| `autoruns` | array | location, name, command | — | hash — location = full registry path or folder |
| `wmi_subscriptions` | array | kind, name | — | query, destination, consumer_type — kind: `filter`\|`consumer`\|`binding` |
| `users` | array | sid | last_logon | name, enabled, description, pw_last_set, profile_ctime, rid |
| `local_groups` | array | group, member_sid | — | member_name, member_class |
| `drivers` | array | name, path | — | signed, signer, version, sha256 |
| `software` | array | name | — | version, publisher, install_date, view (`64`\|`32`) |
| `hotfixes` | array | hotfix_id | — | installed_on |
| `firewall` | array | direction, action, program, port, profile | — | enabled, rule_name |
| `dns_trust` | array | kind, key | — | value, subject, not_before — kind: `hosts_entry`\|`dns_server`\|`proxy_winhttp`\|`proxy_user`\|`root_cert`\|`ca_cert` (certs: key = thumbprint) |
| `audit_logging` | object | — | — | audit_policy (dict), eventlog_running, max_log_sizes (dict), wef_configured, cleared_events (list of {event_id, time}) |
| `shares` | array | name | — | path, acl (sorted list of "principal:right" strings) |
| `powershell_surface` | object | — | — | execution_policy, profiles (list of {path, sha256}), psv2_enabled, scriptblock_logging, transcription |
| `security_posture` | object | — | — | wdigest_uselogoncredential, lsa_runasppl, rdp_enabled, rdp_nla, smbv1_enabled, defender_enabled, defender_exclusions (sorted list) |

### 3.3 platform `ad` (one doc per domain)

| category | type | identity | volatile | other fields |
|---|---|---|---|---|
| `ad_admins` | array | object_sid | last_logon_ts | sam, dn, enabled, when_created, when_changed, pwd_last_set, uac_flags, admin_count, spns (sorted), privileged_groups (sorted) |
| `ad_privileged_groups` | array | group, member_sid | — | member_sam, nesting_path |
| `ad_gpos` | array | guid | — | name, version, path_hash, linked_ous (sorted), startup_scripts (sorted), linked_tasks (sorted) |
| `ad_dcsync` | array | sid | — | sam, rights (sorted) |
| `ad_delegation` | array | kind, sid | — | sam, targets (sorted) — kind: `unconstrained`\|`constrained`\|`rbcd` |
| `ad_kerberoastable` | array | sam | — | spns (sorted), enabled, pwd_last_set |
| `ad_krbtgt` | object | — | — | pwd_last_set, pwd_age_days |
| `ad_adminsdholder` | object | — | — | acl_hash, protected_count |

### 3.4 platform `network`

| category | type | identity | volatile | other fields |
|---|---|---|---|---|
| `device_config` | object | — | — | sha256, line_count, config_path (relative to engagement dir), tier |
| `config_saved` | object | — | — | in_sync (bool), diff_lines (list) |
| `change_provenance` | object | — | entries | last_change_user, last_change_time — entries (list, most recent first) is VOLATILE |
| `local_accounts` | array | username | — | privilege, secret_hash (salted — never the secret) |
| `aaa` | object | — | — | method_lists (dict), tacacs_servers (sorted), radius_servers (sorted) |
| `mgmt_services` | array | service | — | enabled, detail — service: `telnet`\|`http`\|`https`\|`ssh`\|`vty_acl`\|... |
| `snmp` | array | kind, key | — | access, targets — kind: `community`\|`v3_user`\|`trap_target` (community: key = salted hash) |
| `logging_time` | object | — | — | syslog_targets (sorted), logging_level, ntp_servers (sorted), ntp_synced |
| `interfaces` | array | name | counters, last_flap | admin_status, oper_status, description, vlan, mode, ip |
| `tunnels` | array | name | — | kind, src, dst — kind: `gre`\|`ipip`\|`vxlan`\|... |
| `mirror_sessions` | array | session_id | — | src, dst, kind |
| `l2_state` | object | — | — | stp_root (dict vlan→bridge_id), trunks (sorted), mac_count_per_vlan (dict, VOLATILE — see spec) |
| `static_routes` | array | prefix, next_hop | — | interface, metric |
| `routing_neighbors` | array | protocol, peer | state, uptime | remote_as, interface |
| `firewall_rules` | array | rule_hash | hits | rule_text, action, src, dst, port, enabled — rule_hash = sha256 of normalized rule text |
| `nat_rules` | array | rule_hash | — | rule_text, direction, external, internal |
| `vpn_peers` | array | peer | — | kind, detail |
| `software_image` | object | — | — | version, image_file, image_hash, hash_verified |
| `neighbors` | array | local_interface, remote_device | — | remote_port, platform, capabilities |
| `protection_features` | object | — | — | port_security, dhcp_snooping, dai, storm_control (each: enabled/detail) |

Object categories diff key-by-key (recursive; canonical-JSON compare per top-level key);
each differing key produces one `changed` finding. Keys listed as VOLATILE in the spec
(`l2_state.mac_count_per_vlan`, `change_provenance.entries`) are stripped first.

---

## 4. Finding schema (NDJSON, one per line)

```json
{
  "finding_id": "f-2026-07-22T0400Z-0173",
  "engagement": "acme-2026-07",
  "run_id": "2026-07-22T0400Z",
  "severity": "critical",              // critical|high|medium|low|info
  "rule": "policy.windows.new_trusted_root_ca",   // most-specific rule; drift.<plat>.<cat> if no policy hit
  "platform": "windows",
  "category": "dns_trust",
  "change_type": "added",              // added|removed|changed|coverage_gap
  "hosts": ["WIN-FS01", "WIN-FS02"],   // sorted; findings with identical fingerprints merge hosts
  "detail": {
    "identity": {"kind": "root_cert", "key": "9F3A..."},
    "before": null,
    "after": {"kind": "root_cert", "key": "9F3A...", "subject": "CN=Corp Proxy CA 2"},
    "prevalence": 0.014,               // fleet_outlier only
    "note": ""                         // human-oriented extra context
  },
  "first_seen": "2026-07-22T0400Z",
  "comparison": ["temporal", "fleet_outlier"],   // lenses that caught it (accumulated)
  "suppressed": false,
  "suppressed_by": null,               // allowlist entry id when suppressed
  "fingerprint": "a1b2c3d4e5f60718"
}
```

- `fingerprint` = first 16 hex of sha256 over
  `platform + "|" + category + "|" + change_type + "|" + canonical-JSON of detail.identity`.
  Host- AND lens-independent, so the same underlying change is ONE finding with N hosts,
  no matter how many lenses (temporal / baseline / fleet_outlier / policy) caught it — the
  lenses accumulate in `comparison` and the most-specific rule wins as `rule`.
- `first_seen` persists across runs via `findings/state.json` keyed by fingerprint
  (value = the run_id in which the fingerprint first appeared).
- `rule` attribute: `drift.<platform>.<category>` for pure drift; upgraded to a policy
  rule's id (`policy.<platform>.<rule_name>`) when a policy rule matches the same item;
  `coverage.<gap_kind>` for coverage gaps (`host_unreachable`, `partial_snapshot`,
  `category_failed`, `no_transport`, `t3_only`).
- `comparison` values: `temporal`, `baseline`, `fleet_outlier`, `policy`.
- `detail.prevalence` and `detail.note` are present only when set; when the merged hosts'
  `after` values diverge, `detail.per_host` = {host: after} is added alongside the shared
  `after`.
- Suppressed findings stay in the NDJSON (`suppressed: true`) and render in a report
  appendix — never dropped.

## 5. Rules & allowlist file formats

### 5.1 `rules/policy_checks.yml` — baseline-free policy rules (§6 mode 4)

```yaml
rules:
  - id: policy.linux.ld_so_preload_present
    platform: linux              # linux|windows|network|ad|any
    category: persistence
    severity: critical
    description: "/etc/ld.so.preload exists"
    match:                       # fires once per matching ITEM (array cats) or once for the
      all:                       #   WHOLE OBJECT (object cats, identity {"key": "<category>"})
        - {field: mechanism, op: eq, value: ld_so_preload}
        - {field: present, op: eq, value: true}
```

Match DSL (implemented in `diff_engine.py`): `all:` (AND list) and/or `any:` (OR list) of
conditions `{field, op, value}`. Ops: `eq`, `ne`, `regex` (search), `in` (value is list),
`not_in`, `gt`, `lt`, `exists`, `absent`, `contains` (substring or list membership).
`field` supports dot-paths into the item / object category. For object categories the rule
matches against the whole object dict. A policy match contributes a delta with the lens
`policy`, `change_type` from the rule (default `added`), and the rule's `id` as the rule —
which then merges with any drift delta for the same item (same fingerprint), so a
first-appearance of a policy-flagged item shows `comparison: ["temporal","policy"]`.
Rules may set `change_type:` explicitly (default `added` — the flagged thing is present).

### 5.2 `rules/severity_map.yml`

```yaml
defaults: {added: medium, removed: low, changed: medium, outlier: medium,
           coverage_gap: high, policy: high}
overrides:                       # first match wins, evaluated top-down
  - {platform: windows, category: services, change_type: added, severity: high}
  - {platform: any, category: dns_trust, change_type: changed, severity: high}
```

### 5.3 `allowlists/*.yml` — expiring suppressions

```yaml
entries:
  - id: allow-chrome-autoupdate
    reason: "Chrome updater churns its own scheduled task"
    approver: analyst-b
    ticket: ACME-142
    expires: "2026-08-15"        # REQUIRED; missing or expired entries are ignored + warned about
    scope: {hosts: [], groups: [win_workstations]}    # empty = all
    match:                       # same DSL as policy rules, applied to detail.identity+after
                                 #   (plus synthetic `category` and `platform` fields)
      all:
        - {field: category, op: eq, value: scheduled_tasks}
        - {field: task_path, op: regex, value: '^\\GoogleUpdateTask'}
```

`rules/normalize_patterns.yml`: list of `{pattern, replace}` regexes applied by
`normalize.py` to `args_norm`/`cmdline_norm` (GUIDs, temp paths, one-time tokens).

## 6. Script CLIs (control node)

All Python scripts: stdlib + PyYAML + Jinja2 only (vendored under `vendor/python`, put on
sys.path by `scripts/_vendor.py`); Python 3.11+; importable (logic in functions,
`main(argv)` entry, thin `if __name__` shim); exit 0 ok / 1 error / 2 refusal.

| Script | Interface |
|---|---|
| `scope_gate.py` | `generate\|check\|assert-run --engagement-dir D [--ip IP] [--targets-file F] [--operator NAME]` |
| `normalize.py` | `normalize --engagement-dir D --run-id R [--host H] [--rules-dir rules/]`; library: `canonicalize(doc, patterns=None, collector_account=None) -> doc` |
| `diff_engine.py` | `run --engagement-dir D --run-id R [--rules-dir rules/] [--allowlists-dir allowlists/]` → writes `findings/<run_id>.ndjson`; library: `diff_documents(prev, cur, lens)`, `policy_check(doc, rules)`, `fleet_outliers(docs, groups, settings)`, `assemble(deltas, sev_map, engagement, run_id, state)` |
| `report_gen.py` | `render --engagement-dir D --run-id R [--format md,html]` → `reports/<run_id>.{md,html}` |
| `fleet_stats.py` | `matrix --engagement-dir D --run-id R [--format grid\|json]` → grid (or JSON) to stdout; always writes `reports/<run_id>.matrix.json` |
| `siem_ship.py` | `ship --engagement-dir D --run-id R [--splunk] [--elastic] [--dry-run]` (reads scope.yml settings; token from env/vault, never argv; `--dry-run` plans without connecting) |
| `lint_readonly.py` | `check [--roles-dir roles/] [--pattern snapshot_*]` → exit 2 with violation list if any snapshot role can write to a target |
| `baseline.py` | `promote --engagement-dir D --host H --run-id R [--ticket T] [--note N] [--force] [--operator NAME]` — copies snapshot to `baselines/<host>.json` with provenance block `meta.provenance{promoted_at,promoted_from_run,ticket,note}`; REFUSES a partial snapshot (exit 2) unless `--force` |

`diff_engine` comparison modes per run: temporal (prev vs latest per host), baseline
(baselines/<host>.json vs latest, if promoted), fleet outlier (per group from
fleet_groups.json, thresholds from scope.yml settings), policy. Coverage gaps
(unreachable/partial) are emitted as findings from collection status recorded in
`snapshots/_run/<run_id>.json` (written by the CLI after ansible exits: per-host
ok/partial/unreachable from the play recap).

Collector-self: normalize tags items whose user/owner/account/principal/run_as equals
`settings.collector_account` with `collector_self: true`; diff_engine caps a finding's
severity at `info` only when EVERY contributing delta is collector-self (still reported —
hijack of the account stays visible).

## 7. Response layer (separate privilege domain)

Lives in `response/` (separate repo in production; the boundary here is code/entry-point
separation per design §15.3). Never imported by collection code.

- Case file `cases/c-NNNN.json`: the design §14 schema
  (`case_id, engagement, finding, evidence[], proposed_action{tier,play,hosts}, approval{by,at,expires,authorized_by}, result{status,before,after,rolled_back}`).
  `approval.authorized_by` is a deliberate addition to §14: `by` = who confirmed in the
  tool, `authorized_by` = free text naming who authorized it out-of-band.
- v1 plays (Tier 1 only): `disable_account`, `isolate_host`, `block_hash`,
  `revoke_session` — each: preserve → dry-run (`--check`) → explicit confirm → act → log;
  each takes `case_id` + explicit host list; refuses hosts not named in the case finding.
- `response/scripts/respond.py`: `propose --case C --play P --hosts H1,H2 [--target T]
  [--artifact F]...`, `approve --case C [--authorized-by X --confirm]
  [--approval-ttl-hours N]` (interactive confirm; records approver + free-text authorizer),
  `rollback --case C`. All verbs take `[--engagement-dir D] [--operator NAME]`
  (engagement also resolves from `DRIFTWATCH_ENGAGEMENT[_DIR]`).
- Network-device plays: mandatory rollback timer, in-band warning if target not in
  `oob_subnets` (design §13.5). v1 ships NO network-config-writing plays.

## 8. CLI verbs (`bin/driftwatch`)

`new-engagement <id>` · `preflight` · `collect [--deep] [--limit PATTERN] [--collect-only]` ·
`diff [--run-id R]` · `report [--run-id R]` · `ship [--run-id R]` ·
`baseline promote <host> <run_id> [--ticket T]` ·
`respond <propose|approve|rollback> ...` (thin passthrough to response/) ·
`status` · `teardown [--retain report,findings,...] [--yes]`

Each verb: resolve engagement → for collect/preflight: scope_gate assert-run → run
ansible/scripts → append one line to `audit.log`
(`ISO8601 | verb | run_id | operator | outcome`).
`teardown` default profile: shred everything except the report; vault ALWAYS shredded;
`audit.log` + `scope.yml` always kept (the operator's authorization record).

## 9. Testing conventions

- Fixtures: `tests/fixtures/<component>/...`; a small canonical pair of linux snapshots
  (`web01_run1.json`, `web01_run2.json` with seeded drift) lives in
  `tests/fixtures/diff/` and may be reused by other components' tests.
- Tests import scripts via `tests/conftest.py` (adds `scripts/` and `response/scripts/`
  to sys.path, and appends `vendor/python` as a fallback so `import yaml` works on a bare
  interpreter) — `import diff_engine`, not package paths.
- No network, no ansible execution in tests; pure-Python only.
