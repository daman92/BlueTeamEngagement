# role: `snapshot_ad`

Read-only **Active Directory enrichment** collector for driftwatch — design §4.2 **W18**,
CONTRACTS.md §3.3 platform **`ad`**.

Runs **once per domain** (not per host): the operator places exactly **one** domain
controller or domain-joined Windows host per domain into the inventory `ad` group, and
`playbooks/snapshot.yml` runs this role against that group with `serial: 1`. It emits
**one** canonical snapshot document per domain per run, assembled and written **on the
control node** — nothing is written to any target.

```
snapshots/_domain_<domain-fqdn>/<run_id>.json      # platform: ad, host: <domain fqdn>
```

## Why once per domain

AD is a domain-wide database. Querying it from every host would hammer the DC with N
identical queries and produce N identical snapshots. This role collects the domain's
tier-0 state exactly once and stores it as its own document (`meta.platform: "ad"`,
`meta.host: "<domain fqdn>"`), separate from the per-host `snapshot_windows` documents.
Local Windows admin groups are captured per host by `snapshot_windows` (W9); this role is
the authoritative source for **domain** accounts, groups, GPOs, delegation, and DCSync.

## What it collects (CONTRACTS.md §3.3)

| category | type | identity | key content |
|---|---|---|---|
| `ad_admins` | array | `object_sid` | every user that is an effective member of a privileged group, with `sam, dn, enabled, when_created, when_changed, pwd_last_set, uac_flags, admin_count, spns, privileged_groups` (`last_logon_ts` is volatile) |
| `ad_privileged_groups` | array | `group, member_sid` | **full nested expansion** of each privileged group; `member_sam` + `nesting_path` (the exact chain of nested groups) |
| `ad_gpos` | array | `guid` | `name, version, path_hash` (sha256 of `gPCFileSysPath`), `linked_ous`, `startup_scripts`, `linked_tasks` |
| `ad_dcsync` | array | `sid` | principals holding replication rights on the domain NC (`sam, rights`) |
| `ad_delegation` | array | `kind, sid` | `unconstrained` / `constrained` / `rbcd` delegation (`sam, targets`) |
| `ad_kerberoastable` | array | `sam` | user accounts with an SPN (`spns, enabled, pwd_last_set`) |
| `ad_krbtgt` | object | — | `pwd_last_set, pwd_age_days` |
| `ad_adminsdholder` | object | — | `acl_hash` (sha256 of the SDDL), `protected_count` (`adminCount=1` objects) |

Identity is `objectSid` wherever possible — it survives renames, which is exactly how a
renamed account tries to hide.

### Privileged groups expanded

`Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Account Operators`,
`Backup Operators`, `DnsAdmins` (W18-mandated) plus `Administrators`, `Server Operators`,
`Print Operators`, `Group Policy Creator Owners`, `Key Admins`, `Enterprise Key Admins`.
Add any environment-specific group that grants local admin via `dw_ad_privileged_groups`
(`-e` or group_vars) — both `ad_admins` and `ad_privileged_groups` honor the list.

## Collection method

Primary path is **RSAT** through `ansible.windows.win_powershell` (`Get-ADUser` /
`Get-ADGroup` / `Get-ADGroupMember` / `Get-ADObject` / `Get-Acl AD:\…`). Each category is
its own task file under `tasks/`, registers its result, and is `ignore_errors: true` so a
single failing category never fails the play — the failure is recorded in
`meta.failed_categories` and the document is marked `meta.partial: true`.

If the RSAT `ActiveDirectory` module is **absent** on the delegated host, the role falls
back to `community.general.ldap_search` (`tasks/ldap_fallback.yml`, runs on the control
node). The fallback is **reduced fidelity**: it collects `ad_kerberoastable` and a basic
`ad_gpos`, and records the categories that need RSAT-only capabilities (binary
`objectSid` decoding, FILETIME conversion, SDDL/ACL hashing, recursive expansion with
path tracking) as coverage gaps. **Install `RSAT-AD-PowerShell` on the delegated host for
full-fidelity enrichment.** If RSAT is absent *and* the LDAP fallback is unconfigured, the
role never aborts: every `ad_*` category is recorded in `meta.failed_categories` and the
snapshot is still written with `meta.partial: true` (CONTRACTS.md §1.5 — a failed category
never fails the play).

## Read-only guarantee

This role **passes `python scripts/lint_readonly.py check --roles-dir roles`**:

- Every `win_powershell` task carries `tags: [readonly]` — the author's assertion that
  the script only reads. Each script also sets `$Ansible.Changed = $false`.
- The only write modules used are `file`/`template`, and only `delegate_to: localhost`
  (assembling the snapshot on the control node — never a target).
- No target-mutating modules, no network `*_config` modules.

The AD scripts issue only `Get-*` / read operations and hash computations in memory.

## Variables

Shared driftwatch vars (passed by the CLI via `-e` / group_vars):

| var | meaning |
|---|---|
| `dw_engagement` | engagement id → `meta.engagement` |
| `dw_engagement_dir` | engagement volume path |
| `dw_run_id` | run id → output filename + `meta.run_id` |
| `dw_snapshot_dir` | `{{ dw_engagement_dir }}/snapshots` |
| `dw_deep` | gate SYSVOL script/task enumeration for `ad_gpos.startup_scripts` / `linked_tasks` |
| `dw_hash_policy` | recorded in `meta.hash_policy` |

Role-specific (see `defaults/main.yml`):

| var | default | meaning |
|---|---|---|
| `dw_ad_privileged_groups` | see defaults | groups to fully expand |
| `dw_ad_domain_fqdn` / `dw_ad_domain_dn` | `""` | overrides for `meta.host` / LDAP search base when RSAT can't resolve them |
| `dw_ad_ldap_server` | `""` | DC for the LDAP fallback |
| `dw_ad_ldap_bind_dn` / `dw_ad_ldap_bind_pw` | `""` | LDAP bind creds — `bind_pw` **must** come from the engagement vault, never inline |

## Requirements

- Collections: `ansible.windows`, `community.general` (pin in the kit `requirements.yml`).
- On the delegated host: `RSAT-AD-PowerShell` for the primary path. For the fallback:
  `python-ldap` on the control node and LDAP reachability to a DC.
- Transport per design §3.1 (Kerberos/WinRM-HTTPS preferred). SYSVOL enumeration
  (`dw_deep`) needs the delegated account to read the domain SYSVOL share.

## Example invocation

```yaml
# playbooks/snapshot.yml (excerpt) — the `ad` group holds exactly ONE domain-joined
# host (a DC or any domain member) PER DOMAIN, so each host = one domain document.
# NOT run_once: that would collect only a single domain in a multi-domain estate.
- name: AD enrichment (§4.2 W18 / role snapshot_ad — once per domain)
  hosts: ad
  gather_facts: false
  serial: 1                 # keeps DC load low
  any_errors_fatal: false
  roles:
    - role: snapshot_ad
```

```bash
# from the Linux control node
ansible-playbook -i engagements/acme-2026-07/inventory/hosts.yml playbooks/snapshot.yml \
  -e dw_engagement=acme-2026-07 \
  -e dw_engagement_dir=$PWD/engagements/acme-2026-07 \
  -e dw_run_id=2026-07-22T0400Z \
  -e dw_snapshot_dir=$PWD/engagements/acme-2026-07/snapshots \
  -e dw_deep=true -e dw_hash_policy=tiered
```

Writes `engagements/acme-2026-07/snapshots/_domain_acme.example/2026-07-22T0400Z.json`,
which `scripts/normalize.py` + `scripts/diff_engine.py` then consume like any other
snapshot.

## Notes / limitations

- Default DCSync holders (Domain Admins, Enterprise Admins, Administrators, Domain
  Controllers) and default unconstrained-delegation holders (the DCs themselves) are
  reported **as-is** — deciding which are expected is the control node's job
  (policy rules / baseline), not the collector's.
- `Get-ADGroupMember -Recursive` (used by `ad_admins`) can miss members from foreign
  domains / primary-group-only membership; `ad_privileged_groups` does an explicit
  cycle-safe walk and is the authoritative expansion.
- Schema Admins / Enterprise Admins live only in the **forest root** domain; when this
  role runs against a child domain those groups simply resolve to nothing (skipped).
