# role: `snapshot_linux`

Read-only Linux security-snapshot collector for **driftwatch** (design §4.1, categories
L1–L17; schema per `docs/CONTRACTS.md` §3.1 `linux`). It produces **one canonical JSON
document per host per run**, assembled on the control node and written there — the role
writes **nothing** to the target.

## What it collects

Each category is one `ansible.builtin.shell` read (POSIX sh, tagged `readonly`) that
emits US(0x1F)-delimited records and stashes them as a `dw_raw_*` fact;
`templates/snapshot.json.j2` parses every record stream into the exact §3.1 field sets
and the two localhost-delegated tasks at the end of `tasks/main.yml` write the document.

| # | Category key | Type | Source (read-only) |
|---|---|---|---|
| L1 | `processes` | array | `/proc` walk: `readlink /proc/<pid>/exe`, cmdline, owner; tiered `sha256sum` of the on-disk binary |
| L2 | `fileless` | array | same walk: `(deleted)` exe, `memfd:` images, rwx anonymous mappings (`deleted_exe`\|`memfd`\|`anon_exec_map`) |
| L3 | `listening` | array | `ss -Hutlpn`, exe/user resolved from the owning PID via `/proc` |
| L4 | `connections` | array | `ss -Hantup state established`, aggregated to `(path, remote_ip, remote_port, proto)` + count; loopback dropped |
| L5 | `cron` | array | `crontab -l -u <user>` per passwd entry, `/etc/crontab`, `/etc/cron.d/*`, `cron.{hourly,daily,weekly,monthly}` inventory w/ hashes, pending `at` jobs |
| L6 | `systemd_units` | array | `systemctl list-unit-files` (+ per-timer next/last via `systemctl show`), hashes of `/etc/systemd/system` unit files and `*.d/*.conf` drop-ins (`unit`\|`timer`\|`dropin`) |
| L7 | `persistence` | array | `ld.so.preload` (sentinel, `present` flag), `LD_PRELOAD` in env/unit files, `profile.d`, `rc.local`, `init.d`, udev rules, MOTD scripts, tracked shell rc files — all hashed |
| L8 | `users`, `groups` | array | `getent passwd/group`; shadow **dates/flags only — hashes are never read out**; `home_ctime` as the creation-date approximation |
| L9 | `ssh_keys`, `ssh_config` | array/object | `authorized_keys(2)` per user → per-key fingerprint via `ssh-keygen -lf`; `sshd -T` subset + `sshd_config` hash |
| L10 | `sudoers` | array | `/etc/sudoers` + `sudoers.d/*` hashes + parsed grant lines (sorted) |
| L11 | `kernel_modules`, `kernel_state` | array/object | `lsmod` (+ `modinfo -n` → hash on deep runs); `/proc/sys/kernel/tainted` + security sysctl set |
| L12 | `packages` | array | `dpkg-query -W` / `rpm -qa` — **deep runs only** |
| L13 | `file_integrity` | array | `find -perm -4000/-2000` over the fixed standard paths (`kind=suid`); sha256 of the fixed critical set (`kind=critical`) |
| L14 | `firewall` | array | `nft list ruleset` (normalized rule lines) with `iptables-save`/`ip6tables-save` fallback |
| L15 | `dns_trust` | array | `resolv.conf` + resolvectl resolvers, `/etc/hosts` entries, proxy env, CA bundle hash (`ca_bundle`; per-cert `ca_cert` enumeration on deep runs) |
| L16 | `shares` | array | `/etc/exports(.d)` (`nfs_export`) + `smb.conf` share stanzas (`smb_share`) |
| L17 | `logging_health` | object | rsyslog/auditd `is-active`, journald `ForwardToSyslog`, audit-rules hash, rsyslog forward targets |

The top-level document keys are exactly `meta` + those 20 category keys. Field names are
emitted **exactly** as `docs/CONTRACTS.md` §3.1 defines them (the diff engine keys off
identity/volatile/attribute names — a typo silently breaks detection).

## Read-only by construction

This role must pass `python scripts/lint_readonly.py check --roles-dir roles` (a security
control, design §15.3: with one shared privileged account the guarantee degrades from
"cannot write" to "does not write", and the lint enforces it):

- Every `shell` task carries `tags: [readonly]` plus `changed_when: false`, asserting
  the pipeline only reads. Sudo is expected to be scoped to exactly these read commands
  (design §3 command allowlist).
- The only write modules (`file`, `copy`) are the assembly tasks at the end of
  `tasks/main.yml` and are **both** `delegate_to: localhost` — the snapshot is assembled
  and stored on the control node, never on the target.
- A failed category never fails the play: each collection task has `ignore_errors: true`
  + `failed_when: false`, and a non-zero rc records its name in `dw_failed_categories`,
  which sets `meta.partial` and `meta.failed_categories`. The document stays structurally
  complete (empty `[]`/`{}` for a failed category) so the diff engine can still compare it.
- Every collection task carries a hard `timeout` (design §8) so one hung host or command
  cannot stall the fleet.

## Output

`{{ dw_snapshot_dir }}/{{ inventory_hostname }}/{{ dw_run_id }}.json`
(= `engagements/<id>/snapshots/<host>/<run_id>.json`, CONTRACTS §1.3). Snapshots are
emitted **raw**: volatile fields (pid, ppid, started, next_run/last_run, size/used_by,
count, last_login) are included as attributes and stripped later by
`scripts/normalize.py`, not by this role.

## Variables (defaults in `defaults/main.yml`, normally passed with `-e`)

| Var | Meaning |
|---|---|
| `dw_engagement` | engagement id (goes into `meta.engagement`) |
| `dw_engagement_dir` | absolute path to the engagement volume |
| `dw_run_id` | run id, `%Y-%m-%dT%H%MZ` (one per fleet-wide collection cycle) |
| `dw_snapshot_dir` | `{{ dw_engagement_dir }}/snapshots` |
| `dw_deep` | bool — gate expensive work (binary/module hashing, packages, CA-cert enumeration) |
| `dw_hash_policy` | `full` \| `tiered` \| `servers_only` |
| `dw_snapshot_linux_cmd_timeout` / `_hash_timeout` | per-task hard timeouts (seconds) |
| `dw_snapshot_linux_max_procs` | ceiling on processes resolved/hashed per host |
| `dw_snapshot_linux_suid_paths` | fixed search roots for the L13 SUID/SGID inventory |
| `dw_snapshot_linux_critical_files` | fixed critical file set hashed every run (L13) |
| `dw_snapshot_linux_sysctls` | security sysctl set captured in `kernel_state` (L11) |
| `dw_snapshot_linux_shell_rc_files` | shell rc sentinels tracked as `persistence` (L7) |
| `dw_snapshot_linux_sshd_t_keys` | `sshd -T` keys recorded in `ssh_config.effective` (L9) |

### Hashing (tiered — design C.2)

`dw_snapshot_linux_do_hash` opens the hash gate when `dw_hash_policy == 'full'` **or**
`dw_deep` is set; it governs process binaries (L1), kernel modules (L11) and the SUID
inventory (L13). The fixed critical set (L13) is always hashed — it is a handful of
files. Because `sha256` is part of the `processes` identity (CONTRACTS §3.1), a process
not hashed on a fast run carries `sha256: null`; keep a consistent policy/cadence per
engagement and re-run `full` on any host that produces a Critical finding.

## Requirements

- POSIX sh + coreutils (`sha256sum`, `stat`, `find`, `awk`), `ss` (iproute2),
  `getent`; `systemctl`, `nft`/`iptables-save`, `ssh-keygen`, `lsmod`/`modinfo`,
  `crontab`, `atq`, `lastlog` are all optional — absence degrades that record
  stream, never the run.
- `become: true` (scoped sudo): shadow fields, per-user crontabs, sudoers and
  `sshd -T` need root.

## Notes / honest limits

- L2 `fileless` flags are tripwires, not proof — in-memory-only implants need
  EDR/Velociraptor memory scanning (design §12). JIT runtimes (Java, Node) legitimately
  produce `anon_exec_map` records; allowlist them per fleet.
- Linux stores no account-creation date; `home_ctime` (plus first-login/lastlog and auth
  logs, design L8) is an approximation, not an authority.
- `packages` is empty on fast runs by design — compare deep runs against deep runs.
- On hosts without systemd (`systemctl` absent) `systemd_units` is legitimately empty
  and `logging_health` service flags read `false`.
