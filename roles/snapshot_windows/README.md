# role: `snapshot_windows`

Read-only Windows security-snapshot collector for **driftwatch** (design §4.2, categories
W1–W17; schema per `docs/CONTRACTS.md` §3.2 `windows`). It produces **one canonical JSON
document per host per run**, assembled on the control node and written there — the role
writes **nothing** to the target.

## What it collects

Each category is one `ansible.windows.win_powershell` read (structured objects, no console
parsing), tagged `readonly`, registered, and folded into the snapshot by `tasks/assemble.yml`.

| # | Category key | Type | Source (read-only) |
|---|---|---|---|
| W1 | `processes` | array | `Win32_Process` + `GetOwner()`, `Get-AuthenticodeSignature`, tiered `Get-FileHash` |
| W2 | `fileless` | array | derived from `Win32_Process` (null path / name-path mismatch / lolbin / encoded PS) |
| W3 | `listening` | array | `Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint` |
| W4 | `connections` | array | `Get-NetTCPConnection -State Established` (aggregated + counted) |
| W5 | `scheduled_tasks` | array | `Get-ScheduledTask` / `-Info`, `Export-ScheduledTask` → `xml_hash` |
| W6 | `services` | array | `Win32_Service` (flags unquoted paths) |
| W7 | `autoruns` | array | Run/RunOnce (HKLM + all HKU, incl. Wow6432Node), Startup folders, Winlogon, IFEO, AppInit_DLLs, LSA packages |
| W8 | `wmi_subscriptions` | array | `root\subscription` `__EventFilter` / consumers / `__FilterToConsumerBinding` |
| W9 | `users`, `local_groups` | array | `Get-LocalUser`; `Get-LocalGroupMember` (Administrators, Remote Desktop Users, Remote Management Users, Backup Operators) |
| W10 | `drivers` | array | `Win32_SystemDriver` + signature (+ hash on deep runs) |
| W11 | `software`, `hotfixes` | array | Uninstall keys (both views + per-user), `Get-HotFix` |
| W12 | `firewall` | array | `Get-NetFirewallRule -Enabled True -Action Allow` joined to app/port filters |
| W13 | `dns_trust` | array | hosts file, `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, per-user proxy, `Cert:\LocalMachine\Root` + `CA` |
| W14 | `audit_logging` | object | `auditpol`, EventLog service, log sizes, WEF, 1102/104 clears |
| W15 | `shares` | array | `Get-SmbShare` + `Get-SmbShareAccess` |
| W16 | `powershell_surface` | object | execution policy, profiles, PSv2 engine, ScriptBlock logging, transcription |
| W17 | `security_posture` | object | WDigest, LSA RunAsPPL, RDP/NLA, SMBv1, Defender state + exclusions (`Get-MpPreference`) |

The top-level document keys are exactly `meta` + those 19 category keys. Field names inside
each category are emitted **exactly** as `docs/CONTRACTS.md` §3.2 defines them (the diff
engine keys off identity/volatile/attribute field names — a typo silently breaks detection).

## Read-only by construction

This role must pass `python scripts/lint_readonly.py check --roles-dir roles` (a security
control, design §15.3: with one shared privileged account the guarantee degrades from
"cannot write" to "does not write", and the lint enforces it):

- Every `win_powershell` task carries `tags: [readonly]`, asserting the script only reads.
  Each script also sets `$Ansible.Changed = $false`.
- The only write modules (`file`, `copy`) are in `tasks/assemble.yml` and are **all**
  `delegate_to: localhost` — the snapshot is assembled and stored on the control node,
  never on the target.
- A failed category never fails the play: each collection task has `ignore_errors: true`
  and records its name in `dw_failed_categories`, which sets `meta.partial` and
  `meta.failed_categories`. The document stays structurally complete (empty `[]`/`{}` for
  a failed category) so the diff engine can still compare it.

## Output

`{{ dw_snapshot_dir }}/{{ inventory_hostname }}/{{ dw_run_id }}.json`
(= `engagements/<id>/snapshots/<host>/<run_id>.json`, CONTRACTS §1.3). Snapshots are emitted
**raw**: volatile fields (pid, started, last_run, counts, …) are included as attributes and
stripped later by `scripts/normalize.py`, not by this role.

## Variables (defaults in `defaults/main.yml`, normally passed with `-e`)

| Var | Meaning |
|---|---|
| `dw_engagement` | engagement id (goes into `meta.engagement`) |
| `dw_engagement_dir` | absolute path to the engagement volume |
| `dw_run_id` | run id, `%Y-%m-%dT%H%MZ` (one per fleet-wide collection cycle) |
| `dw_snapshot_dir` | `{{ dw_engagement_dir }}/snapshots` |
| `dw_deep` | bool — gate expensive work (full process hashing, driver hashing) |
| `dw_hash_policy` | `full` \| `tiered` \| `servers_only` |
| `dw_transport` | recorded as `meta.transport`; derived from the connection, override for the NTLM exception |
| `dw_event_scan_max` | cap on 1102/104 events enumerated per log |

### Hashing (tiered — design C.2)

`Get-FileHash` is the expensive step, so `processes` hashes are tiered:

- `full` → hash every process image, always.
- `servers_only` → hash everything on hosts in `win_servers` / `crown_jewels`.
- `tiered` (default) → hash everything on **deep** runs, and on every run still hash the
  **interesting subset** — any image that is unsigned or runs from a user-writable path
  (`\Users\`, `\AppData\`, `\Temp\`, `\ProgramData\`, `\Public\`). Those are precisely where
  payloads live. Authenticode signing is cheap and is always collected.

Because `sha256` is part of the `processes` identity (CONTRACTS §3.2), a process not hashed
on a fast run carries `sha256: null`; keep a consistent `hash_policy`/cadence per engagement,
and re-run `full` on any host that produces a Critical finding (design C.2 caveat).

## Requirements

- `ansible.windows` collection (declared in the kit-level `requirements.yml`).
- A Windows transport per design §3.1 (Kerberos/WinRM-HTTPS primary, OpenSSH fallback);
  the account must be in local `Administrators` for full process/WMI/user visibility.
- Ansible cannot be executed on the Windows authoring host; the YAML is valid and
  lint-clean, intended to run from the Linux control node.

## Notes / honest limits

- W2 `fileless` flags are tripwires, not proof — true in-memory-only implants need
  EDR/Velociraptor memory scanning (design §12). Domain accounts surfaced in W9 admin
  groups are enriched by the separate `snapshot_ad` role (design W18), not here.
- `firewall` scopes to enabled Allow rules and joins per-rule filters; on hosts with very
  large rule bases this is the slowest category.
