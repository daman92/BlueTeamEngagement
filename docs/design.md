# Design Document — Blue Team Baseline & Drift Detection Framework

| | |
|---|---|
| **Working name** | `driftwatch` (rename as you like) |
| **Version** | 0.3 — all open items resolved (see Appendix B) |
| **Date** | 2026-07-22 |
| **Classification** | Internal — Security Team |
| **Platform** | Ansible (agentless), targeting Windows, Linux, and network infrastructure |
| **Operating model** | Portable per-engagement kit (laptop + kit), single analyst, in-kit SIEM |

---

## 1. Purpose & Scope

This framework uses Ansible to collect point-in-time security snapshots from every managed host and network device, normalize them into a canonical JSON format, and compare them — against each host's own history, against an approved golden baseline, and against the rest of the fleet. Differences are enumerated in a report that answers, per finding, *which machines have this difference*, when it first appeared, and how severe it is.

**In scope:** Windows Server/desktop, Linux (RHEL/Debian families), switches, routers, and firewalls; snapshot collection; drift detection; anomaly and policy checks; human-readable and SIEM-consumable reporting.

**Explicitly out of scope (see §12):** real-time detection, packet capture, deep memory forensics, and automated remediation. This tool complements — does not replace — EDR, a SIEM, and network monitoring.

**Design principles:**

1. **Agentless and read-only.** Collection uses existing management channels (SSH/WinRM). The playbooks make no persistent changes to targets and minimize their forensic footprint.
2. **Evidence leaves the host immediately.** Snapshots are assembled on the control node, never stored on targets, and are integrity-protected. An attacker on a target cannot rewrite their own history.
3. **Normalize before you diff.** Raw diffs of volatile data (PIDs, ephemeral ports, counters) produce unusable noise. Every category has explicit identity keys and volatile-field rules (§6).
4. **Three lenses, not one.** Temporal drift (host vs. its past), baseline drift (host vs. approved golden state), and fleet outliers (host vs. its peers). Some things are wrong regardless of baseline — those are policy checks that fire even on a first run.
5. **The collector is a target.** A system holding admin credentials to the entire fleet must itself be hardened and audited (§9).

---

## 2. Architecture Overview

```
                        ┌─────────────────────────────────────────────┐
                        │            CONTROL NODE (hardened)           │
                        │                                              │
  ┌──────────────┐      │  ┌───────────┐   ┌────────────┐              │
  │ Linux hosts  │◄─SSH─┤  │  Ansible  │──►│ snapshots/ │ (canonical   │
  └──────────────┘      │  │  playbook │   │  JSON,     │  JSON, git-  │
  ┌──────────────┐      │  │  runs     │   │  per host, │  versioned,  │
  │ Windows hosts│◄WinRM┤  └───────────┘   │  per run)  │  hashed)     │
  └──────────────┘ /SSH │        │         └─────┬──────┘              │
  ┌──────────────┐      │        │               ▼                     │
  │ Switches /   │◄─SSH─┤        │         ┌────────────┐   ┌────────┐ │
  │ routers /    │ (network_cli) │         │ normalize +│──►│reports/│ │
  │ firewalls    │      │        │         │ diff engine│   │ MD/HTML│ │
  └──────────────┘      │        │         │ (Python)   │   │ /JSON  │ │
                        │        │         └─────┬──────┘   └───┬────┘ │
                        └────────┼───────────────┼──────────────┼──────┘
                                 ▼               ▼              ▼
                          run logs        push to central   SIEM / mail /
                          (audited)       off-host store    Slack webhook
```

**Components:**

| Component | Implementation | Notes |
|---|---|---|
| Orchestrator | `ansible-playbook` via systemd timer, or AWX/AAP/Semaphore | AWX preferred at >100 hosts for scheduling, RBAC, and run logging |
| Collection roles | `snapshot_linux`, `snapshot_windows`, `snapshot_network` | Each emits one canonical JSON document per host per run |
| Snapshot store | `snapshots/<host>/<UTC-timestamp>.json` on kit-local or attached encrypted storage, versioned in a local git repo, pushed to GitLab where the engagement allows | Git gives free history, diffing, and tamper evidence. **Decided:** local/attached/GitLab — no object-lock tier, see §5 for the tamper-resistance trade-off this accepts |
| Diff engine | Python (`scripts/diff_engine.py`) | Runs on control node after each collection run; pure functions per category |
| Report generator | Python + Jinja2 (`scripts/report_gen.py`) | Markdown + HTML for humans, NDJSON for SIEM ingestion |
| Baselines & allowlists | `baselines/`, `allowlists/` in the same repo | Changes require review (PR/approval) — see §8 |

**Key design decisions (proposed — confirm at review):**

| Decision | Proposal | Alternatives |
|---|---|---|
| Agent vs. agentless | Agentless Ansible | Osquery/Velociraptor agents give richer telemetry; can coexist later |
| Where diffs run | Control node only | Never on targets — targets can't be trusted to judge themselves |
| Snapshot storage | **Decided:** kit-local / attached storage / GitLab | S3/MinIO object-lock (WORM) — rejected for the portable model; adds infrastructure that doesn't travel |
| Windows transport | WinRM over HTTPS (5986) with Kerberos; OpenSSH acceptable | Never WinRM over HTTP; avoid NTLM |
| Report canonical format | JSON findings; MD/HTML rendered from it | — |

---

## 3. Inventory & Connectivity

```yaml
# inventory/hosts.yml (illustrative)
all:
  children:
    linux:
      children: { rhel: {}, debian: {} }
    windows:
      children: { win_servers: {}, win_workstations: {} }
    network:
      children:
        switches:  { children: { ios_switches: {}, eos_switches: {} } }
        routers:   { children: { ios_routers: {}, junos_routers: {} } }
        firewalls: { children: { asa: {}, fortios: {}, panos: {} } }
    crown_jewels:        # cross-cutting tier: DCs, hypervisors, PKI, core switches
      hosts: { dc01: {}, core-sw-01: {} }
```

| Group | Transport | Ansible settings | Account / privilege |
|---|---|---|---|
| linux | SSH | `ansible_connection=ssh`, `become=true` | Dedicated `svc-driftwatch` account; sudo scoped to the exact read commands the roles run (sudoers command allowlist), no shell writes |
| windows | **Kerberos/WinRM-HTTPS primary, OpenSSH fallback** — see §3.1 | `ansible_connection=winrm`, `ansible_winrm_transport=kerberos`, `ansible_port=5986`, cert validation on. Fallback: `ansible_connection=ssh`, `ansible_shell_type=powershell` | Domain account in local Administrators (typically the one privileged account you're issued); required for full process/user/WMI visibility |
| network | SSH | `ansible_connection=ansible.netcommon.network_cli`, `ansible_network_os` per platform | Read-only privilege level / RBAC role where the platform supports it (e.g., IOS priv 5 with command authorization, JunOS read-only class, PAN-OS superuser-read-only) |

### 3.1 Windows transport ladder (kit is *not* domain-joined)

Targets are usually domain-joined; **your kit never is**. Kerberos still works from a non-domain-joined Linux control node, but only if three things are set up on arrival — and each is a classic silent-failure mode, so the kit should verify them explicitly before a run rather than emitting confusing auth errors.

| Rung | Transport | Use when | Setup / gotchas |
|---|---|---|---|
| **1** | **Kerberos over WinRM-HTTPS (5986)** | Default. Targets domain-joined, WinRM enabled (it is by default on Server; often *not* on workstations) | Kit needs: (a) `/etc/krb5.conf` with the client's realm + KDC, then `kinit user@REALM` to get a TGT — no domain join required; (b) **DNS pointed at the client's DC** so SPNs and host records resolve — Kerberos fails on IP-only targets, always use FQDNs; (c) **clock sync within 5 minutes** of the DC (`chrony` against the DC/client NTP). Time skew and DNS account for most "Kerberos doesn't work" incidents |
| **2** | **OpenSSH** | WinRM unavailable/disabled, workgroup or non-domain hosts, or Kerberos prerequisites can't be met | Set `ansible_shell_type=powershell`. **Requires the OpenSSH Server feature already installed and running** — see the caveat below. Key-based auth preferred if the client will place a key; otherwise password auth over SSH. No double-hop concerns since you're not delegating |
| **3** | NTLM over WinRM-**HTTPS** with cert validation | Last resort only, documented as an exception | Works without domain-joined kit or DNS/time setup, which makes it tempting — but it exposes the privileged credential to relay/replay, and it's the weakest option you'll be asked to justify. Never NTLM over HTTP (5985) under any circumstance |

**The OpenSSH-fallback caveat that matters operationally:** Windows OpenSSH Server is *not* installed by default on most Windows builds. If it's absent, enabling it is a **write action on a client machine** — which contradicts the read-only collection posture and shouldn't be done unilaterally. So the fallback is only a fallback where it already exists. Practical handling:

- Probe for it during pre-flight and record availability per host.
- If neither WinRM nor OpenSSH is reachable, that host becomes an **"authorized but not assessed" coverage gap** (§15.2) — reported, never silently skipped.
- If the gap is large enough to undermine the engagement, ask the *client* to enable WinRM or OpenSSH via their own GPO/change process. Their change, their environment — not a silent modification by your tool.

**Pre-flight connectivity matrix.** Before the first real run, the kit should test every Windows target across the ladder and emit a table of what each host will actually use (`kerberos` / `ssh` / `ntlm` / `unreachable`). Knowing on day one that 40 hosts have no viable transport is far better than discovering it in the middle of collection — and the matrix goes in the report as coverage documentation.

**Required collections:** `ansible.windows`, `community.windows`, `ansible.posix`, `community.general`, `ansible.netcommon`, plus vendor collections per §4.3 tiering (`cisco.ios`, `cisco.nxos`, `cisco.asa`, `arista.eos`, `junipernetworks.junos`, and others as encountered). Kerberos additionally needs `krb5-user`/`krb5-workstation` and `pywinrm[kerberos]` on the kit — bake these into the kit image, not into per-engagement setup.

**Credential handling:** all secrets in the engagement's Ansible Vault, injected on arrival, never committed; no plaintext in inventory. **Expect a single privileged account per engagement** rather than the read-only/privileged split the permanent model assumes — see §15.3 for what that costs and how it is compensated.

---

## 4. Collection Specification

Every role produces one JSON document conforming to the schema in §5. Each row below defines *what* is collected, *how*, and the **identity key** used later for diffing (fields not in the identity key are treated as attributes; volatile fields are dropped — see §6).

### 4.1 Linux — role `snapshot_linux`

| # | Category | What is captured | Method (read-only) | Identity key / notes |
|---|---|---|---|---|
| L1 | Running processes | PID, PPID, user, start time, full args, resolved executable path, SHA-256 of executable | `ps -eww -o pid,ppid,user,lstart,args`; `readlink /proc/<pid>/exe`; hash on-disk binary | Identity = `(exe_path, sha256, user, normalized_args)`. PID/start-time are attributes only |
| L2 | Memory-only / fileless indicators | Processes whose `/proc/<pid>/exe` shows `(deleted)` or `memfd:`; executable anonymous mappings | parse `readlink` output; `/proc/<pid>/maps` scan | Any hit is a **policy finding** (Critical), not just drift |
| L3 | Listening ports | proto, bind addr, port, owning PID→process, user | `ss -tulpen` | Identity = `(proto, port, exe_path)`. Bind-addr change (127.0.0.1→0.0.0.0) is a *changed* finding |
| L4 | Active connections | established/related conns: remote IP, remote port, proto, owning process | `ss -tanpu state established` | Identity = `(exe_path, remote_ip, remote_port, proto)`; **drop local ephemeral port**; aggregate per process (see §6) |
| L5 | Cron | Per-user crontabs, `/etc/crontab`, `/etc/cron.d/*`, `cron.{hourly,daily,weekly,monthly}` file list + hashes, `at`/`anacron` jobs | `crontab -l -u <user>` per passwd entry; slurp files | Identity = `(source_file, user, schedule, command)` |
| L6 | systemd units & timers | Enabled units, unit-file hashes, timers, override/drop-in files, generator output | `systemctl list-unit-files`, `systemctl list-timers --all`, hash `/etc/systemd/system/**` | New/changed unit or timer = High. **This is the modern cron — do not skip** |
| L7 | Other persistence | `/etc/ld.so.preload`, `LD_PRELOAD` in unit envs, `/etc/profile.d/*`, `rc.local`, `init.d`, udev rules, MOTD scripts, shell rc files for root & service accounts | slurp + hash | Any change = High; `ld.so.preload` existing at all = Critical policy finding on most fleets |
| L8 | Users & groups | passwd entries, UID/GID, shell, home; group memberships (esp. `sudo`,`wheel`,`root`,`adm`); shadow: password-last-set, locked/expired; extra UID-0 accounts | `getent passwd/group`, parse `/etc/shadow` fields (no hashes exfiltrated — dates/flags only) | Creation date caveat: Linux stores none. Approximate via home-dir `stat` ctime, `useradd` entries in auth logs, and lastlog first-login. Record all three |
| L9 | SSH trust | `authorized_keys` per user: file hash + per-key fingerprints/comments; `sshd_config` hash + effective settings (`sshd -T` subset) | slurp, `ssh-keygen -lf` | Key added/removed = High. Root login or password-auth flipped on = Critical policy |
| L10 | Sudoers | `/etc/sudoers` + `/etc/sudoers.d/*` hashes and parsed grants | slurp (via scoped sudo) | Any change = High |
| L11 | Kernel | Loaded modules, module file hashes, kernel taint flag, security-relevant sysctls (`ip_forward`, `kptr_restrict`, module signing) | `lsmod`, `/proc/sys/kernel/tainted` | Unexpected module = Critical (rootkit surface) |
| L12 | Packages | Installed package name+version+arch | `dpkg-query -W` / `rpm -qa --qf` | New package outside patch window = Medium |
| L13 | File integrity (targeted) | SUID/SGID inventory in standard paths; hashes of a defined critical set (`/etc/hosts`, `/etc/resolv.conf`, `nsswitch.conf`, `pam.d/*`, core binaries list) | scoped `find -perm -4000`, `sha256sum` | New SUID binary = Critical. Keep the hash set small and fixed for speed; full FIM stays with AIDE/EDR |
| L14 | Host firewall | Effective ruleset | `nft list ruleset` / `iptables-save` / `firewall-cmd --list-all-zones` | Normalize ordering; new ACCEPT rule = High |
| L15 | DNS / proxy / trust store | resolv.conf + systemd-resolved config, `/etc/hosts` entries, system proxy env, CA bundle hash + count of certs in `/etc/pki`//`/etc/ssl` | slurp/hash | New root CA = Critical. Hosts-file entry for a real domain = Critical |
| L16 | Shares & exports | `/etc/exports`, Samba share defs | slurp | New share = High |
| L17 | Logging health | rsyslog/journald forwarding config present and service active; auditd running with expected ruleset hash | `systemctl is-active`, hash `/etc/audit/rules.d` | Forwarding dead or audit rules changed = High (attackers blind you first) |

### 4.2 Windows — role `snapshot_windows`

Collection uses `ansible.windows.win_powershell`, which returns structured objects directly — each task builds a fragment of the snapshot dict, no parsing of console text.

| # | Category | What is captured | Method (read-only) | Identity key / notes |
|---|---|---|---|---|
| W1 | Running processes | PID, PPID, name, image path, command line, owner, start time, SHA-256, Authenticode status/signer | `Get-CimInstance Win32_Process` (+`GetOwner()`), `Get-FileHash`, `Get-AuthenticodeSignature` | Identity = `(path, sha256, owner, normalized_cmdline)`. Unsigned binary in user-writable path (`%TEMP%`, `%APPDATA%`, `C:\Users\*`) = High policy finding |
| W2 | Fileless indicators | Processes with null `ExecutablePath`, image path mismatch vs. name, `rundll32`/`regsvr32`/`mshta`/encoded-PowerShell command lines | derived from W1 | Flag as High. Honest limit: true in-memory implants need EDR/Velociraptor memory scanning (§12) |
| W3 | Listening ports | proto, local addr/port, owning PID→process | `Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint` | Identity = `(proto, port, image_path)` |
| W4 | Active connections | Established TCP: remote IP/port, owning process | `Get-NetTCPConnection -State Established` | Same normalization as L4 |
| W5 | Scheduled tasks | Full task inventory: path, actions (exe+args), triggers, run-as principal, state, author; exported task-XML hash | `Get-ScheduledTask` + `Export-ScheduledTask`; also legacy `AT`/`schtasks` jobs | Identity = `(task_path, action_exe, action_args, principal)`. New/changed = High |
| W6 | Services | Name, display name, binary path+args, start type, log-on account, current state | `Get-CimInstance Win32_Service` | New service = High (classic lateral-movement artifact, event 7045 corroborates). Also flag unquoted service paths |
| W7 | Autoruns (registry & folders) | `Run`/`RunOnce` (HKLM + every loaded HKU hive, incl. Wow6432Node), Startup folders, Winlogon `Shell`/`Userinit`, IFEO debugger keys, `AppInit_DLLs`, LSA security/notification packages, print monitors, `netsh` helper DLLs | targeted registry reads (`Get-ItemProperty`), folder listings + hashes | Any addition = High; IFEO debugger or LSA package addition = Critical |
| W8 | WMI event subscriptions | `__EventFilter`, `__EventConsumer` (CommandLine/ActiveScript), `__FilterToConsumerBinding` in `root\subscription` | `Get-CimInstance -Namespace root\subscription` | Non-inventoried subscription = Critical (favored stealth persistence) |
| W9 | Local users & groups | Name, SID, enabled, password-last-set, last logon, description; members of `Administrators`, `Remote Desktop Users`, `Remote Management Users`, `Backup Operators` (resolving nested domain groups where possible) | `Get-LocalUser`, `Get-LocalGroupMember` | Creation date caveat: not a stored property. Derive from Security event **4720** (needs audit policy + retention), profile-folder CreationTime, and RID sequence (new users take the next RID; a *low* RID reappearing or RID-500 renamed/re-enabled is itself a finding). Domain accounts: **AD enrichment is in v1** — see W18 |
| W10 | Drivers | Loaded kernel drivers: name, path, signature status, version | `Get-CimInstance Win32_SystemDriver` + `Get-AuthenticodeSignature` | New or unsigned driver = Critical (BYOVD attacks) |
| W11 | Installed software & patches | Uninstall registry keys (both views): name, version, publisher, install date; hotfix list | registry read, `Get-HotFix` | New software outside change window = Medium |
| W12 | Host firewall | Enabled allow rules with program/port/direction/profile | `Get-NetFirewallRule` joined to port/app filters | Identity = `(direction, action, program, port, profile)`; new allow = High |
| W13 | DNS / hosts / proxy / trust | hosts-file hash + parsed entries, per-adapter DNS servers, WinHTTP + per-user proxy, thumbprint inventory of `Cert:\LocalMachine\Root` and `CA` | file read, `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, cert store enumeration | New trusted root cert = Critical (TLS interception). DNS server change = High |
| W14 | Audit & logging health | Effective audit policy, event-log service state, max log sizes, WEF subscription config; presence of recent event **1102** (audit log cleared) or **104** (system log cleared) | `auditpol /get /category:*`, `Get-WinEvent -FilterHashtable` | 1102/104 since last snapshot = Critical. Audit policy weakened = High |
| W15 | Shares | SMB shares + share ACLs | `Get-SmbShare`, `Get-SmbShareAccess` | New share or ACL-loosening = High |
| W16 | PowerShell surface | Execution policy, all profile files present + hashes, PSv2 engine enabled, ScriptBlockLogging/transcription state | registry + file checks | Profile appearing = High; logging disabled = High |
| W17 | Security posture keys (optional module) | WDigest `UseLogonCredential`, LSA `RunAsPPL`, RDP enabled + NLA, SMBv1 state, Defender state/exclusions | registry + `Get-MpPreference` | **Defender exclusions are a favorite attacker move** — any new exclusion = High |
| W18 | **AD enrichment (v1)** — runs once per domain, not per host | For every domain account seen in W9 admin groups: `whenCreated`, `whenChanged`, `pwdLastSet`, `lastLogonTimestamp`, `userAccountControl` flags, `adminCount`, SPNs, `servicePrincipalName` presence; **full nested expansion** of Domain Admins / Enterprise Admins / Schema Admins / Account Operators / Backup Operators / DnsAdmins and any group granting local admin; AD-integrated persistence surfaces: GPO list + version + gPCFileSysPath hashes, GPO-linked scheduled tasks/startup scripts, AdminSDHolder ACL, DCSync-capable principals (replication rights), Kerberoastable accounts, `krbtgt` password age, delegation settings (unconstrained/constrained/RBCD) | One play delegated to a DC or any domain-joined host, run **once per domain**: `Get-ADUser/-ADGroup/-ADObject` via RSAT, or LDAP via `community.general.ldap_search` if RSAT is absent | This is the real answer to "user creation date" — unlike local accounts, AD **does** store `whenCreated` authoritatively. Identity = `objectSid` (survives renames, which is exactly how a renamed account tries to hide). New Domain Admin, new DCSync right, `krbtgt` age reset, new unconstrained delegation, or GPO change = **Critical**. Run once per domain, not per host, or you will hammer the DC with N identical queries |

### 4.3 Network devices — role `snapshot_network`

Facts + `show` commands per platform via `network_cli`; config text is sanitized (volatile lines stripped, secrets redacted per §6) then hashed and stored.

**Any vendor may appear, so this role is built in three tiers rather than as per-vendor code.** Writing bespoke tasks for every vendor is not achievable; instead, capability degrades gracefully and *something useful is always collected*:

| Tier | Applies to | Mechanism | What you get |
|---|---|---|---|
| **T1 — Full support** | Vendors with mature collections (`cisco.ios`, `cisco.nxos`, `cisco.asa`, `arista.eos`, `junipernetworks.junos`, `fortinet.fortios`, `paloaltonetworks.panos`) — **this covers your most-encountered set: Cisco, Juniper, Arista, and their virtual variants** | Vendor modules + structured facts | Every row in the table below, parsed into structured fields |
| **T2 — Command-pack** | Any SSH-reachable device with a known CLI dialect not covered above (HPE/Aruba, Extreme, MikroTik, Ubiquiti, Huawei, Sophos, pfSense/OPNsense CLI, etc.) | `ansible.netcommon.cli_command` driving a **YAML command pack** per platform: a list of `show` commands mapped to categories, plus regexes for the handful of high-value parses | Full config text diff + as many structured categories as the pack defines. **Adding a vendor is data, not code** — write a new YAML pack, no role changes |
| **T3 — Generic fallback** | Unknown/unrecognized device that answers SSH | Try a small ladder of universal commands (`show running-config`, `show configuration`, `display current-configuration`, `get system status`, `/export`), keep whatever returns non-error output | Sanitized config text, hashed and diffed. **This alone catches most of what matters** — config changed, when, and exactly which lines |

Design notes for the tiering:

- **Config-text diff is the universal backstop.** Even at T3 with zero vendor knowledge, "the running config changed and here are the added lines" is the single highest-value network finding. Never let an unknown vendor produce an empty snapshot.
- **Detect, then degrade.** Role logic: try `ansible_network_os` if set → else fingerprint from SSH banner / `show version` output → else T3 ladder. Record the tier used in `meta.collection_tier` so the report can say *why* a device has thin coverage.
- **Unsupported device = coverage gap finding**, not silence (same principle as §5 rule 5). A device that couldn't be fingerprinted or wouldn't answer is reported as "assessed at T3 only" or "not assessed."
- Web/API-only appliances (some firewalls, cloud-managed switches) may need `uri`-based collection against their REST API instead of SSH; treat each as its own T2-equivalent pack.
- **Build order (decided):** Cisco (IOS/IOS-XE/NX-OS/ASA), Juniper, and Arista are all **T1 already** — so v1 needs no T2 packs for your common set, and T2 becomes a graceful-degradation path for the occasional oddity rather than upfront work. Write T2 packs reactively, as you meet vendors in the field, and keep them in the kit repo so the library compounds across engagements.

**Virtual network devices deserve explicit treatment (§4.4)** — vEOS, vSRX, CSR/Cat8000v, virtual FortiGate and friends run the same OS as their physical counterparts, so T1 collection works unchanged. But their *security boundary is not the same*, and that difference is easy to miss.

### 4.4 Virtual network devices — the hypervisor is part of the attack surface

A virtual firewall is only as trustworthy as the host it runs on. Collecting a perfect config snapshot from a vSRX tells you nothing about whether someone cloned it, snapshotted it, or quietly mirrored its traffic at the vSwitch. Where virtual network devices are in scope, add these checks — and note that they require **hypervisor access**, which is a separate scope and credential question worth raising with the client up front (Appendix D).

| # | Check | Why it matters |
|---|---|---|
| V1 | **VM snapshots / clones of network appliances** | A snapshot of a firewall VM is a complete offline copy of its config, keys, and rule base. An unexplained snapshot or clone of a security appliance is a **Critical** finding — it's exfiltration that never touches the network |
| V2 | **Promiscuous mode / MAC-address-changes / forged-transmits on port groups** (vSphere), or equivalent vSwitch settings | This is the **virtual equivalent of an un-inventoried SPAN session** (N8). Promiscuous mode on a port group lets any VM on it sniff its neighbours' traffic. Critical |
| V3 | Virtual switch / port group / VLAN config diff | The virtual network topology drifts exactly like physical config, and is usually far less monitored |
| V4 | Appliance VM resource + boot config: attached ISOs, added vNICs, changed boot order | A new vNIC bridging two port groups is a covert path between segments; an attached ISO is a delivery mechanism |
| V5 | Hypervisor host itself | It's a Linux-family host — run the §4.1 collection against ESXi/Proxmox/KVM hosts where in scope. Hypervisor-level compromise defeats every guest control beneath it |
| V6 | Hypervisor management plane accounts + logging | Same logic as N4/N6: new admin on vCenter, or logging disabled there, is as serious as it is on a core switch |
- The categories below are the **T1 target set**. T2 packs implement whichever subset is feasible per platform; T3 delivers N1 only.

| # | Category | What is captured | Example source (IOS shown; equivalents per vendor) | Why / severity |
|---|---|---|---|---|
| N1 | Running config | Sanitized full running config + hash | `show running-config` | The master diff artifact |
| N2 | Running vs. startup | Boolean + diff | `show archive config differences` or local compare | Unsaved config changes = someone changed something and didn't persist it — High, investigate who |
| N3 | Config change provenance | Last-change user/time, archive log | `show archive log config all`, syslog | Change with no matching change ticket = High |
| N4 | Local accounts & AAA | Local users + privilege, AAA method lists, TACACS/RADIUS server IPs & reachability | `show run \| sec username\|aaa` | New local admin or AAA pointed at a new server = Critical (auth bypass) |
| N5 | Management plane | Enabled services: telnet, HTTP(S) server, SSH version, VTY ACLs, SNMP communities/v3 users + trap targets | `show run \| include ...`, `show snmp` | Telnet or HTTP enabled = Critical policy. New RW community = Critical |
| N6 | Logging & time | Syslog destinations, logging levels, NTP servers + sync state | `show logging`, `show ntp associations` | Syslog target removed = High. Rogue NTP = High (breaks log correlation, enables cert games) |
| N7 | Interfaces & tunnels | Admin/oper status deltas, new subinterfaces/VLANs, **GRE/IPIP/VXLAN tunnel interfaces**, err-disabled ports | facts + `show interface status` | Unexpected tunnel = Critical (covert channel / traffic redirect) |
| N8 | Mirroring | SPAN/RSPAN/ERSPAN monitor sessions | `show monitor session all` | Un-inventoried SPAN = Critical — someone is sniffing |
| N9 | L2 state | MAC table count per VLAN (deltas), new MACs on infrastructure/trunk ports, STP root bridge identity, new trunks | `show mac address-table count`, `show spanning-tree root` | STP root change or new trunk = High (MitM setups) |
| N10 | L3 state | Route table summary counts, static routes (full diff), redistribution stanzas, routing-protocol neighbor list | `show ip route summary`, `show ip route static`, `show ip ospf/bgp neighbors` | New static route or unknown neighbor = High/Critical |
| N11 | Firewall rule base | Rule/object inventory hash + structured rule diff; NAT & port-forward rules; VPN peer list | ASA `show run access-list`/`show nat`; FortiOS `show firewall policy`; PAN-OS config API | New inbound NAT/port-forward = Critical. Any-any or disabled-rule-re-enabled = Critical. New VPN peer = Critical |
| N12 | Software integrity | OS version, image filename, image hash where supported | `verify /md5 flash:<image>`, JunOS `file checksum`, `show version` | Image hash mismatch vs. vendor-published = Critical (implant) |
| N13 | Neighbors | CDP/LLDP neighbor table | `show cdp neighbors detail` | Unknown device on an infrastructure port = High (rogue device) |
| N14 | Protection features | Port-security, DHCP snooping, DAI, storm-control state | `show run` sections | Protection silently disabled = High |

---

## 5. Snapshot Format & Storage

One canonical JSON document per host per run, assembled **on the control node** (`delegate_to: localhost` template task fed by registered results) so nothing snapshot-related is written to target disks.

```json
{
  "meta": {
    "schema_version": "1.0",
    "host": "web01.corp.example",
    "platform": "linux",
    "os": "RHEL 9.4",
    "collected_at": "2026-07-22T04:00:12Z",
    "collector_version": "driftwatch 0.1.0",
    "run_id": "2026-07-22T0400Z",
    "partial": false,
    "failed_categories": []
  },
  "processes":   [ { "path": "/usr/sbin/nginx", "sha256": "…", "user": "root", "args_norm": "nginx -g daemon off;", "pid": 812, "started": "…" } ],
  "listening":   [ { "proto": "tcp", "port": 443, "path": "/usr/sbin/nginx", "bind": "0.0.0.0" } ],
  "connections": [ { "path": "/usr/bin/curl", "remote_ip": "203.0.113.9", "remote_port": 443, "proto": "tcp", "count": 3 } ],
  "cron": [ ], "systemd_units": [ ], "users": [ ], "…": "one array per category in §4"
}
```

Storage rules:

1. Path: `snapshots/<host>/<UTC-ISO-timestamp>.json`; `latest.json` symlink per host.
2. Every run is a git commit in the engagement volume's local repo, with a manifest of per-file SHA-256 hashes. Where the engagement permits, push to **GitLab** (self-hosted in the kit, or your own instance) for off-kit durability. Sign commits with a kit-held key for tamper evidence.
3. **Accepted trade-off:** without WORM/object-lock storage, an attacker with control of the kit could rewrite snapshot history. The compensating controls are that the store is on *your* hardware rather than the client's (targets have no route to it), commits are hashed and signed, and GitLab push gives an off-kit copy. Good enough for assessment work; revisit if this ever becomes a standing monitor inside a client network.
4. Retention: within an engagement, keep every snapshot (engagements are days-to-weeks, volume is small). Post-engagement retention is an analyst decision at teardown (§15.4).
5. **A missing or partial snapshot is a finding, not a gap.** Unreachable host, auth failure, or a category that timed out gets reported (attackers break collection on purpose).

---

## 6. Normalization & Diff Engine

The make-or-break subsystem. `normalize.py` transforms raw snapshots into canonical form; `diff_engine.py` compares canonical forms and emits findings.

**Normalization rules (per category, versioned in code):**

| Rule | Detail |
|---|---|
| Stable ordering | Every array sorted by its identity key; canonical JSON (sorted keys) so text diffs are also meaningful |
| Volatile-field strip | PIDs, start times, session counters, interface counters, `Current configuration : N bytes` headers, cert self-signed regen lines, uptime lines — dropped before hashing/diffing (kept as attributes in the raw snapshot) |
| Connection aggregation | Collapse to `(process_path, remote_ip, remote_port, proto)` with a count; drop local ephemeral ports; optional roll-up of high-churn destinations to CIDR/ASN via allowlist entries (e.g., CDN ranges) |
| Config sanitization | Network configs: strip timestamps/counters; redact secrets (`snmp community`, `key`, `password 7`) to salted hashes so *changes* are still detectable without storing the secret |
| Args normalization | Collapse whitespace, strip one-time tokens (GUIDs, temp paths) via per-fleet regex list — reviewed like code |

**Comparison modes (all three run every cycle):**

1. **Temporal:** `latest` vs. `previous` per host → "what changed since yesterday."
2. **Baseline:** `latest` vs. that host's (or host-class's) approved **golden baseline** → "how far from known-good."
3. **Fleet outlier:** prevalence of each item across the host's group. Item on `< 5%` of a group of `≥ 20` peers ⇒ outlier finding ("only WIN-FS01 and WIN-FS02 run `C:\Users\Public\svch0st.exe`"). Also "new to fleet" — never seen on any host before. This directly answers *which machines have what differences* even when a host has no history.
4. **Policy checks (baseline-free):** absolute rules that fire on first contact — deleted-binary/memfd process, `ld.so.preload` present, new trusted root CA, telnet enabled on a device, un-inventoried SPAN session, audit log cleared, extra UID-0 account, unsigned kernel driver, Defender exclusion added, inbound NAT to an internal host, etc. Shipped as a versioned rule file.

**Finding schema:**

```json
{
  "finding_id": "f-2026-07-22-0173",
  "severity": "critical",
  "rule": "policy.windows.new_trusted_root_ca",
  "category": "trust_store",
  "change_type": "added",
  "hosts": ["WIN-FS01", "WIN-FS02"],
  "detail": { "before": null, "after": { "thumbprint": "…", "subject": "CN=Corp Proxy CA 2" } },
  "first_seen": "2026-07-22T04:00Z",
  "comparison": "temporal+fleet_outlier",
  "suppressed": false
}
```

**Suppression/allowlist** entries live in `allowlists/*.yml`, each with pattern, scope (hosts/groups), reason, approver, ticket reference, and an **expiry date** — no permanent silent exceptions. Changes go through review like code.

---

## 7. Reporting

Canonical output is the findings NDJSON; humans get Markdown/HTML rendered from it.

**Per-run report layout:**

1. **Run health:** hosts targeted / collected / partial / unreachable (unreachables listed as findings).
2. **Executive delta:** finding counts by severity vs. previous run; new-this-run at top.
3. **Findings by severity,** each with the full affected-host list, before/after detail, first-seen, and which comparison mode caught it.
4. **Fleet matrix:** findings × hosts grid — the direct answer to "what machines have what differences."
5. **Per-host appendix:** every drift item for a given machine in one place (for the responder assigned to that box).

Example excerpt:

```markdown
### CRITICAL — New trusted root certificate            rule: policy.windows.new_trusted_root_ca
Hosts (2/143 windows): WIN-FS01, WIN-FS02
  + Root CA "CN=Corp Proxy CA 2"  thumbprint 9F3A…  notBefore 2026-07-19
  First seen 2026-07-22T04:00Z · absent from golden baseline · fleet prevalence 1.4%
  Suggested action: confirm against PKI change tickets; if unknown, treat as TLS interception.
```

**Delivery:** written to the engagement's `reports/`; optional webhook for Critical/High. Findings ship to the **kit's own SIEM stack — Security Onion and Splunk** (both travel with the kit, so nothing depends on client infrastructure):

| Destination | Format | Why both |
|---|---|---|
| **Security Onion — PRIMARY index** | ECS-mapped JSON via Elastic ingest: **both findings and full snapshot JSON** | Bulk store and the system of record. Holds the heavy data (snapshot state across the fleet), and puts drift findings next to **Zeek and Suricata** telemetry so "new listening port on WEB03" or "connection to 203.0.113.9" can be checked against actually observed traffic in one interface. This closes a gap the earlier design listed as out of scope — see §12 |
| **Splunk — findings only** | NDJSON over HEC, one event per finding, `sourcetype=driftwatch:finding` | Analyst-facing alerting and reporting on a **deliberately small** data volume. Findings are a few hundred events per run — comfortably inside even a Splunk Free/dev license (500 MB/day), whereas indexing snapshot JSON here would blow through it immediately. Saved searches on Critical/High are the alert layer; the fleet matrix (§7 item 4) renders as a Splunk dashboard |

**Split rationale (decided):** Security Onion is the primary index precisely because snapshot JSON is bulky — indexing full fleet state is what turns "which hosts run this binary?" into a query instead of a re-collection, and Elastic absorbs that volume without licensing pressure. Splunk carries only the finding stream, where its alerting and dashboarding are worth having and the volume is trivial.

Two consequences to design for: (1) the **raw-state pivot lives in Security Onion**, so build the analyst's "pivot from finding to underlying state" path there — the Splunk finding event should carry the `run_id` + `host` keys needed to jump across; (2) SIEM data is engagement data — both indices follow the teardown retention decision in §15.4, and Security Onion holding the bulk snapshot state makes it the **most sensitive single artifact on the kit**. Encrypt the volume it lives on and wipe it deliberately, not incidentally.

---

## 8. Scheduling, Baseline Lifecycle & Operations

**Orchestration decision: systemd timers + a thin CLI wrapper for v1; no AWX/AAP.** Full reasoning in **Appendix C.1** — in short, the portable single-analyst model doesn't use what AWX is good at (multi-user RBAC, standing schedules, team approval workflow) and pays a real cost in kit weight and per-engagement rebuild time. Revisit if the tool ever becomes a standing internal monitor or gains a second concurrent operator.

**Cadence (proposed — engagement-scaled):**

| Job | Scope | Frequency | Notes |
|---|---|---|---|
| `snapshot.yml` (fast set) | processes, ports, connections, tasks/cron, users, services, autoruns | every 2–4 h during an engagement | Cheap. On a days-long engagement, tighter cadence buys you more temporal-diff data points, which you otherwise lack |
| `snapshot.yml --tags deep` | hashing, package inventory, cert stores, SUID scan | daily, off-hours | Hash work is the expensive part — run async with per-task timeouts |
| `snapshot_network.yml` | full §4.3 set | every 1–4 h | Configs are tiny; diff often |
| `diff_report.yml` | normalize + diff + report | after every collection run | Pure control-node work |

**Performance & failure handling:** tune `forks` (25–50), use `serial` batches for WinRM-heavy groups, `async`/`poll` for hashing, and hard per-category timeouts so one hung host can't stall the fleet. A category failure marks the snapshot `partial` with `failed_categories` populated — diffed anyway, gap reported.

**Baseline lifecycle (ties into change management):**

1. First snapshot of a host is auto-tagged *candidate baseline*; an analyst reviews and **promotes** it to golden via a reviewed commit (PR approval).
2. Expected drift (patch Tuesday, approved deploys) is absorbed by re-promoting a post-change snapshot referencing the change ticket — never by silently editing the baseline.
3. Allowlist entries expire (§6); an expiring-soon section appears in the weekly report.
4. Quarterly: prune stale baselines, review suppression list, re-verify severity mapping against recent incidents.

---

## 9. Securing the Framework Itself

This system aggregates admin credentials for every host and device — it is one of the most attractive targets on the network. Treat it like a tier-0 asset. The controls below describe the **permanent-deployment** model (a standing internal monitor). For the **portable per-engagement** model — where the kit is deployed onto networks you don't own, with credentials handed to you on arrival — see §15, which replaces the persistent-service-account and standing-control-node assumptions here with ephemeral, scoped, destroyable equivalents.

| Threat | Control |
|---|---|
| Control-node compromise ⇒ fleet compromise | Dedicated hardened VM, no inbound services, MFA + jump-host-only admin access, itself snapshotted by a second minimal instance (watch the watcher), full auditd + forwarded logs |
| Credential theft | Vault/secrets-manager only, unique least-privilege accounts per platform, sudo command-allowlists on Linux, gMSA/LAPS-style rotation on Windows, network-device read-only roles; alert on any use of `svc-driftwatch` outside collection windows or from any other source IP |
| Malicious playbook edit runs code fleet-wide as admin | Playbook repo requires signed commits + mandatory review; control node pulls only tagged releases; `ansible.cfg` pinned; collection roles contain **no write modules** by construction (CI lint rule rejects `win_shell` writes, `copy`, `file state!=absent`, etc.) |
| Snapshot/report tampering (attacker hides their diff) | Snapshots assembled off-target, git-versioned, pushed to a remote targets can't reach, hash manifest per run, optional WORM object storage |
| Sensitive-data exposure via snapshots | No password hashes or secret values collected (redacted-to-hash pattern §6); store encrypted; access limited to security team; retention limits enforced |
| Transport downgrade | WinRM HTTPS + Kerberos enforced (no NTLM fallback), strict SSH host-key checking with a maintained known_hosts, network-device SSH only |

Also decide consciously: the service account's own logons will appear in the very event logs and session lists being collected — the normalizer tags and folds these as `collector_self` rather than suppressing them entirely (so hijacking of the account remains visible).

---

## 10. Repository Layout

```
driftwatch/
├── ansible.cfg
├── requirements.yml                # collections, pinned versions
├── inventory/
│   ├── hosts.yml
│   └── group_vars/
│       ├── linux.yml  windows.yml  ios.yml  asa.yml  …
│       └── vault.yml               # encrypted
├── playbooks/
│   ├── snapshot.yml                # imports the three roles by group
│   ├── snapshot_network.yml
│   ├── diff_report.yml             # runs scripts/, publishes report
│   └── posture_checks.yml          # optional §4.2 W17-style checks
├── roles/
│   ├── snapshot_linux/   (tasks/, templates/snapshot.json.j2, defaults/)
│   ├── snapshot_windows/
│   ├── snapshot_network/ (tasks/main.yml + per-platform includes)
│   └── report/
├── scripts/
│   ├── normalize.py  diff_engine.py  report_gen.py  fleet_stats.py
├── rules/
│   ├── policy_checks.yml           # §6 mode-4 rules
│   └── severity_map.yml
├── allowlists/                     # reviewed, expiring suppressions
├── baselines/                      # promoted golden snapshots
├── snapshots/                      # or external store; git remote either way
├── reports/
└── tests/                          # molecule + pytest for diff engine
```

---

## 11. Phased Roadmap

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **1 — Core drift (2–3 wks)** | Linux+Windows fast-set collection (L1–L5, L8; W1, W3–W6, W9), canonical snapshots, temporal diff, Markdown report | Two scheduled runs/day across a pilot group; a planted change (new local admin, new scheduled task) is detected and reported within one cycle |
| **2 — Persistence & network (3–4 wks)** | Full §4.1/§4.2 including autoruns, WMI subs, hashing, trust stores; §4.3 for owned vendors; policy-check engine | Planted WMI subscription, hosts-file entry, and un-ticketed switch config change all detected; false-positive rate < ~20 findings/run after allowlisting |
| **3 — Fleet analytics & integration (2–3 wks)** | Fleet-outlier mode, fleet matrix report, SIEM NDJSON shipping, webhook alerts, baseline-promotion workflow | Outlier detection catches a binary present on <5% of a group; Critical findings raise SIEM alerts end-to-end |
| **4 — Hardening & maturity (ongoing)** | §9 controls verified, watcher-of-watcher instance, posture module, quarterly review cadence, purple-team validation of each policy rule | Red-team exercise: ≥ 80% of planted persistence mechanisms surfaced by the next scheduled run |
| **5 — Response layer (§13), separate repo (3–4 wks after Ph. 3)** | Tier-1 reversible plays only (disable account, isolate host, block hash), preserve→propose→approve→act→log flow, own credential set, network commit-confirmed pattern | Tabletop: a Critical finding drives an approved isolation of the named host(s) with evidence captured first and full audit trail; no path from collector creds to any write action |

---

## 12. Deliberate Non-Goals & Companion Tooling

Stating these avoids false confidence:

| Not covered here | Use instead / alongside |
|---|---|
| Real-time detection between snapshots | EDR, Sysmon→SIEM, auditd→SIEM |
| Deep memory forensics (injected code, in-memory-only implants beyond the §4 heuristics) | Velociraptor / EDR memory scanning; this playbook's L2/W2 flags are tripwires, not proof of absence |
| Network traffic analysis | **Now in-kit via Security Onion** (Zeek + Suricata). Not performed by these playbooks, but available alongside them for corroborating drift findings against observed traffic (§7) |
| File integrity at full-filesystem scale | AIDE/Wazuh/EDR FIM; this design hashes a curated critical set only |
| *Autonomous* remediation (tool decides and acts on its own) | Deliberately excluded, permanently. A response layer exists (§13) but is human-gated, evidence-first, and architecturally separate from collection so the collector keeps its read-only guarantee |

---

## 13. Remediation & Response

### 13.1 Why this changes the architecture

Everything up to here is read-only by design, and §9 leans on that: a compromised control node can leak snapshots but cannot damage the fleet. Remediation means handing a system that holds admin credentials for every host the ability to kill processes, disable accounts, delete files, and rewrite device configs. That is the single most dangerous capability you can build, for three reasons:

1. **A false positive becomes a self-inflicted outage.** Auto-quarantining on a bad detection can take down hundreds of production hosts faster than any attacker would.
2. **Your automation becomes the attacker's weapon.** If the response layer is reachable from the collector and an adversary lands on the control node, you've built them a fleet-wide destruction button.
3. **Acting destroys evidence.** Killing the process and deleting the persistence wipes the memory, the artifacts, and the attribution you need to understand scope — often before you know whether this host is the only one affected.

So the response layer is **not** a set of tasks bolted onto the collection roles. It is a separate system with its own principles.

### 13.2 Design principles for the response layer

| Principle | Implementation |
|---|---|
| **Separate from collection** | Own repository, own service accounts, own credential store, own approval workflow. The collector's accounts stay read-only and **cannot** call response plays. Compromising the collector must not yield write access |
| **Evidence before action** | Every response play's first step is a preservation step — trigger a full deep snapshot, capture volatile state (`netstat`, process tree, memory image where an EDR/Velociraptor is available), and copy suspect artifacts to the evidence store *before* anything is changed. No preservation, no action. **Evidence store = the analyst's laptop or kit-local storage**, inside the engagement volume, encrypted at rest. No formal legal chain of custody is maintained — but artifacts are still SHA-256 hashed on capture, because that costs nothing and you need it for your *own* integrity checks and for the report to be defensible technically |
| **Human approval gate** | No play runs autonomously. **The analyst running the tool holds full authority in the tool** — there is no multi-tier approval chain to model, because approval from the system owner happens *outside* the tool and the analyst is accountable for having obtained it. The gate is therefore about **mistakes, not authority**: the analyst must see the dry-run plan and explicitly confirm the exact action against the exact host list before anything executes. Each case records that the analyst confirmed and (free-text) who authorized it, so the report shows a defensible trail |
| **Reversible by default** | Prefer the containment action that buys time without destroying state: **disable** an account, don't delete it; **isolate** a host, don't wipe it; **block** a hash, don't purge the binary; **shut** a port, don't rewrite the config. Capture rollback state so every action can be undone |
| **Graduated tiers** | Match action destructiveness to detection confidence *and* reversibility (§13.3). High-confidence + reversible can be fast-tracked; destructive + low-confidence stays fully manual |
| **Blast-radius controls** | `--check` dry-run first (show me what this would do), `--limit` to the exact affected hosts, `serial: 1` or small batches with a canary host, and a hard kill switch. A play that would touch more hosts than the finding names must refuse and escalate |
| **Full, off-host audit** | Every proposed, approved, executed, and rolled-back action is logged to the append-only store and SIEM: who approved, which finding, before/after state, success/failure. The response layer audits itself the same way §9 audits the collector |

### 13.3 Graduated response tiers

Actions escalate in destructiveness; you rarely start at the bottom. The higher tiers are cheap to reverse and safe to move quickly on; the lower ones are where you slow down, preserve evidence, and require senior approval.

| Tier | Nature | Example actions | Reversible? | Gate |
|---|---|---|---|---|
| **0 — Enrich / notify** | No change to target | Deep snapshot, alert, open case, add context | n/a | Automatic (this is just §7) |
| **1 — Soft containment** | Reversible, buys time | Disable (not delete) account; network-isolate host to a quarantine VLAN/host-firewall rule; block file hash in EDR; revoke a session/token | Yes | Analyst confirms dry-run |
| **2 — Hard containment** | Reversible, disruptive | Kill malicious process; stop/disable a service; shut a switch port; drop a firewall rule feeding a C2 path | Mostly | Analyst + peer, or on-call lead |
| **3 — Eradication** | Destructive, evidence-sensitive | Remove persistence (scheduled task, WMI subscription, cron entry, autorun key); delete dropped artifact; remove rogue account | Partially — needs prior evidence capture | Senior/IR-lead approval; preservation step mandatory |
| **4 — Recovery** | Restore known-good | Restore config from golden baseline (device); **re-image** the host | n/a (rebuild) | IR-lead + owning team; change record |

Two judgment calls worth stating up front for whoever operates this:

- **Surgical eradication is often the wrong instinct.** Once a host is genuinely compromised you can seldom prove you removed *everything*. For anything past a trivial, well-understood artifact, re-imaging (Tier 4) is the more defensible eradication than hunting persistence by hand.
- **Contain fleet-wide, eradicate per-host.** Tier 1 blocking (a hash, a C2 IP at the firewall, an account) is safe to apply broadly and fast. Tiers 3–4 are per-host decisions made after you understand that host's scope.

### 13.4 Finding → candidate response mapping

Each detection maps to a preservation step plus tiered options. The play proposes; the human chooses.

| Finding (from §4/§6) | Preserve first | Containment (T1–T2) | Eradication / recovery (T3–T4) |
|---|---|---|---|
| Malicious/unknown process (L1/W1), memfd or deleted-binary process (L2/W2) | Memory capture, process tree, copy binary + hash | Kill process; block hash fleet-wide; isolate host | Remove the persistence that respawns it (see below); re-image if scope unclear |
| New persistence — cron/systemd (L5/L6), scheduled task/service/autorun/WMI sub (W5–W8) | Export the task/unit/key definition to evidence | Disable the mechanism (leave in place, disabled) | Delete it *after* export; hunt for the same mechanism across the fleet via the fleet-outlier data |
| New/rogue account or admin-group change (L8/W9) | Record account + group state, auth-log context | **Disable** account; force session revoke | Remove account after confirming it's not a renamed legitimate one |
| New authorized_keys / sudoers change (L9/L10) | Copy files to evidence | Revert file from baseline (small, reversible) | — |
| New trusted root CA (L15/W13) | Export cert + thumbprint | — | Remove cert from store (Tier 3 — verify against PKI change record first) |
| Host firewall opened / new listening port (L14/W12/L3/W3) | Snapshot ruleset + owning process | Re-apply baseline firewall; isolate host | Remove the service that opened the port |
| C2-style connection to new external destination (L4/W4) | Capture connection + process | Block IP/domain at the **network firewall** (fleet-wide, Tier 1) + kill local process | — |
| Defender exclusion added / logging disabled (W14/W16/L17) | Record current state | Re-enable logging/auditing; remove exclusion | — |
| Unsigned/new kernel driver or module (L11/W10) | Capture module + hash | Isolate host (do not hot-unload a suspect driver in place) | Re-image — driver/rootkit surface is not something to surgically clean |
| Network device: un-inventoried SPAN, rogue tunnel, new inbound NAT, telnet enabled, unknown static route (N5–N11) | Archive running config, capture the specific stanza | See §13.5 — never freehand a device config change under pressure | Restore config from golden baseline via commit-confirmed |

### 13.5 Network-device remediation is a special hazard

Config remediation on switches, routers, and firewalls carries a failure mode the host side doesn't: **a bad change can black-hole your own management plane and lock you out of the entire fleet at once.** Rules for this layer:

- **Never push a hand-built config change during an incident.** Remediation = restoring the sanitized golden config (or a specific reviewed stanza revert), not improvising.
- **Always use a rollback timer.** Commit with an auto-revert so that if you lose your session the device rolls back on its own: IOS `configure ... commit`/`reload in` pattern, JunOS `commit confirmed <minutes>`, PAN-OS/FortiOS equivalents. This alone prevents most self-lockouts.
- **Know whether you are in-band before you touch it.** The analyst declares `oob_subnets` in the engagement config; **every device not in one of those subnets is assumed in-band**, meaning the path you are managing it over may be the path your change severs. For in-band devices the tool must: (a) warn explicitly in the dry-run plan ("WARNING: core-sw-01 is reached in-band — this change may sever your own management path"), (b) make the rollback timer **mandatory, not optional**, and (c) refuse the change outright if the device is in-band *and* the play touches interface, ACL, routing, or management-plane config without a confirmed timer. For devices in a declared OOB subnet, the timer is still default-on but overridable.
- **Canary one device, then batch.** `serial: 1` on a non-critical device first; core switches and firewalls last.

### 13.6 Where this lives, and where it grows

For v1, keep it minimal and manual: a small set of **reviewed, parameterized response plays** in a separate repo, each taking a `finding_id` and an explicit host list, each doing preserve → propose (`--check`) → (human approves) → act → log. Start with only the reversible Tier 1 actions (disable account, isolate host, block hash) — these cover most of the value at a fraction of the risk.

**Decided: build the minimal plays in-house — no SOAR.** With no SOAR in the stack and a single analyst holding authority, adopting one would add a platform to carry, configure per engagement, and tear down, in exchange for approval/case features that a single operator with full authority doesn't need. Scope stays deliberately small:

- Tier-1 reversible plays only in v1: `disable_account`, `isolate_host`, `block_hash`, `revoke_session`.
- Each play is parameterized (`case_id`, explicit host list), does preserve → dry-run → confirm → act → log, and writes its result back to the case (§14).
- Case management is the `cases/` directory plus Splunk — not a platform. The findings are already in Splunk (§7), so case status is a search, not a product.
- **The guardrail against reimplementing a SOAR badly:** if the response side starts growing scheduling, multi-user queues, or its own web UI, stop and reassess rather than building those. The line to hold is that response stays a small set of audited, human-confirmed plays.

The detection framework and the response framework remain two systems that meet only at the case — which is the boundary that keeps the collector safe, and it is enforced by repo/code separation here rather than by credential separation (see §15.3, since you typically receive only one privileged account).

---

## 14. Unified Operator Model — One Console, Two Privilege Domains

The goal is a single tool the operator learns and a single output they read — *without* collapsing the detection/response separation from §13, which is the property keeping the whole thing safe. The resolution is a standard one: **unify the interface and the output; never unify the privilege.**

Think of it like a CLI that has read commands and write commands — one vocabulary to learn, but the write commands demand extra credentials and approval. Underneath the console, the read-only collector and the response layer remain distinct credential/privilege domains that only ever touch the same **case object**.

**The case is the unit of unification.** Both sides read and write one evolving record, and that record *is* the report:

```json
{
  "case_id": "c-0031", "engagement": "acme-2026-07",
  "finding": { "…": "the §6 finding — what/where/severity" },
  "evidence": [ "paths to preserved artifacts, memory capture refs" ],
  "proposed_action": { "tier": 1, "play": "isolate_host", "hosts": ["WIN-FS01"] },
  "approval": { "by": "analyst-b", "at": "…", "expires": "…" },
  "result": { "status": "executed", "before": "…", "after": "…", "rolled_back": false }
}
```

Detection writes the `finding`; response reads it and writes `proposed_action` → `approval` → `result` back onto the same case. The report renders finding **and** the action taken against it as one story, so the operator sees *detected → contained → outcome* in a single timeline rather than reconciling two tools.

**One operator console, two verb-sets:**

| Verb | Domain | Credentials used | Gate |
|---|---|---|---|
| `collect` / `report` / `diff` | Detection (read-only) | Read-only account set | None — safe by construction |
| `respond --propose <case_id>` | Response | *None yet* — dry-run/`--check` only, no target contact for writes | None (produces a plan) |
| `respond --approve <case_id>` | Response | Privileged account (typically the same one — §15.3) | Analyst confirms the dry-run plan explicitly; records who authorized it out-of-band |
| `teardown` | Kit management | — | Confirmation (§15.4) |

Implement the console as a thin wrapper (a small CLI or Makefile-style runner) over the existing playbooks, **or** as one AWX/Semaphore instance with two job templates bound to two separate credential objects and an approval step on the response template. Either way the enforcement is real, not cosmetic: the `collect` path physically cannot load the privileged credentials, and the `respond --approve` path is the only thing that can, and only after approval. The unification the operator feels is entirely at the UX and output layer.

---

## 15. Multi-Network Engagements: Scope, Credentials & Portability

The permanent-monitor assumptions (standing hardened node, persistent service accounts, months of accumulated baselines) don't hold when the same kit is carried onto different networks. This section defines the **portable per-engagement** model. It changes three things: everything is namespaced to an *engagement*, credentials are *ephemeral*, and *scope is enforced as a hard authorization boundary*.

### 15.1 The engagement is the top-level boundary

Every artifact lives under an engagement namespace, and **nothing crosses between engagements** — that's both client confidentiality and blast-radius control.

```
engagements/
└── acme-2026-07/                 # one self-contained, encrypted volume per engagement
    ├── scope.yml                 # analyst-supplied in-scope subnets + oob_subnets (§15.2)
    ├── inventory/                # generated FROM scope — cannot contain out-of-scope hosts
    ├── vault/                    # ephemeral, per-engagement creds (§15.3)
    ├── snapshots/  findings/  cases/  evidence/  reports/
    └── audit.log                 # append-only, incl. every out-of-scope attempt
```

- One encrypted volume per engagement; mounted only while that engagement is active. Engagement A's data, creds, and findings are never present on disk in cleartext while engagement B runs.
- At close-out: export the client's report + your evidence, then **teardown** (§15.4) wipes the volume and its keys. No residue carries to the next network.
- Baselines split in two: a **portable reference baseline** (generic known-good hashes, known-bad IOCs — no client data) that travels with the kit, versus **per-engagement collected state** that stays in the engagement volume. Because you arrive with little/no history, the diff engine leans hardest on the two lenses that need none: **fleet-outlier** ("on 2 of 200 hosts") and **baseline-free policy checks** (§6 mode 4), which fire on first contact. Temporal drift still works *within* a multi-day engagement (day 1 vs. day 3).

### 15.2 Scope enforcement — the authorization rail

This is the most important control in the portable model, and it is as much a legal boundary as a technical one: touching a host you aren't authorized for is unauthorized access regardless of good intent. So scope isn't a convenience filter — it derives from a **signed authorization document**, it **fails closed**, and it is enforced in **depth** so no single check is load-bearing.

**Three-way classification of every network you encounter:**

| Class | Meaning | Tool behavior |
|---|---|---|
| **In scope, reachable** | Authorized *and* you have a path + creds | Assess normally |
| **In scope, unreachable** | Authorized but no path (segmented, no route, no creds) | Record as a **coverage gap** in the report — "authorized but not assessed, needs jump host / path"; never silently omit |
| **Out of scope** | Not authorized — whether or not you can reach it | **Never connect.** If referenced, record as intel only (see discovery≠access) |

**Defense in depth — scope is checked at four layers, all fail-closed (default deny):**

1. **Inventory generation.** The inventory is *generated from* `scope.yml`'s allow-list; an out-of-scope address can't enter it, so it's never addressable in the first place.
2. **Pre-flight gate.** Before any play executes, a task validates every resolved target IP against the allow-list and explicit deny-list. Any target not affirmatively in-scope, or any ambiguity, **aborts the whole run** — it does not skip-and-continue.
3. **Control-node egress firewall.** The kit's own host firewall permits outbound connections only to in-scope ranges. Even a bug or a typo in a playbar can't put a packet on an out-of-scope host. Belt and suspenders behind layers 1–2.
4. **Credential scoping.** Where the environment supports it, the handed-over accounts are themselves restricted to their subnets/platforms, so a credential is useless off its intended range.

**Discovery ≠ access — the boundary you're actually worried about.** Assessing an in-scope network *will* surface references to other networks: routing tables, firewall rules, AD trusts, ARP caches, established connections to other ranges. That is valuable output and you should capture it — as a finding ("in-scope host references out-of-scope network 10.20.0.0/16"). But **discovering that a network exists is not authorization to touch it.** The tool records the reference and stops; it never auto-pivots to scan or connect. A discovered network becomes assessable only after the analyst explicitly adds it to `scope.yml` — a deliberate act, taken once they've confirmed it's in their given scope. The tool doesn't model *where* authorization comes from; it just refuses to expand its own reach on its own.

**Audit your own boundaries.** Every out-of-scope *attempt* — even one blocked at layer 2 or 3 — is logged to the engagement's append-only `audit.log`. That record is your evidence, contractually and legally, that you stayed within authorization. It protects the operator as much as it protects the client.

### 15.3 Ephemeral credentials — injected on arrival, destroyed on departure

Credentials are never baked into the repo or the kit image. They enter per-engagement, at runtime, and leave with the engagement.

- **Injection on arrival.** On engagement start, the creds you're handed are loaded into the engagement's ephemeral vault — an Ansible-Vault file with a per-engagement password held only by the operator, or a short-lived local secrets store (e.g., a Vault instance seeded at start), or `sops`/`age`-encrypted vars decrypted at runtime. Only the *active* engagement's vault is ever decrypted, so no client's creds are loaded while another's engagement runs.
- **Reality: one privileged account is the norm — so the read-only guarantee has to move.** Ask for a split (read-only for `collect`, privileged for `respond`) and take it when offered, but design for the common case of a single privileged credential. This is the most important consequence in the whole portable model, so state it plainly:

  With one shared privileged account, the collector's safety **degrades from "cannot write" to "does not write."** Credential separation is unavailable, so enforcement moves into the code and the process:

  | Compensating control | Implementation |
  |---|---|
  | Collection roles contain no write capability *by construction* | CI lint rejects any write-capable module in `snapshot_*` roles (`copy`, `template` to targets, `file` with non-absent state, `win_shell`/`shell` without a read-only allowlist, any `config` module in the network role). This is the load-bearing control now — treat the lint as a security control, not style |
  | Separate execution paths, still | `collect` and `respond` remain different repos/plays with different entry points; the credential is shared, the code paths are not. Prevents accidental invocation, not a determined attacker on the kit |
  | Read-only enforcement at the target where possible | Where the client *can* scope it (sudoers command-allowlist, network device RBAC role), take it even if it's only for some platforms — partial is better than none |
  | Audit everything the account does | Every command the collector issues is logged locally; anomalies between "what the playbook should have run" and the target's own logs are visible to the client's own monitoring |
  | Say so in the report | Note in the engagement report that collection ran under a privileged account, so the client understands the trust they extended and can rotate accordingly |
- **Least privilege, per platform.** Same as §3 — distinct accounts for Windows/Linux/network, each least-privilege, each usable only against in-scope targets (§15.2 layer 4 reinforces this).
- **Destroyable.** Credentials live only in the engagement volume; `teardown` shreds the vault and its key with the rest of the volume. Nothing to leak between clients, nothing to subpoena later beyond your retained report/evidence.
- **Rotation reminder for the client.** Because these creds were exposed to an external kit, the close-out report should recommend the client rotate any accounts issued to you after the engagement ends.

### 15.4 Portable kit & teardown

- **The kit is a reproducible hardened image** (laptop or VM) deployed fresh per engagement, so there's no accumulated residue and every engagement starts from a known-clean state. Rebuild from the image rather than reusing a long-lived machine.
- **In-network vs. bring-your-own placement.** Either stand the control node up *inside* the target network (better reachability into segmented subnets, but you're leaving compute in someone else's environment and must retrieve/wipe it) or bring your own hardened node and connect in over an agreed path (cleaner separation, but needs a route to each in-scope subnet — and unreachable-but-in-scope ranges become §15.2 coverage gaps). Choose per engagement; a jump host inside the network often bridges the two.
- **Teardown is parameterized per engagement — the analyst chooses retain vs. shred.** `teardown` takes an explicit retention profile because the right answer changes per client/contract:

  | Artifact | Options | Notes |
  |---|---|---|
  | Client report | Deliver + retain / deliver only | Almost always retained |
  | Findings + cases | Retain / shred | Retaining across engagements is what lets you build cross-client pattern knowledge — but only if the contract permits |
  | Snapshots | Retain / shred | Bulkiest and most sensitive (full topology + account inventory); shred by default unless there's a reason |
  | Evidence artifacts | Retain / shred | Analyst call; hashes kept in the report either way |
  | Credentials + vault | **Always shred** | Never optional, no retention profile can override |
  | SIEM indices (Splunk/Security Onion) | Retain / wipe | Easy to forget — engagement data lives here too |

  Flow: choose profile → export what's retained to the analyst's designated store → verify exports → shred everything else including the vault and keys → confirm no residue → log the teardown with the profile used. Default profile when unspecified: **shred everything except the report** (fail-safe toward less retained client data). Rebuild the kit from image before the next engagement.

---

## Appendix A — Severity Mapping (starting point, tune per environment)

| Severity | Examples |
|---|---|
| **Critical** | Extra UID-0 / new local-admin account; audit log cleared (1102); new trusted root CA; process from deleted binary or memfd; un-inventoried WMI subscription; unsigned/new kernel driver; IFEO or LSA-package addition; `ld.so.preload` present; telnet/HTTP mgmt enabled on device; un-inventoried SPAN session; new inbound NAT/port-forward; new VPN peer; device image hash mismatch; AAA server changed |
| **High** | New service, scheduled task, autorun, cron/systemd timer; sudoers or authorized_keys change; admin-group membership change; new host-firewall allow rule; new listening port on a server; Defender exclusion added; syslog/log-forwarding broken; DNS/proxy changed; new SMB share; new static route; unknown CDP/LLDP neighbor; unsaved device config; host unreachable at collection time |
| **Medium** | New installed package/software outside patch window; fleet-outlier binary (signed, known path); connection pattern to a new external ASN; interface/VLAN additions matching no ticket |
| **Low / Info** | Version drift within approved range; expected post-patch hash changes pending baseline re-promotion; collector self-artifacts |

## Appendix B — Decisions Log (reviewed 2026-07-22)

| # | Question | Decision | Design impact |
|---|---|---|---|
| 1 | Snapshot store | Kit-local / attached storage / **GitLab**; no object-lock tier | §5 rule 3 states the tamper-resistance trade-off accepted |
| 2 | Orchestration | **systemd timers + thin CLI wrapper**; no AWX/AAP in v1 | §8, full analysis in C.1 |
| 3 | Network vendors | **Assume any vendor** | §4.3 rebuilt as 3-tier (full / command-pack / generic fallback) |
| 4 | AD enrichment | **v1** | New W18 row; runs once per domain, not per host |
| 5 | Hash scope | **Tiered** (see C.2) | §4.1 L13 / §4.2 W1, analysis in C.2 |
| 6 | SIEM | **Owned, in-kit: Security Onion + Splunk** | §7 delivery rebuilt; §12 network-traffic gap now covered by Zeek/Suricata |
| 7 | SOAR | **None — build minimal Tier-1 plays in-house** | §13.6 scoped down, with a guardrail against reimplementing a SOAR |
| 8 | Approval authority | **Analyst has full authority**; system-owner approval obtained outside the tool | §13.2 gate reframed as mistake-prevention, not authority modelling |
| 9 | OOB access | Analyst declares `oob_subnets`; **everything else assumed in-band** | §13.5 — in-band devices get mandatory rollback timers + explicit warnings |
| 10 | Evidence store | **Analyst laptop / kit-local**, no legal chain of custody | §13.2 — hashes still taken for technical integrity |
| 11 | Kit placement | **Bring-your-own laptop + kit** | §15.4 — reachability into segmented subnets becomes the main constraint |
| 12 | Scope source | **Analyst supplies allowed subnets**; tool doesn't model authorization provenance | §15.2 simplified; fail-closed enforcement kept as typo protection |
| 13 | Account model | **Typically one privileged account** | §15.3 — read-only guarantee degrades to code-enforced; lint becomes a security control |
| 14 | Retention | **Analyst choice per engagement**, retain or shred | §15.4 teardown parameterized; credentials always shredded |
| 15 | Windows transport | **Kerberos/WinRM-HTTPS primary** (targets domain-joined, kit is not), **OpenSSH fallback**; NTLM last-resort exception only | New §3.1 transport ladder + pre-flight connectivity matrix |
| 16 | Segmented-subnet reachability | **Not a design concern** — unreachable in-scope hosts simply report as coverage gaps | §15.2 unchanged; no jump-host/second-node architecture needed |
| 17 | Vendor build order | Cisco, virtual devices, Juniper, Arista — **all T1 already**, so no upfront T2 work | §4.3 build-order note; T2 packs written reactively. Virtual devices get new §4.4 |
| 18 | SIEM split | **Security Onion primary** (findings + full snapshot JSON); **Splunk findings only** | §7 delivery table rewritten; keeps Splunk inside a small license footprint |

---

## Appendix C — Decision Records

### C.1 Orchestration: AWX/AAP vs. systemd timers + CLI wrapper

**Context that drives this:** a portable kit, rebuilt per engagement, run by a single analyst who holds full authority, on jobs lasting days to weeks. That context inverts the usual answer — AWX is generally the right call for a standing enterprise fleet, and generally the wrong call for a drop-in kit.

| Dimension | AWX / AAP | systemd timers + CLI wrapper |
|---|---|---|
| **Deploy weight** | Runs on Kubernetes/containers (AWX) or a full RPM stack (AAP). Meaningful CPU/RAM on the kit alongside Splunk + Security Onion, which are themselves heavy | A few unit files and a script. Negligible footprint next to the SIEM stack |
| **Per-engagement setup** | Re-import inventory, credentials, job templates, schedules each rebuild — or maintain a backup/restore dance to preserve them | `git clone` + drop in `scope.yml` + `ansible-vault` password. Minutes |
| **Scheduling** | Rich, GUI-managed, with per-template schedules | `OnCalendar=` in a unit file. Fully adequate for "every 2h" |
| **Multi-user RBAC** | Strong — teams, per-credential permissions, delegated access | None. **Irrelevant here:** one analyst, full authority |
| **Approval workflow** | Built-in workflow approval nodes | Must be built (a confirm prompt in the wrapper). **But the required gate is a dry-run confirmation, which is ~20 lines of script** |
| **Credential handling** | Encrypted credential store, injected at runtime, never displayed | Ansible Vault file in the engagement volume. Simpler, and it shreds cleanly at teardown — an advantage for the portable model |
| **Run history / audit** | Excellent: every job, stdout, who launched it, searchable | Journald + your own logs. **You have Splunk in the kit** — ship run logs there and you get better search than AWX gives, in the tool the analyst is already using |
| **Visibility for the operator** | Web UI, job status, dashboards | Terminal. Fine for one operator; the *findings* UI is Splunk regardless |
| **Failure recovery** | Retries, job slicing, workflow branching | Bash-level retry logic; Ansible's own `serial`/`async` do the heavy lifting anyway |
| **Ops burden** | A service to run, upgrade, secure, and troubleshoot — and if it breaks mid-engagement, collection stops | Almost nothing to break. Fewer moving parts on a kit you can't easily rebuild in a client's server room |
| **Attack surface on the kit** | A web app with admin credentials to the client fleet, listening on the kit | No listener. Strictly better for §9/§15 |

**Decision: systemd timers + a thin CLI wrapper.** Every AWX strength (RBAC, delegated approval, multi-team dashboards, standing schedules) addresses a problem the portable single-analyst model doesn't have, and every AWX cost (deploy weight, per-engagement re-setup, another network-listening service holding fleet credentials, an extra thing to break in the field) lands squarely on constraints this model does have. The one genuine loss is run-history UX, and Splunk in the kit more than covers it.

**Revisit if:** this becomes a standing internal monitor; a second analyst runs it concurrently; or you need delegated approval where the approver isn't the operator. At that point AAP's approval nodes become worth the weight — and consider **Semaphore** as the middle option (a single Go binary with a web UI and schedules, far lighter than AWX) if you want run-history UX without the Kubernetes tax.

### C.2 Hash scope: full running-process set daily vs. servers-only

**What's actually being decided:** which binaries get SHA-256 hashed (and on Windows, Authenticode-verified). Hashing is the single most expensive collection activity — it's disk I/O on the target plus round-trip time — and it's also what makes W1/L1 identities meaningful rather than name-based.

| | **Full set, every host, daily** | **Servers only** | **Tiered (recommended)** |
|---|---|---|---|
| **Detection value** | Highest. Catches masquerading (`svch0st.exe`), trojanized-but-correctly-named binaries, and gives exact IOC pivots everywhere | Misses workstations, **which is where initial access almost always lands** — phishing hits a user, not a database server. A blind spot exactly where attackers enter | ~90–95% of the value: everything on servers, plus the *interesting* binaries on workstations |
| **Cost** | Heavy. Hundreds of processes/host × hundreds of hosts; on Windows, WinRM round-trips dominate and `Get-FileHash` + `Get-AuthenticodeSignature` per process is slow | Light — small host count | Moderate and, importantly, **predictable**: the expensive tail is filtered out before hashing |
| **Fit for a days-long engagement** | Punishing: your **first** run is the expensive one and you only get a few runs total. Risk of the deep collection not finishing before you leave | Finishes fast, leaves most of the estate unassessed | First run is bounded; subsequent runs are near-free thanks to caching |
| **Noise** | High duplicate work — the same `svchost.exe` hashed on 400 hosts | Low | Low, and the cache makes fleet-wide identity comparisons cheap |

**Decision: tier the hashing by host role and by binary risk, with a fleet-wide hash cache.**

1. **Servers, DCs, and crown jewels: hash everything**, every deep run. Host count is low, value is high.
2. **Workstations: hash the interesting subset only** — any binary that is unsigned, signed-but-untrusted, running from a user-writable path (`%TEMP%`, `%APPDATA%`, `\Users\`, `/tmp`, `/dev/shm`, `/var/tmp`), has no publisher, is a deleted/memfd image (L2/W2), or isn't already in the known-good cache. **On a normal workstation this is a handful of binaries, not hundreds** — attackers' payloads are precisely the things that fail these filters, so the filter is aligned with the threat rather than being an arbitrary sample.
3. **Cache by `(path, size, mtime, [signer])` -> hash**, shared across the fleet within an engagement. `svchost.exe` gets hashed once, not 400 times; the cache also makes "which hosts run this exact binary?" a lookup instead of a re-collection.
4. **Trust the signature to skip work, but record it.** A valid Authenticode signature from a trusted publisher on a Microsoft-path binary is strong enough to skip hashing on workstations — *record the signer and the skip decision* so the report is honest about what was and wasn't hashed.
5. **Make it a knob, not a constant.** `hash_policy: {full | tiered | servers_only}` per engagement — if a client's environment is small or the engagement is long, run `full` and take the completeness.

**The honest caveat:** tiering means a trojanized *signed* binary in a *system* path on a *workstation* could be skipped. That's a real gap, accepted deliberately because the alternative frequently means the deep run doesn't complete at all during a short engagement. Note the policy used in the report so findings are read with the right confidence, and re-run `full` on any host that produces a Critical finding.

---

## Appendix D — Remaining Open Items

The v0.1 open items are all resolved (Appendix B). What surfaced from those answers:

1. **Hypervisor scope and credentials.** Virtual network devices (§4.4) mean the hypervisor is part of the attack surface, but hypervisor access is usually a *separate* credential and often a separate scope conversation. Worth asking for explicitly at engagement start: vCenter/ESXi/Proxmox read access, or accept that virtual appliance checks V1–V6 can't be performed and report them as coverage gaps.
2. **Windows OpenSSH availability.** The fallback only exists where the feature is already installed. Decide the standing policy: accept the coverage gap, or make "enable WinRM or OpenSSH via your own GPO" a standard client pre-requisite in the pre-engagement checklist. The latter converts a recurring surprise into a one-line ask.
3. **Kit pre-flight checklist.** Kerberos needs DNS pointed at the client DC, clock sync within 5 minutes, and a valid TGT. These should be scripted as a `preflight` verb that fails loudly with specific remediation text, not diagnosed by hand on each engagement.
4. **Security Onion sizing.** As the primary index holding full snapshot JSON, storage and retention sizing on the kit should be sanity-checked against your largest expected engagement (host count × categories × runs) before the first big job.
