# Command packs — adding a vendor as *data*, not code

A **command pack** is a single YAML file that teaches the Tier-2 handler
(`tasks/t2_commandpack.yml`) how to snapshot a device whose CLI dialect has no
mature Ansible collection. The role logic never changes: **you add a vendor by
adding a file here.** This is the design §4.3 promise — "adding a vendor is data,
not code" — and it keeps the pack library compounding across engagements.

Drop a `*.yml` file in this directory. The role discovers every pack at runtime
(via `fileglob`), fingerprints the device, and drives the matching pack. This
`README.md` is not a `.yml` file, so it is never loaded as a pack.

## When a pack is used

Tier is decided in `tasks/main.yml` (design §4.3 "detect, then degrade"):

1. `ansible_network_os` is set and maps to a native T1 handler (e.g. IOS) → **T1**.
2. Otherwise the device is fingerprinted from its `show version` banner. If a
   pack's `meta.fingerprint` matches (or `meta.os` equals `ansible_network_os`) →
   **T2**, driven by that pack.
3. Nothing matched → **T3** generic ladder (config text only).

## Pack schema

```yaml
meta:
  vendor: "Aruba"           # human label; goes into meta.os if `os` is absent
  os: "arubaoscx"           # optional; used for snapshot meta.os and as an
                            #   alternate selector (compared to ansible_network_os)
  fingerprint:              # list of regexes, OR-joined, case-insensitive,
    - "ArubaOS-CX"          #   searched against the `show version` banner
    - "Aruba.*Switch"

config:                     # REQUIRED — the universal config-text backstop
  commands:                 # ladder; first command with usable output wins and
    - "show running-config" #   becomes the sanitized device_config

categories:                 # OPTIONAL — as many §3.4 categories as you can parse
  <category_name>:
    kind: array | object    # default: array
    command: "show ..."     # command whose output this category is parsed from

    # --- array categories ---
    line_regex: '(?im)^...(\S+)...(\S+)'   # run with regex_findall over output
    fields: [field_a, field_b]             # capture groups zipped, IN ORDER
    static: {field_c: "constant"}          # merged into every produced item

    # --- object categories ---
    keys:                                  # each value = a regex whose MATCH TEXT
      some_key: '(?i)(?<=prefix )\S+'      #   is the value (use lookbehind so only
                                           #   the value is captured, not the prefix)
    static: {other_key: []}                # remaining object keys as constants
```

### Rules that keep a pack correct and safe

- **Field names are contract law.** `<category_name>`, and every name in `fields`,
  `static`, and object `keys`, must match `docs/CONTRACTS.md` §3.4 exactly — the
  diff engine keys off them. A typo silently disables detection for that item.
- **Group order == `fields` order.** `regex_findall` returns capture groups
  positionally; the Nth group is assigned to the Nth `fields` entry. Use exactly
  as many capture groups as you list fields (extra groups are ignored; missing
  ones become `""`).
- **Never capture a secret into a field.** Config sanitization already redacts
  secrets (SNMP communities, `password 7`, keys) to salted hashes in the stored
  `.conf`. For `local_accounts.secret_hash` and `snmp` community keys, leave the
  value empty in the pack rather than parsing the raw secret out of the config.
- **Object key regexes should match only the value.** `regex_search` returns the
  whole matched text as the value, so anchor with a lookbehind (`(?<=... )\S+`) to
  avoid storing the surrounding keywords.
- **Config is mandatory; categories are best-effort.** Even a pack with zero
  `categories` is worthwhile: it still yields the full config-text diff. Add
  structured categories for the handful of high-value parses, and grow the pack
  over time.
- **Read-only.** A pack may only contain `show`/read commands. The handler runs
  them through `ansible.netcommon.cli_command` (tagged `readonly`); there is no
  way for a pack to issue a write.

## Testing a new pack

```bash
# Lint stays clean regardless of packs (they are data, not tasks):
python scripts/lint_readonly.py check --roles-dir roles

# Dry-run collection against one device, then inspect the snapshot:
bin/driftwatch --engagement <id> collect --limit <device>
cat engagements/<id>/snapshots/<device>/<run_id>.json
```

See `example_aruba.yml` for a working starting point.
