# driftwatch systemd timers

These units run scheduled collections on the kit control node. Each timer fires a oneshot
service that calls **`driftwatch collect`** — which scope-gates, snapshots, then diffs and
renders the report — so a scheduled run needs no second unit to produce output.

| Unit | Runs | Default cadence |
|---|---|---|
| `driftwatch-fast`    | `driftwatch collect`                 | every 2h |
| `driftwatch-deep`    | `driftwatch collect --deep`          | daily, 03:00 |
| `driftwatch-network` | `driftwatch collect --limit network` | every 2h, offset +1h |

This is the whole orchestration story for v1: a few unit files and a script, no AWX/AAP
(the reasoning is in design Appendix C.1). Run history lives in journald and — once you ship
it — Splunk.

## 1. Install the kit

Convention below is `/opt/driftwatch`; adjust the `ReadWritePaths=`, `WorkingDirectory=`, and
`ExecStart=` paths in the units if you install elsewhere.

```sh
sudo useradd --system --home /opt/driftwatch --shell /usr/sbin/nologin driftwatch
sudo git clone <this-repo> /opt/driftwatch
sudo chown -R driftwatch:driftwatch /opt/driftwatch
sudo -u driftwatch ansible-galaxy collection install -r /opt/driftwatch/requirements.yml -p /opt/driftwatch/collections
```

The transports also need OS packages that belong in the kit **image**, not this repo:
`krb5-user`/`krb5-workstation` (kinit/klist for Kerberos-over-WinRM) and `chrony` (the
preflight clock-skew gate) — design §3.1. On an air-gapped kit, replace the
`ansible-galaxy` step above with the bundled flow: run `bin/vendor-deps` on an
internet-connected build host (fills `vendor/wheels` + `vendor/collections`), bake the
result into the image, then `bin/bootstrap --offline` installs Ansible and the
collections from that bundle with no network access.

## 2. Select the active engagement

The units read `/etc/driftwatch/engagement.env`. This is the single switch that points the
timers at one client's volume — and its absence (`ConditionPathExists=`) keeps the timers
idle between engagements.

```sh
sudo install -d -m 0750 /etc/driftwatch
sudo tee /etc/driftwatch/engagement.env >/dev/null <<'EOF'
DRIFTWATCH_ENGAGEMENT=acme-2026-07
DRIFTWATCH_OPERATOR=analyst-b
ANSIBLE_CONFIG=/opt/driftwatch/ansible.cfg
# Kerberos ticket cache the unattended run will use (see §4).
KRB5CCNAME=FILE:/run/driftwatch/krb5cc
EOF
sudo chmod 0640 /etc/driftwatch/engagement.env
```

Create the engagement and verify transports interactively **before** enabling timers:

```sh
sudo -u driftwatch DRIFTWATCH_ENGAGEMENT=acme-2026-07 /opt/driftwatch/bin/driftwatch new-engagement acme-2026-07
# edit engagements/acme-2026-07/scope.yml, load the vault, then:
sudo -u driftwatch python3 /opt/driftwatch/scripts/scope_gate.py generate --engagement-dir /opt/driftwatch/engagements/acme-2026-07
sudo -u driftwatch DRIFTWATCH_ENGAGEMENT=acme-2026-07 /opt/driftwatch/bin/driftwatch preflight
```

## 3. Enable the timers

```sh
sudo cp /opt/driftwatch/systemd/driftwatch-*.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now driftwatch-fast.timer driftwatch-deep.timer driftwatch-network.timer
systemctl list-timers 'driftwatch-*'
journalctl -u driftwatch-fast.service -f
```

## 4. Kerberos for unattended runs

Interactive `kinit` is fine for hands-on collection, but a timer has no operator to type a
password. Give the `driftwatch` user its own ticket cache, refreshed from a **keytab** the
client issues, and point `KRB5CCNAME` (in `engagement.env`) at it:

```sh
sudo install -d -m 0700 -o driftwatch -g driftwatch /run/driftwatch
# refresh the TGT a few times a day (kinit from keytab):
sudo tee /etc/systemd/system/driftwatch-kinit.service >/dev/null <<'EOF'
[Service]
Type=oneshot
User=driftwatch
EnvironmentFile=/etc/driftwatch/engagement.env
ExecStart=/usr/bin/kinit -k -t /etc/driftwatch/driftwatch.keytab -c ${KRB5CCNAME} DRIFTWATCH$@REALM
EOF
```

Pair it with a `driftwatch-kinit.timer` (`OnCalendar=*-*-* 00/6:00:00`). If the client cannot
issue a keytab, either run collection interactively or accept OpenSSH/NTLM transports per the
preflight matrix. `driftwatch preflight` fails loudly when the TGT is missing.

## 5. Adjust cadence

Do not edit the shipped units — use a drop-in so upgrades don't clobber your change:

```sh
sudo systemctl edit driftwatch-fast.timer
# [Timer]
# OnCalendar=
# OnCalendar=*-*-* 00/4:00:00
sudo systemctl daemon-reload
```

Keep the cadence roughly aligned with `scope.yml` `settings.fast_interval` / `deep_interval`
(those values are informational; systemd is the authority for what actually runs).

## 6. Between engagements

```sh
sudo systemctl disable --now driftwatch-fast.timer driftwatch-deep.timer driftwatch-network.timer
sudo -u driftwatch DRIFTWATCH_ENGAGEMENT=acme-2026-07 /opt/driftwatch/bin/driftwatch teardown --retain report,findings
sudo rm -f /etc/driftwatch/engagement.env /run/driftwatch/krb5cc
```

Then rebuild the kit from image before the next network (design §15.4). The timers stay
inert until a new `engagement.env` exists.
