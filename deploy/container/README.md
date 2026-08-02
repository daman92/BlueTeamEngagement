# driftwatch — optional container image

This directory builds a container image of the driftwatch **tooling**, for operators who
want the control-node dependency set to be byte-identical between the build host and the
kit. It is **entirely optional**. The supported default is the native install:

```sh
./install.sh          # native control node — needs no container runtime at all
```

Nothing in the collection pipeline requires a container, and design Appendix C.1 is the
reason: a kit that holds fleet-wide admin credentials should carry as few extra services
and as little deploy weight as it can. That argument rejected AWX, and it applies here too
— which is why this path is opt-in and why the image publishes nothing.

---

## The non-negotiable property: no client data in a layer

**The image contains code and dependencies. Nothing else, ever.**

No engagement volume, no `vault/`, no credentials, no snapshots, no findings, no reports.

This is not tidiness. A container layer **cannot be reliably shredded at teardown**
(design §15.4). Once client data is in a layer it persists in the local image store, in
every `podman save` tarball made from that image, in any registry the image was ever pushed
to, and in the build cache — none of which `driftwatch teardown` can reach. The teardown
guarantee ("credentials + vault: **always shred**, no retention profile can override") is
only true if those bytes were never baked in to begin with.

Three mechanisms enforce it:

1. **The `Containerfile` copies an allowlist.** Every path that enters the image is named
   explicitly, deliberately mirroring how `scope.yml` works — nothing enters unless it is
   named, and `engagements/` is named nowhere. `response/cases/` and `response/evidence/`
   are likewise excluded; only the response layer's *code* ships.
2. **The build *context* is filtered too.** The allowlist governs what reaches a layer; it
   says nothing about what the builder is handed. The context is the repo root, and that is
   where `engagements/` lives — so an unfiltered build copies the client's vault and
   snapshots into docker's root-owned storage under `/var/lib/docker` (or podman's temp
   context), which `driftwatch teardown` cannot reach any more than it can reach a layer.
   `deploy/container/Containerfile.containerignore` (and its byte-identical BuildKit
   sidecar `Containerfile.dockerignore`) denies everything and then re-admits exactly the
   `COPY` sources. `install.sh --mode container` passes it explicitly — it is not left to
   whether the runtime happens to find it.
3. **The container runs with a read-only root filesystem** (`--read-only`, set by the
   wrapper). The only writable paths at run time are the bind mounts and a `/tmp` tmpfs, so
   "client data cannot land in the image" is structural rather than a promise.

`engagements/` exists in the image only as an empty directory to bind-mount over. Keep the
host side of that mount on the **encrypted** engagement volume (design §15.1) — the
container inherits whatever protection the host path has, and adds none of its own.

## No published ports

There is **no `EXPOSE` line in the `Containerfile` and no `-p`/`--publish` in any wrapper
code path**, and there never should be. driftwatch has no web UI and no listener: the
operator interface is a terminal and the findings UI is Splunk. Appendix C.1 counted "a web
app with admin credentials to the client fleet, listening on the kit" as a cost of AWX and
declined to pay it. Adding a published port here would buy that cost back.

---

## Build

```sh
./install.sh --mode container --check    # report only: is a runtime present? (changes nothing)
./install.sh --mode container            # build driftwatch:0.1.0 and driftwatch:latest
```

Or directly, from the **repository root** (which is the build context). **Pass the context
filter** — without it the build hands `engagements/` to the builder (see *no client data in
a layer*, mechanism 2):

```sh
podman build --ignorefile deploy/container/Containerfile.containerignore \
  -f deploy/container/Containerfile \
  -t driftwatch:0.1.0 -t driftwatch:latest .

DOCKER_BUILDKIT=1 docker build \
  -f deploy/container/Containerfile \
  -t driftwatch:0.1.0 -t driftwatch:latest .
```

docker has no `--ignorefile`; **BuildKit** reads the sidecar
`deploy/container/Containerfile.dockerignore` automatically, and the legacy builder does
**not** — which is why `DOCKER_BUILDKIT=1` is not optional here and why `install.sh` sets
it for you.

**Building needs network** — the base image, the Debian packages, and PyPI/Galaxy. That is
expected and fine: you build on a connected host, not on the kit. See *Air-gapped
transfer* below.

### Runtime: rootless podman preferred, docker supported

`install.sh` and the wrapper both prefer **podman**, and prefer it **rootless**. A
root-owned container daemon on a machine holding fleet-wide admin credentials is a bad
trade — design §9 treats the control node as a tier-0 asset, and podman needs no daemon at
all. docker works and is detected as a fallback; if you use it, note that its daemon runs
as root and that it rewrites host firewall rules (see *Networking* below).

Pass `--runtime docker` (wrapper) to force one.

### Base image and pinning

Debian 12 (bookworm) — small, current, ships Python 3.11 in the base repos so the engine's
3.11+ floor (CONTRACTS §6) is met without third-party interpreter repositories, and it
packages both the krb5 client and its headers.

For a genuinely reproducible kit image (design §15.4), resolve the digest on the build host
and pin to it:

```sh
podman build --build-arg BASE_IMAGE=docker.io/library/debian:12-slim@sha256:<digest> \
  -f deploy/container/Containerfile -t driftwatch:0.1.0 .
```

Everything above the base is already pinned: `requirements.txt` pins the engine deps
exactly, `requirements.yml` pins every Galaxy collection exactly, and `bin/vendor-deps`
constrains ansible-core.

### Offline-ish builds

```sh
./install.sh --mode container --offline
```

This passes `DW_OFFLINE=1`, so `bin/bootstrap --offline` installs pip and Galaxy content
**only** from `vendor/wheels` + `vendor/collections` (build those first with
`bin/vendor-deps bundle` on a connected host), and disables the registry pull. The base
image layers and the `apt-get` step still need locally-cached content, so this is *not* an
air-gap story — it is a reproducibility story. The air-gap story is the next section.

> `bin/vendor-deps bundle` runs `pip download` for the platform it runs on. Some of the
> ansible-core dependency tree (`cryptography`, `cffi`) ships as **platform-specific
> wheels**, so build the bundle on a **Linux x86_64** host if you intend to feed it to this
> image. A bundle built on macOS or Windows installs fine natively there and then fails
> inside the build with "no matching distribution".

## Air-gapped transfer

Same shape as `bin/vendor-deps` for the native kit: build where there is network, carry the
result to site.

```sh
# on the connected build host
podman save -o driftwatch-0.1.0.tar driftwatch:0.1.0

# on the kit, air-gapped
podman load -i driftwatch-0.1.0.tar
```

`docker save` / `docker load` take the same flags. Hash the tarball and record the hash
alongside the kit's other build provenance.

> Because a `save` tarball contains every layer, this is the moment the "no client data in
> a layer" rule pays for itself: the tarball is a file you will copy onto removable media
> and carry across a client boundary.

---

## Run

Always through the wrapper — it establishes the mounts, drops capabilities, and publishes
nothing:

```sh
./deploy/container/driftwatch-container --dry-run status     # print the command, run nothing
./deploy/container/driftwatch-container status
DRIFTWATCH_ENGAGEMENT=acme-2026-07 ./deploy/container/driftwatch-container preflight
DRIFTWATCH_ENGAGEMENT=acme-2026-07 ./deploy/container/driftwatch-container collect --deep
```

Everything after the first non-wrapper argument is passed to `bin/driftwatch` verbatim, so
every verb in CONTRACTS §8 works unchanged.

### Mounts

| Host | Container | Mode | Why |
|---|---|---|---|
| `engagements/` (encrypted volume) | `/opt/driftwatch/engagements` | rw | The **only** client-data path. A mount, never a layer, so `teardown` shreds real files (§15.4). |
| `$XDG_STATE_HOME/driftwatch/home` | `/opt/driftwatch/.home` | rw | Container `HOME`: ssh `known_hosts` + Ansible caches. Without it, `--rm` throws away known_hosts on every run. |
| `/etc/krb5.conf` | `/etc/krb5.conf` | **ro** | Client realm + KDC (§3.1). The container has no business editing it. |
| `$KRB5CCNAME` (FILE cache) | `/tmp/krb5cc` | **rw** | The TGT. Read-**write** on purpose — see below. |
| `$ANSIBLE_VAULT_PASSWORD_FILE` | `/opt/driftwatch/.home/.vaultpass` | ro | Only if already set; the secret never goes on a command line. |

Override any of them: `--engagements DIR`, `--home DIR`, `--krb5-conf PATH`,
`--krb5cc PATH`, `--known-hosts PATH`. `--dry-run` prints the resulting command.

### Kerberos

Rung 1 of the transport ladder (Kerberos over WinRM-HTTPS) needs three things on arrival,
and each fails silently (design §3.1). Two of the three are **host** concerns that a
container cannot fix for you:

- **`/etc/krb5.conf`** — the client's realm and KDC. Mounted read-only. Written by you on
  arrival; it is gitignored precisely because it is per-engagement client configuration.
- **A TGT.** `kinit user@REALM` on the **host**, into a **file** cache, then run the
  wrapper. Only `FILE:` caches can be bind-mounted — `KEYRING:`, `KCM:` and `DIR:` caches
  live outside any filesystem namespace the container can see, and the wrapper says so
  rather than letting every Windows host silently report as unreachable:

  ```sh
  kinit -c FILE:/tmp/krb5cc analyst@CLIENT.EXAMPLE
  KRB5CCNAME=FILE:/tmp/krb5cc ./deploy/container/driftwatch-container preflight
  ```

  The cache is mounted **read-write**, not read-only. GSSAPI writes each service ticket it
  obtains back into the cache; a read-only ccache turns that into an authentication failure
  rather than a cache miss.

- **The clock, within ±5 minutes of the DC.** This is a **host** concern and `chrony` is
  deliberately **not** installed in the image — a container shares the host's clock and
  cannot correct it. Run chrony on the host, synced against the client's NTP source or DC:

  ```sh
  sudo systemctl enable --now chronyd
  chronyc sources          # then verify: timedatectl status
  ```

  Time skew and DNS account for most "Kerberos doesn't work" incidents. `driftwatch
  preflight` checks all three and fails loudly with remediation text — run it first.

**DNS** must point at the client's DC for SPN and host records to resolve; Kerberos fails on
IP-only targets, so always use FQDNs. With `--network host` the container uses the host's
resolver configuration, which is where you already pointed it.

### known_hosts

design §9 requires strict host-key checking against a **maintained** `known_hosts`, and
`ansible.cfg` enforces it (`host_key_checking = True`,
`StrictHostKeyChecking=yes`). **A fresh container starts with an empty known_hosts**, so
every host and device is a first contact.

That is why `--home` is a persistent bind mount: `known_hosts` lives at
`<home>/.ssh/known_hosts` on the host and survives `--rm`. Verify fingerprints
deliberately on first contact — do not accept them reflexively to make the run proceed. To
reuse a `known_hosts` you already curate, mount it explicitly:

```sh
./deploy/container/driftwatch-container --known-hosts ~/.ssh/known_hosts collect
```

### Networking — and what it does to the scope control

The wrapper defaults to **`--network host`**, for two reasons.

1. **It is what reaches the fleet.** Segmented in-scope subnets and network-device SSH from
   a NAT'd container bridge produce "unreachable" coverage gaps that are really just
   plumbing — and design §15.2 requires that authorized-but-unreachable hosts be *reported*
   as gaps, so plumbing artifacts pollute the coverage record.

2. **It is the mode in which layer 3 of the scope control still behaves as written.**
   design §15.2 enforces scope at four fail-closed layers; layer 3 is the control node's
   **own egress firewall**, permitting outbound connections only to in-scope ranges. Host
   egress rules are conventionally written on the `OUTPUT` path. With `--network host` the
   container shares the host network namespace, so its traffic hits `OUTPUT` exactly as any
   host process does and the rule set keeps applying.

   With **bridge/NAT networking** (rootful podman, and docker's default) the container's
   packets are NAT'd and traverse `FORWARD` instead — so `OUTPUT`-based egress rules do
   **not** apply, and docker additionally manages its own iptables chains. **Layer 3 is
   then not enforced as you wrote it.**

**Whichever mode you use, re-verify layer 3 in that mode before collecting.** Layers 1
(inventory generated from scope) and 2 (the pre-flight gate) are inside the tool and keep
failing closed regardless — but the whole point of §15.2 is that no single layer is
load-bearing, so a silently-bypassed layer 3 matters.

The wrapper prints which mode is in effect and what it implies on every run. Use
`--network none` for control-node-only work (`diff`, `report`, `status`, `teardown`) — it
removes the question entirely.

### Hardening applied by the wrapper

| Flag | Why |
|---|---|
| `--cap-drop=ALL` | The container makes outbound connections and reads/writes bind mounts. It needs no capabilities for either. |
| `--security-opt no-new-privileges` | Nothing inside should ever gain privilege; there is no setuid path in the workflow. |
| `--read-only` + `--tmpfs /tmp` | Makes "no client data in a layer" structural. `exec` is kept on `/tmp` because Ansible stages and runs its own module payloads from a temp dir. |
| `--user $(id -u):$(id -g)` (+ `--userns=keep-id` on rootless podman) | Files written into the engagement volume stay owned by the operator. Without `keep-id`, rootless podman maps the container user into a subuid range and every write to the bind mount fails with `EACCES`. |
| `--rm` | No stopped containers accumulate holding a writable layer over client data. |
| no `-p` / no `EXPOSE` | See *No published ports* above. |

On SELinux-enforcing hosts, add `--selinux` to relabel (`:z`) the two mounts the wrapper
owns end to end: the engagement volume and `--home`. It never relabels `/etc/krb5.conf`
(a host system file), `--known-hosts`, or the vault password file — relabelling writes to
the *host's* filesystem labels, and those three belong to the host and to you.

The wrapper also refuses to run an image that is not present locally. `driftwatch:latest`
is an unqualified name published nowhere, so a missing image would otherwise make podman
run short-name resolution (or docker resolve `docker.io/library/driftwatch`) and pull a
stranger's image onto the machine holding the client's admin credentials. Build it, or
`podman load` it, or point `--image` at one you have.

---

## What the container does **not** change

- **Scope still fails closed.** The inventory is still generated from `scope.yml`, and the
  pre-flight gate still aborts the entire run on any target it cannot prove is in scope
  (design §15.2 layers 1–2). Running in a container changes neither.
- **Collection is still read-only.** `scripts/lint_readonly.py` is the load-bearing control
  behind that guarantee (design §15.3) and runs in CI on the same code the image builds.
- **Teardown still applies to the host.** `driftwatch teardown` shreds the bind-mounted
  engagement volume. After that, drop the image too if the engagement is closing out:

  ```sh
  DRIFTWATCH_ENGAGEMENT=acme-2026-07 ./deploy/container/driftwatch-container teardown
  podman rmi driftwatch:0.1.0 driftwatch:latest    # optional; the image holds no client data
  ```

  Then rebuild the kit from image before the next network (design §15.4).
- **systemd timers still run the native install.** The units in `systemd/` call
  `/opt/driftwatch/bin/driftwatch` directly. If you want timers to drive the container,
  point `ExecStart=` at `deploy/container/driftwatch-container` — and re-read the
  networking section first, because an unattended run cannot answer a host-key prompt.
