#!/usr/bin/env bash
#
# install.sh — one-command setup for the driftwatch control node.
#
# design Appendix D.3 says the kit's checks belong in a script that "fails loudly with
# specific remediation text, not diagnosed by hand" on each engagement. That applies to
# STANDING THE KIT UP at least as much as it applies to pre-flighting a fleet: an analyst
# unpacking the kit in a client's server room should get one command, and on failure the
# exact distro-specific line that fixes it — not a pip stack trace.
#
#   ./install.sh                      set up the control node on THIS host (default)
#   ./install.sh --check              prerequisites only; changes NOTHING; exit 0 ok / 1 not
#   ./install.sh --offline            install only from the vendored bundle; no network
#   ./install.sh --mode container     build the OPTIONAL container image (deploy/container/)
#
# This script COMPOSES the tools that already exist rather than duplicating them:
# bin/bootstrap owns the venv/pip/galaxy work, bin/vendor-deps owns the offline bundle.
# install.sh's job is the part neither of them does — telling the operator what is missing
# from THIS HOST, in that host's own package-manager vocabulary, before anything runs.
#
# The container path is strictly opt-in and the default install must never require a
# container runtime. design Appendix C.1 rejected AWX because a kit holding fleet-wide
# admin credentials should carry as few extra services and as little deploy weight as it
# can get away with; that reasoning does not stop at the orchestrator.
set -euo pipefail

# --------------------------------------------------------------------------- locations
SELF="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)/$(basename "$0")"
REPO_ROOT="$(dirname "$SELF")"
CONTAINER_DIR="$REPO_ROOT/deploy/container"

PROG="install.sh"

# Image tag tracks CONTRACTS §1.3 `collector_version` ("driftwatch 0.1.0") so an image in
# the field can be traced back to the collector version that stamped its snapshots.
IMAGE_NAME="driftwatch"
IMAGE_VERSION="0.1.0"

# --------------------------------------------------------------------------- output
# Same vocabulary as bin/driftwatch: colour only on a tty, everything on stderr so stdout
# stays clean for anything that wants to consume it.
_tty()   { [ -t 2 ]; }
_col()   { if _tty; then printf '\033[%sm' "$1" >&2; fi; }
info()   { _col '0;36'; printf '[%s] ' "$PROG" >&2; _col '0'; printf '%s\n' "$*" >&2; }
ok()     { _col '0;32'; printf '[%s] OK: ' "$PROG" >&2; _col '0'; printf '%s\n' "$*" >&2; }
warn()   { _col '0;33'; printf '[%s] WARN: ' "$PROG" >&2; _col '0'; printf '%s\n' "$*" >&2; }
err()    { _col '0;31'; printf '[%s] ERROR: ' "$PROG" >&2; _col '0'; printf '%s\n' "$*" >&2; }
die()    { err "$*"; exit 1; }
# A copy-pasteable remediation command, and a plain indented note. Every blocker below is
# expected to be followed by at least one remedy() — that is the whole point of the script.
remedy() { _col '0;32'; printf '        $ ' >&2; _col '0'; printf '%s\n' "$*" >&2; }
note()   { printf '          %s\n' "$*" >&2; }

# Findings accumulate rather than aborting at the first problem: an operator on a client
# site wants the whole list in one pass, not one missing package per re-run.
BLOCKERS=0
ADVISORIES=0
blocker()  { err  "$*"; BLOCKERS=$((BLOCKERS + 1)); }
advisory() { warn "$*"; ADVISORIES=$((ADVISORIES + 1)); }

# --------------------------------------------------------------------------- options
MODE="native"
OFFLINE=false
CHECK_ONLY=false
ASSUME_YES=false

usage() {
  cat >&2 <<EOF
$PROG — one-command setup for the driftwatch control node

usage: ./install.sh [--mode native|container] [--offline] [--check] [--yes] [--help]

  --mode native      (DEFAULT) set up the control node directly on this host: verify
                     prerequisites, restore exec bits, then hand the venv/pip/collections
                     work to bin/bootstrap and self-test the result.
  --mode container   build the OPTIONAL container image from deploy/container/ instead.
                     Strictly opt-in — the default path needs no container runtime.
  --offline          install ONLY from the pre-built bundle (vendor/wheels +
                     vendor/collections); never touches the network. Build the bundle on a
                     connected host first with: bin/vendor-deps bundle
  --check            prerequisite check only. Prints what it WOULD do and whether the host
                     is ready, changes nothing on disk, exits 0 if installable / 1 if not.
  --yes              non-interactive: assume yes to prompts (including the OS-package
                     install offered for the Kerberos transport).
  --help             this text.

examples:
  ./install.sh --check                      # is this host ready? (safe, read-only)
  ./install.sh                              # normal online install
  ./install.sh --offline --yes              # air-gapped kit, unattended
  ./install.sh --mode container --check     # is a container runtime available?
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode)     MODE="${2:-}"; [ -n "$MODE" ] || die "--mode needs a value (native|container)"; shift 2 ;;
      --mode=*)   MODE="${1#*=}"; shift ;;
      --offline)  OFFLINE=true; shift ;;
      --check)    CHECK_ONLY=true; shift ;;
      --yes|-y)   ASSUME_YES=true; shift ;;
      -h|--help)  usage; exit 0 ;;
      *)          err "unknown option: $1"; usage; exit 1 ;;
    esac
  done
  case "$MODE" in
    native|container) ;;
    *) die "--mode must be 'native' or 'container' (got '$MODE')" ;;
  esac
}

# Prompt gate. Anything that changes the HOST (as opposed to the repo checkout) goes
# through here: OS packages are the client's machine's business, not this script's.
confirm() {
  local prompt="$1" answer=""
  [ "$ASSUME_YES" = true ] && return 0
  if [ ! -t 0 ]; then
    warn "no terminal on stdin and --yes not given — assuming NO for: $prompt"
    return 1
  fi
  printf '[%s] %s [y/N] ' "$PROG" "$prompt" >&2
  read -r answer || true
  case "$answer" in
    [Yy]|[Yy][Ee][Ss]) return 0 ;;
    *) return 1 ;;
  esac
}

# --------------------------------------------------------------------------- host detection
OS_KIND="unknown"        # linux | wsl | darwin | windows | unknown
DISTRO_ID=""
DISTRO_NAME=""
PKG_MGR="none"           # apt | dnf | yum | zypper | pacman | apk | brew | none
PKG_INSTALL=""           # copy-pasteable install prefix, sudo included where needed
PY_PKGS=""
VENV_PKG=""              # only where the stdlib venv module is a SEPARATE package (Debian)
KRB5_PKG=""
KRB5_DEV_PKGS=""         # headers+toolchain pywinrm[kerberos] needs to build its GSSAPI binding
CHRONY_PKG=""
SUDO=""

# Read one field out of /etc/os-release WITHOUT sourcing it — os-release is shell syntax by
# convention, but it is a file we did not write and this script runs before anything else.
os_release_field() {
  [ -r /etc/os-release ] || return 0
  sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n1 | sed 's/^"//; s/"$//'
}

detect_host() {
  local uname_s
  uname_s="$(uname -s 2>/dev/null || echo unknown)"
  case "$uname_s" in
    Linux)
      OS_KIND="linux"
      # WSL reports Linux. It is a fine place to develop and lab-test, but it is not a kit:
      # no systemd timers, and its network stack is not the one the egress-firewall scope
      # control (design §15.2 layer 3) is written against.
      if [ -r /proc/version ] && grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
        OS_KIND="wsl"
      fi
      ;;
    Darwin)               OS_KIND="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) OS_KIND="windows" ;;
    *)                    OS_KIND="unknown" ;;
  esac

  DISTRO_ID="$(os_release_field ID || true)"
  DISTRO_NAME="$(os_release_field PRETTY_NAME || true)"
  [ -n "$DISTRO_NAME" ] || DISTRO_NAME="$uname_s"

  if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo "
  else
    SUDO=""   # no sudo on this box: print the bare command and let the operator escalate
  fi

  # Detect by which binary is actually present rather than by ID, so derivatives (Mint,
  # Rocky, Alma, EndeavourOS, ...) resolve correctly without a lookup table per fork.
  if   command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
  elif command -v dnf     >/dev/null 2>&1; then PKG_MGR="dnf"
  elif command -v yum     >/dev/null 2>&1; then PKG_MGR="yum"
  elif command -v zypper  >/dev/null 2>&1; then PKG_MGR="zypper"
  elif command -v pacman  >/dev/null 2>&1; then PKG_MGR="pacman"
  elif command -v apk     >/dev/null 2>&1; then PKG_MGR="apk"
  elif command -v brew    >/dev/null 2>&1; then PKG_MGR="brew"
  else                                          PKG_MGR="none"
  fi

  # Package names differ per family and getting them wrong is exactly the "generic
  # 'install python'" advice this script exists to avoid.
  #
  # KRB5_DEV_PKGS is separate from KRB5_PKG on purpose: krb5-user/krb5-workstation gives
  # the kinit/klist BINARIES that preflight needs, while pywinrm[kerberos] additionally
  # compiles a GSSAPI binding and therefore needs the krb5 HEADERS and a compiler. Those
  # are only ever offered as remediation after that build actually fails — dragging a
  # toolchain onto a client's machine on the off-chance is not this script's call.
  case "$PKG_MGR" in
    apt)    PKG_INSTALL="${SUDO}apt-get install -y"
            PY_PKGS="python3 python3-venv python3-pip"
            VENV_PKG="python3-venv"      # Debian/Ubuntu split venv+ensurepip out of python3
            KRB5_PKG="krb5-user";        CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc python3-dev libkrb5-dev" ;;
    dnf)    PKG_INSTALL="${SUDO}dnf install -y"
            PY_PKGS="python3 python3-pip"
            KRB5_PKG="krb5-workstation"; CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc python3-devel krb5-devel" ;;
    yum)    PKG_INSTALL="${SUDO}yum install -y"
            PY_PKGS="python3 python3-pip"
            KRB5_PKG="krb5-workstation"; CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc python3-devel krb5-devel" ;;
    # Leap/SLES 15 ship 3.6 as "python3"; the 3.11 interpreter is a separate package.
    zypper) PKG_INSTALL="${SUDO}zypper --non-interactive install"
            PY_PKGS="python311 python311-pip"
            VENV_PKG="python311-base"
            KRB5_PKG="krb5-client";      CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc python311-devel krb5-devel" ;;
    pacman) PKG_INSTALL="${SUDO}pacman -S --needed --noconfirm"
            PY_PKGS="python python-pip"
            KRB5_PKG="krb5";             CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc krb5" ;;
    apk)    PKG_INSTALL="${SUDO}apk add --no-cache"
            PY_PKGS="python3 py3-pip"
            KRB5_PKG="krb5";             CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc musl-dev python3-dev krb5-dev" ;;
    brew)   PKG_INSTALL="brew install"
            PY_PKGS="python@3.11"
            KRB5_PKG="krb5";             CHRONY_PKG=""       # macOS syncs its own clock
            KRB5_DEV_PKGS="krb5" ;;
    *)      PKG_INSTALL=""
            PY_PKGS="python3.11"
            KRB5_PKG="krb5";             CHRONY_PKG="chrony"
            KRB5_DEV_PKGS="gcc python3-devel krb5-devel" ;;
  esac
}

# --------------------------------------------------------------------------- prerequisites
PY=""            # best interpreter found
PY_VER=""
PY_OK=false

detect_python() {
  local c v
  # bin/bootstrap and bin/vendor-deps honour $PYTHON; if the operator already pinned one,
  # test THAT rather than second-guessing them.
  for c in "${PYTHON:-}" python3.13 python3.12 python3.11 python3 python; do
    [ -n "$c" ] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    v="$("$c" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true)"
    [ -n "$v" ] || continue
    [ -n "$PY" ] || { PY="$c"; PY_VER="$v"; }   # remember the first one that runs at all
    if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      PY="$c"; PY_VER="$v"; PY_OK=true
      return 0
    fi
  done
  return 0
}

check_platform() {
  case "$OS_KIND" in
    linux)
      info "host: $DISTRO_NAME  (linux, package manager: $PKG_MGR)"
      ;;
    wsl)
      advisory "this is WSL, not a Linux kit — usable for development and lab shakedown, NOT for an engagement"
      note "no systemd timers (systemd/README.md), and the control-node egress firewall"
      note "(design §15.2 layer 3) is not enforceable from inside WSL's network stack."
      ;;
    darwin)
      advisory "macOS is not the supported control node — the kit targets Linux (design §15.4)"
      note "The Python engine and the diff/report pipeline work here; ansible collection"
      note "against Windows/network targets is only shaken out on Linux. Use for dev only."
      ;;
    windows)
      advisory "Windows/Git Bash detected — development only; the kit control node is Linux"
      note "bin/driftwatch calls shred, flock, id and ansible; expect them to be absent here."
      ;;
    *)
      advisory "unrecognised platform '$OS_KIND' — proceeding, but nothing here is verified on it"
      ;;
  esac
}

check_bash() {
  local major="${BASH_VERSINFO[0]:-0}"
  if [ "$major" -lt 4 ]; then
    blocker "bash $BASH_VERSION is too old — bin/driftwatch needs bash 4.0+ (it uses arrays under 'set -u')"
    if [ "$PKG_MGR" = "brew" ]; then
      remedy "brew install bash    # macOS ships bash 3.2 for licensing reasons"
      note "then re-run this script with the new shell: /opt/homebrew/bin/bash ./install.sh"
    else
      remedy "${PKG_INSTALL:-<your package manager> install} bash"
    fi
  else
    ok "bash $BASH_VERSION"
  fi
}

# Debian and its derivatives ship `venv` and `ensurepip` in a SEPARATE package from the
# interpreter, so an interpreter that satisfies the 3.11+ floor can still be unable to make
# a virtualenv. bin/bootstrap's very first action is `python -m venv .venv`, so without this
# probe --check reports "PREREQUISITES MET" on a host where step 1 of the install cannot run
# — a fail-open in the one place this script exists to close. Importing the modules is
# read-only; it creates nothing, which keeps --check's contract intact.
check_python_venv() {
  local pkg="$VENV_PKG"
  if "$PY" -c 'import venv, ensurepip' >/dev/null 2>&1; then
    ok "python venv + ensurepip available (bin/bootstrap builds .venv with them)"
    return 0
  fi
  blocker "'$PY' cannot create a virtualenv — the venv/ensurepip stdlib modules are missing"
  # On Debian the package tracks the interpreter's minor version, so name the one that
  # matches the interpreter we actually selected rather than a generic python3-venv.
  case "$PKG_MGR:$PY" in
    apt:python3.*) pkg="${PY##*/}-venv" ;;
  esac
  if [ -n "$PKG_INSTALL" ] && [ -n "$pkg" ]; then
    remedy "$PKG_INSTALL $pkg"
  elif [ -n "$PKG_INSTALL" ]; then
    remedy "$PKG_INSTALL $PY_PKGS"
  else
    note "install this host's python venv/ensurepip package before re-running"
  fi
  note "bin/bootstrap's first step is 'python -m venv .venv'; it cannot proceed without them."
}

check_python() {
  detect_python
  if [ "$PY_OK" = true ]; then
    ok "python: $PY ($PY_VER)"
    check_python_venv
    return 0
  fi
  if [ -n "$PY" ]; then
    blocker "python $PY_VER found at '$PY', but the engine requires 3.11+ (CONTRACTS §6)"
  else
    blocker "no python3 interpreter found — the whole control-node engine is Python 3.11+"
  fi
  if [ -n "$PKG_INSTALL" ]; then
    remedy "$PKG_INSTALL $PY_PKGS"
  else
    note "no package manager detected; install Python 3.11+ by whatever means this host uses"
  fi
  note "Already have a newer interpreter under another name? Point the kit at it:"
  remedy "PYTHON=python3.12 ./install.sh"
}

check_repo_layout() {
  local missing="" p
  for p in bin/bootstrap bin/driftwatch bin/vendor-deps requirements.txt requirements.yml \
           ansible.cfg scripts/lint_readonly.py scripts/driftwatch_common.py \
           playbooks roles rules tests
  do
    [ -e "$REPO_ROOT/$p" ] || missing="$missing $p"
  done
  if [ -n "$missing" ]; then
    blocker "incomplete checkout — missing:$missing"
    note "Re-fetch the repository; a partial copy cannot be made safe by this script."
    return 0
  fi
  ok "repository layout complete (CONTRACTS §1.1)"

  # vendor/python IS committed: the engine must import PyYAML/Jinja2 on a bare interpreter
  # with no pip and no PyPI, which is the whole air-gap story (README, CONTRACTS §1.1).
  if [ -d "$REPO_ROOT/vendor/python" ]; then
    ok "vendored engine deps present (vendor/python — engine runs with no pip)"
  else
    blocker "vendor/python/ is missing — the engine cannot import PyYAML/Jinja2 offline"
    remedy "bin/vendor-deps python     # on a connected host, then commit the result"
  fi
}

check_exec_bits() {
  # GitHub's "Download ZIP" does not preserve the Unix executable bit, so a ZIP-deployed kit
  # fails with "Permission denied" on ./bin/driftwatch. Cheap to detect, cheap to fix.
  local f needs=""
  for f in "$REPO_ROOT"/bin/* "$CONTAINER_DIR/driftwatch-container"; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || needs="$needs $(basename "$f")"
  done
  if [ -n "$needs" ]; then
    if [ "$CHECK_ONLY" = true ]; then
      info "would restore the executable bit on:$needs (ZIP downloads drop it)"
    fi
  else
    ok "bin/* already executable"
  fi
}

check_offline_bundle() {
  [ "$OFFLINE" = true ] || return 0
  local wheels="$REPO_ROOT/vendor/wheels" colls="$REPO_ROOT/vendor/collections" bad=false

  if [ ! -d "$wheels" ] || [ -z "$(ls -A "$wheels" 2>/dev/null)" ]; then
    blocker "--offline requested but vendor/wheels/ is missing or empty"
    bad=true
  fi
  if [ ! -d "$colls" ] || [ -z "$(ls -A "$colls" 2>/dev/null)" ]; then
    blocker "--offline requested but vendor/collections/ is missing or empty"
    bad=true
  fi
  if [ "$bad" = true ]; then
    note "The offline bundle is built on an INTERNET-CONNECTED host and carried to site;"
    note "it is deliberately not in git (100s of MB). On the connected host, run:"
    remedy "bin/vendor-deps bundle"
    note "then copy vendor/wheels/ and vendor/collections/ onto this kit and re-run."
    return 0
  fi
  ok "offline bundle present ($(ls -1 "$wheels" | wc -l | tr -d ' ') wheels, $(ls -1 "$colls" | wc -l | tr -d ' ') collection files)"
}

# OS packages the Windows transport ladder needs. design §3.1 is explicit that these belong
# in the kit IMAGE rather than in per-engagement setup — so the right outcome here is a loud
# advisory with the exact install line, not a silent apt-get behind the operator's back.
MISSING_OS_PKGS=""
check_kerberos_stack() {
  MISSING_OS_PKGS=""

  if command -v kinit >/dev/null 2>&1 && command -v klist >/dev/null 2>&1; then
    ok "kerberos client present (kinit/klist)"
  else
    advisory "no Kerberos client — rung 1 of the Windows transport ladder (Kerberos over WinRM-HTTPS) cannot work"
    [ -n "$KRB5_PKG" ] && MISSING_OS_PKGS="$MISSING_OS_PKGS $KRB5_PKG"
    note "Without it 'driftwatch preflight' fails at the TGT check and every Windows host"
    note "drops to OpenSSH or reports as a coverage gap (design §3.1, §15.2)."
  fi

  if command -v chronyc >/dev/null 2>&1 || [ -x /usr/sbin/chronyd ]; then
    ok "chrony present (clock sync for the ±5 min Kerberos window)"
  elif command -v timedatectl >/dev/null 2>&1; then
    advisory "chrony not installed; systemd-timesyncd may be handling the clock"
    note "Kerberos fails outside ±5 minutes of the DC and the error does not say so."
    note "Verify with: timedatectl status   — and sync against the CLIENT's NTP/DC on arrival."
  else
    advisory "no clock-sync tooling found — Kerberos needs the kit within 5 minutes of the DC"
    [ -n "$CHRONY_PKG" ] && MISSING_OS_PKGS="$MISSING_OS_PKGS $CHRONY_PKG"
    note "Time skew and DNS account for most 'Kerberos doesn't work' incidents (design §3.1)."
  fi

  # Name the packages either way. Without this, a host with no recognised package manager
  # got the advisories above and no package NAMES at all under --check, while a real run
  # printed them from offer_os_packages — --check must not know less than the install does.
  if [ -n "$MISSING_OS_PKGS" ]; then
    if [ -n "$PKG_INSTALL" ]; then
      note "Install line for this host:"
      remedy "$PKG_INSTALL$MISSING_OS_PKGS"
    else
      note "No package manager detected. Install these by whatever means this host uses:$MISSING_OS_PKGS"
    fi
  fi
}

check_optional_tools() {
  local missing="" c
  # bin/driftwatch degrades gracefully without each of these, but says so at the worst
  # possible moment (mid-collect, mid-teardown). Better to know now.
  for c in git flock shred ssh; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  if [ -n "$missing" ]; then
    advisory "optional kit utilities missing:$missing"
    for c in $missing; do
      case "$c" in
        git)   note "git   — the per-engagement tamper-evident snapshot history (design §5) is skipped" ;;
        flock) note "flock — overlapping systemd-timer collections are no longer prevented" ;;
        shred) note "shred — teardown falls back to rm; erasure then rests entirely on the" \
                    "encrypted engagement volume (design §15.1, §15.4)" ;;
        ssh)   note "ssh   — the Linux and network-device transports have no client binary" ;;
      esac
    done
    if [ -n "$PKG_INSTALL" ]; then
      remedy "$PKG_INSTALL$missing"
    fi
  else
    ok "optional kit utilities present (git, flock, shred, ssh)"
  fi
}

# --------------------------------------------------------------------------- native install
print_native_plan() {
  local net="online (PyPI + Ansible Galaxy)"
  local boot_cmd="bin/bootstrap"
  local winrm_src="PyPI"
  if [ "$OFFLINE" = true ]; then
    net="OFFLINE (vendor/wheels + vendor/collections only)"
    boot_cmd="bin/bootstrap --offline"
    winrm_src="vendor/wheels"
  fi
  cat >&2 <<EOF

What a real run would do (in this order):
  1. chmod +x bin/*                     restore exec bits a ZIP download drops
  2. offer the missing OS packages      printed above; never installed silently
  3. $boot_cmd
                                        .venv + pip + ansible-galaxy — $net
  4. pip install pywinrm[kerberos]      Windows transport rung 1, from $winrm_src
                                        (bootstrap does not install it; §3.1 needs it)
  5. scripts/lint_readonly.py check     the read-only SECURITY control (design §15.3)
  6. pytest tests/ -q                   kit self-test, if pytest is installed
  7. print next steps                   doctor, then new-engagement --interactive

Nothing above was executed: --check is read-only by contract.
EOF
}

fix_exec_bits() {
  local f changed=false
  for f in "$REPO_ROOT"/bin/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] && continue
    chmod +x "$f" 2>/dev/null && changed=true || warn "could not chmod +x $f (read-only media?)"
  done
  if [ -f "$CONTAINER_DIR/driftwatch-container" ] && [ ! -x "$CONTAINER_DIR/driftwatch-container" ]; then
    chmod +x "$CONTAINER_DIR/driftwatch-container" 2>/dev/null && changed=true || true
  fi
  [ -x "$SELF" ] || chmod +x "$SELF" 2>/dev/null || true
  if [ "$changed" = true ]; then
    info "restored executable bits (a GitHub ZIP download drops them)"
  fi
}

offer_os_packages() {
  [ -n "$MISSING_OS_PKGS" ] || return 0
  if [ -z "$PKG_INSTALL" ]; then
    warn "OS packages are missing but no package manager was detected — install by hand:$MISSING_OS_PKGS"
    return 0
  fi
  # These change the HOST, not the checkout. design §3.1 puts them in the kit image, so the
  # operator may well be running a kit where this is already handled — ask, never assume.
  warn "the Windows/Kerberos transport needs OS packages that are not installed:$MISSING_OS_PKGS"
  remedy "$PKG_INSTALL$MISSING_OS_PKGS"
  if confirm "run that command now?"; then
    info "running: $PKG_INSTALL$MISSING_OS_PKGS"
    # Deliberate word splitting: both halves are command lines assembled above.
    # shellcheck disable=SC2086
    if $PKG_INSTALL $MISSING_OS_PKGS; then
      ok "OS packages installed"
    else
      warn "package install failed — install them by hand before 'driftwatch preflight'"
    fi
  else
    warn "skipped — 'driftwatch preflight' will fail at the Kerberos checks until these exist"
  fi
}

run_bootstrap() {
  local mode_desc="online (PyPI + Galaxy)" rc=0
  [ "$OFFLINE" = true ] && mode_desc="offline (vendor/wheels + vendor/collections)"
  info "handing venv + pip + collections to bin/bootstrap — $mode_desc"

  # Invoked through `bash` explicitly: on read-only or noexec media the chmod above cannot
  # take, and bootstrap is the one step that must not fail for a cosmetic reason.
  # PYTHON is exported so bootstrap uses the SAME interpreter this script validated.
  #
  # The `if` matters as much as the command: under `set -e` a bare invocation would abort
  # the whole script the instant pip exits non-zero, leaving the operator with a pip
  # traceback and no remediation — precisely the failure mode Appendix D.3 rejects.
  if [ "$OFFLINE" = true ]; then
    PYTHON="$PY" bash "$REPO_ROOT/bin/bootstrap" --offline || rc=$?
  else
    PYTHON="$PY" bash "$REPO_ROOT/bin/bootstrap" || rc=$?
  fi

  if [ "$rc" -ne 0 ]; then
    err "bin/bootstrap failed (exit $rc) — the ansible environment was NOT created."
    if [ "$OFFLINE" = true ]; then
      note "Offline installs fail closed on an incomplete bundle. Most common cause: the"
      note "bundle was built on a different OS/arch, so the cryptography/cffi wheels in"
      note "vendor/wheels do not match this host. Rebuild it on a matching Linux host:"
      remedy "bin/vendor-deps bundle"
    else
      note "Most common causes, in order: no route to PyPI/Galaxy from this network (use"
      note "--offline with a bundle instead), a proxy that needs \$https_proxy set, or a"
      note "python missing venv/ensurepip. Re-check the host first:"
      remedy "./install.sh --check"
    fi
    die "cannot continue without the ansible environment"
  fi
  ok "ansible environment ready (.venv + ./collections)"
}

# The Windows transport ladder's rung 1 (Kerberos over WinRM-HTTPS) is what
# inventory/group_vars/windows.yml actually selects — `ansible_connection: winrm` with
# `ansible_winrm_transport: kerberos`. That connection plugin needs pywinrm[kerberos], and
# bin/bootstrap does not install it (it installs requirements.txt + ansible-core only). The
# container image installs it explicitly for exactly this reason; the native install — the
# SUPPORTED default — must not silently be the weaker of the two, or every Windows host in
# the fleet reports as a coverage gap on day one (design §3.1, §15.2).
install_windows_transport() {
  local vpy rc=0
  vpy="$(venv_python)"

  info "installing the Windows transport stack (pywinrm[kerberos]) into .venv"
  if [ "$OFFLINE" = true ]; then
    "$vpy" -m pip install --quiet --no-index --find-links "$REPO_ROOT/vendor/wheels" \
      "pywinrm[kerberos]" || rc=$?
  else
    "$vpy" -m pip install --quiet "pywinrm[kerberos]>=0.4.3" || rc=$?
  fi

  if [ "$rc" -eq 0 ] && "$vpy" -c 'import winrm' >/dev/null 2>&1; then
    ok "Windows transport stack installed (Kerberos over WinRM-HTTPS available)"
    return 0
  fi

  # Not a blocker: a Linux/network-only engagement is perfectly valid, and the collector
  # still degrades to OpenSSH (rung 2) where the client publishes it. But it must be LOUD,
  # because the failure otherwise surfaces mid-collect as "unreachable" on every Windows host.
  advisory "pywinrm[kerberos] did not install — Windows hosts will have NO WinRM transport"
  note "This almost always means the krb5 headers or a compiler are missing: the GSSAPI"
  note "binding is built from source. kinit/klist alone (KRB5_PKG) are not enough."
  if [ -n "$PKG_INSTALL" ] && [ -n "$KRB5_DEV_PKGS" ]; then
    remedy "$PKG_INSTALL $KRB5_DEV_PKGS"
  elif [ -n "$KRB5_DEV_PKGS" ]; then
    note "Install the krb5 development headers and a C toolchain: $KRB5_DEV_PKGS"
  fi
  if [ "$OFFLINE" = true ]; then
    remedy "$vpy -m pip install --no-index --find-links vendor/wheels 'pywinrm[kerberos]'"
    note "If pip says 'no matching distribution', the bundle predates this dependency or"
    note "was built on another platform — rebuild it with: bin/vendor-deps bundle"
  else
    remedy "$vpy -m pip install 'pywinrm[kerberos]>=0.4.3'"
  fi
  note "Linux and network-device collection are unaffected; 'driftwatch preflight' will"
  note "report every Windows host as no-transport until this is resolved (design §3.1)."
}

venv_python() {
  local v="$REPO_ROOT/.venv/bin/python"
  [ -x "$v" ] || v="$REPO_ROOT/.venv/Scripts/python"   # Linux vs Windows venv layout
  [ -x "$v" ] || v="$PY"
  printf '%s' "$v"
}

self_test() {
  local vpy; vpy="$(venv_python)"

  # The read-only lint is a SECURITY control, not a style check (design §9, §15.3): with the
  # single shared privileged account the portable model assumes, the collector's safety
  # degrades from "cannot write" to "does not write", and this lint is what makes that true.
  # It needs only PyYAML, which is vendored — so it runs offline, on a bare interpreter.
  info "self-test 1/2 — read-only collector lint"
  if "$PY" "$REPO_ROOT/scripts/lint_readonly.py" check --roles-dir "$REPO_ROOT/roles"; then
    ok "read-only lint PASSED"
  else
    err "read-only lint FAILED — a snapshot_* role can write to targets."
    note "This is the load-bearing control behind the agentless read-only guarantee."
    die "do not point this checkout at a client fleet until the lint is green"
  fi

  info "self-test 2/2 — unit suite"
  if "$vpy" -c 'import pytest' >/dev/null 2>&1; then
    if ( cd "$REPO_ROOT" && "$vpy" -m pytest tests/ -q ); then
      ok "unit suite PASSED"
    else
      die "unit suite FAILED — fix this kit before an engagement depends on it"
    fi
  else
    advisory "pytest not installed — skipping the unit suite (it is a dev-only dependency)"
    remedy "$vpy -m pip install -r requirements-dev.txt"
  fi
}

print_next_steps() {
  cat >&2 <<EOF

--------------------------------------------------------------------------------
driftwatch control node is installed.

Next:
  0. Put the virtualenv on PATH for this shell. bin/driftwatch requires ansible,
     ansible-playbook and ansible-inventory to BE on PATH (it will not silently
     reach into .venv), and 'doctor' reports this as a warning if you skip it:
       . .venv/bin/activate

  1. Confirm the kit itself is sound (transports, tooling, permissions):
       ./bin/driftwatch doctor

  2. Stand up the engagement. The guided flow writes scope.yml, which IS the
     authorization boundary — an empty in_scope authorizes nothing (design §15.2):
       ./bin/driftwatch new-engagement --interactive

  3. Load the credentials you were handed into the engagement's ephemeral vault,
     then verify the Windows transports BEFORE collecting (design §3.1):
       ansible-vault create engagements/<id>/vault/vault.yml
       DRIFTWATCH_ENGAGEMENT=<id> ./bin/driftwatch preflight

Nothing here has run against a live fleet — shake it out in a lab first.
--------------------------------------------------------------------------------
EOF
}

install_native() {
  info "mode: native control-node install   offline=$OFFLINE   check-only=$CHECK_ONLY"
  info "repo: $REPO_ROOT"

  check_platform
  check_bash
  check_python
  check_repo_layout
  check_exec_bits
  check_offline_bundle
  check_kerberos_stack
  check_optional_tools

  if [ "$CHECK_ONLY" = true ]; then
    print_native_plan
    finish_check
  fi

  if [ "$BLOCKERS" -gt 0 ]; then
    err "$BLOCKERS blocker(s) above must be resolved first — nothing was changed."
    die "prerequisites not met"
  fi

  fix_exec_bits
  offer_os_packages
  run_bootstrap
  install_windows_transport
  self_test
  print_next_steps
}

# --------------------------------------------------------------------------- container mode
CONTAINER_RUNTIME=""

# Every path the Containerfile names in a COPY. A missing one does not fail early with a
# useful message: it fails deep inside the build with a bare "COPY failed", after the base
# image and the whole apt layer have been pulled. `baselines/` is the live example — git
# stores files, not directories, so an empty baselines/ is absent from every clone and
# every ZIP unless something keeps it (CONTRACTS §1.1 still declares it part of the layout).
CONTAINER_COPY_PATHS="requirements.txt requirements.yml ansible.cfg README.md
                      bin scripts playbooks roles rules allowlists inventory systemd docs
                      tests baselines vendor
                      response/scripts response/playbooks response/README.md"

check_container_context() {
  local missing="" p
  # Deliberate word splitting over the whitespace-separated path list above.
  # shellcheck disable=SC2086
  for p in $CONTAINER_COPY_PATHS; do
    [ -e "$REPO_ROOT/$p" ] || missing="$missing $p"
  done
  if [ -n "$missing" ]; then
    blocker "the build context is missing paths the Containerfile COPYs:$missing"
    note "The Containerfile copies an ALLOWLIST, not the whole context (that is what keeps"
    note "engagements/ out of every layer), so each of these must exist before the build."
    note "Re-fetch the repository; a partial copy cannot be made safe by this script."
    return 0
  fi
  ok "container build context complete (every Containerfile COPY source present)"
}

detect_container_runtime() {
  # Rootless podman first, deliberately. A root-owned container daemon on a box that holds
  # fleet-wide admin credentials is a bad trade — design §9 treats the control node as a
  # tier-0 asset, and Appendix C.1 already rejected "another service to break on the kit".
  # docker stays supported as a fallback.
  if   command -v podman >/dev/null 2>&1; then CONTAINER_RUNTIME="podman"
  elif command -v docker >/dev/null 2>&1; then CONTAINER_RUNTIME="docker"
  else                                        CONTAINER_RUNTIME=""
  fi
}

check_container_prereqs() {
  detect_container_runtime

  if [ -z "$CONTAINER_RUNTIME" ]; then
    blocker "no container runtime found — --mode container needs podman (preferred) or docker"
    [ -n "$PKG_INSTALL" ] && remedy "$PKG_INSTALL podman"
    note "podman is preferred because it is rootless and daemonless."
    note "The container is entirely OPTIONAL — the native install needs no runtime at all:"
    remedy "./install.sh"
  else
    # Rootlessness is inferred from the uid rather than asked of the runtime: `podman info`
    # initialises the user's container storage on first call, and --check must not write.
    if [ "$CONTAINER_RUNTIME" = "podman" ] && [ "$(id -u 2>/dev/null || echo 1000)" != "0" ]; then
      ok "container runtime: podman (rootless — the preferred configuration)"
    elif [ "$CONTAINER_RUNTIME" = "podman" ]; then
      advisory "podman found, but this shell is root — prefer running it rootless as the operator user"
    else
      advisory "container runtime: docker (supported fallback)"
      note "docker's daemon runs as root on a kit that holds fleet-wide admin credentials."
      note "Prefer rootless podman where the client environment allows it."
    fi
  fi

  local f
  for f in Containerfile README.md driftwatch-container \
           Containerfile.containerignore Containerfile.dockerignore; do
    if [ -f "$CONTAINER_DIR/$f" ]; then
      ok "deploy/container/$f present"
    else
      blocker "deploy/container/$f is missing — incomplete checkout"
    fi
  done

  if [ "$OFFLINE" = true ]; then
    check_offline_bundle
    advisory "--offline limits the BUILD to the vendored bundle, but a build is not an air-gap story"
    note "Base-image layers and OS packages still come from a registry / package mirror."
    note "The real air-gapped path is to build on a connected host and carry the image:"
    remedy "podman save -o driftwatch-$IMAGE_VERSION.tar $IMAGE_NAME:$IMAGE_VERSION"
    remedy "podman load -i driftwatch-$IMAGE_VERSION.tar     # on the kit"
  fi
}

print_container_plan() {
  local ctx_flag="--ignorefile deploy/container/Containerfile.containerignore"
  [ "$CONTAINER_RUNTIME" = "docker" ] && ctx_flag="(DOCKER_BUILDKIT=1; sidecar Containerfile.dockerignore)"
  cat >&2 <<EOF

What a real run would do:
  1. ${CONTAINER_RUNTIME:-<runtime>} build -f deploy/container/Containerfile \\
       -t $IMAGE_NAME:$IMAGE_VERSION -t $IMAGE_NAME:latest $REPO_ROOT
       context filtered by: $ctx_flag
  2. print the exact 'driftwatch-container' invocation and its mount list

The image carries CODE AND DEPENDENCIES ONLY. No engagement volume, no vault, no
credentials, no snapshots ever enter a layer — anything written into a layer cannot be
reliably shredded at teardown (design §15.4). engagements/ is always a bind mount.

The same rule applies to the build CONTEXT, which is this repo root and therefore holds
engagements/ too: the ignore file above keeps it out of the builder entirely, so it never
reaches docker's root-owned storage or podman's temp copy.

Nothing above was executed: --check is read-only by contract.
EOF
}

build_container() {
  local build_args_desc="" pull_flag="" rc=0
  # The Containerfile's COPY allowlist keeps client data out of the LAYERS. It does nothing
  # about the build CONTEXT, and the context here is the repo root — which is where
  # engagements/<id>/ lives (vault, snapshots, findings, evidence). Every build would
  # otherwise hand the whole encrypted volume's plaintext-on-disk contents to the builder:
  # to a root-owned daemon under /var/lib/docker for docker, to a temp copy for podman.
  # Neither is reachable by `driftwatch teardown`, which is the same argument design §15.4
  # makes about layers. So the ignore file is not an optimisation, it is the second half of
  # the same control — and it is passed EXPLICITLY rather than trusted to sidecar lookup.
  local ignorefile="$CONTAINER_DIR/Containerfile.containerignore"
  [ -f "$ignorefile" ] || die "missing $ignorefile — refusing to build a context that would include engagements/"

  if [ "$OFFLINE" = true ]; then
    # podman spells it --pull=never; docker's --pull is a boolean.
    if [ "$CONTAINER_RUNTIME" = "podman" ]; then pull_flag="--pull=never"; else pull_flag="--pull=false"; fi
    build_args_desc=" (offline: bundle-only pip/galaxy, no registry pull)"
  fi

  info "building $IMAGE_NAME:$IMAGE_VERSION with $CONTAINER_RUNTIME$build_args_desc"
  info "build context: $REPO_ROOT, filtered by $(basename "$ignorefile") (engagements/ excluded)"

  if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    # podman/buildah take the ignore file as an explicit flag.
    if [ "$OFFLINE" = true ]; then
      podman build --ignorefile "$ignorefile" \
        -f "$CONTAINER_DIR/Containerfile" \
        -t "$IMAGE_NAME:$IMAGE_VERSION" -t "$IMAGE_NAME:latest" \
        --build-arg "DW_OFFLINE=1" "$pull_flag" "$REPO_ROOT" || rc=$?
    else
      podman build --ignorefile "$ignorefile" \
        -f "$CONTAINER_DIR/Containerfile" \
        -t "$IMAGE_NAME:$IMAGE_VERSION" -t "$IMAGE_NAME:latest" \
        "$REPO_ROOT" || rc=$?
    fi
  else
    # docker has no --ignorefile. BuildKit reads "<dockerfile-path>.dockerignore", which is
    # why that sidecar exists next to the Containerfile; the legacy builder would ignore it
    # and sweep the engagement volume into the context, so BuildKit is forced on here.
    if [ "$OFFLINE" = true ]; then
      DOCKER_BUILDKIT=1 docker build \
        -f "$CONTAINER_DIR/Containerfile" \
        -t "$IMAGE_NAME:$IMAGE_VERSION" -t "$IMAGE_NAME:latest" \
        --build-arg "DW_OFFLINE=1" "$pull_flag" "$REPO_ROOT" || rc=$?
    else
      DOCKER_BUILDKIT=1 docker build \
        -f "$CONTAINER_DIR/Containerfile" \
        -t "$IMAGE_NAME:$IMAGE_VERSION" -t "$IMAGE_NAME:latest" \
        "$REPO_ROOT" || rc=$?
    fi
  fi

  if [ "$rc" -ne 0 ]; then
    err "image build failed (exit $rc) — no image was tagged."
    note "Builds need network for the base image, apt and (unless --offline) PyPI/Galaxy."
    note "Build on a connected host and carry the result to the kit instead:"
    remedy "podman save -o driftwatch-$IMAGE_VERSION.tar $IMAGE_NAME:$IMAGE_VERSION"
    die "container build failed"
  fi
  ok "built $IMAGE_NAME:$IMAGE_VERSION (also tagged :latest)"
}

print_container_next_steps() {
  cat >&2 <<EOF

--------------------------------------------------------------------------------
Image built: $IMAGE_NAME:$IMAGE_VERSION (and :latest)

Run it through the wrapper — it establishes the mounts the kit needs, publishes NO
ports, and drops all capabilities:

  ./deploy/container/driftwatch-container --dry-run status    # print the command only
  ./deploy/container/driftwatch-container status
  DRIFTWATCH_ENGAGEMENT=<id> ./deploy/container/driftwatch-container collect --deep

Mounts the wrapper establishes:
  engagements/     -> /opt/driftwatch/engagements        rw  the ONLY client-data path;
                                                             keep it on the encrypted volume
  /etc/krb5.conf   -> /etc/krb5.conf                     ro  client realm + KDC (§3.1)
  \$KRB5CCNAME      -> /tmp/krb5cc                        rw  TGT; rw because GSSAPI writes
                                                             service tickets back to the cache
  kit home         -> /opt/driftwatch/.home              rw  known_hosts + ansible caches;
                                                             a fresh container starts EMPTY (§9)

Read deploy/container/README.md before using this in the field — in particular what
--network host does to the egress-firewall scope control (design §15.2 layer 3), and
why nothing client-side may ever be baked into a layer (§15.4).

Air-gapped transfer:
  $CONTAINER_RUNTIME save -o driftwatch-$IMAGE_VERSION.tar $IMAGE_NAME:$IMAGE_VERSION
  $CONTAINER_RUNTIME load -i driftwatch-$IMAGE_VERSION.tar        # on the kit
--------------------------------------------------------------------------------
EOF
}

install_container() {
  info "mode: container image build (OPTIONAL)   offline=$OFFLINE   check-only=$CHECK_ONLY"
  info "repo: $REPO_ROOT"
  warn "the container is for reproducibility of the TOOLING only — the native install"
  warn "(./install.sh) is the supported default and needs no container runtime."

  check_platform
  check_repo_layout
  # The Containerfile COPYs an explicit allowlist of repo paths; a partial checkout fails
  # deep inside the build with a bare "COPY failed", so check every one of them up front.
  check_container_context
  check_container_prereqs

  if [ "$CHECK_ONLY" = true ]; then
    print_container_plan
    finish_check
  fi

  if [ "$BLOCKERS" -gt 0 ]; then
    err "$BLOCKERS blocker(s) above must be resolved first — nothing was built."
    die "prerequisites not met"
  fi

  fix_exec_bits
  build_container
  print_container_next_steps
}

# --------------------------------------------------------------------------- dispatch
finish_check() {
  printf '\n' >&2
  if [ "$BLOCKERS" -eq 0 ]; then
    ok "PREREQUISITES MET — $ADVISORIES advisory/advisories. Re-run without --check to install."
    exit 0
  fi
  err "NOT INSTALLABLE — $BLOCKERS blocker(s), $ADVISORIES advisory/advisories (all listed above)."
  exit 1
}

main() {
  parse_args "$@"
  detect_host
  case "$MODE" in
    native)    install_native ;;
    container) install_container ;;
  esac
}

main "$@"
