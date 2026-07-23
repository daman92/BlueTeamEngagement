"""lint_readonly — prove the collector cannot write to a target (design §9, §15.3).

With a single shared privileged account the collector's safety degrades from "cannot
write" to "does not write", and THIS LINT is what enforces "does not write". It is a
security control, not style: CI runs it and a violation fails the build.

Rule set (applied to every task in roles/snapshot_*/):

  * target-mutating modules (copy, template, file, lineinfile, user, service, package,
    win_regedit, reboot, ...) are FORBIDDEN unless delegated to localhost — writing the
    assembled snapshot to the CONTROL node is the only legitimate use of copy/template/file.
  * any network *_config module is FORBIDDEN (config write); *_command / *_facts are reads.
  * command-family modules (command, shell, raw, win_shell, win_powershell, script, ...)
    are permitted ONLY when the task is tagged `readonly`, an explicit assertion by the
    role author that the command only reads. Untagged => violation.

Exit 0 = clean, 2 = violations found, 1 = error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Modules that mutate a target. Legitimate only against localhost (snapshot assembly).
LOCALHOST_OK = {"copy", "template", "file", "win_copy", "win_template", "win_file"}
WRITE_MODULES = LOCALHOST_OK | {
    "lineinfile", "blockinfile", "replace", "ini_file", "unarchive", "assemble", "patch",
    "get_url", "win_get_url", "uri_write",
    "user", "win_user", "group", "win_group",
    "service", "systemd", "win_service", "sysvinit",
    "package", "yum", "apt", "dnf", "zypper", "win_package", "package_facts_write",
    "cron", "at", "win_scheduled_task", "systemd_service",
    "win_regedit", "win_reg_stat_write", "win_shortcut", "win_environment",
    "reboot", "win_reboot", "mount", "win_mapped_drive", "win_share", "win_acl",
    "authorized_key", "known_hosts", "win_certificate_store", "win_firewall_rule",
    "win_dsc", "win_feature", "win_optional_feature", "win_updates",
    "iptables", "ufw", "firewalld", "nft",
}
COMMAND_FAMILY = {
    "command", "shell", "raw", "script", "expect",
    "win_command", "win_shell", "win_powershell", "powershell", "psexec",
}
# Keys on a task that are directives, not the module.
RESERVED = {
    "name", "when", "register", "delegate_to", "delegate_facts", "become", "become_user",
    "become_method", "become_flags", "tags", "loop", "loop_control", "vars", "ignore_errors",
    "block", "rescue", "always", "notify", "changed_when", "failed_when", "until", "retries",
    "delay", "no_log", "environment", "args", "check_mode", "run_once", "listen", "throttle",
    "timeout", "async", "poll", "connection", "module_defaults", "collections", "any_errors_fatal",
    "diff", "debugger", "port", "remote_user", "vars_files", "action",
}
LOCALHOST = {"localhost", "127.0.0.1", "::1"}


class Violation:
    def __init__(self, file, task_name, module, reason):
        self.file, self.task_name, self.module, self.reason = file, task_name, module, reason

    def __str__(self):
        return f"{self.file}: task '{self.task_name}' uses '{self.module}' — {self.reason}"


def short_module(key: str) -> str:
    """ansible.builtin.copy -> copy; community.windows.win_copy -> win_copy."""
    return key.split(".")[-1]


def find_module(task: dict) -> str | None:
    if "action" in task and isinstance(task["action"], str):
        return short_module(task["action"].split()[0])
    for key in task:
        if key not in RESERVED and key not in ("block", "rescue", "always"):
            return short_module(key)
    return None


def _delegated_localhost(task: dict, inherited_delegate) -> bool:
    d = task.get("delegate_to", inherited_delegate)
    return isinstance(d, str) and d.strip().strip("'\"") in LOCALHOST


def _merge_tags(inherited, task) -> set:
    tags = set(inherited)
    t = task.get("tags")
    if isinstance(t, str):
        tags.add(t)
    elif isinstance(t, list):
        tags.update(t)
    return tags


def walk_tasks(tasks, file, inherited_tags=frozenset(), inherited_delegate=None):
    """Yield (task, effective_tags, delegated_localhost_bool) for real module tasks,
    recursing into block/rescue/always."""
    if not isinstance(tasks, list):
        return
    for task in tasks:
        if not isinstance(task, dict):
            continue
        tags = _merge_tags(inherited_tags, task)
        delegate = task.get("delegate_to", inherited_delegate)
        if any(k in task for k in ("block", "rescue", "always")):
            for sub in ("block", "rescue", "always"):
                yield from walk_tasks(task.get(sub, []), file, tags, delegate)
            continue
        yield task, tags, (isinstance(delegate, str) and delegate.strip().strip("'\"") in LOCALHOST)


def lint_task(task: dict, tags: set, deleg_localhost: bool, file: str) -> Violation | None:
    module = find_module(task)
    if module is None:
        return None
    if module in WRITE_MODULES:
        if module in LOCALHOST_OK and deleg_localhost:
            return None
        return Violation(file, task.get("name", "<unnamed>"), module,
                         "target-mutating module (allowed only delegated to localhost)"
                         if module in LOCALHOST_OK else "target-mutating module forbidden in a collector role")
    if module.endswith("_config") and module not in ("show_config",):
        return Violation(file, task.get("name", "<unnamed>"), module,
                         "network config-write module forbidden in a collector role")
    if module in COMMAND_FAMILY and "readonly" not in tags:
        return Violation(file, task.get("name", "<unnamed>"), module,
                         "command-family module must be tagged 'readonly' to assert it only reads")
    return None


def lint_file(path: Path) -> list[Violation]:
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        return [Violation(str(path), "<parse>", "-", f"YAML error: {exc}")]
    violations = []
    rel = path.name
    for doc in docs:
        # tasks files are a list; playbooks are a list of plays each with tasks/pre_tasks/...
        if isinstance(doc, list) and doc and isinstance(doc[0], dict) and \
                any(k in doc[0] for k in ("hosts", "tasks", "roles")):
            for play in doc:
                for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                    for t, tags, dl in walk_tasks(play.get(section, []), rel):
                        v = lint_task(t, tags, dl, rel)
                        if v:
                            violations.append(v)
        else:
            for t, tags, dl in walk_tasks(doc if isinstance(doc, list) else [], rel):
                v = lint_task(t, tags, dl, rel)
                if v:
                    violations.append(v)
    return violations


def lint_roles(roles_dir: Path, pattern: str = "snapshot_*") -> list[Violation]:
    violations = []
    for role in sorted(roles_dir.glob(pattern)):
        if not role.is_dir() or not (role / "tasks").exists():
            continue
        for yml in sorted((role / "tasks").glob("*.yml")):
            for v in lint_file(yml):
                v.file = str(yml.relative_to(roles_dir))
                violations.append(v)
    return violations


def cmd_check(args) -> int:
    roles_dir = Path(args.roles_dir)
    if not roles_dir.exists():
        sys.stderr.write(f"roles dir not found: {roles_dir}\n")
        return 1
    violations = lint_roles(roles_dir, args.pattern)
    if violations:
        sys.stderr.write(f"read-only lint FAILED — {len(violations)} violation(s):\n")
        for v in violations:
            sys.stderr.write(f"  {v}\n")
        return 2
    scanned = sum(1 for _ in roles_dir.glob(f"{args.pattern}/tasks/*.yml"))
    print(f"read-only lint OK — {scanned} task file(s) clean under {args.pattern}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="lint_readonly")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check")
    p.add_argument("--roles-dir", default="roles")
    p.add_argument("--pattern", default="snapshot_*")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
