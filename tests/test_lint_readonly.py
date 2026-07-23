"""Tests for the read-only security lint. Because this lint is a load-bearing security
control (§15.3), its own behavior is tested: it must catch writes and must not have
false negatives on the patterns the design calls out."""

import textwrap

import lint_readonly as lint


def _write(tmp_path, content):
    p = tmp_path / "tasks.yml"
    p.write_text(textwrap.dedent(content))
    return p


def test_flags_copy_to_target(tmp_path):
    p = _write(tmp_path, """
    - name: write a file to the target
      ansible.builtin.copy:
        dest: /etc/evil
        content: x
    """)
    v = lint.lint_file(p)
    assert v and v[0].module == "copy"


def test_allows_copy_delegated_to_localhost(tmp_path):
    p = _write(tmp_path, """
    - name: assemble snapshot on control node
      ansible.builtin.copy:
        dest: "{{ dw_snapshot_dir }}/x.json"
        content: "{{ snap | to_nice_json }}"
      delegate_to: localhost
    """)
    assert lint.lint_file(p) == []


def test_flags_file_module_on_target(tmp_path):
    p = _write(tmp_path, """
    - name: remove something on the target
      ansible.builtin.file:
        path: /var/log/wtmp
        state: absent
    """)
    v = lint.lint_file(p)
    assert v and v[0].module == "file"


def test_command_family_requires_readonly_tag(tmp_path):
    p = _write(tmp_path, """
    - name: run ps without a readonly tag
      ansible.builtin.command: ps -eww
    """)
    v = lint.lint_file(p)
    assert v and "readonly" in v[0].reason


def test_command_family_ok_with_readonly_tag(tmp_path):
    p = _write(tmp_path, """
    - name: run ps
      ansible.builtin.command: ps -eww
      tags: [readonly]
    """)
    assert lint.lint_file(p) == []


def test_win_powershell_requires_readonly_tag(tmp_path):
    p = _write(tmp_path, """
    - name: collect processes
      ansible.windows.win_powershell:
        script: Get-CimInstance Win32_Process
    """)
    v = lint.lint_file(p)
    assert v and v[0].module == "win_powershell"


def test_flags_network_config_module(tmp_path):
    p = _write(tmp_path, """
    - name: change config
      cisco.ios.ios_config:
        lines: ["no ip http server"]
    """)
    v = lint.lint_file(p)
    assert v and v[0].module == "ios_config"


def test_inherits_readonly_tag_from_block(tmp_path):
    p = _write(tmp_path, """
    - name: readonly collection block
      tags: [readonly]
      block:
        - name: ps
          ansible.builtin.command: ps -eww
        - name: ss
          ansible.builtin.shell: ss -tulpen
    """)
    assert lint.lint_file(p) == []


def test_service_module_forbidden(tmp_path):
    p = _write(tmp_path, """
    - name: stop a service
      ansible.builtin.service:
        name: sshd
        state: stopped
    """)
    v = lint.lint_file(p)
    assert v and v[0].module == "service"


def test_short_module_fqcn():
    assert lint.short_module("ansible.builtin.copy") == "copy"
    assert lint.short_module("community.windows.win_copy") == "win_copy"
    assert lint.short_module("command") == "command"
