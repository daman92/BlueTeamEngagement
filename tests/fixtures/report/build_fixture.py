"""Regenerate the report-component test fixture engagement.

Run:  python tests/fixtures/report/build_fixture.py
Writes a self-contained engagement tree (findings for two runs + a run-status file)
under tests/fixtures/report/engagement/ that the report/fleet_stats tests load.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENG = HERE / "engagement"

PREV = "2026-07-22T0000Z"
RUN = "2026-07-22T0400Z"


def _canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _write_ndjson(path: Path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(_canon(r) + "\n")


def build() -> Path:
    (ENG / "scope.yml").parent.mkdir(parents=True, exist_ok=True)
    (ENG / "scope.yml").write_text(
        "engagement: acme-2026-07\n"
        'client: "ACME Corp"\n'
        'authorized_by: "J. Doe, CISO (signed SOW 2026-07-01)"\n',
        encoding="utf-8",
    )

    prev = [
        {"finding_id": "f-2026-07-22T0000Z-0001", "engagement": "acme-2026-07",
         "run_id": PREV, "severity": "high", "rule": "drift.windows.services",
         "platform": "windows", "category": "services", "change_type": "added",
         "hosts": ["WIN-FS01"], "detail": {"identity": {"name": "EvilSvc"},
         "before": None, "after": {"name": "EvilSvc", "state": "running"}},
         "first_seen": PREV, "comparison": ["temporal"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "prev000000000001"},
        {"finding_id": "f-2026-07-22T0000Z-0002", "engagement": "acme-2026-07",
         "run_id": PREV, "severity": "medium", "rule": "drift.linux.packages",
         "platform": "linux", "category": "packages", "change_type": "added",
         "hosts": ["web01"], "detail": {"identity": {"name": "nmap", "arch": "x86_64"},
         "before": None, "after": {"name": "nmap", "arch": "x86_64", "version": "7.94"}},
         "first_seen": PREV, "comparison": ["temporal"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "prev000000000002"},
    ]

    cur = [
        {"finding_id": "f-2026-07-22T0400Z-0001", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "critical", "rule": "policy.windows.new_trusted_root_ca",
         "platform": "windows", "category": "dns_trust", "change_type": "added",
         "hosts": ["WIN-FS01", "WIN-FS02"],
         "detail": {"identity": {"kind": "root_cert", "key": "9F3A"}, "before": None,
                    "after": {"kind": "root_cert", "key": "9F3A",
                              "subject": "CN=Corp Proxy CA 2", "not_before": "2026-07-19"},
                    "prevalence": 0.014, "note": "absent from golden baseline"},
         "first_seen": RUN, "comparison": ["temporal", "fleet_outlier", "policy"],
         "suppressed": False, "suppressed_by": None, "fingerprint": "a1b2c3d4e5f60718"},
        {"finding_id": "f-2026-07-22T0400Z-0002", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "high", "rule": "drift.windows.services",
         "platform": "windows", "category": "services", "change_type": "changed",
         "hosts": ["WIN-FS01", "WIN-FS03"],
         "detail": {"identity": {"name": "EvilSvc"},
                    "before": {"name": "EvilSvc", "state": "stopped"},
                    "after": {"name": "EvilSvc", "state": "running"},
                    "per_host": {"WIN-FS01": {"name": "EvilSvc", "state": "running", "account": "SYSTEM"},
                                 "WIN-FS03": {"name": "EvilSvc", "state": "running", "account": "svc-app"}}},
         "first_seen": PREV, "comparison": ["temporal", "baseline"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "b2c3d4e5f6071829"},
        {"finding_id": "f-2026-07-22T0400Z-0003", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "high", "rule": "coverage.host_unreachable",
         "platform": "linux", "category": "meta", "change_type": "coverage_gap",
         "hosts": ["db01"],
         "detail": {"identity": {"kind": "host_unreachable"}, "before": None,
                    "after": {"host": "db01"},
                    "note": "authorized but not assessed — no successful collection"},
         "first_seen": RUN, "comparison": ["policy"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "c3d4e5f607182930"},
        {"finding_id": "f-2026-07-22T0400Z-0004", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "medium", "rule": "drift.linux.processes",
         "platform": "linux", "category": "processes", "change_type": "added",
         "hosts": ["web01"],
         "detail": {"identity": {"path": "/tmp/x", "sha256": "deadbeef", "user": "root",
                                 "args_norm": "x"}, "before": None,
                    "after": {"path": "/tmp/x", "sha256": "deadbeef", "user": "root",
                              "args_norm": "x"}, "prevalence": 0.02,
                    "note": "present on 1/50 of group 'linux'"},
         "first_seen": RUN, "comparison": ["fleet_outlier"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "d4e5f60718293041"},
        {"finding_id": "f-2026-07-22T0400Z-0005", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "low", "rule": "drift.windows.scheduled_tasks",
         "platform": "windows", "category": "scheduled_tasks", "change_type": "added",
         "hosts": ["WIN-WS-07"],
         "detail": {"identity": {"task_path": "\\GoogleUpdateTaskMachine",
                                 "action_exe": "GoogleUpdate.exe", "action_args": "/c",
                                 "principal": "SYSTEM"}, "before": None,
                    "after": {"task_path": "\\GoogleUpdateTaskMachine"}},
         "first_seen": RUN, "comparison": ["temporal"], "suppressed": True,
         "suppressed_by": "allow-chrome-autoupdate", "fingerprint": "e5f6071829304152"},
        {"finding_id": "f-2026-07-22T0400Z-0006", "engagement": "acme-2026-07",
         "run_id": RUN, "severity": "info", "rule": "drift.linux.connections",
         "platform": "linux", "category": "connections", "change_type": "added",
         "hosts": ["web01"],
         "detail": {"identity": {"path": "/usr/bin/ssh", "remote_ip": "10.0.0.9",
                                 "remote_port": 22, "proto": "tcp"}, "before": None,
                    "after": {"path": "/usr/bin/ssh", "remote_ip": "10.0.0.9"},
                    "note": "collector self"},
         "first_seen": PREV, "comparison": ["temporal"], "suppressed": False,
         "suppressed_by": None, "fingerprint": "f60718293041526e"},
    ]

    _write_ndjson(ENG / "findings" / f"{PREV}.ndjson", prev)
    _write_ndjson(ENG / "findings" / f"{RUN}.ndjson", cur)

    run_status = {
        "hosts": {
            "web01": {"status": "ok", "platform": "linux", "failed_categories": []},
            "WIN-FS01": {"status": "ok", "platform": "windows", "failed_categories": []},
            "WIN-FS02": {"status": "ok", "platform": "windows", "failed_categories": []},
            "WIN-FS03": {"status": "partial", "platform": "windows",
                         "failed_categories": ["software", "drivers"]},
            "db01": {"status": "unreachable", "platform": "linux"},
        },
        "no_transport": ["WIN-WS-07"],
        "t3_only": ["sw-legacy-3"],
    }
    run_path = ENG / "snapshots" / "_run" / f"{RUN}.json"
    run_path.parent.mkdir(parents=True, exist_ok=True)
    with open(run_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(run_status, fh, indent=2, sort_keys=True)

    return ENG


if __name__ == "__main__":
    print("built", build())
