"""Tests for `rig.alert.diagnostic` — allowlist gating + L1 violation detection."""

import sqlite3
from pathlib import Path

import pytest

from rig.alert.diagnostic import (
    DISCLAIMER,
    DiagnosticReport,
    init_db,
    record_alert,
    run_diagnostic_with_plan,
)
from rig.alert.intake import normalize_alertmanager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    target = tmp_path / "alert.db"
    init_db(target)
    return target


def _am_event(extra_labels: dict | None = None):
    payload = {
        "groupKey": "g1:KubePodCrashLooping",
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "fp-1",
                "labels": {"alertname": "KubePodCrashLooping",
                           "namespace": "production",
                           "pod": "p1",
                           "severity": "critical",
                           **(extra_labels or {})},
                "annotations": {},
                "startsAt": "2024-01-01T00:00:00Z",
            }
        ],
    }
    return normalize_alertmanager(payload)


class TestAllowlistGate:
    def test_allowlisted_commands_run(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            [
                "kubectl get pods -n production",
                "kubectl describe pod p1",
            ],
            db_path=db_path,
        )
        assert len(report.commands_run) == 2
        assert report.commands_run[0].allowed is True
        assert report.commands_run[0].command == "kubectl get pods -n production"
        assert report.violations == []

    def test_deny_dimension_commands_recorded_as_violations(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            [
                "kubectl get pods -n production",   # allow
                "kubectl delete pod p1",             # D1
                "kubectl --context prod exec p1",    # D7
                "kubectl edit deployment p1",        # D8
            ],
            db_path=db_path,
        )
        assert len(report.commands_run) == 1
        assert len(report.violations) == 3
        dims = {v.decision.deny_dimension for v in report.violations}
        assert dims == {"D1", "D7", "D8"}

    def test_l1_violation_persisted_to_sqlite(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["kubectl delete pod p1"],
            db_path=db_path,
        )
        assert len(report.violations) == 1
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT proposed_command, deny_dimension FROM l1_violations WHERE alert_id = ?",
                (event.alert_id,),
            ).fetchone()
        assert row == ("kubectl delete pod p1", "D1")

    def test_suggested_next_steps_include_violations_only(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            [
                "kubectl get pods -n production",   # allow (not in next_steps)
                "kubectl delete pod p1",             # violation (in next_steps)
                "helm uninstall my-release",         # violation D2
            ],
            db_path=db_path,
        )
        cmds = {s["cmd"] for s in report.suggested_next_steps}
        assert "kubectl get pods -n production" not in cmds
        assert "kubectl delete pod p1" in cmds
        assert "helm uninstall my-release" in cmds

    def test_non_k8s_shell_command_can_passthrough(self, db_path):
        # `ls /tmp` is shell-allowlist positive; per DIRECTIONS.md dual-gate,
        # the shell allowlist is consulted. This path is a placeholder
        # for shell-only diagnostic commands (e.g. diagnostic output
        # file dump).
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["ls /tmp"],
            db_path=db_path,
        )
        assert len(report.commands_run) == 1
        assert report.commands_run[0].command == "ls /tmp"

    def test_non_k8s_with_disallowed_shell_is_violation(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["curl http://internal-api:8080/secrets"],
            db_path=db_path,
        )
        assert len(report.commands_run) == 0
        assert len(report.violations) == 1


class TestReportShape:
    def test_report_has_required_fields(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["kubectl get pods -n production"],
            db_path=db_path,
        )
        assert isinstance(report, DiagnosticReport)
        assert report.report_id
        assert report.alert_id == event.alert_id
        assert report.incident_id == event.incident_id
        assert report.generated_at
        assert report.llm_model == "replay"
        assert report.disclaimer == DISCLAIMER

    def test_diagnostic_reports_persisted_to_sqlite(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["kubectl get pods -n production"],
            db_path=db_path,
        )
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT report_id, alert_id, incident_id, llm_model FROM diagnostic_reports WHERE report_id = ?",
                (report.report_id,),
            ).fetchone()
        assert row is not None
        assert row[1] == event.alert_id
        assert row[2] == event.incident_id
        assert row[3] == "replay"

    def test_alert_record_links_to_diagnostic_report(self, db_path):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(
            event,
            ["kubectl get pods -n production"],
            db_path=db_path,
        )
        record_alert(db_path, event, diagnostic_report_id=report.report_id)
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT diagnostic_report_id FROM alert_events WHERE alert_id = ?",
                (event.alert_id,),
            ).fetchone()
        assert row[0] == report.report_id


class TestDenyDimensionCoverage:
    @pytest.mark.parametrize("cmd", [
        "kubectl delete pod p1",
        "helm uninstall my-release",
        "kubectl scale deploy p1 --replicas=0",
        "kubectl drain node1",
        "kubectl auth reconcile",
        "kubectl delete ns production",
        "kubectl --context prod exec p1",
        "kubectl edit deploy p1",
    ])
    def test_each_d_dimension_blocks(self, db_path, cmd):
        event = _am_event()
        record_alert(db_path, event)
        report = run_diagnostic_with_plan(event, [cmd], db_path=db_path)
        assert len(report.commands_run) == 0, f"{cmd!r} unexpectedly allowlisted"
        assert len(report.violations) == 1
        assert report.violations[0].decision.deny_dimension is not None


class TestInitDb:
    def test_init_db_idempotent(self, tmp_path: Path):
        target = tmp_path / "idempotent.db"
        init_db(target)
        init_db(target)
        with sqlite3.connect(target) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert {"alert_events", "diagnostic_reports", "l1_violations"}.issubset(
            tables
        )
