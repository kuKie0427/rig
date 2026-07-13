"""Tests for `rig.audit.replay` — per-incident decision-tree rebuild.

DIRECTIONS.md § Phase 3 测试:
"tests/test_audit_replay.py — 锁定 schema 版本,旧 audit log 始终
可 replay".
"""

import json
from pathlib import Path

import pytest

from rig.audit.replay import (
    _build_parser,
    main,
    replay,
    to_markdown,
)
from rig.audit.writer import (
    AuditRecord,
    CommandType,
    init_db,
    record_command,
)


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    base = tmp_path / "replay-test"
    init_db(base)
    return base


def _rec(
    *,
    execution_id: str,
    incident_id: str,
    timestamp: str,
    command: str = "kubectl get pods",
    command_type: CommandType = "kubectl",
    deny_reason: str | None = None,
    approved_by: list[str] | None = None,
    required_approvals: int = 2,
    rollback_id: str | None = None,
    cluster: str | None = "k8s-prod",
    namespace: str | None = "production",
    exit_code: int | None = 0,
    stdout: str | None = "ok",
    stderr: str | None = None,
) -> AuditRecord:
    return AuditRecord(
        execution_id=execution_id,
        timestamp=timestamp,
        user="alice",
        command=command,
        command_type=command_type,
        deny_reason=deny_reason,
        approved_by=list(approved_by if approved_by is not None else ["alice"]),
        required_approvals=required_approvals,
        incident_id=incident_id,
        cluster=cluster,
        namespace=namespace,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        rollback_id=rollback_id,
    )


class TestReplayEmpty:
    def test_returns_empty_for_unknown_incident(self, audit_dir):
        tree = replay("never-seen", audit_dir=str(audit_dir))
        assert tree == []

    def test_to_markdown_renders_empty_message(self):
        md = to_markdown([])
        assert "no audit_log entries" in md


class TestReplayOrdering:
    def test_results_ordered_by_timestamp(self, audit_dir):
        for ts in ["2024-01-01T00:00:03Z", "2024-01-01T00:00:01Z", "2024-01-01T00:00:02Z"]:
            record_command(
                _rec(
                    execution_id=f"order-{ts}",
                    incident_id="inc-order",
                    timestamp=ts,
                ),
                audit_dir,
            )
        tree = replay("inc-order", audit_dir=str(audit_dir))
        timestamps = [n["timestamp"] for n in tree]
        assert timestamps == sorted(timestamps)


class TestReplayShape:
    def test_node_has_decision_tree_fields(self, audit_dir):
        record_command(
            _rec(
                execution_id="shape-1",
                incident_id="inc-shape",
                timestamp="2024-01-01T00:00:00Z",
                command="kubectl delete pod p1",
                deny_reason="D1",
                approved_by=["alice", "bob"],
                required_approvals=3,
                exit_code=137,
                stdout="pod \"p1\" deleted",
                stderr=None,
            ),
            audit_dir,
        )
        tree = replay("inc-shape", audit_dir=str(audit_dir))
        assert len(tree) == 1
        n = tree[0]
        assert n["command"] == "kubectl delete pod p1"
        assert n["deny_reason"] == "D1"
        assert n["approved_by"] == ["alice", "bob"]
        assert n["required_approvals"] == 3
        assert n["exit_code"] == 137
        assert n["stdout"] == 'pod "p1" deleted'


class TestReplayCrossSchemaBackwardCompat:
    """DIRECTIONS.md § Phase 3 测试: 锁定 schema 版本,旧 audit log
    始终可 replay.

    Phase 3 ships with SCHEMA_VERSION=1; replay() must keep working
    for that schema. Future schema bumps are out of scope (Phase 4+
    work) — but the contract here is "any version that alembic has
    already migrated TO schema_version row is replayable".
    """

    def test_v1_record_is_replayable(self, audit_dir):
        record_command(
            _rec(
                execution_id="v1-record",
                incident_id="inc-v1",
                timestamp="2024-01-01T00:00:00Z",
            ),
            audit_dir,
        )
        tree = replay("inc-v1", audit_dir=str(audit_dir))
        assert len(tree) == 1
        assert tree[0]["execution_id"] == "v1-record"


class TestMarkdownRenderer:
    def test_renders_command_section(self, audit_dir):
        record_command(
            _rec(
                execution_id="md-1",
                incident_id="inc-md",
                timestamp="2024-01-01T00:00:00Z",
                command="helm uninstall my-release",
                deny_reason="D2",
            ),
            audit_dir,
        )
        tree = replay("inc-md", audit_dir=str(audit_dir))
        md = to_markdown(tree)
        assert "# Incident replay" in md
        assert "## `helm uninstall my-release`" in md
        assert "deny_dimension: `D2`" in md
        assert "alice" in md  # user


class TestModuleCLI:
    def test_cli_markdown_to_stdout(
        self, audit_dir, monkeypatch, capsys
    ):
        record_command(
            _rec(
                execution_id="cli-1",
                incident_id="inc-cli",
                timestamp="2024-01-01T00:00:00Z",
            ),
            audit_dir,
        )
        rc = main(
            ["--incident-id", "inc-cli", "--audit-dir", str(audit_dir)]
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "# Incident replay" in out

    def test_cli_json_mode(
        self, audit_dir, monkeypatch, capsys
    ):
        record_command(
            _rec(
                execution_id="json-1",
                incident_id="inc-json",
                timestamp="2024-01-01T00:00:00Z",
                command="kubectl get pods",
            ),
            audit_dir,
        )
        rc = main(
            [
                "--incident-id", "inc-json",
                "--audit-dir", str(audit_dir),
                "--format", "json",
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0
        parsed = json.loads(out)
        assert isinstance(parsed, list)
        assert parsed[0]["command"] == "kubectl get pods"

    def test_cli_missing_incident_id(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--audit-dir", "/tmp"])
        assert exc.value.code == 2

    def test_parser_defines_required_flags(self):
        parser = _build_parser()
        # Smoke: ensure the parser constructed without error and has
        # the expected actions.
        args = parser.parse_args(["--incident-id", "x"])
        assert args.incident_id == "x"
        assert args.format == "markdown"
        assert args.audit_dir is None
