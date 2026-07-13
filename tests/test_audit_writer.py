"""Tests for `rig.audit.writer` — audit log dual-write."""

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from rig.audit.writer import (
    SCHEMA_VERSION,
    AuditRecord,
    CommandType,
    audit_lock,
    fetch_by_incident,
    init_db,
    reconcile_wal,
    record_command,
)


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    base = tmp_path / "audit"
    init_db(base)
    return base


def _record(
    execution_id: str | None = None,
    *,
    incident_id: str | None = "inc-1",
    command: str = "kubectl get pods",
    command_type: CommandType = "kubectl",
    user: str = "alice@example",
    approved_by: list[str] | None = None,
    deny_reason: str | None = None,
    required_approvals: int = 2,
    exit_code: int | None = 0,
    stdout: str | None = "p1 Ready",
    stderr: str | None = None,
    cluster: str | None = "k8s-prod",
    namespace: str | None = "production",
    rollback_id: str | None = None,
) -> AuditRecord:
    return AuditRecord(
        execution_id=execution_id or f"e-{int(time.time()*1000)}-{threading.get_ident()}",
        timestamp="2024-01-01T00:00:00Z",
        user=user,
        command=command,
        command_type=command_type,
        deny_reason=deny_reason,
        approved_by=list(approved_by if approved_by is not None else ["alice"]),
        required_approvals=required_approvals,
        incident_id=incident_id,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        rollback_id=rollback_id,
        cluster=cluster,
        namespace=namespace,
    )


class TestInitDb:
    def test_init_creates_tables(self, audit_dir):
        db = audit_dir / "audit.db"
        with sqlite3.connect(db) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert {"audit_log", "audit_wal_reconcile",
                "audit_schema_version"}.issubset(tables)

    def test_init_idempotent(self, audit_dir):
        init_db(audit_dir)
        init_db(audit_dir)  # second call must not raise
        assert (audit_dir / "audit.db").exists()

    def test_schema_version_row(self, audit_dir):
        with sqlite3.connect(audit_dir / "audit.db") as conn:
            row = conn.execute(
                "SELECT version FROM audit_schema_version"
            ).fetchone()
        assert row[0] == SCHEMA_VERSION


class TestRecordCommand:
    def test_basic_record_persisted(self, audit_dir):
        record = _record(command="kubectl get pods")
        wal_path = record_command(record, audit_dir)
        rows = fetch_by_incident(record.incident_id or "", audit_dir=str(audit_dir))
        assert len(rows) == 1
        assert rows[0]["command"] == "kubectl get pods"
        assert rows[0]["approved_by"] == ["alice"]
        assert (audit_dir / "audit-wal" / f"{record.execution_id}.json").exists()
        assert wal_path.exists()

    def test_wal_file_round_trips_record_payload(self, audit_dir):
        record = _record()
        record_command(record, audit_dir)
        wal = audit_dir / "audit-wal" / f"{record.execution_id}.json"
        payload = json.loads(wal.read_text())
        assert payload["execution_id"] == record.execution_id
        assert payload["command"] == record.command
        assert payload["approved_by"] == ["alice"]

    def test_idempotent_upsert_same_execution_id(self, audit_dir):
        record = _record()
        record_command(record, audit_dir)
        # Second call with same execution_id must not raise
        record_command(record, audit_dir)
        rows = fetch_by_incident(record.incident_id or "", audit_dir=str(audit_dir))
        assert len(rows) == 1

    def test_distinct_execution_ids_kept_separate(self, audit_dir):
        rec_a = _record(execution_id="exec-aaaa", incident_id="inc-aaaa")
        rec_b = _record(execution_id="exec-bbbb", incident_id="inc-bbbb")
        record_command(rec_a, audit_dir)
        record_command(rec_b, audit_dir)
        assert len(fetch_by_incident("inc-aaaa", audit_dir=str(audit_dir))) == 1
        assert len(fetch_by_incident("inc-bbbb", audit_dir=str(audit_dir))) == 1


class TestConcurrentWrites:
    """DIRECTIONS.md § Phase 3 测试: 并发写竞态 (2-approver 同时审批)."""

    def test_two_threads_concurrent_writes(self, audit_dir):
        results: list[Path] = []
        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                rec = _record(
                    execution_id=f"concurrent-{idx}",
                    incident_id=f"inc-concurrent-{idx}",
                    command=f"kubectl get pods-{idx}",
                )
                wal = record_command(rec, audit_dir)
                results.append(wal)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"concurrent writes raised: {errors!r}"
        assert len(results) == 8
        for wal in results:
            assert wal.exists()


class TestReconcileWal:
    def test_reconcile_picks_up_missing_wal(self, tmp_path):
        base = tmp_path / "reconcile-test"
        init_db(base)
        wal_dir = base / "audit-wal"
        wal_dir.mkdir(exist_ok=True)

        # Write a WAL file by hand WITHOUT going through record_command
        exec_id = "recover-me-1"
        wal_path = wal_dir / f"{exec_id}.json"
        wal_path.write_text(
            json.dumps(
                {
                    "execution_id": exec_id,
                    "incident_id": "inc-recover",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "user": "carol",
                    "command": "kubectl scale --replicas=0 deploy api",
                    "command_type": "kubectl",
                    "deny_reason": "D3",
                    "approved_by": ["carol", "dave"],
                    "required_approvals": 2,
                    "exit_code": 0,
                    "stdout": "scaled",
                    "stderr": None,
                    "rollback_id": None,
                    "cluster": "k8s-prod",
                    "namespace": "production",
                }
            )
        )

        replayed = reconcile_wal(base)
        assert replayed == 1
        rows = fetch_by_incident("inc-recover", audit_dir=str(base))
        assert len(rows) == 1
        assert rows[0]["command"] == "kubectl scale --replicas=0 deploy api"

    def test_reconcile_skips_already_recorded(self, audit_dir):
        rec = _record(execution_id="dup-test-1", incident_id="inc-dup")
        record_command(rec, audit_dir)
        replayed = reconcile_wal(audit_dir)
        assert replayed == 0

    def test_reconcile_handles_missing_wal_dir(self, audit_dir):
        # If WAL dir is missing (e.g. fresh install, never written),
        # reconcile is a no-op. We *create* the WAL dir here, drop
        # one file into it, then remove the entire directory, so the
        # reconcile path is exercised against a directory that was
        # present during record_command but absent during reconcile.
        wal = audit_dir / "audit-wal"
        wal.mkdir(exist_ok=True)
        sample = wal / "sample.json"
        sample.write_text("{}")  # ensure the dir is non-empty before removal
        sample.unlink()
        wal.rmdir()
        assert reconcile_wal(audit_dir) == 0


class TestFetchByIncident:
    def test_returns_empty_for_unknown_incident(self, audit_dir):
        assert fetch_by_incident("never-seen", audit_dir=str(audit_dir)) == []

    def test_returns_empty_when_db_missing(self, tmp_path):
        # fetch_by_incident on a non-existent audit_dir is graceful
        empty_dir = tmp_path / "noaudit"
        empty_dir.mkdir()
        assert fetch_by_incident("anything", audit_dir=str(empty_dir)) == []

    def test_orders_by_timestamp_asc(self, audit_dir):
        for ts in ["2024-01-01T00:00:03Z", "2024-01-01T00:00:01Z", "2024-01-01T00:00:02Z"]:
            rec = _record(
                execution_id=f"order-{ts}",
                incident_id="inc-order",
            )
            object.__setattr__(rec, "timestamp", ts)
            record_command(rec, audit_dir)
        rows = fetch_by_incident("inc-order", audit_dir=str(audit_dir))
        timestamps = [r["timestamp"] for r in rows]
        assert timestamps == sorted(timestamps)


class TestAuditLock:
    def test_lock_file_exists_when_held(self, tmp_path):
        base = tmp_path / "lock-test"
        base.mkdir()
        with audit_lock(base, exclusive=True):
            assert (base / "audit.lock").exists()
            # Manual flock test: the locked file is fd-writable.
            with open(base / "audit.lock", "w") as f:
                f.write("held")

    def test_lock_released_after_exit(self, tmp_path):
        base = tmp_path / "lock-test2"
        base.mkdir()
        with audit_lock(base, exclusive=True):
            pass
        # After exit, lock should be released; another acquirer
        # is able to take it without blocking.
        with audit_lock(base, exclusive=True):
            assert (base / "audit.lock").exists()
