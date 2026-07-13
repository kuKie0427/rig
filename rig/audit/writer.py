"""Audit log writer (DIRECTIONS.md § Phase 3).

Three layers:

  Schema                 alert_log table (see `schema.sql`).
  Migration (alembic)    `rig/audit/migrations/` — schema versions.
  Dual-write             SQLite primary (audit.db in `~/.rig/`)
                         + JSON WAL file (`~/.rig/audit-wal/<exec>.json`)
                         for crash recovery.

Concurrency model per DIRECTIONS.md open question 1 (selected
"SQLite BEGIN IMMEDIATE row lock"):

  * Same-process writes: serialize via `BEGIN IMMEDIATE`; one writer
    in flight at a time per process.
  * Multi-process safety: an `flock`-style `<audit_dir>/.lock`
    file guards `audit.db` across processes; first process to hold
    the lock owns the canonical SQLite.

A read-only `replay_by_incident(incident_id)` helper reconstructs the
per-incident command list for `rig replay` (Phase 3 § replay.py).
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .schema import SCHEMA_SQL

logger = logging.getLogger(__name__)

CommandType = Literal["kubectl", "helm", "shell"]

SCHEMA_VERSION = 1

_DEFAULT_AUDIT_DIR = Path.home() / ".rig"
_DEFAULT_DB_PATH = _DEFAULT_AUDIT_DIR / "audit.db"
_DEFAULT_WAL_DIR = _DEFAULT_AUDIT_DIR / "audit-wal"
_LOCK_FILE = "audit.lock"


@dataclass(frozen=True)
class AuditRecord:
    execution_id: str
    timestamp: str
    user: str
    command: str
    command_type: CommandType
    deny_reason: str | None
    approved_by: list[str]
    required_approvals: int
    incident_id: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    rollback_id: str | None = None
    cluster: str | None = None
    namespace: str | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_audit_dir() -> Path:
    return Path(os.environ.get("RIG_AUDIT_DIR") or _DEFAULT_AUDIT_DIR)


def default_db_path(audit_dir: Path | None = None) -> Path:
    return (audit_dir or default_audit_dir()) / "audit.db"


def default_wal_dir(audit_dir: Path | None = None) -> Path:
    return (audit_dir or default_audit_dir()) / "audit-wal"


def _audit_lock_path(audit_dir: Path) -> Path:
    return audit_dir / _LOCK_FILE


@contextmanager
def audit_lock(audit_dir: Path | None = None, exclusive: bool = True):
    """Multi-process advisory lock over the audit dir.

    `exclusive=True` (default) is for writers; `exclusive=False` for
    readers (Phase 3.5). The lock is auto-released on context exit
    or process death (flock semantics).
    """
    path = _audit_lock_path(audit_dir or default_audit_dir())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def init_db(audit_dir: Path | None = None) -> Path:
    """Apply schema.sql. Idempotent via CREATE TABLE IF NOT EXISTS.

    Returns the resolved audit directory.
    """
    base = audit_dir or default_audit_dir()
    base.mkdir(parents=True, exist_ok=True)
    db_path = base / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_schema_version ("
            "  version INTEGER PRIMARY KEY,"
            "  applied_at TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT OR IGNORE INTO audit_schema_version (version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, _now_iso()),
        )
        conn.commit()
    return base


def _wal_path_for(execution_id: str, wal_dir: Path) -> Path:
    return wal_dir / f"{execution_id}.json"


def record_command(record: AuditRecord, audit_dir: Path | None = None) -> Path:
    """Persist a command decision. SQLite is the primary store; the
    WAL JSON file is the crash-recovery fallback.

    Returns the resolved WAL file path (the SQLite `audit.db` lives at
    `audit_dir / "audit.db"` — call sites only need the WAL path for
    logging / Phase 3 replay input).
    """
    base = audit_dir or default_audit_dir()
    base.mkdir(parents=True, exist_ok=True)
    wal_dir = base / "audit-wal"
    wal_dir.mkdir(exist_ok=True)
    wal_path = _wal_path_for(record.execution_id, wal_dir)

    payload = asdict(record)
    wal_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    db_path = base / "audit.db"
    with audit_lock(base, exclusive=True):
        _ensure_schema(db_path)
        try:
            _insert_or_replace(db_path, record)
        except sqlite3.IntegrityError:
            logger.warning(
                "execution_id %s already in audit_log; replaying WAL file only",
                record.execution_id,
            )
    return wal_path


def _ensure_schema(db_path: Path) -> None:
    """Apply schema.sql to an existing db file (idempotent)."""
    if db_path.exists():
        with sqlite3.connect(db_path) as conn:
            already = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
            ).fetchone()
        if already is not None:
            return
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()


def _insert_or_replace(db_path: Path, record: AuditRecord) -> None:
    """Atomic single-row insert. SQLite `BEGIN IMMEDIATE` per
    DIRECTIONS.md § Phase 3 open-question 1 to serialize
    same-process writers; multi-process safety is via `audit_lock`.
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """
                INSERT INTO audit_log (
                    execution_id, incident_id, timestamp, user, command,
                    command_type, deny_reason, approved_by,
                    required_approvals, stdout, stderr, exit_code,
                    rollback_id, cluster, namespace
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(execution_id) DO UPDATE SET
                    incident_id = excluded.incident_id,
                    timestamp = excluded.timestamp,
                    user = excluded.user,
                    command = excluded.command,
                    command_type = excluded.command_type,
                    deny_reason = excluded.deny_reason,
                    approved_by = excluded.approved_by,
                    required_approvals = excluded.required_approvals,
                    stdout = COALESCE(excluded.stdout, audit_log.stdout),
                    stderr = COALESCE(excluded.stderr, audit_log.stderr),
                    exit_code = excluded.exit_code,
                    rollback_id = excluded.rollback_id,
                    cluster = excluded.cluster,
                    namespace = excluded.namespace
                """,
                (
                    record.execution_id,
                    record.incident_id,
                    record.timestamp,
                    record.user,
                    record.command,
                    record.command_type,
                    record.deny_reason,
                    json.dumps(record.approved_by),
                    record.required_approvals,
                    record.stdout,
                    record.stderr,
                    record.exit_code,
                    record.rollback_id,
                    record.cluster,
                    record.namespace,
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_wal_reconcile
                  (execution_id, wal_path, recorded_at)
                VALUES (?, ?, ?)
                """,
                (record.execution_id, str(wal_path_for_reconcile(record.execution_id)), _now_iso()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def wal_path_for_reconcile(execution_id: str) -> Path:
    """Symmetric helper used by `_insert_or_replace` to record the
    WAL file path (logical view, not the actual file system path
    used in this invocation).
    """
    return default_wal_dir() / f"{execution_id}.json"


def reconcile_wal(audit_dir: Path | None = None) -> int:
    """Replay any WAL files not yet in audit_log. Returns count."""
    base = audit_dir or default_audit_dir()
    db_path = base / "audit.db"
    wal_dir = base / "audit-wal"
    if not wal_dir.exists():
        return 0
    if not db_path.exists():
        init_db(base)
    replayed = 0
    with audit_lock(base, exclusive=True):
        _ensure_schema(db_path)
        for wal_path in sorted(wal_dir.glob("*.json")):
            try:
                payload = json.loads(wal_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed WAL %s: %s", wal_path, exc)
                continue
            try:
                record = AuditRecord(**payload)
            except TypeError as exc:
                logger.warning("Skipping incompatible WAL %s: %s", wal_path, exc)
                continue
            with sqlite3.connect(db_path) as conn:
                exists = conn.execute(
                    "SELECT 1 FROM audit_log WHERE execution_id = ?",
                    (record.execution_id,),
                ).fetchone()
            if exists:
                continue
            _insert_or_replace(db_path, record)
            replayed += 1
    return replayed


def fetch_by_incident(
    incident_id: str, audit_dir: str | Path | None = None
) -> list[dict[str, Any]]:
    """Return all audit_log rows for an incident, ordered by timestamp.

    Used by `rig replay` to rebuild the per-incident command trace.
    """
    base = Path(audit_dir) if audit_dir else default_audit_dir()
    db_path = base / "audit.db"
    if not db_path.exists():
        return []
    with audit_lock(base, exclusive=False), sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT execution_id, timestamp, user, command, command_type,
                   deny_reason, approved_by, required_approvals,
                   stdout, stderr, exit_code, rollback_id,
                   cluster, namespace
            FROM audit_log
            WHERE incident_id = ?
            ORDER BY timestamp ASC
            """,
            (incident_id,),
        ).fetchall()
    return [
        {
            "execution_id": r[0],
            "timestamp": r[1],
            "user": r[2],
            "command": r[3],
            "command_type": r[4],
            "deny_reason": r[5],
            "approved_by": json.loads(r[6]) if r[6] else [],
            "required_approvals": r[7],
            "stdout": r[8],
            "stderr": r[9],
            "exit_code": r[10],
            "rollback_id": r[11],
            "cluster": r[12],
            "namespace": r[13],
        }
        for r in rows
    ]


__all__ = [
    "AuditRecord",
    "CommandType",
    "SCHEMA_VERSION",
    "audit_lock",
    "default_audit_dir",
    "default_db_path",
    "default_wal_dir",
    "fetch_by_incident",
    "init_db",
    "record_command",
    "reconcile_wal",
]
