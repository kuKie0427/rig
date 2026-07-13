"""Audit log subsystem (DIRECTIONS.md § Phase 3).

Layered:
  schema.sql              audit_log table.
  schema.py              SCHEMA_SQL loader.
  writer.py              AuditRecord dataclass + record_command +
                          reconcile_wal + fetch_by_incident. SQLite +
                          WAL dual-write per DIRECTIONS.md § Phase 3.
  replay.py              Per-incident decision-tree reconstruction
                          (library API + module CLI).

Public surface re-exported here is what downstream code (Phase 2
diagnostic's `l1_violations` linkage, Phase 4 profiles' audit hooks)
imports.
"""

from .replay import replay, to_markdown
from .writer import (
    SCHEMA_VERSION,
    AuditRecord,
    CommandType,
    audit_lock,
    default_audit_dir,
    default_db_path,
    default_wal_dir,
    fetch_by_incident,
    init_db,
    reconcile_wal,
    record_command,
)

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
    "replay",
    "to_markdown",
]
