-- Audit log table (DIRECTIONS.md § Phase 3).
--
-- Applied by `init_db` in `rig/audit/writer.py`. SQLite-flavored
-- (UUID stored as TEXT, JSON serialized as TEXT). Migrated via
-- alembic per DIRECTIONS.md § Phase 3 § writer.py directive.
--
-- Schema version: see `rig/audit/writer.py:_SCHEMA_VERSION`.
-- Bump _SCHEMA_VERSION and add an alembic revision when changing
-- column types.

CREATE TABLE IF NOT EXISTS audit_log (
    execution_id      TEXT PRIMARY KEY,
    incident_id       TEXT,
    timestamp         TEXT NOT NULL,
    user              TEXT NOT NULL,
    command           TEXT NOT NULL,
    command_type      TEXT NOT NULL CHECK (command_type IN ('kubectl', 'helm', 'shell')),
    deny_reason       TEXT,
    approved_by       TEXT NOT NULL,
    required_approvals INTEGER NOT NULL,
    stdout            TEXT,
    stderr            TEXT,
    exit_code         INTEGER,
    rollback_id       TEXT,
    cluster           TEXT,
    namespace         TEXT
);

CREATE INDEX IF NOT EXISTS idx_incident ON audit_log (incident_id);
CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_user ON audit_log (user);

CREATE TABLE IF NOT EXISTS audit_wal_reconcile (
    execution_id  TEXT PRIMARY KEY,
    wal_path      TEXT NOT NULL,
    recorded_at   TEXT NOT NULL
);
