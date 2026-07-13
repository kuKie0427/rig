-- L1 alert + diagnostic-report schema (DIRECTIONS.md § Phase 2).
--
-- Applied by `init_db` in `rig/alert/diagnostic.py` when a process
-- starts. SQLite-flavored DDL — Postgres compatible modulo TEXT
-- column type substitutions (Phase 3 may upgrade storage).
--
-- Schema version is locked at this file's mtime. Bump the index
-- name and add a migration before changing column types.

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id              TEXT PRIMARY KEY,
    incident_id           TEXT NOT NULL,
    source                TEXT NOT NULL,
    severity              TEXT NOT NULL,
    labels_json           TEXT NOT NULL,
    annotations_json      TEXT NOT NULL,
    received_at           TEXT NOT NULL,
    diagnostic_report_id  TEXT,
    cluster               TEXT,
    namespace             TEXT,
    raw_payload_json      TEXT
);

CREATE INDEX IF NOT EXISTS idx_incident_alert
    ON alert_events (incident_id);

CREATE INDEX IF NOT EXISTS idx_alert_source_group
    ON alert_events (source, alert_id);

CREATE TABLE IF NOT EXISTS diagnostic_reports (
    report_id              TEXT PRIMARY KEY,
    alert_id               TEXT NOT NULL,
    incident_id            TEXT NOT NULL,
    generated_at           TEXT NOT NULL,
    commands_run_json      TEXT NOT NULL,
    summary                TEXT NOT NULL,
    suggested_next_steps_json TEXT NOT NULL,
    llm_model              TEXT NOT NULL,
    prompt_text            TEXT,
    disclaimer             TEXT NOT NULL DEFAULT '模型生成,可能不准'
);

CREATE INDEX IF NOT EXISTS idx_incident_report
    ON diagnostic_reports (incident_id);

CREATE TABLE IF NOT EXISTS l1_violations (
    violation_id           TEXT PRIMARY KEY,
    alert_id               TEXT NOT NULL,
    incident_id            TEXT NOT NULL,
    detected_at            TEXT NOT NULL,
    proposed_command       TEXT NOT NULL,
    deny_dimension         TEXT,
    matched_text           TEXT,
    risk_level             TEXT,
    reason                 TEXT
);

CREATE INDEX IF NOT EXISTS idx_violation_incident
    ON l1_violations (incident_id);
