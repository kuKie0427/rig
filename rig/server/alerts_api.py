"""L1 alert webhook intake (Phase 2 of DIRECTIONS.md).

Three endpoints, one per upstream source:

  POST /api/alerts/alertmanager   Prometheus Alertmanager v2 webhook
  POST /api/alerts/robusta        Robusta trigger / finding webhook
  POST /api/alerts/datadog        Datadog webhook v1

Each endpoint:
  1. Validates the JSON payload (malformed → 400).
  2. Routes through `rig.alert.intake.normalize_*()` → AlertEvent.
  3. Passes the event through `rig.alert.diagnostic.run_diagnostic`.
  4. Persists the alert + report to the L1 store (SQLite at
     `~/.rig/alert.db` by default; configurable via env).
  5. Multi-channel emit (chat, Slack, email, PagerDuty) per
     `rig.alert.report` (skipped when env not configured).
  6. Returns 202 Accepted with `{alert_id, incident_id,
     report_id, violations: [...]}`. The 202 documents the
     "diagnostic is in flight / queued" semantics — actual stdout
     capture and Phase 3 audit_log persistence happen asynchronously.

Auth: webhook endpoints are deliberately unauthenticated for Phase 2
(per the L1 intake scope HARD-lock in DIRECTIONS.md § Phase 2).
Phase 3 may add HMAC validation or a shared secret per source.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import flask

from ..alert.diagnostic import (
    DiagnosticReport,
    init_db,
    record_alert,
    run_diagnostic,
)
from ..alert.intake import (
    AlertEvent,
    AlertSource,
    dedup_by_incident_id,
    normalize_payload,
)
from ..alert.report import (
    emit_to_chat,
    emit_to_email,
    emit_to_pagerduty,
    emit_to_slack,
)

logger = logging.getLogger(__name__)

alerts_api = flask.Blueprint("alerts_api", __name__)

_DEFAULT_DB_PATH = Path.home() / ".rig" / "alert.db"


def _resolve_db_path() -> Path | None:
    """Look up the SQLite path from env or fall back to default.

    Returns None if explicitly disabled via `RIG_ALERT_DB_DISABLED=1`
    — useful for test runners that don't want filesystem artifacts.
    """
    if os.environ.get("RIG_ALERT_DB_DISABLED") == "1":
        return None
    override = os.environ.get("RIG_ALERT_DB_PATH")
    return Path(override) if override else _DEFAULT_DB_PATH


def _resolve_db() -> Path | None:
    db_path = _resolve_db_path()
    if db_path is not None and not db_path.exists():
        try:
            init_db(db_path)
        except OSError as exc:
            logger.warning(
                "Cannot initialise alert DB at %s: %s", db_path, exc
            )
            return None
    return db_path


def _diagnose(event: AlertEvent, raw: dict[str, Any]) -> DiagnosticReport | None:
    """Run the diagnostic flow on `event` and persist. Returns the
    report (or None if persistence / LLM is disabled in test mode).
    """
    db_path = _resolve_db()
    if db_path is not None:
        try:
            record_alert(db_path, event, raw_payload=raw)
        except OSError as exc:
            logger.warning(
                "Failed to record alert %s: %s", event.alert_id, exc
            )
    try:
        report = run_diagnostic(event, db_path=db_path)
    except Exception as exc:
        logger.exception("run_diagnostic failed for %s: %s", event.alert_id, exc)
        return None
    return report


def _broadcast(event: AlertEvent, report: DiagnosticReport | None) -> dict[str, bool]:
    return {
        "chat": emit_to_chat(report or event),
        "slack": emit_to_slack(report or event),
        "email": emit_to_email(report or event),
        "pagerduty": emit_to_pagerduty(report or event),
    }


def _intake(source: AlertSource):
    """Shared body: parse payload, dedupe, diagnose, broadcast."""
    payload = flask.request.get_json(silent=True)
    if payload is None:
        return flask.jsonify(
            {"error": "expected application/json body"}
        ), 400
    if not isinstance(payload, dict):
        return flask.jsonify({"error": "body must be a JSON object"}), 400

    try:
        event = normalize_payload(source, payload)
    except ValueError as exc:
        return flask.jsonify({"error": str(exc)}), 400

    deduped, _registry = dedup_by_incident_id(event)
    report = _diagnose(deduped, payload)
    broadcast = _broadcast(deduped, report)

    return flask.jsonify(
        {
            "alert_id": deduped.alert_id,
            "incident_id": deduped.incident_id,
            "source": deduped.source,
            "severity": deduped.severity,
            "report_id": report.report_id if report else None,
            "violations": [
                {
                    "cmd": v.proposed_command,
                    "deny_dimension": v.decision.deny_dimension,
                    "risk_level": v.decision.risk_level,
                }
                for v in (report.violations if report else [])
            ],
            "commands_run": [r.command for r in (report.commands_run if report else [])],
            "channels": broadcast,
        }
    ), 202


@alerts_api.post("/api/alerts/alertmanager")
def alertmanager_webhook():
    return _intake("alertmanager")


@alerts_api.post("/api/alerts/robusta")
def robusta_webhook():
    return _intake("robusta")


@alerts_api.post("/api/alerts/datadog")
def datadog_webhook():
    return _intake("datadog")


__all__ = [
    "alerts_api",
]
