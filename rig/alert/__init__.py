"""L1 alert intake and diagnostic subsystem.

Phase 2 of DIRECTIONS.md. Three responsibilities:

  intake.py       Webhook payload → internal AlertEvent normalization
                  (3 source-specific normalizers + incident_id dedup).
  diagnostic.py   LLM-driven read-only diagnosis gated by
                  k8s_validation.allowlist (double-check); L1_violation
                  downgrade to L2 queue.
  report.py       Multi-channel distribution of the diagnostic report:
                  chat SSE / Slack webhook / SMTP / PagerDuty incident notes.

Scope is HARD-locked per DIRECTIONS.md § Phase 2:
  - ✅ do: webhook intake, read-only diagnosis, report gen,
           multi-channel distribute, suggested_next_steps → L2.
  - ❌ don't: K8s API watcher / Prometheus query / time-series
           anomaly / root-cause correlation / any-fix auto-execution
           / alert priority / silence management.

Phase 3 (audit log + replay) consumes the `incident_id` field
unified across L1 reports and L2 commands. Phase 1's
k8s_validation.allowlist is the L1 allowlist source — L1 diagnostic
LLM commands and L2 daily-engineer commands share the SAME allowlist,
not two separate lists.
"""

from .diagnostic import (
    CommandRun,
    DiagnosticReport,
    L1Violation,
    init_db,
    record_alert,
    record_diagnostic_report,
    record_violation,
    run_diagnostic,
    run_diagnostic_with_plan,
)
from .intake import (
    DEFAULT_INCIDENT_NAMESPACE_KEYS,
    AlertEvent,
    AlertSeverity,
    AlertSource,
    dedup_by_incident_id,
    normalize_alertmanager,
    normalize_datadog,
    normalize_payload,
    normalize_robusta,
)
from .report import (
    ReportChannel,
    chat_buffer_snapshot,
    emit_to_chat,
    emit_to_email,
    emit_to_pagerduty,
    emit_to_slack,
    reset_chat_buffer,
)

__all__ = [
    "AlertEvent",
    "AlertSeverity",
    "AlertSource",
    "CommandRun",
    "DEFAULT_INCIDENT_NAMESPACE_KEYS",
    "DiagnosticReport",
    "L1Violation",
    "ReportChannel",
    "chat_buffer_snapshot",
    "dedup_by_incident_id",
    "emit_to_chat",
    "emit_to_email",
    "emit_to_pagerduty",
    "emit_to_slack",
    "init_db",
    "normalize_alertmanager",
    "normalize_datadog",
    "normalize_payload",
    "normalize_robusta",
    "record_alert",
    "record_diagnostic_report",
    "record_violation",
    "reset_chat_buffer",
    "run_diagnostic",
    "run_diagnostic_with_plan",
]
