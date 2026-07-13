"""Webhook payload normalization to internal `AlertEvent` dataclass.

Three source-specific normalizers are exported:

  normalize_alertmanager(payload)  Prometheus Alertmanager v2 webhook
  normalize_robusta(payload)       Robusta trigger / finding webhook
  normalize_datadog(payload)       Datadog webhook v1

All three converge on a single `AlertEvent` shape so downstream
diagnostic, report, and (Phase 3) audit subsystems don't branch on
source.

`incident_id` is unified across L1 reports and L2 commands per
DIRECTIONS.md § Phase 2 → § Phase 3 transition. For dedup, two
`AlertEvent`s share an `incident_id` iff:
  - they share the same `source` AND
  - they share the same logical group key
    (Alertmanager `groupKey` / Robusta `id` / Datadog `alert_id`).

This is enforced by `dedup_by_incident_id`, which maps incoming
`AlertEvent`s onto existing open incidents (incident_id reuse) or
new incidents (incident_id mint).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

AlertSource = Literal["alertmanager", "robusta", "datadog"]
AlertSeverity = Literal["critical", "warning", "info"]

DEFAULT_INCIDENT_NAMESPACE_KEYS: tuple[str, ...] = (
    "namespace",
    "kubernetes_namespace",
    "k8s_namespace",
    "ns",
)


@dataclass(frozen=True)
class AlertEvent:
    alert_id: str
    incident_id: str
    source: AlertSource
    severity: AlertSeverity
    labels: dict[str, str]
    annotations: dict[str, str]
    received_at: str
    cluster: str | None = None
    namespace: str | None = None
    diagnostic_report_id: str | None = None

    def with_incident(self, incident_id: str) -> "AlertEvent":
        return AlertEvent(
            alert_id=self.alert_id,
            incident_id=incident_id,
            source=self.source,
            severity=self.severity,
            labels=dict(self.labels),
            annotations=dict(self.annotations),
            received_at=self.received_at,
            cluster=self.cluster,
            namespace=self.namespace,
            diagnostic_report_id=self.diagnostic_report_id,
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_str(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _coerce_labels(payload: dict[str, Any], keys: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            out[key] = value
        elif isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, str):
                    out[k] = v
                elif isinstance(v, (int, float)):
                    out[k] = str(v)
    return out


def _extract_namespace(labels: dict[str, str]) -> str | None:
    for key in DEFAULT_INCIDENT_NAMESPACE_KEYS:
        if key in labels:
            return labels[key]
    return None


def _infer_severity(value: Any) -> AlertSeverity:
    if not isinstance(value, str):
        return "info"
    v = value.strip().lower()
    if v in {"critical", "firing", "error", "alert", "high"}:
        return "critical"
    if v in {"warning", "warn"}:
        return "warning"
    if v in {"info", "informational", "low", "notice", "ok", "recovered"}:
        return "info"
    return "info"


def normalize_alertmanager(payload: dict[str, Any]) -> AlertEvent:
    """Normalize a Prometheus Alertmanager v2 webhook payload.

    The webhook receives `{"version": "4", "groupKey": ..., "alerts": [...]}`.
    Each alert in `alerts` becomes one `AlertEvent`. If multiple alerts share
    the same `groupKey`, callers feed them through `dedup_by_incident_id`
    to share `incident_id`.
    """
    if not isinstance(payload, dict):
        raise ValueError("Alertmanager payload must be a JSON object")

    alerts = payload.get("alerts") or []
    if isinstance(alerts, list) and alerts:
        first = alerts[0]
    elif isinstance(alerts, dict):
        first = alerts
    else:
        first = {}

    labels = _coerce_labels(first, ("labels",))
    annotations = _coerce_labels(first, ("annotations",))
    alert_id = _first_str(first, "fingerprint") or _first_str(
        payload, "groupKey"
    ) or uuid4().hex
    group_key = _first_str(payload, "groupKey") or alert_id
    severity = _infer_severity(
        labels.get("severity") or first.get("status")
    )

    return AlertEvent(
        alert_id=alert_id,
        incident_id=f"am:{group_key}",
        source="alertmanager",
        severity=severity,
        labels=labels,
        annotations=annotations,
        received_at=_first_str(first, "startsAt") or _now_iso(),
        cluster=labels.get("cluster") or _first_str(payload, "externalURL"),
        namespace=_extract_namespace(labels),
    )


def normalize_robusta(payload: dict[str, Any]) -> AlertEvent:
    """Normalize a Robusta trigger / finding webhook payload.

    Robusta's envelope uses `id` as the canonical finding identifier;
    `subject_name` + `subject_type` + `service` collapse into `labels`
    so downstream consumers don't branch on Robusta specifics.
    """
    if not isinstance(payload, dict):
        raise ValueError("Robusta payload must be a JSON object")

    labels = _coerce_labels(payload, ("labels",))
    extra = {
        k: v
        for k, v in {
            "service": _first_str(payload, "service"),
            "subject_type": _first_str(payload, "subject_type"),
            "subject_name": _first_str(payload, "subject_name"),
            "title": _first_str(payload, "title"),
        }.items()
        if v is not None
    }
    labels.update({k: v for k, v in extra.items() if isinstance(v, str)})

    annotations: dict[str, str] = {}
    description = _first_str(payload, "description")
    if description:
        annotations["description"] = description
    runbook = _first_str(payload, "runbook_url") or _first_str(
        payload, "documentation_url"
    )
    if runbook:
        annotations["runbook_url"] = runbook

    alert_id = _first_str(payload, "id") or uuid4().hex
    severity = _infer_severity(payload.get("severity") or payload.get("priority"))

    return AlertEvent(
        alert_id=alert_id,
        incident_id=f"rb:{alert_id}",
        source="robusta",
        severity=severity,
        labels=labels,
        annotations=annotations,
        received_at=_first_str(payload, "timestamp") or _now_iso(),
        cluster=_first_str(payload, "cluster"),
        namespace=_first_str(payload, "namespace")
        or _extract_namespace(labels),
    )


def normalize_datadog(payload: dict[str, Any]) -> AlertEvent:
    """Normalize a Datadog webhook payload.

    Datadog's `tags` field is comma-separated `key:value` pairs that
    become the canonical `labels`. `body` and `snapshot` collapse into
    `annotations`.
    """
    if not isinstance(payload, dict):
        raise ValueError("Datadog payload must be a JSON object")

    labels: dict[str, str] = {}
    tags_raw = payload.get("tags")
    if isinstance(tags_raw, str):
        for entry in tags_raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                k, _, v = entry.partition(":")
                labels[k.strip()] = v.strip()
            else:
                labels[entry] = "true"
    elif isinstance(tags_raw, list):
        for entry in tags_raw:
            if isinstance(entry, str):
                if ":" in entry:
                    k, _, v = entry.partition(":")
                    labels[k.strip()] = v.strip()
                else:
                    labels[entry.strip()] = "true"

    annotations: dict[str, str] = {}
    for src_key in ("body", "snapshot", "message"):
        value = payload.get(src_key)
        if isinstance(value, str) and value:
            annotations[src_key] = value
    link = _first_str(payload, "link")
    if link:
        annotations["link"] = link

    alert_id = _first_str(payload, "alert_id") or _first_str(payload, "id") or uuid4().hex
    severity = _infer_severity(
        payload.get("alert_type") or payload.get("alert_status")
    )

    return AlertEvent(
        alert_id=alert_id,
        incident_id=f"dd:{alert_id}",
        source="datadog",
        severity=severity,
        labels=labels,
        annotations=annotations,
        received_at=_first_str(payload, "date") or _now_iso(),
        cluster=labels.get("cluster") or _first_str(payload, "host"),
        namespace=_extract_namespace(labels),
    )


def normalize_payload(source: AlertSource, payload: dict[str, Any]) -> AlertEvent:
    """Dispatch to the source-specific normalizer."""
    if source == "alertmanager":
        return normalize_alertmanager(payload)
    if source == "robusta":
        return normalize_robusta(payload)
    if source == "datadog":
        return normalize_datadog(payload)
    raise ValueError(f"Unknown alert source: {source!r}")


@dataclass
class _IncidentRegistry:
    open_incidents: dict[tuple[AlertSource, str], str] = field(default_factory=dict)
    closed_incidents: dict[tuple[AlertSource, str], str] = field(default_factory=dict)

    def resolve(
        self, event: AlertEvent, allow_reopen: bool = False
    ) -> AlertEvent:
        key = (event.source, event.incident_id.removeprefix(f"{event.source}:"))
        if key in self.open_incidents:
            return event.with_incident(self.open_incidents[key])
        if key in self.closed_incidents:
            if allow_reopen:
                incident_id = self.closed_incidents[key]
                del self.closed_incidents[key]
                self.open_incidents[key] = incident_id
                return event.with_incident(incident_id)
            return event.with_incident(f"{event.source}:{uuid4().hex}")
        self.open_incidents[key] = event.incident_id
        return event.with_incident(event.incident_id)

    def close(self, incident_id: str) -> None:
        for key, value in list(self.open_incidents.items()):
            if value == incident_id:
                del self.open_incidents[key]
                self.closed_incidents[key] = value
                return


_DEFAULT_REGISTRY = _IncidentRegistry()


def dedup_by_incident_id(
    event: AlertEvent,
    registry: _IncidentRegistry | None = None,
    allow_reopen: bool = False,
) -> tuple[AlertEvent, _IncidentRegistry]:
    """Resolve `event` against an incident registry and return the event with
    a canonical incident_id (potentially reusing an existing one).

    If `registry` is None, a module-level default is used so that
    follow-up webhooks in the same process automatically share dedup
    state. Tests that need isolation should pass an explicit
    `_IncidentRegistry()` instance.

    `allow_reopen=True` reuses an existing incident_id even after the
    previous incident was closed via `registry.close(...)`. Default
    is False — closed incidents stay closed; matching alerts get a
    fresh incident_id.
    """
    if registry is None:
        registry = _DEFAULT_REGISTRY
    return registry.resolve(event, allow_reopen=allow_reopen), registry
