"""Tests for incident_id dedup across webhooks.

DIRECTIONS.md § Phase 2 测试:
"tests/test_alert_dedup.py — 同 group_key alert 在 incident 关闭前
不起新诊断,追加到原 incident_id 下的新 alert_events 记录"

The dedup registry groups alerts by `(source, group_key)` and reuses
the same `incident_id` for follow-up alerts. Same-source same-key
firing alerts → 1 incident. Different-source or different-key →
different incidents.
"""

from rig.alert.intake import (
    _IncidentRegistry,
    dedup_by_incident_id,
    normalize_alertmanager,
    normalize_datadog,
    normalize_robusta,
)


def _am(group_key: str = "g1:KubePodCrashLooping", fingerprint: str = "fp-1") -> dict:
    return {
        "groupKey": group_key,
        "alerts": [
            {
                "status": "firing",
                "fingerprint": fingerprint,
                "labels": {"alertname": "KubePodCrashLooping",
                           "namespace": "production",
                           "severity": "critical"},
                "annotations": {},
                "startsAt": "2024-01-01T00:00:00Z",
            }
        ],
    }


def _rb(rid: str = "f-1") -> dict:
    return {
        "id": rid,
        "severity": "warning",
        "service": "svc",
        "namespace": "production",
        "subject_type": "pod",
        "subject_name": "p1",
    }


def _dd(alert_id: str = "dd-1") -> dict:
    return {
        "alert_id": alert_id,
        "alert_type": "error",
        "tags": "namespace:production",
    }


class TestDedupRegistry:
    def test_first_alert_creates_incident(self):
        e = normalize_alertmanager(_am())
        resolved, registry = dedup_by_incident_id(e)
        assert resolved.incident_id == e.incident_id
        assert (e.source, e.incident_id.removeprefix(f"{e.source}:")
                ) in registry.open_incidents

    def test_same_source_same_key_reuses_incident_id(self):
        e1 = normalize_alertmanager(_am())
        e2 = normalize_alertmanager(_am("g1:KubePodCrashLooping", "fp-2"))
        _, registry = dedup_by_incident_id(e1)
        e2_resolved, _ = dedup_by_incident_id(e2, registry)
        assert e2_resolved.incident_id == e1.incident_id

    def test_same_source_different_key_different_incident(self):
        e1 = normalize_alertmanager(_am("k1:KPC"))
        e2 = normalize_alertmanager(_am("k2:KPC"))
        e1r, registry = dedup_by_incident_id(e1)
        e2r, _ = dedup_by_incident_id(e2, registry)
        assert e1r.incident_id != e2r.incident_id

    def test_different_source_same_logical_group_different_incident(self):
        # Alertmanager group "g1" vs Robusta finding "f-1" should NOT
        # collide on dedup; only same-source same-key collapses.
        e1 = normalize_alertmanager(_am("g1"))
        e2 = normalize_robusta(_rb("g1"))
        e1r, registry = dedup_by_incident_id(e1)
        e2r, _ = dedup_by_incident_id(e2, registry)
        assert e1r.incident_id != e2r.incident_id

    def test_closed_incident_does_not_dedupe_by_default(self):
        e = normalize_alertmanager(_am())
        _, registry = dedup_by_incident_id(e)
        registry.close(e.incident_id)
        # Explicit registry threading required (module-level default
        # would carry state across tests).
        e2, _ = dedup_by_incident_id(e, registry)
        assert e2.incident_id != e.incident_id

    def test_close_then_reopen_reuses_incident_id(self):
        registry = _IncidentRegistry()
        e = normalize_alertmanager(_am())
        e1r, _ = dedup_by_incident_id(e, registry)
        registry.close(e1r.incident_id)
        # Calling dedup on the SAME `e` with allow_reopen=True after
        # close should reuse the original (now-closed) incident_id.
        reopened, _ = dedup_by_incident_id(e, registry, allow_reopen=True)
        assert reopened.incident_id == e1r.incident_id

    def test_three_followups_share_incident_id(self):
        e1 = normalize_alertmanager(_am("g1", "fp-1"))
        e2 = normalize_alertmanager(_am("g1", "fp-2"))
        e3 = normalize_alertmanager(_am("g1", "fp-3"))
        e4 = normalize_alertmanager(_am("g1", "fp-4"))
        e1r, registry = dedup_by_incident_id(e1)
        e2r, _ = dedup_by_incident_id(e2, registry)
        e3r, _ = dedup_by_incident_id(e3, registry)
        e4r, _ = dedup_by_incident_id(e4, registry)
        assert e1r.incident_id == e2r.incident_id == e3r.incident_id == e4r.incident_id

    def test_independent_datadog_incidents(self):
        e1 = normalize_datadog(_dd("dd-1"))
        e2 = normalize_datadog(_dd("dd-2"))
        e1r, registry = dedup_by_incident_id(e1)
        e2r, _ = dedup_by_incident_id(e2, registry)
        assert e1r.incident_id != e2r.incident_id

    def test_empty_registry_passes_through(self):
        empty = _IncidentRegistry()
        e = normalize_alertmanager(_am())
        resolved, _ = dedup_by_incident_id(e, empty)
        assert resolved.incident_id == e.incident_id
