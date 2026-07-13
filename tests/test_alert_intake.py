"""Tests for `rig.alert.intake` — webhook payload normalization."""

import pytest

from rig.alert.intake import (
    DEFAULT_INCIDENT_NAMESPACE_KEYS,
    normalize_alertmanager,
    normalize_datadog,
    normalize_payload,
    normalize_robusta,
)

AM_PAYLOAD = {
    "version": "4",
    "groupKey": "abc123:KubePodCrashLooping",
    "receiver": "rig",
    "externalURL": "http://alertmanager.example",
    "alerts": [
        {
            "status": "firing",
            "fingerprint": "deadbeef",
            "labels": {
                "alertname": "KubePodCrashLooping",
                "namespace": "production",
                "pod": "my-app-7f8d9-mk4xp",
                "severity": "critical",
                "cluster": "k8s-prod",
            },
            "annotations": {
                "summary": "pod crash-looping",
                "runbook_url": "https://runbooks.example/kpc",
            },
            "startsAt": "2024-01-01T00:00:00Z",
        }
    ],
}


RB_PAYLOAD = {
    "id": "finding-42",
    "type": "issue",
    "title": "HighMemory",
    "service": "my-api",
    "subject_type": "pod",
    "subject_name": "my-pod-y",
    "namespace": "staging",
    "cluster": "k8s-staging",
    "severity": "warning",
    "description": "my-pod-y memory usage > 90% for 5 minutes",
    "runbook_url": "https://runbooks.example/high-mem",
    "firing": True,
    "timestamp": "2024-01-01T00:00:00Z",
}


DD_PAYLOAD = {
    "alert_id": "dd-007",
    "alert_type": "error",
    "alert_status": "Triggered",
    "title": "K8s pod down",
    "body": "pod my-app-x is crash-looping",
    "tags": "namespace:production,pod:my-app-x,cluster:k8s-prod",
    "link": "https://app.datadoghq.com/event/123",
    "date": "2024-01-01T00:00:00Z",
    "host": "k8s-prod",
}


class TestNormalizeAlertmanager:
    def test_basic_alert_extracted(self):
        event = normalize_alertmanager(AM_PAYLOAD)
        assert event.source == "alertmanager"
        assert event.severity == "critical"
        assert event.namespace == "production"
        assert event.labels["pod"] == "my-app-7f8d9-mk4xp"
        assert event.labels["cluster"] == "k8s-prod"
        assert event.annotations["runbook_url"] == "https://runbooks.example/kpc"
        assert event.alert_id == "deadbeef"
        assert event.incident_id.startswith("am:")
        assert "abc123:KubePodCrashLooping" in event.incident_id

    def test_received_at_uses_starts_at(self):
        event = normalize_alertmanager(AM_PAYLOAD)
        assert event.received_at == "2024-01-01T00:00:00Z"

    def test_severity_warning_propagates(self):
        payload = dict(AM_PAYLOAD)
        payload["alerts"] = [
            {
                "status": "firing",
                "fingerprint": "x",
                "labels": {"alertname": "y", "severity": "warning"},
                "annotations": {},
                "startsAt": "2024-01-01T00:00:00Z",
            }
        ]
        event = normalize_alertmanager(payload)
        assert event.severity == "warning"

    def test_malformed_payload_raises(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            normalize_alertmanager("not a dict")  # type: ignore[arg-type]

    def test_empty_alerts_list_handles_gracefully(self):
        payload = dict(AM_PAYLOAD)
        payload["alerts"] = []
        event = normalize_alertmanager(payload)
        assert event.source == "alertmanager"
        assert event.labels == {}
        assert event.alert_id  # has fallback uuid


class TestNormalizeRobusta:
    def test_basic_finding_extracted(self):
        event = normalize_robusta(RB_PAYLOAD)
        assert event.source == "robusta"
        assert event.severity == "warning"
        assert event.namespace == "staging"
        assert event.labels["service"] == "my-api"
        assert event.labels["subject_type"] == "pod"
        assert event.labels["subject_name"] == "my-pod-y"
        assert event.annotations["description"].startswith("my-pod-y memory")
        assert event.annotations["runbook_url"].startswith("https://")
        assert event.alert_id == "finding-42"
        assert event.incident_id.startswith("rb:")

    def test_malformed_payload_raises(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            normalize_robusta("nope")  # type: ignore[arg-type]


class TestNormalizeDatadog:
    def test_basic_alert_extracted(self):
        event = normalize_datadog(DD_PAYLOAD)
        assert event.source == "datadog"
        assert event.severity == "critical"
        assert event.namespace == "production"
        assert event.labels["pod"] == "my-app-x"
        assert event.labels["cluster"] == "k8s-prod"
        assert event.annotations["body"].startswith("pod my-app-x")
        assert event.annotations["link"].startswith("https://app.datadoghq.com")
        assert event.alert_id == "dd-007"
        assert event.incident_id.startswith("dd:")

    def test_tags_parsing_strips_whitespace(self):
        payload = dict(DD_PAYLOAD)
        payload["tags"] = " namespace:prod , pod:foo ,extra"
        event = normalize_datadog(payload)
        assert event.labels["namespace"] == "prod"
        assert event.labels["pod"] == "foo"
        assert "extra" in event.labels

    def test_alert_status_recovered(self):
        payload = dict(DD_PAYLOAD)
        payload["alert_type"] = "info"
        payload["alert_status"] = "Recovered"
        event = normalize_datadog(payload)
        assert event.severity == "info"

    def test_malformed_payload_raises(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            normalize_datadog([1, 2, 3])  # type: ignore[arg-type]


class TestNormalizeDispatch:
    def test_dispatch_by_source(self):
        assert normalize_payload("alertmanager", AM_PAYLOAD).source == "alertmanager"
        assert normalize_payload("robusta", RB_PAYLOAD).source == "robusta"
        assert normalize_payload("datadog", DD_PAYLOAD).source == "datadog"

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="Unknown alert source"):
            normalize_payload("prometheus", AM_PAYLOAD)  # type: ignore[arg-type]


class TestAlertEventInvariants:
    def test_default_namespace_keys_contains_namespace(self):
        assert "namespace" in DEFAULT_INCIDENT_NAMESPACE_KEYS
        assert "ns" in DEFAULT_INCIDENT_NAMESPACE_KEYS
