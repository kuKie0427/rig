"""Tests for `rig.alert.report` — multi-channel emit layer."""

from rig.alert.intake import AlertEvent
from rig.alert.report import (
    chat_buffer_snapshot,
    emit_to_chat,
    emit_to_email,
    emit_to_pagerduty,
    emit_to_slack,
    reset_chat_buffer,
)


def _event() -> AlertEvent:
    return AlertEvent(
        alert_id="evt-x",
        incident_id="am:x",
        source="alertmanager",
        severity="critical",
        labels={"namespace": "production"},
        annotations={"summary": "pod crash-looping"},
        received_at="2024-01-01T00:00:00Z",
        cluster="k8s-prod",
        namespace="production",
    )


class TestEmitToChat:
    def setup_method(self):
        reset_chat_buffer()

    def test_chat_buffer_appends(self):
        ev = _event()
        ok = emit_to_chat(ev)
        assert ok is True
        snap = chat_buffer_snapshot()
        assert len(snap) == 1
        assert snap[0]["alert_id"] == "evt-x"
        assert snap[0]["incident_id"] == "am:x"
        assert "evt-x" in snap[0]["summary"] or "pod" in snap[0]["summary"].lower()

    def test_chat_buffer_overflow_drops_oldest(self):
        from rig.alert.report import CHAT_BUFFER_LIMIT
        for i in range(CHAT_BUFFER_LIMIT + 5):
            ev = AlertEvent(
                alert_id=f"evt-{i}",
                incident_id="am:overflow",
                source="alertmanager",
                severity="info",
                labels={},
                annotations={},
                received_at="2024-01-01T00:00:00Z",
            )
            emit_to_chat(ev)
        snap = chat_buffer_snapshot()
        assert len(snap) == CHAT_BUFFER_LIMIT
        assert snap[0]["alert_id"] == "evt-5"
        assert snap[-1]["alert_id"] == f"evt-{CHAT_BUFFER_LIMIT + 5 - 1}"

    def test_reset_clears(self):
        emit_to_chat(_event())
        reset_chat_buffer()
        assert chat_buffer_snapshot() == []


class TestEmitToSlack:
    def test_no_webhook_returns_false(self, monkeypatch):
        monkeypatch.delenv("RIG_SLACK_WEBHOOK", raising=False)
        assert emit_to_slack(_event()) is False

    def test_unreachable_webhook_returns_false(self, monkeypatch):
        monkeypatch.setenv(
            "RIG_SLACK_WEBHOOK", "http://127.0.0.1:1/never-listening"
        )
        assert emit_to_slack(_event()) is False


class TestEmitToEmail:
    def test_missing_env_returns_false(self, monkeypatch):
        for key in ("RIG_SMTP_HOST", "RIG_SMTP_USER", "RIG_SMTP_PASSWORD",
                    "RIG_SMTP_FROM", "RIG_SMTP_TO"):
            monkeypatch.delenv(key, raising=False)
        assert emit_to_email(_event()) is False

    def test_unreachable_smtp_returns_false(self, monkeypatch):
        monkeypatch.setenv("RIG_SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("RIG_SMTP_PORT", "1")
        monkeypatch.setenv("RIG_SMTP_USER", "rig")
        monkeypatch.setenv("RIG_SMTP_PASSWORD", "x")
        monkeypatch.setenv("RIG_SMTP_FROM", "rig@example")
        monkeypatch.setenv("RIG_SMTP_TO", "oncall@example")
        assert emit_to_email(_event()) is False


class TestEmitToPagerDuty:
    def test_missing_env_returns_false(self, monkeypatch):
        for key in ("RIG_PAGERDUTY_TOKEN", "RIG_PAGERDUTY_INCIDENT"):
            monkeypatch.delenv(key, raising=False)
        assert emit_to_pagerduty(_event()) is False

    def test_unreachable_pagerduty_returns_false(self, monkeypatch):
        monkeypatch.setenv("RIG_PAGERDUTY_TOKEN", "x")
        monkeypatch.setenv("RIG_PAGERDUTY_INCIDENT", "P123")
        assert emit_to_pagerduty(_event()) is False
