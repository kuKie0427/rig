"""Multi-channel emit of L1 diagnostic reports.

Four channels (all optional; `ReportChannel` enum selects which):

  emit_to_chat(event_or_report)
      Pushes a markdown summary into the rig chat SSE feed.
      Phase 2 ships an in-process buffer; Phase 3 ties this into the
      server SSE machinery. The buffer is per-process and explicitly
      not durable — chat feeds are transient by design.

  emit_to_slack(report, webhook_url=None)
      POSTs the markdown summary to a Slack incoming-webhook URL.
      Reads `RIG_SLACK_WEBHOOK` from the environment if `webhook_url`
      is None; returns False (with `logger.warning`) when neither is
      configured. Uses `urllib.request` so we don't add a Slack SDK
      dependency.

  emit_to_email(report)
      Sends the markdown summary via SMTP. Reads `RIG_SMTP_HOST`,
      `RIG_SMTP_PORT`, `RIG_SMTP_USER`, `RIG_SMTP_PASSWORD`, and
      `RIG_SMTP_FROM`. Uses stdlib `smtplib`. Returns False (with
      `logger.warning`) when any required env var is missing.

  emit_to_pagerduty(report, incident_id=None, token=None)
      Adds the markdown summary as a note on an existing PagerDuty
      incident (`/incidents/{id}/notes` API). Reads `RIG_PAGERDUTY_TOKEN`
      and (when `incident_id` is None) `RIG_PAGERDUTY_INCIDENT`.

All four functions return `bool` (delivered or skipped) and never
raise — channels are best-effort and must not block the diagnostic
flow if a sink is misconfigured.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from email.message import EmailMessage
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from collections.abc import MutableSequence

logger = logging.getLogger(__name__)

ReportChannel: TypeAlias = Literal["chat", "slack", "email", "pagerduty"]

CHAT_BUFFER_LIMIT = 256


@dataclass
class _ChatBuffer:
    """Per-process ring buffer of markdown summaries pushed via
    `emit_to_chat`. The rig server's SSE endpoint consumes from
    `_CHAT_BUFFER` once that machinery is wired (Phase 3).
    """

    entries: MutableSequence[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.entries is None:
            self.entries = deque(maxlen=CHAT_BUFFER_LIMIT)


_CHAT_BUFFER = _ChatBuffer()


def chat_buffer_snapshot() -> list[dict]:
    """Return a shallow copy of the in-process chat SSE buffer."""
    return list(_CHAT_BUFFER.entries)


def reset_chat_buffer() -> None:
    """Empty the chat buffer. Test-only convenience."""
    _CHAT_BUFFER.entries.clear()


def emit_to_chat(report_or_event) -> bool:
    """Append a markdown summary to the chat SSE buffer.

    `report_or_event` is either a `DiagnosticReport` (preferred) or
    an `AlertEvent` (fallback when no diagnostic has run yet, e.g.
    alerts that immediately defer to L2 for unresolvable labels).
    """
    summary = _summary_text(report_or_event)
    _CHAT_BUFFER.entries.append(
        {
            "alert_id": getattr(report_or_event, "alert_id", None),
            "incident_id": getattr(report_or_event, "incident_id", None),
            "summary": summary,
        }
    )
    return True


def _summary_text(report_or_event) -> str:
    summary = getattr(report_or_event, "summary", None)
    if isinstance(summary, str) and summary:
        return summary
    return getattr(report_or_event, "alert_id", "alert") + " — no summary yet"


def emit_to_slack(report_or_event, webhook_url: str | None = None) -> bool:
    """POST the markdown summary as a Slack message.

    Returns False without raising when no webhook URL is configured.
    """
    url = webhook_url or os.environ.get("RIG_SLACK_WEBHOOK")
    if not url:
        logger.warning("RIG_SLACK_WEBHOOK not configured; skipping Slack emit")
        return False
    payload = json.dumps({"text": _summary_text(report_or_event)}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return 200 <= response.status < 300
    except urllib.error.URLError as exc:
        logger.warning("Slack emit failed: %s", exc)
        return False


def emit_to_email(
    report_or_event,
    recipient: str | None = None,
) -> bool:
    """Send the markdown summary via SMTP.

    Required env vars: `RIG_SMTP_HOST`, `RIG_SMTP_PORT`,
    `RIG_SMTP_USER`, `RIG_SMTP_PASSWORD`, `RIG_SMTP_FROM`.
    `recipient` defaults to `RIG_SMTP_TO` (or fails soft).
    """
    host = os.environ.get("RIG_SMTP_HOST")
    port_raw = os.environ.get("RIG_SMTP_PORT", "587")
    user = os.environ.get("RIG_SMTP_USER")
    password = os.environ.get("RIG_SMTP_PASSWORD")
    sender = os.environ.get("RIG_SMTP_FROM")
    to = recipient or os.environ.get("RIG_SMTP_TO")
    if not (host and user and password and sender and to):
        logger.warning("SMTP not fully configured; skipping email emit")
        return False

    msg = EmailMessage()
    msg["Subject"] = f"[rig L1] {getattr(report_or_event, 'alert_id', 'alert')}"
    msg["From"] = sender
    msg["To"] = to
    msg.set_content(_summary_text(report_or_event))

    try:
        with smtplib.SMTP(host, int(port_raw), timeout=5) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("SMTP emit failed: %s", exc)
        return False


def emit_to_pagerduty(
    report_or_event,
    incident_id: str | None = None,
    token: str | None = None,
) -> bool:
    """POST the markdown summary as a PagerDuty incident note.

    Reads `RIG_PAGERDUTY_TOKEN` (and `RIG_PAGERDUTY_INCIDENT` when
    `incident_id` is None). Returns False when either is missing;
    tests assert the function does NOT raise on misconfiguration.
    """
    api_token = token or os.environ.get("RIG_PAGERDUTY_TOKEN")
    target = incident_id or os.environ.get("RIG_PAGERDUTY_INCIDENT")
    if not (api_token and target):
        logger.warning(
            "PagerDuty not fully configured; skipping PagerDuty emit"
        )
        return False
    url = (
        f"https://api.pagerduty.com/incidents/{target}/notes"
    )
    payload = json.dumps({"note": {"content": _summary_text(report_or_event)}}).encode(
        "utf-8"
    )
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Token token={api_token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return 200 <= response.status < 300
    except urllib.error.URLError as exc:
        logger.warning("PagerDuty emit failed: %s", exc)
        return False


__all__ = [
    "ReportChannel",
    "chat_buffer_snapshot",
    "emit_to_chat",
    "emit_to_email",
    "emit_to_pagerduty",
    "emit_to_slack",
    "reset_chat_buffer",
]
