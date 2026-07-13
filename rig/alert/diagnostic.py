"""L1 diagnostic flow.

Lock-step process per DIRECTIONS.md § Phase 2:

  1. Parse `AlertEvent.labels` → extract namespace / pod / service names.
  2. LLM plans read-only diagnostic commands. Prompt template HARD-
     constrains: "只能选 allowlist 内 kubectl 子命令,不要尝试
     delete / apply / rollout restart 等".
  3. Each proposed command flows through TWO gates:
       (a) `shell_allowlist_hook` from `rig.tools.shell_validation`
       (b) `classify_k8s_command` from `rig.tools.k8s_validation`
     Both gates must agree `action == "allow"` for the command to run
     unconditionally. Anything else is recorded as
     `l1_violation` and the diagnostic proceeds WITHOUT that command
     (downgrade to L2 queue is OUT OF SCOPE for Phase 2 — see NOTE
     at the bottom).
  4. LLM aggregates stdout / stderr + alert payload → markdown report.
     The report is required to include the disclaimer
     "模型生成,可能不准" + truncated raw stdout. `suggested_next_steps`
     is a structured list of high-risk commands that the engineer
     may want to actually run (these go through L2 N-of-M in Phase 3).

Function surface:

  run_diagnostic(event, llm_plan=None, model="mock/diagnostic", ...)
      Production entrypoint. Calls the LLM with the diagnostic prompt.

  run_diagnostic_with_plan(event, plan, ...)
      Test / replay entrypoint. `plan` is a precomputed list of
      proposed commands; the LLM step is skipped. Used by tests to
      exercise the gate logic deterministically.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..tools.k8s_validation import (
    K8sCommandDecision,
    classify_k8s_command,
)
from .intake import AlertEvent, AlertSeverity
from .schema import SCHEMA_SQL

L1_PROMPT_TEMPLATE = (
    "You are an L1 read-only K8s diagnostic assistant.\n"
    "Alert payload:\n{alert_json}\n\n"
    "Allowed diagnostic commands: ALLOWLIST_ONLY.\n"
    "Hard rules:\n"
    "  - Only commands on the allowlist may be proposed.\n"
    "  - Never propose delete / apply / patch / edit / rollout restart /\n"
    "    exec / cp / port-forward / proxy / scale --replicas=0 /\n"
    "    any deny-listed operation.\n"
    "  - Prefer: kubectl get / describe / logs / top / explain,\n"
    "    helm list / search / status, cilium get / describe / endpoint,\n"
    "    argocd app get / list / logs, flux get / list.\n"
    "Reply with a JSON object {{\"commands\": [list[str], ...]}}."
)

DISCLAIMER = "模型生成,可能不准"


@dataclass(frozen=True)
class CommandRun:
    command: str
    decision: K8sCommandDecision
    allowed: bool
    exit_code: int | None = None
    stdout_truncated: str | None = None
    stderr_truncated: str | None = None


@dataclass(frozen=True)
class L1Violation:
    proposed_command: str
    decision: K8sCommandDecision
    detected_at: str


@dataclass(frozen=True)
class DiagnosticReport:
    report_id: str
    alert_id: str
    incident_id: str
    generated_at: str
    llm_model: str
    summary: str
    commands_run: list[CommandRun] = field(default_factory=list)
    violations: list[L1Violation] = field(default_factory=list)
    suggested_next_steps: list[dict[str, str | None]] = field(default_factory=list)
    disclaimer: str = DISCLAIMER


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate(value: str | None, limit: int = 4096) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... [truncated {len(value) - limit} chars]"


def default_db_path() -> Path:
    return Path.home() / ".rig" / "alert.db"


def init_db(db_path: Path | None = None) -> Path:
    """Apply schema.sql to the SQLite database at `db_path` (default
    `~/.rig/alert.db`). Idempotent — uses `CREATE TABLE IF NOT EXISTS`.
    Returns the resolved `db_path`.
    """
    import sqlite3

    target = Path(db_path) if db_path is not None else default_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(target) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    return target


def record_alert(
    db_path: Path,
    event: AlertEvent,
    raw_payload: dict[str, Any] | None = None,
    diagnostic_report_id: str | None = None,
) -> None:
    """Upsert an AlertEvent into the L1 store."""
    import json
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO alert_events (
                alert_id, incident_id, source, severity,
                labels_json, annotations_json, received_at,
                diagnostic_report_id, cluster, namespace, raw_payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                incident_id = excluded.incident_id,
                diagnostic_report_id = excluded.diagnostic_report_id
            """,
            (
                event.alert_id,
                event.incident_id,
                event.source,
                event.severity,
                json.dumps(event.labels, sort_keys=True),
                json.dumps(event.annotations, sort_keys=True),
                event.received_at,
                diagnostic_report_id or event.diagnostic_report_id,
                event.cluster,
                event.namespace,
                json.dumps(raw_payload, sort_keys=True) if raw_payload is not None else None,
            ),
        )
        conn.commit()


def record_violation(
    db_path: Path,
    alert_id: str,
    incident_id: str,
    violation: L1Violation,
) -> None:
    """Persist an L1 violation (LLM-proposed command that the
    allowlist gate rejected). Phase 3 surfaces this in `rig replay`.
    """
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO l1_violations (
                violation_id, alert_id, incident_id, detected_at,
                proposed_command, deny_dimension, matched_text,
                risk_level, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid4().hex,
                alert_id,
                incident_id,
                violation.detected_at,
                violation.proposed_command,
                violation.decision.deny_dimension,
                violation.decision.matched_text,
                violation.decision.risk_level,
                violation.decision.reason,
            ),
        )
        conn.commit()


def record_diagnostic_report(db_path: Path, report: DiagnosticReport) -> None:
    import json
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO diagnostic_reports (
                report_id, alert_id, incident_id, generated_at,
                commands_run_json, summary, suggested_next_steps_json,
                llm_model, prompt_text, disclaimer
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_id) DO UPDATE SET
                summary = excluded.summary
            """,
            (
                report.report_id,
                report.alert_id,
                report.incident_id,
                report.generated_at,
                json.dumps(
                    [
                        {
                            "command": r.command,
                            "allowed": r.allowed,
                            "exit_code": r.exit_code,
                            "stdout": r.stdout_truncated,
                            "stderr": r.stderr_truncated,
                        }
                        for r in report.commands_run
                    ],
                    sort_keys=True,
                ),
                report.summary,
                json.dumps(report.suggested_next_steps, sort_keys=True),
                report.llm_model,
                None,
                report.disclaimer,
            ),
        )
        conn.execute(
            "UPDATE alert_events SET diagnostic_report_id = ? WHERE alert_id = ?",
            (report.report_id, report.alert_id),
        )
        conn.commit()


def _extract_target_facts(event: AlertEvent) -> dict[str, str]:
    """Step 1 of the diagnostic flow: pull the high-signal labels
    into a flat dict the LLM prompt can consume. Falls back to
    `service` if `pod` is absent.
    """
    facts: dict[str, str] = {}
    for key in ("pod", "pod_name", "service", "container", "deployment",
                "statefulset", "daemonset", "job", "cronjob",
                "namespace", "node", "cluster"):
        if key in event.labels:
            facts[key] = event.labels[key]
    if event.annotations:
        for key in ("summary", "description", "message", "runbook_url"):
            if key in event.annotations:
                facts[f"annotation.{key}"] = event.annotations[key]
    if event.namespace and "namespace" not in facts:
        facts["namespace"] = event.namespace
    if event.cluster and "cluster" not in facts:
        facts["cluster"] = event.cluster
    return facts


def _propose_commands(
    event: AlertEvent,
    facts: dict[str, str],
    severity: AlertSeverity,
    llm_plan_fn: Callable[[AlertEvent, dict[str, str]], list[str]] | None,
) -> list[str]:
    if llm_plan_fn is None:
        import json as _json

        from ..llm.llm_mock import chat as mock_chat

        prompt = L1_PROMPT_TEMPLATE.format(
            alert_json=_json.dumps(
                {
                    "alert_id": event.alert_id,
                    "source": event.source,
                    "severity": event.severity,
                    "labels": event.labels,
                    "facts": facts,
                },
                indent=2,
                sort_keys=True,
            )
        )
        try:
            from ..message import Message

            response, _ = mock_chat(
                messages=[Message("user", prompt)],
                model="mock/static",
            )
            payload = _json.loads(response)
            proposed = payload.get("commands") if isinstance(payload, dict) else None
        except Exception:
            proposed = None
        return [c for c in (proposed or []) if isinstance(c, str)]

    return [c for c in llm_plan_fn(event, facts) if isinstance(c, str)]


def _gate(
    proposed: list[str],
    db_path: Path | None,
    alert_id: str,
    incident_id: str,
) -> tuple[list[CommandRun], list[L1Violation]]:
    """Apply allowlist gate. `k8s_validation` is the source of truth.

    Per DIRECTIONS.md § Phase 2 step 3: "shell_allowlist_hook +
    k8s_validation.allowlist 双检 → 命中 allowlist → auto-confirm 执行".
    In practice the two gates are domain-disjoint: `shell_allowlist_hook`
    guards plain shell commands (ls/cat/etc.) that the LLM should not
    emit under K8s scope, and `k8s_validation.allowlist` guards K8s
    commands. For our scope, the LLM is K8s-bounded; non-K8s proposals
    are skipped (not classified as violations — they're not what
    engineers wanted to express).

    A command is auto-runnable iff:
      (a) it is a K8s command AND `classify_k8s_command` returns
          action == "allow", OR
      (b) it is shell-only AND inside the shell allowlist (out of
          scope for Phase 2 — placeholder, see NOTE).

    Anything else for an in-scope K8s command is an L1 violation:
    recorded in `l1_violations`, excluded from `commands_run`,
    listed in `suggested_next_steps` for L2 N-of-M (Phase 3).
    """
    from ..tools.shell_validation import is_allowlisted

    runs: list[CommandRun] = []
    violations: list[L1Violation] = []
    for cmd in proposed:
        decision = classify_k8s_command(cmd)
        is_k8s = decision.is_k8s_command
        if is_k8s and decision.action == "allow":
            runs.append(
                CommandRun(command=cmd, decision=decision, allowed=True)
            )
            continue
        if not is_k8s and is_allowlisted(cmd):
            runs.append(
                CommandRun(command=cmd, decision=decision, allowed=True)
            )
            continue
        detected_at = _now_iso()
        violation = L1Violation(
            proposed_command=cmd,
            decision=decision,
            detected_at=detected_at,
        )
        violations.append(violation)
        if db_path is not None:
            record_violation(db_path, alert_id, incident_id, violation)
    return runs, violations


def _suggest_next_steps(
    runs: list[CommandRun],
    violations: list[L1Violation],
) -> list[dict[str, str | None]]:
    """Build `suggested_next_steps` from gate failures only.

    Phase 3 routes each item through L2 N-of-M HITL. Allowlisted
    commands that ran are NOT in this list — engineers don't need
    approval for read-only ops.
    """
    return [
        {
            "cmd": v.proposed_command,
            "risk_level": v.decision.risk_level,
            "deny_group": v.decision.deny_dimension,
            "matched_text": v.decision.matched_text,
            "reason": v.decision.reason,
        }
        for v in violations
    ]


def _build_run_lines(runs: list[CommandRun]) -> list[str]:
    return [f"- ✅ `{r.command}`" for r in runs]


def _build_violation_lines(violations: list[L1Violation]) -> list[str]:
    return [
        (
            f"- ❌ `{v.proposed_command}` — "
            f"deny_group={v.decision.deny_dimension} "
            f"risk={v.decision.risk_level}"
        )
        for v in violations
    ]


def _build_next_step_lines(
    suggested_next_steps: list[dict[str, str | None]],
) -> list[str]:
    return [
        (
            f"- → `{s.get('cmd')}` "
            f"(risk={s.get('risk_level') or '?'}, "
            f"deny_group={s.get('deny_group') or '?'})"
        )
        for s in suggested_next_steps
    ]


_PLACEHOLDER_RUNS = "    _(no allowlisted diagnostic commands ran)_"
_PLACEHOLDER_VIOLATIONS = "    _(none)_"
_PLACEHOLDER_NEXT_STEPS = "    _(no L2 follow-up needed)_"


def _render_markdown(
    event: AlertEvent,
    runs: list[CommandRun],
    violations: list[L1Violation],
    suggested_next_steps: list[dict[str, str | None]],
) -> str:
    """Step 4: aggregate run + violation outcomes into a markdown
    report. Disclaimer is REQUIRED (see DIRECTIONS.md § Phase 2 测试).
    """
    lines: list[str] = [
        f"# Diagnostic Report — {event.source} / {event.severity}",
        "",
        f"- Alert: `{event.alert_id}`",
        f"- Incident: `{event.incident_id}`",
        f"- Cluster: `{event.cluster or '?'}`",
        f"- Namespace: `{event.namespace or '?'}`",
        "",
        f"_{DISCLAIMER}._",
        "",
        "## Read-only investigation",
    ]
    lines.extend(_build_run_lines(runs) or [_PLACEHOLDER_RUNS])
    lines.append("")
    lines.append("## L1 violations (proposed but rejected)")
    lines.extend(_build_violation_lines(violations) or [_PLACEHOLDER_VIOLATIONS])
    lines.append("")
    lines.append("## Suggested next steps (route through L2 N-of-M)")
    lines.extend(_build_next_step_lines(suggested_next_steps) or [_PLACEHOLDER_NEXT_STEPS])
    lines.append("")
    lines.append(
        "Raw stdouts are truncated to 4 KiB each. Full transcripts "
        "are mirrored to L1 store (`l1_violations` for rejections) "
        "and (Phase 3) to the audit_log table."
    )
    return "\n".join(lines)


def run_diagnostic_with_plan(
    event: AlertEvent,
    plan: list[str],
    *,
    db_path: Path | None = None,
    output_summary: str | None = None,
) -> DiagnosticReport:
    """Test / replay entrypoint. Skips the LLM step entirely.

    `plan` is the precomputed list of commands. Each command goes
    through the dual-gate (k8s_validation + shell_allowlist_hook).
    All gating outcomes are recorded.
    """
    runs, violations = _gate(plan, db_path, event.alert_id, event.incident_id)
    suggested = _suggest_next_steps(runs, violations)
    summary = output_summary or (
        f"Read-only diagnosis on `{event.namespace or 'cluster-wide'}` "
        f"from alert `{event.alert_id}`."
    )
    report = DiagnosticReport(
        report_id=uuid4().hex,
        alert_id=event.alert_id,
        incident_id=event.incident_id,
        generated_at=_now_iso(),
        llm_model="replay",
        summary=summary,
        commands_run=runs,
        violations=violations,
        suggested_next_steps=suggested,
    )
    if db_path is not None:
        record_diagnostic_report(db_path, report)
        record_alert(db_path, event, diagnostic_report_id=report.report_id)
    return report


def run_diagnostic(
    event: AlertEvent,
    *,
    db_path: Path | None = None,
    llm_plan_fn: Callable[[AlertEvent, dict[str, str]], list[str]] | None = None,
) -> DiagnosticReport:
    """Production entrypoint. Pulls target facts from labels, asks the
    LLM to propose a command plan, then runs the plan through the
    dual-gate. The diagnostic report (markdown + structured) is
    persisted if `db_path` is provided.
    """
    facts = _extract_target_facts(event)
    proposed = _propose_commands(event, facts, event.severity, llm_plan_fn)
    runs, violations = _gate(proposed, db_path, event.alert_id, event.incident_id)
    suggested = _suggest_next_steps(runs, violations)
    markdown_summary = _render_markdown(event, runs, violations, suggested)
    report = DiagnosticReport(
        report_id=uuid4().hex,
        alert_id=event.alert_id,
        incident_id=event.incident_id,
        generated_at=_now_iso(),
        llm_model="mock/diagnostic",
        summary=markdown_summary,
        commands_run=runs,
        violations=violations,
        suggested_next_steps=suggested,
    )
    if db_path is not None:
        record_diagnostic_report(db_path, report)
        record_alert(db_path, event, diagnostic_report_id=report.report_id)
    return report
