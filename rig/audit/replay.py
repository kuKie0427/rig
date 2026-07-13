"""Audit-log replay (DIRECTIONS.md § Phase 3 § replay.py).

Restores the per-incident command trace for an `incident_id` and
renders it as either a structured table (for `rig replay` to embed
in a future webui panel) or a markdown decision tree (the
`--markdown` flag).

Library entrypoint: `replay(incident_id, audit_dir=None)`.
Module CLI: `python -m rig.audit.replay --incident-id <UUID>`.
Full `rig replay` CLI subcommand is registered in rig-cli during
Phase 4 (Phase 3 ships this module-entry bridge to avoid scope
sprawl onto rig-cli's Click tree).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .writer import fetch_by_incident

DecisionNode = dict[str, Any]


def _decision_node(row: dict[str, Any]) -> DecisionNode:
    """Convert one audit_log row into a decision-tree node."""
    return {
        "execution_id": row["execution_id"],
        "timestamp": row["timestamp"],
        "user": row["user"],
        "command": row["command"],
        "command_type": row["command_type"],
        "deny_reason": row["deny_reason"],
        "approved_by": row["approved_by"],
        "required_approvals": row["required_approvals"],
        "exit_code": row["exit_code"],
        "rollback_id": row["rollback_id"],
        "cluster": row["cluster"],
        "namespace": row["namespace"],
        "stdout": row["stdout"],
        "stderr": row["stderr"],
    }


def replay(
    incident_id: str, audit_dir: str | None = None
) -> list[DecisionNode]:
    """Return the per-incident decision tree for `incident_id`.

    Each element is one audit_log row, ordered by timestamp ASC.
    An empty list means the incident is unknown (or has no
    audit_log entries yet, which is allowed — `incident_id` is
    nullable in the schema).
    """
    rows = fetch_by_incident(incident_id, audit_dir=audit_dir)
    return [_decision_node(r) for r in rows]


def to_markdown(decision_tree: list[DecisionNode]) -> str:
    """Render the decision tree as markdown for `rig replay`.

    Each command becomes one H3 section with the audit context
    (user, timestamp, approvals, exit_code, stdout/stderr).
    """
    if not decision_tree:
        return "# Incident replay\n\n_(no audit_log entries — incident is unknown or has no record)_\n"
    lines = [
        f"# Incident replay — {len(decision_tree)} command(s)",
        "",
    ]
    for node in decision_tree:
        lines.append(f"## `{node['command']}`")
        lines.append("")
        lines.append(
            f"- executed_at: {node['timestamp']}  "
            f"(user `{node['user']}`, "
            f"approvals `{','.join(node['approved_by']) or '-'}` "
            f"of {node['required_approvals']})"
        )
        if node.get("deny_reason"):
            lines.append(f"- deny_dimension: `{node['deny_reason']}`")
        if node.get("exit_code") is not None:
            lines.append(f"- exit_code: {node['exit_code']}")
        if node.get("cluster"):
            lines.append(f"- cluster: `{node['cluster']}`")
        if node.get("namespace"):
            lines.append(f"- namespace: `{node['namespace']}`")
        if node.get("rollback_id"):
            lines.append(
                f"- rollback reference: `{node['rollback_id']}` "
                f"(see also `rig replay --incident-id {node['rollback_id']}`)"
            )
        if node.get("stdout"):
            lines.append(f"- stdout:\n\n  ```\n  {node['stdout']}\n  ```")
        if node.get("stderr"):
            lines.append(f"- stderr:\n\n  ```\n  {node['stderr']}\n  ```")
        lines.append("")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m rig.audit.replay",
        description="Render the audit_log decision tree for an incident.",
    )
    p.add_argument(
        "--incident-id",
        required=True,
        help="The incident_id whose audit_log entries should be replayed.",
    )
    p.add_argument(
        "--audit-dir",
        default=None,
        help="Override the audit_dir (default: ~/.rig/).",
    )
    p.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format. `json` emits the structured tree; "
        "`markdown` (default) emits the human-readable tree.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    tree = replay(args.incident_id, args.audit_dir)
    if args.format == "json":
        json.dump(tree, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(to_markdown(tree))
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["replay", "to_markdown", "main"]
