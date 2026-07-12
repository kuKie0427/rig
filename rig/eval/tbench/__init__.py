"""
Terminal-Bench evaluation support for rig.

Terminal-Bench (tbench) is an external benchmark for evaluating agents on
terminal-based tasks. This module provides a rig adapter that implements
the AbstractInstalledAgent interface.

Usage:
    # Install rig with eval extras (includes terminal-bench in the same env):
    # pip install 'rig[eval]'

    # Run via CLI:
    rig-eval-tbench --task hello-world --model anthropic/claude-haiku-4-5

    # Or use terminal-bench directly:
    tb run \\
        --dataset terminal-bench-core==head \\
        --agent-import-path rig.eval.tbench.agent:RigAgent \\
        --task-id hello-world

See: https://github.com/openai/terminal-bench
"""

from __future__ import annotations

# Default model for tbench evaluations — shared by agent.py and run.py
# to avoid silent drift if one file is updated without the other.
DEFAULT_MODEL = "anthropic/claude-sonnet-4-6"

# Lazy import to avoid ImportError when terminal-bench is not installed.
# The friendly error message in run.py would never be reached if we import
# RigAgent eagerly here (since agent.py imports terminal_bench at module level).


def __getattr__(name: str) -> object:
    if name == "RigAgent":
        from .agent import RigAgent

        return RigAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["RigAgent", "DEFAULT_MODEL"]
