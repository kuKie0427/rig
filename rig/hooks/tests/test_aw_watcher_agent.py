"""Tests for aw_watcher_agent lifecycle hook integration."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from rig.hooks import HookRegistry, HookType, get_registry, set_registry, trigger_hook
from rig.hooks.aw_watcher_agent import emit_end, emit_start
from rig.hooks.types import ToolExecutePostData, ToolExecutePreData
from rig.logmanager import LogManager, _current_log_var
from rig.tools.base import ToolUse


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_emit_start_shells_out_when_enabled(monkeypatch):
    """session.start should emit a best-effort aw-watcher-agent CLI call."""
    monkeypatch.setenv("RIG_AW_WATCHER_AGENT", "1")
    model = SimpleNamespace(full="anthropic/test-model")

    with (
        patch("rig.hooks.aw_watcher_agent.get_default_model", return_value=model),
        patch(
            "rig.hooks.aw_watcher_agent.subprocess.run",
            return_value=_completed(),
        ) as run,
    ):
        assert list(emit_start(Path("/tmp/conv123"), Path("/tmp/workspace"), [])) == []

    argv = run.call_args.args[0]
    assert argv[:2] == ["aw-watcher-agent", "emit-start"]
    assert "--session-id" in argv and "conv123" in argv
    assert "--workspace" in argv and "workspace" in argv
    assert "--model" in argv and "anthropic/test-model" in argv


def test_emit_end_shells_out_when_enabled(monkeypatch):
    """session.end should emit the matching aw-watcher-agent close event."""
    monkeypatch.setenv("RIG_AW_WATCHER_AGENT", "1")

    manager = cast(
        LogManager,
        SimpleNamespace(
            logdir=Path("/tmp/conv123"),
            workspace=Path("/tmp/workspace"),
        ),
    )

    with patch(
        "rig.hooks.aw_watcher_agent.subprocess.run",
        return_value=_completed(),
    ) as run:
        assert list(emit_end(manager)) == []

    argv = run.call_args.args[0]
    assert argv[:2] == ["aw-watcher-agent", "emit-end"]
    assert "--session-id" in argv and "conv123" in argv


def test_session_end_hook_accepts_trigger_kwargs(monkeypatch):
    """Registered session.end hook should tolerate extra trigger kwargs."""
    from rig.hooks.aw_watcher_agent import register

    monkeypatch.setenv("RIG_AW_WATCHER_AGENT", "1")
    manager = cast(
        LogManager,
        SimpleNamespace(
            logdir=Path("/tmp/conv123"),
            workspace=Path("/tmp/workspace"),
        ),
    )

    old = get_registry()
    set_registry(HookRegistry())
    try:
        register()
        with patch(
            "rig.hooks.aw_watcher_agent.subprocess.run",
            return_value=_completed(),
        ) as run:
            assert (
                list(
                    trigger_hook(
                        HookType.SESSION_END,
                        logdir=Path("/tmp/conv123"),
                        manager=manager,
                    )
                )
                == []
            )
        run.assert_called_once()
    finally:
        set_registry(old)


def test_emit_start_noops_when_disabled(monkeypatch):
    """No subprocess call should happen when the plugin is disabled."""
    monkeypatch.delenv("RIG_AW_WATCHER_AGENT", raising=False)

    with patch("rig.hooks.aw_watcher_agent.subprocess.run") as run:
        assert list(emit_start(Path("/tmp/conv123"), Path("/tmp/workspace"), [])) == []

    run.assert_not_called()


def test_tool_activity_hooks_emit_heartbeat_when_registered(monkeypatch):
    """Registered tool hooks should emit one activity heartbeat per tool call."""
    from rig.hooks.aw_watcher_agent import register

    monkeypatch.setenv("RIG_AW_WATCHER_AGENT", "1")
    manager = cast(
        LogManager,
        SimpleNamespace(
            logdir=Path("/tmp/conv123"),
            workspace=Path("/tmp/workspace"),
        ),
    )
    tool_use = ToolUse(tool="shell", args=[], content="echo hi")
    token = _current_log_var.set(manager)

    old = get_registry()
    set_registry(HookRegistry())
    try:
        register()
        with (
            patch("rig.hooks.aw_watcher_agent.get_default_model", return_value=None),
            patch(
                "rig.hooks.aw_watcher_agent.time.monotonic", side_effect=[10.0, 10.35]
            ),
            patch(
                "rig.hooks.aw_watcher_agent.subprocess.run",
                return_value=_completed(),
            ) as run,
        ):
            assert (
                list(
                    trigger_hook(
                        HookType.TOOL_EXECUTE_PRE,
                        ToolExecutePreData(
                            log=cast(Any, SimpleNamespace(messages=[])),
                            workspace=Path("/tmp/workspace"),
                            tool_use=tool_use,
                        ),
                    )
                )
                == []
            )
            assert (
                list(
                    trigger_hook(
                        HookType.TOOL_EXECUTE_POST,
                        ToolExecutePostData(
                            log=cast(Any, SimpleNamespace(messages=[])),
                            workspace=Path("/tmp/workspace"),
                            tool_use=tool_use,
                        ),
                    )
                )
                == []
            )

        run.assert_called_once()
        argv = run.call_args.args[0]
        assert argv[:2] == ["aw-watcher-agent", "emit-activity"]
        assert "--session-id" in argv and "conv123" in argv
        assert "--workspace" in argv and "workspace" in argv
        assert "--tool" in argv and "shell" in argv
        assert "--status" in argv and "success" in argv
        assert "--duration-ms" in argv and "350" in argv
    finally:
        set_registry(old)
        _current_log_var.reset(token)
