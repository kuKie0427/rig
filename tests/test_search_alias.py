"""Tests for `rig search` alias and rig-* plugin dispatch."""

import importlib
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rig.cli.main import main


@pytest.fixture
def runner():
    return CliRunner()


class TestSearchAlias:
    def test_search_calls_search_chats(self, runner: CliRunner):
        """rig search QUERY delegates to search_chats."""
        with patch("rig.tools.chats.search_chats") as mock_search:
            result = runner.invoke(main, ["search", "flask migration"])
        assert result.exit_code == 0
        mock_search.assert_called_once_with(
            "flask migration", max_results=20, context_lines=1, max_matches=1
        )

    def test_search_multiword_query_joined(self, runner: CliRunner):
        """rig search word1 word2 joins terms into a single query."""
        with patch("rig.tools.chats.search_chats") as mock_search:
            result = runner.invoke(main, ["search", "flask", "migration"])
        assert result.exit_code == 0
        mock_search.assert_called_once_with(
            "flask migration", max_results=20, context_lines=1, max_matches=1
        )

    def test_search_empty_query_errors(self, runner: CliRunner):
        """rig search with no query prints an error."""
        result = runner.invoke(main, ["search"])
        assert result.exit_code != 0
        assert "Usage:" in result.output or "query" in result.output.lower()

    def test_search_does_not_intercept_non_search_prompts(self, runner: CliRunner):
        """rig 'search for recipes' is not intercepted by the search alias.

        prompts[0] == "search for recipes" (one string), not "search".
        """
        with (
            patch("rig.tools.chats.search_chats") as mock_search,
            patch.object(importlib.import_module("rig.chat"), "chat"),
        ):
            runner.invoke(
                main,
                ["--non-interactive", "--no-confirm", "search for recipes"],
            )
        # search_chats must NOT be called — this is a regular chat prompt
        mock_search.assert_not_called()

    def test_help_mentions_search(self, runner: CliRunner):
        """rig --help mentions the search shortcut."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "search" in result.output.lower()

    def test_search_does_not_swallow_version(self, runner: CliRunner):
        """rig --version search QUERY shows version, not search results."""
        with patch("rig.tools.chats.search_chats") as mock_search:
            result = runner.invoke(main, ["--version", "search", "anything"])
        assert result.exit_code == 0
        mock_search.assert_not_called()
        assert "rig" in result.output.lower() or "version" in result.output.lower()

    def test_search_does_not_swallow_version_json(self, runner: CliRunner):
        """rig --version-json search QUERY shows version JSON, not search results."""
        with patch("rig.tools.chats.search_chats") as mock_search:
            result = runner.invoke(main, ["--version-json", "search", "anything"])
        assert result.exit_code == 0
        mock_search.assert_not_called()
        assert "{" in result.output or "version" in result.output.lower()


class TestPluginDispatch:
    def test_plugin_found_in_path_is_executed(self, runner: CliRunner):
        """rig sessions delegates to rig-sessions if found in PATH."""
        with (
            patch(
                "rig.cli.main.shutil.which",
                return_value="/usr/local/bin/rig-sessions",
            ),
            patch("rig.cli.main.subprocess.call", return_value=0) as mock_call,
        ):
            # Use only positional args — rig CLI rejects unknown --flags before dispatch
            result = runner.invoke(main, ["sessions"])
        assert result.exit_code == 0
        mock_call.assert_called_once_with(["/usr/local/bin/rig-sessions"])

    def test_plugin_not_found_falls_through(self, runner: CliRunner):
        """rig unknowncmd with no rig-unknowncmd in PATH falls through to normal CLI."""
        with (
            patch("rig.cli.main.shutil.which", return_value=None),
            patch.object(importlib.import_module("rig.chat"), "chat"),
        ):
            # Normal CLI starts a chat session; shutil.which returning None means no dispatch
            runner.invoke(main, ["unknowncmd"])

    def test_plugin_dispatch_skipped_for_version_flag(self, runner: CliRunner):
        """rig --version sessions does not trigger plugin dispatch."""
        with (
            patch("rig.cli.main.subprocess.call") as mock_call,
        ):
            result = runner.invoke(main, ["--version", "sessions"])
        assert result.exit_code == 0
        mock_call.assert_not_called()

    def test_help_mentions_plugin_dispatch(self, runner: CliRunner):
        """rig --help mentions the plugin dispatch mechanism."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "rig-" in result.output


class TestUtilSubcommandMirroring:
    def test_util_subcmd_delegates_to_rig_util(self, runner: CliRunner):
        """rig chats [args] delegates to rig-util chats [args]."""
        with (
            patch(
                "rig.cli.main.shutil.which",
                return_value="/usr/local/bin/rig-util",
            ),
            patch("rig.cli.main.subprocess.call", return_value=0) as mock_call,
        ):
            result = runner.invoke(main, ["chats"])
        assert result.exit_code == 0
        mock_call.assert_called_once_with(["/usr/local/bin/rig-util", "chats"])

    def test_util_subcmd_passes_all_args(self, runner: CliRunner):
        """rig chats list passes 'chats list' to rig-util."""
        with (
            patch(
                "rig.cli.main.shutil.which",
                return_value="/usr/local/bin/rig-util",
            ),
            patch("rig.cli.main.subprocess.call", return_value=0) as mock_call,
        ):
            result = runner.invoke(main, ["chats", "list"])
        assert result.exit_code == 0
        mock_call.assert_called_once_with(
            ["/usr/local/bin/rig-util", "chats", "list"]
        )

    def test_util_subcmd_skipped_for_version_flag(self, runner: CliRunner):
        """rig --version chats does not trigger rig-util dispatch."""
        with patch("rig.cli.main.subprocess.call") as mock_call:
            result = runner.invoke(main, ["--version", "chats"])
        assert result.exit_code == 0
        mock_call.assert_not_called()

    def test_util_subcommands_all_known(self):
        """UTIL_SUBCOMMANDS contains expected rig-util subcommands."""
        from rig.cli.util import UTIL_SUBCOMMANDS

        for expected in ("chats", "tools", "skills", "models", "context"):
            assert expected in UTIL_SUBCOMMANDS

    def test_util_subcmd_takes_priority_over_path_dispatch(self, runner: CliRunner):
        """rig chats delegates to rig-util, not a hypothetical rig-chats binary."""
        calls: list = []

        def fake_which(cmd: str) -> str | None:
            if cmd == "rig-util":
                return "/usr/local/bin/rig-util"
            if cmd == "rig-chats":
                return "/usr/local/bin/rig-chats"
            return None

        def fake_call(args: list) -> int:
            calls.append(args)
            return 0

        with (
            patch("rig.cli.main.shutil.which", side_effect=fake_which),
            patch("rig.cli.main.subprocess.call", side_effect=fake_call),
        ):
            runner.invoke(main, ["chats"])

        assert calls == [["/usr/local/bin/rig-util", "chats"]]

    def test_help_mentions_util_subcommand_shortcut(self, runner: CliRunner):
        """rig --help describes the rig-util subcommand shortcut."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        # Help text should describe that rig-util subcommands work directly
        assert "chats" in result.output

    def test_util_subcmd_errors_when_rig_util_not_installed(self, runner: CliRunner):
        """rig chats exits with code 1 and an actionable error when rig-util is absent."""
        with patch("rig.cli.main.shutil.which", return_value=None):
            result = runner.invoke(main, ["chats"])
        assert result.exit_code == 1
        assert "rig-util" in result.output
