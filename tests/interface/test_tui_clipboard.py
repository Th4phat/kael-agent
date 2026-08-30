"""Tests for the system-clipboard fallback in the TUI drag-to-copy flow.

Textual's built-in ``copy_to_clipboard`` writes an OSC52 escape sequence
to the terminal, which only works on terminals that support OSC52 and
on tmux/screen with passthrough enabled. In a plain Linux terminal
neither may apply — the text is copied to Textual's internal clipboard
but never reaches the OS clipboard. ``_copy_to_system_clipboard``
probes the local environment for a real clipboard tool and pipes the
selected text to its stdin.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from kael.interface.tui.app import _copy_to_system_clipboard


def test_returns_false_when_no_binary_on_path() -> None:
    with patch("kael.interface.tui.app.shutil.which", return_value=None):
        assert _copy_to_system_clipboard("hello") is False


def test_returns_false_when_binary_exits_nonzero() -> None:
    completed = subprocess.CompletedProcess(
        args=("/bin/false",), returncode=1, stdout="", stderr="nope"
    )
    with (
        patch("kael.interface.tui.app.shutil.which", return_value="/bin/false"),
        patch("kael.interface.tui.app.subprocess.run", return_value=completed) as run_mock,
    ):
        assert _copy_to_system_clipboard("hello") is False
    # The first probed binary on the allow-list was tried first.
    assert run_mock.call_args_list[0].args[0] == ("pbcopy",)


def test_returns_false_when_subprocess_raises() -> None:
    with (
        patch("kael.interface.tui.app.shutil.which", return_value="/bin/true"),
        patch(
            "kael.interface.tui.app.subprocess.run",
            side_effect=OSError("no permission"),
        ),
    ):
        assert _copy_to_system_clipboard("hello") is False


def test_returns_true_when_binary_succeeds() -> None:
    completed = subprocess.CompletedProcess(args=("/bin/true",), returncode=0, stdout="", stderr="")
    with (
        patch("kael.interface.tui.app.shutil.which", return_value="/bin/true"),
        patch("kael.interface.tui.app.subprocess.run", return_value=completed) as run_mock,
    ):
        assert _copy_to_system_clipboard("hello world") is True
    # Selected text was piped to stdin and stdout/stderr were sent to
    # DEVNULL (avoid the stdin-pipe deadlock with ``xclip``).
    call = run_mock.call_args
    assert call.kwargs["input"] == "hello world"
    assert call.kwargs["stdout"] is subprocess.DEVNULL
    assert call.kwargs["stderr"] is subprocess.DEVNULL


def test_falls_through_allow_list_until_one_works() -> None:
    """If the first tool is on PATH but exits 1, the next is tried."""
    calls: list[tuple[str, ...]] = []

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in {"pbcopy", "xclip"} else None

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(tuple(cmd))
        if cmd[0] == "pbcopy":
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="denied")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("kael.interface.tui.app.shutil.which", side_effect=fake_which),
        patch("kael.interface.tui.app.subprocess.run", side_effect=fake_run),
    ):
        assert _copy_to_system_clipboard("payload") is True
    # xclip should have been tried after pbcopy failed.
    assert calls[0][0] == "pbcopy"
    assert calls[1][0] == "xclip"
    assert len(calls) == 2
