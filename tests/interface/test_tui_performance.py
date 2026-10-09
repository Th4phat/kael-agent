"""Tests for the TUI paths that run without a live app.

- ``_update_stats_display`` only touches the widget when the text changed.
- The target/prompt submit flow (free-form text falls through to a
  prompt-only run).

Widget behaviour under a running app lives in ``test_tui_widgets.py``.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Static

from kael.config import load_settings
from kael.core.inputs import build_root_task
from kael.interface.tui.app import ChatTextArea, KaelTUIApp
from kael.report.writer import read_run_record


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning",
    "ignore::RuntimeWarning",
)


def _make_args(run_name: str = "test-perf") -> argparse.Namespace:
    return argparse.Namespace(
        run_name=run_name,
        targets_info=[],
        instruction="",
        diff_scope={"active": False},
        scan_mode="deep",
        non_interactive=False,
        local_sources=[],
        scope_mode="auto",
        diff_base=None,
        user_explicit_instruction=None,
    )


@pytest.fixture
def app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> KaelTUIApp:
    # KaelTUIApp.__init__ calls ReportState.save_run_data() which
    # resolves ``run_dir_for(run_name)`` against the current working
    # directory and creates the directory. Run inside ``tmp_path`` so
    # the test never writes a real ``kael_runs/test-perf-*`` dir on
    # the developer's machine.
    monkeypatch.chdir(tmp_path)
    run_name = f"test-perf-{id(object())}"
    instance = KaelTUIApp(_make_args(run_name))
    instance.report_state.vulnerability_reports = []
    yield instance
    leftover = tmp_path / "kael_runs"
    if leftover.exists():
        shutil.rmtree(leftover, ignore_errors=True)


class TestStatsUpdateSkip:
    async def test_identical_stats_do_not_update_widget(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            stats = app.query_one("#stats_display", Static)
            calls: list[object] = []
            monkeypatch.setattr(stats, "update", lambda content: calls.append(content))

            app._last_stats_plain = None
            app._update_stats_display()
            assert len(calls) == 1
            app._update_stats_display()
            assert len(calls) == 1, "identical stats text must be a no-op"

            app.report_state.run_record["llm_usage"]["total_tokens"] = 150
            app._update_stats_display()
            assert len(calls) == 2, "usage change should re-render"


class TestTuiPromptOnlySubmit:
    """TUI submit flow: free-form text falls through to prompt-only mode.

    Regression for: typing a prompt into the target field with no target
    on the CLI used to error out with "Invalid target" instead of starting
    a prompt-only run.
    """

    def test_free_form_text_starts_prompt_only(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert app._awaiting_target
        assert not app._prompt_only

        started = []
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: started.append(self))

        app._submit_target("audit the staging k8s cluster for misconfigurations")

        assert app._awaiting_target is False
        assert app._prompt_only is True
        assert app.args.instruction == "audit the staging k8s cluster for misconfigurations"
        assert app.scan_config["user_instructions"] == (
            "audit the staging k8s cluster for misconfigurations"
        )
        assert started, "scan thread should be started on prompt-only submit"

    def test_multiline_prompt_uses_full_message_as_instruction(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: None)

        app._submit_target("look for auth bypasses\n\nfocus on /api/v1 endpoints, ignore /healthz")

        assert app._prompt_only
        assert "look for auth bypasses" in app.args.instruction
        assert "/api/v1" in app.args.instruction

    def test_valid_target_still_sets_target(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: None)

        app._submit_target("https://example.com")

        assert not app._prompt_only
        assert app._awaiting_target is False
        assert app.args.targets_info[0]["type"] == "web_application"

    def test_empty_input_does_nothing(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        started = []
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: started.append(self))
        notifies = []
        monkeypatch.setattr(KaelTUIApp, "notify", lambda self, *a, **kw: notifies.append(a))

        app._submit_target("   \n  ")

        assert app._awaiting_target
        assert not app._prompt_only
        assert not started
        assert notifies, "empty submit should notify the user"


class TestTuiLocalTargetSubmit:
    @pytest.mark.parametrize("is_file", [True, False], ids=["archive", "directory"])
    def test_local_target_prepares_and_persists_upload(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch, is_file: bool
    ) -> None:
        target = Path.cwd() / ("LastWord.zip" if is_file else "source")
        if is_file:
            target.write_bytes(b"archive contents")
        else:
            target.mkdir()
        started = []
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: started.append(self))

        app._submit_target(f"./{target.name}\nInspect this target")

        expected_source = {
            "source_path": str(target),
            "workspace_subdir": target.name,
        }
        if is_file:
            expected_source["is_file"] = True
        assert app.args.local_sources == [expected_source]
        assert app.scan_config["local_sources"] == [expected_source]
        record = read_run_record(app.report_state.get_run_dir())
        assert record["local_sources"] == [expected_source]
        assert record["targets_info"] == app.args.targets_info
        assert f"/workspace/{target.name}" in build_root_task(app.scan_config)
        assert app.scan_config["user_instructions"] == "Inspect this target"
        assert started
        assert not app._prompt_only

    def test_missing_local_path_stays_in_target_entry_until_corrected(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = Path.cwd() / "Last_Word.zip"
        target.write_bytes(b"archive contents")
        started = []
        notifications = []
        monkeypatch.setattr(KaelTUIApp, "_start_scan_thread", lambda self: started.append(self))
        monkeypatch.setattr(
            KaelTUIApp, "notify", lambda self, *a, **kw: notifications.append((a, kw))
        )

        app._submit_target("./LastWord.zip")

        assert app._awaiting_target
        assert not app._prompt_only
        assert not started
        assert not app.args.targets_info
        assert not app.args.local_sources
        assert "./LastWord.zip" in notifications[-1][0][0]
        assert str(Path.cwd()) in notifications[-1][0][0]
        assert notifications[-1][1]["severity"] == "error"

        app._submit_target("./Last_Word.zip")

        assert started
        assert not app._awaiting_target
        assert app.args.local_sources[0]["source_path"] == str(target)

    @pytest.mark.parametrize("size", [(120, 40), (40, 18)])
    @pytest.mark.parametrize("theme", ["kael", "textual-light"])
    async def test_keyboard_retry_forwards_file_to_scan_thread(
        self,
        app: KaelTUIApp,
        monkeypatch: pytest.MonkeyPatch,
        size: tuple[int, int],
        theme: str,
    ) -> None:
        target = Path.cwd() / "Last_Word.zip"
        target.write_bytes(b"archive contents")
        load_settings().llm.model = "openrouter/example-model"
        run_scan = AsyncMock()
        monkeypatch.setattr("kael.interface.tui.app.run_kael_scan", run_scan)
        monkeypatch.setattr("kael.interface.tui.app.session_manager.cleanup", AsyncMock())

        async with app.run_test(size=size, notifications=True) as pilot:
            app.theme = theme
            editor = app.query_one("#chat_input", ChatTextArea)
            editor.text = "./LastWord.zip\nInspect this archive"
            await pilot.press("enter")
            await pilot.pause()

            assert editor.text == "./LastWord.zip\nInspect this archive"
            assert editor.has_focus
            assert app._awaiting_target
            run_scan.assert_not_awaited()
            toast = app.query_one("Toast")
            assert 0 <= toast.region.x < toast.region.right <= size[0]
            assert 0 <= toast.region.y < toast.region.bottom <= size[1]
            assert 0 <= editor.region.x < editor.region.right <= size[0]
            assert 0 <= editor.region.y < editor.region.bottom <= size[1]

            editor.text = "./Last_Word.zip\nInspect this archive"
            await pilot.press("enter")
            assert app._scan_completed.wait(timeout=5)
            await pilot.pause()

            run_scan.assert_awaited_once()
            call = run_scan.await_args
            assert call.kwargs["local_sources"] == [
                {
                    "source_path": str(target),
                    "workspace_subdir": "Last_Word.zip",
                    "is_file": True,
                }
            ]
            assert call.kwargs["scan_config"]["user_instructions"] == "Inspect this archive"
            assert not call.kwargs["scan_config"]["prompt_only"]
            assert not app._awaiting_target
            assert editor.text == ""
