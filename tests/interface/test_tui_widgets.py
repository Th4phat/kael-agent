"""Widget-level behaviour of the TUI under a real (headless) app.

Events are posted the way the scan thread posts them (``post_message``),
so these cover the push-based ingestion path end to end: one widget per
event, in-place updates, per-agent containers, folding, keys.
"""

from __future__ import annotations

import argparse
import json
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from textual.widgets import ListView, Markdown, Static

from kael.interface.tui.app import (
    GraphChanged,
    KaelTUIApp,
    QuitScreen,
    SdkEvent,
)
from kael.interface.tui.widgets import MAX_MOUNTED_EVENTS, AssistantMessage, ChatStream


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning",
    "ignore::RuntimeWarning",
)

ROOT, CHILD = "a1root", "b2child"


def _make_args(run_name: str) -> argparse.Namespace:
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
def app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> KaelTUIApp:
    monkeypatch.chdir(tmp_path)
    instance = KaelTUIApp(_make_args(f"test-widgets-{id(object())}"))
    yield instance
    leftover = tmp_path / "kael_runs"
    if leftover.exists():
        shutil.rmtree(leftover, ignore_errors=True)


def _delta(text: str, kind: str = "response.output_text.delta") -> Any:
    return SimpleNamespace(type="raw_response_event", data=SimpleNamespace(type=kind, delta=text))


def _item(**fields: Any) -> Any:
    return SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(**fields))


def _final_message(text: str) -> Any:
    return _item(type="message_output_item", raw_item={"content": [{"text": text}]})


def _tool_call(call_id: str, name: str = "exec_command", **args: Any) -> Any:
    return _item(
        type="tool_call_item",
        raw_item={"call_id": call_id, "name": name, "arguments": json.dumps(args)},
    )


def _tool_output(call_id: str, output: str) -> Any:
    return _item(type="tool_call_output_item", raw_item={"call_id": call_id}, output=output)


def _graph(*agents: tuple[str, str | None, str]) -> GraphChanged:
    return GraphChanged(
        {aid: parent for aid, parent, _ in agents},
        {aid: "running" for aid, _, _ in agents},
        {aid: name for aid, _, name in agents},
    )


async def _start(app: KaelTUIApp, pilot: Any, *agents: tuple[str, str | None, str]) -> None:
    await pilot.pause()
    app.post_message(_graph(*(agents or ((ROOT, None, "kael"),))))
    await pilot.pause(0.1)


class TestStreaming:
    async def test_deltas_grow_one_markdown_widget_and_final_does_not_rerender(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        updates: list[str] = []
        original_update = AssistantMessage.update

        def spy(self: AssistantMessage, text: str) -> Any:
            updates.append(text)
            return original_update(self, text)

        monkeypatch.setattr(AssistantMessage, "update", spy)
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            words = [f"word{i} " for i in range(200)]
            for word in words:
                app.post_message(SdkEvent(ROOT, _delta(word)))
            await pilot.pause(0.5)

            container = app.query_one(f"#agent-{ROOT}", ChatStream)
            messages = container.query(AssistantMessage)
            assert len(messages) == 1
            assert messages[0].source == "".join(words)

            before = len(updates)  # the one initial render on mount
            app.post_message(SdkEvent(ROOT, _final_message("".join(words))))
            await pilot.pause(0.3)
            assert len(container.query(AssistantMessage)) == 1
            assert len(updates) == before, "identical final text must not call Markdown.update"

    async def test_reasoning_streams_into_folded_block_closed_by_answer(
        self, app: KaelTUIApp
    ) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            for i in range(5):
                app.post_message(
                    SdkEvent(ROOT, _delta(f"think{i} ", "response.reasoning_summary_text.delta"))
                )
            app.post_message(SdkEvent(ROOT, _delta("answer")))
            await pilot.pause(0.4)

            container = app.query_one(f"#agent-{ROOT}", ChatStream)
            reasoning = container.query(".reasoning")
            assert len(reasoning) == 1
            assert reasoning[0].has_class("folded")
            assert "think4" in reasoning[0].source
            events = app.live_view.events_for_agent(ROOT)
            assert [e["data"]["role"] for e in events] == ["reasoning", "assistant"]
            assert events[0]["data"]["metadata"]["streaming"] is False


class TestToolEvents:
    async def test_call_and_output_update_the_same_widget(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            app.post_message(SdkEvent(ROOT, _tool_call("c1", cmd="ls -la")))
            await pilot.pause(0.2)
            container = app.query_one(f"#agent-{ROOT}", ChatStream)
            (block,) = container.query(".tool-call")
            assert block.has_class("status-running")

            app.post_message(SdkEvent(ROOT, _tool_output("c1", "Output:\nfoo\n")))
            await pilot.pause(0.2)
            blocks = container.query(".tool-call")
            assert len(blocks) == 1
            assert blocks[0] is block
            assert block.has_class("status-completed")
            assert not block.has_class("status-running")

    async def test_fold_all_toggles_tool_blocks(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            for i in range(3):
                app.post_message(SdkEvent(ROOT, _tool_call(f"c{i}", cmd=f"echo {i}")))
            await pilot.pause(0.3)
            blocks = list(app.query(".tool-call"))
            assert len(blocks) == 3
            assert not any(b.has_class("folded") for b in blocks)

            await pilot.press("ctrl+o")
            assert all(b.has_class("folded") for b in blocks)
            await pilot.press("ctrl+o")
            assert not any(b.has_class("folded") for b in blocks)


class TestAgents:
    async def test_hidden_agent_gets_events_and_switching_shows_them(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot, (ROOT, None, "kael"), (CHILD, ROOT, "recon"))
            assert app.selected_agent_id == ROOT

            for i in range(3):
                app.post_message(SdkEvent(CHILD, _final_message(f"child message {i}")))
            await pilot.pause(0.3)

            child = app.query_one(f"#agent-{CHILD}", ChatStream)
            assert not child.display
            assert len(child.query(AssistantMessage)) == 3
            assert "+3" in str(app.agent_nodes[CHILD].label)

            app.selected_agent_id = CHILD
            await pilot.pause(0.3)
            assert child.display
            assert "+3" not in str(app.agent_nodes[CHILD].label)
            assert app.query_one("#chat_area").current == f"agent-{CHILD}"

    async def test_graph_changed_sets_status_glyph(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            assert str(app.agent_nodes[ROOT].label).startswith("● kael")
            app.post_message(GraphChanged({ROOT: None}, {ROOT: "completed"}, {ROOT: "kael"}))
            await pilot.pause(0.1)
            assert str(app.agent_nodes[ROOT].label).startswith("✓ kael")

    async def test_ctrl_down_cycles_agents(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot, (ROOT, None, "kael"), (CHILD, ROOT, "recon"))
            assert app.selected_agent_id == ROOT
            await pilot.press("ctrl+down")
            await pilot.pause(0.1)
            assert app.selected_agent_id == CHILD
            await pilot.press("ctrl+down")
            await pilot.pause(0.1)
            assert app.selected_agent_id == ROOT

    async def test_mounted_events_are_capped(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            for i in range(MAX_MOUNTED_EVENTS + 20):
                await app._sync_event(app.live_view.record_user_message(ROOT, f"msg {i}"))
            container = app.query_one(f"#agent-{ROOT}", ChatStream)
            assert len(container.children) == MAX_MOUNTED_EVENTS
            assert len(app.live_view.events_for_agent(ROOT)) == MAX_MOUNTED_EVENTS + 20


class TestFindings:
    async def test_callback_from_thread_appends_list_item(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await _start(app, pilot)
            # The scan thread reports findings through ReportState, whose
            # callback the app wires to post_message.
            thread = threading.Thread(
                target=app.report_state.add_vulnerability_report,
                kwargs={"title": "IDOR", "severity": "high", "agent_id": ROOT},
            )
            thread.start()
            thread.join()
            await pilot.pause(0.3)

            findings = app.query_one("#findings", ListView)
            assert len(findings.children) == 1
            assert findings.border_title == "findings (1)"
            assert "(1)" in str(app.agent_nodes[ROOT].label)


class TestInputAndKeys:
    async def test_enter_on_empty_input_is_noop_and_ctrl_j_inserts_newline(
        self, app: KaelTUIApp
    ) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            chat_input = app.query_one("#chat_input")
            await pilot.press("enter")
            assert chat_input.text == ""
            await pilot.press("a", "ctrl+j", "b")
            assert chat_input.text == "a\nb"

    async def test_ctrl_c_without_selection_opens_quit_dialog(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause(0.1)
            assert isinstance(app.screen, QuitScreen)
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert not isinstance(app.screen, QuitScreen)

    async def test_theme_and_layout(self, app: KaelTUIApp) -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.theme == "kael"
            assert "kael" in app.available_themes
            assert app.query_one("#chat_area").current == "welcome"
            assert isinstance(app.query_one("#welcome"), Markdown)
            assert app.query_one("#agents_tree").border_title == "agents"
            assert isinstance(app.query_one("#stats_display"), Static)

    async def test_tick_after_shutdown_is_noop(self, app: KaelTUIApp) -> None:
        # The 1s interval can fire while teardown is removing widgets.
        async with app.run_test(size=(120, 40)):
            pass
        app._tick()
