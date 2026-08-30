"""Tests for the TUI performance hot paths.

The chat/stats/vulnerability panels were re-rendering the entire
:class:`rich.text.Text` on every ``set_interval`` tick (≈ 2.85 Hz),
producing a noticeable post-completion lag once the event list grew.
These tests pin the new behavior:

- ``_update_stats_display`` is a no-op when the rendered text is identical
  to the previous tick (text-equality on ``Text.plain``).
- ``_update_vulnerabilities_panel`` is a no-op when the vulnerability
  set is unchanged (signature over id/severity/title/agent_id).
- ``_update_ui`` stops the heartbeat timer once the scan completes and
  no agent is in a running/waiting state.
- Multiple widget updates within ``_update_ui`` are wrapped in a single
  ``batch_update`` so a single repaint is produced.
- Streaming assistant messages render only the new tail per delta, not
  the full accumulated content. The full content is re-rendered exactly
  once on cache miss and then again on finalization.
"""

from __future__ import annotations

import argparse
import shutil
import warnings
from pathlib import Path
from typing import Any, Self
from unittest.mock import MagicMock

import pytest
from rich.text import Text

from kael.interface.tui.app import KaelTUIApp
from kael.interface.tui.renderers.agent_message_renderer import AgentMessageRenderer


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


def _make_chat_history_mock() -> MagicMock:
    widget = MagicMock()
    widget.is_mounted = True
    widget.screen = MagicMock()
    widget.scroll_y = 0
    widget.max_scroll_y = 0
    return widget


def _make_simple_widget() -> MagicMock:
    widget = MagicMock()
    widget.is_mounted = True
    widget.screen = MagicMock()
    return widget


@pytest.fixture
def app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> KaelTUIApp:
    # KaelTUIApp.__init__ calls ReportState.save_run_data() which
    # resolves ``run_dir_for(run_name)`` against the current working
    # directory and creates the directory. Run inside ``tmp_path`` so
    # the test never writes a real ``kael_runs/test-perf-*`` dir on
    # the developer's machine. See git history: 32 of these had
    # accumulated on ``main`` before this fixture was added.
    monkeypatch.chdir(tmp_path)
    fake_screen = MagicMock()
    fake_screen.selections = None
    monkeypatch.setattr(KaelTUIApp, "screen", property(lambda _: fake_screen))
    run_name = f"test-perf-{id(object())}"
    instance = KaelTUIApp(_make_args(run_name))
    instance.report_state.vulnerability_reports = []
    instance._last_vuln_signature = None
    instance._last_stats_plain = None
    yield instance
    # Defensive cleanup in case the test wrote anything else.
    leftover = tmp_path / "kael_runs"
    if leftover.exists():
        shutil.rmtree(leftover, ignore_errors=True)


def _wire_full_ui(app: KaelTUIApp) -> None:
    app._chat_history = _make_chat_history_mock()
    app._chat_display = _make_simple_widget()
    app._agents_tree = _make_simple_widget()
    app._stats_display = _make_simple_widget()
    app._status_display = _make_simple_widget()
    app._status_text = _make_simple_widget()
    app._keymap_indicator = _make_simple_widget()
    app._vulnerabilities_panel = _make_simple_widget()


class TestStatsUpdateSkip:
    @staticmethod
    def _wire_stats_widget(app: KaelTUIApp) -> MagicMock:
        widget = MagicMock()
        widget.is_mounted = True
        widget.screen = MagicMock()
        widget.screen.selections = None
        app._stats_display = widget
        return widget

    def test_first_call_renders(self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch) -> None:
        widget = self._wire_stats_widget(app)
        app._update_stats_display()
        assert widget.update.call_count == 1
        assert app._last_stats_plain is not None

    def test_second_call_with_same_content_skips(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        widget = self._wire_stats_widget(app)
        app._update_stats_display()
        app._update_stats_display()
        assert widget.update.call_count == 1, "second tick with identical stats should be a no-op"

    def test_changed_usage_updates(self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch) -> None:
        widget = self._wire_stats_widget(app)
        app._update_stats_display()
        assert widget.update.call_count == 1

        app.report_state.run_record["llm_usage"]["total_tokens"] = 150
        app.report_state.run_record["llm_usage"]["input_tokens"] = 100
        app.report_state.run_record["llm_usage"]["output_tokens"] = 50
        app._update_stats_display()
        assert widget.update.call_count == 2, "usage change should trigger a second render"


class TestVulnUpdateSkip:
    @staticmethod
    def _wire_vuln_panel(
        app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch | None = None
    ) -> MagicMock:
        widget = MagicMock()
        widget.is_mounted = True
        widget.screen = MagicMock()
        widget._vulnerabilities = []
        app._vulnerabilities_panel = widget
        if monkeypatch is not None:
            monkeypatch.setattr(KaelTUIApp, "_is_widget_safe", lambda *_: True)
        return widget

    @staticmethod
    def _vuln(
        vuln_id: str, severity: str = "high", title: str = "XSS", agent_id: str = "a1"
    ) -> dict[str, Any]:
        return {
            "id": vuln_id,
            "severity": severity,
            "title": title,
            "agent_id": agent_id,
            "timestamp": "2026-01-01T00:00:00Z",
        }

    def test_no_vulns_hides_panel(self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch) -> None:
        widget = self._wire_vuln_panel(app, monkeypatch=monkeypatch)
        app._update_vulnerabilities_panel()
        widget.add_class.assert_called_with("hidden")
        assert widget.update_vulnerabilities.call_count == 0

    def test_first_vuln_renders(self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch) -> None:
        widget = self._wire_vuln_panel(app, monkeypatch=monkeypatch)
        app.report_state.vulnerability_reports = [self._vuln("v-1")]
        app._update_vulnerabilities_panel()
        assert widget.update_vulnerabilities.call_count == 1
        assert app._last_vuln_signature is not None

    def test_same_vuln_set_skips(self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch) -> None:
        widget = self._wire_vuln_panel(app, monkeypatch=monkeypatch)
        app.report_state.vulnerability_reports = [self._vuln("v-1")]
        app._update_vulnerabilities_panel()
        app._update_vulnerabilities_panel()
        assert widget.update_vulnerabilities.call_count == 1

    def test_new_vuln_triggers_render(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        widget = self._wire_vuln_panel(app, monkeypatch=monkeypatch)
        app.report_state.vulnerability_reports = [self._vuln("v-1")]
        app._update_vulnerabilities_panel()
        app.report_state.vulnerability_reports = [
            self._vuln("v-1"),
            self._vuln("v-2", severity="critical", title="RCE"),
        ]
        app._update_vulnerabilities_panel()
        assert widget.update_vulnerabilities.call_count == 2

    def test_clearing_vulns_resets_signature(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._wire_vuln_panel(app, monkeypatch=monkeypatch)
        app.report_state.vulnerability_reports = [self._vuln("v-1")]
        app._update_vulnerabilities_panel()
        app.report_state.vulnerability_reports = []
        app._update_vulnerabilities_panel()
        assert app._last_vuln_signature is None


class TestHasActiveAgents:
    def test_empty(self, app: KaelTUIApp) -> None:
        assert app._has_active_agents() is False

    def test_running(self, app: KaelTUIApp) -> None:
        app.live_view.upsert_agent("a1", name="alpha", status="running")
        assert app._has_active_agents() is True

    def test_completed(self, app: KaelTUIApp) -> None:
        app.live_view.upsert_agent("a1", name="alpha", status="completed")
        assert app._has_active_agents() is False

    def test_mixed(self, app: KaelTUIApp) -> None:
        app.live_view.upsert_agent("a1", name="alpha", status="completed")
        app.live_view.upsert_agent("a2", name="beta", status="running")
        assert app._has_active_agents() is True


class TestHeartbeatStopsOnCompletion:
    def test_stops_when_no_active_agents(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        timer = MagicMock()
        app._heartbeat_timer = timer
        _wire_full_ui(app)
        app._scan_completed.set()
        monkeypatch.setattr(KaelTUIApp, "_is_widget_safe", lambda *_: True)
        app._update_ui()
        timer.stop.assert_called_once()
        assert app._heartbeat_timer is None

    def test_keeps_running_with_active_agent(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        timer = MagicMock()
        app._heartbeat_timer = timer
        _wire_full_ui(app)
        app._scan_completed.set()
        app.live_view.upsert_agent("a1", name="alpha", status="running")
        monkeypatch.setattr(KaelTUIApp, "_is_widget_safe", lambda *_: True)
        app._update_ui()
        timer.stop.assert_not_called()
        assert app._heartbeat_timer is timer

    def test_keeps_running_when_scan_active(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        timer = MagicMock()
        app._heartbeat_timer = timer
        _wire_full_ui(app)
        monkeypatch.setattr(KaelTUIApp, "_is_widget_safe", lambda *_: True)
        app._update_ui()
        timer.stop.assert_not_called()


class TestBatchUpdateWraps:
    def test_update_ui_uses_batch_update(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entered: list[bool] = []

        batch_self: list[KaelTUIApp] = []

        def fake_batch_update(inner_self: KaelTUIApp) -> Any:
            batch_self.append(inner_self)

            class _Batch:
                def __enter__(self) -> Self:
                    entered.append(True)
                    return self

                def __exit__(self, *exc: object) -> None:
                    entered.append(False)

            return _Batch()

        _wire_full_ui(app)
        monkeypatch.setattr(KaelTUIApp, "_is_widget_safe", lambda *_: True)
        monkeypatch.setattr(KaelTUIApp, "batch_update", fake_batch_update)
        app._update_ui()
        assert entered == [True, False], (
            "_update_ui should wrap the per-tick updates in batch_update"
        )
        assert batch_self == [app]


class TestStreamingTailRender:
    """Pin the new tail-render fast path for streaming assistant messages.

    On every SDK delta the live view mutates the open assistant event in
    place (content grows, version bumps). The TUI used to re-render the
    full accumulated content every tick — O(N) per delta, O(N²) over the
    whole stream. The new path renders only the new tail and concatenates
    onto a cached ``Text``.
    """

    @staticmethod
    def _make_streaming_event(content: str, version: int = 1) -> dict[str, Any]:
        return {
            "id": "chat_1",
            "type": "chat",
            "agent_id": "a1",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": version,
            "data": {
                "role": "assistant",
                "content": content,
                "metadata": {"source": "sdk_stream", "streaming": True},
            },
        }

    def test_initial_open_event_renders_full_content(self, app: KaelTUIApp) -> None:
        event = self._make_streaming_event("hello world", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = event

        rendered = app._render_event_content(event)

        assert isinstance(rendered, Text)
        assert "hello world" in rendered.plain
        assert app._rendered_content_len["chat_1"] == len("hello world")

    def test_streaming_delta_renders_only_tail(self, app: KaelTUIApp) -> None:
        # First render: full content, version 1
        first = self._make_streaming_event("hello ", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        first_render = app._render_event_content(first)
        assert isinstance(first_render, Text)
        first_len = len(first_render.plain)
        # Streaming events are cached by id alone (not id+version) so
        # the tail path can find the previous render on the next delta.
        assert app._rendered_event_cache["chat_1"] is first_render

        # Delta arrives: content grows, version bumps
        delta = self._make_streaming_event("hello world", version=2)
        app.live_view._open_assistant_event_by_agent["a1"] = delta

        delta_render = app._render_event_content(delta)

        # The new render must include the entire accumulated content
        assert "hello world" in delta_render.plain
        # And it must include the original content
        assert "hello " in delta_render.plain
        # Tail length is the delta (6 chars: "world"); cached length was
        # 6 ("hello "), so combined should be 6 + 6 = 12 (modulo any
        # whitespace the markdown pass inserts). We only assert >=.
        assert len(delta_render.plain) >= first_len
        assert app._rendered_content_len["chat_1"] == len("hello world")

    def test_streaming_deltas_do_not_invoke_full_render(self, app: KaelTUIApp) -> None:
        """Critical regression guard: a long stream of deltas must not
        call ``render_simple`` once per delta. The tail path bypasses
        the full-content markdown pass and just appends a small
        rendered tail.
        """
        # The lru_cache on render_simple counts each unique full-content
        # call as a miss. Streaming deltas should never invoke
        # render_simple; only the initial cache miss and a final miss on
        # finalization should show up.
        AgentMessageRenderer.render_simple.cache_clear()
        baseline = AgentMessageRenderer.render_simple.cache_info().misses

        # First event: full render → 1 miss
        event = self._make_streaming_event("a", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = event
        app._render_event_content(event)
        after_initial = AgentMessageRenderer.render_simple.cache_info().misses
        assert after_initial - baseline == 1

        # 50 deltas
        accumulated = "a"
        for i in range(50):
            accumulated += "b"
            delta = self._make_streaming_event(accumulated, version=i + 2)
            app.live_view._open_assistant_event_by_agent["a1"] = delta
            app._render_event_content(delta)

        after_deltas = AgentMessageRenderer.render_simple.cache_info().misses
        assert after_deltas == after_initial, (
            f"expected no additional render_simple misses across 50 "
            f"deltas; got {after_deltas - after_initial}"
        )

    def test_finalization_triggers_fresh_full_render(self, app: KaelTUIApp) -> None:
        # Open event, version 1
        open_event = self._make_streaming_event("streaming ", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = open_event
        app._render_event_content(open_event)

        # Finalize: remove from open map AND set metadata.streaming = False
        app.live_view._open_assistant_event_by_agent.pop("a1", None)
        final_event = self._make_streaming_event("streaming done", version=2)
        final_event["data"]["metadata"]["streaming"] = False

        final_render = app._render_event_content(final_event)
        assert isinstance(final_render, Text)
        assert "streaming done" in final_render.plain

    def test_is_open_streaming_chat(self, app: KaelTUIApp) -> None:
        open_event = self._make_streaming_event("hi", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = open_event
        assert app._is_open_streaming_chat(open_event) is True

        # User events: never streaming on the assistant path
        user_event = {
            "id": "chat_2",
            "type": "chat",
            "agent_id": "a1",
            "timestamp": "2026-01-01T00:00:01Z",
            "version": 1,
            "data": {
                "role": "user",
                "content": "hi",
                "metadata": {"source": "tui_user"},
            },
        }
        assert app._is_open_streaming_chat(user_event) is False

        # Finalized assistant event: not open
        app.live_view._open_assistant_event_by_agent.pop("a1", None)
        final = self._make_streaming_event("hi", version=2)
        final["data"]["metadata"]["streaming"] = False
        assert app._is_open_streaming_chat(final) is False

    def test_append_streaming_tail_no_op_when_content_shrank(self, app: KaelTUIApp) -> None:
        open_event = self._make_streaming_event("hello", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = open_event
        cached = app._render_event_content(open_event)
        assert isinstance(cached, Text)

        # Defensive: content shorter than prev_len returns the cached Text
        # unchanged.
        result = app._append_streaming_tail(open_event, cached, {"content": "hi", "metadata": {}})
        assert result is cached

    def test_render_simple_lru_cache_hits_for_repeat_content(self, app: KaelTUIApp) -> None:
        # Clearing the cache_info baseline by reading it once
        AgentMessageRenderer.render_simple.cache_clear()
        AgentMessageRenderer.render_simple("repeat me")
        AgentMessageRenderer.render_simple("repeat me")
        AgentMessageRenderer.render_simple("repeat me")
        info = AgentMessageRenderer.render_simple.cache_info()
        assert info.hits >= 2
        assert info.misses == 1

    def test_live_view_is_open_assistant_event(self, app: KaelTUIApp) -> None:
        # Initially no open events
        assert app.live_view.is_open_assistant_event("chat_1") is False

        # Add an open event
        open_event = self._make_streaming_event("hi", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = open_event
        assert app.live_view.is_open_assistant_event("chat_1") is True
        assert app.live_view.is_open_assistant_event("chat_2") is False

    def test_gather_agent_events_does_not_sort(self, app: KaelTUIApp) -> None:
        """The per-tick sort in ``_gather_agent_events`` was removed
        because events are already in arrival order from
        ``live_view._append_event``.
        """
        for i in range(5):
            app.live_view._append_event(
                "a1",
                "chat",
                {
                    "role": "user",
                    "content": f"msg-{i}",
                    "metadata": {"source": "tui_user"},
                },
            )
        events = app._gather_agent_events("a1")
        contents = [e["data"]["content"] for e in events]
        assert contents == [f"msg-{i}" for i in range(5)]

    def test_streaming_delta_at_whitespace_boundary(self, app: KaelTUIApp) -> None:
        """When the SDK token boundary lands on a whitespace character,
        the cached first render strips it but the tail render must
        re-include the boundary character. Otherwise the user sees
        ``"helloworld"`` instead of ``"hello world"``.
        """
        # First render: trailing space gets stripped by render_simple
        first = self._make_streaming_event("hello ", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        first_render = app._render_event_content(first)
        assert isinstance(first_render, Text)
        assert first_render.plain == "hello"
        # The offset tracks the rendered length (5), not the raw length (6)
        assert app._rendered_content_len["chat_1"] == 5

        # Delta: raw content "hello world"; the slice [5:] is " world"
        # (with the leading space included) so the tail render re-adds it.
        delta = self._make_streaming_event("hello world", version=2)
        app.live_view._open_assistant_event_by_agent["a1"] = delta
        delta_render = app._render_event_content(delta)
        assert "hello world" in delta_render.plain
        assert "helloworld" not in delta_render.plain

    def test_streaming_delta_with_code_block_incremental(self, app: KaelTUIApp) -> None:
        """Code blocks are tokenized by Pygments on the tail. The full
        output should still contain the code block content; the tail
        render must not produce a partial/unclosed code fence.
        """
        # First render: opens a code block
        first = self._make_streaming_event("```python\nx = 1", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        app._render_event_content(first)

        # Delta: closes the code block
        delta = self._make_streaming_event("```python\nx = 1\n```", version=2)
        app.live_view._open_assistant_event_by_agent["a1"] = delta
        delta_render = app._render_event_content(delta)
        # The code block content should be present in the rendered text
        assert "x = 1" in delta_render.plain

    def test_streaming_tail_mutates_cached_in_place(self, app: KaelTUIApp) -> None:
        """Ponytail fix: the tail-render must mutate the cached Text
        in place, not rebuild a fresh combined Text on every delta.

        The earlier implementation did
        ``combined = Text(); combined.append_text(cached); combined.append_text(tail)``
        which copied the full accumulated content every tick — O(content)
        per delta, O(N²) over a long final-report stream. The new path
        returns the same ``Text`` object from the cache, mutated in place
        to grow by the new tail — O(tail) per delta, O(N) over the stream.

        Regression guard: the returned Text from a tail render must be
        the *same object* the cache holds. If a future refactor
        reintroduces the copy, this test fails.
        """
        first = self._make_streaming_event("hello", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        first_render = app._render_event_content(first)
        assert isinstance(first_render, Text)
        cached_id = id(first_render)

        delta = self._make_streaming_event("hello world", version=2)
        app.live_view._open_assistant_event_by_agent["a1"] = delta
        delta_render = app._render_event_content(delta)
        assert isinstance(delta_render, Text)
        assert id(delta_render) == cached_id, (
            "tail render must return the cached Text mutated in place, not a fresh copy"
        )
        # The cache must hold the same object too.
        assert app._rendered_event_cache["chat_1"] is delta_render

    def test_get_rendered_events_skips_sanitize_for_single_text(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ponytail fix: the single-Text fast path (one chat event,
        typically the streaming final report) must skip the per-tick
        ``_sanitize_text`` call. Our renderer produces well-formed
        Text — re-walking every span every tick was O(spans) overhead
        per delta on long final reports.

        Regression guard: ``_sanitize_text`` must not be called from
        ``_get_rendered_events_content`` when the only renderable is a
        single Text.
        """
        calls: list[int] = []

        original = KaelTUIApp._sanitize_text

        def counting(text: Text) -> Text:
            calls.append(1)
            return original(text)

        monkeypatch.setattr(KaelTUIApp, "_sanitize_text", counting)

        first = self._make_streaming_event("hello", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        app.live_view._append_event("a1", "chat", first["data"])
        events_list = app.live_view._events_by_agent["a1"]
        first_event = events_list[-1]
        first_event["version"] = 1
        first_event["data"]["metadata"]["streaming"] = True
        app.live_view._open_assistant_event_by_agent["a1"] = first_event
        first_event["data"]["content"] = "hello"
        app._render_event_content(first_event)

        # Drive the full _update_chat_view path: 30 deltas.
        before = sum(calls)
        accumulated = "hello"
        for i in range(30):
            accumulated += " more"
            first_event["version"] = i + 2
            first_event["data"]["content"] = accumulated
            first_event["data"]["metadata"]["streaming"] = True
            events = app._gather_agent_events("a1")
            current_event_ids = [f"{e['id']}:{e.get('version', 0)}" for e in events]
            if current_event_ids != app._displayed_events:
                app._displayed_events = current_event_ids
                app._get_rendered_events_content(events)
        after = sum(calls)
        assert after - before == 0, (
            f"_get_rendered_events_content must skip _sanitize_text "
            f"on the single-Text streaming path; got {after - before} "
            f"sanitize calls over 30 deltas"
        )

    def test_get_rendered_events_sanitize_still_runs_on_multi_renderable(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Counterpart to the single-Text skip: the multi-renderable
        merge path (chat + tool widgets) must still call
        ``_sanitize_text`` on the final combined so any malformed
        spans from tool renders get clamped before the widget update.
        """
        calls: list[int] = []

        original = KaelTUIApp._sanitize_text

        def counting(text: Text) -> Text:
            calls.append(1)
            return original(text)

        monkeypatch.setattr(KaelTUIApp, "_sanitize_text", counting)

        # Open a chat streaming event + a tool event. The renderable
        # list now has a Text (chat) and a Static (tool) so the
        # single-Text fast path is bypassed and we go through merge.
        first = self._make_streaming_event("report body", version=1)
        app.live_view._open_assistant_event_by_agent["a1"] = first
        app.live_view._append_event("a1", "chat", first["data"])
        events_list = app.live_view._events_by_agent["a1"]
        chat_event = events_list[-1]
        chat_event["version"] = 1
        chat_event["data"]["metadata"]["streaming"] = True

        # Append a tool event too.
        app.live_view._append_event(
            "a1",
            "tool",
            {
                "tool_name": "shell",
                "args": {"command": "ls"},
                "status": "completed",
                "agent_id": "a1",
                "call_id": "call-1",
            },
        )

        events = app._gather_agent_events("a1")
        before = sum(calls)
        app._get_rendered_events_content(events)
        after = sum(calls)
        assert after > before, (
            "merge path must still call _sanitize_text on the final "
            "combined so tool-render spans are clamped"
        )


class TestScrollDeferUpdate:
    """Pin the defer-flush behaviour that eliminates scroll lag.

    ``Static.update()`` re-converts the whole chat ``Text`` via
    ``Content.from_rich_text`` (~200ms for a 250KB report). While the
    user is scrolled up reading history, that freeze lands on the UI
    thread mid-scroll → the "random" scroll lag. The fix skips the
    update while scrolled up and flushes the stashed content when the
    user returns to the bottom (or when the scan completes).
    """

    @staticmethod
    def _wire_chat(app: KaelTUIApp, *, scroll_y: int, max_scroll_y: int) -> MagicMock:
        history = _make_chat_history_mock()
        history.scroll_y = scroll_y
        history.max_scroll_y = max_scroll_y
        history.is_mounted = True
        history.screen = MagicMock()
        app._chat_history = history
        display = _make_simple_widget()
        display.screen = MagicMock()
        app._chat_display = display
        return display

    @staticmethod
    def _seed_event(app: KaelTUIApp, content: str, version: int = 1) -> None:
        # Neutralize the reactive watcher so setting selected_agent_id
        # doesn't fire call_later(_update_chat_view) during the test
        # (would pollute the call_later call count assertions).
        app.watch_selected_agent_id = lambda *_: None
        app.selected_agent_id = "a1"
        app._displayed_events.clear()
        app._pending_chat_content = None
        event = {
            "id": "chat_1",
            "type": "chat",
            "agent_id": "a1",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": version,
            "data": {"role": "assistant", "content": content},
        }
        app.live_view._append_event("a1", "chat", event["data"])
        events_list = app.live_view._events_by_agent["a1"]
        events_list[-1]["version"] = version

    def test_scrolled_up_skips_update_and_defers(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(app, "call_later", lambda *_, **__: None)
        self._seed_event(app, "first render", version=1)
        # scrolled up: scroll_y=0, max_scroll_y=10 → not at bottom
        display = self._wire_chat(app, scroll_y=0, max_scroll_y=10)

        app._update_chat_view()

        assert display.update.call_count == 0, (
            "scrolled-up tick must not call Static.update (the ~200ms "
            "from_rich_text freeze that causes scroll lag)"
        )
        assert app._pending_chat_content is not None, "content must be stashed for deferred flush"
        assert app._displayed_events, (
            "_displayed_events must be committed at stash time so a "
            "no-change heartbeat short-circuits instead of re-rendering"
        )

    def test_return_to_bottom_flushes_pending(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scroll_end_calls: list[bool] = []
        monkeypatch.setattr(app, "call_later", lambda *_, **__: scroll_end_calls.append(True))
        self._seed_event(app, "deferred body", version=1)
        self._wire_chat(app, scroll_y=0, max_scroll_y=10)

        # Tick 1: scrolled up → defer.
        app._update_chat_view()
        assert app._pending_chat_content is not None

        # User scrolls back to bottom.
        app._chat_history.scroll_y = 10
        app._chat_history.max_scroll_y = 10

        app._update_chat_view()

        assert app._pending_chat_content is None, "flush must clear pending"
        assert app._chat_display.update.call_count == 1, (
            "return-to-bottom must flush the deferred update"
        )
        assert scroll_end_calls, "flush must re-pin to the bottom (scroll_end)"

    def test_at_bottom_updates_immediately(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(app, "call_later", lambda *_, **__: None)
        self._seed_event(app, "live stream", version=1)
        # at bottom: scroll_y == max_scroll_y
        display = self._wire_chat(app, scroll_y=5, max_scroll_y=5)

        app._update_chat_view()

        assert display.update.call_count == 1, (
            "at-bottom tick must update immediately (follow the stream)"
        )
        assert app._pending_chat_content is None

    def test_scan_completion_flush_preserves_scroll_position(
        self, app: KaelTUIApp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scroll_end_calls: list[bool] = []
        monkeypatch.setattr(app, "call_later", lambda *_, **__: scroll_end_calls.append(True))
        self._seed_event(app, "final report", version=1)
        self._wire_chat(app, scroll_y=0, max_scroll_y=10)

        # Defer while scrolled up.
        app._update_chat_view()
        assert app._pending_chat_content is not None

        # Scan completes → flush WITHOUT scroll_end (preserve reading pos).
        app._flush_pending_chat(scroll_to_end=False)

        assert app._pending_chat_content is None
        assert app._chat_display.update.call_count == 1, (
            "completion must flush the deferred content so the user sees "
            "the final report even if they never scroll back to bottom"
        )
        assert not scroll_end_calls, (
            "completion flush must NOT scroll_end — preserve the user's "
            "reading position instead of yanking them to the bottom"
        )


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
