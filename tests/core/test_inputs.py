"""Tests for the scan-config → root-task builder."""

from __future__ import annotations

import json

from agents.run_config import CallModelData, ModelInputData

from kael.core.inputs import (
    build_root_task,
    build_scope_context,
    child_initial_input,
    limit_model_input,
)


class TestBuildRootTask:
    def test_prompt_only_skips_target_preamble(self) -> None:
        """Prompt-only runs must not include target / scope boilerplate
        that the prompt-only system prompt doesn't expect.
        """
        task = build_root_task(
            {
                "targets": [],
                "user_instructions": "do a thing",
                "prompt_only": True,
            }
        )
        assert "Special instructions" not in task
        assert "Repositories" not in task
        assert "URLs" not in task
        assert "do a thing" in task

    def test_prompt_only_without_instructions_returns_prompt(self) -> None:
        task = build_root_task(
            {
                "targets": [],
                "user_instructions": "",
                "prompt_only": True,
            }
        )
        assert "No task provided" in task

    def test_targeted_run_includes_target_metadata(self) -> None:
        task = build_root_task(
            {
                "targets": [
                    {
                        "type": "web_application",
                        "details": {"target_url": "https://example.com"},
                    }
                ],
                "user_instructions": "focus on auth",
                "prompt_only": False,
            }
        )
        assert "https://example.com" in task
        assert "focus on auth" in task
        assert "Special instructions" in task


class TestBuildScopeContext:
    def test_prompt_only_relaxes_scope(self) -> None:
        ctx = build_scope_context(
            {
                "targets": [],
                "prompt_only": True,
            }
        )
        assert ctx["scope_source"] == "user_prompt"
        assert ctx["authorization_source"] == "user_prompt_only"
        assert ctx["user_instructions_do_not_expand_scope"] is False
        assert ctx["authorized_targets"] == []

    def test_targeted_run_keeps_strict_scope(self) -> None:
        ctx = build_scope_context(
            {
                "targets": [
                    {
                        "type": "web_application",
                        "details": {"target_url": "https://example.com"},
                    }
                ],
                "prompt_only": False,
            }
        )
        assert ctx["scope_source"] == "system_scan_config"
        assert ctx["authorization_source"] == "kael_platform_verified_targets"
        assert ctx["user_instructions_do_not_expand_scope"] is True
        assert len(ctx["authorized_targets"]) == 1


def test_model_input_stays_bounded_without_losing_task_or_latest_tool_result() -> None:
    items = [{"role": "user", "content": "original task"}]
    for i in range(40):
        items.extend(
            [
                {
                    "type": "function_call",
                    "call_id": str(i),
                    "name": "exec_command",
                    "arguments": "{}",
                },
                {"type": "function_call_output", "call_id": str(i), "output": "x" * 10_000},
            ]
        )
    items[-1]["output"] += "LATEST_RESULT"
    items.insert(21, {"role": "user", "content": "keep this later instruction"})
    original = json.dumps(items)
    data = CallModelData(
        model_data=ModelInputData(input=items, instructions="scope"),
        agent=None,  # type: ignore[arg-type]
        context=None,
    )

    result = limit_model_input(data)

    assert result.instructions == "scope"
    assert result.input[0] == items[0]
    assert result.input[1]["content"] == "keep this later instruction"
    assert "LATEST_RESULT" in result.input[-1]["output"]
    assert len(json.dumps(result.input)) <= 60_000
    assert json.dumps(items) == original
    calls = {item["call_id"] for item in result.input if item.get("type") == "function_call"}
    assert all(
        item.get("call_id") in calls
        for item in result.input
        if item.get("type") == "function_call_output"
    )


def test_inherited_parent_history_is_bounded() -> None:
    inherited = child_initial_input(
        name="child",
        child_id="child-id",
        parent_id="root-id",
        task="focused task",
        parent_history=[{"role": "user", "content": "x" * 200_000}],
    )
    assert len(inherited[0]["content"]) < 9_000
    assert inherited[-1]["content"] == "focused task"

    legacy = [
        {"role": "user", "content": "== Inherited context from parent ==\n" + "x" * 160_000},
        {"role": "user", "content": "child identity"},
        {"role": "user", "content": "focused task"},
        {"type": "function_call", "call_id": "1", "name": "think", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "1", "output": "done"},
    ]
    result = limit_model_input(
        CallModelData(ModelInputData(input=legacy, instructions=None), agent=None, context=None)  # type: ignore[arg-type]
    )
    assert result.input[0]["content"] == "focused task"
    assert len(json.dumps(result.input)) <= 60_000
