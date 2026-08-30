"""Tests for the scan-config → root-task builder."""

from __future__ import annotations

from kael.core.inputs import build_root_task, build_scope_context


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
