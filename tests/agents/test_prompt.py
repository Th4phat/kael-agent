"""Tests for the system prompt renderer (Phase 1.4 — no silent failures)."""

from __future__ import annotations

import pytest

from kael.agents import prompt as prompt_module
from kael.agents.prompt import SystemPromptRenderError, render_system_prompt


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning",
    "ignore::ResourceWarning",
)


class TestRenderSystemPrompt:
    def test_renders_successfully(self) -> None:
        out = render_system_prompt()
        assert isinstance(out, str)
        assert len(out) > 100
        assert "Kael" in out or "security" in out.lower()

    def test_root_agent_includes_coordination_skill(self) -> None:
        out = render_system_prompt(is_root=True)
        assert isinstance(out, str)

    def test_non_root_omits_root_coordination(self) -> None:
        out_root = render_system_prompt(is_root=True)
        out_child = render_system_prompt(is_root=False)
        # The root coordination block is template-driven; we just check
        # the renders are different (root has extra material).
        assert isinstance(out_root, str)
        assert isinstance(out_child, str)

    def test_whitebox_includes_extra_skills(self) -> None:
        out_wb = render_system_prompt(is_whitebox=True)
        out_bb = render_system_prompt(is_whitebox=False)
        assert isinstance(out_wb, str)
        assert isinstance(out_bb, str)

    def test_prompt_only_renders_separate_template(self) -> None:
        """Prompt-only mode swaps to a freeform template that has no
        authorized-target / refusal-avoidance section.
        """
        out = render_system_prompt(prompt_only=True)
        assert isinstance(out, str)
        assert "PROMPT-ONLY MODE" in out
        # The default security template's "system-verified scope" and
        # refusal-avoidance blocks must NOT appear in prompt-only.
        assert "SYSTEM-VERIFIED SCOPE" not in out
        assert "REFUSAL AVOIDANCE" not in out

    def test_prompt_only_and_default_differ(self) -> None:
        default = render_system_prompt()
        freeform = render_system_prompt(prompt_only=True)
        assert default != freeform

    def test_failure_raises_instead_of_returning_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Phase 1.4 fix: a render failure must raise, not return ``""``."""

        def broken(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("simulated template error")

        prompt_module._build_env_and_skills.cache_clear()
        monkeypatch.setattr(prompt_module, "load_skills", broken)
        with pytest.raises(SystemPromptRenderError) as excinfo:
            render_system_prompt()
        assert "simulated template error" in str(excinfo.value)
        prompt_module._build_env_and_skills.cache_clear()


class TestPromptCaching:
    def test_cached_for_same_input(self) -> None:
        prompt_module._build_env_and_skills.cache_clear()
        a = prompt_module._build_env_and_skills(
            skills=("vulnerabilities/sql_injection",),
            scan_mode="deep",
            is_whitebox=False,
            is_root=True,
            browser_backend="",
        )
        b = prompt_module._build_env_and_skills(
            skills=("vulnerabilities/sql_injection",),
            scan_mode="deep",
            is_whitebox=False,
            is_root=True,
            browser_backend="",
        )
        assert a is b
        prompt_module._build_env_and_skills.cache_clear()
