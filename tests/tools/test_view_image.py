"""Tests for the Kael vision sub-agent ``view_image`` tool."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# Minimal 1x1 PNG so the SDK mime-type sniff returns ``image/png``.
_PNG_1x1 = bytes.fromhex(
    "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C489"
    "0000000A49444154789C6300010000000500010D0A2DB40000000049454E44AE426082"
)


def _make_session_with_png() -> MagicMock:
    session = MagicMock()
    policy = MagicMock()
    policy.absolute_workspace_path.side_effect = lambda p: p
    policy.relative_path.side_effect = lambda p: p
    session._workspace_path_policy.return_value = policy

    file_obj = MagicMock()
    file_obj.read.return_value = _PNG_1x1
    session.read = AsyncMock(return_value=file_obj)
    return session


class TestViewImageVisionSubAgent:
    def test_args_model_exposes_prompt_field(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs

        fields = ViewImageArgs.model_fields
        assert "path" in fields
        assert "prompt" in fields
        assert fields["prompt"].default

    def test_returns_text_from_vision_model(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        msg = MagicMock(spec=["content"])
        chunk = MagicMock()
        chunk.text = "A login form labelled 'Welcome back'."
        msg.content = [chunk]
        response = MagicMock()
        response.output = [msg]
        response.usage = MagicMock()

        model = MagicMock()
        model.get_response = AsyncMock(return_value=response)

        settings = MagicMock()
        settings.llm.model = "openai/gpt-5"
        settings.llm.vision_model = None
        settings.llm.openrouter_provider = None

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
            patch("kael.tools.view_image.tool.KaelProvider") as provider_cls,
            patch(
                "kael.tools.view_image.tool.get_global_report_state",
                return_value=None,
            ),
            patch("kael.tools.view_image.tool.ResponseOutputMessage", MagicMock),
        ):
            provider_cls.return_value.get_model.return_value = model
            out = asyncio.run(tool.run(ViewImageArgs(path="shot.png", prompt="What do you see?")))

        assert out == "A login form labelled 'Welcome back'."
        # The vision call must include the image as an input_image data URL
        # with high detail — that is the whole point of this tool.
        kwargs = model.get_response.await_args.kwargs
        user_message = kwargs["input"][0]
        image_part = next(p for p in user_message["content"] if p["type"] == "input_image")
        assert image_part["image_url"].startswith("data:image/png;base64,")
        assert image_part["detail"] == "high"

    def test_missing_kael_llm_returns_helpful_message(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        settings = MagicMock()
        settings.llm.model = None
        settings.llm.vision_model = None

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
        ):
            out = asyncio.run(tool.run(ViewImageArgs(path="x.png")))

        assert "KAEL_LLM" in out
        assert "x.png" in out

    def test_unreadable_image_returns_error_string(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = MagicMock()
        policy = MagicMock()
        policy.absolute_workspace_path.side_effect = lambda p: p
        policy.relative_path.side_effect = lambda p: p
        session._workspace_path_policy.return_value = policy
        session.read = AsyncMock(side_effect=FileNotFoundError)

        tool = ViewImageTool(session=session)
        out = asyncio.run(tool.run(ViewImageArgs(path="ghost.png")))
        assert "was not found" in out

    def test_non_image_payload_rejected(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = MagicMock()
        policy = MagicMock()
        policy.absolute_workspace_path.side_effect = lambda p: p
        policy.relative_path.side_effect = lambda p: p
        session._workspace_path_policy.return_value = policy

        file_obj = MagicMock()
        file_obj.read.return_value = b"this is not an image"
        session.read = AsyncMock(return_value=file_obj)

        tool = ViewImageTool(session=session)
        out = asyncio.run(tool.run(ViewImageArgs(path="notes.txt")))
        assert "not a supported image file" in out

    def test_dedicated_vision_model_used_when_configured(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        msg = MagicMock(spec=["content"])
        chunk = MagicMock()
        chunk.text = "vision output"
        msg.content = [chunk]
        response = MagicMock()
        response.output = [msg]
        response.usage = MagicMock()

        vision_model = MagicMock()
        vision_model.get_response = AsyncMock(return_value=response)

        settings = MagicMock()
        settings.llm.model = "anthropic/claude-3-haiku-text-only"
        settings.llm.vision_model = "openai/gpt-4o"
        settings.llm.vision_api_key = "sk-vision-key"
        settings.llm.vision_api_base = None
        settings.llm.api_key = "sk-main-key"
        settings.llm.api_base = None
        settings.llm.openrouter_provider = None

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
            patch("kael.tools.view_image.tool.LitellmModel") as litellm_cls,
            patch("kael.tools.view_image.tool.KaelProvider") as provider_cls,
            patch(
                "kael.tools.view_image.tool.get_global_report_state",
                return_value=None,
            ),
            patch("kael.tools.view_image.tool.ResponseOutputMessage", MagicMock),
        ):
            litellm_cls.return_value = vision_model
            out = asyncio.run(tool.run(ViewImageArgs(path="shot.png")))

        assert out == "vision output"
        # KaelProvider must NOT be used when vision_model is set; the
        # vision call has its own dedicated credentials.
        provider_cls.assert_not_called()
        litellm_cls.assert_called_once_with(
            model="openai/gpt-4o",
            api_key="sk-vision-key",
            base_url=None,
        )

    def test_vision_creds_fall_back_to_main(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        response = MagicMock()
        response.output = []
        response.usage = MagicMock()
        vision_model = MagicMock()
        vision_model.get_response = AsyncMock(return_value=response)

        settings = MagicMock()
        settings.llm.model = "openai/gpt-5"
        settings.llm.vision_model = "openai/gpt-4o"
        settings.llm.vision_api_key = None
        settings.llm.vision_api_base = None
        settings.llm.api_key = "sk-main-key"
        settings.llm.api_base = "https://api.example.com"
        settings.llm.openrouter_provider = None

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
            patch("kael.tools.view_image.tool.LitellmModel") as litellm_cls,
            patch(
                "kael.tools.view_image.tool.get_global_report_state",
                return_value=None,
            ),
        ):
            litellm_cls.return_value = vision_model
            asyncio.run(tool.run(ViewImageArgs(path="shot.png")))

        litellm_cls.assert_called_once_with(
            model="openai/gpt-4o",
            api_key="sk-main-key",
            base_url="https://api.example.com",
        )

    def test_openrouter_provider_routed_for_vision_model(self) -> None:
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        response = MagicMock()
        response.output = []
        response.usage = MagicMock()
        vision_model = MagicMock()
        vision_model.get_response = AsyncMock(return_value=response)

        settings = MagicMock()
        settings.llm.model = "anthropic/claude-3-haiku"
        settings.llm.vision_model = "openrouter/openai/gpt-4o"
        settings.llm.vision_api_key = "sk-or"
        settings.llm.vision_api_base = None
        settings.llm.api_key = "sk-main"
        settings.llm.api_base = None
        settings.llm.openrouter_provider = {"order": ["OpenAI"]}

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
            patch("kael.tools.view_image.tool.LitellmModel") as litellm_cls,
            patch(
                "kael.tools.view_image.tool.get_global_report_state",
                return_value=None,
            ),
        ):
            litellm_cls.return_value = vision_model
            asyncio.run(tool.run(ViewImageArgs(path="shot.png")))

        kwargs = vision_model.get_response.await_args.kwargs
        assert kwargs["model_settings"].extra_body == {"provider": {"order": ["OpenAI"]}}

    def test_bare_model_uses_openai_compat_client(self) -> None:
        """Bare model name + VISION_LLM_API_BASE → raw OpenAI-compat client.

        This is the path for vLLM, Ollama, LM Studio, LiteLLM Proxy,
        and any other OpenAI-compatible endpoint that does not need
        litellm provider-prefix routing.
        """
        from kael.tools.view_image.tool import ViewImageArgs, ViewImageTool

        session = _make_session_with_png()
        tool = ViewImageTool(session=session)

        response = MagicMock()
        response.output = []
        response.usage = MagicMock()
        vision_model_obj = MagicMock()
        vision_model_obj.get_response = AsyncMock(return_value=response)

        settings = MagicMock()
        settings.llm.model = "openai/gpt-5"
        settings.llm.vision_model = "qwen2.5vl-7b"
        settings.llm.vision_api_key = "ollama"
        settings.llm.vision_api_base = "http://localhost:11434/v1"
        settings.llm.api_key = "sk-main"
        settings.llm.api_base = None
        settings.llm.openrouter_provider = None

        with (
            patch("kael.tools.view_image.tool.load_settings", return_value=settings),
            patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
            patch("kael.tools.view_image.tool.AsyncOpenAI") as client_cls,
            patch("kael.tools.view_image.tool.OpenAIChatCompletionsModel") as chat_cls,
            patch("kael.tools.view_image.tool.LitellmModel") as litellm_cls,
            patch(
                "kael.tools.view_image.tool.get_global_report_state",
                return_value=None,
            ),
        ):
            chat_cls.return_value = vision_model_obj
            asyncio.run(tool.run(ViewImageArgs(path="shot.png")))

        # LitellmModel must NOT be touched for bare model names.
        litellm_cls.assert_not_called()
        client_cls.assert_called_once_with(
            api_key="ollama",
            base_url="http://localhost:11434/v1",
        )
        chat_cls.assert_called_once()
        chat_kwargs = chat_cls.call_args.kwargs
        assert chat_kwargs["model"] == "qwen2.5vl-7b"
